"""Administrator command surface for /guard.

Requirement: Decision Commands; Operator Introspection; Coverage Boundary
Disclosure; Approver Authorization; Late Decision Disclosure.

This module owns command parsing and execution only: it reads gateway state,
applies the one-shot ticket compare-and-swap from store/tickets.py, wakes the
suspended caller through approval/waiter.py and writes one audit row per
administrator action (store/audit.py, source "manual"). Every reply leaves
through anonymize.py and is capped at REPLY_LIMIT characters. A sender that is
not an administrator is refused before any ticket access; the refusal audit
row itself is rate limited per subject (REFUSAL_WINDOW_S). A sender that passes
the administrator gate first runs the ticket maintenance sweep
(store/tickets.py sweep), so a command can no longer be served from a store
full of tickets no process can still settle.

The one command that writes startup-sweep state is `/guard sweep`: it is the
explicit retry for a startup sweep that failed while the store was opened, and
it is the only place besides opening the store that moves that state. It runs
with the process start instant as its cutoff, so it can withdraw only the
tickets an earlier process left behind -- never this process's live ones -- and
it is rate limited per administrator like every other command-side side effect
(review R11-03).
"""

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
import time
from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..anonymize import Anonymizer
from ..approval.lateness import reject_late_decision
from ..core.reviewer import ReviewerStatus
from ..notify.ratelimit import NotifyRateLimiter
from ..notify.sender import is_admin_subject
from ..reviewers.base_check import NAME as BASE_CHECK_NAME
from ..store import audit, db, tickets
from ..triage.decisions import MODE_ENFORCE, MODE_OBSERVE, Decision
from ..triage.rules import RULE_SET_VERSION
from .contracts import FastJudgeStatus, GatewayStatus, StartupSweepView, TicketView

_LOGGER = logging.getLogger("tooling_guard")
"""Logger for the failures a reply must not echo verbatim."""

#: Marker prefix the gateway writes on an audit summary line to carry the policy
#: layer a verdict came from. The audit table has no layer column and its
#: rule_id column is evidence -- an observe rule such as R8 fires on calls it
#: never blocks -- so this marker, and the attribution block of summary_json,
#: are where the cause of a row is recorded.
_LAYER_MARKER = "layer="

__all__ = [
    "RECOVERY_WINDOW_S",
    "REFUSAL_TEXT",
    "REFUSAL_WINDOW_S",
    "REPLY_LIMIT",
    "Command",
    "finalize_reply",
    "handle_command",
    "parse_command",
    "startup_sweep_view",
]

#: Hard cap for one command reply, in characters.
REPLY_LIMIT = 2000
#: Appended when a reply had to be truncated; carries the pre-cut length.
TRUNCATION_NOTE = "…[回执已截断：原始长度 {total} 字符]"
#: Refusal sent to every sender that is not an administrator.
REFUSAL_TEXT = "拒绝：/guard 仅限管理员使用，本次未执行任何操作。"
#: Audit rows scanned per stats call; store/audit.py has no aggregation helper.
STATS_SCAN_LIMIT = 500
#: Pending tickets rendered per stats call.
PENDING_VIEW_LIMIT = 5
#: Validation warnings rendered per status call.
WARNING_VIEW_LIMIT = 5
#: Longest reason persisted with a ticket transition.
STORE_REASON_LIMIT = 200
#: Channels whose decision rows carry the requester in subject_key.
SUBJECT_RESTORED_SOURCES = frozenset({audit.SOURCE_MANUAL, audit.SOURCE_WEB})
"""Channels that keep subject_key on the requester instead of the decider.

The deciding identity always lands in the audit `actor` column, so the question
is only whether subject_key keeps naming the request. Both channels answer yes:
the command plane because both identities are platform strings, the dashboard
because its whole row is only legible when it separates the approved caller from
the approving username. Requirement Audit Trail (spec web-console:113) asks for
exactly that pair: `actor` is the dashboard username, subject_key stays on the
ticket's requester.
"""

#: Why an approval with no waiter is withdrawn instead of left consumable.
RETRY_WITHDRAWN_REASON = "approved without a waiter: retry window withdrawn"
#: Appended to an approval reply whose deciding identity is also the requester.
SELF_APPROVAL_NOTE = "\n自批：批准者=票据请求者，审计行已记 self_approved。"
#: Reply text of a failed decision; the exception type stays in the log.
DECISION_FAILED_TEXT = "失败（审计存储异常）：票据未改动，请查看日志。"
#: Longest summary_line persisted with an audit row.
SUMMARY_LIMIT = 200
#: Command token that may prefix the message text.
COMMAND_TOKEN = "guard"
#: Supported modes, in disclosure order.
ALL_MODES = (MODE_OBSERVE, MODE_ENFORCE)
#: Ticket identifier shape accepted by approve/deny (uuid-shaped today).
TICKET_ID_MAX = 128
_TICKET_ID_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_.:")
#: tool_name recorded on every administrator audit row.
_AUDIT_TOOL = "/guard"
#: Late decisions remembered per process; the oldest key is dropped past this.
_LATE_SEEN_LIMIT = 128
_late_seen: "OrderedDict[tuple[str, str], None]" = OrderedDict()
"""Late decisions already disclosed, oldest first.

A closed or already-settled ticket can be decided again at any time -- the Web
dashboard keeps its buttons live, and an operator who does not see the reply
simply clicks again. Every one of those clicks used to write its own audit row,
so a dozen retries buried the real history under identical late-decision lines.
The pair (ticket, verb) is remembered here, bounded, purely to keep one late
decision to one row; nothing about the ticket itself changes, and a lost key
only costs a duplicate row, never a permission."""
#: Rule id recorded on the ticket maintenance sweep row.
_SWEEP_RULE = "guard_ticket_sweep"
#: Rule id recorded on the audit row of one explicit startup-sweep recovery.
_RECOVERY_RULE = "guard_startup_sweep_recovery"
#: tool_name that, with the administrator subject, forms the recovery rate key.
_RECOVERY_TOOL = "guard/sweep"
#: Window during which one administrator produces at most one recovery attempt.
RECOVERY_WINDOW_S = 60.0
#: Per-subject admission for the explicit startup-sweep recovery.
_RECOVERIES = NotifyRateLimiter(window_s=RECOVERY_WINDOW_S)
#: Note returned by the command plane when the maintenance sweep itself failed.
_SWEEP_FAILED_NOTE = "\nticket sweep 失败（{error}）：本次未作废任何票据。"
#: Window during which one sender produces at most one refusal audit row.
REFUSAL_WINDOW_S = 60.0
#: Per-subject admission for unauthorized-attempt audit rows.
_REFUSALS = NotifyRateLimiter(window_s=REFUSAL_WINDOW_S)
#: Fallback redactor, used when the gateway exposes no redactor.
_FALLBACK_ANONYMIZER = Anonymizer()
#: Windows accepted by /guard stats, in seconds; None means every stored row.
STATS_WINDOWS: dict[str, float | None] = {
    "24h": 24 * 3600.0,
    "7d": 7 * 24 * 3600.0,
    "all": None,
}
#: Window used when the operator types no /guard stats argument.
DEFAULT_STATS_WINDOW = "24h"
#: rule_id labels rendered by /guard stats.
TOP_RULE_LIMIT = 5
#: Label for audit rows that carry no judge route.
UNJUDGED_LABEL = "未判定"
#: rule_id recorded for one unauthorized /guard attempt.
_REFUSAL_RULE = "guard_unauthorized"
#: /guard status line of the trust switch, as it stands (Deep Analysis Sampling).
TRUST_ROOT_ON = "域内直接放行：已启用（exec 族工具仍逐次复核）"
TRUST_ROOT_OFF = "域内直接放行：已关闭"
#: /guard status lines of the two reviewer switches, as the assembly reads them.
#: The fast-judge line carries a prefix plus the backend, the two score bands
#: and the confidence floor read from the one shared status view, so a jev/llm
#: swap cannot hide behind a switch word (Requirement: Fast Judge Observability).
JEV_LINE_ENABLED = "JEV 快审：已启用（"
JEV_LINE_DISABLED = "JEV 快审：已关闭（"
JEV_LINE_UNREADABLE = (
    "JEV 快审：状态不可读（未读取到快审配置，不发请求，模型判定未参与）"
)
DEEP_ON = "深度复核：已启用"
DEEP_OFF = "深度复核：已关闭（llm_enabled=false，不发请求）"

_HELP = """\
/guard（whoami 任何人可用，其余仅管理员）
  whoami                只读自述身份
  status [ticket_id]    网关概览或单票据视图
  stats [24h|7d|all]    窗口计数与待批票据
  approve <ticket_id>   批准一次（一次性精确消费）
  deny <ticket_id> [原因]  拒绝
  sweep | mode [observe|enforce]  重开批准闸门 / 查看或切换模式
  notifytest            立刻给管理员发一条测试私信，验证通知通道
"""

_COVERAGE = (
    "  (a) cron/后台唤醒与子 agent 内部调用不经本钩子：看不到也管不到。",
    "  (b) MCP/handoff/后台/未知形态工具被剥离即不可用；挂起最长 110s，超时按拒绝。",
)

#: Subcommand that sends one test private message through the notice channel.
NOTIFY_TEST_COMMAND = "notifytest"
#: Text of that test message. It says what it is, so an administrator who sees it
#: days later does not mistake it for a ticket somebody has to answer.
NOTIFY_TEST_TEXT = (
    "[工具网关] 通知通道测试：这条私信由 /guard notifytest 触发，"
    "不代表任何工具调用被挂起，也没有票据需要处理。"
    "收到即说明挂起通知与其它告警可以送达这个账号。"
)


@dataclass(frozen=True, slots=True)
class Command:
    """One parsed /guard invocation."""

    name: str
    args: tuple[str, ...] = ()


def parse_command(text: str) -> Command:
    """Split one message into the /guard subcommand and its arguments.

    Requirement: Decision Commands. The first token is case-insensitive and may
    carry the leading slash or the "guard" word itself, because the host passes
    the whole message text.

    Args:
        text: Raw message text.

    Returns:
        The parsed command; name is empty when no subcommand was typed.
    """
    tokens = str(text or "").split()
    if tokens and tokens[0].lstrip("/").lower() == COMMAND_TOKEN:
        tokens = tokens[1:]
    if not tokens:
        return Command(name="")
    return Command(name=tokens[0].lstrip("/").lower(), args=tuple(tokens[1:]))


def finalize_reply(reply: str, anonymizer: Anonymizer | None = None) -> str:
    """Redact one reply and cap it at REPLY_LIMIT characters.

    Requirement: Notification Content; Sanitized Persistence.

    Args:
        reply: Reply text before redaction.
        anonymizer: Redactor to apply; a default one is used when omitted.

    Returns:
        Redacted text, truncated with TRUNCATION_NOTE when it exceeded the cap.
    """
    redactor = anonymizer if anonymizer is not None else _FALLBACK_ANONYMIZER
    text = redactor.redact(str(reply))
    if len(text) <= REPLY_LIMIT:
        return text
    note = TRUNCATION_NOTE.format(total=len(text))
    budget = max(REPLY_LIMIT - len(note), 0)
    return redactor.redact_head(text, budget) + note


async def handle_command(
    text: str,
    gateway: Any,
    *,
    event: Any = None,
    registry: Any = None,
) -> str:
    """Execute one /guard command for the sending administrator.

    Requirement: Decision Commands; Approver Authorization. /guard whoami is
    routed before the administrator gate and is read-only for every sender: it
    writes no audit row, creates no ticket and changes no configuration, because
    the sender who needs it is exactly the sender who cannot pass the gate.

    Every other command refuses a non-administrator before any ticket or
    configuration access: no ticket is read or written and no configuration
    changes, so a refused read-only command cannot alter any state. The refusal
    keeps REFUSAL_TEXT verbatim and appends a diagnosis of this sender's own
    identity (see _diagnosis_note). Its deny_requester audit row is admitted at
    most once per subject and REFUSAL_WINDOW_S window (see _record_refusal); the
    attempts that were folded into the next admitted row are never discarded
    silently.

    An administrator command first runs the ticket maintenance sweep
    (store/tickets.sweep) and records one audit row when it settled anything, so
    closed approval windows and orphaned suspensions cannot accumulate.

    Args:
        text: Raw message text, including the command word.
        gateway: The gateway owning config, snapshot, store and registry.
        event: The host message event used for the administrator check.
        registry: Approval registry to wake; defaults to gateway.registry.

    Returns:
        The reply text, redacted and capped at REPLY_LIMIT characters.
    """
    command = parse_command(text)
    anonymizer = _anonymizer(gateway)
    if command.name == WHOAMI_COMMAND:
        return finalize_reply(_whoami_reply(gateway, event), anonymizer)
    actor = _admin_actor(gateway, event)
    if actor is None:
        refusal = _record_refusal(gateway, event, command)
        return finalize_reply(
            REFUSAL_TEXT
            + _diagnosis_note(gateway, event)
            + _refusal_note(refusal)
            + _audit_note(refusal.failure),
            anonymizer,
        )
    note = _sweep_note(gateway, actor)
    if command.name == NOTIFY_TEST_COMMAND:
        return finalize_reply(note + await _notify_test_reply(gateway, event), anonymizer)
    try:
        reply = _dispatch(command, gateway, actor, event, registry)
    except Exception as exc:  # noqa: BLE001 - a command never reaches the loop
        reply = f"/guard 执行出错（{type(exc).__name__}）：请用 /guard stats 复核结果。"
    return finalize_reply(note + reply, anonymizer)


def admin_actor(gateway: Any, event: Any) -> str | None:
    """Return the administrator identity behind one event, or None.

    Requirement: Approval Channels Are Equivalent. Every approval channel applies
    the same two-condition test (the host reports an administrator AND the
    configured admins allowlist names this sender), so the test keeps exactly one
    implementation and the reply channel borrows it instead of restating it.

    Args:
        gateway: Gateway owning the admins allowlist.
        event: Host message event.

    Returns:
        The administrator identity string, or None when the sender may not decide.
    """
    return _admin_actor(gateway, event)


def chat_type(event: Any) -> str:
    """Return the chat type token of one event.

    Args:
        event: Host message event.

    Returns:
        "FriendMessage", "GroupMessage" or UNREADABLE.
    """
    return _message_type(event)


def store_connection(gateway: Any) -> Any | None:
    """Return the gateway store connection, or None when storage is unavailable.

    Args:
        gateway: Gateway owning the store.

    Returns:
        An open connection, or None.
    """
    return _store(gateway)


def redactor(gateway: Any) -> Anonymizer:
    """Return the redactor that finalises operator-facing text.

    Args:
        gateway: Gateway supplying the redactor.

    Returns:
        The gateway anonymizer, or the module fallback.
    """
    return _anonymizer(gateway)


def _dispatch(
    command: Command,
    gateway: Any,
    actor: str,
    event: Any,
    registry: Any,
) -> str:
    """Route one parsed command to its handler.

    Args:
        command: Parsed command.
        gateway: Gateway under inspection.
        actor: Administrator identity string.
        event: Host message event.
        registry: Approval registry to wake.

    Returns:
        The unredacted reply text.
    """
    if command.name in ("", "help", "?"):
        return _HELP
    if command.name == "status":
        return _status_reply(gateway, command.args)
    if command.name == "sweep":
        return _sweep_recovery(gateway, actor)
    if command.name == "stats":
        return _stats_reply(gateway, command.args)
    if command.name == "approve":
        return _approve(gateway, command.args, actor, registry)
    if command.name == "deny":
        return _deny(gateway, command.args, actor, registry)
    if command.name == "mode":
        return _mode_reply(gateway, command.args, actor)
    return f"未知子命令：{command.name}\n{_HELP}"


async def _notify_test_reply(gateway: Any, event: Any) -> str:
    """Send one test notice through the delivery boundary and report the result.

    Requirement: Administrator Channel; Notification Delivery Failure. The
    delivery path is the one the suspension notice uses, so a test that arrives
    proves the real notices can arrive, and one that does not names the reason
    instead of leaving "I never got a message" unexplained.

    Args:
        gateway: Gateway owning the admins allowlist and the delivery boundary.
        event: Host message event the command arrived on.

    Returns:
        Reply text naming the recipients and what the host answered.
    """
    admins = _admin_entries(gateway)
    if not admins:
        return "未配置 admins：没有收件人，通知通道不可用。"
    send = getattr(gateway, "_send_notice", None)
    if not callable(send):
        return "网关没有通知边界（_send_notice 不可用），无法测试。"
    recipients = ", ".join(admins)
    try:
        reached = await send(
            NOTIFY_TEST_TEXT,
            admins=admins,
            context=getattr(gateway, "_context", None),
            event=event,
            redact=False,
        )
    except Exception as exc:  # noqa: BLE001 - a command never reaches the loop
        return f"测试通知发送出错（{type(exc).__name__}）。收件人：{recipients}。"
    if not reached:
        return (
            f"宿主没有接受这条测试通知。收件人：{recipients}。"
            "请确认 admins 的平台前缀与宿主正在运行的平台 id 一致（/guard whoami 能给出现用平台）。"
        )
    return (
        f"测试通知已交给宿主，宿主返回成功。收件人：{recipients}。"
        "宿主对没有会话的地址也会回成功，所以只有私信真的到了才算通；"
        "没收到时先确认这个 QQ 号是 bot 的私聊好友，且 admins 的平台前缀正确。"
    )


def read_reviewer_statuses(gateway: Any) -> tuple[ReviewerStatus, ...]:
    """Return the reviewer statuses of one gateway, tolerantly.

    Requirement: Observability. The gateway's `reviewer_statuses()` is the only
    source of this view: `/guard status` and the web status response both read
    it, so a reviewer cannot be enabled on one surface and busy on the other. A
    gateway without the reader, or one whose reader raises, renders no reviewer
    table instead of failing the whole reply.

    Args:
        gateway: Gateway under inspection.

    Returns:
        The statuses, or an empty tuple.
    """
    reader = getattr(gateway, "reviewer_statuses", None)
    if not callable(reader):
        return ()
    found: list[tuple[ReviewerStatus, ...]] = []
    with contextlib.suppress(Exception):
        found.append(tuple(reader()))
    return found[0] if found else ()


def read_fast_judge_status(gateway: Any) -> FastJudgeStatus | None:
    """Return the configured fast-judge status of one gateway, tolerantly.

    Requirement: Fast Judge Observability. ``Gateway.fast_judge_status`` is the
    only source of this view: ``/guard status`` and the Web ``/status`` payload
    both read this function, so the two faces cannot report a different switch,
    backend, band pair or confidence floor. It is a reader, not a computation --
    the bands are resolved once in the gateway from the same configuration the
    fast judge is built from, and nothing here re-derives a default or assumes
    the jev backend. A gateway without the property, a property that raises and
    a value of the wrong shape all map to ``None``, which the callers render as
    unreadable instead of failing the whole reply.

    Args:
        gateway: Gateway under inspection.

    Returns:
        The status, or None when the gateway cannot answer.
    """
    try:
        source = getattr(gateway, "fast_judge_status", None)
        if callable(source):
            source = source()
    except Exception:  # noqa: BLE001 - a status read never fails a reply
        return None
    return source if isinstance(source, FastJudgeStatus) else None


def _reviewer_outcome(status: ReviewerStatus) -> str:
    """Render the last verdict of one reviewer without any call argument text."""
    outcome = status.last_outcome
    if outcome is None:
        return "暂无"
    text = getattr(outcome, "value", None) or str(outcome)
    if status.last_elapsed_s:
        return f"{text}（{status.last_elapsed_s:.2f}s）"
    return text


def _reviewer_lines(statuses: Sequence[ReviewerStatus]) -> list[str]:
    """Render one line per reviewer from the single status source.

    Requirement: Observability; Built-in Base Checker. Every line carries the
    name, order, enabled flag, busy flag, in-flight count and last verdict, so a
    disabled base checker is visible instead of merely absent. The last error is
    never echoed: it may quote a host exception, and the degraded kind already
    says what happened.

    Args:
        statuses: Reviewer statuses of the gateway.

    Returns:
        The reviewer table lines, empty when there is nothing to show.
    """
    if not statuses:
        return []
    parts: list[str] = []
    for status in statuses:
        if not status.enabled:
            state = "已停用"
        elif status.busy:
            state = f"正忙 in_flight={status.in_flight}"
        else:
            state = "就绪"
        part = f"{status.name} {state}"
        outcome = _reviewer_outcome(status)
        if outcome:
            part = f"{part} 最近={outcome}"
        if status.last_degraded:
            part = f"{part} 降级={_clip(str(status.last_degraded), 40)}"
        parts.append(part)
    line = "审查器 reviewers：" + "｜".join(parts)
    if any(not item.enabled and item.name == BASE_CHECK_NAME for item in statuses):
        line = f"{line}（base_check 只管白名单提示，policy 阶段仍不可停用）"
    return [line]


def startup_sweep_view(gateway: Any) -> StartupSweepView | None:
    """Read the startup ticket sweep state of the gateway store, tolerantly.

    Requirement: Operator Introspection; Ticket Persistence (review R11-03). The
    text status reply and the web /status payload read this one function, so the
    two faces cannot disagree about whether approvals are closed. It is
    read-only on purpose: a status query never runs a sweep, so polling status
    cannot move the state it reports -- only opening the store and the explicit
    `/guard sweep` recovery do.

    Args:
        gateway: Gateway under inspection.

    Returns:
        The startup sweep view, or None when no store is reachable.
    """
    try:
        conn = _store(gateway)
        if conn is None:
            return None
        state = db.startup_sweep_state(conn)
    except Exception:  # noqa: BLE001 - a status query never fails the reply
        return None
    return StartupSweepView(
        ok=bool(state.ok),
        attempts=int(state.attempts),
        error=str(state.error or ""),
        approvals_closed=not state.ok,
    )


def _startup_sweep_line(view: StartupSweepView | None) -> str:
    """Render the startup sweep state as one stable, assertable line.

    Requirement: Operator Introspection (review R11-03). The tokens `ok`,
    `attempts` and `approvals_closed` are fixed; a closed approval side is
    spelled out together with the command that reopens it, because a closed gate
    with no visible cause was the whole defect.

    Args:
        view: Startup sweep view, or None when the store was unreachable.

    Returns:
        The status line.
    """
    if view is None:
        return "启动清理 startup_sweep：未读到存储（状态未知）"
    line = (
        f"启动清理 startup_sweep ok={'是' if view.ok else '否'}"
        f" attempts={view.attempts}"
        f" approvals_closed={'是' if view.approvals_closed else '否'}"
    )
    if view.approvals_closed:
        line = (
            f"{line}｜批准侧已关闭（批准一律被拒）：修好后执行 /guard sweep 重开闸门。"
        )
    if view.error:
        line = f"{line} error={_clip(view.error, 120)}"
    return line


def _status_reply(gateway: Any, args: Sequence[str] = ()) -> str:
    """Render gateway status plus the reviewer table and boundary statements.

    Requirement: Coverage Boundary Disclosure; Operator Introspection;
    Observability. With a ticket id the reply becomes the read-only view of that
    one ticket.

    Args:
        gateway: Gateway under inspection.
        args: Command arguments; the first one is an optional ticket id.

    Returns:
        The status reply text.
    """
    if args:
        return _ticket_status_reply(gateway, args)
    warnings = _warnings(gateway)
    reviewers = read_reviewer_statuses(gateway)
    status = GatewayStatus(
        enabled=_flag(gateway, "enabled"),
        mode=_mode(gateway),
        warning_count=len(warnings),
        judge_route=_judge_route(gateway),
        hook_degraded=_hook_degraded(gateway),
        startup_sweep=startup_sweep_view(gateway),
    )
    lines = [
        (
            f"/guard status · 判定模式 mode：{status.mode}（{_mode_meaning(status.mode)}）"
            f" · 网关 enabled：{'是' if status.enabled else '否'}"
            f" · warning_count：{status.warning_count}"
            f" · judge route：{status.judge_route or 'none'}"
        ),
        f"{_startup_sweep_line(status.startup_sweep)}｜{_trust_line(gateway)}",
        _jev_line(gateway),
        _deep_line(gateway),
    ]
    if status.hook_degraded:
        lines.append(f"上次工具集安装降级：{status.hook_degraded}")
    lines.extend(_reviewer_lines(reviewers))
    if not status.enabled:
        lines.append(
            "注意：网关未启用（配置校验未通过），降级观察不拦截；需修正的 key 见下。"
        )
    for warning in warnings[:WARNING_VIEW_LIMIT]:
        key = getattr(warning, "key", "?")
        message = getattr(warning, "message", warning)
        lines.append(f"  · {key}: {_clip(str(message), 120)}")
    if len(warnings) > WARNING_VIEW_LIMIT:
        lines.append(f"  · 其余 {len(warnings) - WARNING_VIEW_LIMIT} 条未展开")
    lines.append("覆盖边界声明：")
    lines.extend(_COVERAGE)
    return "\n".join(lines)


def _ticket_status_reply(gateway: Any, args: Sequence[str]) -> str:
    """Render one read-only ticket view for /guard status <ticket_id>.

    Requirement: Operator Introspection. Nothing is written and no ticket
    state is touched; an unknown or malformed identifier is refused politely.

    Args:
        gateway: Gateway owning the store.
        args: Command arguments; the first one is the ticket id.

    Returns:
        The ticket view, or a refusal text.
    """
    if len(args) > 1:
        return "status 只接受一个票据 id：/guard status [ticket_id]"
    ticket_id = args[0]
    if not valid_ticket_id(ticket_id):
        return "status 需要一个合法票据 id：/guard status [ticket_id]"
    conn = _store(gateway)
    if conn is None:
        return "票据视图不可用：审计存储不可用（fail-closed），未做任何改动。"
    ticket = tickets.get_ticket(conn, ticket_id)
    if ticket is None:
        return f"未找到票据 {ticket_id}，未做任何改动。"
    view = TicketView(
        ticket_id=str(getattr(ticket, "ticket_id", ticket_id)),
        state=str(getattr(ticket, "state", "?")),
        tool_name=str(getattr(ticket, "tool_name", "") or ""),
        created_at=str(getattr(ticket, "created_at", "") or ""),
    )
    deadline = getattr(ticket, "window_deadline", None)
    if not deadline:
        window = "未设置批准窗口"
    elif tickets.is_expired_window(ticket):
        window = f"窗口已过期（截止 {deadline}）"
    else:
        window = f"窗口仍有效（截止 {deadline}）"
    reason = _clip(
        redact_text(gateway, getattr(ticket, "reason", None) or ""), STORE_REASON_LIMIT
    )
    return "\n".join(
        (
            f"票据 {view.ticket_id}",
            f"state：{view.state} · 批准窗口：{window}",
            (
                f"tool_name：{view.tool_name or '?'} · created_at：{view.created_at or '?'}"
                f" · decided_by：{getattr(ticket, 'decided_by', None) or '未决'}"
                f" · reason：{reason or '无'}"
            ),
        )
    )


def _row_layer(row: Mapping[str, Any]) -> str:
    """Return the policy layer a stored audit row was attributed to.

    Requirement: Operator Introspection. The attribution lives in the
    attribution block of summary_json, and on the summary line as a layer=
    marker; the rule_id column is evidence only, so it is never read here.
    Rows written before the attribution block existed carry neither and
    simply do not count.

    Args:
        row: One stored audit row.

    Returns:
        The layer name, empty when the row carries none.
    """
    raw = row.get("summary_json")
    if isinstance(raw, str) and raw:
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            payload = None
        if isinstance(payload, Mapping):
            block = payload.get("attribution")
            if isinstance(block, Mapping):
                layer = block.get("layer")
                if isinstance(layer, str) and layer:
                    return layer
    line = row.get("summary_line")
    if isinstance(line, str):
        for token in line.split():
            if token.startswith(_LAYER_MARKER):
                return token[len(_LAYER_MARKER) :]
    return ""


def _stats_reply(gateway: Any, args: Sequence[str] = ()) -> str:
    """Summarize audit decisions for one window plus pending tickets.

    Requirement: Operator Introspection. The store exposes no aggregation
    helper, so counts come from the most recent audit rows filtered by the
    window the operator asked for.

    Args:
        gateway: Gateway under inspection.
        args: Command arguments; the first one is an optional window token.

    Returns:
        The stats reply text.
    """
    window = DEFAULT_STATS_WINDOW
    if args:
        window = str(args[0]).lower()
    if window not in STATS_WINDOWS or len(args) > 1:
        return f"非法统计窗口：{' '.join(args)}；只接受 24h、7d 或 all。\n{_HELP}"
    conn = _store(gateway)
    if conn is None:
        return "/guard stats 不可用：审计存储不可用，无法统计（fail-closed）。"
    span = STATS_WINDOWS[window]
    since = None if span is None else db.utc_iso(time.time() - span)
    try:
        rows = audit.query_recent(conn, STATS_SCAN_LIMIT)
        total = audit.count_events(conn)
        pending = tickets.list_pending(conn)
    except Exception as exc:  # noqa: BLE001 - unreadable store is reported, not raised
        return f"/guard stats 读取失败（{type(exc).__name__}），未改动任何数据。"
    counted = [
        row for row in rows if since is None or str(row.get("ts") or "") >= since
    ]
    decisions: dict[str, int] = {}
    rules: dict[str, int] = {}
    layers: dict[str, int] = {}
    routes: dict[str, int] = {}
    for row in counted:
        name = str(row.get("decision") or "?")
        decisions[name] = decisions.get(name, 0) + 1
        rule = row.get("rule_id")
        if rule:
            rules[str(rule)] = rules.get(str(rule), 0) + 1
        layer = _row_layer(row)
        if layer:
            layers[layer] = layers.get(layer, 0) + 1
        route = row.get("judge_route")
        label = str(route) if route else UNJUDGED_LABEL
        routes[label] = routes.get(label, 0) + 1
    degraded = next((row for row in counted if row.get("degraded")), None)
    lines = [
        f"/guard stats {window}",
        f"窗口 {window}：审计 {len(counted)} 条（扫最近 {STATS_SCAN_LIMIT}，库内 {total}）",
        "各 decision 计数：" + (_format_counts(decisions) or "无"),
    ]
    if layers:
        lines.append(
            f"归因层 Top{TOP_RULE_LIMIT}："
            + _format_counts(layers, limit=TOP_RULE_LIMIT)
        )
    if rules:
        # The rule word is kept, but labelled: it says what fired, and an
        # observe rule fires on calls it never blocks, so a reader who counts
        # these as decisions blames an observer. The layer line above is the
        # attribution.
        lines.append(
            f"命中规则 Top{TOP_RULE_LIMIT}（证据，非归因）："
            + _format_counts(rules, limit=TOP_RULE_LIMIT)
        )
    lines.append("judge_route 计数：" + (_format_counts(routes) or "无"))
    lines.append(f"待批票据数：{len(pending)}")
    for view in _ticket_views(pending):
        lines.append(
            f"  · {view.ticket_id} {view.state}"
            f" 工具 {view.tool_name or '?'} 创建于 {view.created_at or '?'}"
        )
    if len(pending) > PENDING_VIEW_LIMIT:
        lines.append(f"  · 其余 {len(pending) - PENDING_VIEW_LIMIT} 条未列出")
    if degraded is None:
        lines.append("最近一条降级事实：无")
    else:
        detail = " ".join(
            part
            for part in (
                str(degraded.get("ts") or ""),
                str(degraded.get("decision") or ""),
                f"source={degraded.get('source')}",
                str(degraded.get("summary_line") or ""),
            )
            if part
        )
        lines.append("最近一条降级事实：" + detail.strip())
    return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class DecisionResult:
    """Outcome of one ticket decision, shared by every approval channel.

    Requirement: Approval Channels Are Equivalent. The command plane and the web
    card both call :func:`decide_ticket`, so one decision means one CAS, one
    late-decision path and one audit row shape no matter which channel typed it.

    Attributes:
        status: One of "decided", "late", "missing", "unavailable", "error".
        ticket_id: Ticket the decision targeted.
        message: Channel-facing reply text, already redacted and composed.
        state: Ticket state after the attempt, when it is known.
        woke: Whether a suspended caller was woken by this decision.
        audit_failure: Exception type name when the audit row could not be written.
        self_approved: Whether the deciding identity is the ticket's requester.
            Approval is never refused for it, but it is marked so a
            self-approved escalation is visible to whoever reads the trail.
    """

    status: str
    ticket_id: str
    message: str
    state: str | None = None
    woke: bool = False
    audit_failure: str | None = None
    self_approved: bool = False


def _requester_subject(conn: sqlite3.Connection, ticket_id: str) -> str | None:
    """Return the subject_key of the ticket's requester, when the row is readable.

    Requirement: Audit Trail Completeness. The deciding administrator has its own
    audit column (store/audit.py actor), so subject_key can keep naming the
    request the row is about; the ticket is the only record of that requester.

    Args:
        conn: Open store connection.
        ticket_id: Ticket that was just decided.

    Returns:
        The requester's subject_key, or None when the ticket cannot be read.
    """
    try:
        ticket = tickets.get_ticket(conn, ticket_id)
    except Exception:  # noqa: BLE001 - a lookup failure must not undo the decision
        return None
    return None if ticket is None else ticket.subject_key


def _self_approval(gateway: Any, actor: str, subject_key: str | None) -> bool:
    """Report whether the deciding identity is the ticket's requester.

    Requirement: Approver Authorization. A dashboard administrator is a
    username while a ticket carries a platform identity, so the two only meet
    through the configured web_subject_map; the command plane compares them
    directly. A hit is marked, never resolved behind the operator's back:
    self-approval stays possible, it just stops being invisible.

    Args:
        gateway: Gateway owning the configuration.
        actor: Deciding administrator identity.
        subject_key: Requester identity of the decided ticket.

    Returns:
        True when both identities name the same principal.
    """
    if not actor or not subject_key:
        return False
    if actor == subject_key:
        return True
    config = getattr(gateway, "config", None)
    for entry in getattr(config, "web_subject_map", ()) or ():
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            continue
        holder, subject = entry
        if holder == actor and subject == subject_key:
            return True
    return False


def _withdraw_unconsumable_approval(
    conn: sqlite3.Connection, ticket_id: str, *, actor: str
) -> bool:
    """Withdraw an approval no waiter can ever consume.

    Requirement: Approved Retry Outcome and Window. An approval is a licence for
    one retry by the call that was suspended, and that call re-enters through the
    waiting coroutine. Once no waiter is left, nothing can present the four-tuple
    consume_approved demands, so the row would only sit there granting a one-shot
    retry window to whichever later call happens to repeat the exact session,
    tool and argument digest. The decision itself stays on record (audit row and
    the pending -> approved transition); what is withdrawn is the grant.

    Args:
        conn: Open store connection.
        ticket_id: Ticket that was just approved.
        actor: Identity that approved it, recorded on the transition row.

    Returns:
        True when the approval was withdrawn, False when the ticket moved on its
        own and the caller should re-read it.
    """
    try:
        result = tickets.transition(
            conn,
            ticket_id,
            (tickets.APPROVED,),
            tickets.CANCELED_EXTERNAL,
            actor=actor,
            reason=RETRY_WITHDRAWN_REASON,
        )
    except Exception:  # noqa: BLE001 - the approval itself already stands
        return False
    return result.ok


def decide_ticket(
    gateway: Any,
    ticket_id: str,
    *,
    approve: bool,
    actor: str,
    reason: str | None = None,
    registry: Any = None,
    source: str = audit.SOURCE_MANUAL,
    tool_name: str = _AUDIT_TOOL,
) -> DecisionResult:
    """Move one pending ticket to approved or denied exactly once.

    Requirement: Decision Commands; Ticket Lifecycle; Approval Channels Are
    Equivalent. Only the PENDING -> APPROVED|DENIED compare-and-swap in
    store/tickets.py runs here, so a second decision loses the race and is
    settled by the same late path the command plane uses. Approval only waives
    a suspension: it never overrides deny_rule, deny_policy or deny_judge, and
    it never replays the original tool call.

    Args:
        gateway: Gateway owning the store, registry and redactor.
        ticket_id: Ticket to decide; the caller validates its shape.
        approve: True to approve, False to deny.
        actor: Administrator identity string recorded with the row.
        reason: Operator reason for a denial, redacted and clipped before it is
            stored.
        registry: Approval registry to wake; defaults to the gateway's own.
        source: Audit source marker of the channel ("manual" or "web").
        tool_name: Audit tool name of the channel.

    Returns:
        The shared outcome: status, state, wake flag, reply text and audit
        failure, if any.
    """
    verb = "approve" if approve else "deny"
    target = tickets.APPROVED if approve else tickets.DENIED
    conn = _store(gateway)
    if conn is None:
        return DecisionResult(
            "unavailable",
            ticket_id,
            "审批不可用：审计存储不可用，票据无法读写（fail-closed）。",
        )
    typed_reason = (reason or "").strip()
    redacted = redact_text(gateway, typed_reason) if typed_reason else None
    stored = _clip(redacted, STORE_REASON_LIMIT) if redacted else None
    try:
        result = tickets.transition(
            conn,
            ticket_id,
            (tickets.PENDING,),
            target,
            actor=actor,
            reason=(
                f"approved by administrator {actor}"
                if approve
                else stored or f"denied by administrator {actor}"
            ),
        )
    except Exception as exc:  # noqa: BLE001 - logged here, never echoed
        _LOGGER.warning("%s of ticket %s failed: %s", verb, ticket_id, exc)
        return DecisionResult("error", ticket_id, f"{verb} {DECISION_FAILED_TEXT}")
    if not result.ok:
        return _late_result(
            gateway,
            conn,
            ticket_id,
            target,
            actor,
            verb,
            source=source,
            tool_name=tool_name,
        )
    woke = _resolve(registry, gateway, ticket_id, target)
    requester = _requester_subject(conn, ticket_id)
    subject_key = requester if source in SUBJECT_RESTORED_SOURCES else None
    self_approved = _self_approval(gateway, actor, requester)
    withdrew = (
        approve
        and not woke
        and _withdraw_unconsumable_approval(conn, ticket_id, actor=actor)
    )
    if approve:
        summary = f"guard approve {ticket_id}"
        if self_approved:
            summary += " self_approved"
        if withdrew:
            summary += " retry_window=withdrawn reason=no_waiter"
        failure = record_action(
            gateway,
            decision=Decision.ALLOW_APPROVED_RETRY.value,
            summary=summary,
            actor=actor,
            ticket_id=ticket_id,
            subject_key=subject_key,
            rule_id="guard_admin_approve",
            source=source,
            tool_name=tool_name,
        )
        message = f"已批准 {ticket_id}：批准窗口内可重试一次。"
        if withdrew:
            message += "但无存活等待方，重试窗口已撤回。"
        else:
            message += "等待方已唤醒。" if woke else "当前无等待方。"
        if self_approved:
            message += SELF_APPROVAL_NOTE
    else:
        failure = record_action(
            gateway,
            decision=Decision.DENY_POLICY.value,
            summary=(
                f"guard deny {ticket_id} {redacted or ''}".strip()
                + (" self_approved" if self_approved else "")
            ),
            actor=actor,
            ticket_id=ticket_id,
            subject_key=subject_key,
            rule_id="guard_admin_deny",
            source=source,
            tool_name=tool_name,
        )
        message = f"已拒绝 {ticket_id}"
        message += f"（原因：{redacted}）" if redacted else ""
        message += "：等待方已唤醒并按拒绝结束。" if woke else "：当前无等待方。"
        if self_approved:
            message += SELF_APPROVAL_NOTE
    return DecisionResult(
        "decided",
        ticket_id,
        message + _audit_note(failure),
        state=tickets.CANCELED_EXTERNAL if withdrew else target,
        woke=woke,
        audit_failure=failure,
        self_approved=self_approved,
    )


def _approve(gateway: Any, args: Sequence[str], actor: str, registry: Any) -> str:
    """Approve one pending ticket exactly once.

    Requirement: Decision Commands; Ticket Lifecycle.

    Args:
        gateway: Gateway owning the store.
        args: Command arguments; the first one is the ticket id.
        actor: Administrator identity string.
        registry: Approval registry to wake.

    Returns:
        The approve reply text.
    """
    ticket_id = args[0] if args else ""
    if not valid_ticket_id(ticket_id):
        return "用法：/guard approve <ticket_id>"
    return decide_ticket(
        gateway, ticket_id, approve=True, actor=actor, registry=registry
    ).message


def _deny(gateway: Any, args: Sequence[str], actor: str, registry: Any) -> str:
    """Deny one pending ticket with an optional redacted reason.

    Requirement: Decision Commands; Ticket Lifecycle.

    Args:
        gateway: Gateway owning the store.
        args: Command arguments; the first one is the ticket id, the rest is
            the operator reason.
        actor: Administrator identity string.
        registry: Approval registry to wake.

    Returns:
        The deny reply text.
    """
    ticket_id = args[0] if args else ""
    if not valid_ticket_id(ticket_id):
        return "用法：/guard deny <ticket_id> [原因]"
    return decide_ticket(
        gateway,
        ticket_id,
        approve=False,
        actor=actor,
        reason=" ".join(args[1:]).strip(),
        registry=registry,
    ).message


def _late_result(
    gateway: Any,
    conn: Any,
    ticket_id: str,
    decision: str,
    actor: str,
    verb: str,
    *,
    source: str = audit.SOURCE_MANUAL,
    tool_name: str = _AUDIT_TOOL,
) -> DecisionResult:
    """Report a decision that lost the compare-and-swap race.

    Requirement: Late Decision Disclosure. A live approval window is never
    expired just because the operator typed the command twice, so
    reject_late_decision only runs when the window is closed or the ticket is
    no longer approvable.

    Args:
        gateway: Gateway owning the store.
        conn: Open store connection.
        ticket_id: Ticket the operator tried to decide.
        decision: Decision that lost the race.
        actor: Administrator identity string.
        verb: Operator subcommand, for the reply text.
        source: Audit source marker of the channel.
        tool_name: Audit tool name of the channel.

    Returns:
        The shared outcome for the refused late decision.
    """
    try:
        ticket = tickets.get_ticket(conn, ticket_id)
    except Exception as exc:  # noqa: BLE001 - the reply reports the failure
        return DecisionResult(
            "error",
            ticket_id,
            f"{verb} 未能复核票据状态（{type(exc).__name__}），未改动。",
        )
    if ticket is None:
        return DecisionResult("missing", ticket_id, f"未找到票据 {ticket_id}，未改动。")
    if not _late_disclosure_due(ticket_id, verb):
        return DecisionResult(
            "late",
            ticket_id,
            f"票据 {ticket_id} 的迟到决定已记录过，本次未重复写审计，也未改动任何权限。",
            state=ticket.state,
        )
    if ticket.state == tickets.APPROVED and not tickets.is_expired_window(ticket):
        failure = record_action(
            gateway,
            decision=Decision.DENY_POLICY.value,
            summary=f"late {verb} ignored {ticket_id}: approval window still open",
            actor=actor,
            ticket_id=ticket_id,
            subject_key=(
                ticket.subject_key if source in SUBJECT_RESTORED_SOURCES else None
            ),
            rule_id="guard_late_decision",
            degraded=True,
            source=source,
            tool_name=tool_name,
        )
        return DecisionResult(
            "late",
            ticket_id,
            (
                f"票据 {ticket_id} 已批准且窗口未关闭，本次未重复消费。"
                + _audit_note(failure)
            ),
            state=ticket.state,
            audit_failure=failure,
        )
    try:
        late = reject_late_decision(conn, ticket_id, decision, actor=actor)
    except Exception as exc:  # noqa: BLE001 - the reply reports the failure
        return DecisionResult(
            "error",
            ticket_id,
            f"{verb} 的迟到决定处理失败（{type(exc).__name__}），未改动。",
            state=ticket.state,
        )
    failure = record_action(
        gateway,
        decision=Decision.TIMEOUT_DENY.value,
        summary=f"late {verb} rejected {ticket_id} state={ticket.state}",
        actor=actor,
        ticket_id=ticket_id,
        subject_key=ticket.subject_key if source in SUBJECT_RESTORED_SOURCES else None,
        rule_id="guard_late_decision",
        degraded=True,
        source=source,
        tool_name=tool_name,
    )
    message = (
        f"票据 {ticket_id} 已过期：迟到决定按超时处理，未授予任何权限。"
        if late
        else f"票据 {ticket_id} 现已 {ticket.state}：迟到决定被丢弃，未授予权限。"
    )
    return DecisionResult(
        "late",
        ticket_id,
        message + _audit_note(failure),
        state=ticket.state,
        audit_failure=failure,
    )


def _mode_reply(gateway: Any, args: Sequence[str], actor: str) -> str:
    """Show or switch the effective enforcement mode.

    Requirement: Decision Commands. A switch happens only for an explicit
    administrator command and always writes one audit row.

    Args:
        gateway: Gateway whose mode changes.
        args: Command arguments; empty to display, one mode to switch.
        actor: Administrator identity string.

    Returns:
        The mode reply text.
    """
    current = _mode(gateway)
    if not args:
        return f"当前模式 {current}（{_mode_meaning(current)}）\n用法：/guard mode observe|enforce"
    if len(args) > 1:
        return "用法：/guard mode observe|enforce"
    target = args[0].lower()
    if target not in ALL_MODES:
        return f"非法模式 {target}：只接受 observe 或 enforce，未改动。"
    if target == current:
        return f"已是 {target}（{_mode_meaning(target)}），未改动。"
    failure = _apply_mode(gateway, target)
    if failure is not None:
        return f"切换失败：{failure}，模式仍为 {_mode(gateway)}。"
    if _mode(gateway) != target:
        return f"切换未生效（当前 mode={_mode(gateway)}），未写入审计。"
    # A successful switch is an allow-class operator action, never a refusal:
    # /guard stats counts this row by its decision, so recording the row as
    # DENY_POLICY would report every switch to enforce as a denial.
    audit_failure: str | None = record_action(
        gateway,
        decision=Decision.ALLOW_PASSTHROUGH.value,
        summary=f"guard mode -> {target} by {actor}",
        actor=actor,
        rule_id="guard_mode_switch",
    )
    if target == MODE_ENFORCE:
        reply = f"enforce 已开启：危险调用将被拦截。当前 mode={_mode(gateway)}。"
    else:
        reply = f"已切换为 observe：危险调用只记录不拦截。当前 mode={_mode(gateway)}。"
    if not _flag(gateway, "enabled"):
        reply += "注意：配置校验未过（enabled=false），该模式暂不生效。"
    return reply + _audit_note(audit_failure)


def _apply_mode(gateway: Any, mode: str) -> str | None:
    """Switch the gateway mode through the public Gateway.set_mode entry point.

    Requirement: Policy Snapshot Consistency. The gateway must provide set_mode;
    when it is missing the switch is refused, and no config or snapshot field is
    ever written from here.

    Args:
        gateway: Gateway to switch.
        mode: Target mode, already validated.

    Returns:
        None on success, or a short failure reason.
    """
    setter = getattr(gateway, "set_mode", None)
    if not callable(setter):
        return "网关不支持模式切换（缺少 set_mode），本次未改动任何状态"
    if setter(mode) is False:
        return "网关拒绝该模式（set_mode 返回 False）"
    return None


def _mono() -> float:
    """Return the instant used to admit refusal audit rows.

    Requirement: Approver Authorization. Indirection exists so a test can move
    the throttle clock without waiting on the wall clock.

    Returns:
        A monotonic timestamp in seconds.
    """
    return time.monotonic()


def _writer(gateway: Any) -> Any:
    """Return the gateway's ordered audit queue, or None when there is none.

    Requirement: Retention and Rotation (single write queue). The command
    surface does not own a connection of its own: it submits to the same queue
    the decision path uses, so an operator row cannot be moved ahead of the
    decisions it describes. A gateway that offers no queue (store unavailable,
    or a host that never opened one) is read as unavailable storage.

    Args:
        gateway: Gateway under inspection.

    Returns:
        The `AuditWriter` of the gateway, or None.
    """
    factory = getattr(gateway, "audit_writer", None)
    if not callable(factory):
        return None
    with contextlib.suppress(Exception):
        return factory()
    return None


def record_action(
    gateway: Any,
    *,
    decision: str,
    summary: str,
    actor: str,
    ticket_id: str | None = None,
    subject_key: str | None = None,
    rule_id: str | None = None,
    degraded: bool = False,
    source: str = audit.SOURCE_MANUAL,
    tool_name: str = _AUDIT_TOOL,
) -> str | None:
    """Persist one administrator action as an audit row.

    Requirement: Operator Introspection; Sanitized Persistence; Retention and
    Rotation (single write queue); Rule Set Versioning. One submit followed by
    one drain: the row is queued in the process-wide order and committed at
    once, so the reply can report the write honestly.

    The delegated and labels columns stay NULL because a command-plane row
    describes an administrator action, not a managed tool call, so it has no
    delegation verdict to record.

    Args:
        gateway: Gateway supplying store, mode, policy version and redactor.
        decision: Decision vocabulary value for this action.
        summary: Operator-facing summary, redacted before it is stored.
        actor: Administrator identity string, always recorded in `actor`.
        ticket_id: Ticket the action targeted, when any.
        subject_key: Requester subject the row is about; falls back to the
            actor when the channel does not restore it. A decision row therefore
            keeps both identities instead of overwriting one with the other.
        rule_id: Rule identifier recorded with the row.
        degraded: Whether the row records a degraded action (gateway
            self-degradation only, never an unauthorized attempt).
        source: Channel marker; the command plane writes "manual" and the web
            card writes "web", so the two stay distinguishable.
        tool_name: Audit tool name of the channel.

    Returns:
        None on success, or the exception type name when the write failed.
    """
    writer = _writer(gateway)
    if writer is None:
        return "storage_unavailable"
    observe = _mode(gateway) == MODE_OBSERVE
    payload: dict[str, Any] = {
        "decision": decision,
        "source": source,
        "tool_name": tool_name,
        "subject_key": subject_key or actor,
        "actor": actor,
        "summary_line": _clip(redact_text(gateway, summary), SUMMARY_LIMIT),
        "ticket_id": ticket_id,
        "rule_id": rule_id,
        "policy_version": _policy_version(gateway),
        "degraded": 1 if degraded else 0,
        "rule_set_version": RULE_SET_VERSION,
        "delegated": None,
        "labels": None,
    }
    if observe:
        payload["observe"] = True
        payload["would_be"] = decision
    writer.submit(payload)
    try:
        writer.drain()
    except Exception as exc:  # noqa: BLE001 - returned to the caller as a note
        return type(exc).__name__
    return None


def _sweep_summary(gateway: Any) -> dict[str, Any]:
    """Settle the dead tickets no caller can finish, before serving a command.

    Requirement: Ticket Persistence; Approved Retry Outcome and Window. The
    recovery scans in store/tickets.py had no production caller, so an approved
    ticket whose window closed stayed approved and a suspension orphaned by a
    dead request stayed pending forever. The sweep runs on the administrator
    path only and never on behalf of a refused sender, so a refusal still
    cannot touch a ticket. It is narrowed by tickets.SWEEP_ORPHAN_GRACE_S, which
    is longer than one in-call wait, so a live waiter's own ticket is never
    swept while it waits.

    Args:
        gateway: Gateway owning the store.

    Returns:
        The tickets.sweep summary (keys "expired", "invalidated", "changed"),
        or a mapping carrying an "error" key when storage was unavailable or the
        sweep failed. The success shape is unchanged; the failure shape is now
        distinguishable, because returning the same empty mapping for "nothing
        to settle" and "the sweep crashed" hid a broken sweep behind a zero that
        read as "no change" (review R11-03). A failed sweep never fails the
        command.
    """
    conn = _store(gateway)
    if conn is None:
        return {"error": "storage unavailable"}
    try:
        counts = tickets.sweep(conn)
    except (db.StorageUnavailableError, sqlite3.Error) as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    return counts


def _sweep_line(counts: dict[str, Any]) -> str:
    """Render the summary line of one ticket maintenance sweep.

    Args:
        counts: tickets.sweep summary.

    Returns:
        A one-line summary in the key=value shape the rest of the audit uses.
    """
    expired = int(counts.get("expired", 0))
    invalidated = int(counts.get("invalidated", 0))
    return (
        f"ticket sweep expired={expired} invalidated={invalidated}"
        f" changed={int(counts.get('changed', 0))}"
    )


def _sweep_note(gateway: Any, actor: str) -> str:
    """Run the maintenance sweep and record it when it changed anything.

    Requirement: Operator Introspection; Approved Retry Outcome and Window. One
    audit row per command that actually settled a ticket, so the settled counts
    are traceable; a sweep that settled nothing writes nothing. Do not read that
    as "the command path is a pure read": an expired ticket is still a write. The
    narrow claim is that no command triggers the startup recovery sweep, which is
    the only sweep that reopens the approval gate (review R13-D2).

    Args:
        gateway: Gateway under inspection.
        actor: Administrator identity the row is attributed to.

    Returns:
        The audit-failure note, empty when the row was written or not needed.
    """
    counts = _sweep_summary(gateway)
    error = str(counts.get("error") or "")
    if error:
        return _SWEEP_FAILED_NOTE.format(error=_clip(error, 160))
    if int(counts.get("changed", 0)) <= 0:
        return ""
    failure = record_action(
        gateway,
        decision=Decision.ALLOW_PASSTHROUGH.value,
        summary=_sweep_line(counts),
        actor=actor,
        rule_id=_SWEEP_RULE,
        degraded=False,
    )
    return _audit_note(failure)


def _recovery_line(view: StartupSweepView, counts: dict[str, Any]) -> str:
    """Render the summary line of one explicit startup sweep recovery.

    Args:
        view: Startup sweep state right after the recovery ran.
        counts: tickets sweep summary; empty when the sweep raised.

    Returns:
        A one-line summary in the key=value shape the rest of the audit uses.
    """
    return (
        f"startup sweep recovery ok={'是' if view.ok else '否'}"
        f" attempts={view.attempts}"
        f" expired={int(counts.get('expired', 0))}"
        f" invalidated={int(counts.get('invalidated', 0))}"
        f" changed={int(counts.get('changed', 0))}"
    )


def _schedule_startup_sweep_alert(gateway: Any, view: StartupSweepView) -> None:
    """Ask the gateway to alert the administrators about a failed recovery.

    Requirement: Admin Alerting. The alert goes through the gateway because only
    it owns the administrator list and the shared rate limiter; the command face
    must not send anything itself. A gateway without the hook (a stand-in, or one
    whose notifier was never assembled) is silently tolerated: the reply already
    reports the failure.

    Args:
        gateway: Gateway that delivers the alert.
        view: Failed startup sweep state.

    Returns:
        None.
    """
    schedule = getattr(gateway, "schedule_startup_sweep_alert", None)
    if not callable(schedule):
        return
    with contextlib.suppress(Exception):
        schedule(attempts=view.attempts)


def _sweep_recovery(gateway: Any, actor: str) -> str:
    """Re-run the startup ticket sweep and reopen the approval side.

    Requirement: Ticket Persistence; Operator Introspection (review R11-03). This
    is the only command that writes startup sweep state, and it writes it exactly
    the way opening the store does: through db.recover_startup_sweep, with the
    process start instant as the cutoff. That cutoff is what makes the retry safe
    -- it withdraws only tickets an earlier process left behind, so this
    process's live tickets stay pending and no settled ticket is ever restored.
    It is rate limited per administrator and audited on the manual source.

    Args:
        gateway: Gateway owning the store.
        actor: Administrator identity the attempt is attributed to.

    Returns:
        The reply text describing what the recovery did.
    """
    admission = _RECOVERIES.admit(
        subject=actor,
        tool_name=_RECOVERY_TOOL,
        mode=_mode_token(gateway),
        decision=Decision.ALLOW_PASSTHROUGH.value,
        now=_mono(),
    )
    if not admission.send:
        return (
            f"启动清理未执行：同一管理员 {int(RECOVERY_WINDOW_S)} 秒内只允许一次恢复动作；"
            "批准闸门状态未变，请先用 /guard status 复核。"
        )
    conn = _store(gateway)
    if conn is None:
        return "启动清理未执行：审计存储不可用（fail-closed），本次未改动任何票据。"
    try:
        counts, state = db.recover_startup_sweep(conn)
    except Exception as exc:  # noqa: BLE001 - the store may be unusable
        return (
            f"启动清理未执行：读取存储失败（{type(exc).__name__}），"
            "本次未改动任何票据；批准闸门可能仍关闭。"
        )
    view = StartupSweepView(
        ok=bool(state.ok),
        attempts=int(state.attempts),
        error=str(state.error or ""),
        approvals_closed=not state.ok,
    )
    failure = record_action(
        gateway,
        decision=Decision.ALLOW_PASSTHROUGH.value,
        summary=_recovery_line(view, counts),
        actor=actor,
        rule_id=_RECOVERY_RULE,
        degraded=not view.ok,
    )
    if not view.ok:
        _schedule_startup_sweep_alert(gateway, view)
    lines = [_recovery_line(view, counts), _startup_sweep_line(view)]
    if view.ok:
        lines.append(
            "批准闸门已重新打开：本次只作废本进程启动前创建的 pending 与未消费 approved 票据；"
            "本进程创建的活票据保持原状态，已作废或已消费的票据不会被复活。"
        )
    else:
        lines.append(
            "恢复失败：批准侧仍关闭（find_approved 与 consume_approved 一律拒绝）。"
        )
    return "\n".join(lines) + _audit_note(failure)


@dataclass(frozen=True)
class _Refusal:
    """Outcome of one unauthorized /guard attempt.

    Requirement: Approver Authorization.

    Attributes:
        failure: Exception type name when the audit row could not be written.
        throttled: True when the attempt was folded into the current window and
            no audit row was written at all.
        suppressed: Attempts folded into this row that were never written.
    """

    failure: str | None = None
    throttled: bool = False
    suppressed: int = 0


def _record_refusal(gateway: Any, event: Any, command: Command) -> _Refusal:
    """Persist one unauthorized /guard attempt, at most once per window.

    Requirement: Approver Authorization. Only the audit table is touched: no
    ticket is read or written and no configuration changes, so a refused
    read-only command cannot alter any state. The row is admitted per subject by
    a REFUSAL_WINDOW_S window (notify.ratelimit.NotifyRateLimiter), because an
    unauthorized sender could otherwise write one audit row per attempt and
    inflate the store. Attempts that are not admitted are counted in memory and
    folded into the next admitted row as "suppressed=N", so no refusal fact is
    dropped: the next row of the same subject states how many were folded.

    Args:
        gateway: Gateway under inspection.
        event: Host event of the refused sender.
        command: Parsed command; only its name is recorded, never its arguments.

    Returns:
        The refusal outcome: whether the row was written, whether this attempt
        was throttled, and how many attempts this row absorbed.
    """
    subject = _refusal_subject(gateway, event)
    admission = _REFUSALS.admit(
        subject=subject,
        tool_name=_AUDIT_TOOL,
        mode=_mode_token(gateway),
        decision=Decision.DENY_REQUESTER.value,
        now=_mono(),
    )
    if not admission.send:
        return _Refusal(throttled=True)
    summary = _anonymizer(gateway).redact_head(
        f"unauthorized /guard {command.name or '-'}", SUMMARY_LIMIT
    )
    if admission.merged:
        summary = _clip(f"{summary} suppressed={int(admission.merged)}", SUMMARY_LIMIT)
    failure = record_action(
        gateway,
        decision=Decision.DENY_REQUESTER.value,
        summary=summary,
        actor=subject,
        rule_id=_REFUSAL_RULE,
        degraded=False,
    )
    return _Refusal(failure=failure, suppressed=int(admission.merged))


def _refusal_note(refusal: _Refusal) -> str:
    """Render the operator-facing note about refusal audit throttling.

    Requirement: Approver Authorization. The note is deliberately explicit: a
    refusal that was not written to the store is still reported, so the sender
    cannot read a silenced audit trail as a successful attempt.

    Args:
        refusal: Outcome of _record_refusal.

    Returns:
        The note, empty when the attempt was written and nothing was folded.
    """
    if refusal.throttled:
        return (
            f"\n注意：同类拒绝已限频（{int(REFUSAL_WINDOW_S)} 秒窗口内同一主体只写 1 条审计），"
            "本次仅在内存计数，未再写入审计；折叠次数会记在下一行的 suppressed。"
        )
    if refusal.suppressed:
        return (
            f"\n注意：本窗口另有 {refusal.suppressed} 次同类拒绝被压掉，"
            f"已记入本条审计行的 summary_line（suppressed={refusal.suppressed}）。"
        )
    return ""


def _mode_token(gateway: Any) -> str:
    """Return a mode token that cannot fail while refusing a sender.

    Args:
        gateway: Gateway under inspection.

    Returns:
        The effective mode, or "unknown" when it cannot be read.
    """
    with contextlib.suppress(Exception):
        value = _mode(gateway)
        if value:
            return value
    return "unknown"


def _refusal_subject(gateway: Any, event: Any) -> str:
    """Return the redacted, platform-neutral identity of a refused sender.

    Args:
        gateway: Gateway supplying the redactor.
        event: Host event of the refused sender.

    Returns:
        The redacted identity, or "anonymous" when the host exposes none.
    """
    platform = _accessor(event, "get_platform_id")
    sender = _accessor(event, "get_sender_id")
    subject = ":".join(part for part in (platform, sender) if part) or "anonymous"
    return _clip(redact_text(gateway, subject), STORE_REASON_LIMIT)


def _resolve(registry: Any, gateway: Any, ticket_id: str, decision: str) -> bool:
    """Wake the caller suspended on this ticket.

    Requirement: Approval Wait. The registry is memory-only, so a missing or
    already resolved entry is not an error.

    Args:
        registry: Explicit registry override.
        gateway: Gateway supplying its own registry.
        ticket_id: Ticket that was decided.
        decision: approved or denied.

    Returns:
        True when a suspended waiter was resolved.
    """
    target = registry if registry is not None else getattr(gateway, "registry", None)
    resolve = getattr(target, "resolve", None)
    if not callable(resolve):
        return False
    try:
        return bool(resolve(ticket_id, decision))
    except Exception:  # noqa: BLE001 - a failed resolve must not fail the command
        return False


def _admin_actor(gateway: Any, event: Any) -> str | None:
    """Return the administrator identity, or None when the sender is refused.

    Requirement: Approver Authorization. Two independent conditions must both
    hold, and either one failing refuses the sender:

    1. the host reports the sender as an administrator (event.is_admin()), and
    2. the sender identity (platform_id:sender_id) is named by the configured
       GatewayConfig.admins allowlist.

    event.is_admin() alone never authorizes: the host accessor is an assertion
    by the adapter, while the allowlist is the operator's own statement about
    who may approve tool calls. Neither is trusted alone.

    Args:
        gateway: Gateway owning the configuration and its admins allowlist.
        event: Host message event.

    Returns:
        The administrator identity string, or None when either condition fails.
        An event that exposes no identity is refused, because an identity that
        cannot be matched against the allowlist cannot be trusted.
    """
    if not _host_admin(event):
        return None
    actor = _event_origin(event)
    if not actor or not _listed_admin(gateway, actor):
        return None
    return actor


def _event_origin(event: Any) -> str:
    """Return the platform-neutral identity of a sender.

    Args:
        event: Host message event.

    Returns:
        "platform_id:sender_id", or "" when the host exposes no identity.
    """
    platform = _accessor(event, "get_platform_id")
    sender = _accessor(event, "get_sender_id")
    return ":".join(part for part in (platform, sender) if part)


def _admin_entries(gateway: Any) -> tuple[str, ...]:
    """Return the configured administrator identifiers.

    Requirement: Approver Authorization.

    Args:
        gateway: Gateway owning the configuration.

    Returns:
        The non-empty admins entries, empty when the configuration is
        unreadable (which refuses everybody rather than admitting everybody).
    """
    with contextlib.suppress(Exception):
        admins = getattr(getattr(gateway, "config", None), "admins", ()) or ()
        return tuple(str(entry).strip() for entry in admins if str(entry).strip())
    return ()


def _listed_admin(gateway: Any, actor: str) -> bool:
    """Report whether an identity is named by the configured admins allowlist.

    Requirement: Approver Authorization. Two configured shapes name an
    administrator, because policy/config.py accepts both:

    * a platform-qualified entry, either "platform:123" or the unified origin
      "platform:FriendMessage:123" -- matched only against the same platform_id
      and sender_id;
    * a bare "123" -- matched against the event sender_id alone, i.e. on every
      platform.

    The bare form is therefore wider than the operator may expect: the same
    sender_id on any platform becomes an approver. policy/config.py reports
    every such entry as the non-fatal advisory "bare_admin_entry" so the
    operator can tighten it to "platform:123". An entry whose colon-separated
    form has an empty segment ("platform:" / ":123") names nobody and is
    skipped.

    The rule itself lives in notify/sender.py is_admin_subject, which the
    gateway's suspension eligibility also calls: the command face grants an
    approval, the gateway path only grants the right to wait, and both must read
    the same list the same way.

    Args:
        gateway: Gateway owning the configuration.
        actor: Identity in "platform_id:sender_id" form.

    Returns:
        True when the identity is explicitly allowed.
    """
    return is_admin_subject(actor, _admin_entries(gateway))


#: Subcommand that reports the caller's own identity to every sender.
WHOAMI_COMMAND = "whoami"
#: Placeholder used when the host exposes no readable value for one field.
UNREADABLE = "未读到"
#: Advice shown by /guard whoami when this sender cannot use /guard.
_WHOAMI_ADVICE = (
    "建议：admins 条目写成 {platform}:<你的 id> 或裸 <你的 id>；"
    "宿主「管理员 ID」只填纯 UID。"
)


@dataclass(frozen=True, slots=True)
class _SenderFacts:
    """What /guard decides about one sender, read but never stored.

    Requirement: Approver Authorization; Operator Introspection.

    Attributes:
        subject: "platform_id:sender_id", or "" when the host exposes none.
        platform: Host platform id, or "".
        message_type: Chat type reported by the host, or UNREADABLE.
        sender: Host sender id, or "".
        listed: True when the configured admins allowlist names this sender.
        host_admin: True when the host's own is_admin() reports it.
    """

    subject: str
    platform: str
    message_type: str
    sender: str
    listed: bool
    host_admin: bool

    @property
    def allowed(self) -> bool:
        """Report whether both approval conditions hold for this sender."""
        return self.host_admin and self.listed


def _host_admin(event: Any) -> bool:
    """Return the host's own administrator assertion for one event.

    Requirement: Approver Authorization. This is the single reading of
    event.is_admin() on the command face: _admin_actor gates on it and
    /guard whoami reports it, so the two can never disagree about what the
    host said. A missing accessor, or one that raises, reads as "not an
    administrator" -- never as permission.

    Args:
        event: Host message event, possibly None.

    Returns:
        True only when the host accessor is present and truthy.
    """
    if event is None:
        return False
    flag = getattr(event, "is_admin", None)
    if flag is None:
        return False
    try:
        return bool(flag() if callable(flag) else flag)
    except Exception:  # noqa: BLE001 - a hostile event reads as not-admin
        return False


def _message_type(event: Any) -> str:
    """Return the chat type of one event, the way the host states it.

    Requirement: Sender Self-Identification. The host accessor returns a
    MessageType member, whose payload is the string the audit paths use
    ("FriendMessage" / "GroupMessage"); when the accessor is missing the middle
    segment of the unified message origin carries the same word. Nothing is
    guessed: an unreadable type says so instead of arriving as an empty string.

    Args:
        event: Host message event.

    Returns:
        The chat type token, or UNREADABLE.
    """
    reader = getattr(event, "get_message_type", None)
    value: Any = None
    if callable(reader):
        with contextlib.suppress(Exception):
            value = reader()
    token = str(getattr(value, "value", None) or value or "").strip()
    if token:
        return token
    with contextlib.suppress(Exception):
        parts = str(getattr(event, "unified_msg_origin", "") or "").split(":")
        if len(parts) >= 3 and parts[1]:
            return parts[1]
    return UNREADABLE


def _sender_facts(gateway: Any, event: Any) -> _SenderFacts:
    """Read every identity fact /guard uses about one sender.

    Requirement: Approver Authorization. Read-only by construction: it reads
    the event and the configuration allowlist and touches neither the store nor
    the ticket table, so both /guard whoami and the refusal diagnosis can call
    it on a path that must leave no trace.

    Args:
        gateway: Gateway owning the configuration allowlist.
        event: Host message event, possibly None.

    Returns:
        The facts of this sender; every unreadable field is spelled out.
    """
    platform = _accessor(event, "get_platform_id")
    sender = _accessor(event, "get_sender_id")
    subject = _event_origin(event)
    return _SenderFacts(
        subject=subject,
        platform=platform,
        message_type=_message_type(event),
        sender=sender,
        listed=bool(subject) and _listed_admin(gateway, subject),
        host_admin=_host_admin(event),
    )


def _verdict_line(facts: _SenderFacts) -> str:
    """Render whether this sender may use /guard, and why.

    Requirement: Sender Self-Identification. The two conditions are named in the
    same line as the verdict, so a sender refused by one of them cannot read the
    answer as an arbitrary denial.

    Args:
        facts: Facts of this sender.

    Returns:
        The verdict line.
    """
    return (
        f"插件名单命中 {'是' if facts.listed else '否'} · "
        f"宿主管理员 {'是' if facts.host_admin else '否'} · "
        f"能否使用 /guard {'是' if facts.allowed else '否'}（两个条件都需满足）"
    )


def _whoami_reply(gateway: Any, event: Any) -> str:
    """Render the read-only self-report of the calling sender.

    Requirement: Sender Self-Identification. Available to every sender, because the
    whole point is to answer "why was I not recognised as an administrator" --
    a refusal that a stranger cannot inspect is exactly the defect being fixed.
    Only the requester's own identity is reported: the configured allowlist
    answers "hit or not" and is never echoed, since its entries name other
    people.

    Args:
        gateway: Gateway owning the configuration allowlist.
        event: Host message event.

    Returns:
        The self-report lines.
    """
    facts = _sender_facts(gateway, event)
    lines = [
        (
            f"主体 {facts.subject or UNREADABLE} · 平台 id {facts.platform or UNREADABLE}"
            f" · 消息类型 {facts.message_type} · 发送者 id {facts.sender or UNREADABLE}"
        ),
        _verdict_line(facts),
    ]
    if not facts.allowed:
        lines.append(_WHOAMI_ADVICE.format(platform=facts.platform or UNREADABLE))
    return "\n".join(lines)


def _diagnosis_note(gateway: Any, event: Any) -> str:
    """Render the refusal diagnosis appended to the fixed refusal sentence.

    Requirement: Refusal Diagnosis. REFUSAL_TEXT keeps its exact first
    sentence (existing assertions and the e2e scenario read it verbatim); these
    lines say which half of the two-condition gate failed and which platform
    segment an allowlist entry must carry, so a platform mismatch stops looking
    like a blanket denial. An event that exposes no identity gets no diagnosis
    -- there is nothing true to say about it -- and the reply stays byte-equal
    to REFUSAL_TEXT. Allowlist entries are never printed.

    Args:
        gateway: Gateway owning the configuration allowlist.
        event: Host event of the refused sender, possibly None.

    Returns:
        The note, or "" when the sender has no readable identity.
    """
    facts = _sender_facts(gateway, event)
    if not facts.subject:
        return ""
    platform = facts.platform or UNREADABLE
    return (
        f"\n诊断：主体 {facts.subject} · 平台 id {platform}"
        f" · 名单命中 {'是' if facts.listed else '否'}"
        f" · 宿主管理员 {'是' if facts.host_admin else '否'}"
        f"；admins 条目平台段须等于 {platform}（写成 {platform}:<你的 id> 或裸 <你的 id>）。"
    )


def _accessor(event: Any, name: str) -> str:
    """Call one platform-neutral event accessor safely.

    Args:
        event: Host message event.
        name: Accessor name.

    Returns:
        The accessor result as text, or an empty string.
    """
    getter = getattr(event, name, None)
    if not callable(getter):
        return ""
    try:
        value = getter()
    except Exception:  # noqa: BLE001 - a hostile event has no identity
        return ""
    return "" if value is None else str(value)


def _anonymizer(gateway: Any) -> Anonymizer:
    """Return the gateway redactor, or the module fallback.

    Args:
        gateway: Gateway under inspection.

    Returns:
        An object exposing redact() and redact_head().
    """
    candidate = getattr(gateway, "anonymizer", None)
    if callable(getattr(candidate, "redact", None)) and callable(
        getattr(candidate, "redact_head", None)
    ):
        return candidate
    return _FALLBACK_ANONYMIZER


def redact_text(gateway: Any, text: str) -> str:
    """Redact one operator-supplied string.

    Args:
        gateway: Gateway supplying the redactor.
        text: Raw text.

    Returns:
        Redacted text.
    """
    try:
        return _anonymizer(gateway).redact(str(text))
    except Exception:  # noqa: BLE001 - redaction never breaks a reply
        return _FALLBACK_ANONYMIZER.redact(str(text))


def _store(gateway: Any) -> Any | None:
    """Open the gateway store, tolerating an unavailable backend.

    Args:
        gateway: Gateway owning the store.

    Returns:
        An open connection, or None when storage is unavailable.
    """
    try:
        return getattr(gateway, "store", None)
    except Exception:  # noqa: BLE001 - storage unavailable is a refusal, not a raise
        return None


def _mode(gateway: Any) -> str:
    """Return the effective gateway mode as text.

    Args:
        gateway: Gateway under inspection.

    Returns:
        The effective mode, or "unknown".
    """
    value = getattr(gateway, "mode", None)
    return str(value) if value else "unknown"


def _flag(gateway: Any, name: str) -> bool:
    """Read one boolean gateway flag without raising.

    Args:
        gateway: Gateway under inspection.
        name: Attribute name.

    Returns:
        The flag value, False when unreadable.
    """
    return bool(getattr(gateway, name, False))


def _warnings(gateway: Any) -> tuple[Any, ...]:
    """Return the configuration issues of this gateway.

    Fatal warnings come first, then the non-fatal advisories that never disable
    the gateway (policy/config.py reports a bare admin id as
    "bare_admin_entry"), so one status call shows both kinds.

    Args:
        gateway: Gateway under inspection.

    Returns:
        The issue tuple, empty when unavailable.
    """
    validation = getattr(gateway, "validation", None)
    fatal = tuple(getattr(validation, "warnings", ()) or ())
    advisories = tuple(getattr(validation, "advisories", ()) or ())
    return fatal + advisories


def _hook_degraded(gateway: Any) -> str | None:
    """Return why the last request hook round degraded, when it did.

    Args:
        gateway: Gateway under inspection.

    Returns:
        The degradation kind, or None when no round reported one.
    """
    value = getattr(gateway, "hook_degraded", None)
    return None if value is None else str(value)


def _judge_route(gateway: Any) -> str | None:
    """Return the configured judge route description.

    Args:
        gateway: Gateway under inspection.

    Returns:
        The route text, or None.
    """
    value = getattr(gateway, "judge_route", None)
    return None if value is None else str(value)


def _trust_line(gateway: Any) -> str:
    """Render the trust-switch line of /guard status.

    Requirement: Deep Analysis Sampling; Operator Introspection. The line states
    the switch it reads and nothing more: no counter of skipped deep reviews
    exists, so none is quoted.

    Args:
        gateway: Gateway under inspection.

    Returns:
        The line for the switch of the live policy snapshot.
    """
    snapshot = getattr(gateway, "snapshot", None)
    if getattr(snapshot, "trust_project_roots", False):
        return TRUST_ROOT_ON
    return TRUST_ROOT_OFF


def _jev_line(gateway: Any) -> str:
    """Render the fast-judge line of /guard status.

    Requirement: Fast Judge Observability. The line answers three questions from
    the one status view the Web face reads too: is the fast judge part of the
    pipeline, which backend the configured client actually speaks (never a
    hardcoded ``jev``), and which two bands plus confidence floor band a score.
    A closed line still reports the configured backend and bands -- the numbers
    say what would run -- but states outright that the model verdict took no
    part, so a switched-off judge is never read as a pass.

    Args:
        gateway: Gateway under inspection.

    Returns:
        The line for the fast-judge status.
    """
    status = read_fast_judge_status(gateway)
    if status is None:
        return JEV_LINE_UNREADABLE
    backend = status.backend or "未配置"
    bands = (
        f"后端={backend}，阈值 {status.allow_score}/{status.block_score}，"
        f"confidence 下限 {status.min_confidence:.2f}"
    )
    if status.enabled:
        return f"{JEV_LINE_ENABLED}{bands}）"
    return f"{JEV_LINE_DISABLED}jev_enabled=false，不发请求，模型判定未参与；{bands}）"


def _deep_line(gateway: Any) -> str:
    """Render the deep-reviewer switch line of /guard status.

    Requirement: Operator Introspection; Reviewer Registry. A gateway with no
    readable configuration built no client either, so it reads as closed rather
    than as a promise the assembly did not make.

    Args:
        gateway: Gateway under inspection.

    Returns:
        The line for the deep-reviewer switch.
    """
    config = getattr(gateway, "config", None)
    if config is not None and getattr(config, "llm_enabled", False):
        return DEEP_ON
    return DEEP_OFF


def _policy_version(gateway: Any) -> str | None:
    """Return the policy version recorded with the next audit row.

    Args:
        gateway: Gateway under inspection.

    Returns:
        The snapshot policy version, or None.
    """
    snapshot = getattr(gateway, "snapshot", None)
    value = getattr(snapshot, "policy_version", None)
    return None if value is None else str(value)


def _mode_meaning(mode: str) -> str:
    """Render the operator-facing meaning of one mode.

    Args:
        mode: Mode value.

    Returns:
        A one-clause explanation.
    """
    if mode == MODE_ENFORCE:
        return "enforce：危险调用将被拦截"
    if mode == MODE_OBSERVE:
        return "observe：仅观察，危险调用只记录不拦截"
    return "未知模式，按 fail-closed 处理"


def valid_ticket_id(value: str) -> bool:
    """Report whether the operator typed a plausible ticket identifier.

    Args:
        value: Candidate identifier.

    Returns:
        True when it is non-empty, short enough and shaped like a ticket id.
    """
    text = str(value or "").strip()
    if not text or len(text) > TICKET_ID_MAX:
        return False
    return all(char in _TICKET_ID_ALPHABET for char in text.lower())


def _ticket_views(pending: Iterable[Any]) -> list[TicketView]:
    """Project pending tickets onto the read-only ticket view contract.

    Requirement: Operator Introspection.

    Args:
        pending: Pending tickets, oldest first.

    Returns:
        At most PENDING_VIEW_LIMIT views.
    """
    views: list[TicketView] = []
    for ticket in list(pending)[:PENDING_VIEW_LIMIT]:
        views.append(
            TicketView(
                ticket_id=str(getattr(ticket, "ticket_id", "?")),
                state=str(getattr(ticket, "state", "?")),
                tool_name=str(getattr(ticket, "tool_name", "") or ""),
                created_at=str(getattr(ticket, "created_at", "") or ""),
            )
        )
    return views


def _format_counts(counts: dict[str, int], *, limit: int = 8) -> str:
    """Render a count mapping as "name n, name n".

    Args:
        counts: Mapping of label to count.
        limit: Maximum labels rendered.

    Returns:
        The rendered text, empty when there is nothing to count.
    """
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return "、".join(f"{name} {count}" for name, count in ordered[:limit])


def _clip(text: str | None, limit: int) -> str:
    """Cut text to a hard character limit with an ellipsis.

    Args:
        text: Candidate text.
        limit: Maximum length, ellipsis included.

    Returns:
        The clipped text, empty when there is nothing to cut.
    """
    value = "" if text is None else str(text)
    if len(value) <= limit:
        return value
    return value[: max(limit - 1, 0)] + "…"


def _late_disclosure_due(ticket_id: str, verb: str) -> bool:
    """Return True the first time one late decision is disclosed.

    Requirement: Late Decision Disclosure. The disclosure itself is mandatory;
    repeating it for the same ticket and the same verb is not, and repeating it
    is what made the audit log unreadable.

    Args:
        ticket_id: Ticket the late decision names.
        verb: Operator subcommand whose window had already closed.

    Returns:
        True when the caller should write the row, False when it already did.
    """
    key = (ticket_id, verb)
    if key in _late_seen:
        return False
    _late_seen[key] = None
    while len(_late_seen) > _LATE_SEEN_LIMIT:
        _late_seen.popitem(last=False)
    return True


def _audit_note(failure: str | None) -> str:
    """Render the audit-write failure note appended to a reply.

    Args:
        failure: Exception type name, or None on success.

    Returns:
        The note, empty when the audit row was written.
    """
    if failure is None:
        return ""
    return f"\n注意：审计写入失败（{failure}），请检查存储后再操作。"
