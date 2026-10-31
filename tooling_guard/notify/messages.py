"""Administrator notification rendering. Requirement: Notification Content.

Every fragment of a rendered message passes through the central anonymizer
before it is joined, so a rendered message is safe to persist, log, or deliver.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from ..anonymize import Anonymizer

FIELD_LIMIT = 200
"""Maximum characters kept for a single-line redacted field."""

ARG_SUMMARY_LIMIT = 400
"""Maximum characters kept for the redacted argument summary."""

MAX_RULES_SHOWN = 5
"""Maximum number of matched rule identifiers listed in a notification."""

VERB_LABELS: dict[str, str] = {
    "read": "读取",
    "write": "写入",
    "edit": "修改",
    "exec": "执行",
    "deliver": "外发",
    "fetch": "抓取",
    "query": "查询",
    "delegate": "委派",
    "call": "调用",
}
"""Chinese wording of the coarse verb, so a notice never prints a raw enum."""

TIER_LABELS: dict[str, str] = {
    "T-strong": "强",
    "T-weak": "弱",
    "unknown": "未定级",
}
"""Chinese wording of the tool tier label. The tiers only describe shape (0.6.0
stopped deriving decisions from them), so "未定级" is a fact, not a fault."""

TICKET_KIND_LINES: dict[str, str] = {
    "model_deny": (
        "为何要你决定：模型审查拒绝了这个调用，但它不在静态拒绝项内——"
        "这是一次高风险操作，放行必须由你显式同意。"
    ),
    "model_suspend": (
        "为何要你决定：模型审查无法自行给这个调用放行，需要你判断。"
    ),
    "all_abstain": (
        "为何要你决定：出现了一个非常规操作，模型没有给出明确结论，需要你判断。"
    ),
}
"""Reason line printed for each suspension cause.

Requirement: Layered Consensus. Only the static layer refuses a call on its own,
so every suspension comes from the models or from their silence; the notice says
which one it was instead of making the administrator guess from a decision word.
"""


def _text(value: Any) -> str:
    """Return a printable form of a value without raising.

    Args:
        value: Arbitrary object.

    Returns:
        The str() form when available, else a fixed marker.
    """
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:  # noqa: BLE001 - a broken __str__ must not break rendering
        return "<unprintable>"


def _as_anonymizer(anonymizer: Any) -> Any:
    """Return the redactor used for every rendered fragment.

    Args:
        anonymizer: An object providing redact, redact_mapping, and redact_head,
            typically an Anonymizer instance; None yields the default one.

    Returns:
        The redactor to use.
    """
    if anonymizer is None:
        return Anonymizer()
    return anonymizer


def _pick(event: Any, *names: str, default: Any = None) -> Any:
    """Return the first present field of an event description.

    Args:
        event: Mapping or plain object describing the suspension.
        *names: Candidate field names, in priority order.
        default: Value returned when no candidate is present.

    Returns:
        The first value that is not None.
    """
    for name in names:
        try:
            value = (
                event.get(name)
                if isinstance(event, Mapping)
                else getattr(event, name, None)
            )
        except Exception:  # noqa: BLE001 - a hostile attribute read is skipped
            value = None
        if value is not None:
            return value
    return default


def _field(anonymizer: Any, value: Any) -> str:
    """Render one redacted and truncated single-line field.

    Args:
        anonymizer: Active redactor.
        value: Raw field value.

    Returns:
        The redacted prefix of its printable form.
    """
    return anonymizer.redact_head(_text(value), FIELD_LIMIT)


def _label(table: Mapping[str, str], value: Any, default: str) -> str:
    """Return the display word of one enumerated field.

    Requirement: Notification Content. The gateway classifies by enum value
    ("exec", "T-strong"); a notification is read by a person, so it gets the
    Chinese word when the table has one and the raw value otherwise.

    Args:
        table: Enum value to display word.
        value: Raw field value, possibly None.
        default: Word used when the field is missing or empty.

    Returns:
        The display word.
    """
    key = _text(value).strip()
    if not key:
        return default
    return table.get(key, key)


def _rules_text(anonymizer: Any, rules: Any) -> str:
    """Render the matched rule identifiers as one redacted line.

    Args:
        anonymizer: Active redactor.
        rules: One rule identifier or a sequence of them.

    Returns:
        A comma-separated list, empty when nothing was matched.
    """
    if rules is None:
        return ""
    if isinstance(rules, str):
        items = [rules]
    else:
        try:
            items = [_text(item) for item in rules]
        except TypeError:
            items = [_text(rules)]
    shown = [item for item in items if item.strip()][:MAX_RULES_SHOWN]
    return ", ".join(anonymizer.redact_head(item, FIELD_LIMIT) for item in shown)


def _argument_summary(anonymizer: Any, arguments: Any) -> str:
    """Render the redacted, truncated argument summary of the call.

    Args:
        anonymizer: Active redactor.
        arguments: Tool arguments, mapping or any other value.

    Returns:
        A single-line redacted prefix, empty when there are no arguments.
    """
    if arguments is None:
        return ""
    if isinstance(arguments, Mapping):
        redacted = anonymizer.redact_mapping(arguments)
        try:
            rendered = json.dumps(
                redacted, ensure_ascii=False, sort_keys=True, default=_text
            )
        except Exception:  # noqa: BLE001 - fall back to the plain text form
            rendered = _text(redacted)
    else:
        rendered = anonymizer.redact(_text(arguments))
    return anonymizer.redact_head(rendered, ARG_SUMMARY_LIMIT)


def _decision_label(value: Any) -> str:
    """Return a readable label for a decision value.

    Args:
        value: Raw decision text.

    Returns:
        A Chinese label for a known decision, else the redacted raw text.
    """
    lowered = _text(value).strip().lower()
    if lowered == "approved":
        return "批准（approve）"
    if lowered == "denied":
        return "拒绝（deny）"
    return _text(value)


def render_admin_message(event: Any, *, anonymizer: Any) -> str:
    """Render the administrator notification of one suspended tool call.

    Requirement: Notification Content.

    Args:
        event: Mapping or object describing the suspension. Recognised fields,
            first present one wins: ticket_id/ticket, tool_name/tool, verb,
            tier, arguments/args, rule_ids/rules, decision/verdict/would_be,
            subject_key/subject, session_key/session, remaining_s/
            remaining_seconds, ticket_kind.
        anonymizer: The central anonymizer; every fragment is redacted.

    Returns:
        A Chinese notification body that contains no raw secret.
    """
    redactor = _as_anonymizer(anonymizer)
    ticket = _field(redactor, _pick(event, "ticket_id", "ticket", default="<unknown>"))
    tool = _field(redactor, _pick(event, "tool_name", "tool", default="<unknown>"))
    verb = _field(redactor, _label(VERB_LABELS, _pick(event, "verb"), "未知动作"))
    tier = _field(redactor, _label(TIER_LABELS, _pick(event, "tier"), "未定级"))
    decision = _decision_label(
        _pick(event, "decision", "verdict", "would_be", default="suspended")
    )
    rules = _rules_text(redactor, _pick(event, "rule_ids", "rules")) or "无"
    # Requirement: Verdict Aggregation.  The rule word is evidence only -- an
    # observe rule fires on calls it never blocks -- so the notice names the
    # layer that decided first, and the rules after it, labelled.
    # The layer is a fixed vocabulary word, so anything that is not text (an
    # attribution block, a number, None) renders as absent instead of as its repr.
    raw_layer = _pick(event, "layer", default="")
    layer = raw_layer.strip() if isinstance(raw_layer, str) else ""
    subject = _field(
        redactor, _pick(event, "subject_key", "subject", default="未知主体")
    )
    session = _field(
        redactor, _pick(event, "session_key", "session", default="未知会话")
    )
    remaining = _pick(event, "remaining_s", "remaining_seconds")
    left = f"{_field(redactor, remaining)} 秒" if remaining is not None else "未知"
    summary = _argument_summary(redactor, _pick(event, "arguments", "args"))
    kind = _text(_pick(event, "ticket_kind", default="")).strip().lower()
    why = TICKET_KIND_LINES.get(kind)

    # Six lines, one decision each: what is held, what it is, what it touches,
    # who it is for, how to answer, and what this gateway does not cover.
    lines = [f"[工具网关] 挂起等待（不是拒绝），等你决定｜票据：{ticket}"]
    described = f"工具 {tool} · 动作 {verb} · 层级 {tier} · 判定 {decision}"
    if layer:
        described = f"{described} · 归因 {_field(redactor, layer)}"
    lines.append(f"{described} · 命中规则 {rules}")
    if why:
        lines.append(why)
    if summary:
        lines.append(f"目标/参数 {summary}")
    lines.append(f"主体 {subject} · 会话 {session} · 剩余 {left}")
    short = _short_code(ticket)
    hint = "回复「同意」批准或「拒绝 原因」拒绝"
    if short:
        hint = f"回复「同意 {short}」批准或「拒绝 {short} 原因」拒绝"
    # The command sits inside corner brackets on purpose: the delivery path runs
    # a whitespace-token path redactor, and a bare "/guard" would come out as
    # "<EXT>/guard". Glued to the bracket it stays a literal command.
    lines.append(f"{hint}；等价命令「/guard approve {ticket}」。")
    lines.append("覆盖：cron/后台唤醒与子 agent 内部调用不在本网关内。")
    return "\n".join(lines)


def _short_code(ticket: str) -> str:
    """Return the ticket short code a reply names, or "" when there is none.

    Requirement: Reply Approval Channel. The notice prints the short code so the
    administrator can answer without copying a uuid; a placeholder ticket (an
    unreadable event) prints no code at all rather than a meaningless prefix.

    Args:
        ticket: Rendered ticket identifier.

    Returns:
        The first eight characters, or "" for a placeholder.
    """
    stripped = str(ticket or "").strip()
    if not stripped or "<" in stripped:
        return ""
    return stripped[:8]


def render_late_notice(
    event: Any = None,
    *,
    anonymizer: Any = None,
    ticket_id: Any = None,
    decision: Any = None,
    state: Any = None,
    reason: Any = None,
) -> str:
    """Render the notice sent when a decision arrived after the budget.

    Requirement: Late Decision Disclosure.

    Args:
        event: Mapping or object describing the late decision, optional when the
            explicit arguments below are given.
        anonymizer: The central anonymizer.
        ticket_id: Ticket identifier, overriding the event field.
        decision: The late decision, overriding the event field.
        state: Current ticket state, overriding the event field.
        reason: Extra explanation, overriding the event field.

    Returns:
        A Chinese notice that states the decision was rejected and the ticket
        state is unchanged.
    """
    redactor = _as_anonymizer(anonymizer)
    ticket = _field(
        redactor,
        ticket_id
        if ticket_id is not None
        else _pick(event, "ticket_id", "ticket", default="<unknown>"),
    )
    current = _field(
        redactor,
        state
        if state is not None
        else _pick(event, "state", "current_state", default="timeout"),
    )
    late = _field(
        redactor,
        decision
        if decision is not None
        else _pick(event, "decision", default="<unknown>"),
    )
    detail = reason if reason is not None else _pick(event, "reason", default="")
    lines = [
        f"[工具网关] 迟到决定未生效｜票据：{ticket}",
        f"当前状态 {current} · 收到的迟到决定 {_decision_label(late)}",
        "处理：票据状态保持不变，批准不会复活授权；如仍需执行请让 agent 重新发起同一调用。",
    ]
    if detail:
        lines.append(f"（{_field(redactor, detail)}）")
    return "\n".join(lines)


def render_delivery_failure_notice(
    event: Any = None,
    *,
    anonymizer: Any = None,
    ticket_id: Any = None,
    error: Any = None,
    attempts: Any = None,
) -> str:
    """Render the notice sent when the administrator channel could not deliver.

    Requirement: Notification Delivery Failure.

    Args:
        event: Mapping or object describing the delivery failure, optional when
            the explicit arguments below are given.
        anonymizer: The central anonymizer.
        ticket_id: Ticket identifier, overriding the event field.
        error: Delivery error text, overriding the event field.
        attempts: Number of delivery attempts, overriding the event field.

    Returns:
        A Chinese notice that states delivery failure is not consent and the
        call still times out.
    """
    redactor = _as_anonymizer(anonymizer)
    ticket = _field(
        redactor,
        ticket_id
        if ticket_id is not None
        else _pick(event, "ticket_id", "ticket", default="<unknown>"),
    )
    detail = error if error is not None else _pick(event, "error", "reason", default="")
    tries = attempts if attempts is not None else _pick(event, "attempts")
    lines = [f"[工具网关] 通知投递失败（不等于放行）｜票据：{ticket}"]
    if tries is not None:
        tail = f"：{_field(redactor, detail)}" if detail else ""
        lines.append(f"尝试 {_field(redactor, tries)} 次{tail}")
    elif detail:
        lines.append(f"失败原因：{_field(redactor, detail)}")
    lines.append(
        "处理：调用继续挂起，预算耗尽后按超时拒绝并记 notify_failed；"
        "可用 /guard status 查票，或 /guard approve、/guard deny 处理。"
    )
    return "\n".join(lines)


def render_canceled_notice(
    event: Any = None,
    *,
    anonymizer: Any = None,
    ticket_id: Any = None,
    state: Any = None,
) -> str:
    """Render the closing notice of a ticket closed by outer cancellation.

    Requirement: External Cancellation Degradation.

    Args:
        event: Mapping or object describing the cancelled suspension, optional
            when the explicit arguments below are given.
        anonymizer: The central anonymizer.
        ticket_id: Ticket identifier, overriding the event field.
        state: Current ticket state, overriding the event field.

    Returns:
        A Chinese notice that states the call was cancelled from outside, the
        ticket closed unexecuted and no approval can apply to it.
    """
    redactor = _as_anonymizer(anonymizer)
    ticket = _field(
        redactor,
        ticket_id
        if ticket_id is not None
        else _pick(event, "ticket_id", "ticket", default="<unknown>"),
    )
    current = _field(
        redactor,
        state
        if state is not None
        else _pick(event, "state", "current_state", default="canceled_external"),
    )
    tool = _field(redactor, _pick(event, "tool_name", "tool", default=""))
    subject = _field(redactor, _pick(event, "subject_key", "subject", default=""))
    session = _field(redactor, _pick(event, "session_key", "session", default=""))
    arguments = _pick(event, "arguments", "args")
    facts = [
        f"状态 {current}",
        f"工具 {tool}" if tool else "",
        f"主体 {subject}" if subject else "",
        f"会话 {session}" if session else "",
    ]
    lines = [
        f"[工具网关] 外层取消：票据已关闭，本次未执行｜票据：{ticket}",
        " · ".join(part for part in facts if part),
    ]
    summary = _argument_summary(redactor, arguments)
    if summary:
        lines.append(f"参数 {summary}")
    lines.append("处理：请求中断或平台超时，本次从未执行；该票据的批准不再适用。")
    return "\n".join(lines)


MERGED_NOTICE_TEMPLATE = "另有 {count} 条同目标同类告警在限频窗口内被合并。"
"""Line appended to a delivered notice that absorbed earlier alerts."""


def render_merged_notice(count: Any) -> str:
    """Return the merged-count line of one delivered notification.

    Requirement: Rate Limiting and Merging.

    Args:
        count: Alerts suppressed since the last delivery of this class.

    Returns:
        One Chinese line naming the merged count, or the empty string when
        nothing was merged.  The count comes from the limiter itself, so it
        carries no user text and needs no further redaction.
    """
    try:
        value = int(count)
    except (TypeError, ValueError):
        return ""
    if value <= 0:
        return ""
    return MERGED_NOTICE_TEMPLATE.format(count=value)


__all__ = [
    "MERGED_NOTICE_TEMPLATE",
    "render_admin_message",
    "render_canceled_notice",
    "render_delivery_failure_notice",
    "render_late_notice",
    "render_merged_notice",
]
