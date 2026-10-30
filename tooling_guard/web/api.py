"""JSON endpoints the dashboard plugin page calls.

Requirement: Plugin Page Presence; Read Filtering; Visibility Scope; Approval
Authority; Audit Trail.

Every handler is a thin adapter over a shared core. Identity is read from the
host-injected `PluginRequest.username` (never a cookie, a header or a body
field); rows come from the store read helpers through `web.queries`; and an
approval is the very same `ui.commands.decide_ticket` call `/guard approve`
makes, so the two channels share one state transition and one late-decision
path instead of growing two. Nothing here opens a port, calls sqlite or decides
whether a tool may run.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable
from typing import Any

from ..notify.ratelimit import NotifyRateLimiter
from ..store import audit, tickets
from ..triage.decisions import Decision
from ..ui import commands
from . import queries

#: Audit `tool_name` of every row this surface writes; it is what separates the
#: web card from the `/guard` command plane.
AUDIT_TOOL = "/guard/web"

#: Rule id of an unauthorized attempt, read or decision.
REFUSAL_RULE = "guard_web_deny_requester"

#: Audit `actor` of a request that carried no host-injected identity.
NO_IDENTITY = "<no-identity>"

#: Refusal window of the read surface: one row per subject and action per window.
#: The window length is not restated here — it is whatever the command plane
#: already uses, so the two surfaces cannot drift apart.
REFUSAL_WINDOW_S = commands.REFUSAL_WINDOW_S

#: Actionable answer to a request that arrived without a dashboard identity.
#: It is a payload field, never an audit row: the refusal row is written by
#: `_read_refusal` and the notice only tells the operator what to do about it.
READ_NOTICE = (
    "拿不到 dashboard 登录身份（request.username 为空），因此拒绝读取；"
    "请从 AstrBot 面板登录后再打开本页。"
)

#: Decision-face refusal of a request that carried no identity at all. The only
#: actionable step is logging in, so it must not hide behind 「仅管理员」: this
#: caller was not judged against the list, it has no name to judge.
REFUSAL_NO_IDENTITY = (
    "本次请求没有宿主注入的 dashboard 用户名，无法判断批准权限；"
    "请从本机登录 AstrBot 仪表盘后重试。本次未改动任何票据。"
)

#: Decision-face refusal of an identified user the non-empty
#: `web_admin_usernames` list does not carry. The caller was named, just not
#: authorized, so the wording is about authority and never about identity.
REFUSAL_NOT_ADMIN = "仅管理员可以批准或拒绝，本次未改动任何票据。"

#: Rows of a ticket detail payload.
DETAIL_ROW_LIMIT = 20

#: The handler result: an HTTP status code plus the JSON payload.
Result = tuple[int, dict[str, Any]]

#: Builds the host response object from a handler result.
Responder = Callable[[int, dict[str, Any]], Any]


def host_responder(status_code: int, payload: dict[str, Any]) -> Any:
    """Turn one handler result into the host JSON envelope.

    Requirement: Plugin Page Presence. The dashboard bridge resolves
    `response.data.data` and raises when `response.data.status` is "error", so a
    refusal must come back through `error_response`.

    Args:
        status_code: HTTP status the handler chose.
        payload: JSON payload of the answer.

    Returns:
        The host response object.
    """
    from astrbot.api.web import error_response, json_response

    if status_code >= 400:
        return error_response(
            str(payload.get("message") or "请求被拒绝。"),
            status_code=status_code,
            data=payload,
        )
    return json_response({"status": "ok", "data": payload}, status_code=status_code)


def _request() -> Any:
    """Return the host request bound to the current handler."""
    from astrbot.api.web import request

    return request


def _identity(request: Any) -> str:
    """Return the host-injected dashboard username, trimmed."""
    value = getattr(request, "username", None)
    return value.strip() if isinstance(value, str) else ""


def _store(gateway: Any) -> Any:
    """Return the gateway store, or None when storage is unavailable."""
    with contextlib.suppress(Exception):
        return getattr(gateway, "store", None)
    return None


def _unavailable() -> Result:
    """Return the answer used when the store cannot be read."""
    return 503, {"message": "审计存储不可用，无法读写票据与审计行（fail-closed）。"}


def _record_refusal(
    gateway: Any,
    actor: str,
    action: str,
    *,
    ticket_id: str | None = None,
    suppressed: int = 0,
) -> str | None:
    """Write the `deny_requester` row of one unauthorized attempt.

    Requirement: Visibility Scope; Approval Authority; Audit Trail. Reads and
    decisions are both audited; the summary names the action only, never a
    request body, and the caller is responsible for not having touched a ticket.

    Decisions are never throttled. An approve or deny from a request that may
    not decide is one real attempt to cross an authority boundary, and folding
    two of them into one row would hide exactly the sequence an operator reads
    the table for. Only the read surface folds repeats, and it does so in
    `_read_refusal` before reaching this function.

    Args:
        gateway: Gateway owning the audit writer.
        actor: Host-injected dashboard username, possibly empty.
        action: Short action description.
        ticket_id: Ticket the attempt named, when it named one.
        suppressed: Refusals folded into this row since the last admitted one.

    Returns:
        None on success, or the audit failure kind.
    """
    summary = f"web {action} refused"
    if suppressed:
        summary = f"{summary} suppressed={suppressed}"
    return commands.record_action(
        gateway,
        decision=Decision.DENY_REQUESTER.value,
        summary=summary,
        actor=actor or NO_IDENTITY,
        ticket_id=ticket_id,
        rule_id=REFUSAL_RULE,
        source=audit.SOURCE_WEB,
        tool_name=AUDIT_TOOL,
    )


def _mono() -> float:
    """Return the clock the read limiter reads.

    Requirement: Audit Trail. One narrow, patchable function: a test that proves
    the fold counter without sleeping rebinds this symbol, exactly as
    `ui.commands._mono` is rebound by its own suite.
    """
    return time.monotonic()


def _mode_token(gateway: Any) -> str:
    """Return the gateway mode used to key the read limiter."""
    mode = getattr(gateway, "mode", "")
    return mode if isinstance(mode, str) else ""


#: Read-surface refusal limiter. Reads fold because an identity-less page
#: reloads on its own; decisions never touch it.
_READ_REFUSALS = NotifyRateLimiter(window_s=REFUSAL_WINDOW_S)


def _read_refusal(
    gateway: Any, actor: str, action: str, *, ticket_id: str | None = None
) -> int:
    """Write the refusal row of one unauthorized read, at most once per window.

    Requirement: Audit Trail. A page that may read nothing retries on its own, so
    one row per attempt buries the audit table in repeats of the same line. The
    limiter folds them and the next admitted row carries `suppressed=N`.

    Identity and action both key the limiter. The subject is the host-injected
    username (`NO_IDENTITY` when there is none), and the action travels in the
    limiter's `decision` slot rather than in `tool_name`, which stays
    `AUDIT_TOOL` for every row this surface writes — folding the action into
    `tool_name` would misreport that audit column to save nothing. Distinct
    actions therefore never suppress each other: one page load that reads the
    event list and the ticket list writes two rows, because they are two
    actions. The ticket id is deliberately kept out of the key, so one identity
    probing many ticket ids still folds into one row.

    Args:
        gateway: Gateway owning the audit writer.
        actor: Host-injected dashboard username, possibly empty.
        action: Short action description.
        ticket_id: Ticket the attempt named, when it named one.

    Returns:
        Refusals folded into this row; 0 when it was folded into an earlier one.
    """
    admission = _READ_REFUSALS.admit(
        subject=actor or NO_IDENTITY,
        tool_name=AUDIT_TOOL,
        mode=_mode_token(gateway),
        decision=action,
        now=_mono(),
    )
    if not admission.send:
        return 0
    _record_refusal(
        gateway, actor, action, ticket_id=ticket_id, suppressed=admission.merged
    )
    return admission.merged


async def handle_events(gateway: Any, request: Any) -> Result:
    """Answer one audit list request.

    Requirement: Read Filtering; Visibility Scope; Audit Trail. A request without
    a host-injected identity reads nothing, says what the operator should do
    about it, and leaves one `deny_requester` row per refusal window; a read
    never writes an `allow_*` row.

    Args:
        gateway: Gateway under inspection.
        request: Bound host request.

    Returns:
        Status code and payload.
    """
    username = _identity(request)
    scope = queries.resolve_scope(gateway, username)
    if scope.reads_nothing:
        _read_refusal(gateway, username, "events read")
        return 200, {
            "events": [],
            "total": 0,
            "limit": queries.LIMIT_DEFAULT,
            "offset": 0,
            "notice": READ_NOTICE,
            "scope": scope.payload(),
        }
    try:
        filters = queries.parse_event_filters(
            getattr(request, "query", None), scope=scope
        )
    except queries.QueryError as exc:
        return 400, {"message": str(exc)}
    conn = _store(gateway)
    if conn is None:
        return _unavailable()
    try:
        rows, total = queries.read_events(conn, filters)
    except (audit.StorageUnavailableError, ValueError):
        return _unavailable()
    return 200, {
        "events": [queries.serialize_event(gateway, row) for row in rows],
        "total": total,
        "limit": filters.limit,
        "offset": filters.offset,
        "scope": scope.payload(),
    }


async def handle_tickets(gateway: Any, request: Any) -> Result:
    """Answer the pending-ticket list request.

    Requirement: Read Filtering; Visibility Scope. The subject restriction is
    applied by `tickets.list_pending` (SQL `WHERE`), not by trimming the answer
    afterwards, and only a `web_subject_map` entry supplies one — an identified
    user the map does not name sees every subject.

    Args:
        gateway: Gateway under inspection.
        request: Bound host request.

    Returns:
        Status code and payload.
    """
    username = _identity(request)
    scope = queries.resolve_scope(gateway, username)
    if scope.reads_nothing:
        _read_refusal(gateway, username, "tickets read")
        return 200, {
            "tickets": [],
            "total": 0,
            "notice": READ_NOTICE,
            "scope": scope.payload(),
        }
    conn = _store(gateway)
    if conn is None:
        return _unavailable()
    try:
        pending = tickets.list_pending(conn, subject_key=scope.subject_key)
    except audit.StorageUnavailableError:
        return _unavailable()
    return 200, {
        "tickets": [
            queries.serialize_ticket(gateway, item)
            for item in pending[: queries.LIMIT_MAX]
        ],
        "total": len(pending),
        "scope": scope.payload(),
    }


async def handle_ticket(gateway: Any, request: Any, *, ticket_id: str) -> Result:
    """Answer one ticket detail request.

    Requirement: Visibility Scope. A row of another subject answers exactly like
    a missing one, so the response cannot reveal that it exists, and reaching
    that branch leaves a row every time: asking for a foreign ticket id is a
    probe, not a page reload, so it is not folded.

    Args:
        gateway: Gateway under inspection.
        request: Bound host request.
        ticket_id: Ticket named by the path.

    Returns:
        Status code and payload.
    """
    username = _identity(request)
    scope = queries.resolve_scope(gateway, username)
    if scope.reads_nothing:
        _read_refusal(gateway, username, "ticket read", ticket_id=ticket_id or None)
        return 404, {"message": "未找到票据。", "notice": READ_NOTICE}
    if not commands.valid_ticket_id(ticket_id):
        return 400, {"message": "票据 id 不合法。"}
    conn = _store(gateway)
    if conn is None:
        return _unavailable()
    try:
        ticket = tickets.get_ticket(conn, ticket_id)
        if ticket is None:
            return 404, {"message": "未找到票据。"}
        if not queries.ticket_visible(ticket, scope):
            _record_refusal(gateway, username, "ticket read", ticket_id=ticket_id)
            return 404, {"message": "未找到票据。"}
        transitions = tickets.list_transitions(conn, ticket_id)
        related = audit.query_by_ticket(conn, ticket_id, limit=DETAIL_ROW_LIMIT)
    except (audit.StorageUnavailableError, ValueError):
        return _unavailable()
    return 200, {
        "ticket": queries.serialize_ticket(gateway, ticket),
        "transitions": [
            queries.serialize_transition(gateway, row)
            for row in transitions[-DETAIL_ROW_LIMIT:]
        ],
        "audit": [queries.serialize_event(gateway, row) for row in related],
        "context": queries.serialize_call_context(
            gateway, queries.pick_ticket_event(related)
        ),
        "scope": scope.payload(),
    }


async def _body_reason(request: Any) -> str | None:
    """Read the optional denial reason from the request body.

    Args:
        request: Bound host request.

    Returns:
        The trimmed reason, or None when the body has none.
    """
    reader = getattr(request, "json", None)
    if not callable(reader):
        return None
    body = await reader({})
    if not isinstance(body, dict):
        return None
    raw = body.get("reason")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()[: queries.REASON_LIMIT]
    return None


async def handle_decision(
    gateway: Any, request: Any, *, ticket_id: str, approve: bool
) -> Result:
    """Approve or deny one ticket, or refuse without touching it.

    Requirement: Approval Authority; Audit Trail. Only a name the non-empty
    `web_admin_usernames` list carries may decide; an empty list lets any
    logged-in user decide, and a request with no identity is never an
    administrator. A refusal returns before the ticket is read, so `state`,
    `approved_at` and `retry_consumed` cannot change, and every refusal leaves
    its own row — decisions are never folded. An authorized decision is the same
    `decide_ticket` call the command plane makes (same CAS, same one-shot
    window, same late path), only with the web source marker.

    Args:
        gateway: Gateway owning the store and the approval registry.
        request: Bound host request.
        ticket_id: Ticket named by the path.
        approve: True to approve, False to deny.

    Returns:
        Status code and payload.
    """
    username = _identity(request)
    scope = queries.resolve_scope(gateway, username)
    verb = "approve" if approve else "deny"
    if not scope.admin:
        _record_refusal(
            gateway,
            username,
            f"{verb} {ticket_id}".strip(),
            ticket_id=ticket_id or None,
        )
        return 403, {
            "ticket_id": ticket_id,
            "message": REFUSAL_NOT_ADMIN if scope.username else REFUSAL_NO_IDENTITY,
        }
    if not commands.valid_ticket_id(ticket_id):
        return 400, {"message": "票据 id 不合法。"}
    reason = None if approve else await _body_reason(request)
    result = commands.decide_ticket(
        gateway,
        ticket_id,
        approve=approve,
        actor=username,
        reason=reason,
        source=audit.SOURCE_WEB,
        tool_name=AUDIT_TOOL,
    )
    payload = {
        "ticket_id": ticket_id,
        "status": result.status,
        "state": result.state,
        "woke": result.woke,
        "audit_failure": result.audit_failure,
        "message": result.message,
    }
    if result.status == "decided":
        return 200, payload
    if result.status == "missing":
        return 404, payload
    if result.status == "late":
        return 409, payload
    if result.status == "unavailable":
        return 503, payload
    return 500, payload


async def handle_status(gateway: Any, request: Any) -> Result:
    """Answer the status request from the gateway's single status source.

    Requirement: Observability. Mode, enabled flag, judge route, the reviewer
    table and the startup ticket sweep state all come from the gateway itself; no
    second derivation is computed here, and the raw reviewer error is never
    echoed. The sweep state is read through commands.startup_sweep_view, the same
    reader the text reply uses, so the two faces cannot disagree; reading it never
    runs a sweep (review R11-03). The fast judge block is read through
    commands.read_fast_judge_status -- the reader behind the text face's line --
    for the same reason: the backend and the two bands have exactly one home.

    Args:
        gateway: Gateway under inspection.
        request: Bound host request.

    Returns:
        Status code and payload.
    """
    username = _identity(request)
    if not username:
        return 401, {"message": "未授权：请求缺少宿主注入的 dashboard 用户名。"}
    scope = queries.resolve_scope(gateway, username)
    reviewers = [
        queries.serialize_reviewer(gateway, item)
        for item in commands.read_reviewer_statuses(gateway)
    ]
    hook_degraded = getattr(gateway, "hook_degraded", None)
    sweep = commands.startup_sweep_view(gateway)
    fast_judge = queries.serialize_fast_judge(commands.read_fast_judge_status(gateway))
    return 200, {
        "mode": str(getattr(gateway, "mode", "") or "unknown"),
        "enabled": bool(getattr(gateway, "enabled", False)),
        "judge_route": getattr(gateway, "judge_route", None),
        "hook_degraded": hook_degraded,
        # Fixed keys: {"ok", "attempts", "error", "approvals_closed"}, or None
        # when no store was reachable and the state is therefore unknown.
        "startup_sweep": sweep.as_dict() if sweep is not None else None,
        # Fixed keys: available / enabled / backend / allow_score /
        # block_score / min_confidence; available=False and enabled=False when
        # the gateway cannot answer, never a missing block.
        "fast_judge": fast_judge,
        "web_admin": scope.admin,
        "reviewers": reviewers,
        "degraded": [
            item["last_degraded"] for item in reviewers if item["last_degraded"]
        ],
    }


def make_views(
    plugin_name: str, gateway: Any, respond: Responder
) -> tuple[tuple[str, str, Any, str], ...]:
    """Build the registered route table of this plugin.

    Requirement: Plugin Page Presence. The host hands a handler only the path
    parameters (`view_handler(**path_values)`), so each view closes over the
    gateway and reads the request through the host proxy. Routes are prefixed
    with the plugin directory name because the dashboard subpath always starts
    with it; the page therefore calls `guard/api/...`.

    Args:
        plugin_name: Plugin directory name, as the host sees it.
        gateway: Gateway the handlers answer from.
        respond: Builder of the host response object.

    Returns:
        Tuples of route, method, handler and description.
    """
    base = f"/{plugin_name}/guard/api"

    async def events_view(**_path: str) -> Any:
        return respond(*await handle_events(gateway, _request()))

    async def tickets_view(**_path: str) -> Any:
        return respond(*await handle_tickets(gateway, _request()))

    async def ticket_view(**_path: str) -> Any:
        ticket_id = str(_path.get("ticket_id") or "")
        return respond(*await handle_ticket(gateway, _request(), ticket_id=ticket_id))

    async def approve_view(**_path: str) -> Any:
        ticket_id = str(_path.get("ticket_id") or "")
        return respond(
            *await handle_decision(
                gateway, _request(), ticket_id=ticket_id, approve=True
            )
        )

    async def deny_view(**_path: str) -> Any:
        ticket_id = str(_path.get("ticket_id") or "")
        return respond(
            *await handle_decision(
                gateway, _request(), ticket_id=ticket_id, approve=False
            )
        )

    async def status_view(**_path: str) -> Any:
        return respond(*await handle_status(gateway, _request()))

    return (
        (
            f"{base}/events",
            "GET",
            events_view,
            "受管调用审计行（脱敏，按可见范围过滤）",
        ),
        (f"{base}/tickets", "GET", tickets_view, "挂起票据列表（按可见范围过滤）"),
        (
            f"{base}/tickets/<ticket_id>",
            "GET",
            ticket_view,
            "单张票据详情、状态迁移历史与相关审计行",
        ),
        (
            f"{base}/tickets/<ticket_id>/approve",
            "POST",
            approve_view,
            "批准挂起票据（仅管理员，与 /guard approve 同一 CAS）",
        ),
        (
            f"{base}/tickets/<ticket_id>/deny",
            "POST",
            deny_view,
            "拒绝挂起票据（仅管理员，与 /guard deny 同一 CAS）",
        ),
        (f"{base}/status", "GET", status_view, "网关模式、审查器与最近降级"),
    )


def register_web_apis(
    register: Callable[..., None],
    plugin_name: str,
    gateway: Any,
    respond: Responder = host_responder,
) -> tuple[str, ...]:
    """Register every web API through the host's `register_web_api`.

    Requirement: Plugin Page Presence. The host replaces an entry registered
    with the same route and methods, so a second construction cannot
    double-register a route.

    Args:
        register: The host's `register_web_api` bound method.
        plugin_name: Plugin directory name, as the host sees it.
        gateway: Gateway the handlers answer from.
        respond: Builder of the host response object.

    Returns:
        The registered routes, in registration order.
    """
    routes: list[str] = []
    for route, method, handler, desc in make_views(plugin_name, gateway, respond):
        register(route, handler, [method], desc)
        routes.append(route)
    return tuple(routes)


__all__ = [
    "AUDIT_TOOL",
    "REFUSAL_RULE",
    "handle_decision",
    "handle_events",
    "handle_status",
    "handle_ticket",
    "handle_tickets",
    "host_responder",
    "make_views",
    "register_web_apis",
]
