"""Read-side filtering, redaction and serialization for the dashboard page.

Requirement: Read Filtering; Visibility Scope; Audit Trail.

The web card answers exactly one extra question compared with the command
plane: who may read which row. It decides nothing about a tool call, opens no
socket and never touches sqlite directly - rows come from the store read
helpers (`store.audit.query_events`, `store.tickets.list_pending`) and every
value leaves the process only after `ui.commands.redact_text`. The columns that
carry argument text or an argument digest (`summary_json`, `args_digest`) are
dropped instead of serialized.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from ..notify.messages import TIER_LABELS, VERB_LABELS
from ..store import audit, db, tickets
from ..triage.decisions import Decision
from ..ui.commands import redact_text
from ..ui.contracts import FastJudgeStatus

#: Page size used when the request names none, and the hard ceiling.
LIMIT_DEFAULT = 50
LIMIT_MAX = 200

#: Default and maximum width of one read window, in seconds.
WINDOW_DEFAULT_S = 86_400
WINDOW_MAX_S = 7 * 86_400

#: Longest string echoed back to the browser, and the longest stored reason.
FIELD_LIMIT = 200
REASON_LIMIT = 200

#: Audit columns a response may carry. Argument text and digests are absent by
#: construction: `summary_json` is never selected for output at all.
EVENT_FIELDS: tuple[str, ...] = (
    "id",
    "ts",
    "decision",
    "would_be",
    "rule_id",
    "tool_name",
    "subject_key",
    "session_key",
    "ticket_id",
    "policy_version",
    "summary_line",
    "source",
    "degraded",
    "judge_route",
    "rule_set_version",
    "labels",
    "delegated",
)

#: Event fields that may quote call text, so they are redacted before output.
EVENT_TEXT_FIELDS = frozenset({"summary_line"})

#: Marker prefix the gateway writes on an audit summary line to carry the policy
#: layer a verdict came from. The table has no layer column, and its rule_id
#: column is evidence -- an observe rule such as R8 fires on calls it never
#: blocks -- so the wire form derives the attribution from this marker.
LAYER_MARKER = "layer="

#: Longest argument head the approval panel shows; matches trace/summary.py.
ARGS_HEAD_LIMIT = 512

#: Trajectory summary keys the approval panel reads, as (summary key, wire key).
#: The record keeps the redacted head of the arguments as `args_head` -- there is
#: no `arguments` key -- so the panel used to render an empty "参数" for every
#: ticket it opened; the wire key stays `arguments` because that is what the page
#: and its readers call it.
CONTEXT_TEXT_KEYS: tuple[tuple[str, str], ...] = (
    ("verb", "verb"),
    ("tier", "tier"),
    ("args_head", "arguments"),
)

#: Trajectory summary list keys the approval panel reads.
CONTEXT_LIST_KEYS: tuple[str, ...] = ("targets", "rule_hits", "labels")

#: Reviewer verdict fields the approval panel shows, in reading order.
REVIEW_FIELDS: tuple[str, ...] = (
    "outcome",
    "decision",
    "score",
    "confidence",
    "note",
    "skipped",
    "degraded",
    # The layer each reviewer read, so the approval panel says which stage
    # produced a verdict instead of leaving it to be inferred from a rule word.
    "layer",
    "source",
)

#: Ticket fields a response may carry.
TICKET_FIELDS: tuple[str, ...] = (
    "ticket_id",
    "state",
    "ticket_kind",
    "subject_key",
    "session_key",
    "tool_name",
    "created_at",
    "approved_at",
    "window_deadline",
    "decided_by",
    "reason",
    "retry_consumed",
    "result_summary",
    "updated_at",
    "completed_at",
)

#: Ticket fields that may quote an operator text or a tool result.
TICKET_TEXT_FIELDS = frozenset({"reason", "result_summary"})

#: Decisions the `decision` filter accepts; anything else selects no row.
KNOWN_DECISIONS = frozenset(item.value for item in Decision)


class QueryError(ValueError):
    """A request the server refuses with 400 instead of answering."""


@dataclass(frozen=True, slots=True)
class Scope:
    """Who is asking, and what that identity may read.

    Requirement: Visibility Scope. The dashboard is served by the host on this
    machine, so the login itself is the trust boundary and a host-injected
    username is an authenticated operator. Both configuration keys are
    therefore optional narrowings, never an allowlist: empty means "do not
    restrict", non-empty means "restrict to what is listed".

    - no username at all: the request carries no identity, so reads and
      decisions are both refused (fail-closed) and leave a refusal row;
    - `web_subject_map` has no entry for the name: every subject is visible;
    - `web_subject_map` names the user: visibility narrows to that subject;
    - `web_admin_usernames` is empty: every logged-in user may approve or
      deny; non-empty: only the listed names may.

    Administration decides tickets; it neither widens nor narrows a read.
    """

    username: str
    admin: bool
    subject_key: str | None = None

    @property
    def reads_nothing(self) -> bool:
        """Report whether this request must read no row at all.

        Requirement: Visibility Scope. Only a request without a host-injected
        username reads nothing; an identified user reads every subject unless
        `web_subject_map` narrows it.
        """
        return not self.username

    def payload(self) -> dict[str, Any]:
        """Return the wire form of this scope."""
        return {
            "username": self.username,
            "admin": self.admin,
            "subject_key": self.subject_key,
        }


@dataclass(frozen=True, slots=True)
class EventFilters:
    """One validated audit read."""

    subject_key: str | None = None
    session_key: str | None = None
    decision: str | None = None
    rule_id: str | None = None
    since: str | None = None
    until: str | None = None
    limit: int = LIMIT_DEFAULT
    offset: int = 0
    selects_nothing: bool = False


def resolve_scope(gateway: Any, username: Any) -> Scope:
    """Resolve the caller's identity, narrowing and decision rights.

    Requirement: Visibility Scope. Identity is the host-injected dashboard
    username and nothing else: no cookie, header or body field is consulted.
    A missing, blank or non-str username carries no identity and reads nothing.
    An identified user reads every subject by default — an empty
    `web_subject_map` narrows nothing rather than hiding everything — and only
    an entry naming that user narrows the view to one subject.
    `web_admin_usernames` follows the same empty-means-unrestricted rule for
    decisions, so an empty list lets any logged-in user decide while a
    non-empty one restricts decisions to the names it carries.

    Args:
        gateway: Gateway under inspection.
        username: Host-injected dashboard username, possibly empty or not a str.

    Returns:
        The resolved scope.
    """
    name = username.strip() if isinstance(username, str) else ""
    config = getattr(gateway, "config", None)
    admins = getattr(config, "web_admin_usernames", ()) or ()
    pairs = getattr(config, "web_subject_map", ()) or ()
    mapping: dict[str, str] = {}
    for entry in pairs:
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            continue
        holder, subject = entry
        if isinstance(holder, str) and isinstance(subject, str) and subject.strip():
            mapping[holder] = subject
    listed = [item for item in admins if isinstance(item, str) and item.strip()]
    return Scope(
        username=name,
        admin=bool(name) and (not listed or any(item == name for item in listed)),
        subject_key=mapping.get(name) if name else None,
    )


def _param(query: Any, name: str) -> str | None:
    """Return one trimmed query parameter, or None when absent or blank."""
    if query is None:
        return None
    getter = getattr(query, "get", None)
    if not callable(getter):
        return None
    raw = getter(name, None)
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


def _int_param(query: Any, name: str, default: int) -> int:
    """Return an integer query parameter, refusing a non-numeric value."""
    raw = _param(query, name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise QueryError(f"{name} 必须是整数。") from exc


def parse_instant(text: str, *, name: str) -> datetime:
    """Parse one window bound given as an ISO timestamp or as epoch seconds.

    Args:
        text: Raw parameter value.
        name: Parameter name, used in the error message.

    Returns:
        The parsed instant in UTC.

    Raises:
        QueryError: When the value is neither an epoch nor an ISO timestamp.
    """
    candidate = text.strip()
    if candidate and candidate.replace(".", "", 1).isdigit():
        try:
            return datetime.fromtimestamp(float(candidate), UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise QueryError(f"{name} 不是合法时间。") from exc
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise QueryError(f"{name} 不是合法时间。") from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def parse_event_filters(
    query: Any, *, scope: Scope, now: datetime | None = None
) -> EventFilters:
    """Validate one audit list request against the caller's scope.

    Requirement: Read Filtering; Visibility Scope. Conditions combine with AND.
    An unknown `decision` selects nothing rather than answering with the whole
    table; the window defaults to the last day and a span wider than
    `WINDOW_MAX_S` is refused instead of scanning everything; and the
    `subject` parameter is only honoured when `web_subject_map` narrowed
    nothing, so a narrowed scope cannot widen its own view by asking for another
    subject.

    Args:
        query: Request query mapping.
        scope: Resolved caller scope.
        now: Current instant, defaults to the current UTC time.

    Returns:
        The validated filters.

    Raises:
        QueryError: When a parameter is malformed or the window is too wide.
    """
    moment = now or datetime.now(UTC)
    limit = _int_param(query, "limit", LIMIT_DEFAULT)
    if limit < 1:
        raise QueryError("limit 必须大于 0。")
    offset = _int_param(query, "offset", 0)
    if offset < 0:
        raise QueryError("offset 不能为负。")
    since_text = _param(query, "since")
    until_text = _param(query, "until")
    since = (
        parse_instant(since_text, name="since")
        if since_text
        else moment - timedelta(seconds=WINDOW_DEFAULT_S)
    )
    until = parse_instant(until_text, name="until") if until_text else moment
    if until < since:
        raise QueryError("until 早于 since。")
    if (until - since).total_seconds() > WINDOW_MAX_S:
        raise QueryError(f"时间窗跨度超过 {WINDOW_MAX_S // 86_400} 天上限。")
    decision = _param(query, "decision")
    if scope.subject_key is not None:
        subject = scope.subject_key
    else:
        subject = _param(query, "subject")
    selects_nothing = scope.reads_nothing or (
        decision is not None and decision not in KNOWN_DECISIONS
    )
    return EventFilters(
        subject_key=subject,
        session_key=_param(query, "session"),
        decision=decision,
        rule_id=_param(query, "rule_id"),
        since=db.utc_iso(since),
        until=db.utc_iso(until),
        limit=min(limit, LIMIT_MAX),
        offset=offset,
        selects_nothing=selects_nothing,
    )


def read_events(conn: Any, filters: EventFilters) -> tuple[list[dict[str, Any]], int]:
    """Execute one filtered audit read.

    Args:
        conn: Open store connection.
        filters: Validated filters.

    Returns:
        The page of rows and the matching total; both empty when the filters can
        select nothing.
    """
    if filters.selects_nothing:
        return [], 0
    return audit.query_events(
        conn,
        subject_key=filters.subject_key,
        session_key=filters.session_key,
        decision=filters.decision,
        rule_id=filters.rule_id,
        since=filters.since,
        until=filters.until,
        limit=filters.limit,
        offset=filters.offset,
    )


def ticket_visible(ticket: tickets.Ticket, scope: Scope) -> bool:
    """Report whether the scope may read this ticket row.

    Requirement: Visibility Scope. A request without an identity sees nothing, a
    narrowed identity sees only its own subject, and an identity with no
    `web_subject_map` entry sees every row; `admin` grants decisions, not reads.
    """
    if scope.reads_nothing:
        return False
    if scope.subject_key is None:
        return True
    return ticket.subject_key == scope.subject_key


def _text(value: Any, limit: int = FIELD_LIMIT) -> str | None:
    """Render one column as a bounded string, or None when it is empty."""
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] if text else None


def _redacted(gateway: Any, value: Any, limit: int = FIELD_LIMIT) -> str | None:
    """Redact then bound one text column."""
    text = _text(value, limit)
    return redact_text(gateway, text) if text is not None else None


def serialize_event(gateway: Any, row: Mapping[str, Any]) -> dict[str, Any]:
    """Return one audit row as the browser may see it.

    Requirement: Read Filtering; Audit Trail; Verdict Aggregation. Only
    whitelisted columns are copied, so no argument text, argument digest or
    trajectory JSON can leak; the free-text column is redacted before it leaves
    the process.

    The wire form also carries the policy layer behind the verdict, read from
    the marker the summary line already holds: rule_id travels as evidence, and
    a browser that grouped rows by it would count the observing rules as
    causes.

    Args:
        gateway: Gateway owning the anonymizer.
        row: Audit row read from the store.

    Returns:
        The wire form of the row.
    """
    event: dict[str, Any] = {}
    for name in EVENT_FIELDS:
        if name == "id":
            event[name] = row.get(name)
        elif name == "degraded":
            event[name] = bool(row.get(name))
        elif name in EVENT_TEXT_FIELDS:
            event[name] = _redacted(gateway, row.get(name))
        else:
            event[name] = _text(row.get(name))
    event["layer"] = _layer_marker(event.get("summary_line"))
    return event


def _layer_marker(line: Any) -> str | None:
    """Return the layer marker of one audit summary line.

    Args:
        line: The redacted summary line of a row.

    Returns:
        The layer name, None when the row carries no marker.
    """
    text = _text(line)
    if not text:
        return None
    # The marker rides the reserved tail, so a token the argument text happens to
    # contain earlier in the line must lose to the one the gateway appended.
    for token in reversed(text.split()):
        if token.startswith(LAYER_MARKER):
            return _text(token[len(LAYER_MARKER) :], 32)
    return None


def _summary_of(row: Mapping[str, Any] | None) -> Mapping[str, Any]:
    """Return the stored trajectory summary of one audit row, or an empty map.

    Args:
        row: Audit row read from the store, possibly None.

    Returns:
        The decoded summary mapping; empty when the row carries none or it does
        not decode. A malformed summary is not an error here: the panel simply
        shows what the other columns still say.
    """
    if row is None:
        return {}
    raw = row.get("summary_json")
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, Mapping) else {}


def pick_ticket_event(rows: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    """Return the audit row that best describes the call behind a ticket.

    Requirement: Approval Detail. The suspension row is the one that carries the
    reviewer verdicts; the rows that follow it record the decision, and the rows
    before it belong to an earlier call with the same digest. A side row about the
    same ticket also says "suspended" (a notify_failed row is written with the plan
    decision) and it carries no summary, so "the newest suspended row" is not
    enough: the readable summary is what the panel needs, which is why a suspended
    row with a summary is chosen first.

    Args:
        rows: Audit rows of one ticket, newest first.

    Returns:
        The suspension row when there is one, otherwise the row that carries a
        readable summary, otherwise the newest row, otherwise None.
    """
    if not rows:
        return None
    suspended = [
        row for row in rows if _text(row.get("decision")) == Decision.SUSPENDED.value
    ]
    readable = [row for row in rows if _summary_of(row)]
    for row in suspended:
        if _summary_of(row):
            return row
    if readable:
        return readable[0]
    if suspended:
        return suspended[0]
    return rows[0]


def _review_items(
    gateway: Any, review: Any
) -> dict[str, dict[str, Any]]:
    """Return one reviewer report as the approval panel may show it.

    Requirement: Approval Detail. Every field is re-redacted here even though the
    gateway already redacted it at record time: the audit row is storage, and
    storage is not the place a leak is caught.

    Args:
        gateway: Gateway owning the anonymizer.
        review: The stored review mapping.

    Returns:
        Reviewer name to its verdict fields, in the stored order.
    """
    view: dict[str, dict[str, Any]] = {}
    if not isinstance(review, Mapping):
        return view
    for name, report in review.items():
        if not isinstance(report, Mapping):
            continue
        item: dict[str, Any] = {}
        for field in REVIEW_FIELDS:
            value = report.get(field)
            if value is None or value == "":
                continue
            item[field] = value if isinstance(value, (int, float)) else _redacted(gateway, value)
        reason = _redacted(gateway, report.get("reason"))
        if reason:
            item["reason"] = reason
        for field in ("rule_ids", "labels"):
            values = report.get(field)
            if isinstance(values, (list, tuple)) and values:
                item[field] = [str(value) for value in values][:8]
        view[str(name)] = item
    return view


def _label(table: Mapping[str, str], value: Any) -> str | None:
    """Return the Chinese wording of one enum value, None when it is absent."""
    text = _text(value)
    if text is None:
        return None
    return table.get(text, text)


def serialize_call_context(
    gateway: Any, row: Mapping[str, Any] | None
) -> dict[str, Any] | None:
    """Return what the suspended call was, for the approval panel.

    Requirement: Approval Detail. The panel exists to answer one question before
    an operator clicks approve: what would actually run, and what did each
    reviewer say about it. Argument text is the answer to the first half, so it
    leaves the process redacted and bounded instead of being withheld -- the
    digest alone cannot be reviewed by a human.

    Args:
        gateway: Gateway owning the anonymizer.
        row: The audit row `pick_ticket_event` chose, possibly None.

    Returns:
        The wire form of the call context, or None when the row carries none.
    """
    summary = _summary_of(row)
    if not summary:
        return None
    context: dict[str, Any] = {}
    for source, wire in CONTEXT_TEXT_KEYS:
        value = summary.get(source)
        limit = ARGS_HEAD_LIMIT if wire == "arguments" else FIELD_LIMIT
        context[wire] = _redacted(gateway, value, limit)
    # The two enum columns read as raw identifiers in a stored record; an operator
    # reading "T-strong" beside an empty verb learns nothing, so both are shown in
    # the same Chinese wording the notification uses (notify.messages).
    context["verb"] = _label(VERB_LABELS, summary.get("verb"))
    context["tier"] = _label(TIER_LABELS, summary.get("tier"))
    for key in CONTEXT_LIST_KEYS:
        values = summary.get(key)
        if isinstance(values, (list, tuple)):
            context[key] = [_redacted(gateway, value) for value in values][:8]
    context["review"] = _review_items(gateway, summary.get("review"))
    if row is not None:
        context["decision"] = _text(row.get("decision"))
        context["would_be"] = _text(row.get("would_be"))
        context["judge_route"] = _text(row.get("judge_route"))
    return context


def serialize_ticket(gateway: Any, ticket: tickets.Ticket) -> dict[str, Any]:
    """Return one ticket as the browser may see it.

    Args:
        gateway: Gateway owning the anonymizer.
        ticket: Ticket read from the store.

    Returns:
        The wire form of the ticket, without its argument digest.
    """
    view: dict[str, Any] = {}
    for name in TICKET_FIELDS:
        value = getattr(ticket, name, None)
        if name == "retry_consumed":
            view[name] = bool(value)
        elif name in TICKET_TEXT_FIELDS:
            view[name] = _redacted(gateway, value)
        else:
            view[name] = _text(value)
    return view


def serialize_transition(gateway: Any, row: Mapping[str, Any]) -> dict[str, Any]:
    """Return one persisted ticket transition with its reason redacted."""
    return {
        "from_state": _text(row.get("from_state"), 32),
        "to_state": _text(row.get("to_state"), 32),
        "actor": _redacted(gateway, row.get("actor")),
        "reason": _redacted(gateway, row.get("reason")),
        "at": _text(row.get("at"), 40),
    }


def serialize_reviewer(gateway: Any, status: Any) -> dict[str, Any]:
    """Return one reviewer status from the gateway's single status source.

    Requirement: Observability. The name, order, flags and last verdict come
    from `ReviewerStatus` unchanged; the raw last error is never echoed.

    Args:
        gateway: Gateway owning the anonymizer.
        status: Reviewer status read from the gateway.

    Returns:
        The wire form of the status.
    """
    outcome = getattr(status, "last_outcome", None)
    return {
        "name": _text(getattr(status, "name", None), 64),
        "enabled": bool(getattr(status, "enabled", False)),
        "order": int(getattr(status, "order", 0) or 0),
        "busy": bool(getattr(status, "busy", False)),
        "in_flight": int(getattr(status, "in_flight", 0) or 0),
        "last_outcome": _text(getattr(outcome, "value", None) or outcome, 32),
        "last_degraded": _redacted(
            gateway, getattr(status, "last_degraded", None), 120
        ),
        "last_elapsed_s": float(getattr(status, "last_elapsed_s", 0.0) or 0.0),
    }


def serialize_fast_judge(status: Any) -> dict[str, Any]:
    """Return the fast judge status from the one shared gateway view.

    Requirement: Fast Judge Observability. The switch, the backend the
    configured client actually speaks, the two bands and the confidence floor
    all come from ``Gateway.fast_judge_status`` through
    ``ui.commands.read_fast_judge_status``: the payload serializes that view
    and never recomputes a threshold. ``available`` is the only field added
    here -- it records whether the gateway could answer at all -- and an
    unreadable gateway still gets the full key set, because dropping the keys
    would make "unreadable" look like "no fast judge configured".

    Args:
        status: Fast judge status read from the gateway, None when unavailable.

    Returns:
        The wire form of the status, with every key always present.
    """
    available = isinstance(status, FastJudgeStatus)
    view = status if available else FastJudgeStatus()
    return {
        "available": available,
        "enabled": bool(view.enabled),
        "backend": _text(view.backend, 16) or "",
        "allow_score": int(view.allow_score),
        "block_score": int(view.block_score),
        "min_confidence": float(view.min_confidence),
    }


__all__ = [
    "EVENT_FIELDS",
    "FIELD_LIMIT",
    "KNOWN_DECISIONS",
    "LIMIT_DEFAULT",
    "LIMIT_MAX",
    "REASON_LIMIT",
    "WINDOW_DEFAULT_S",
    "WINDOW_MAX_S",
    "EventFilters",
    "QueryError",
    "Scope",
    "parse_event_filters",
    "parse_instant",
    "read_events",
    "LAYER_MARKER",
    "resolve_scope",
    "serialize_event",
    "serialize_fast_judge",
    "serialize_reviewer",
    "serialize_ticket",
    "serialize_transition",
    "ticket_visible",
]
