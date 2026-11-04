"""Approval ticket persistence and the compare-and-swap state machine.

Requirement: Ticket Persistence; Ticket Lifecycle; Approval Retry Binding;
Canonical Retry Digest; Ticket Marker and Late Attempts; External Cancellation
Degradation; Approved Retry Outcome and Window.

Every state change is one `UPDATE ... WHERE state IN (...)` compare-and-swap plus
one `ticket_transitions` row inside the same transaction.  A zero affected row count
is a conflict: the stored state is never overwritten and the caller fails closed.

State machine (design.md D5):

    pending          -> approved | denied | timeout | canceled_external
    approved         -> expired | canceled_external | consumed
    consumed         -> completed
    denied | timeout | expired | canceled_external | completed -> terminal

`expired` is reachable only from `approved`; `canceled_external` is the outer
cancellation path and never collides with the timeout budget outcome.
"""

from __future__ import annotations

import re
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .db import (
    StorageUnavailableError,
    require_startup_sweep,
    rollback_quietly,
    serialized_write,
    utc_iso,
)

PENDING = "pending"
"""Suspension opened; waiting for an administrator decision."""

APPROVED = "approved"
"""Administrator approved; authorizes one exact-match new call in the window."""

DENIED = "denied"
"""Administrator denied."""

TIMEOUT = "timeout"
"""The in-call suspension budget ran out while waiting for a decision."""

EXPIRED = "expired"
"""The approval window closed (agent run ended or approved_at + 300s)."""

CANCELED_EXTERNAL = "canceled_external"
"""Outer executor cancellation or service restart invalidated the ticket."""

CONSUMED = "consumed"
"""The approved authorization was atomically consumed by one exact match."""

COMPLETED = "completed"
"""The consumed retry finished and persisted its redacted result."""

TICKET_STATES: tuple[str, ...] = (
    PENDING,
    APPROVED,
    DENIED,
    TIMEOUT,
    EXPIRED,
    CANCELED_EXTERNAL,
    CONSUMED,
    COMPLETED,
)
"""Every persisted ticket state, in lifecycle order."""

APPROVAL_WINDOW_S = 300
"""Fallback approval window: the window ends at run end or approved_at + 300s."""

SWEEP_ORPHAN_GRACE_S = 120.0
"""Age after which an open pending ticket counts as an orphan of a past process.

It is deliberately longer than the upper bound of one in-call wait
(approval/waiter.py MAX_SUSPEND_WAIT_S = 110s), so a live waiter can never have
its own ticket swept out from under it by the command-side maintenance sweep.

The startup path (startup_sweep) deliberately does NOT apply it: at restart time
no waiter of the previous process exists, so grace would only preserve grants
nobody can ever finish.
"""

STARTUP_ACTOR = "system:startup"
"""Actor recorded on every transition a restart performs."""

STARTUP_REASON = "service restart invalidates open tickets"
"""Redacted reason recorded on every transition a restart performs."""

_TRANSITIONS: dict[str, frozenset[str]] = {
    PENDING: frozenset({APPROVED, DENIED, TIMEOUT, CANCELED_EXTERNAL}),
    APPROVED: frozenset({EXPIRED, CANCELED_EXTERNAL, CONSUMED}),
    CONSUMED: frozenset({COMPLETED}),
    DENIED: frozenset(),
    TIMEOUT: frozenset(),
    EXPIRED: frozenset(),
    CANCELED_EXTERNAL: frozenset(),
    COMPLETED: frozenset(),
}
"""Legal one-way transitions; any other pair is refused before any SQL runs."""

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{32}$")

_COLUMNS: tuple[str, ...] = (
    "ticket_id",
    "marker",
    "subject_key",
    "session_key",
    "tool_name",
    "args_digest",
    "created_at",
    "approved_at",
    "window_deadline",
    "state",
    "decided_by",
    "reason",
    "retry_consumed",
    "result_summary",
    "updated_at",
    "completed_at",
    "ticket_kind",
)


@dataclass(frozen=True)
class Ticket:
    """One persisted approval ticket.

    Requirement: Ticket Persistence (ID/marker, subject, session, tool, digest,
    state and timestamps are stored together).
    """

    ticket_id: str
    marker: str
    subject_key: str
    session_key: str
    tool_name: str
    args_digest: str
    created_at: str
    approved_at: str | None
    window_deadline: str | None
    state: str
    decided_by: str | None = None
    reason: str | None = None
    retry_consumed: bool = False
    result_summary: str | None = None
    updated_at: str = ""
    completed_at: str | None = None
    ticket_kind: str | None = None

    @classmethod
    def from_row(cls, row: Any) -> Ticket:
        """Build a ticket from one database row.

        Requirement: Ticket Persistence.

        Args:
            row: Row with every ticket column.

        Returns:
            The ticket value object.
        """
        return cls(
            ticket_id=row["ticket_id"],
            marker=row["marker"],
            subject_key=row["subject_key"],
            session_key=row["session_key"],
            tool_name=row["tool_name"],
            args_digest=row["args_digest"],
            created_at=row["created_at"],
            approved_at=row["approved_at"],
            window_deadline=row["window_deadline"],
            state=row["state"],
            decided_by=row["decided_by"],
            reason=row["reason"],
            retry_consumed=bool(row["retry_consumed"]),
            result_summary=row["result_summary"],
            updated_at=row["updated_at"],
            completed_at=row["completed_at"],
            ticket_kind=row["ticket_kind"],
        )


@dataclass(frozen=True)
class TicketTransitionResult:
    """Outcome of one compare-and-swap transition attempt.

    Requirement: Ticket Lifecycle (transitions are atomic and one-way; a second
    decision is rejected).  `affected` is the row count of the CAS update.
    """

    ticket_id: str
    new_state: str
    expected: tuple[str, ...]
    affected: int
    previous_state: str | None = None
    illegal: bool = False
    conflict: bool = False

    @property
    def ok(self) -> bool:
        """Report whether the CAS applied exactly one row.

        Requirement: Ticket Lifecycle.

        Returns:
            True when the transition is durable and not illegal.
        """
        return self.affected == 1 and not self.illegal


def _as_datetime(value: datetime | float | str) -> datetime:
    """Return an aware UTC datetime for a stored or caller supplied time.

    Requirement: Approved Retry Outcome and Window.

    Args:
        value: aware or naive datetime, epoch seconds, or canonical string.

    Returns:
        The instant in UTC.
    """
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=UTC)
    elif isinstance(value, str):
        moment = datetime.fromisoformat(value)
    else:
        raise TypeError(f"unsupported timestamp type: {type(value)!r}")
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def compute_window_deadline(
    approved_at: datetime | float | str,
    run_deadline: datetime | float | str | None = None,
) -> str:
    """Return the approval window end for a freshly approved ticket.

    Requirement: Approved Retry Outcome and Window.  The window is the earlier
    of the agent run end and `approved_at + 300s`; without a run end the 300
    second fallback applies.

    Args:
        approved_at: Instant of approval.
        run_deadline: Instant the agent run ends, when the hook provided it.

    Returns:
        Canonical UTC timestamp for `window_deadline`.
    """
    approved = _as_datetime(approved_at)
    deadline = approved + timedelta(seconds=APPROVAL_WINDOW_S)
    if run_deadline is not None:
        run_end = _as_datetime(run_deadline)
        deadline = min(deadline, run_end)
    return utc_iso(deadline)


def _allowed_predecessors(new_state: str) -> frozenset[str]:
    """Return every state that may legally enter new_state.

    Requirement: Ticket Lifecycle.

    Args:
        new_state: Target state.

    Returns:
        Set of legal predecessor states (empty for unknown states).
    """
    return frozenset(
        source for source, targets in _TRANSITIONS.items() if new_state in targets
    )


def _check_name(value: str, label: str) -> str:
    """Validate a required non-empty string field.

    Requirement: Ticket Persistence.

    Args:
        value: Candidate value.
        label: Field name used in the error message.

    Returns:
        The value unchanged.

    Raises:
        ValueError: When the value is empty or not a string.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _check_digest(args_digest: str) -> str:
    """Validate the canonical retry digest.

    Requirement: Canonical Retry Digest (32 lowercase hexadecimal characters).

    Args:
        args_digest: Candidate digest.

    Returns:
        The digest unchanged.

    Raises:
        ValueError: When it is not 32 lowercase hexadecimal characters.
    """
    if not isinstance(args_digest, str) or not _DIGEST_PATTERN.match(args_digest):
        raise ValueError(
            "args_digest must be 32 lowercase hexadecimal characters, "
            f"got {args_digest!r}"
        )
    return args_digest


def _insert_transition(
    conn: sqlite3.Connection,
    ticket_id: str,
    from_state: str,
    to_state: str,
    actor: str,
    reason: str | None,
    at: str,
) -> None:
    """Append one row to the ticket transition log.

    Requirement: Ticket Persistence (every CAS transition is persisted).

    Args:
        conn: Open connection, inside the caller's transaction.
        ticket_id: Ticket the row belongs to.
        from_state: State read before the CAS.
        to_state: State written by the CAS.
        actor: Who or what caused the change.
        reason: Redacted reason, if any.
        at: Canonical UTC timestamp.
    """
    conn.execute(
        "INSERT INTO ticket_transitions"
        " (ticket_id, from_state, to_state, actor, reason, at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (ticket_id, from_state, to_state, actor, reason, at),
    )


@serialized_write
def create_ticket(
    conn: sqlite3.Connection,
    *,
    subject_key: str,
    session_key: str,
    tool_name: str,
    args_digest: str,
    ticket_id: str | None = None,
    marker: str | None = None,
    ticket_kind: str | None = None,
    now: datetime | float | str | None = None,
) -> Ticket:
    """Persist a new ticket in the pending state.

    Requirement: Ticket Persistence; Ticket Marker and Late Attempts (the marker
    is an audit-correlation and exact-retry matching key only).

    Args:
        conn: Open connection.
        subject_key: Redacted platform_id:sender_id value.  It is mandatory: a
            missing sender id must prevent ticket creation.
        session_key: Minimized session key.
        tool_name: Managed tool name.
        args_digest: Canonical digest of the schema-filtered arguments.
        ticket_id: Optional UUID; generated when omitted.
        marker: Optional unguessable marker; generated when omitted.
        ticket_kind: Optional reason word the ticket was opened for
            ('model_deny' / 'all_abstain'); None when the caller has none.
        now: Creation instant, defaults to the current UTC time.

    Returns:
        The persisted ticket.

    Raises:
        ValueError: On an empty identity field or a non canonical digest.
        StorageUnavailableError: When the insert fails; the caller must then deny
            because storage is unavailable.
    """
    identifier = ticket_id if ticket_id is not None else str(uuid.uuid4())
    token = marker if marker is not None else secrets.token_urlsafe(24)
    created = utc_iso(now)
    row = (
        _check_name(identifier, "ticket_id"),
        _check_name(token, "marker"),
        _check_name(subject_key, "subject_key"),
        _check_name(session_key, "session_key"),
        _check_name(tool_name, "tool_name"),
        _check_digest(args_digest),
        created,
        None,
        None,
        PENDING,
        None,
        None,
        0,
        None,
        created,
        None,
        None if ticket_kind is None else _check_name(ticket_kind, "ticket_kind"),
    )
    columns = ", ".join(_COLUMNS)
    placeholders = ", ".join("?" for _ in _COLUMNS)
    try:
        conn.execute(f"INSERT INTO tickets ({columns}) VALUES ({placeholders})", row)
        conn.commit()
    except sqlite3.Error as exc:
        rollback_quietly(conn)
        raise StorageUnavailableError(f"cannot create ticket: {exc}") from exc
    ticket = get_ticket(conn, identifier)
    if ticket is None:
        raise StorageUnavailableError("ticket vanished after insert")
    return ticket


def get_ticket(conn: sqlite3.Connection, ticket_id: str) -> Ticket | None:
    """Return one ticket, or None when it does not exist.

    Requirement: Ticket Persistence; Operator Introspection.

    Args:
        conn: Open connection.
        ticket_id: Ticket identifier.

    Returns:
        The ticket, or None when unknown.

    Raises:
        StorageUnavailableError: When the read fails.
    """
    try:
        row = conn.execute(
            "SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,)
        ).fetchone()
    except sqlite3.Error as exc:
        raise StorageUnavailableError(f"cannot read ticket: {exc}") from exc
    return None if row is None else Ticket.from_row(row)


def list_pending(
    conn: sqlite3.Connection,
    *,
    subject_key: str | None = None,
    session_key: str | None = None,
) -> list[Ticket]:
    """List tickets still waiting for an administrator decision.

    Requirement: Ticket Persistence; Decision Commands (status stays readable
    while the call is suspended).

    Args:
        conn: Open connection.
        subject_key: Optional identity filter.
        session_key: Optional session filter.

    Returns:
        Pending tickets, oldest first.

    Raises:
        StorageUnavailableError: When the read fails.
    """
    sql = "SELECT * FROM tickets WHERE state = ?"
    params: list[Any] = [PENDING]
    if subject_key is not None:
        sql += " AND subject_key = ?"
        params.append(subject_key)
    if session_key is not None:
        sql += " AND session_key = ?"
        params.append(session_key)
    sql += " ORDER BY created_at ASC, ticket_id ASC"
    try:
        rows = conn.execute(sql, tuple(params)).fetchall()
    except sqlite3.Error as exc:
        raise StorageUnavailableError(f"cannot list pending tickets: {exc}") from exc
    return [Ticket.from_row(row) for row in rows]


@serialized_write
def transition(
    conn: sqlite3.Connection,
    ticket_id: str,
    expect_states: tuple[str, ...] | list[str],
    new_state: str,
    *,
    actor: str,
    reason: str | None = None,
    now: datetime | float | str | None = None,
    run_deadline: datetime | float | str | None = None,
    result_summary: str | None = None,
) -> TicketTransitionResult:
    """Apply one atomic compare-and-swap ticket transition.

    Requirement: Ticket Lifecycle; Ticket Marker and Late Attempts; External
    Cancellation Degradation.  The update is a single
    `UPDATE tickets SET ... WHERE ticket_id = ? AND state IN (...)`; the caller's
    expected states are intersected with the legal predecessors of new_state, so
    an illegal pair (for example pending to expired) never touches the row.  A
    row count of 0 means another decision already won: the stored state is left
    untouched and the result reports a conflict.

    Args:
        conn: Open connection.
        ticket_id: Ticket identifier.
        expect_states: States the caller believes the ticket may be in.
        new_state: Target state; must be a member of TICKET_STATES.
        actor: Who or what performs the transition (admin id or system marker).
        reason: Optional redacted reason persisted with the transition.
        now: Transition instant, defaults to the current UTC time.
        run_deadline: Agent run end used to bound the approval window when
            entering the approved state.  Without it the 300 second fallback
            applies.
        result_summary: Redacted result persisted when entering completed.

    Returns:
        The transition result carrying the affected row count.

    Raises:
        ValueError: When the target state or an expected state is unknown.
        StorageUnavailableError: When the CAS or the audit row cannot be written.
    """
    if new_state not in TICKET_STATES:
        raise ValueError(f"unknown ticket state: {new_state!r}")
    expected = tuple(dict.fromkeys(expect_states))
    unknown = [state for state in expected if state not in TICKET_STATES]
    if unknown:
        raise ValueError(f"unknown expected state(s): {', '.join(unknown)}")
    permitted = tuple(state for state in expected if new_state in _TRANSITIONS[state])
    if not permitted:
        return TicketTransitionResult(
            ticket_id=ticket_id,
            new_state=new_state,
            expected=expected,
            affected=0,
            illegal=True,
        )

    stamp = utc_iso(now)
    assignments: dict[str, Any] = {"state": new_state, "updated_at": stamp}
    if reason is not None:
        assignments["reason"] = reason
    if new_state == APPROVED:
        assignments["approved_at"] = stamp
        assignments["window_deadline"] = compute_window_deadline(stamp, run_deadline)
        assignments["decided_by"] = actor
    elif new_state == DENIED:
        assignments["decided_by"] = actor
    elif new_state == CONSUMED:
        assignments["retry_consumed"] = 1
    elif new_state == COMPLETED:
        assignments["completed_at"] = stamp
        if result_summary is not None:
            assignments["result_summary"] = result_summary

    columns = tuple(assignments)
    set_clause = ", ".join(f"{column} = ?" for column in columns)
    placeholders = ", ".join("?" for _ in permitted)
    sql = (
        f"UPDATE tickets SET {set_clause}"
        f" WHERE ticket_id = ? AND state IN ({placeholders})"
    )
    params = tuple(assignments[column] for column in columns) + (ticket_id,) + permitted

    try:
        current = conn.execute(
            "SELECT state FROM tickets WHERE ticket_id = ?", (ticket_id,)
        ).fetchone()
        previous = None if current is None else current["state"]
        cursor = conn.execute(sql, params)
        affected = int(cursor.rowcount or 0)
        if affected == 1:
            _insert_transition(
                conn,
                ticket_id,
                previous or "unknown",
                new_state,
                actor,
                reason,
                stamp,
            )
        conn.commit()
    except sqlite3.Error as exc:
        rollback_quietly(conn)
        raise StorageUnavailableError(f"cannot transition ticket: {exc}") from exc
    return TicketTransitionResult(
        ticket_id=ticket_id,
        new_state=new_state,
        expected=expected,
        affected=affected,
        previous_state=previous,
        conflict=affected == 0,
    )


def find_approved(
    conn: sqlite3.Connection,
    *,
    subject_key: str,
    session_key: str,
    tool_name: str,
    args_digest: str,
    now: datetime | float | str | None = None,
) -> Ticket | None:
    """Return the approved ticket bound to one exact retry quadruple.

    Requirement: Approval Retry Binding; Approved Retry Outcome and Window.

    The read only ever locates an authorization consume_approved can still
    consume: approved, not yet consumed and inside the window.  It grants
    nothing by itself -- the caller still has to consume the ticket atomically
    and re-judge the call.

    A store whose startup sweep failed finds nothing here: that sweep is what
    withdraws the previous process's grants, so require_startup_sweep runs first
    and raises instead of answering (review R10-03).

    Args:
        conn: Open connection.
        subject_key: Identity of the retrying caller.
        session_key: Session key of the retrying call.
        tool_name: Tool name of the retrying call.
        args_digest: Digest of the retrying call arguments.
        now: Comparison instant, defaults to the current UTC time.

    Returns:
        The oldest matching ticket, or None when no authorization applies.

    Raises:
        ValueError: When args_digest is not a canonical retry digest.
        StorageUnavailableError: When the read fails, or when the startup ticket
            sweep has not settled; the caller must then deny.
    """
    require_startup_sweep(conn)
    _check_digest(args_digest)
    stamp = utc_iso(now)
    sql = (
        "SELECT * FROM tickets"
        " WHERE state = ?"
        " AND retry_consumed = 0"
        " AND subject_key = ?"
        " AND session_key = ?"
        " AND tool_name = ?"
        " AND args_digest = ?"
        " AND (window_deadline IS NULL OR window_deadline > ?)"
        " ORDER BY approved_at ASC, ticket_id ASC"
        " LIMIT 1"
    )
    params = (APPROVED, subject_key, session_key, tool_name, args_digest, stamp)
    try:
        row = conn.execute(sql, params).fetchone()
    except sqlite3.Error as exc:
        raise StorageUnavailableError(f"cannot find approved ticket: {exc}") from exc
    return None if row is None else Ticket.from_row(row)


@serialized_write
def consume_approved(
    conn: sqlite3.Connection,
    ticket_id: str,
    *,
    subject_key: str,
    session_key: str,
    tool_name: str,
    args_digest: str,
    now: datetime | float | str | None = None,
) -> bool:
    """Consume an approved ticket once for an exact-matching retry.

    Requirement: Approval Retry Binding; Canonical Retry Digest; Approved Retry
    Outcome and Window.  One statement performs the whole check: exact
    (subject_key, session_key, tool_name, args_digest) match, state still
    approved, not yet consumed and the window still open; the row moves to
    consumed only when every condition holds.  A mismatch, a repeat and an
    expired window all return False and leave the state untouched.

    A store whose startup sweep failed consumes nothing: that sweep is what
    withdraws the previous process's grants, so require_startup_sweep runs first
    and raises instead of answering (review R10-03).  The check and the update
    run under the connection's commit owner (store.db.serialized_write), so the
    event-loop caller and a worker-thread writer can never share a transaction.

    Args:
        conn: Open connection.
        ticket_id: Ticket identifier.
        subject_key: Identity of the retrying caller.
        session_key: Session key of the retrying call.
        tool_name: Tool name of the retrying call.
        args_digest: Digest of the retrying call arguments.
        now: Comparison instant, defaults to the current UTC time.

    Returns:
        True when this call consumed the authorization, otherwise False.

    Raises:
        StorageUnavailableError: When the statement or audit row fails, or when
            the startup ticket sweep has not settled; the caller must then deny
            because storage is unavailable.
    """
    require_startup_sweep(conn)
    stamp = utc_iso(now)
    sql = (
        "UPDATE tickets SET state = ?, retry_consumed = 1, updated_at = ?"
        " WHERE ticket_id = ?"
        " AND state = ?"
        " AND retry_consumed = 0"
        " AND subject_key = ?"
        " AND session_key = ?"
        " AND tool_name = ?"
        " AND args_digest = ?"
        " AND (window_deadline IS NULL OR window_deadline > ?)"
    )
    params = (
        CONSUMED,
        stamp,
        ticket_id,
        APPROVED,
        subject_key,
        session_key,
        tool_name,
        args_digest,
        stamp,
    )
    try:
        cursor = conn.execute(sql, params)
        affected = int(cursor.rowcount or 0)
        if affected == 1:
            _insert_transition(
                conn,
                ticket_id,
                APPROVED,
                CONSUMED,
                "gateway:consume",
                "exact-match retry consumed the approval",
                stamp,
            )
        conn.commit()
    except sqlite3.Error as exc:
        rollback_quietly(conn)
        raise StorageUnavailableError(f"cannot consume ticket: {exc}") from exc
    return affected == 1


@serialized_write
def expire_stale(
    conn: sqlite3.Connection,
    now: datetime | float | str | None = None,
) -> list[TicketTransitionResult]:
    """Move every approved ticket whose window closed to the expired state.

    Requirement: Approved Retry Outcome and Window.  Only approved tickets are
    expired here; a pending ticket ends as timeout through the waiter's
    suspension budget, never as expired.

    Args:
        conn: Open connection.
        now: Comparison instant, defaults to the current UTC time.

    Returns:
        One result per ticket that was considered, in ticket id order.

    Raises:
        StorageUnavailableError: When the scan or a transition fails.
    """
    stamp = utc_iso(now)
    try:
        rows = conn.execute(
            "SELECT ticket_id FROM tickets"
            " WHERE state = ? AND window_deadline IS NOT NULL"
            " AND window_deadline <= ? ORDER BY ticket_id ASC",
            (APPROVED, stamp),
        ).fetchall()
    except sqlite3.Error as exc:
        raise StorageUnavailableError(f"cannot scan stale tickets: {exc}") from exc
    results: list[TicketTransitionResult] = []
    for row in rows:
        results.append(
            transition(
                conn,
                row["ticket_id"],
                (APPROVED,),
                EXPIRED,
                actor="system:expire_stale",
                reason="approval window ended",
                now=stamp,
            )
        )
    return results


@serialized_write
def cancel_external(
    conn: sqlite3.Connection,
    ticket_id: str,
    *,
    actor: str,
    reason: str | None = None,
    now: datetime | float | str | None = None,
) -> TicketTransitionResult:
    """Invalidate a pending or approved ticket because the outside canceled.

    Requirement: External Cancellation Degradation.  This is the outer executor
    cancellation and restart path; it is deliberately not timeout.

    Args:
        conn: Open connection.
        ticket_id: Ticket identifier.
        actor: Who or what canceled the suspension.
        reason: Optional redacted reason.
        now: Transition instant, defaults to the current UTC time.

    Returns:
        The transition result.

    Raises:
        StorageUnavailableError: When the CAS cannot be written.
    """
    return transition(
        conn,
        ticket_id,
        (PENDING, APPROVED),
        CANCELED_EXTERNAL,
        actor=actor,
        reason=reason,
        now=now,
    )


@serialized_write
def invalidate_on_startup(
    conn: sqlite3.Connection,
    *,
    actor: str = STARTUP_ACTOR,
    reason: str = STARTUP_REASON,
    now: datetime | float | str | None = None,
    orphan_grace_s: float | None = None,
    created_before: str | None = None,
) -> list[TicketTransitionResult]:
    """Invalidate pending and unconsumed approved tickets after a restart.

    Requirement: Ticket Persistence; Ticket Lifecycle (a restart never resumes
    old waiters or grants).

    Args:
        conn: Open connection.
        actor: Recovery actor recorded on each transition.
        reason: Redacted reason recorded on each transition.
        now: Transition instant, defaults to the current UTC time.
        orphan_grace_s: When given, only pending tickets created at least this
            many seconds before now are invalidated, and approved tickets are
            left alone (expire_stale owns them). That narrowed shape is what a
            per-command maintenance sweep needs: it may only reclaim a
            suspension whose process is gone, never one a live caller can still
            finish, and never a grant the operator still holds open.
        created_before: When given, only tickets created strictly before this
            canonical timestamp are invalidated. That is what makes a retry safe
            inside a live process: with the process start instant as the cutoff,
            only the previous process's tickets can be withdrawn and this
            process's own pending and approved tickets keep their state.

    Returns:
        One result per invalidated ticket.

    Raises:
        StorageUnavailableError: When the scan or a transition fails.
    """
    stamp = utc_iso(now)
    clauses: list[str] = []
    params: list[object] = []
    if orphan_grace_s is None:
        clauses.append("state IN (?, ?)")
        params.extend((PENDING, APPROVED))
    else:
        cutoff = utc_iso(_as_datetime(stamp) - timedelta(seconds=float(orphan_grace_s)))
        clauses.extend(("state = ?", "created_at <= ?"))
        params.extend((PENDING, cutoff))
    if created_before is not None:
        clauses.append("created_at < ?")
        params.append(created_before)
    query = (
        "SELECT ticket_id FROM tickets WHERE "
        + " AND ".join(clauses)
        + " ORDER BY created_at ASC, ticket_id ASC"
    )
    try:
        rows = conn.execute(query, tuple(params)).fetchall()
    except sqlite3.Error as exc:
        raise StorageUnavailableError(f"cannot scan open tickets: {exc}") from exc
    return [
        cancel_external(conn, row["ticket_id"], actor=actor, reason=reason, now=now)
        for row in rows
    ]


def startup_sweep(
    conn: sqlite3.Connection,
    *,
    now: datetime | float | str | None = None,
    created_before: str | None = None,
) -> dict[str, int]:
    """Settle every ticket the dying process left open, without any grace.

    Requirement: Ticket Persistence (on startup, invalidate pending and
    unconsumed approved tickets as `canceled_external`; never resume old waiters
    or grants); Ticket Lifecycle (a restart invalidates open tickets).

    This is the startup semantics, and it is deliberately not the command-plane
    semantics of `sweep`: a restart is proof that no waiter of the previous
    process exists, so a pending suspension can never be approved into a fresh
    grant and an approved ticket can never be consumed.  `sweep` must instead
    keep SWEEP_ORPHAN_GRACE_S, because it runs while this very process may have a
    live waiter whose own ticket it would otherwise destroy.

    Both steps go through the CAS in `transition` and the `_TRANSITIONS` table;
    no row is updated directly:

    1. expire_stale: an approved ticket whose window already closed keeps the
       `expired` terminal state the window semantics own (it is equally dead).
    2. invalidate_on_startup without a grace horizon: every remaining pending
       and unconsumed approved ticket becomes `canceled_external`.

    The open-time call passes no cutoff: a restart is proof that every ticket in
    the file died with the previous process. The controlled retry inside a live
    process passes the process start instant instead, so step 2 can only reach
    the rows the previous process wrote. Step 1 needs no cutoff because it only
    settles approved tickets whose approval window already closed, which is a
    settled fact of the window rather than a decision this call makes, and it
    never touches a pending ticket or a grant still inside its window.

    Args:
        conn: Open connection.
        now: Transition instant for both steps, defaults to the current UTC time.
        created_before: When given, step 2 only invalidates tickets created
            strictly before this canonical timestamp.

    Returns:
        A summary with these stable keys:

        * "expired": approved tickets settled as expired by the window scan.
        * "invalidated": tickets settled as canceled_external by this call, i.e.
          "pending_invalidated" + "approved_invalidated".
        * "pending_invalidated": of those, the ones that were pending.
        * "approved_invalidated": of those, the ones that were unconsumed
          approved -- the grants a restart must never leave usable.
        * "changed": "expired" + "invalidated"; 0 means the store was clean.

    Raises:
        StorageUnavailableError: When a scan or a transition fails.
    """
    stamp = utc_iso(now)
    expired = expire_stale(conn, stamp)
    invalidated = invalidate_on_startup(
        conn, now=stamp, orphan_grace_s=None, created_before=created_before
    )
    settled = [item for item in invalidated if item.ok]
    expired_count = sum(1 for item in expired if item.ok)
    pending_count = sum(1 for item in settled if item.previous_state == PENDING)
    approved_count = sum(1 for item in settled if item.previous_state == APPROVED)
    invalidated_count = len(settled)
    return {
        "expired": expired_count,
        "invalidated": invalidated_count,
        "pending_invalidated": pending_count,
        "approved_invalidated": approved_count,
        "changed": expired_count + invalidated_count,
    }


def sweep(
    conn: sqlite3.Connection,
    *,
    now: datetime | float | str | None = None,
    orphan_grace_s: float = SWEEP_ORPHAN_GRACE_S,
) -> dict[str, int]:
    """Reclaim the tickets no process can still finish, in one maintenance step.

    Requirement: Ticket Persistence; Approved Retry Outcome and Window. The two
    recovery scans below had no production caller, so closed approval windows
    and suspensions orphaned by a dead process stayed open forever. This is the
    single entry point that runs them, in this order:

    1. expire_stale: an approved ticket whose window closed becomes expired.
    2. invalidate_on_startup (narrowed by orphan_grace_s): a pending ticket
       created before the grace horizon becomes canceled_external. Approved
       tickets are untouched here because step 1 owns them.

    It is safe to call on every command invocation: it only settles tickets that
    are already dead, and a settled ticket produces no further rows.  Because it
    can run while this process still waits on a ticket, it is NOT the startup
    path; `startup_sweep` is, and it drops the grace horizon.

    Args:
        conn: Open connection.
        now: Comparison instant for both scans, defaults to the current UTC time.
        orphan_grace_s: Grace horizon for the orphan scan, in seconds.

    Returns:
        A summary with these stable keys:

        * "expired": approved tickets settled as expired by this call.
        * "invalidated": pending tickets settled as canceled_external here.
        * "changed": the number of tickets this call settled, i.e. the sum of
          the two counts; 0 means the store was already clean.

    Raises:
        StorageUnavailableError: When a scan or a transition fails.
    """
    stamp = utc_iso(now)
    expired = expire_stale(conn, stamp)
    invalidated = invalidate_on_startup(conn, now=stamp, orphan_grace_s=orphan_grace_s)
    expired_count = sum(1 for item in expired if item.ok)
    invalidated_count = sum(1 for item in invalidated if item.ok)
    return {
        "expired": expired_count,
        "invalidated": invalidated_count,
        "changed": expired_count + invalidated_count,
    }


@serialized_write
def complete_ticket(
    conn: sqlite3.Connection,
    ticket_id: str,
    *,
    actor: str,
    result_summary: str | None = None,
    reason: str | None = None,
    now: datetime | float | str | None = None,
) -> TicketTransitionResult:
    """Persist the finished retry of a consumed ticket.

    Requirement: Ticket Lifecycle (the success terminal state completed differs
    from expired, timeout and outer cancellation).

    Args:
        conn: Open connection.
        ticket_id: Ticket identifier.
        actor: Who or what completed the retry.
        result_summary: Redacted result summary, never raw output.
        reason: Optional redacted reason.
        now: Transition instant, defaults to the current UTC time.

    Returns:
        The transition result.

    Raises:
        StorageUnavailableError: When the CAS cannot be written.
    """
    return transition(
        conn,
        ticket_id,
        (CONSUMED,),
        COMPLETED,
        actor=actor,
        reason=reason,
        now=now,
        result_summary=result_summary,
    )


def list_transitions(
    conn: sqlite3.Connection,
    ticket_id: str,
) -> list[dict[str, Any]]:
    """Return the persisted transition history of one ticket.

    Requirement: Ticket Persistence (each CAS leaves exactly one audit row).

    Args:
        conn: Open connection.
        ticket_id: Ticket identifier.

    Returns:
        Transition rows oldest first, as plain dicts.

    Raises:
        StorageUnavailableError: When the read fails.
    """
    try:
        rows = conn.execute(
            "SELECT * FROM ticket_transitions WHERE ticket_id = ? ORDER BY id ASC",
            (ticket_id,),
        ).fetchall()
    except sqlite3.Error as exc:
        raise StorageUnavailableError(f"cannot read transitions: {exc}") from exc
    return [dict(row) for row in rows]


def is_expired_window(
    ticket: Ticket, now: datetime | float | str | None = None
) -> bool:
    """Report whether an approved ticket window has already closed.

    Requirement: Approved Retry Outcome and Window.

    Args:
        ticket: Ticket under test.
        now: Comparison instant, defaults to the current UTC time.

    Returns:
        True when a window deadline is set and has passed.
    """
    if ticket.window_deadline is None:
        return False
    return ticket.window_deadline <= utc_iso(now)


__all__ = [
    "APPROVAL_WINDOW_S",
    "APPROVED",
    "CANCELED_EXTERNAL",
    "COMPLETED",
    "CONSUMED",
    "DENIED",
    "EXPIRED",
    "PENDING",
    "STARTUP_ACTOR",
    "STARTUP_REASON",
    "SWEEP_ORPHAN_GRACE_S",
    "TICKET_STATES",
    "TIMEOUT",
    "Ticket",
    "TicketTransitionResult",
    "cancel_external",
    "complete_ticket",
    "compute_window_deadline",
    "consume_approved",
    "create_ticket",
    "expire_stale",
    "get_ticket",
    "invalidate_on_startup",
    "is_expired_window",
    "list_pending",
    "list_transitions",
    "startup_sweep",
    "sweep",
    "transition",
]
