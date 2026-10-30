"""Decision audit trail and trajectory retention.

Requirement: Tables and Fields; Write Before Forward; Observe Verdict
Persistence; Unmanaged Side-Observation Audit; Sanitized Persistence;
Retention and Rotation; Storage Unavailable Is Deny.

Every value written here is already-redacted text: callers must pass the output
of `tooling_guard.anonymize` and this module never assembles raw arguments,
results or prompts.  A failed write raises StorageUnavailableError so the caller
turns the pending allow into deny.

`AuditWriter` is the ordered write path (one process-wide FIFO drain) and
`scan_for_secrets` is the read-only check that the redaction actually happened.
"""

from __future__ import annotations

import re
import sqlite3
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from typing import Any

from ..trace.retention import trim_for_subject
from .db import (
    StorageUnavailableError,
    retention_cutoff,
    rollback_quietly,
    serialized_write,
    utc_iso,
)
from .tickets import APPROVED, PENDING

SOURCE_NATIVE = "native"
"""Verdict produced on the managed native path."""

SOURCE_UNMANAGED_SIDE_OBSERVATION = "unmanaged_side_observation"
"""Side observation of a call the managed path could not intercept."""

SOURCE_MANUAL = "manual"
"""Operator command or test path."""

SOURCE_WEB = "web"
"""Administrator action submitted through the plugin's dashboard page."""

SOURCES: tuple[str, ...] = (
    SOURCE_NATIVE,
    SOURCE_UNMANAGED_SIDE_OBSERVATION,
    SOURCE_MANUAL,
    SOURCE_WEB,
)
"""Accepted values of the source column."""

REQUIRED_FIELDS: tuple[str, ...] = ("decision", "source")
"""Fields record_event demands on every row."""

_COLUMNS: tuple[str, ...] = (
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
    "args_digest",
    "labels",
    "delegated",
    "summary_json",
    "actor",
)
"""Columns of audit_events, in insert order.

judge_route, rule_set_version, args_digest, labels, delegated, summary_json and
actor are last because store/db.py appends them to a file written by an older
version with ALTER TABLE ADD COLUMN; keeping the insert order identical means a
fresh file and a migrated file hold the same physical column order.

args_digest, labels and summary_json carry the per-call trajectory record so one
audit row can be correlated with the arguments, the orthogonal labels, the
decision with its reason, the ticket marker and whether the call was delegated.

actor carries who made an administrator decision.  subject_key keeps describing
whose request the row is about, so a decision row no longer loses the requester
subject: the deciding identity has its own column instead of overwriting it.
"""

JUDGE_ROUTES: tuple[str, ...] = ("endpoint", "astrbot_provider", "jev")
"""Accepted values of judge_route; NULL records that no model judged the call."""

DELEGATED_YES = "yes"
"""delegated column: the call was let through to the real tool."""

DELEGATED_NO = "no"
"""delegated column: the call never reached the real tool."""

DELEGATED_VALUES: tuple[str, ...] = (DELEGATED_YES, DELEGATED_NO)
"""Accepted values of the delegated column.

`yes` records that the call was let through to the real tool (an allow_* verdict
in enforce mode, or the allow path observe mode takes); `no` records that it was
not (deny, suspend, timeout, cancel).  NULL records a row with no call semantics
at all, such as a /guard subcommand changing the mode.
"""
UNSETTLED_TICKET_STATES: tuple[str, ...] = (PENDING, APPROVED)
"""Ticket states whose audit rows retention must keep.

pending and approved are the two states that can still be decided, so an audit
row they reference is still evidence for a decision nobody has made yet.
"""

_AUDIT_TEXT_COLUMNS: tuple[str, ...] = (
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
    "judge_route",
    "rule_set_version",
    "args_digest",
    "labels",
    "summary_json",
    "actor",
)
"""Text columns of audit_events that scan_for_secrets inspects."""

_TRAJECTORY_TEXT_COLUMNS: tuple[str, ...] = (
    "subject_key",
    "session_key",
    "tool_name",
    "summary",
)
"""Text columns of trajectory_snippets that scan_for_secrets inspects."""

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_\-]{2,}"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"://[^/\s:@]+:[^/\s@]+@"),
)
"""Shapes that must never reach the database.

The `sk-` pattern is anchored on a non-alphanumeric boundary so an ordinary word
such as "risk-free" is not a hit while `sk-abc123` is.
"""

_OBSERVE_PREFIX = "allow"
"""Observe mode persists the real allow_* decision in the decision column."""


def _text(value: Any, field: str, *, required: bool) -> str | None:
    """Normalize one optional or required text field.

    Requirement: Sanitized Persistence (every persisted value is a string or
    NULL).

    Args:
        value: Candidate value.
        field: Column name used in the error message.
        required: Whether an empty value is an error.

    Returns:
        The stripped string, or None when it is empty and optional.

    Raises:
        ValueError: When a required field is empty.
        TypeError: When the value is not a string.
    """
    if value is None:
        if required:
            raise ValueError(f"audit field {field!r} is required")
        return None
    if not isinstance(value, str):
        raise TypeError(f"audit field {field!r} must be a string")
    stripped = value.strip()
    if not stripped:
        if required:
            raise ValueError(f"audit field {field!r} is required")
        return None
    return stripped


def _judge_route(value: Any) -> str | None:
    """Normalize the nullable judge-route column.

    Requirement: Tables and Fields.  The value names which model route
    produced the verdict, so only the routes the gateway can actually take are
    accepted; NULL means no model judged this call at all, and an empty string
    normalizes to NULL instead of recording an unnamed route.

    Args:
        value: Candidate value.

    Returns:
        One of JUDGE_ROUTES, or None when the call carried no route.

    Raises:
        TypeError: When the value is not a string.
        ValueError: When the value is not an accepted route.
    """
    route = _text(value, "judge_route", required=False)
    if route is not None and route not in JUDGE_ROUTES:
        raise ValueError(
            f"unknown judge_route: {route!r}; expected one of {JUDGE_ROUTES}"
        )
    return route


def _delegated(value: Any) -> str | None:
    """Normalize the nullable delegated column.

    Requirement: Trajectory Summary Record.  The column says whether the call
    reached the real tool, so only DELEGATED_VALUES are accepted; NULL records a
    row that carries no call semantics rather than an unresolved verdict.

    Args:
        value: Candidate value.

    Returns:
        One of DELEGATED_VALUES, or None.

    Raises:
        TypeError: When the value is not a string.
        ValueError: When the value is not an accepted marker.
    """
    marker = _text(value, "delegated", required=False)
    if marker is not None and marker not in DELEGATED_VALUES:
        raise ValueError(
            f"unknown delegated marker: {marker!r}; expected one of {DELEGATED_VALUES}"
        )
    return marker


def _is_observe(event: Mapping[str, Any]) -> bool:
    """Report whether the event was produced in observe mode.

    Requirement: Observe Verdict Persistence.  An event is an observe row when
    it says so explicitly, or when only a would-be verdict was recorded.

    Args:
        event: Candidate audit event.

    Returns:
        True when the row describes an observe-mode verdict.
    """
    flag = event.get("observe")
    if flag is not None:
        return bool(flag)
    return str(event.get("mode", "")).lower() == "observe"


@serialized_write
def record_event(conn: sqlite3.Connection, event: Mapping[str, Any]) -> int:
    """Insert one decision audit row.

    Requirement: Observe Verdict Persistence; Unmanaged Side-Observation Audit;
    Sanitized Persistence; Write Before Forward.  In observe mode the decision
    column keeps the real allow_* verdict and the would_be column records what
    enforcement would have done; that column is mandatory for observe rows and
    NULL otherwise.

    The insert and its commit run under the connection's commit owner
    (store.db.serialized_write), so a write issued from a worker thread -- the
    side-observation path -- cannot share a transaction with the drain that owns
    this queue on the event loop.

    Args:
        conn: Open connection from `store.db.open_or_raise`.
        event: Mapping with at least `decision` and `source`; remaining
            keys follow _COLUMNS.  `judge_route`, `rule_set_version`,
            `args_digest`, `labels`, `delegated`, `summary_json` and
            `actor` are optional, may be ``None``, and normalize to NULL when
            empty; every
            other key is optional once the row is not an observe row.  All text
            must already be redacted.

    Returns:
        The rowid of the inserted audit row.

    Raises:
        ValueError: When a required field is missing, a text field is not a
            string, the source is unknown, the judge_route is not one of
            JUDGE_ROUTES, or an observe row carries no would_be verdict.
        StorageUnavailableError: When the insert fails; the caller must deny.
    """
    decision = _text(event.get("decision"), "decision", required=True)
    source = _text(event.get("source"), "source", required=True)
    if source not in SOURCES:
        raise ValueError(f"unknown audit source: {source!r}")
    would_be = _text(event.get("would_be"), "would_be", required=False)
    if _is_observe(event) and would_be is None:
        raise ValueError("observe rows must record the would_be verdict")
    judge_route = _judge_route(event.get("judge_route"))
    rule_set_version = _text(
        event.get("rule_set_version"), "rule_set_version", required=False
    )
    args_digest = _text(event.get("args_digest"), "args_digest", required=False)
    labels = _text(event.get("labels"), "labels", required=False)
    delegated = _delegated(event.get("delegated"))
    summary_json = _text(event.get("summary_json"), "summary_json", required=False)
    actor = _text(event.get("actor"), "actor", required=False)
    row = (
        utc_iso(event.get("ts")),
        decision,
        would_be,
        _text(event.get("rule_id"), "rule_id", required=False),
        _text(event.get("tool_name"), "tool_name", required=False),
        _text(event.get("subject_key"), "subject_key", required=False),
        _text(event.get("session_key"), "session_key", required=False),
        _text(event.get("ticket_id"), "ticket_id", required=False),
        _text(event.get("policy_version"), "policy_version", required=False),
        _text(event.get("summary_line"), "summary_line", required=False),
        source,
        1 if event.get("degraded") else 0,
        judge_route,
        rule_set_version,
        args_digest,
        labels,
        delegated,
        summary_json,
        actor,
    )
    columns = ", ".join(_COLUMNS)
    placeholders = ", ".join("?" for _ in _COLUMNS)
    try:
        cursor = conn.execute(
            f"INSERT INTO audit_events ({columns}) VALUES ({placeholders})", row
        )
        conn.commit()
    except sqlite3.Error as exc:
        rollback_quietly(conn)
        raise StorageUnavailableError(f"cannot write audit event: {exc}") from exc
    return int(cursor.lastrowid or 0)


class AuditWriter:
    """Ordered, drainable audit write queue bound to one connection.

    Requirement: Retention and Rotation (single write queue).  The store is
    synchronous sqlite on one connection inside one event loop, so a single
    ``record_event`` call is already atomic: it never awaits, so two commits
    cannot interleave.  What that does NOT give is *submission* order -- any
    ``await`` between "row N was decided" and its insert lets row N+1 commit
    first.  This writer makes the queue the ordering authority: ``submit`` only
    appends and ``drain`` inserts in FIFO order, so commit order equals
    submission order by construction.

    No thread, timer or background task is started: the queue is emptied only by
    an explicit ``drain``/``flush``.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        sink: Callable[[sqlite3.Connection, Mapping[str, Any]], int] | None = None,
        retention: Callable[[sqlite3.Connection], dict[str, int]] | None = None,
    ) -> None:
        """Build a writer over one connection.

        Args:
            conn: Open connection from `store.db.open_or_raise`.
            sink: Row writer, defaults to `record_event`; a test injects a
                failing sink to prove storage errors are not swallowed.
            retention: Optional retention pass applied after a drain that wrote
                at least one row, so trimming follows the write batch instead of
                racing it.
        """
        self._conn = conn
        self._sink = record_event if sink is None else sink
        self._retention = retention
        self._queue: deque[tuple[int, Mapping[str, Any]]] = deque()
        self._failures: list[tuple[int, str]] = []
        self._written = 0
        self._submitted = 0
        self._last_retention: dict[str, int] | None = None

    def submit(self, event: Mapping[str, Any]) -> int:
        """Queue one already-redacted event without touching the store.

        Args:
            event: Mapping accepted by `record_event`.

        Returns:
            The submission sequence number, which is also the position the row
            occupies in commit order.
        """
        sequence = self._submitted
        self._submitted += 1
        self._queue.append((sequence, event))
        return sequence

    @property
    def pending(self) -> int:
        """Number of events submitted but not yet written."""
        return len(self._queue)

    @property
    def failures(self) -> tuple[tuple[int, str], ...]:
        """Rejected rows as (submission sequence, error message) pairs."""
        return tuple(self._failures)

    @property
    def written(self) -> int:
        """Total rows written by every drain so far."""
        return self._written

    @property
    def last_retention(self) -> dict[str, int] | None:
        """Counters of the retention pass run by the last drain, if any."""
        return self._last_retention

    def drain(self) -> int:
        """Write every queued event in FIFO order.

        Requirement: Retention and Rotation (single write queue).  A row the
        store rejects on its own merits is charged to `failures` and skipped, so
        it can never block or reorder the rows behind it.  A storage error is
        deliberately re-raised with that row still queued: the caller treats it
        as "storage unavailable, deny", and the next drain retries the row
        instead of losing it.

        Returns:
            Number of rows written by this call.

        Raises:
            StorageUnavailableError: When an insert fails; the failed row and
                everything behind it stay queued.
        """
        written = 0
        while self._queue:
            sequence, event = self._queue[0]
            try:
                self._sink(self._conn, event)
            except (ValueError, TypeError) as exc:
                self._failures.append((sequence, str(exc)))
                self._queue.popleft()
                continue
            self._queue.popleft()
            written += 1
        self._written += written
        if written and self._retention is not None:
            self._last_retention = self._retention(self._conn)
        return written

    def flush(self) -> int:
        """Drain the queue; an alias of `drain` for call sites that read better."""
        return self.drain()


def record_side_observation(
    conn: sqlite3.Connection,
    *,
    decision: str,
    tool_name: str | None = None,
    subject_key: str | None = None,
    session_key: str | None = None,
    summary_line: str | None = None,
    degraded: bool = True,
    rule_id: str | None = None,
    policy_version: str | None = None,
    now: datetime | float | str | None = None,
) -> int:
    """Insert an audit row for a call observed outside the managed path.

    Requirement: Unmanaged Side-Observation Audit (source is recorded as
    `unmanaged_side_observation` and the row never implies enforcement).

    Args:
        conn: Open connection.
        decision: Verdict that was actually applied (usually allow_*).
        tool_name: Managed tool name, when known.
        subject_key: Redacted identity, when known.
        session_key: Minimized session key, when known.
        summary_line: One already-redacted line describing the call.
        degraded: Whether the event is marked degraded, default True.
        rule_id: Matched rule identifier, when known.
        policy_version: Policy snapshot version, when known.
        now: Event instant, defaults to the current UTC time.

    Returns:
        The rowid of the inserted audit row.

    Raises:
        StorageUnavailableError: When the insert fails; the caller must deny.
    """
    return record_event(
        conn,
        {
            "ts": now,
            "decision": decision,
            "source": SOURCE_UNMANAGED_SIDE_OBSERVATION,
            "tool_name": tool_name,
            "subject_key": subject_key,
            "session_key": session_key,
            "summary_line": summary_line,
            "degraded": degraded,
            "rule_id": rule_id,
            "policy_version": policy_version,
        },
    )


def query_recent(conn: sqlite3.Connection, limit: int = 50) -> list[dict[str, Any]]:
    """Return the most recent audit rows, newest first.

    Requirement: Operator Introspection.

    Args:
        conn: Open connection.
        limit: Maximum number of rows; must be at least 1.

    Returns:
        Plain dicts of every audit column, newest first.

    Raises:
        ValueError: When limit is below 1.
        StorageUnavailableError: When the read fails.
    """
    if int(limit) < 1:
        raise ValueError("limit must be >= 1")
    try:
        rows = conn.execute(
            "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (int(limit),)
        ).fetchall()
    except sqlite3.Error as exc:
        raise StorageUnavailableError(f"cannot read audit events: {exc}") from exc
    return [dict(row) for row in rows]


def query_by_ticket(
    conn: sqlite3.Connection, ticket_id: str, limit: int = 50
) -> list[dict[str, Any]]:
    """Return the audit rows recorded for one ticket.

    Requirement: Operator Introspection.

    Args:
        conn: Open connection.
        ticket_id: Ticket identifier.
        limit: Maximum number of rows; must be at least 1.

    Returns:
        Plain dicts, newest first.

    Raises:
        ValueError: When limit is below 1.
        StorageUnavailableError: When the read fails.
    """
    if int(limit) < 1:
        raise ValueError("limit must be >= 1")
    try:
        rows = conn.execute(
            "SELECT * FROM audit_events WHERE ticket_id = ? ORDER BY id DESC LIMIT ?",
            (ticket_id, int(limit)),
        ).fetchall()
    except sqlite3.Error as exc:
        raise StorageUnavailableError(f"cannot read audit events: {exc}") from exc
    return [dict(row) for row in rows]


def query_events(
    conn: sqlite3.Connection,
    *,
    subject_key: str | None = None,
    session_key: str | None = None,
    decision: str | None = None,
    rule_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Return one filtered page of audit rows plus the matching total.

    Requirement: Read Filtering; Visibility Scope. Filtering happens in SQL, so
    a row the caller may not see is never selected, and every condition is
    combined with AND.

    Args:
        conn: Open connection.
        subject_key: Exact subject to restrict to; a non-administrator reader
            passes its own subject here.
        session_key: Exact session to restrict to.
        decision: Exact decision value.
        rule_id: Exact rule identifier.
        since: Inclusive lower bound of the ts column, an ISO timestamp.
        until: Inclusive upper bound of the ts column, an ISO timestamp.
        limit: Page size; must be at least 1.
        offset: Rows to skip; must be at least 0.

    Returns:
        The page of rows, newest first, and the total number of matching rows.

    Raises:
        ValueError: When limit is below 1 or offset is negative.
        StorageUnavailableError: When the read fails.
    """
    if int(limit) < 1:
        raise ValueError("limit must be >= 1")
    if int(offset) < 0:
        raise ValueError("offset must be >= 0")
    clauses: list[str] = []
    params: list[Any] = []
    for column, value in (
        ("subject_key", subject_key),
        ("session_key", session_key),
        ("decision", decision),
        ("rule_id", rule_id),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    if since is not None:
        clauses.append("ts >= ?")
        params.append(since)
    if until is not None:
        clauses.append("ts <= ?")
        params.append(until)
    where = " AND ".join(clauses)
    where = f" WHERE {where}" if where else ""
    try:
        total_row = conn.execute(
            f"SELECT COUNT(*) AS total FROM audit_events{where}", tuple(params)
        ).fetchone()
        rows = conn.execute(
            f"SELECT * FROM audit_events{where} ORDER BY id DESC LIMIT ? OFFSET ?",
            (*params, int(limit), int(offset)),
        ).fetchall()
    except sqlite3.Error as exc:
        raise StorageUnavailableError(f"cannot read audit events: {exc}") from exc
    return [dict(row) for row in rows], int(total_row["total"])


def count_events(conn: sqlite3.Connection) -> int:
    """Return the number of persisted audit rows.

    Requirement: Operator Introspection.

    Args:
        conn: Open connection.

    Returns:
        Row count of the audit table.

    Raises:
        StorageUnavailableError: When the read fails.
    """
    try:
        row = conn.execute("SELECT COUNT(*) AS total FROM audit_events").fetchone()
    except sqlite3.Error as exc:
        raise StorageUnavailableError(f"cannot count audit events: {exc}") from exc
    return int(row["total"])


def _row_matches_secret(row: sqlite3.Row, columns: tuple[str, ...]) -> bool:
    """Report whether one row carries a key shape in an inspected column.

    Args:
        row: Row holding every column named in columns.
        columns: Text columns to inspect.

    Returns:
        True when any column matches SECRET_PATTERNS.
    """
    for column in columns:
        value = row[column]
        if not isinstance(value, str):
            continue
        if any(pattern.search(value) for pattern in SECRET_PATTERNS):
            return True
    return False


def _count_secret_rows(
    conn: sqlite3.Connection, table: str, columns: tuple[str, ...]
) -> int:
    """Count the rows of one table that carry a key shape.

    Args:
        conn: Open connection.
        table: Table name; an internal literal, never caller input.
        columns: Text columns to inspect.

    Returns:
        Number of matching rows.

    Raises:
        StorageUnavailableError: When the read fails.
    """
    hits = 0
    try:
        for row in conn.execute(f"SELECT * FROM {table}"):
            if _row_matches_secret(row, columns):
                hits += 1
    except sqlite3.Error as exc:
        raise StorageUnavailableError(f"cannot scan {table}: {exc}") from exc
    return hits


def scan_for_secrets(conn: sqlite3.Connection) -> tuple[int, int]:
    """Count stored rows that still contain a key-shaped string.

    Requirement: Sanitized Persistence (redaction is verified, never assumed).
    Redaction happens before the write, so this read-only check is the evidence:
    zero hits on the normal path plus a non-zero count after raw text is stored
    deliberately is what proves "no secret reaches the database".  A hit is an
    operator-visible defect; nothing is rewritten silently here.

    Args:
        conn: Open connection.

    Returns:
        ``(audit_events hits, trajectory_snippets hits)``.

    Raises:
        StorageUnavailableError: When the store cannot be read.
    """
    return (
        _count_secret_rows(conn, "audit_events", _AUDIT_TEXT_COLUMNS),
        _count_secret_rows(conn, "trajectory_snippets", _TRAJECTORY_TEXT_COLUMNS),
    )


def _has_ticket_table(conn: sqlite3.Connection) -> bool:
    """Report whether this file holds a ticket table.

    Requirement: Retention and Rotation.  A file written before the ticket table
    existed holds no ticket references, so a missing table means "nothing to
    protect" rather than a retention failure.

    Args:
        conn: Open connection.

    Returns:
        True when the tickets table exists.
    """
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'tickets'"
        ).fetchone()
    except sqlite3.Error:
        return False
    return row is not None


@serialized_write
def purge_older_than(
    conn: sqlite3.Connection,
    days: int | None = None,
    *,
    now: datetime | None = None,
) -> int:
    """Delete audit rows older than the retention window.

    Requirement: Retention and Rotation (the window is the configured
    `audit_retention_days`, seven days by default).  The comparison is a strict
    `ts < cutoff`, so a row sitting exactly on the boundary survives.  Rows
    referenced by a ticket still in UNSETTLED_TICKET_STATES are kept: they are
    the evidence for a decision that has not been made yet.

    The protection is a correlated NOT EXISTS subquery rather than a
    NOT IN (?, ?, …) list of every open ticket identifier: the bind count must
    not grow with the number of open tickets, or a store holding more open
    tickets than SQLITE_MAX_VARIABLE_NUMBER could never be purged at all. This
    statement binds one cutoff plus one marker per state in
    UNSETTLED_TICKET_STATES, whatever the ticket table holds.

    Args:
        conn: Open connection.
        days: Retention window in days; defaults to the seven day baseline and
            must be at least 1.
        now: Reference instant, defaults to the current UTC time.

    Returns:
        Number of deleted rows.

    Raises:
        ValueError: When days is below 1.
        StorageUnavailableError: When the delete fails.
    """
    window = DEFAULT_AUDIT_RETENTION_DAYS if days is None else int(days)
    cutoff = retention_cutoff(window, now=now)
    params: list[Any]
    if _has_ticket_table(conn):
        marks = ", ".join("?" for _ in UNSETTLED_TICKET_STATES)
        statement = "DELETE FROM audit_events WHERE ts < ?"
        statement += " AND NOT EXISTS (SELECT 1 FROM tickets t"
        statement += " WHERE t.ticket_id = audit_events.ticket_id"
        statement += f" AND t.state IN ({marks}))"
        params = [cutoff, *UNSETTLED_TICKET_STATES]
    else:
        statement = "DELETE FROM audit_events WHERE ts < ?"
        params = [cutoff]
    try:
        cursor = conn.execute(statement, params)
        deleted = int(cursor.rowcount or 0)
        conn.commit()
    except sqlite3.Error as exc:
        rollback_quietly(conn)
        raise StorageUnavailableError(f"cannot purge audit events: {exc}") from exc
    return deleted


@serialized_write
def record_trajectory_snippet(
    conn: sqlite3.Connection,
    *,
    subject_key: str,
    summary: str,
    session_key: str | None = None,
    tool_name: str | None = None,
    now: datetime | float | str | None = None,
    keep: int | None = None,
) -> int:
    """Append one redacted trajectory snippet and trim the subject's history.

    Requirement: Retention and Rotation (trajectory retention is
    `trajectory_retention_per_user` entries per subject, fifty by default).

    Args:
        conn: Open connection.
        subject_key: Redacted identity the snippet belongs to.
        summary: Already-redacted snippet text.
        session_key: Minimized session key, when known.
        tool_name: Managed tool name, when known.
        now: Snippet instant, defaults to the current UTC time.
        keep: Per-subject cap applied right after the insert; when omitted no
            trimming happens and the caller must call trim_trajectory itself.

    Returns:
        The rowid of the inserted snippet.

    Raises:
        ValueError: When a required text field is empty.
        StorageUnavailableError: When the insert or trim fails.
    """
    row = (
        _text(subject_key, "subject_key", required=True),
        _text(session_key, "session_key", required=False),
        _text(tool_name, "tool_name", required=False),
        _text(summary, "summary", required=True),
        utc_iso(now),
    )
    try:
        cursor = conn.execute(
            "INSERT INTO trajectory_snippets"
            " (subject_key, session_key, tool_name, summary, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            row,
        )
        conn.commit()
    except sqlite3.Error as exc:
        rollback_quietly(conn)
        raise StorageUnavailableError(
            f"cannot write trajectory snippet: {exc}"
        ) from exc
    snippet_id = int(cursor.lastrowid or 0)
    if keep is not None:
        trim_trajectory(conn, row[0], keep)
    return snippet_id


_TRIM_BATCH = 400
"""Rows deleted per statement; keeps below the sqlite host-parameter limit."""


@serialized_write
def trim_trajectory(conn: sqlite3.Connection, subject_key: str, keep: int) -> int:
    """Keep only the newest snippets of one subject.

    Requirement: Retention and Rotation.  The newest `keep` rows of the subject
    are kept and every older row is deleted.  Which rows survive is decided by
    `trace.retention.trim_for_subject`, so the snippet cap has exactly one
    definition and the in-memory and on-disk paths cannot drift apart.

    Args:
        conn: Open connection.
        subject_key: Redacted identity to trim.
        keep: Number of newest snippets to retain; must be at least 1.

    Returns:
        Number of deleted rows.

    Raises:
        ValueError: When subject_key is empty or keep is below 1.
        StorageUnavailableError: When the trim fails.
    """
    subject = _text(subject_key, "subject_key", required=True)
    cap = int(keep)
    if cap < 1:
        raise ValueError("keep must be >= 1")
    try:
        rows = conn.execute(
            "SELECT id FROM trajectory_snippets WHERE subject_key = ? ORDER BY id",
            (subject,),
        ).fetchall()
    except sqlite3.Error as exc:
        raise StorageUnavailableError(f"cannot read trajectory: {exc}") from exc
    identifiers = [int(row["id"]) for row in rows]
    surviving = set(trim_for_subject(identifiers, cap))
    stale = [value for value in identifiers if value not in surviving]
    if not stale:
        return 0
    deleted = 0
    try:
        for start in range(0, len(stale), _TRIM_BATCH):
            chunk = stale[start : start + _TRIM_BATCH]
            marks = ", ".join("?" for _ in chunk)
            cursor = conn.execute(
                f"DELETE FROM trajectory_snippets WHERE id IN ({marks})", chunk
            )
            deleted += int(cursor.rowcount or 0)
        conn.commit()
    except sqlite3.Error as exc:
        rollback_quietly(conn)
        raise StorageUnavailableError(f"cannot trim trajectory: {exc}") from exc
    return deleted


def list_trajectory(
    conn: sqlite3.Connection, subject_key: str, limit: int = 50
) -> list[dict[str, Any]]:
    """Return one subject's recent trajectory snippets, newest first.

    Requirement: Operator Introspection; Retention and Rotation.

    Args:
        conn: Open connection.
        subject_key: Redacted identity to read.
        limit: Maximum number of rows; must be at least 1.

    Returns:
        Plain dicts of snippet rows, newest first.

    Raises:
        ValueError: When subject_key is empty or limit is below 1.
        StorageUnavailableError: When the read fails.
    """
    subject = _text(subject_key, "subject_key", required=True)
    if int(limit) < 1:
        raise ValueError("limit must be >= 1")
    try:
        rows = conn.execute(
            "SELECT * FROM trajectory_snippets WHERE subject_key = ?"
            " ORDER BY id DESC LIMIT ?",
            (subject, int(limit)),
        ).fetchall()
    except sqlite3.Error as exc:
        raise StorageUnavailableError(f"cannot read trajectory: {exc}") from exc
    return [dict(row) for row in rows]


DEFAULT_AUDIT_RETENTION_DAYS = 7
"""Configured default of `audit_retention_days`."""

DEFAULT_TRAJECTORY_KEEP = 50
"""Configured default of `trajectory_retention_per_user`."""


@serialized_write
def apply_retention(
    conn: sqlite3.Connection,
    *,
    audit_days: int | None = None,
    per_subject_keep: int | None = None,
    trajectory_keep: int | None = None,
    subjects: Iterable[str] | None = None,
    now: datetime | None = None,
) -> dict[str, int]:
    """Apply audit purge and per-subject trajectory trimming in one call.

    Requirement: Retention and Rotation.  Idempotent: a second call with the
    same arguments deletes nothing, because both passes are expressed as "rows
    that are already too old / already past the cap".  Audit rows referenced by
    an unsettled ticket survive the purge (see `purge_older_than`).

    Args:
        conn: Open connection.
        audit_days: Audit window in days, defaults to the seven day baseline.
        per_subject_keep: Per-subject snippet cap, defaults to fifty.
        trajectory_keep: Deprecated alias of `per_subject_keep`; kept so call
            sites written against the earlier name keep working.
        subjects: Subjects to trim; when omitted, every subject that has any
            snippet is trimmed.
        now: Reference instant, defaults to the current UTC time.

    Returns:
        Deleted row count per table: `{"audit_events": n,
        "trajectory_snippets": m}`.

    Raises:
        ValueError: When both cap parameters disagree.
        StorageUnavailableError: When a delete fails.
    """
    if (
        per_subject_keep is not None
        and trajectory_keep is not None
        and int(per_subject_keep) != int(trajectory_keep)
    ):
        raise ValueError("per_subject_keep and trajectory_keep disagree")
    requested = per_subject_keep if per_subject_keep is not None else trajectory_keep
    keep = DEFAULT_TRAJECTORY_KEEP if requested is None else int(requested)
    targets: list[str] = list(subjects) if subjects is not None else []
    if subjects is None:
        try:
            rows = conn.execute(
                "SELECT DISTINCT subject_key FROM trajectory_snippets"
            ).fetchall()
        except sqlite3.Error as exc:
            raise StorageUnavailableError(
                f"cannot list trajectory subjects: {exc}"
            ) from exc
        targets = [row["subject_key"] for row in rows]
    audit_deleted = purge_older_than(conn, audit_days, now=now)
    trajectory_deleted = 0
    for subject in targets:
        trajectory_deleted += trim_trajectory(conn, subject, keep)
    return {
        "audit_events": audit_deleted,
        "trajectory_snippets": trajectory_deleted,
    }


__all__ = [
    "DEFAULT_AUDIT_RETENTION_DAYS",
    "DEFAULT_TRAJECTORY_KEEP",
    "JUDGE_ROUTES",
    "SECRET_PATTERNS",
    "SOURCES",
    "SOURCE_MANUAL",
    "SOURCE_NATIVE",
    "SOURCE_UNMANAGED_SIDE_OBSERVATION",
    "UNSETTLED_TICKET_STATES",
    "AuditWriter",
    "apply_retention",
    "count_events",
    "list_trajectory",
    "purge_older_than",
    "query_by_ticket",
    "query_recent",
    "record_event",
    "record_side_observation",
    "record_trajectory_snippet",
    "scan_for_secrets",
    "trim_trajectory",
]
