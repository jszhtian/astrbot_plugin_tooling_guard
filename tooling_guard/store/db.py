"""SQLite lifecycle for the tooling guard store: open, migrate, close.

Requirement: Storage Location; Storage Unavailable Is Deny; Schema Versioning;
Tables and Fields.

This module is the only place allowed to call `sqlite3.connect` in the whole
package (ARCHITECTURE.md section 3).  Everything else receives the
`sqlite3.Connection` created here.

Migration version 1 creates these columns:

`schema_version`
    `version`, `applied_at`
`audit_events`
    `id`, `ts`, `decision`, `would_be`, `rule_id`, `tool_name`,
    `subject_key`, `session_key`, `ticket_id`, `policy_version`,
    `summary_line`, `source`, `degraded`, `judge_route`, `rule_set_version`,
    `args_digest`, `labels`, `delegated`, `summary_json`, `actor`
`tickets`
    `ticket_id`, `marker`, `subject_key`, `session_key`, `tool_name`,
    `args_digest`, `created_at`, `approved_at`, `window_deadline`,
    `state`, `decided_by`, `reason`, `retry_consumed`,
    `result_summary`, `updated_at`, `completed_at`
`ticket_transitions`
    `id`, `ticket_id`, `from_state`, `to_state`, `actor`, `reason`,
    `at`
`trajectory_snippets`
    `id`, `subject_key`, `session_key`, `tool_name`, `summary`,
    `created_at`
"""

from __future__ import annotations

import functools
import logging
import os
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_LOGGER = logging.getLogger("tooling_guard")
"""Logger used for the failures that must not stop the store from opening."""

PLUGIN_NAME = "astrbot_plugin_tooling_guard"
"""Plugin name handed to the host data-directory accessor."""

LEGACY_PLUGIN_NAME = "astrbot_tooling_guard"
"""Pre-rename plugin name, whose data directory is migrated once on first load."""

DB_FILENAME = "tooling_guard.sqlite3"
"""Database file name inside the plugin data directory."""

SCHEMA_VERSION = 3
"""Schema version this code writes and understands."""

BUSY_TIMEOUT_MS = 150
"""Write-lock wait the audit connection gives SQLite.

Requirement: Fail-Closed on Broken Choke Point.  The store is written from the
same coroutine that drives the request, so every millisecond the busy handler
waits is a millisecond the event loop cannot answer anything else.  At 5000 ms
one contended write froze the loop until the lock cleared -- 5.5 s measured,
with the heartbeat counter still at zero -- so the wait is short enough to give
up inside one frame and report "database is locked" instead.  Work that can
legitimately take seconds belongs on a worker thread, see
SideObserver.record_async in tooling_guard/observation.py.
"""

ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
"""Canonical stored timestamp: UTC, fixed width, so ordering == chronology."""

_PLUGIN_DIR = Path(__file__).resolve().parents[2]
"""Plugin directory.  The database must never live below this path."""

_SCHEMA_VERSION_DDL = """CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
)"""

MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: (
        _SCHEMA_VERSION_DDL,
        """CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    decision TEXT NOT NULL,
    would_be TEXT,
    rule_id TEXT,
    tool_name TEXT,
    subject_key TEXT,
    session_key TEXT,
    ticket_id TEXT,
    policy_version TEXT,
    summary_line TEXT,
    source TEXT NOT NULL,
    degraded INTEGER NOT NULL DEFAULT 0,
    judge_route TEXT,
    rule_set_version TEXT,
    args_digest TEXT,
    labels TEXT,
    delegated TEXT,
    summary_json TEXT,
    actor TEXT
)""",
        """CREATE INDEX IF NOT EXISTS idx_audit_events_ts
    ON audit_events(ts)""",
        """CREATE TABLE IF NOT EXISTS tickets (
    ticket_id TEXT PRIMARY KEY,
    marker TEXT NOT NULL UNIQUE,
    subject_key TEXT NOT NULL,
    session_key TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    args_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    approved_at TEXT,
    window_deadline TEXT,
    state TEXT NOT NULL,
    decided_by TEXT,
    reason TEXT,
    retry_consumed INTEGER NOT NULL DEFAULT 0,
    result_summary TEXT,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    ticket_kind TEXT
)""",
        """CREATE INDEX IF NOT EXISTS idx_tickets_state ON tickets(state)""",
        """CREATE TABLE IF NOT EXISTS ticket_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id TEXT NOT NULL REFERENCES tickets(ticket_id) ON DELETE CASCADE,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT,
    at TEXT NOT NULL
)""",
        """CREATE INDEX IF NOT EXISTS idx_ticket_transitions_ticket
    ON ticket_transitions(ticket_id)""",
        """CREATE TABLE IF NOT EXISTS trajectory_snippets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_key TEXT NOT NULL,
    session_key TEXT,
    tool_name TEXT,
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL
)""",
        """CREATE INDEX IF NOT EXISTS idx_trajectory_snippets_subject
    ON trajectory_snippets(subject_key, id)""",
    ),
    2: (
        """CREATE TABLE IF NOT EXISTS notice_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id TEXT NOT NULL,
    admin TEXT NOT NULL,
    target TEXT,
    sent_at TEXT NOT NULL
)""",
        """CREATE INDEX IF NOT EXISTS idx_notice_deliveries_admin
    ON notice_deliveries(admin, sent_at)""",
        """CREATE INDEX IF NOT EXISTS idx_notice_deliveries_ticket
    ON notice_deliveries(ticket_id)""",
    ),
    3: (),
}
"""Forward-only migrations keyed by target schema version.

Version 3 adds no table of its own: `tickets.ticket_kind` is a late column and
is created by `_ensure_columns` (idempotent) rather than by a bare ALTER TABLE
inside a migration.  The bump is still recorded so a file written by this
version cannot be read by an older build as a version it understands.
"""

_ADDED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("audit_events", "judge_route", "TEXT"),
    ("audit_events", "rule_set_version", "TEXT"),
    ("audit_events", "args_digest", "TEXT"),
    ("audit_events", "labels", "TEXT"),
    ("audit_events", "delegated", "TEXT"),
    ("audit_events", "summary_json", "TEXT"),
    ("audit_events", "actor", "TEXT"),
    ("tickets", "ticket_kind", "TEXT"),
)
"""Columns added after the initial schema, as (table, column, declaration).

A fresh file gets them from MIGRATIONS[1]; a file written by an older version
gets them from _ensure_columns, so both end up with the same columns.
"""

TABLES: tuple[str, ...] = (
    "schema_version",
    "audit_events",
    "tickets",
    "ticket_transitions",
    "trajectory_snippets",
    "notice_deliveries",
)
"""Tables the migration guarantees to exist."""


class StorageUnavailableError(RuntimeError):
    """Raised when the store cannot be opened, migrated, read or written.

    Requirement: Storage Unavailable Is Deny.  Callers must treat this as
    "storage unavailable": every managed call is denied in every mode
    (including observe); it is never a reason to allow a call.
    """


def utc_iso(value: datetime | float | str | None = None) -> str:
    """Return the canonical UTC timestamp string used for every stored time.

    Requirement: Tables and Fields (fixed column representation).

    Args:
        value: None for "now", an aware or naive datetime (naive is read as
            UTC), epoch seconds, or an already canonical string, which is
            returned unchanged.

    Returns:
        `YYYY-MM-DDTHH:MM:SS.ffffffZ` in UTC; string ordering equals
        chronological ordering, so SQL comparisons stay correct.

    Raises:
        TypeError: When value is not a supported timestamp type.
    """
    if value is None:
        moment = datetime.now(UTC)
    elif isinstance(value, datetime):
        moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        moment = moment.astimezone(UTC)
    elif isinstance(value, (int, float)):
        moment = datetime.fromtimestamp(float(value), tz=UTC)
    elif isinstance(value, str):
        return value
    else:
        raise TypeError(f"unsupported timestamp type: {type(value)!r}")
    return moment.strftime(ISO_FORMAT)


PROCESS_STARTED_AT: str = utc_iso()
"""The instant this process started, captured once when this module loads.

Requirement: Ticket Persistence (review R11-03). The controlled startup-sweep
recovery may only withdraw what an earlier process left behind, so it needs a
cutoff that does not move: reading the clock per call would push the horizon
forward on every retry and let the retry cancel this process's own live tickets.
"""


def retention_cutoff(days: int, *, now: datetime | None = None) -> str:
    """Return the timestamp *days* days before *now*, for retention deletes.

    Requirement: Retention and Rotation.

    Args:
        days: Whole days to subtract; must be at least 1.
        now: Reference instant, defaults to the current UTC time.

    Returns:
        Canonical UTC timestamp suitable for a `ts < ?` comparison.

    Raises:
        ValueError: When days is below 1.
    """
    if days < 1:
        raise ValueError("retention days must be >= 1")
    reference = now if now is not None else datetime.now(UTC)
    return utc_iso(reference - timedelta(days=days))


def _failing_accessor(_name: str | None = None) -> Path:
    """Stand-in accessor used when the host accessor cannot be imported."""
    raise StorageUnavailableError("host data-directory accessor unavailable")


def _host_accessor() -> Callable[[str | None], Path | str]:
    """Return the public StarTools.get_data_dir accessor when importable.

    Requirement: Storage Location (resolve through the AstrBot accessor first).

    Returns:
        The public accessor, or a callable that raises
        StorageUnavailableError when only the public API is missing.
    """
    try:
        from astrbot.api.star import StarTools
    except Exception:  # noqa: BLE001 - any import failure means "no accessor"
        return _failing_accessor
    accessor = getattr(StarTools, "get_data_dir", None)
    if not callable(accessor):
        return _failing_accessor
    return accessor


def ensure_outside_plugin_dir(path: Path | str) -> Path:
    """Return *path* as an absolute path, refusing the plugin directory.

    Requirement: Storage Location (the database is never stored inside the
    plugin directory, which the host replaces on every update).

    Args:
        path: Candidate directory or database file path.

    Returns:
        The resolved absolute path.

    Raises:
        StorageUnavailableError: When path resolves below the plugin directory.
    """
    resolved = Path(path).resolve()
    try:
        resolved.relative_to(_PLUGIN_DIR)
    except ValueError:
        return resolved
    raise StorageUnavailableError(
        f"refusing to store inside the plugin directory: {resolved}"
    )


def resolve_data_dir(
    accessor: Callable[[str | None], Path | str] | None = None,
) -> Path:
    """Resolve the plugin data directory in the specified precedence order.

    Requirement: Storage Location.  Order: the host accessor
    StarTools.get_data_dir(PLUGIN_NAME), then ASTRBOT_DATA_DIR with
    plugin_data/<plugin> appended, then the local fallback
    ./data/plugin_data/<plugin> (the AstrBot root data directory).

    Args:
        accessor: Optional replacement for the host accessor; tests inject one
            so the live data directory is never touched.  None uses the public
            AstrBot accessor.

    Returns:
        Absolute path of the plugin data directory.  It is not created here.

    Raises:
        StorageUnavailableError: When no candidate resolves outside the plugin
            directory.
    """
    host = accessor if accessor is not None else _host_accessor()
    candidates: list[Path] = []
    host_path: Path | None = None
    try:
        host_path = Path(host(PLUGIN_NAME))
    except Exception:  # noqa: BLE001 - an accessor failure only drops this candidate
        host_path = None
    if host_path is not None:
        candidates.append(host_path)
    env_root = os.environ.get("ASTRBOT_DATA_DIR")
    if env_root:
        candidates.append(Path(env_root) / "plugin_data" / PLUGIN_NAME)
    candidates.append(Path.cwd() / "data" / "plugin_data" / PLUGIN_NAME)

    failures: list[str] = []
    for candidate in candidates:
        try:
            return ensure_outside_plugin_dir(candidate)
        except StorageUnavailableError as exc:
            failures.append(str(exc))
    raise StorageUnavailableError(
        "no writable data directory outside the plugin directory: "
        + "; ".join(failures)
    )


def default_db_path(
    accessor: Callable[[str | None], Path | str] | None = None,
) -> Path:
    """Return the default database path inside the plugin data directory.

    Requirement: Storage Location.

    Args:
        accessor: Optional replacement for the host accessor.

    Returns:
        Absolute path `<plugin data dir>/tooling_guard.sqlite3`.
    """
    return resolve_data_dir(accessor) / DB_FILENAME


def _dir_is_empty(path: Path) -> bool:
    """Return True when *path* is an empty directory.

    Args:
        path: Directory to inspect.

    Returns:
        True only when the directory exists, can be listed, and holds no
        entries; a listing failure counts as "not empty" so the caller never
        renames a directory it could not read.
    """
    try:
        return next(path.iterdir(), None) is None
    except OSError:
        return False


def _migrate_legacy_data_dir(legacy: Path, target: Path) -> str | None:
    """Rename *legacy* to *target*, or explain why it was left alone.

    Args:
        legacy: Existing legacy data directory.
        target: Resolved new data directory, absent or empty.

    Returns:
        A one-line explanation, or None when there is no legacy directory.
    """
    if not legacy.is_dir():
        return None
    if target.exists() and not _dir_is_empty(target):
        return (
            f"legacy data dir {legacy} left in place: "
            f"{target} already has content (no merge)"
        )
    if target.exists():
        target.rmdir()
    legacy.rename(target)
    return f"migrated legacy data dir {legacy} -> {target}"


def migrate_legacy_data_dir(path: Path | str) -> str | None:
    """Migrate the pre-rename data directory into the resolved one, once.

    Requirement: Storage Location.  The plugin directory name changed from
    astrbot_tooling_guard to astrbot_plugin_tooling_guard, so an installation
    created before the rename keeps its audit store only if the old directory is
    moved into place.  The directory is renamed, never merged: a new directory
    that already holds data wins and the legacy one is reported instead.

    Args:
        path: The already-resolved new data directory.

    Returns:
        A one-line explanation for the caller to log, or None when there is
        nothing to migrate.  Refusals and failures are returned as text rather
        than raised, because a load must never fail on it.
    """
    try:
        target = ensure_outside_plugin_dir(path)
        legacy = ensure_outside_plugin_dir(target.parent / LEGACY_PLUGIN_NAME)
    except StorageUnavailableError as exc:
        return f"refusing legacy data dir migration: {exc}"
    try:
        return _migrate_legacy_data_dir(legacy, target)
    except Exception as exc:  # noqa: BLE001 - a failed migration must not block load
        return f"legacy data dir migration failed: {exc}"


@dataclass(frozen=True)
class StartupSweepState:
    """What the startup ticket sweep of one connection last reported.

    Requirement: Ticket Persistence; Storage Unavailable Is Deny.  `attempts`
    counts the sweeps the connection has run: one that never attempted a sweep
    is not failed closed, and once an attempt fails the approval side stays
    closed until a later attempt succeeds.

    Attributes:
        ok: True when the last attempted sweep settled the stale tickets.
        error: Failure text of the last failed sweep, empty when it succeeded.
        attempts: How many sweeps this connection has run.
    """

    ok: bool
    error: str
    attempts: int


class _CommitOwner:
    """Write serialization and sweep state of one connection.

    Requirement: Write Before Forward; Unmanaged Side-Observation Audit.
    `sqlite3.connect(check_same_thread=False)` removes the thread-affinity check
    only: two threads sharing a connection share its transaction, so one side's
    rollback discards the other's uncommitted rows and one side's commit commits
    them.  The owner is one re-entrant lock per connection, held from before a
    write function's first statement until after its commit or rollback, so a
    transaction can never interleave with another thread's.  Re-entrant because
    write helpers call write helpers (transition inside expire_stale, the
    transition insert inside consume_approved).

    Attributes:
        conn: The connection this owner belongs to.
        lock: The commit owner; see write_transaction.
        blocked: Threads currently waiting for the owner.
        sweep_ok: Whether the last attempted startup sweep succeeded.
        sweep_error: Failure text of that sweep.
        sweep_attempts: How many startup sweeps ran on this connection.
    """

    __slots__ = (
        "blocked",
        "conn",
        "lock",
        "sweep_attempts",
        "sweep_error",
        "sweep_ok",
    )

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.lock = threading.RLock()
        self.blocked = 0
        self.sweep_ok = True
        self.sweep_error = ""
        self.sweep_attempts = 0


_OWNERS: dict[int, _CommitOwner] = {}
"""Commit owners keyed by id(conn); each entry keeps its connection alive."""

_OWNERS_LOCK = threading.RLock()
"""Guards _OWNERS and every counter read or written below."""


def _owner(conn: sqlite3.Connection) -> _CommitOwner:
    """Return the commit owner of *conn*, registering one on first use.

    The entry holds a strong reference to the connection, so its id cannot be
    recycled while the entry is registered; close_db drops the entry.

    Args:
        conn: Connection the owner belongs to.

    Returns:
        The owner of this connection.
    """
    key = id(conn)
    with _OWNERS_LOCK:
        owner = _OWNERS.get(key)
        if owner is None or owner.conn is not conn:
            owner = _CommitOwner(conn)
            _OWNERS[key] = owner
    return owner


def write_lock(conn: sqlite3.Connection) -> threading.RLock:
    """Return the lock that owns every write transaction on *conn*.

    Requirement: Unmanaged Side-Observation Audit.  A caller that has to keep a
    transaction open across several statements holds this lock itself; the store
    write functions take it through write_transaction.

    Args:
        conn: Connection the transactions run on.

    Returns:
        The re-entrant commit lock of this connection.
    """
    return _owner(conn).lock


def blocked_writers(conn: sqlite3.Connection) -> int:
    """Report how many threads wait for the commit owner of *conn*.

    Requirement: Unmanaged Side-Observation Audit.  Makes the serialization
    observable: a non-zero count is a writer that is queued behind another
    thread's transaction instead of sharing it.

    Args:
        conn: Connection the writers target.

    Returns:
        The number of threads currently blocked in write_transaction.
    """
    with _OWNERS_LOCK:
        return _owner(conn).blocked


@contextmanager
def write_transaction(conn: sqlite3.Connection) -> Iterator[None]:
    """Hold the commit owner of *conn* for one whole write transaction.

    Requirement: Write Before Forward; Unmanaged Side-Observation Audit.  The
    lock must span the first statement and the commit or rollback, not just the
    statement: that is the boundary SQLite itself treats as one transaction, and
    a lock that covered only the INSERT would still let a second thread's
    rollback discard the first thread's uncommitted rows.

    Args:
        conn: Connection the transaction runs on; None is a no-op.

    Yields:
        None, with the commit owner held.
    """
    if conn is None:
        yield
        return
    owner = _owner(conn)
    with _OWNERS_LOCK:
        owner.blocked += 1
    owner.lock.acquire()
    try:
        with _OWNERS_LOCK:
            owner.blocked -= 1
        yield
    finally:
        owner.lock.release()


def serialized_write(func: Callable[..., Any]) -> Callable[..., Any]:
    """Run one store write function under its connection's commit owner.

    Requirement: Write Before Forward; Unmanaged Side-Observation Audit.  The
    connection is the function's first argument (or its `conn` keyword), which
    is uniform across store/audit.py and store/tickets.py.

    Args:
        func: A store function whose first parameter is the connection.

    Returns:
        The same function, wrapped in write_transaction.
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        conn = args[0] if args else kwargs.get("conn")
        with write_transaction(conn):
            return func(*args, **kwargs)

    return wrapper


def startup_sweep_state(conn: sqlite3.Connection) -> StartupSweepState:
    """Report what the last startup ticket sweep on *conn* did.

    Requirement: Ticket Persistence; Storage Unavailable Is Deny.

    Args:
        conn: Connection the sweep ran on.

    Returns:
        The recorded state; a connection that never ran a sweep reports ok.
    """
    with _OWNERS_LOCK:
        owner = _owner(conn)
        return StartupSweepState(
            ok=owner.sweep_ok,
            error=owner.sweep_error,
            attempts=owner.sweep_attempts,
        )


def _record_startup_sweep(conn: sqlite3.Connection, error: str) -> None:
    """Store the outcome of one startup sweep attempt on *conn*.

    Args:
        conn: Connection the sweep ran on.
        error: Failure text, or the empty string when it succeeded.
    """
    with _OWNERS_LOCK:
        owner = _owner(conn)
        owner.sweep_attempts += 1
        owner.sweep_ok = not error
        owner.sweep_error = error


def require_startup_sweep(conn: sqlite3.Connection) -> None:
    """Refuse approvals while the last startup sweep on *conn* has not settled.

    Requirement: Ticket Persistence; Ticket Lifecycle (a restart invalidates
    pending and unconsumed approved tickets, never restores grants).  Opening
    the store must not fail when the sweep cannot run, so the failure is
    recorded here and the approval side is closed instead: a ticket the restart
    was supposed to withdraw is neither found nor consumed until a later sweep
    succeeds, and everything else on the store keeps working.  A closed approval
    side raises rather than returning None, matching find_approved's and
    consume_approved's existing "cannot read the tickets" contract; the gateway
    suppresses it and denies.

    Args:
        conn: Connection the approval query runs on.

    Raises:
        StorageUnavailableError: When the last startup sweep failed.
    """
    state = startup_sweep_state(conn)
    if state.ok:
        return
    raise StorageUnavailableError(
        f"startup ticket sweep did not settle ({state.error}); approvals are closed"
    )


def rollback_quietly(conn: sqlite3.Connection) -> None:
    """Roll back the open transaction without masking the original failure.

    Requirement: Storage Unavailable Is Deny.  A rollback on a closed or broken
    connection raises too, so swallowing that error keeps the caller's
    StorageUnavailableError as the exception that reaches the request path --
    otherwise the request would see a raw sqlite3 error and might treat the
    failure as anything but "storage unavailable, deny".

    Args:
        conn: Connection whose transaction should be discarded.
    """

    try:
        conn.rollback()
    except sqlite3.Error:
        pass


def _ensure_columns(conn: sqlite3.Connection) -> None:
    """Add late columns to a file written by an older version.

    Requirement: Tables and Fields; Schema Versioning.  SQLite has no
    ``ADD COLUMN IF NOT EXISTS`, so existence is decided by PRAGMA table_info
    rather than by swallowing a "duplicate column" error: a genuine failure
    still surfaces as StorageUnavailableError through migrate.  Existing rows
    keep NULL in the added column, which is exactly "no value recorded", so old
    history stays readable.

    Args:
        conn: Open connection inside the migration transaction.
    """
    for table, column, declaration in _ADDED_COLUMNS:
        present = {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in present:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def migrate(conn: sqlite3.Connection) -> int:
    """Apply forward migrations and record the reached schema version.

    Requirement: Schema Versioning; Tables and Fields.  Idempotent: every
    statement is CREATE ... IF NOT EXISTS, _ensure_columns re-adds a late column
    only when PRAGMA table_info does not already report it, and a database
    already at SCHEMA_VERSION keeps its rows.  A failing migration rolls back and
    leaves the previous file readable; the caller then treats the store as
    unavailable.

    Args:
        conn: Open connection.

    Returns:
        The schema version now recorded in the file.

    Raises:
        StorageUnavailableError: On any SQL error, or when the file was written
            by a newer schema than this code understands.
    """
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(_SCHEMA_VERSION_DDL)
        row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
        current = int(row[0]) if row is not None and row[0] is not None else 0
        if current > SCHEMA_VERSION:
            raise StorageUnavailableError(
                f"database schema version {current} is newer than supported "
                f"{SCHEMA_VERSION}"
            )
        for version in sorted(MIGRATIONS):
            if version <= current:
                continue
            for statement in MIGRATIONS[version]:
                conn.execute(statement)
            conn.execute(
                "INSERT OR REPLACE INTO schema_version (version, applied_at)"
                " VALUES (?, ?)",
                (version, utc_iso()),
            )
        _ensure_columns(conn)
        conn.commit()
    except StorageUnavailableError:
        rollback_quietly(conn)
        raise
    except (sqlite3.Error, OSError) as exc:
        rollback_quietly(conn)
        raise StorageUnavailableError(f"migration failed: {exc}") from exc
    return SCHEMA_VERSION


def owner_count() -> int:
    """Return how many connections the commit-owner registry holds.

    Requirement: Write Before Forward (observability). Read-only; the startup
    path uses it to prove a failed open leaves no owner -- and therefore no
    reachable lock -- behind.
    """
    with _OWNERS_LOCK:
        return len(_OWNERS)


def _abandon_connection(conn: sqlite3.Connection) -> None:
    """Close *conn* and drop its commit owner after an unusable open.

    Requirement: Storage Unavailable Is Deny (review R11-03). An unexpected
    failure while sweeping a freshly opened connection used to leave it in
    _OWNERS, and that registry keeps its connection alive: the file stays open
    and the lock stays reachable by id(), including by a later connection that
    reuses that id. A connection nobody may hand out leaves the registry.

    Args:
        conn: Connection that could not be brought up.
    """
    rollback_quietly(conn)
    try:
        conn.close()
    except sqlite3.Error:
        pass
    with _OWNERS_LOCK:
        _OWNERS.pop(id(conn), None)


def run_startup_sweep(
    conn: sqlite3.Connection, *, created_before: str | None = None
) -> dict[str, int]:
    """Settle the tickets no process can still finish, once per store open.

    Requirement: Ticket Persistence; Ticket Lifecycle (a restart invalidates
    pending and unconsumed approved tickets, never restores waiters or grants).
    store/tickets.py sweep had exactly one caller, the /guard command plane, so a
    restart left orphaned suspensions and already closed approval windows in the
    file until an operator happened to type a command. Opening the store is the
    moment a process becomes able to wait for or grant a ticket, which is the
    moment the dead ones can be reclaimed.

    It calls `tickets.startup_sweep`, not the command-plane `tickets.sweep`: the
    latter keeps a SWEEP_ORPHAN_GRACE_S horizon so it can never destroy a live
    waiter's own ticket, and that same horizon used to leave a restart's
    unconsumed approved grants consumable (R9-05). At open time no waiter of the
    previous process exists, so the startup path applies no grace at all.

    The sweep is imported inside the function because store/tickets.py imports
    this module; keeping it here means the startup path is the store package's
    own, with no gateway wiring.

    A failing sweep never blocks the open, but it is not harmless either: the
    rows it would have settled stay approved and consumable, so the restart no
    longer withdraws the previous process's grants.  The failure is therefore
    recorded on the connection (see startup_sweep_state) and the approval side
    is closed until a later sweep succeeds -- find_approved and consume_approved
    call require_startup_sweep, everything else on the store keeps working.
    Ignoring how long an unconsumed approval stays findable was exactly the
    bypass review R10 reported.

    A failure that is neither a storage error nor an sqlite error is a crash of
    this path rather than a degraded store: the state is recorded, the
    connection is dropped together with its commit owner (_abandon_connection)
    and the error is re-raised, because a connection whose open crashed may not
    be handed to the gateway.

    Args:
        conn: Open, migrated connection.
        created_before: Canonical timestamp; when given, only tickets created
            strictly before it may be invalidated. The open-time call passes
            None (a restart is proof that every stored ticket is dead), while the
            controlled retry passes PROCESS_STARTED_AT so it cannot cancel this
            process's own live tickets.

    Returns:
        The startup summary with the stable keys "expired", "invalidated",
        "pending_invalidated", "approved_invalidated" and "changed", or an empty
        mapping when the sweep itself failed.  The empty result is not "nothing
        to settle": startup_sweep_state(conn) tells the two apart.

    Raises:
        Exception: Any non-sqlite exception the sweep raised, after the
            connection has been closed and unregistered.
    """
    from .tickets import startup_sweep

    try:
        summary = startup_sweep(conn, created_before=created_before)
    except (StorageUnavailableError, sqlite3.Error) as exc:
        _record_startup_sweep(conn, str(exc))
        _LOGGER.warning("startup ticket sweep failed: %s", exc)
        return {}
    except Exception as exc:  # a crashed open must not leak its owner
        _record_startup_sweep(conn, f"{type(exc).__name__}: {exc}")
        _abandon_connection(conn)
        _LOGGER.warning("startup ticket sweep crashed, connection dropped: %s", exc)
        raise
    _record_startup_sweep(conn, "")
    if summary.get("changed"):
        _LOGGER.info(
            "startup ticket sweep expired=%d invalidated=%d pending=%d approved=%d",
            summary.get("expired", 0),
            summary.get("invalidated", 0),
            summary.get("pending_invalidated", 0),
            summary.get("approved_invalidated", 0),
        )
    return summary


def recover_startup_sweep(
    conn: sqlite3.Connection, *, created_before: str | None = None
) -> tuple[dict[str, int], StartupSweepState]:
    """Re-run the startup ticket sweep for the running process.

    Requirement: Ticket Persistence; Ticket Lifecycle (review R11-03). A failed
    startup sweep closes the approval side until a later sweep succeeds, but the
    sweep only ran while the store was opened, so that later sweep never came and
    the gate stayed shut for the life of the process. This is the one controlled
    retry, behind the administrator command `/guard sweep`.

    It withdraws only what an earlier process left behind: every ticket created
    before this process started. A ticket this process created is never
    cancelled, and nothing settled is restored -- the sweep only moves pending
    and unconsumed approved rows to a terminal state, so an already expired,
    cancelled or consumed ticket keeps the state it has.

    Args:
        conn: Open, migrated connection.
        created_before: Cutoff instant as a canonical timestamp; defaults to
            PROCESS_STARTED_AT, the instant captured when this module loaded.

    Returns:
        The sweep summary (see run_startup_sweep) and the state recorded right
        after the attempt, so a caller can report ok/attempts/error without
        reading the connection twice.
    """
    cutoff = PROCESS_STARTED_AT if created_before is None else created_before
    summary = run_startup_sweep(conn, created_before=cutoff)
    return summary, startup_sweep_state(conn)


def open_db(path: Path | str) -> sqlite3.Connection:
    """Open, configure and migrate the SQLite database at *path*.

    Requirement: Storage Location; Schema Versioning; Storage Unavailable Is
    Deny.  Sets check_same_thread=False, PRAGMA journal_mode=WAL,
    PRAGMA foreign_keys=ON and PRAGMA busy_timeout=BUSY_TIMEOUT_MS before
    migrating, then runs one ticket startup sweep (run_startup_sweep) so a
    restart reclaims -- and invalidates -- what the dead process left behind.

    Args:
        path: Database file path; its parent directory is created on demand.

    Returns:
        An open, migrated connection yielding sqlite3.Row rows.

    Raises:
        StorageUnavailableError: When the path is inside the plugin directory,
            or the file cannot be created, opened or migrated.
    """
    db_path = ensure_outside_plugin_dir(path)
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
    except (sqlite3.Error, OSError) as exc:
        raise StorageUnavailableError(f"cannot open store at {db_path}: {exc}") from exc
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        migrate(conn)
    except StorageUnavailableError:
        conn.close()
        raise
    except (sqlite3.Error, OSError) as exc:
        conn.close()
        raise StorageUnavailableError(
            f"cannot configure store at {db_path}: {exc}"
        ) from exc
    run_startup_sweep(conn)
    return conn


def open_or_raise(path: Path | str) -> sqlite3.Connection:
    """Open the store and raise instead of degrading when it is unusable.

    Requirement: Storage Unavailable Is Deny.  Storage unavailability (open,
    migration or write failure) denies ALL managed calls in every mode,
    including observe; it must never degrade into a pass-through.  Callers let
    StorageUnavailableError propagate to the decision layer and turn it into a
    deny.

    Args:
        path: Database file path.

    Returns:
        An open, migrated connection.

    Raises:
        StorageUnavailableError: Whenever the store is not fully usable.
    """
    return open_db(path)


def open_store(data_dir: Path | str) -> sqlite3.Connection:
    """Open the database inside *data_dir*.

    Requirement: Storage Location.

    Args:
        data_dir: Plugin data directory.

    Returns:
        An open, migrated connection.

    Raises:
        StorageUnavailableError: Whenever the store is not fully usable.
    """
    return open_db(Path(data_dir) / DB_FILENAME)


def close_db(conn: sqlite3.Connection | None) -> None:
    """Close the connection, tolerating repeat calls.

    Requirement: Storage Location (lifecycle); the file is closed on shutdown
    so the next start opens a consistent database.  The commit owner registered
    for this connection is dropped with it, so the registry does not keep a
    closed connection alive.

    Args:
        conn: Connection to close; None is a no-op.
    """
    if conn is None:
        return
    try:
        conn.close()
    except sqlite3.Error:
        pass
    with _OWNERS_LOCK:
        _OWNERS.pop(id(conn), None)
