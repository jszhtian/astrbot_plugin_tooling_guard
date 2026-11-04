"""Remember which administrator was handed which suspension notice.

Requirement: Reply Approval Channel; Approver Authorization. The reply channel
must answer one question before it can decide anything: which pending ticket is
this "同意" about? Two of the three answers are cheap -- the reply names a short
code, or it quotes the notice itself. The third one is not: an administrator
who simply types 同意 after receiving a private message named no ticket at all.

The only honest way to answer that case is to know which tickets were actually
delivered to that administrator, which the audit row cannot supply (it records
the delivery, not a queryable relation). This table is that relation: one row per
(ticket, administrator) that a notice reached. It is deliberately narrow -- no
message body, no verdict, just the address the notice went to -- and it is never
authorization: a row only says "this administrator was told about this ticket",
never "this administrator may decide it". The decision itself stays in
commands.decide_ticket, behind the same two-condition administrator gate as
/guard approve.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Iterable, Mapping

from .db import StorageUnavailableError, rollback_quietly, serialized_write, utc_iso
from .tickets import PENDING

__all__ = [
    "admin_of",
    "delivered_ticket_ids",
    "record_deliveries",
]

#: Attempt results that mean the notice actually reached the administrator.
DELIVERED_RESULTS = frozenset({"private", "inline"})
"""Result words build_sender records for a delivery it considers made.

"private" is a direct message the host accepted; "inline" is the copy posted in
the triggering conversation, which the administrator can quote just as well.
"no_platform", "rejected", "raised" and "ephemeral" are all *not* deliveries and
are never recorded: an administrator who never saw the notice must not get a
ticket attributed to them by replying 同意 to something else.
"""


def admin_of(attempt: Mapping[str, Any]) -> str:
    """Return the administrator identity of one delivery attempt.

    Args:
        attempt: One record from notify.sender.delivery_attempts.

    Returns:
        The cleaned administrator id, or "" when the record names none.
    """
    return str(attempt.get("admin") or "").strip()


@serialized_write
def record_deliveries(
    conn: sqlite3.Connection,
    ticket_id: str,
    attempts: Iterable[Mapping[str, Any]],
    *,
    sent_at: str | None = None,
) -> int:
    """Record that one notice about *ticket_id* reached some administrators.

    Requirement: Reply Approval Channel. Only successful attempts are stored, so
    the table answers "who was told" rather than "who was tried". A repeated
    delivery of the same ticket to the same address overwrites the earlier row
    instead of accumulating duplicates: the newest instant is the one that
    matters when the reply channel ranks candidates.

    Args:
        conn: Open connection.
        ticket_id: Ticket the notice was about; empty means nothing to record.
        attempts: Delivery attempts of the send that just happened.
        sent_at: Timestamp to store, defaulting to now.

    Returns:
        How many rows were written.

    Raises:
        StorageUnavailableError: When the write fails.
    """
    if not ticket_id:
        return 0
    stamp = utc_iso(sent_at)
    rows: list[tuple[str, str, str, str]] = []
    for attempt in attempts:
        if not isinstance(attempt, Mapping):
            continue
        if str(attempt.get("result") or "") not in DELIVERED_RESULTS:
            continue
        admin = admin_of(attempt)
        if not admin:
            continue
        target = str(attempt.get("target") or "")
        rows.append((ticket_id, admin, target, stamp))
    if not rows:
        return 0
    ids = sorted({row[1] for row in rows})
    try:
        conn.executemany(
            "DELETE FROM notice_deliveries WHERE ticket_id = ? AND admin = ?",
            [(ticket_id, admin) for admin in ids],
        )
        conn.executemany(
            "INSERT INTO notice_deliveries (ticket_id, admin, target, sent_at)"
            " VALUES (?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    except sqlite3.Error as exc:
        rollback_quietly(conn)
        raise StorageUnavailableError(f"cannot record notice delivery: {exc}") from exc
    return len(rows)


def delivered_ticket_ids(
    conn: sqlite3.Connection, admin: str, *, limit: int = 20
) -> list[str]:
    """List the tickets a notice about which reached one administrator.

    Requirement: Reply Approval Channel. Only tickets that are *still pending*
    come back: a decided ticket is not a candidate for a later 同意, and the
    query is the reply channel's whole candidate set for an administrator who
    named no ticket.

    Args:
        conn: Open connection.
        admin: Administrator identity, as stored by record_deliveries.
        limit: Maximum number of ticket ids to return.

    Returns:
        Ticket ids, most recently notified first, without duplicates.

    Raises:
        StorageUnavailableError: When the read fails.
    """
    key = (admin or "").strip()
    if not key:
        return []
    sql = (
        "SELECT d.ticket_id, MAX(d.sent_at) AS newest"
        " FROM notice_deliveries AS d"
        " JOIN tickets AS t ON t.ticket_id = d.ticket_id"
        " WHERE d.admin = ? AND t.state = ?"
        " GROUP BY d.ticket_id"
        " ORDER BY newest DESC, d.ticket_id ASC"
        " LIMIT ?"
    )
    try:
        rows = conn.execute(sql, (key, PENDING, int(limit))).fetchall()
    except sqlite3.Error as exc:
        raise StorageUnavailableError(f"cannot read notice deliveries: {exc}") from exc
    return [str(row[0]) for row in rows]
