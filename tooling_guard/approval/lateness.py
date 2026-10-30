"""Late decision rejection. Requirement: Late Decision Disclosure."""

from __future__ import annotations

from typing import Any

from ..store.tickets import (
    APPROVED,
    DENIED,
    EXPIRED,
    PENDING,
    TIMEOUT,
    get_ticket,
    transition,
)

DECISIONS: tuple[str, ...] = (APPROVED, DENIED)
"""Decisions a late decision is allowed to carry."""


def reject_late_decision(
    conn: Any,
    ticket_id: str,
    decision: str,
    *,
    actor: str,
    now: float | None = None,
) -> bool:
    """Reject a decision that arrived after the suspension budget expired.

    Requirement: Late Decision Disclosure.

    Only transitions that cannot grant approval are persisted, and the
    transition row is the record of the rejection: pending -> timeout while the
    waiter has not settled the ticket yet, and approved -> expired when an
    earlier approval window already closed. A ticket that is already settled is
    left untouched, so a timeout ticket can never be turned back into an
    approved one.

    Args:
        conn: Open store connection.
        ticket_id: Ticket identifier.
        decision: The late decision, "approved" or "denied".
        actor: Administrator identifier that sent the late decision.
        now: Persistence instant override.

    Returns:
        True when a non-approving transition was persisted, False when the
        ticket is unknown or already settled.

    Raises:
        ValueError: When decision or actor is not usable.
        StorageUnavailableError: When the store cannot be read or written; the
            ticket state is unchanged in that case and nothing is granted.
    """
    if decision not in DECISIONS:
        raise ValueError(f"unsupported decision: {decision!r}")
    handled_by = actor.strip() if isinstance(actor, str) else ""
    if not handled_by:
        raise ValueError("actor must be a non-empty administrator identifier")
    ticket = get_ticket(conn, ticket_id)
    if ticket is None:
        return False
    reason = f"late {decision} rejected: suspension budget already spent"
    if ticket.state == PENDING:
        result = transition(
            conn,
            ticket_id,
            (PENDING,),
            TIMEOUT,
            actor=handled_by,
            reason=reason,
            now=now,
        )
    elif ticket.state == APPROVED:
        result = transition(
            conn,
            ticket_id,
            (APPROVED,),
            EXPIRED,
            actor=handled_by,
            reason=reason,
            now=now,
        )
    else:
        return False
    return bool(result.ok)


__all__ = ["reject_late_decision"]
