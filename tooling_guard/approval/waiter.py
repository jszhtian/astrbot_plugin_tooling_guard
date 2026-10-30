"""In-call approval wait. Requirement: Approval Wait and Exact-Match Retry.

The wait is a rendezvous between the suspended tool call and the administrator
decision command: the call blocks inside the proxy, the decision command calls
ApprovalRegistry.resolve, and the persisted ticket state machine stays the only
authority over what a ticket means.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..store.tickets import (
    APPROVED,
    CANCELED_EXTERNAL,
    COMPLETED,
    DENIED,
    EXPIRED,
    PENDING,
    TIMEOUT,
    cancel_external,
    transition,
)

DECISIONS: tuple[str, ...] = (APPROVED, DENIED)
"""Decisions a resolver is allowed to carry."""

OUTCOMES: tuple[str, ...] = (APPROVED, DENIED, TIMEOUT)
"""Every value wait_for_decision may return.

"Cancelled" is deliberately not a return value: cancelling the enclosing task is
a control-flow event, so wait_for_decision settles the ticket as
canceled_external and then re-raises CancelledError unchanged.
"""

MAX_SUSPEND_WAIT_S = 110.0
"""Upper bound of one in-call wait (design D8); it is only a cap."""

MIN_SUSPEND_REMAINING_S = 30.0
"""Below this request budget the call is not suspended at all (design D8)."""

WAITER_ACTOR = "tooling_guard"
"""Actor recorded on transitions persisted by the waiter itself."""

_TERMINAL_STATES = frozenset({DENIED, TIMEOUT, EXPIRED, CANCELED_EXTERNAL, COMPLETED})


@dataclass(slots=True)
class _Entry:
    """One registered ticket.

    Attributes:
        event: Event the suspended call waits on.
        decision: Frozen decision, or None while still undecided.
    """

    event: asyncio.Event
    decision: str | None = None


class ApprovalRegistry:
    """In-memory rendezvous between a suspended call and a decision command.

    Requirement: Approval Wait and Exact-Match Retry.

    The registry is memory-only on purpose: a restart drops every wait, which
    matches the startup invalidation of persisted tickets.
    """

    def __init__(self) -> None:
        """Create an empty registry."""
        self._entries: dict[str, _Entry] = {}

    def register(self, ticket_id: str) -> asyncio.Event:
        """Create the wait handle of one ticket.

        Requirement: Approval Wait and Exact-Match Retry.

        Args:
            ticket_id: Ticket identifier.

        Returns:
            The event set by resolve; an earlier registration of the same
            ticket is replaced, so callers that may race with a decision check
            decision() first, as wait_for_decision does.
        """
        entry = _Entry(event=asyncio.Event())
        self._entries[str(ticket_id)] = entry
        return entry.event

    def resolve(self, ticket_id: str, decision: str) -> bool:
        """Record a decision and wake the suspended call.

        Requirement: Approval Wait and Exact-Match Retry.

        Args:
            ticket_id: Ticket identifier.
            decision: "approved" or "denied".

        Returns:
            True when this call resolved the ticket, False when the ticket is
            unknown or was already resolved.

        Raises:
            ValueError: When decision is not a supported decision.
        """
        if decision not in DECISIONS:
            raise ValueError(f"unsupported decision: {decision!r}")
        entry = self._entries.get(str(ticket_id))
        if entry is None or entry.decision is not None:
            return False
        entry.decision = decision
        entry.event.set()
        return True

    def decision(self, ticket_id: str) -> str | None:
        """Return the frozen decision of one ticket.

        Args:
            ticket_id: Ticket identifier.

        Returns:
            "approved", "denied", or None while undecided or unknown.
        """
        entry = self._entries.get(str(ticket_id))
        return entry.decision if entry is not None else None

    def discard(self, ticket_id: str) -> None:
        """Drop one registration, whether or not it was resolved.

        Args:
            ticket_id: Ticket identifier.
        """
        self._entries.pop(str(ticket_id), None)

    def pending(self) -> list[str]:
        """Return the identifiers of tickets still awaiting a decision.

        Returns:
            Ticket identifiers that were registered and not yet resolved.
        """
        return [
            ticket_id
            for ticket_id, entry in self._entries.items()
            if entry.decision is None
        ]


def _remaining_s(deadline: float, current: float) -> float:
    """Return the non-negative request budget left before the deadline.

    Args:
        deadline: Deadline instant on the same clock as current.
        current: Current instant.

    Returns:
        max(0, deadline - current), or 0.0 for a non-numeric input.
    """
    try:
        return max(0.0, float(deadline) - float(current))
    except (TypeError, ValueError):
        return 0.0


def _already_terminal(ticket: Any) -> bool:
    """Report whether a previously read ticket is already settled.

    Args:
        ticket: Ticket object, or None when the caller did not read one.

    Returns:
        True when the ticket is in a state the waiter must not rewrite.
    """
    return getattr(ticket, "state", None) in _TERMINAL_STATES


def _persist_timeout(store: Any, ticket_id: str, ticket: Any) -> bool:
    """Persist an exhausted suspension budget as pending -> timeout.

    Requirement: Approval Ticket Lifecycle; Dynamic Suspension Budget.

    Args:
        store: Open store connection.
        ticket_id: Ticket identifier.
        ticket: Ticket read before the wait, when available.

    Returns:
        True when the transition was written; False when the ticket is already
        settled or the store refused the write. A failed write never changes the
        returned outcome, and the caller re-reads the ticket before deciding.
    """
    if _already_terminal(ticket):
        return False
    try:
        result = transition(
            store,
            ticket_id,
            (PENDING,),
            TIMEOUT,
            actor=WAITER_ACTOR,
            reason="suspension budget exhausted",
        )
    except Exception:  # noqa: BLE001 - a failed write must not change the verdict
        return False
    return bool(getattr(result, "ok", False))


def _persist_canceled(store: Any, ticket_id: str, ticket: Any) -> bool:
    """Persist an externally cancelled wait as canceled_external.

    Requirement: External Cancellation Degradation.

    Args:
        store: Open store connection.
        ticket_id: Ticket identifier.
        ticket: Ticket read before the wait, when available.

    Returns:
        True when the transition was written, False otherwise. The wait is never
        persisted as timeout in this case.
    """
    if _already_terminal(ticket):
        return False
    try:
        result = cancel_external(
            store,
            ticket_id,
            actor=WAITER_ACTOR,
            reason="outer request cancelled",
        )
    except Exception:  # noqa: BLE001 - a failed write must not change the verdict
        return False
    return bool(getattr(result, "ok", False))


async def wait_for_decision(
    ticket_id: str,
    *,
    deadline: float,
    store: Any,
    registry: ApprovalRegistry | None = None,
    now: Callable[[], float] = time.monotonic,
    ticket: Any = None,
) -> str:
    """Wait for an administrator decision without outliving the request.

    Requirement: Approval Wait and Exact-Match Retry; Late Decision Disclosure.

    Notes:
        The wait is min(110, max(0, deadline - now())) seconds and the call is
        not suspended at all when less than 30 seconds of request budget remain;
        the caller then applies its own enforce or observe verdict. Cancelling
        the enclosing request settles the ticket as "canceled_external" (never as
        a timeout) and the CancelledError is then re-raised unchanged, so the
        caller can never mistake a cancellation for an ordinary verdict.

    Args:
        ticket_id: Ticket the suspended call waits on.
        deadline: Instant the request budget ends at, on the clock now returns.
        store: Open store connection used to persist the outcome.
        registry: Shared registry; a private one is used when omitted.
        now: Clock reader, injectable for tests.
        ticket: Ticket already read by the caller; a settled ticket is never
            rewritten here.

    Returns:
        One of OUTCOMES: the recorded decision, or "timeout" when the budget ran
        out. It is always a non-empty string, never None.

    Raises:
        asyncio.CancelledError: The wait was cancelled from outside; the ticket
            is already settled as "canceled_external" when this propagates.
    """
    remaining = _remaining_s(deadline, now())
    if remaining < MIN_SUSPEND_REMAINING_S:
        return TIMEOUT
    active = registry if registry is not None else ApprovalRegistry()
    early = active.decision(ticket_id)
    if early in DECISIONS:
        active.discard(ticket_id)
        return early
    wait_s = min(MAX_SUSPEND_WAIT_S, remaining)
    event = active.register(ticket_id)
    try:
        await asyncio.wait_for(event.wait(), timeout=wait_s)
    except TimeoutError:
        decided = active.decision(ticket_id)
        active.discard(ticket_id)
        if decided in DECISIONS:
            return decided
        _persist_timeout(store, ticket_id, ticket)
        return TIMEOUT
    except asyncio.CancelledError:
        active.discard(ticket_id)
        _persist_canceled(store, ticket_id, ticket)
        raise
    decided = active.decision(ticket_id)
    active.discard(ticket_id)
    if decided in DECISIONS:
        return decided
    _persist_timeout(store, ticket_id, ticket)
    return TIMEOUT


__all__ = [
    "DECISIONS",
    "MAX_SUSPEND_WAIT_S",
    "MIN_SUSPEND_REMAINING_S",
    "OUTCOMES",
    "ApprovalRegistry",
    "wait_for_decision",
]
