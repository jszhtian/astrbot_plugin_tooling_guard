"""Notification rate limiting and alert merging.

Requirement: Rate Limiting and Merging; Degraded Mode Alert.

The limiter is pure logic.  It starts no task, sleeps never, and reads no clock
of its own: the caller passes the current instant in, so a test moves the window
without waiting and one process keeps a bounded table of what it merged.

Only caller-supplied identity dimensions are ever stored -- requester key, tool
name, mode, decision class.  Arguments, results and prompts never reach this
module, so the table can neither leak nor grow with call payload size.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

WINDOW_S = 60.0
"""Default alert window: one notice per class per target per minute."""

DEGRADED_WINDOW_S = 600.0
"""Default degraded interval: a degradation is reported at most every 10 min."""

CAPACITY = 256
"""Hard cap on tracked alert classes, so a hostile key space stays bounded."""

FIELD_LIMIT = 120
"""Maximum characters kept for one key dimension."""

DEGRADED_CLASS = "degraded"
"""Decision class shared by every degraded-mode alert."""

_EMPTY = "-"
"""Stand-in for an empty key dimension, so a key never collapses to fewer parts."""


def _dim(value: Any) -> str:
    """Return one normalized, bounded key dimension.

    Args:
        value: Candidate dimension; a broken str() is treated as empty.

    Returns:
        Whitespace-collapsed text, capped at FIELD_LIMIT characters, never empty.
    """
    if isinstance(value, str):
        text = value
    else:
        try:
            text = str(value)
        except Exception:  # noqa: BLE001 - a broken __str__ must not break limiting
            text = ""
    collapsed = " ".join(text.split())
    return (collapsed or _EMPTY)[:FIELD_LIMIT]


def _instant(now: Any) -> float:
    """Return one clock reading as a float.

    Args:
        now: Candidate instant.

    Returns:
        The float value, or 0.0 when it is not numeric.
    """
    try:
        return float(now)
    except (TypeError, ValueError):
        return 0.0


def is_degraded(degraded: Any) -> bool:
    """Report whether an alert carries a degradation marker.

    Args:
        degraded: Marker string (empty means "not degraded") or any truthy flag.

    Returns:
        True when the alert belongs to the degraded class.
    """
    if isinstance(degraded, str):
        return bool(degraded.strip())
    return bool(degraded)


def decision_class(decision: Any, *, degraded: Any = None) -> str:
    """Return the low-cardinality class one alert belongs to.

    Requirement: Rate Limiting and Merging; Degraded Mode Alert.

    Args:
        decision: Verdict the alert reports.
        degraded: Degradation marker; a truthy value collapses the class to
            DEGRADED_CLASS so every degraded alert shares one longer interval.

    Returns:
        The class used as the last key dimension.
    """
    if is_degraded(degraded):
        return DEGRADED_CLASS
    return _dim(decision)


def limit_key(
    *,
    subject: Any,
    tool_name: Any,
    mode: Any,
    decision: Any,
    degraded: Any = None,
    ticket_id: Any = None,
    pending: bool = False,
) -> tuple[str, str, str, str, str]:
    """Return the bounded, sanitized key of one alert class.

    Requirement: Rate Limiting and Merging; Ticket Notice Is Never Merged Away.

    Args:
        subject: Requester key.
        tool_name: Public tool name.
        mode: Effective gateway mode.
        decision: Verdict the alert reports.
        degraded: Degradation marker, when the alert is a degraded one.
        ticket_id: Ticket the alert reports; an ordinary alert keeps it, so two
            different pending tickets are never merged into one delivery.
        pending: Whether the notice announces a ticket that is still waiting for
            an administrator. A pending notice keeps its ticket even when it is
            degraded: the degraded class shares one ten-minute window across
            every tool of a requester, and a merged-away pending notice is a
            ticket nobody is told about -- it then times out with no trace that
            an answer was ever asked for.

    Returns:
        A five-part tuple: requester, tool, mode, decision class, ticket.  Every
        part is whitespace-collapsed and capped, so the key holds no raw argument
        text.  A degraded alert that is not pending carries an empty ticket part,
        which keeps its single long-window class intact.
    """
    alert_class = decision_class(decision, degraded=degraded)
    keep_ticket = pending or alert_class != DEGRADED_CLASS
    ticket = _dim(ticket_id) if keep_ticket else ""
    return (_dim(subject), _dim(tool_name), _dim(mode), alert_class, ticket)


@dataclass(frozen=True, slots=True)
class Admission:
    """Outcome of one rate-limit decision.

    Attributes:
        send: Whether this alert must be delivered now.
        merged: Alerts suppressed since the last delivery of this class; the
            caller adds the count to the notice it delivers now.
        window_s: Window that applied to this decision.
    """

    send: bool
    merged: int
    window_s: float


@dataclass(slots=True)
class _Entry:
    """Per-class window state.

    Attributes:
        last_sent: Instant the class was last admitted for delivery.
        merged: Alerts suppressed since that delivery.
    """

    last_sent: float
    merged: int = 0


class NotifyRateLimiter:
    """Bounded, clock-injected window table for administrator alerts.

    Requirement: Rate Limiting and Merging; Degraded Mode Alert.

    The table is process-local and memory-only: a restart deliberately forgets
    what it merged, which matches the startup invalidation of pending tickets.
    """

    def __init__(
        self,
        *,
        window_s: float = WINDOW_S,
        degraded_window_s: float = DEGRADED_WINDOW_S,
        capacity: int = CAPACITY,
        retain_s: float | None = None,
    ) -> None:
        """Build an empty limiter.

        Args:
            window_s: Window of one ordinary alert class.
            degraded_window_s: Longer interval of the shared degraded class.
            capacity: Hard cap on tracked classes.
            retain_s: Age after which an untouched class is forgotten; defaults
                to twice the longer window.

        Raises:
            ValueError: When capacity is below one, which would forbid every
                alert instead of bounding the table.
        """
        if capacity < 1:
            raise ValueError("capacity must be at least 1")
        self._window_s = max(0.0, float(window_s))
        self._degraded_window_s = max(0.0, float(degraded_window_s))
        self._capacity = int(capacity)
        self._retain_s = (
            max(self._window_s, self._degraded_window_s) * 2.0
            if retain_s is None
            else max(0.0, float(retain_s))
        )
        self._state: dict[tuple[str, str, str, str, str], _Entry] = {}
        self._merged_total = 0

    @property
    def size(self) -> int:
        """Number of tracked alert classes."""
        return len(self._state)

    @property
    def capacity(self) -> int:
        """Hard cap on tracked alert classes."""
        return self._capacity

    @property
    def merged_total(self) -> int:
        """Alerts merged away since this limiter was created."""
        return self._merged_total

    def window_for(self, degraded: Any = None) -> float:
        """Return the window that applies to one class.

        Args:
            degraded: Degradation marker of the alert.

        Returns:
            The degraded interval for a degraded alert, the ordinary window
            otherwise.
        """
        if is_degraded(degraded):
            return self._degraded_window_s
        return self._window_s

    def reset(self) -> None:
        """Forget every tracked class."""
        self._state.clear()
        self._merged_total = 0

    def admit(
        self,
        *,
        subject: Any,
        tool_name: Any,
        mode: Any,
        decision: Any,
        degraded: Any = None,
        ticket_id: Any = None,
        pending: bool = False,
        now: Any,
    ) -> Admission:
        """Decide whether one alert is delivered now or merged into a later one.

        Requirement: Rate Limiting and Merging; Degraded Mode Alert; Ticket Notice
        Is Never Merged Away.

        Args:
            subject: Requester key.
            tool_name: Public tool name.
            mode: Effective gateway mode.
            decision: Verdict the alert reports.
            degraded: Degradation marker, when the alert is a degraded one.
            ticket_id: Ticket the alert reports; a different ticket of the same
                class is delivered instead of being merged away.
            pending: Whether the ticket is still waiting for an answer. A
                pending notice is keyed by its ticket even when degraded, so a
                second request of the same class inside the degraded window
                still reaches the administrators.
            now: Current instant on the caller's clock.

        Returns:
            The admission of this alert; `send` is False when the alert is
            counted as merged instead of delivered.
        """
        current = _instant(now)
        window = self.window_for(degraded)
        key = limit_key(
            subject=subject,
            tool_name=tool_name,
            mode=mode,
            decision=decision,
            degraded=degraded,
            ticket_id=ticket_id,
            pending=pending,
        )
        self._expire(current)
        entry = self._state.get(key)
        if entry is None:
            self._remember(key, current)
            return Admission(send=True, merged=0, window_s=window)
        elapsed = current - entry.last_sent
        elapsed = max(elapsed, 0.0)
        if elapsed < window:
            entry.merged += 1
            self._merged_total += 1
            return Admission(send=False, merged=0, window_s=window)
        merged = entry.merged
        entry.merged = 0
        entry.last_sent = current
        return Admission(send=True, merged=merged, window_s=window)

    def _remember(self, key: tuple[str, str, str, str], now: float) -> None:
        """Store one new class, evicting the oldest when the table is full.

        Args:
            key: Alert class key.
            now: Instant of the first delivery.
        """
        while len(self._state) >= self._capacity:
            oldest = min(self._state, key=lambda item: self._state[item].last_sent)
            del self._state[oldest]
        self._state[key] = _Entry(last_sent=now)

    def _expire(self, now: float) -> None:
        """Drop every class untouched for longer than the retention horizon.

        Args:
            now: Current instant on the caller's clock.
        """
        horizon = now - self._retain_s
        stale = [
            key for key, entry in self._state.items() if entry.last_sent <= horizon
        ]
        for key in stale:
            del self._state[key]


__all__ = [
    "CAPACITY",
    "DEGRADED_CLASS",
    "DEGRADED_WINDOW_S",
    "FIELD_LIMIT",
    "WINDOW_S",
    "Admission",
    "NotifyRateLimiter",
    "decision_class",
    "is_degraded",
    "limit_key",
]
