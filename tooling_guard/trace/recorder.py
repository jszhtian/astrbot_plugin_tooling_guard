"""Ordered per-session trajectory recorder.

Requirement: Trajectory Window; Retention and Rotation.

Same-session appends stay ordered by ts_seq; different sessions never block each
other. Nothing is persisted here: the store layer owns durability.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from .retention import DEFAULT_KEEP, trim_for_subject
from .summary import CallSummary

NO_SESSION = ""


class TrajectoryRecorder:
    """Append CallSummary records per session and expose read-only views.

    Requirement: Trajectory Window; Retention and Rotation.

    Args:
        keep: Number of most recent records kept per session (default 50).

    Raises:
        ValueError: When keep is below 1.
    """

    def __init__(self, *, keep: int = DEFAULT_KEEP) -> None:
        if keep < 1:
            raise ValueError(f"keep must be >= 1, got {keep}")
        self._keep = keep
        self._events: dict[str, list[CallSummary]] = {}

    @property
    def keep(self) -> int:
        """Return the number of records retained per session."""
        return self._keep

    def append(self, summary: CallSummary) -> None:
        """Append one summary, keeping the session ordered and trimmed.

        Requirement: Trajectory Window; Retention and Rotation.

        Args:
            summary: Record to append; its session selects the window.
        """
        session_key = summary.session if summary.session is not None else NO_SESSION
        events = self._events.setdefault(session_key, [])
        events.append(summary)
        events.sort(key=lambda item: item.ts_seq)
        self._events[session_key] = trim_for_subject(events, self._keep)

    def snapshot(
        self, session_key: str | None = None
    ) -> tuple[CallSummary, ...] | Mapping[str, tuple[CallSummary, ...]]:
        """Return an immutable copy of one session window or of all sessions.

        Requirement: Trajectory Window.

        Args:
            session_key: Session to copy, or None for every session.

        Returns:
            tuple[CallSummary, ...] | Mapping[str, tuple[CallSummary, ...]]:
            Records oldest first; a read-only mapping of session key to records
            when session_key is None.
        """
        if session_key is None:
            return MappingProxyType(
                {key: tuple(value) for key, value in self._events.items()}
            )
        return tuple(self._events.get(session_key, ()))

    def sessions(self) -> tuple[str, ...]:
        """Return the session keys in first-append order.

        Requirement: Trajectory Window.
        """
        return tuple(self._events)

    def clear(self, session_key: str | None = None) -> int:
        """Drop one session window, or every window.

        Requirement: Trajectory Window.

        Args:
            session_key: Session to drop, or None for all sessions.

        Returns:
            int: Number of windows dropped.
        """
        if session_key is None:
            dropped = len(self._events)
            self._events.clear()
            return dropped
        return 1 if self._events.pop(session_key, None) is not None else 0

    def __len__(self) -> int:
        """Return the total number of retained records."""
        return sum(len(events) for events in self._events.values())
