"""Pre-execution intent records keyed by a generated call UUID.

Requirement: Pre-execution Intent Record; Argument Digesting.

The recorder keeps FIFO state in memory only: it never opens sqlite, opens a
network connection, opens a thread, or calls a model. Persistence belongs to
tooling_guard.store.

Pairing key
-----------
An intent is filed under `(event identity, tool name, args digest)`
(specs/call-triage "Pre-execution Intent Record"). The event identity is the
string :func:`event_key_of` builds from the requester and session keys the hook
adapter already computes; the digest is the shared
`tooling_guard.digest.args_digest` evaluated over the RAW argument bytes, so
redaction must happen after the digest and never before it. The public hook
carries no `tool_call_id` (astrbot/core/agent/runners/tool_loop_agent_runner.py
:1197-1246), and runner calls are sequential, so a FIFO per key is enough to
pair intent with result.

Consumption
-----------
A paired intent leaves the FIFO, so one intent is consumed at most once and a
replayed call finds nothing. A miss returns `None` after counting it: the
caller records `intent_unpaired` and continues, because a pairing failure is
never a reason to block a tool call.

Concurrency
-----------
Every mutating operation is plain synchronous deque work with no await point
between the scan and the removal, so two coroutines sharing one recorder cannot
interleave a check-then-take pair.

Gateway wiring (implemented by the proxy slice, not here)
---------------------------------------------------------
Root main.py files an intent from the observation hook::

    intent.record_intent(
        tool_name=name,
        event_key=intent.event_key_of(subject_key, session_key),
        subject_key=subject_key,
        session_key=session_key,
        arguments=arguments,
    )

The managed proxy takes it back inside ManagedToolProxy.call before it judges
the call::

    paired = intent.pop_intent(event_key, tool_name, intent.args_digest(args))
    call_id = paired or str(uuid.uuid4())  # never blocks when None
    if paired is None:
        ...record an audit row with decision=intent.UNPAIRED_REASON...

pop_intent returns the inherited call_id or None; both are normal outcomes and
neither may stop delegation.
"""

from __future__ import annotations

import time
import uuid
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from ..digest import args_digest as _shared_args_digest
from ..digest import canonical_json
from .retention import trim_for_subject

UNPAIRED_REASON = "intent_unpaired"
"""Audit decision recorded when a proxy call finds no live intent."""

INTENT_CAPACITY = 128
"""Maximum live intents held by one recorder, oldest dropped first."""

INTENT_WINDOW = 50
"""Live intents kept per requester, matching the trajectory window."""

DEFAULT_CAPACITY = INTENT_CAPACITY
"""Backwards-compatible alias for the module capacity constant."""

_KEY_SEPARATOR = "|"


def _text(value: Any) -> str:
    """Return a str value unchanged and anything else as an empty string.

    Args:
        value: Arbitrary object expected to be a str.

    Returns:
        The value when it is a str, else "".
    """
    return value if isinstance(value, str) else ""


def event_key_of(subject_key: Any = "", session_key: Any = "") -> str:
    """Return the event identity a pairing key is filed under.

    Requirement: Pre-execution Intent Record.

    Args:
        subject_key: platform_id:sender_id of the requester.
        session_key: Minimal conversation correlation key.

    Returns:
        A non-empty key; two calls with the same requester and session in the
        same process share it.
    """
    return f"{_text(subject_key)}{_KEY_SEPARATOR}{_text(session_key)}"


def _key_of(event_key: Any, subject_key: Any, session_key: Any) -> str:
    """Return the explicit event key, else one derived from the two keys.

    Args:
        event_key: Explicit event identity, used verbatim when non-empty.
        subject_key: platform_id:sender_id of the requester.
        session_key: Minimal conversation correlation key.

    Returns:
        The pairing key.
    """
    explicit = _text(event_key)
    return explicit or event_key_of(subject_key, session_key)


def canonical_arguments(arguments: Mapping[str, Any] | None) -> str:
    """Return the canonical JSON text that digests and heads are built from.

    Requirement: Argument Digesting.

    Delegates to tooling_guard.digest so an intent record, a trajectory entry
    and a ticket all encode the same call into the same text.

    Args:
        arguments: Raw tool arguments; None means no arguments. A value that is
            not a mapping is treated as no arguments so a malformed call never
            raises here.

    Returns:
        The canonical JSON text.
    """
    try:
        return canonical_json(None, dict(arguments or {}))
    except (TypeError, ValueError):
        return canonical_json(None, {})


def args_digest(arguments: Mapping[str, Any] | None) -> str:
    """Return the shared truncated digest of the canonical arguments.

    Requirement: Argument Digesting; Ticket Persistence.

    Returns the same 32 lowercase hex characters tooling_guard.digest produces
    for the same call, so an intent digest, a trajectory digest and a ticket
    digest are always comparable.

    Args:
        arguments: Raw tool arguments, digested before any redaction. A value
            that is not a mapping is treated as no arguments.

    Returns:
        The 32 hex character digest.
    """
    try:
        return _shared_args_digest(None, dict(arguments or {}))
    except (TypeError, ValueError):
        return _shared_args_digest(None, {})


@dataclass(frozen=True, slots=True)
class Intent:
    """One pre-execution intent observation.

    Requirement: Pre-execution Intent Record.

    Attributes:
        call_id: UUID generated before the call executes.
        ts: Wall-clock seconds when the intent was observed.
        tool_name: Managed tool name.
        args_digest: SHA-256 digest of the call arguments.
        subject_key: platform_id:sender_id identity.
        session_key: Minimal conversation correlation key.
        seq: Monotonic recorder sequence number.
        unpaired_reason: None while live, intent_unpaired once drained.
        event_key: Event identity the intent was filed under.
    """

    call_id: str
    ts: float
    tool_name: str
    args_digest: str
    subject_key: str
    session_key: str
    seq: int
    unpaired_reason: str | None = None
    event_key: str = ""


@dataclass(frozen=True, slots=True)
class IntentStats:
    """Counters describing intent-recorder health.

    Requirement: Pre-execution Intent Record.

    Attributes:
        recorded: Intents generated so far.
        paired: Intents matched by a proxy call.
        missed: Pairing attempts that found no intent.
        evicted: Intents dropped because a FIFO bound was reached.
        drained: Intents reported by drain_unpaired.
        pending: Intents still waiting to pair.
    """

    recorded: int
    paired: int
    missed: int
    evicted: int
    drained: int
    pending: int


class IntentRecorder:
    """Generate call_id UUIDs, pair FIFO, and report unpaired intents.

    Requirement: Pre-execution Intent Record.

    Runner calls are sequential, so a FIFO keyed by (event identity, tool,
    args_digest) is enough to pair an observed intent with the proxy call that
    follows it. Pairing failure never blocks execution; it is counted and
    surfaced by stats and drain_unpaired.

    Args:
        capacity: Maximum live intents kept in the FIFO, oldest dropped first.
        window: Maximum live intents kept per requester, mirroring the per-user
            trajectory window.

    Raises:
        ValueError: When capacity or window is below 1.
    """

    def __init__(
        self,
        *,
        capacity: int = INTENT_CAPACITY,
        window: int = INTENT_WINDOW,
    ) -> None:
        if capacity < 1:
            raise ValueError(f"capacity must be >= 1, got {capacity}")
        if window < 1:
            raise ValueError(f"window must be >= 1, got {window}")
        self._capacity = capacity
        self._window = window
        self._pending: deque[Intent] = deque()
        self._unpaired: list[Intent] = []
        self._recorded = 0
        self._paired = 0
        self._missed = 0
        self._evicted = 0
        self._drained = 0
        self._seq = 0

    @property
    def capacity(self) -> int:
        """Return the maximum number of live intents held in the FIFO."""
        return self._capacity

    @property
    def window(self) -> int:
        """Return the maximum number of live intents held per requester."""
        return self._window

    def record(
        self,
        *,
        tool_name: str,
        subject_key: str = "",
        session_key: str = "",
        arguments: Mapping[str, Any] | None = None,
        event_key: str = "",
        ts: float | None = None,
    ) -> Intent:
        """Create one intent with a fresh UUID and append it to the FIFO.

        Requirement: Pre-execution Intent Record.

        Args:
            tool_name: Managed tool name observed before execution.
            subject_key: platform_id:sender_id of the requester.
            session_key: Minimal conversation correlation key.
            arguments: Call arguments the digest is computed over, digested
                before any redaction.
            event_key: Explicit event identity, overriding the derived key.
            ts: Optional wall-clock seconds; defaults to time.time().

        Returns:
            Intent: The recorded intent, including its generated call_id.
        """
        self._seq += 1
        intent = Intent(
            call_id=str(uuid.uuid4()),
            ts=time.time() if ts is None else ts,
            tool_name=_text(tool_name),
            args_digest=args_digest(arguments),
            subject_key=_text(subject_key),
            session_key=_text(session_key),
            seq=self._seq,
            event_key=_key_of(event_key, subject_key, session_key),
        )
        while len(self._pending) >= self._capacity:
            evicted = replace(self._pending.popleft(), unpaired_reason=UNPAIRED_REASON)
            self._unpaired.append(evicted)
            self._evicted += 1
            del self._unpaired[: max(0, len(self._unpaired) - self._capacity)]
        self._pending.append(intent)
        self._recorded += 1
        self._trim_window(intent.subject_key)
        return intent

    def _trim_window(self, subject_key: str) -> None:
        """Drop the oldest live intents of one requester beyond the window.

        Requirement: Trajectory Window; Pre-execution Intent Record.

        Args:
            subject_key: Requester whose window is enforced; the comparison is
                exact, and several sessions of one requester share it.
        """
        members = [item for item in self._pending if item.subject_key == subject_key]
        if len(members) <= self._window:
            return
        dropped = len(members) - len(trim_for_subject(members, self._window))
        if dropped <= 0:
            return
        kept: deque[Intent] = deque()
        seen = 0
        for item in self._pending:
            if item.subject_key == subject_key and seen < dropped:
                seen += 1
                self._unpaired.append(replace(item, unpaired_reason=UNPAIRED_REASON))
                continue
            kept.append(item)
        self._pending = kept
        self._evicted += dropped
        del self._unpaired[: max(0, len(self._unpaired) - self._capacity)]

    def take(
        self,
        *,
        event_key: str,
        tool_name: str,
        digest: str,
    ) -> Intent | None:
        """Remove and return the oldest intent matching the pairing key.

        Requirement: Pre-execution Intent Record.

        Args:
            event_key: Event identity of the proxy call.
            tool_name: Tool name seen by the proxy.
            digest: args_digest of the arguments seen by the proxy.

        Returns:
            Intent | None: The consumed intent, or None when nothing matches; a
            miss only increments the miss counter and never blocks the call.
        """
        key = _key_of(event_key, "", "")
        name = _text(tool_name)
        target = _text(digest)
        for index, item in enumerate(self._pending):
            if item.event_key != key or item.tool_name != name:
                continue
            if item.args_digest != target:
                continue
            del self._pending[index]
            self._paired += 1
            return item
        self._missed += 1
        return None

    def pair(
        self,
        *,
        tool_name: str,
        subject_key: str = "",
        session_key: str = "",
        arguments: Mapping[str, Any] | None = None,
        event_key: str = "",
    ) -> Intent | None:
        """Pair the oldest matching intent with a proxy call.

        Requirement: Pre-execution Intent Record.

        Args:
            tool_name: Tool name seen by the proxy.
            subject_key: platform_id:sender_id of the requester.
            session_key: Minimal conversation correlation key.
            arguments: Arguments seen by the proxy, digested before redaction.
            event_key: Explicit event identity, overriding the derived key.

        Returns:
            Intent | None: The paired intent, or None when no intent matches; a
            miss only increments the miss counter and never blocks the call.
        """
        return self.take(
            event_key=_key_of(event_key, subject_key, session_key),
            tool_name=tool_name,
            digest=args_digest(arguments),
        )

    def drain_unpaired(self) -> list[Intent]:
        """Return and clear every intent that never paired.

        Requirement: Pre-execution Intent Record.

        Returns:
            list[Intent]: Evicted and still-pending intents, each marked with
            unpaired_reason equal to intent_unpaired.
        """
        drained = list(self._unpaired)
        drained.extend(
            replace(item, unpaired_reason=UNPAIRED_REASON) for item in self._pending
        )
        self._pending.clear()
        self._unpaired.clear()
        self._drained += len(drained)
        return drained

    def pending(self) -> tuple[Intent, ...]:
        """Return the live, not-yet-paired intents in FIFO order."""
        return tuple(self._pending)

    def stats(self) -> IntentStats:
        """Return a snapshot of recorder counters.

        Requirement: Pre-execution Intent Record.
        """
        return IntentStats(
            recorded=self._recorded,
            paired=self._paired,
            missed=self._missed,
            evicted=self._evicted,
            drained=self._drained,
            pending=len(self._pending),
        )

    def clear(self) -> None:
        """Drop live intents without reporting them as unpaired."""
        self._pending.clear()

    def __len__(self) -> int:
        """Return the number of live intents."""
        return len(self._pending)


_default_recorder: IntentRecorder | None = None


def default_recorder() -> IntentRecorder:
    """Return the process-wide recorder the observation hook files into.

    Requirement: Pre-execution Intent Record.

    Returns:
        The shared IntentRecorder, created on first use.
    """
    global _default_recorder
    if _default_recorder is None:
        _default_recorder = IntentRecorder()
    return _default_recorder


def reset_intents() -> None:
    """Replace the process-wide recorder with an empty one."""
    global _default_recorder
    _default_recorder = IntentRecorder()


def record_intent(
    *,
    tool_name: str,
    subject_key: str = "",
    session_key: str = "",
    arguments: Mapping[str, Any] | None = None,
    event_key: str = "",
    ts: float | None = None,
) -> Intent:
    """File one intent into the process-wide recorder.

    Requirement: Pre-execution Intent Record.

    Args:
        tool_name: Managed tool name observed before execution.
        subject_key: platform_id:sender_id of the requester.
        session_key: Minimal conversation correlation key.
        arguments: Raw call arguments.
        event_key: Explicit event identity, overriding the derived key.
        ts: Optional wall-clock seconds.

    Returns:
        Intent: The recorded intent, including its generated call_id.
    """
    return default_recorder().record(
        tool_name=tool_name,
        subject_key=subject_key,
        session_key=session_key,
        arguments=arguments,
        event_key=event_key,
        ts=ts,
    )


def take_intent(event_key: str, tool_name: str, args_digest: str) -> Intent | None:
    """Consume the oldest intent matching the pairing key, if any.

    Requirement: Pre-execution Intent Record.

    Args:
        event_key: Event identity of the proxy call.
        tool_name: Tool name seen by the proxy.
        args_digest: args_digest of the arguments seen by the proxy.

    Returns:
        Intent | None: The consumed intent, or None when nothing matches.
    """
    return default_recorder().take(
        event_key=event_key,
        tool_name=tool_name,
        digest=args_digest,
    )


def pop_intent(event_key: str, tool_name: str, args_digest: str) -> str | None:
    """Return the call_id inherited from the matching intent, else None.

    Requirement: Pre-execution Intent Record.

    This is the contract the managed proxy uses: the value is a call identity
    when an intent paired, and None when it did not, which the caller records as
    intent_unpaired and continues past. Neither outcome blocks a call.

    The digest must come from args_digest(raw_arguments) on this module, the
    same schema-free digest the hook computed. A schema-canonicalized digest
    (ticket and approval matching use one) fills defaults and reorders keys, so
    it never equals the hook side digest and every call would look unpaired.

    Args:
        event_key: Event identity of the proxy call, built with event_key_of
            from the same requester and session the hook used.
        tool_name: Tool name seen by the proxy.
        args_digest: args_digest of the raw arguments seen by the proxy.

    Returns:
        The paired call_id, or None.
    """
    intent = take_intent(event_key, tool_name, args_digest)
    return None if intent is None else intent.call_id


def drain_unpaired_intents() -> list[Intent]:
    """Return and clear every unpaired intent of the process-wide recorder."""
    return default_recorder().drain_unpaired()


def intent_stats() -> IntentStats:
    """Return the counters of the process-wide recorder."""
    return default_recorder().stats()


__all__ = [
    "DEFAULT_CAPACITY",
    "INTENT_CAPACITY",
    "INTENT_WINDOW",
    "UNPAIRED_REASON",
    "Intent",
    "IntentRecorder",
    "IntentStats",
    "args_digest",
    "canonical_arguments",
    "default_recorder",
    "drain_unpaired_intents",
    "event_key_of",
    "intent_stats",
    "pop_intent",
    "record_intent",
    "reset_intents",
    "take_intent",
]
