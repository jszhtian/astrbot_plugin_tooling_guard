"""Trajectory-level watch: per-call facts in, one R12 trigger out.

Requirement: Taint Escalation; Trajectory Review Trigger.

The per-call pipeline judges one call at a time, so a write is not dangerous by
itself and an execution is not dangerous by itself: only the pair is. This module
keeps the small amount of state that pair needs -- a taint store fed by private
reads, a bounded ledger of writes along with the taint state they were made
under, and the untrusted text seen so far -- and answers one question per call:
does this call complete a shape the deep analysis should look at?

It never decides a verdict. A trigger is a fact the gateway turns into a deep
review, and the deep review is the only thing allowed to tighten a plan. It also
never classifies a call: the labels, paths and source kind arrive already
computed, so this package depends on nothing above it.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import Any

from .escalation import TIER_STRONG, TRIGGER_NONE, Escalation, evaluate
from .taint import DEFAULT_SESSION_TTL_SECONDS, TaintStore

#: Trigger kind of a tainted write whose path a later call executes.
TRIGGER_WRITE_EXEC = "write_exec"
#: Entries kept per session ledger before the oldest are dropped.
DEFAULT_KEEP = 64
#: Cap of one ledger text; a longer body is clipped, never stored whole.
LEDGER_TEXT_LIMIT = 4096
#: Shortest basename accepted when a path is compared by name alone.
MIN_BASENAME_CHARS = 4


@dataclass(frozen=True, slots=True)
class CallFacts:
    """What one managed call contributes to the trajectory.

    Requirement: Trajectory Review Trigger. The caller classifies the call and
    fills these fields; the watch only consumes them, so the trace package
    never imports the triage package that produced them.
    """

    tool: str
    labels: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()
    texts: tuple[str, ...] = ()
    payload: str = ""
    source: str = ""
    writes: tuple[str, ...] = ()
    executes: tuple[str, ...] = ()
    untrusted: bool = False
    tier: str = TIER_STRONG


@dataclass(frozen=True, slots=True)
class WriteFact:
    """One write observed in a session and the taint state it was made under.

    Requirement: Trajectory Review Trigger. The flag is taken once, at write
    time, so a session tainted afterwards never makes an older write dangerous.
    """

    path: str
    basename: str
    tainted: bool
    ts_seq: int


@dataclass(frozen=True, slots=True)
class TrajectoryTrigger:
    """The trajectory verdict of one call.

    Requirement: Trajectory Review Trigger.
    """

    trigger: str = TRIGGER_NONE
    reason: str = ""
    session_key: str = ""
    tool: str = ""
    ts_seq: int = 0
    written: str = ""
    executed: str = ""
    escalation: Escalation | None = None

    @property
    def fired(self) -> bool:
        """Return whether this call completed a shape worth a deep look."""
        return self.trigger != TRIGGER_NONE

    def as_dict(self) -> dict[str, Any]:
        """Return the audit-facing projection of this trigger."""
        return {
            "trigger": self.trigger,
            "reason": self.reason,
            "session": self.session_key,
            "tool": self.tool,
            "ts_seq": self.ts_seq,
            "written": self.written,
            "executed": self.executed,
        }


class TrajectoryWatch:
    """Track the trajectory facts the per-call rules cannot see.

    Requirement: Taint Escalation; Trajectory Review Trigger. State is per
    session and bounded: writes are trimmed to the kept entries, untrusted texts
    to the same bound, and a session idle past its TTL is forgotten whole.
    """

    def __init__(
        self,
        *,
        taint: TaintStore | None = None,
        keep: int = DEFAULT_KEEP,
        session_ttl: float = DEFAULT_SESSION_TTL_SECONDS,
        project_roots: Iterable[str] = (),
        secret_patterns: Iterable[str] = (),
    ) -> None:
        """Build a watch, or reuse a taint store the caller already owns.

        Args:
            taint: Optional taint store; one is built from the other arguments
                when omitted.
            keep: Entries kept per session ledger.
            session_ttl: Seconds a session stays known to the watch.
            project_roots: Roots counted as private/local content.
            secret_patterns: Extra secret patterns for trigger C.

        Raises:
            ValueError: When session_ttl is not positive.
        """
        ttl = float(session_ttl)
        if ttl <= 0:
            raise ValueError("session_ttl must be positive")
        self._taint = (
            taint
            if taint is not None
            else TaintStore(
                session_ttl=ttl,
                secret_patterns=tuple(secret_patterns),
                project_roots=tuple(project_roots),
            )
        )
        self._keep = max(1, int(keep))
        self._session_ttl = ttl
        self._writes: dict[str, list[WriteFact]] = {}
        self._untrusted: dict[str, tuple[str, ...]] = {}
        self._seen: dict[str, float] = {}

    @property
    def taint(self) -> TaintStore:
        """Return the taint store this watch feeds and reads."""
        return self._taint

    def __len__(self) -> int:
        return len(self._seen)

    def observe(
        self,
        *,
        session_key: str,
        facts: CallFacts,
        args: Mapping[str, Any] | None = None,
        ts_seq: int = 0,
        now: float | None = None,
    ) -> TrajectoryTrigger:
        """Record one finished call and return its trajectory verdict.

        Requirement: Taint Escalation; Trajectory Review Trigger. The call feeds
        the taint store when its source is private, the R12 triggers are
        evaluated for this call, and the write-then-execute pair is checked
        against the write ledger, so a write only ever meets the executions that
        came after it.

        Args:
            session_key: Session the call belongs to.
            facts: Classification facts of the call.
            args: Call arguments; their string values form the call surface.
            ts_seq: Trajectory sequence this call will be stored under.
            now: Optional wall-clock seconds.

        Returns:
            The trigger; its fired flag is False when nothing suspicious ran.
        """
        stamp = time.time() if now is None else now
        self._expire(stamp)
        key = str(session_key)
        self._seen[key] = stamp
        self._ingest(key, facts, ts_seq=ts_seq, now=now)
        verdict = evaluate(
            self._taint,
            session_key=key,
            tool=facts.tool,
            args=args or {},
            labels=facts.labels,
            destinations=facts.destinations,
            untrusted_texts=self._untrusted.get(key, ()),
            tier=facts.tier,
            ts_seq=ts_seq,
            now=now,
        )
        base = TrajectoryTrigger(
            reason=verdict.reason,
            session_key=key,
            tool=facts.tool,
            ts_seq=ts_seq,
            escalation=verdict,
        )
        if verdict.escalated:
            return replace(base, trigger=verdict.trigger)
        pair = self._executed_write(key, facts)
        if pair is not None:
            fact, candidate = pair
            return replace(
                base,
                trigger=TRIGGER_WRITE_EXEC,
                reason=(
                    "write_exec: this call executes a path a tainted call wrote"
                    f" (written at ts_seq={fact.ts_seq})"
                ),
                written=fact.path,
                executed=candidate,
            )
        self._remember_write(key, facts, ts_seq=ts_seq, now=now)
        return base

    def clear(self, session_key: str | None = None) -> None:
        """Forget one session, or everything when no session is named."""
        if session_key is None:
            self._seen.clear()
            self._writes.clear()
            self._untrusted.clear()
            self._taint.clear()
            return
        self._seen.pop(session_key, None)
        self._writes.pop(session_key, None)
        self._untrusted.pop(session_key, None)
        self._taint.clear(session_key)

    def _ingest(
        self,
        key: str,
        facts: CallFacts,
        *,
        ts_seq: int,
        now: float | None,
    ) -> None:
        """Feed a private read into the taint store, remember untrusted text.

        Requirement: Taint Escalation. Only a call whose source kind is private
        can shingle here, so an external result never becomes an A source; the
        session is marked once and keeps its first-mark provenance. Every
        shingle is filed under this session key, so no other session can match
        the content this one read.
        """
        if facts.source:
            for text in facts.texts:
                self._taint.index_private_if(
                    text, source=facts.source, session_key=key, now=now
                )
            self._taint.mark(key, ts_seq=ts_seq, now=now)
        if facts.untrusted:
            self._remember_untrusted(key, facts.texts)

    def _remember_untrusted(self, key: str, texts: Iterable[str]) -> None:
        """Keep the untrusted text a later deliver destination may come from."""
        kept = list(self._untrusted.get(key, ()))
        for text in texts:
            clipped = text[:LEDGER_TEXT_LIMIT]
            if clipped and clipped not in kept:
                kept.append(clipped)
        self._untrusted[key] = tuple(kept[-self._keep :])

    def _remember_write(
        self,
        key: str,
        facts: CallFacts,
        *,
        ts_seq: int,
        now: float | None,
    ) -> None:
        """Record what this call wrote and whether the write carried taint.

        Requirement: Trajectory Review Trigger. A write counts as tainted when
        the session is already tainted or when the written body itself carries
        private shingles; an untainted write never completes the pair later.
        """
        if not facts.writes:
            return
        tainted = (
            self._taint.is_tainted(key, now=now)
            or self._taint.match(facts.payload, session_key=key, now=now).matched
        )
        ledger = self._writes.setdefault(key, [])
        for path in facts.writes:
            ledger.append(
                WriteFact(
                    path=_normalize_path(path),
                    basename=_basename(path),
                    tainted=tainted,
                    ts_seq=ts_seq,
                )
            )
        del ledger[: max(0, len(ledger) - self._keep)]

    def _executed_write(
        self, key: str, facts: CallFacts
    ) -> tuple[WriteFact, str] | None:
        """Return the newest tainted write this execution names, if any."""
        if not facts.executes:
            return None
        for fact in reversed(self._writes.get(key, ())):
            if not fact.tainted:
                continue
            for candidate in facts.executes:
                if _matches(fact, candidate):
                    return fact, candidate
        return None

    def _expire(self, stamp: float) -> None:
        """Forget sessions idle past the TTL and purge expired shingles."""
        stale = [
            key for key, seen in self._seen.items() if stamp - seen >= self._session_ttl
        ]
        for key in stale:
            self._seen.pop(key, None)
            self._writes.pop(key, None)
            self._untrusted.pop(key, None)
        self._taint.purge_expired(now=stamp)


def _normalize_path(value: str) -> str:
    """Return a path in the one shape both sides of a comparison agree on."""
    text = value.strip().strip("\"'`")
    return text.replace("\\", "/").casefold().rstrip("/")


def _basename(value: str) -> str:
    """Return the last component of a path."""
    return _normalize_path(value).rsplit("/", 1)[-1]


def _matches(fact: WriteFact, candidate: str) -> bool:
    """Return whether an execution candidate names the written path."""
    normalized = _normalize_path(candidate)
    if not normalized or not fact.path:
        return False
    if normalized == fact.path:
        return True
    name = _basename(candidate)
    return bool(name) and name == fact.basename and len(name) >= MIN_BASENAME_CHARS
