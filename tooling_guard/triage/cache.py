"""Bounded conclusion cache for deep trajectory analysis.

Requirement: Analysis Result Caching; Rule Set Versioning (task 6.5).

A trajectory segment SHALL be deep-analyzed at most once per
(user, ts_seq range, rule_set_version) key, and a repeat analysis MUST reuse
the cached conclusion instead of spending a second model request.  The key
therefore names the segment (subject + its ts_seq range), the rule catalog that
produced the conclusion, and the argument digest of the call being judged: a
rule upgrade or a different argument set is a different question and must be
answered again, never answered from an older verdict.

The cache is bounded on purpose.  A resident plugin judges every tool call for
the lifetime of the process, so an unbounded map would keep one conclusion per
segment forever; eviction is least-recently-used because the segment a session
keeps returning to is exactly the one worth keeping.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Final

#: Default number of conclusions kept before the least recently used is dropped.
DEEP_CONCLUSION_CACHE_CAPACITY: Final[int] = 64


@dataclass(frozen=True, slots=True)
class ConclusionKey:
    """Identity of one cached conclusion.

    Requirement: Analysis Result Caching; Rule Set Versioning.

    Attributes:
        subject: Requester key the segment belongs to.
        ts_seq_start: First recorded ts_seq of the analyzed segment.
        ts_seq_end: Last recorded ts_seq of the analyzed segment.
        rule_set_version: Catalog version that produced the conclusion.
        args_digest: Argument digest of the call being judged.
    """

    subject: str
    ts_seq_start: int
    ts_seq_end: int
    rule_set_version: str
    args_digest: str


class ConclusionCache:
    """A bounded, least-recently-used map of deep-analysis conclusions.

    Requirement: Analysis Result Caching.  Storing and reading is pure dict
    work: no clock, no I/O, no thread, so a caller can drive it from an event
    loop step without side effects on the audit trail.
    """

    def __init__(self, *, capacity: int = DEEP_CONCLUSION_CACHE_CAPACITY) -> None:
        """Initialize the cache.

        Args:
            capacity: Maximum entries kept; at least one, otherwise the module
                default is used instead of disabling the cache by accident.
        """
        usable = capacity if isinstance(capacity, int) and capacity > 0 else 0
        self._capacity = usable or DEEP_CONCLUSION_CACHE_CAPACITY
        self._entries: OrderedDict[ConclusionKey, Any] = OrderedDict()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    @property
    def capacity(self) -> int:
        """Return the entry limit of this cache."""
        return self._capacity

    def __len__(self) -> int:
        """Return how many conclusions are cached."""
        return len(self._entries)

    def __contains__(self, key: object) -> bool:
        """Return whether a conclusion is cached under key, without an LRU touch."""
        return key in self._entries

    def get(self, key: ConclusionKey) -> Any | None:
        """Return the conclusion cached under key, or None on a miss.

        Requirement: Analysis Result Caching.  A hit refreshes the entry LRU
        position so a segment reused across judgements is not the first one
        evicted.  None means "no conclusion": callers must treat it as a miss
        rather than as an uncertain verdict, because an uncertain verdict is a
        conclusion too.
        """
        if key in self._entries:
            self._entries.move_to_end(key)
            self.hits += 1
            return self._entries[key]
        self.misses += 1
        return None

    def put(self, key: ConclusionKey, conclusion: Any) -> bool:
        """Store one conclusion, evicting the least recently used on overflow.

        Args:
            key: Segment/argument identity of the conclusion.
            conclusion: Opaque value handed back by get.

        Returns:
            True when at least one older entry was evicted.
        """
        self._entries[key] = conclusion
        self._entries.move_to_end(key)
        evicted = False
        while len(self._entries) > self._capacity:
            self._entries.popitem(last=False)
            self.evictions += 1
            evicted = True
        return evicted

    def __iter__(self) -> Iterator[ConclusionKey]:
        """Iterate the cached keys, least recently used first."""
        return iter(tuple(self._entries))

    def keys(self) -> tuple[ConclusionKey, ...]:
        """Return the cached keys, least recently used first."""
        return tuple(self._entries)

    def clear(self) -> int:
        """Drop every cached conclusion and return how many were dropped."""
        dropped = len(self._entries)
        self._entries.clear()
        return dropped
