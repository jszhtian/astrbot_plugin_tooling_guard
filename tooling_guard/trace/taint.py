"""Session taint and the private-shingle set behind R12 trigger A.

Requirement: Taint Escalation; Shingle 规格可执行; Taint lifecycle.

Three prohibitions hold for everything in this module: the shingle set is never
persisted, never sent to a model, and never leaves the process. Only
private/local data may enter the set; untrusted external results must never
become an A source. Shingles are bucketed per session, so one conversation can
never match the private content another conversation read.
"""

from __future__ import annotations

import hashlib
import re
import time
import unicodedata
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import unquote_plus

from ..anonymize import (
    PATTERN_UNCOMPILABLE,
    validate_secret_pattern,
)

DEFAULT_K = 5
DEFAULT_MIN_WINDOW = 24
DEFAULT_TTL_SECONDS = 1800.0
DEFAULT_CAPACITY = 4096
DEFAULT_MIN_SHINGLES = 2
DEFAULT_COVERED_CHARS = 48
DEFAULT_SESSION_TTL_SECONDS = 1800.0

SOURCE_FILE_READ = "file_read"
SOURCE_GROUP_HISTORY = "group_history"
SOURCE_KB_RETRIEVAL = "kb_retrieval"
SOURCE_LOCAL_READ = "local_read"
PRIVATE_SOURCES: frozenset[str] = frozenset(
    {
        SOURCE_FILE_READ,
        SOURCE_GROUP_HISTORY,
        SOURCE_KB_RETRIEVAL,
        SOURCE_LOCAL_READ,
    }
)

_URL_WITH_CREDENTIALS = re.compile(r"(?i)https?://[^\s/@]*:[^\s/@]*@")
_BEARER = re.compile(r"(?i)\bbearer\s+([a-z0-9._\-]{6,})")
_API_KEY = re.compile(r"(?i)\b(?:api[_-]?key|apikey|access[_-]?token|secret)\b")
_PASSWORD = re.compile(r"(?i)\b(?:password|passwd)\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_WINDOWS_ROOTED = re.compile(r"(?i)\b[a-z]:[\\/](?:[^\\/\s]+[\\/])*[^\\/\s]*")
_UNC_PATH = re.compile(r"(?i)(?<!:)(?:\\\\|//)[^\s\\/]+[\\/][^\s]*")
_ENV_HOME = re.compile(r"(?i)(?:^|[\s\"'=(])~[/\\][^\s]*")
_ENV_VAR = re.compile(r"\$\{?[A-Z_][A-Z0-9_]*\}?")


def normalize_text(text: str) -> str:
    """Normalize text for shingling: NFKC, lowercase, URL-decode, depunctuate.

    Requirement: Shingle 规格可执行.

    Args:
        text: Raw text from a private/local source.

    Returns:
        str: Whitespace-collapsed, punctuation-free lowercase token text.
    """
    normalized = unicodedata.normalize("NFKC", text).lower()
    for _ in range(3):
        decoded = unquote_plus(normalized)
        if decoded == normalized:
            break
        normalized = unicodedata.normalize("NFKC", decoded).lower()
    chars: list[str] = []
    for char in normalized:
        category = unicodedata.category(char)
        if category.startswith("P") or category in {"Sm", "So", "Sk", "Sc"}:
            chars.append(" ")
            continue
        chars.append(char)
    collapsed = " ".join("".join(chars).split())
    return collapsed


@dataclass(frozen=True, slots=True)
class ShingleParams:
    """Configuration of the private shingle set and its match thresholds.

    Requirement: Shingle 规格可执行.

    Attributes:
        k: Word count per shingle window (default 5).
        min_window: Minimum character length of a window (default 24).
        ttl: Entry time-to-live in seconds (default 1800 = 30 minutes).
        capacity: Maximum retained shingle entries over all session buckets,
            oldest entry evicted first (default 4096).
        min_shingles: Distinct-shingle threshold (default 2).
        covered_chars: Covered-character union threshold (default 48).

    Raises:
        ValueError: When any parameter is out of range.
    """

    k: int = DEFAULT_K
    min_window: int = DEFAULT_MIN_WINDOW
    ttl: float = DEFAULT_TTL_SECONDS
    capacity: int = DEFAULT_CAPACITY
    min_shingles: int = DEFAULT_MIN_SHINGLES
    covered_chars: int = DEFAULT_COVERED_CHARS

    def __post_init__(self) -> None:
        """Validate the shingle parameters.

        Requirement: Shingle 规格可执行.

        Raises:
            ValueError: When a parameter is outside its supported range.
        """
        if self.k < 1:
            raise ValueError(f"k must be >= 1, got {self.k}")
        if self.min_window < 0:
            raise ValueError(f"min_window must be >= 0, got {self.min_window}")
        if self.ttl <= 0:
            raise ValueError(f"ttl must be > 0, got {self.ttl}")
        if self.capacity < 1:
            raise ValueError(f"capacity must be >= 1, got {self.capacity}")
        if self.min_shingles < 1:
            raise ValueError(f"min_shingles must be >= 1, got {self.min_shingles}")
        if self.covered_chars < 1:
            raise ValueError(f"covered_chars must be >= 1, got {self.covered_chars}")


@dataclass(frozen=True, slots=True)
class ShingleHit:
    """Outcome of one A-source match test.

    Requirement: Shingle 规格可执行.

    Attributes:
        matched: Whether the text reached one of the two thresholds.
        distinct: Number of distinct stored shingles found in the text.
        covered_chars: Size of the union of matched character spans.
        by_distinct: Whether the distinct-shingle threshold fired.
        by_coverage: Whether the covered-character union threshold fired.
        shingles: The matched shingle hashes.
    """

    matched: bool
    distinct: int
    covered_chars: int
    by_distinct: bool
    by_coverage: bool
    shingles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TaintRecord:
    """One tainted session with first-mark provenance.

    Requirement: Taint lifecycle.

    Attributes:
        session_key: Minimal conversation correlation key.
        agent_run: Agent run that first propagated the taint, or None.
        ts_seq: Trajectory sequence at the first mark.
        marked_at: Wall-clock seconds of the first mark.
        expires_at: Wall-clock seconds when the taint lapses.
    """

    session_key: str
    agent_run: str | None
    ts_seq: int
    marked_at: float
    expires_at: float


def _shingle_hash(window: str) -> str:
    return hashlib.blake2b(window.encode("utf-8"), digest_size=16).hexdigest()


def window_spans(text: str, params: ShingleParams) -> list[tuple[str, int, int]]:
    """Split normalized text into (window, start, end) character spans.

    Requirement: Shingle 规格可执行.

    Windows of k words shorter than min_window characters are padded forward
    with following words so each window reaches min_window characters when the
    text allows it. The returned offsets are in the normalized text, so the
    coverage union is computed over real character positions.

    Args:
        text: Text to split; it is normalized first.
        params: Shingle parameters controlling k and min_window.

    Returns:
        list[tuple[str, int, int]]: Window text and its [start, end) offsets.
    """
    normalized = normalize_text(text)
    tokens = normalized.split()
    if not tokens:
        return []
    offsets: list[int] = []
    cursor = 0
    for token in tokens:
        found = normalized.find(token, cursor)
        offsets.append(found)
        cursor = found + len(token)
    spans: list[tuple[str, int, int]] = []
    for start in range(len(tokens)):
        end = start + params.k
        if end > len(tokens):
            break
        window = " ".join(tokens[start:end])
        while len(window) < params.min_window and end < len(tokens):
            end += 1
            window = " ".join(tokens[start:end])
        spans.append((window, offsets[start], offsets[end - 1] + len(tokens[end - 1])))
    return spans


def window_texts(text: str, params: ShingleParams) -> list[tuple[str, int]]:
    """Split normalized text into (window, character length) pairs.

    Requirement: Shingle 规格可执行.

    Args:
        text: Text to split; it is normalized first.
        params: Shingle parameters controlling k and min_window.

    Returns:
        list[tuple[str, int]]: Window text and its character length.
    """
    return [(window, end - start) for window, start, end in window_spans(text, params)]


def is_private_source(source: str, *, project_roots: Iterable[str] = ()) -> bool:
    """Return whether a source kind may feed the A shingle set.

    Requirement: Taint Escalation.

    Only private/local data feeds trigger A, so the four private source kinds
    qualify directly and a project-root path or project-root token also does.
    Anything else, in particular untrusted external results, is rejected.

    Args:
        source: Source kind or path string.
        project_roots: Configured project root paths.

    Returns:
        bool: True when the source is private/local.
    """
    if source in PRIVATE_SOURCES:
        return True
    if not source:
        return False
    candidate = source.replace("\\", "/").lower()
    for root in project_roots:
        normalized_root = root.replace("\\", "/").lower().rstrip("/")
        if normalized_root and (
            candidate == normalized_root or candidate.startswith(normalized_root + "/")
        ):
            return True
    return False


#: Bucket used when content is indexed without a session. The first mark adopts
#: it, so it never lets one session match another session's content.
UNSCOPED_SESSION = ""


def _session_bucket(session_key: str | None) -> str:
    """Return the shingle bucket one session owns, or the unscoped bucket."""
    return str(session_key) if session_key else UNSCOPED_SESSION


class TaintStore:
    """Own per-session taint and the memory-only private shingle set.

    Requirement: Taint Escalation; Shingle 规格可执行; Taint lifecycle.

    The store answers two questions only: whether a session is tainted, and
    whether text carries the private shingles, secrets, or sensitive paths of
    that same session. It never denies anything; the escalation module turns
    these answers into a verdict for the triage layer.

    Private shingles are bucketed per session: index_private files a text under
    one session key, match only reads that session's bucket, and clear drops one
    bucket. One conversation can therefore never answer trigger A for what
    another conversation read. The capacity bound is global: every bucket shares
    one bounded LRU order, so going over the cap drops the oldest entry of the
    store (a detection loss, never a false escalation).

    Args:
        params: Shingle and threshold configuration.
        session_ttl: Session-taint time-to-live in seconds (default 30
            minutes).
        secret_patterns: Caller-supplied secret regular expressions. An
            expression the anonymize.py subset refuses is counted in
            refused_secret_patterns and never compiled, so a caller that skipped
            the configuration gate cannot park a backtracking bomb in
            has_secret.
        project_roots: Project root paths counted as private/local.

    Raises:
        ValueError: When session_ttl or a secret pattern is invalid.
    """

    def __init__(
        self,
        *,
        params: ShingleParams | None = None,
        session_ttl: float = DEFAULT_SESSION_TTL_SECONDS,
        secret_patterns: Iterable[str] = (),
        project_roots: Iterable[str] = (),
    ) -> None:
        if session_ttl <= 0:
            raise ValueError(f"session_ttl must be > 0, got {session_ttl}")
        self._params = params or ShingleParams()
        self._session_ttl = float(session_ttl)
        self._project_roots = tuple(project_roots)
        # This constructor is reachable from any caller that keeps its own list
        # (main.py:4530 -> trace/watch.py:145 -> here) without passing the
        # configuration gate, so the subset check runs again before re.compile.
        # A refused expression would otherwise be searched synchronously inside
        # has_secret, where no asyncio timeout can interrupt the match. The
        # judgement stays the one anonymize.py owns. An expression that compiles
        # in neither place still raises re.error verbatim.
        kept_patterns: list[re.Pattern[str]] = []
        refused_patterns = 0
        for pattern in secret_patterns:
            code = validate_secret_pattern(pattern)
            if code is not None and code != PATTERN_UNCOMPILABLE:
                refused_patterns += 1
                continue
            kept_patterns.append(re.compile(pattern))
        self._secret_patterns: tuple[re.Pattern[str], ...] = tuple(kept_patterns)
        self._refused_secret_patterns = refused_patterns
        self._shingles: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._tainted: dict[str, TaintRecord] = {}

    @property
    def params(self) -> ShingleParams:
        """Return the active shingle parameters."""
        return self._params

    @property
    def session_ttl(self) -> float:
        """Return the session-taint time-to-live in seconds."""
        return self._session_ttl

    @property
    def secret_patterns(self) -> tuple[str, ...]:
        """Return the caller patterns that survived the subset check.

        Requirement: Sanitized Persistence. The sources are reported instead of
        the compiled objects so a caller can show which configured expression is
        in force without gaining a way to run one.
        """
        return tuple(pattern.pattern for pattern in self._secret_patterns)

    @property
    def refused_secret_patterns(self) -> int:
        """Return how many caller patterns were refused and never compiled."""
        return self._refused_secret_patterns

    def _expire_shingles(self, now: float) -> None:
        expired = [
            key
            for key, added in self._shingles.items()
            if now - added >= self._params.ttl
        ]
        for key in expired:
            del self._shingles[key]

    def _expire_taint(self, now: float) -> None:
        expired = [
            key for key, record in self._tainted.items() if now >= record.expires_at
        ]
        for key in expired:
            del self._tainted[key]

    def _trim(self) -> None:
        """Enforce the global shingle cap, dropping the oldest entries first."""
        while len(self._shingles) > self._params.capacity:
            self._shingles.popitem(last=False)

    def _drop_bucket(self, bucket: str) -> int:
        """Drop every shingle of one session bucket and return the count."""
        doomed = [key for key in self._shingles if key[0] == bucket]
        for key in doomed:
            del self._shingles[key]
        return len(doomed)

    def _move_bucket(self, source: str, target: str) -> int:
        """Move one bucket's shingles into another, keeping the LRU order."""
        moved = 0
        for key, added in list(self._shingles.items()):
            if key[0] != source:
                continue
            del self._shingles[key]
            self._shingles[(target, key[1])] = added
            moved += 1
        self._trim()
        return moved

    def _copy_bucket(self, source: str, target: str) -> int:
        """Copy one bucket's shingles into another, keeping the cap."""
        copied = 0
        for (bucket, digest), added in list(self._shingles.items()):
            if bucket != source or (target, digest) in self._shingles:
                continue
            self._shingles[(target, digest)] = added
            copied += 1
        self._trim()
        return copied

    def index_private(
        self,
        text: str,
        *,
        session_key: str | None = None,
        now: float | None = None,
    ) -> int:
        """Add the shingles of one private/local text to one session bucket.

        Requirement: Taint Escalation.

        Only the session that owns the bucket can match the entry later.
        A session_key of None files the entry in the unscoped bucket, for
        callers that do not know the session yet: the first mark adopts that
        bucket, so unscoped content still never outlives one session.

        Args:
            text: Private/local text to index.
            session_key: Session that owns the content, when already known.
            now: Optional wall-clock seconds.

        Returns:
            int: Number of shingle entries added.
        """
        stamp = time.time() if now is None else now
        self._expire_shingles(stamp)
        bucket = _session_bucket(session_key)
        added = 0
        for window, _ in window_texts(text, self._params):
            key = (bucket, _shingle_hash(window))
            if key in self._shingles:
                del self._shingles[key]
            self._shingles[key] = stamp
            added += 1
            self._trim()
        return added

    def index_private_if(
        self,
        text: str,
        *,
        source: str,
        session_key: str | None = None,
        project_roots: Iterable[str] = (),
        now: float | None = None,
    ) -> int:
        """Index a text only when its source kind is private/local.

        Requirement: Taint Escalation.

        Untrusted external results are rejected here, so they can never become
        an A source.

        Args:
            text: Candidate text.
            source: Source kind or path the text came from.
            session_key: Session that owns the content, when already known.
            project_roots: Project roots counted as private/local; defaults to
                the roots given at construction.
            now: Optional wall-clock seconds.

        Returns:
            int: Number of shingle entries added, or 0 when rejected.
        """
        roots = tuple(project_roots) or self._project_roots
        if not is_private_source(source, project_roots=roots):
            return 0
        return self.index_private(text, session_key=session_key, now=now)

    def is_private_source(self, source: str) -> bool:
        """Return whether a source kind may feed trigger A.

        Requirement: Taint Escalation.
        """
        return is_private_source(source, project_roots=self._project_roots)

    def match(
        self,
        text: str,
        *,
        session_key: str | None = None,
        now: float | None = None,
    ) -> ShingleHit:
        """Test text against one session's private shingle bucket.

        Requirement: Shingle 规格可执行.

        Coverage counts each covered character once over the union of matched
        spans, never by summing per-window lengths. Only the shingles of
        session_key are visible, so another session's private content can never
        be matched back and one conversation is never mistaken for another.

        Args:
            text: Candidate text.
            session_key: Session whose bucket is consulted.
            now: Optional wall-clock seconds.

        Returns:
            ShingleHit: Threshold outcome, distinct count, and covered union.
        """
        stamp = time.time() if now is None else now
        self._expire_shingles(stamp)
        bucket = _session_bucket(session_key)
        spans: list[tuple[int, int]] = []
        matched_hashes: list[str] = []
        for window, start, end in window_spans(text, self._params):
            digest = _shingle_hash(window)
            if (bucket, digest) not in self._shingles:
                continue
            matched_hashes.append(digest)
            spans.append((start, end))
        distinct = len(dict.fromkeys(matched_hashes))
        covered = (
            len(set().union(*(set(range(start, end)) for start, end in spans)))
            if spans
            else 0
        )
        by_distinct = distinct >= self._params.min_shingles
        by_coverage = covered >= self._params.covered_chars
        return ShingleHit(
            matched=by_distinct or by_coverage,
            distinct=distinct,
            covered_chars=covered,
            by_distinct=by_distinct,
            by_coverage=by_coverage,
            shingles=tuple(matched_hashes),
        )

    def has_secret(self, text: str) -> bool:
        """Return whether text carries a secret-shaped token.

        Requirement: Taint Escalation.

        Args:
            text: Candidate text (URL, query, or path).

        Returns:
            bool: True when a secret or sensitive-path pattern matches.
        """
        if not text:
            return False
        for pattern in (
            _URL_WITH_CREDENTIALS,
            _BEARER,
            _API_KEY,
            _PASSWORD,
            _PRIVATE_KEY,
            _WINDOWS_ROOTED,
            _UNC_PATH,
            _ENV_HOME,
            _ENV_VAR,
        ):
            if pattern.search(text):
                return True
        return any(pattern.search(text) for pattern in self._secret_patterns)

    def mark(
        self,
        session_key: str,
        *,
        ts_seq: int = 0,
        agent_run: str | None = None,
        now: float | None = None,
    ) -> TaintRecord:
        """Taint a session, recording the first-mark provenance.

        Requirement: Taint lifecycle.

        Re-marking an already tainted session keeps the original ts_seq and
        first-mark instant and only refreshes the expiry. A mark also adopts the
        unscoped bucket, so content indexed before the session was known belongs
        to the session that is tainted first and to no other.

        Args:
            session_key: Minimal conversation correlation key.
            ts_seq: Trajectory sequence at the mark.
            agent_run: Agent run that propagates the taint.
            now: Optional wall-clock seconds.

        Returns:
            TaintRecord: The resulting taint record.
        """
        stamp = time.time() if now is None else now
        self._expire_taint(stamp)
        if session_key and session_key != UNSCOPED_SESSION:
            self._move_bucket(UNSCOPED_SESSION, session_key)
        existing = self._tainted.get(session_key)
        if existing is not None:
            record = TaintRecord(
                session_key=session_key,
                agent_run=agent_run if agent_run is not None else existing.agent_run,
                ts_seq=existing.ts_seq,
                marked_at=existing.marked_at,
                expires_at=stamp + self._session_ttl,
            )
        else:
            record = TaintRecord(
                session_key=session_key,
                agent_run=agent_run,
                ts_seq=ts_seq,
                marked_at=stamp,
                expires_at=stamp + self._session_ttl,
            )
        self._tainted[session_key] = record
        return record

    def propagate(
        self,
        source_session: str,
        target_session: str,
        *,
        agent_run: str | None = None,
        now: float | None = None,
    ) -> TaintRecord | None:
        """Propagate the taint of one session into a derived agent run.

        Requirement: Taint lifecycle.

        The derived run inherits the source bucket, because it may carry the
        same private content into a sink; the source keeps its own.

        Args:
            source_session: Session that carries the taint.
            target_session: Session key of the derived agent run.
            agent_run: Agent run identifier to record.
            now: Optional wall-clock seconds.

        Returns:
            TaintRecord | None: The propagated record, or None when the source
            session is not tainted.
        """
        stamp = time.time() if now is None else now
        self._expire_taint(stamp)
        origin = self._tainted.get(source_session)
        if origin is None:
            return None
        record = TaintRecord(
            session_key=target_session,
            agent_run=agent_run if agent_run is not None else origin.agent_run,
            ts_seq=origin.ts_seq,
            marked_at=origin.marked_at,
            expires_at=stamp + self._session_ttl,
        )
        self._tainted[target_session] = record
        if source_session and target_session and source_session != target_session:
            self._copy_bucket(source_session, target_session)
        return record

    def is_tainted(self, session_key: str, *, now: float | None = None) -> bool:
        """Return whether a session is currently tainted.

        Requirement: Taint lifecycle.
        """
        stamp = time.time() if now is None else now
        self._expire_taint(stamp)
        return session_key in self._tainted

    def status(
        self, session_key: str, *, now: float | None = None
    ) -> TaintRecord | None:
        """Return the visible taint state for one session.

        Requirement: Taint lifecycle.
        """
        stamp = time.time() if now is None else now
        self._expire_taint(stamp)
        return self._tainted.get(session_key)

    def clear(self, session_key: str | None = None) -> int:
        """Clear one session taint and its shingle bucket, or everything.

        Requirement: Taint lifecycle.

        Clearing one session removes only that session's private shingles: no
        other session loses its bucket, and no other session inherits it.

        Args:
            session_key: Session to clear, or None to clear everything.

        Returns:
            int: Number of taint records removed.
        """
        if session_key is None:
            removed = len(self._tainted)
            self._tainted.clear()
            self._shingles.clear()
            return removed
        removed = 1 if self._tainted.pop(session_key, None) is not None else 0
        self._drop_bucket(_session_bucket(session_key))
        return removed

    def purge_expired(self, *, now: float | None = None) -> int:
        """Drop expired shingle entries and taint records.

        Requirement: Taint lifecycle.

        Returns:
            int: Number of taint records removed.
        """
        stamp = time.time() if now is None else now
        self._expire_shingles(stamp)
        before = len(self._tainted)
        self._expire_taint(stamp)
        return before - len(self._tainted)

    def shingle_count(
        self, *, session_key: str | None = None, now: float | None = None
    ) -> int:
        """Return the number of live shingle entries, of one session or all.

        Requirement: Shingle 规格可执行.
        """
        stamp = time.time() if now is None else now
        self._expire_shingles(stamp)
        if session_key is None:
            return len(self._shingles)
        bucket = _session_bucket(session_key)
        return sum(1 for key in self._shingles if key[0] == bucket)

    def __len__(self) -> int:
        """Return the number of tainted sessions."""
        return len(self._tainted)
