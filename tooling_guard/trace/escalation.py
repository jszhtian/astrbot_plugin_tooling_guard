"""R12 trajectory escalation verdicts (A content return, B destination, C secrets).

Requirement: Taint Escalation.

This module only judges. It never denies, never writes a store row, and never
opens a socket: an Escalation is handed to the triage/policy layers, which own
the decision.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from ..anonymize import _DEFAULT_RULES, _Rule
from .taint import ShingleHit, TaintStore

TRIGGER_NONE = "none"
TRIGGER_A = "A"
TRIGGER_B = "B"
TRIGGER_C = "C"
TRIGGER_ORDER: tuple[str, ...] = (TRIGGER_C, TRIGGER_A, TRIGGER_B)
TIER_STRONG = "T-strong"
WOULD_BE_SUSPEND = "suspend"
WOULD_BE_NONE = "none"
SINK_DELIVER = "sink_deliver"
SINK_READ = "sink_read"
SINK_KINDS: frozenset[str] = frozenset({SINK_DELIVER, SINK_READ})
_MIN_DESTINATION_CHARS: Final[int] = 4
"""Shortest destination string considered for trigger B at all."""
_MIN_ALPHA_DESTINATION_CHARS: Final[int] = 8
"""Shortest all-letter destination that is specific enough for trigger B.

Requirement: Taint Escalation.  A destination is a host, an address or an
identifier, so an ordinary word only qualifies once it is long enough to be
unlikely in prose: "data", "report", "upload" and "hunter" all appear in
untrusted text that has nothing to do with a destination, and matching them
suspended every tainted deliver call that happened to mention one.
"""
_STRUCTURED_DESTINATION_CHARS: Final[str] = ".:/\\@#?&="
"""Characters that make a destination an address rather than a word."""
_LEFT_BOUNDARY: Final[str] = r"(?<![0-9a-z_])"
_RIGHT_BOUNDARY: Final[str] = r"(?![0-9a-z_])"
_PAIR_RULE_NAMES: Final[frozenset[str]] = frozenset(
    {"authorization", "binding", "password", "token", "url_secret"}
)
"""Anonymizer rules that match a generic key/value pair, not a value shape.

Requirement: Taint Escalation.  Every other rule owns a shape no ordinary
sentence produces (an sk- key, a PEM header, a URL credential), so its match is
itself the secret.  A key such as "token" proves nothing on its own, which is
why the pair family carries an extra value-shape test.
"""
_VALUE_RULES: Final[tuple[_Rule, ...]] = tuple(
    rule for rule in _DEFAULT_RULES if rule.name not in _PAIR_RULE_NAMES
)
"""Anonymizer rules whose match is a secret value by construction."""
_PAIR_RULES: Final[tuple[_Rule, ...]] = tuple(
    rule for rule in _DEFAULT_RULES if rule.name in _PAIR_RULE_NAMES
)
"""Anonymizer rules that bind a key to a value of any shape."""
_MIN_CREDENTIAL_CHARS: Final[int] = 5
"""Shortest key/value pair value that can be a credential."""
_LONG_CREDENTIAL_CHARS: Final[int] = 12
"""All-lowercase value length that is long enough to be a credential.

Requirement: Taint Escalation.  A generated token always mixes case, digits or
symbols; a 6-character all-lowercase value is a word.  "token=abcdef" is the
review finding: it escalated a call that carried no secret at all.
"""


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _iter_strings(item)
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _iter_strings(item)


@dataclass(frozen=True, slots=True)
class Escalation:
    """One R12 evaluation result.

    Requirement: Taint Escalation.

    Attributes:
        trigger: The highest-priority trigger, or none.
        tier: Tool tier of the evaluated call; unknown stays T-strong.
        reason: Human-readable justification for the verdict.
        would_be: suspend when the rules fire, none otherwise.
        session_key: Session the verdict belongs to.
        tool: Tool name under evaluation.
        ts_seq: Trajectory sequence the verdict is anchored at.
        triggers: Every trigger that fired, in priority order.
        matched_shingles: Private shingle hashes found in the payload.
        covered_chars: Covered-character union of the A match.
        destinations: Destination strings considered for trigger B.
        resolved_by: sink kind that produced the verdict, or empty.
    """

    trigger: str = TRIGGER_NONE
    tier: str = TIER_STRONG
    reason: str = ""
    would_be: str = WOULD_BE_NONE
    session_key: str = ""
    tool: str = ""
    ts_seq: int = 0
    triggers: tuple[str, ...] = ()
    matched_shingles: tuple[str, ...] = ()
    covered_chars: int = 0
    destinations: tuple[str, ...] = ()
    resolved_by: str = ""

    @property
    def escalated(self) -> bool:
        """Return whether any R12 trigger fired."""
        return self.trigger != TRIGGER_NONE

    @property
    def suspends(self) -> bool:
        """Return whether the verdict asks for suspension."""
        return self.would_be == WOULD_BE_SUSPEND

    def as_dict(self) -> dict[str, Any]:
        """Return the verdict as a plain mapping for audit and views.

        Requirement: Taint Escalation.
        """
        return {
            "trigger": self.trigger,
            "triggers": list(self.triggers),
            "tier": self.tier,
            "reason": self.reason,
            "would_be": self.would_be,
            "session": self.session_key,
            "tool": self.tool,
            "ts_seq": self.ts_seq,
            "matched_shingles": list(self.matched_shingles),
            "covered_chars": self.covered_chars,
            "destinations": list(self.destinations),
            "resolved_by": self.resolved_by,
        }


def sink_kind_of(labels: Iterable[str]) -> str:
    """Return the sink kind carried by a label set, or empty when unknown.

    Requirement: Taint Escalation.

    Args:
        labels: Orthogonal labels such as sink_deliver or sink_read.

    Returns:
        str: sink_deliver, sink_read, or the empty string.
    """
    present = [label for label in labels if label in SINK_KINDS]
    if SINK_DELIVER in present:
        return SINK_DELIVER
    if SINK_READ in present:
        return SINK_READ
    return ""


def _credential_tail(text: str) -> str:
    """Return the value part of one key/value or URL match.

    Requirement: Taint Escalation.  A key/value rule matches key, separator and
    value together and only the value can be the secret, so the shape test runs
    on the text after the last separator.  A match without a separator (the
    mysql -p form, a URL credential) is the credential itself and is returned
    unchanged.

    Args:
        text: Text a key/value rule matched.

    Returns:
        str: The candidate value, with surrounding quotes and blanks removed.
    """
    cut = max(text.rfind("="), text.rfind(":"))
    if cut < 0:
        return text
    return text[cut + 1 :].strip(" \t\"'")


def _looks_like_credential(value: str) -> bool:
    """Report whether a key/value match really holds a credential.

    Requirement: Taint Escalation.  A bare key binding is not a secret, so the
    value has to look generated: a digit, a symbol or an upper-case letter, or
    a length no ordinary word reaches.

    Args:
        value: Candidate value taken from a key/value match.

    Returns:
        bool: True when the value is credential shaped.
    """
    if len(value) < _MIN_CREDENTIAL_CHARS:
        return False
    if len(value) >= _LONG_CREDENTIAL_CHARS:
        return True
    return any(char.isdigit() or char.isupper() or not char.isalnum() for char in value)


def _secret_value_hit(text: str) -> bool:
    """Report whether one call-surface string carries an actual secret value.

    Requirement: Taint Escalation.  The previous test asked the anonymizer
    whether redaction changed the text, which bound the trigger to the redaction
    rules instead of the secret they describe: a gap in a rule class was a
    silent miss here too, and a bare "token=abcdef" binding counted as a leak.
    The rules decide now -- a structural class is a secret by construction, and
    a generic key/value binding must still carry a credential-shaped value.

    Args:
        text: One string of the call surface.

    Returns:
        bool: True when a secret value is present.
    """
    if not text:
        return False
    for rule in _VALUE_RULES:
        if rule.pattern.search(text):
            return True
    return any(
        _looks_like_credential(_credential_tail(match.group(0)))
        for rule in _PAIR_RULES
        for match in rule.pattern.finditer(text)
    )


def _destination_is_specific(needle: str) -> bool:
    """Report whether a destination is specific enough to raise trigger B.

    Requirement: Taint Escalation.  A destination that is also an ordinary word
    is not evidence of an injection: the report finding is that "data",
    "report", "upload" and "hunter" suspended any tainted deliver call whose
    untrusted context happened to contain them.

    Args:
        needle: Stripped destination string.

    Returns:
        bool: True for an address, a number-bearing token or a long word.
    """
    if len(needle) >= _MIN_ALPHA_DESTINATION_CHARS:
        return True
    if any(char.isdigit() for char in needle):
        return True
    return any(char in _STRUCTURED_DESTINATION_CHARS for char in needle)


def _destination_seen(
    destination: str, untrusted_texts: Iterable[str], exempt: frozenset[str]
) -> bool:
    if not destination:
        return False
    needle = destination.strip()
    if len(needle) < _MIN_DESTINATION_CHARS:
        return False
    if not _destination_is_specific(needle):
        return False
    if needle.casefold() in frozenset(
        item.strip().casefold() for item in exempt if item
    ):
        return False
    pattern = re.compile(
        _LEFT_BOUNDARY + re.escape(needle) + _RIGHT_BOUNDARY, re.IGNORECASE
    )
    for text in untrusted_texts:
        if text and pattern.search(text):
            return True
    return False


def evaluate(
    taint: TaintStore,
    *,
    session_key: str,
    tool: str,
    args: Mapping[str, Any] | None = None,
    labels: Iterable[str] = (),
    destinations: Iterable[str] = (),
    untrusted_texts: Iterable[str] = (),
    exempt_destinations: Iterable[str] = (),
    tier: str = TIER_STRONG,
    ts_seq: int = 0,
    now: float | None = None,
) -> Escalation:
    """Evaluate the three R12 triggers for one call and return the verdict.

    Requirement: Taint Escalation.

    Trigger A fires when a tainted session sends outbound payload (delivered
    content, or the URL/query of a read sink) that carries the private shingles
    of that same session. Trigger B fires only for
    a deliver sink whose destination first appears inside untrusted content, is
    not exempt and is specific enough to be a destination at all (an address, a
    number-bearing token or a long word) rather than an ordinary word that
    untrusted text happens to contain; a read sink never raises B, so a tainted
    session that fetches a search-result URL without an A shingle or a C match
    is not escalated.
    Trigger C fires only for a tainted session on a sink call, and only when
    the call surface carries an actual secret value (a token, key or PEM block
    as the anonymizer rules define them); a bare keyword such as password or
    api_key, an environment reference, or a system path never raises it.

    A and C both require a tainted session, because a session that read nothing
    private has nothing to leak and matching content alone must never escalate.
    A tainted session alone never escalates either: the flag only raises the
    cost of private content crossing the boundary, it is not itself a payload.

    Args:
        taint: Store answering shingle and secret questions.
        session_key: Session the verdict belongs to.
        tool: Tool name under evaluation.
        args: Call arguments; their string values form the call surface.
        labels: Labels carrying sink_deliver or sink_read.
        destinations: Destination strings for trigger B.
        untrusted_texts: Untrusted content already ingested in this session;
            a deliver destination seen here is a B injection.
        exempt_destinations: Destinations taken from the user's own message or a
            configured allowlist; these never raise B.
        tier: Tool tier, defaulting to T-strong.
        ts_seq: Trajectory sequence the verdict anchors at.
        now: Optional wall-clock seconds for shingle expiry.

    Returns:
        Escalation: The verdict; would_be is suspend only when a trigger fired.
    """
    label_tuple = tuple(labels)
    sink = sink_kind_of(label_tuple)
    destination_tuple = tuple(dest for dest in destinations if dest)
    exempt = frozenset(exempt_destinations)
    surfaces = [text for text in _iter_strings(args or {}) if text]
    untrusted = tuple(text for text in untrusted_texts if text)

    fired: list[str] = []
    reasons: list[str] = []
    hit = ShingleHit(
        matched=False,
        distinct=0,
        covered_chars=0,
        by_distinct=False,
        by_coverage=False,
        shingles=(),
    )
    matched_shingles: tuple[str, ...] = ()
    covered = 0

    tainted = taint.is_tainted(session_key, now=now)
    secret_surface = list(surfaces) + list(destination_tuple)
    if sink and tainted:
        secret_hit = next(
            (text for text in secret_surface if _secret_value_hit(text)), ""
        )
        if secret_hit:
            fired.append(TRIGGER_C)
            reasons.append("C: secret value in the call surface of a tainted session")

    if sink:
        if sink == SINK_DELIVER:
            payload_parts = list(surfaces) + list(destination_tuple)
        else:
            payload_parts = list(destination_tuple) + list(surfaces)
        payload = "\n".join(payload_parts)
        if tainted and payload:
            hit = taint.match(payload, session_key=session_key, now=now)
            matched_shingles = hit.shingles
            covered = hit.covered_chars
            if hit.matched:
                fired.append(TRIGGER_A)
                reasons.append(
                    "A: private shingles in the outbound payload "
                    f"(distinct={hit.distinct}, covered={hit.covered_chars})"
                )
        if sink == SINK_DELIVER and any(
            _destination_seen(destination, untrusted, exempt)
            for destination in destination_tuple
        ):
            fired.append(TRIGGER_B)
            reasons.append("B: deliver destination first seen in untrusted content")

    ordered = tuple(trigger for trigger in TRIGGER_ORDER if trigger in fired)
    if not ordered:
        return Escalation(
            trigger=TRIGGER_NONE,
            tier=tier,
            reason=taint_reason(sink, exempt, destination_tuple),
            would_be=WOULD_BE_NONE,
            session_key=session_key,
            tool=tool,
            ts_seq=ts_seq,
            destinations=destination_tuple,
            resolved_by=sink,
        )
    return Escalation(
        trigger=ordered[0],
        tier=tier,
        reason="; ".join(reasons),
        would_be=WOULD_BE_SUSPEND,
        session_key=session_key,
        tool=tool,
        ts_seq=ts_seq,
        triggers=ordered,
        matched_shingles=matched_shingles,
        covered_chars=covered,
        destinations=destination_tuple,
        resolved_by=sink,
    )


def taint_reason(
    sink: str, exempt: frozenset[str], destinations: tuple[str, ...]
) -> str:
    """Explain why no R12 trigger fired for a call.

    Requirement: Taint Escalation.

    Args:
        sink: Sink kind of the evaluated call.
        exempt: Destinations exempted from trigger B.
        destinations: Destinations of the call.

    Returns:
        str: A short machine-readable explanation.
    """
    if not sink:
        return "no sink label: no outbound content to escalate"
    if sink == SINK_READ:
        return "sink_read: no private shingle in URL/query and no secret pattern"
    if destinations and all(destination in exempt for destination in destinations):
        return "sink_deliver: destination exempt (user message or allowlist)"
    return "sink_deliver: destination not present in untrusted content"


@dataclass(slots=True)
class EscalationLog:
    """Bounded in-memory log of escalation verdicts for status views.

    Requirement: Taint Escalation.

    Args:
        capacity: Maximum retained verdicts (default 64).
    """

    capacity: int = 64
    _items: list[Escalation] = field(default_factory=list)

    def record(self, verdict: Escalation) -> None:
        """Append a verdict, dropping the oldest when the log is full.

        Requirement: Taint Escalation.
        """
        self._items.append(verdict)
        if len(self._items) > self.capacity:
            del self._items[: len(self._items) - self.capacity]

    def snapshot(self) -> tuple[Escalation, ...]:
        """Return the retained verdicts, oldest first.

        Requirement: Taint Escalation.
        """
        return tuple(self._items)

    def clear(self) -> None:
        """Drop every retained verdict."""
        self._items.clear()
