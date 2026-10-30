"""Score, noul and confidence: the fast judge's three answers, and the banding.

Requirement: Fail-Closed Triage. One fast-judge request now returns a risk
score, a noul flag and the endpoint's confidence in its own judgement, and this
module is the single place that turns that triple into a Decision:

- ``decide`` maps (score, noul, confidence, thresholds) onto ALLOW_FAST /
  SUSPENDED / DENY_JUDGE, or returns None when the answer is unusable -- an
  abstention the engine already denies with degraded judge_abstained;
- ``forces_deep`` reports the one case that must run the synchronous deep
  analysis before the call is released: the middle band with noul=true;
- ``normalize_confidence`` reads the third answer, and ``annotate_confidence``
  names what the floor did so the audit row can say it.

The bands are, with the shipped defaults 30 / 75:

- score < fast_allow_score  -> allow_fast (released outright);
- score >= fast_block_score -> deny_judge;
- middle, noul=true  -> allow_fast, but the plan carries force_deep so the
  gateway runs the deep analysis synchronously before releasing;
- middle, noul=false -> suspended (a ticket, a human decides);
- middle, noul missing -> None: unconfirmed, deny like an abstain.

The confidence floor (``fast_min_confidence``, default 0.6) rewrites exactly
two of those rows:

- a release (the low band) with confidence below the floor suspends instead;
- a denial (the high band) with confidence below the floor suspends instead.

The middle band is deliberately exempt. noul=true already buys a synchronous
deep analysis before the call is released, which is the second opinion a low
confidence would ask for, and noul=false already suspends. A missing or
unusable confidence (no field, a bool, a string, or a value outside 0..1)
never fires the floor: an endpoint that does not speak the field must keep
judging on score and noul alone, with NOTE_CONFIDENCE_MISSING as the evidence.

The price of rewriting the denial is stated where it is taken rather than
hidden: a call the judge scored as blocking (score >= fast_block_score) but was
unsure about no longer fails fast. It parks in the human queue as SUSPENDED, so
until an administrator decides -- or the wait window expires and the wait
becomes timeout_deny -- the call is neither released nor refused. That is the
deliberate trade: an unsure denial becomes an answerable one, at the cost of an
immediate refusal and one ticket plus one notification per unsure block.

No network, no clock and no store live here. The thresholds arrive as a
``FastThresholds`` value the caller built from the validated configuration,
so this module never reads a config mapping itself beyond ``from_config``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Final

from ..triage.decisions import Decision

#: Shipped default of ``fast_allow_score``: below it a call is released.
DEFAULT_FAST_ALLOW_SCORE: Final[int] = 30

#: Shipped default of ``fast_block_score``: at or above it a call is denied.
DEFAULT_FAST_BLOCK_SCORE: Final[int] = 75

#: Shipped default of ``fast_min_confidence``: a judged confidence strictly
#: below it turns a release and a denial into a wait for a human.
DEFAULT_FAST_MIN_CONFIDENCE: Final[float] = 0.6

#: The two fast-judge backends. Any other value is a fatal configuration
#: issue (tooling_guard/policy/config.py), so the client treats the closed
#: set as the only legal input.
BACKEND_JEV: Final[str] = "jev"
BACKEND_LLM: Final[str] = "llm"
FAST_JUDGE_BACKENDS: Final[frozenset[str]] = frozenset({BACKEND_JEV, BACKEND_LLM})

#: Note recorded on a FastVerdict when the endpoint answered the retired
#: choice protocol (a "choice" word, no score). The answer stays unusable --
#: unconfirmed denies -- but the degradation kind says why.
LEGACY_CHOICE_NOTE: Final[str] = "legacy_choice_answer"

#: Degradation kind recorded when the fast judge answered the retired choice
#: protocol: the abstain path still denies, the kind just names the cause so
#: an operator can tell a legacy endpoint from a broken one.
DEGRADED_JUDGE_LEGACY_CHOICE: Final[str] = "judge_abstained_legacy_choice"

#: Note recorded when the confidence floor is what turns this verdict's band
#: into a wait. Diagnostics only: ``decide`` reads the confidence value, never
#: the note, so a note can never change a band.
NOTE_LOW_CONFIDENCE: Final[str] = "confidence_below_floor"

#: Note recorded when the endpoint carried no usable confidence at all. It is
#: evidence, not a blocker: the verdict is still banded on score and noul.
NOTE_CONFIDENCE_MISSING: Final[str] = "confidence_missing"

#: Degradation kind recorded when the confidence floor produced the wait, so
#: an operator sees "the judge was unsure" instead of reading the row as a
#: plain judge suspension.
DEGRADED_FAST_LOW_CONFIDENCE: Final[str] = "fast_low_confidence"


def _config_int(config: Any, name: str, default: int) -> int:
    """Read one integer from a config mapping or object, or the default."""
    if isinstance(config, Mapping):
        value = config.get(name, default)
    else:
        value = getattr(config, name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return value


def _config_float(config: Any, name: str, default: float) -> float:
    """Read one probability from a config mapping or object, or the default.

    The value is normalized the same way an answer is, so a mistyped floor
    reads as the shipped default rather than as a floor nothing can trip.
    Configuration validation already rejects such a value as fatal; this is
    the defence in depth behind it, on the same footing as ``_config_int``.
    """
    if isinstance(config, Mapping):
        value = config.get(name, default)
    else:
        value = getattr(config, name, default)
    read = normalize_confidence(value)
    return default if read is None else read


def normalize_confidence(raw: Any) -> float | None:
    """Normalize one confidence answer to 0..1, or None when it is not one.

    A confidence is a number in 0..1. Anything else -- a bool (True is not
    1.0 here), a string, NaN, an infinity or a value outside the interval --
    is treated as "the endpoint did not answer" and returns None. Nothing is
    clamped on purpose: a 1.4 is not read as a certain 1.0, because a value
    outside the stated scale says the endpoint is not speaking this protocol,
    and reading it as certainty would switch off the very floor it was meant
    to trip. NaN fails the range comparison, which is also the intent.
    """
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    value = float(raw)
    if not 0.0 <= value <= 1.0:
        return None
    return value


@dataclass(frozen=True, slots=True)
class FastThresholds:
    """The two score bands and the confidence floor, as validated values.

    Attributes:
        allow_score: ``fast_allow_score``; a score strictly below it releases.
        block_score: ``fast_block_score``; a score at or above it denies.
        min_confidence: ``fast_min_confidence``; a confidence strictly below it
            turns the two outer bands into a wait. It is the third field and
            carries a default, so every existing two-argument construction
            keeps its meaning.
    """

    allow_score: int = DEFAULT_FAST_ALLOW_SCORE
    block_score: int = DEFAULT_FAST_BLOCK_SCORE
    min_confidence: float = DEFAULT_FAST_MIN_CONFIDENCE

    @classmethod
    def from_config(cls, config: Any) -> FastThresholds:
        """Build the thresholds from the validated gateway configuration.

        This is the only reader of the three config fields outside the
        validation pass itself, so "who reads the thresholds" has one
        answer. A missing or mistyped value falls back to the shipped
        default rather than to a permissive zero.
        """
        return cls(
            allow_score=_config_int(
                config, "fast_allow_score", DEFAULT_FAST_ALLOW_SCORE
            ),
            block_score=_config_int(
                config, "fast_block_score", DEFAULT_FAST_BLOCK_SCORE
            ),
            min_confidence=_config_float(
                config, "fast_min_confidence", DEFAULT_FAST_MIN_CONFIDENCE
            ),
        )


@dataclass(frozen=True, slots=True)
class FastVerdict:
    """What one fast-judge request answered, before any banding.

    Attributes:
        score_pct: The risk score normalized to 0..100, or None when the
            answer carried no usable score -- None always denies.
        noul: The deep-analysis recommendation, or None when the endpoint
            did not answer the question in any tolerated shape.
        raw_score: The score exactly as the endpoint returned it, kept for
            diagnostics; never enters the audit summary text.
        band: The criteria text of the rounded band, when the caller knew
            the criteria; diagnostics only.
        note: Diagnostic marker, e.g. LEGACY_CHOICE_NOTE, NOTE_UNREADABLE,
            NOTE_CONFIDENCE_MISSING or NOTE_LOW_CONFIDENCE.
        confidence: The endpoint's confidence in this judgement, normalized to
            0..1, or None when it carried none (see normalize_confidence).
            Appended last so every existing positional construction keeps its
            meaning. Like raw_score it is diagnostics: it never enters the
            audit summary text, only the band, the note and the degraded kind
            do.
    """

    score_pct: int | None
    noul: bool | None = None
    raw_score: Any = None
    band: str = ""
    note: str = ""
    confidence: float | None = None


def normalize_score(raw: Any, criteria_count: int) -> int | None:
    """Normalize a criteria-index-space score to 0..100, or None.

    The jev backend answers on the scale of the criteria it was given: a
    continuous value in 0..len(criteria)-1 (a real endpoint answered 3.72 on
    five bands). The percent is round(raw / (len(criteria) - 1) * 100),
    clamped to 0..100. A criteria list shorter than two bands has no scale,
    and a non-numeric answer is no answer: both return None, which the
    decision step treats as an abstention.
    """
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    if isinstance(criteria_count, bool) or not isinstance(criteria_count, int):
        return None
    if criteria_count < 2:
        return None
    pct = round(float(raw) / (criteria_count - 1) * 100)
    return max(0, min(100, pct))


def band_of(raw: Any, criteria: Sequence[str]) -> str:
    """Return the criteria text of the rounded band, or an empty string."""
    if not criteria:
        return ""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return ""
    index = max(0, min(len(criteria) - 1, round(float(raw))))
    return str(criteria[index])


#: Key carrying the fast judge's deep-analysis recommendation out of a verdict
#: detail. The reviewer publishes it and the gateway reads it to decide whether
#: the synchronous deep analysis must run before this call is delegated.
DETAIL_FORCE_DEEP: Final[str] = "force_deep"


def _confidence_floor(thresholds: FastThresholds) -> float | None:
    """Return the usable floor, or None when the configured one cannot gate.

    A mistyped ``min_confidence`` (a bool, a string, NaN, or a value outside
    0..1) must decide nothing and must not disable the inverted-thresholds
    guard either. Configuration validation already rejects such a value as
    fatal; here it simply reads as "no floor", which is the pre-existing
    behaviour without a confidence answer.
    """
    return normalize_confidence(thresholds.min_confidence)


def below_confidence_floor(verdict: FastVerdict, thresholds: FastThresholds) -> bool:
    """Return whether the answer's confidence sits below the configured floor.

    False when the endpoint carried no usable confidence: a missing answer
    never trips the floor (NOTE_CONFIDENCE_MISSING is the evidence), so an
    endpoint that does not speak the field keeps the score/noul bands exactly
    as they were. False too when the configured floor cannot gate -- see
    _confidence_floor -- because a broken floor is not a reason to change a
    judgement.
    """
    confidence = normalize_confidence(verdict.confidence)
    if confidence is None:
        return False
    floor = _confidence_floor(thresholds)
    if floor is None:
        return False
    return confidence < floor


def decide(verdict: FastVerdict, thresholds: FastThresholds) -> Decision | None:
    """Band one verdict. The single mapping from (score, confidence).

    Requirement: Layered Consensus. Only the two outer bands are decisions, and
    only when the answer was confident:

    - score >= block: DENY_JUDGE;
    - score <  allow: ALLOW_FAST.

    Everything else returns None, an abstention. The middle band abstains because
    that is exactly where the fast judge is least sure: the 0.6.1 fix. A score
    under the confidence floor abstains as well, and that is the 0.6.2 fix -- it
    used to return SUSPENDED, so a nervous low-scoring answer raised a ticket by
    itself and the deep layer never got to overrule it. A unanimous measured call
    still ends in front of a human either way (the deep layer's own abstention
    raises the all_abstain ticket), but now it is a human deciding with two
    opinions instead of one guess.

    The deep layer is asked whenever this stage abstains, so an abstention is a
    hand-off, not a silence. Before 0.6.1 the middle band voted: noul=true
    released the call (handing the consensus an approval vote that could carry
    it) and noul=false suspended it (raising a ticket without ever consulting the
    deep layer), so the fast judge alone decided every middle-band call and a
    mis-scored harmless command went straight to a human.

    Inverted thresholds are tested explicitly: allow 80 with block 70 would
    otherwise release a score of 65, because the block test fails and the allow
    test passes. The configuration layer rejects that pair as fatal; this guard
    is the defence in depth behind it.
    """
    score = verdict.score_pct
    if score is None:
        return None
    if thresholds.allow_score >= thresholds.block_score:
        return None
    if below_confidence_floor(verdict, thresholds):
        return None
    if score >= thresholds.block_score:
        return Decision.DENY_JUDGE
    if score < thresholds.allow_score:
        return Decision.ALLOW_FAST
    return None


def annotate_confidence(
    verdict: FastVerdict, thresholds: FastThresholds
) -> FastVerdict:
    """Return the verdict annotated with what its confidence did.

    Diagnostics only: decide reads ``FastVerdict.confidence`` itself and never
    ``FastVerdict.note``, so annotating here can never change a band. The note
    is the one place both markers are written from one source, and the engine
    turns NOTE_LOW_CONFIDENCE into the audit row's ``fast_low_confidence``
    degraded kind:

    - NOTE_CONFIDENCE_MISSING when the endpoint carried no usable confidence;
    - NOTE_LOW_CONFIDENCE when the floor is what turns this verdict's band into
      a wait -- the two outer bands only, because a middle-band verdict abstains
      on its own and a low confidence there is not a confidence wait;
    - the verdict unchanged when the score is unusable (it already carries
      NOTE_UNREADABLE or LEGACY_CHOICE_NOTE, and no confidence reached a band)
      or when the threshold pair is inverted (there is no band to rewrite).
    """
    score = verdict.score_pct
    if score is None:
        return verdict
    if thresholds.allow_score >= thresholds.block_score:
        return verdict
    confidence = normalize_confidence(verdict.confidence)
    if confidence is None:
        note = NOTE_CONFIDENCE_MISSING
    else:
        floor = _confidence_floor(thresholds)
        rewrites = score < thresholds.allow_score or score >= thresholds.block_score
        note = (
            NOTE_LOW_CONFIDENCE
            if floor is not None and confidence < floor and rewrites
            else ""
        )
    if not note or verdict.note == note:
        return verdict
    return replace(verdict, note=note)


def forces_deep(verdict: FastVerdict, thresholds: FastThresholds) -> bool:
    """Return whether this verdict explicitly asks for the deep analysis.

    noul is the fast judge's own request for a second opinion, so it is honoured
    wherever the score already produced a decision: a judge that releases a call
    but adds noul=true knows it was guessing, and the deep layer gets to look
    before the release stands. The middle band needs no flag -- it abstains in
    decide(), and an abstention always asks the deep layer.

    Anything unreadable returns False: forcing a deep request on a broken answer
    would spend budget on a call nothing was said about. Inverted thresholds
    return False for the same reason decide() abstains on them.
    """
    score = verdict.score_pct
    if score is None:
        return False
    if thresholds.allow_score >= thresholds.block_score:
        return False
    return verdict.noul is True


__all__ = [
    "BACKEND_JEV",
    "BACKEND_LLM",
    "DEFAULT_FAST_ALLOW_SCORE",
    "DEFAULT_FAST_BLOCK_SCORE",
    "DEFAULT_FAST_MIN_CONFIDENCE",
    "DEGRADED_FAST_LOW_CONFIDENCE",
    "DEGRADED_JUDGE_LEGACY_CHOICE",
    "DETAIL_FORCE_DEEP",
    "FAST_JUDGE_BACKENDS",
    "LEGACY_CHOICE_NOTE",
    "NOTE_CONFIDENCE_MISSING",
    "NOTE_LOW_CONFIDENCE",
    "FastThresholds",
    "FastVerdict",
    "annotate_confidence",
    "band_of",
    "below_confidence_floor",
    "decide",
    "forces_deep",
    "normalize_confidence",
    "normalize_score",
]
