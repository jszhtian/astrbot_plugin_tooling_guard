"""Answer parsing for the two fast-judge protocols.

Requirement: Fail-Closed Triage; Fast Judge Budget.

Both parsers return a `jev.score.FastVerdict` and nothing else: this module
never decides. Banding belongs to `jev.score.decide` alone, so a change of
thresholds or of the band count can never disagree with a second copy of the
mapping living here.

Two protocols arrive. `parse_jev_answer` reads the native one, where the
endpoint answers a risk score on the scale of the five bands plus a yes/no deep
question. That score is in criteria-index space (a real endpoint answered 3.72),
so it is normalized here through `normalize_score` before any band is applied.
`parse_llm_answer` reads an OpenAI-compatible chat answer whose content must be
one JSON object carrying a `score` on the 0..100 scale and a `noul` flag. The
number is read in every shape a model actually writes it -- `72`, `72.0`,
`"72"` -- because a reviewer that states the right number as a float has still
answered; the flag is read through `_flag`, and an absent or unusable flag
defaults to false rather than voiding the score it arrived with.

Three answers travel: `score`, `noul` and `confidence`. The third one is
optional by design. It is read from `answers.risk.confidence` on the native
protocol and from the object's `confidence` on the chat protocol, and a
missing, boolean, string or out-of-range value is reported as
`FastVerdict.confidence = None` with `NOTE_CONFIDENCE_MISSING` as the
evidence. It never becomes `NOTE_UNREADABLE` and never touches the score or the
flag: an endpoint that does not speak the field keeps being judged on the two
answers it does speak. Only the floor in `jev.score` decides what a low
confidence costs, and that decision belongs there, not here.

Every unreadable shape collapses to `FastVerdict(score_pct=None, noul=None)`,
which `decide` treats as an abstention and the engine denies. A legacy endpoint
answering only a choice word is reported as such through
`LEGACY_CHOICE_NOTE`, so the audit row says why nothing was banded instead of
claiming the answer was garbage.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Final

from ..prompts.systemone import DEEP_KEY, RISK_CRITERIA, RISK_KEY
from .score import (
    LEGACY_CHOICE_NOTE,
    NOTE_CONFIDENCE_MISSING,
    FastVerdict,
    band_of,
    normalize_confidence,
    normalize_score,
)

NOTE_UNREADABLE: Final[str] = "answer_unreadable"
"""Note recorded when the answer carried no usable score or no usable flag."""

_TRUE_WORDS: Final[frozenset[str]] = frozenset({"yes", "true", "y", "1"})
_FALSE_WORDS: Final[frozenset[str]] = frozenset({"no", "false", "n", "0"})
_SCORE_KEYS: Final[tuple[str, ...]] = ("score", "value")
_FLAG_KEYS: Final[tuple[str, ...]] = ("noul", "value", "choice", "probability")
_CHOICE_KEY: Final[str] = "choice"
_CONFIDENCE_KEY: Final[str] = "confidence"


def _mapping(value: Any) -> Mapping[str, Any] | None:
    """Return the value as a mapping, or None when it is not one."""
    return value if isinstance(value, Mapping) else None


def _unreadable(raw: Any = None) -> FastVerdict:
    """Return the verdict of an answer nothing usable was read from."""
    return FastVerdict(score_pct=None, noul=None, raw_score=raw, note=NOTE_UNREADABLE)


def _raw_score(value: Any) -> Any:
    """Read a raw score out of one answer in any tolerated shape.

    A score question may answer `{"score": n}`, `{"value": n}` or a bare
    number. A boolean is never a score, and a string is not coerced: guessing
    what "high" means would invent a band the endpoint never stated.
    """
    answered = _mapping(value)
    if answered is not None:
        for name in _SCORE_KEYS:
            if name in answered:
                return answered[name]
        return None
    if isinstance(value, bool):
        return None
    return value if isinstance(value, (int, float)) else None


def _probability(value: Any) -> bool | None:
    """Read one 0..1 probability as a yes/no answer, or None when it is not one.

    The deployed jev endpoint answers a noul question with the probability of a
    yes -- `{"type": "noul", "noul": 0.4615}` -- rather than a boolean, so a
    numeric answer has to be read as one. The threshold is the fixed 0.5 the
    `probability` key already used, and it is not configurable: an answer that
    is a coin flip must not be tunable into a release.

    A value outside 0..1 is not a probability and returns None -- NaN included,
    because it fails the range test -- and the caller reads None as an
    unreadable flag: an abstention that denies, never a release.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not 0.0 <= number <= 1.0:
        return None
    return number >= 0.5


def _flag(value: Any) -> bool | None:
    """Read a yes/no answer out of one answer in any tolerated shape.

    Accepted: a bare boolean, a bare number in 0..1 read as a probability (the
    shape the endpoint actually answers a noul question with), `{"noul": <any
    of those>}`, `{"value": ...}`, `{"choice": "yes"|"no"|"true"|"false"}`,
    and `{"probability": p}` with `p >= 0.5` counting as true -- the
    threshold is fixed here rather than configurable, because an answer that is
    a coin flip must not be tunable into a release.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        word = value.strip().lower()
        if word in _TRUE_WORDS:
            return True
        if word in _FALSE_WORDS:
            return False
        return None
    if isinstance(value, (int, float)):
        return _probability(value)
    answered = _mapping(value)
    if answered is None:
        return None
    for name in _FLAG_KEYS:
        if name not in answered:
            continue
        item = answered[name]
        if name == "probability":
            return _probability(item)
        return _flag(item)
    return None


def _confidence(value: Any) -> float | None:
    """Read the endpoint's own confidence out of one answer, or None.

    Only a mapping's `confidence` key is read: a bare number says nothing about
    what it is confident *about*, and guessing would invent a floor the endpoint
    never reported. A value outside 0..1 is not clamped -- see
    `normalize_confidence` -- because it means the endpoint is not speaking
    this protocol, and reading 1.4 as certainty would switch the floor off.

    None is the answer for every unusable shape, and the caller must tell it
    apart from a low confidence: confidence is an optional extra answer, so its
    absence is evidence, not an unreadable answer.
    """
    answered = _mapping(value)
    if answered is None:
        return None
    return normalize_confidence(answered.get(_CONFIDENCE_KEY))


def _choice_word(node: Any, depth: int = 2) -> str | None:
    """Return the legacy choice word carried anywhere in an answer tree."""
    answered = _mapping(node)
    if answered is None:
        return None
    word = answered.get(_CHOICE_KEY)
    if isinstance(word, str):
        return word
    if depth <= 0:
        return None
    for value in answered.values():
        found = _choice_word(value, depth - 1)
        if found is not None:
            return found
    return None


def parse_jev_answer(response: Any) -> FastVerdict:
    """Read one native jev answer as a verdict.

    Requirement: Fail-Closed Triage. The risk answer is normalized on the scale
    of `RISK_CRITERIA`; the deep answer is read as a yes/no flag, and the risk
    answer's own `confidence` is read as a 0..1 number when it carries one. A
    response carrying a legacy choice word but no usable score is an abstention
    and is marked as legacy, so an operator sees a protocol mismatch rather than
    a parse error.

    Args:
        response: The decoded JSON body of the jev response.

    Returns:
        FastVerdict: The normalized score, the flag, the confidence (None when
        the answer carried none, with `NOTE_CONFIDENCE_MISSING`) and the
        diagnostics. An unusable answer carries `score_pct=None`, which always
        denies.
    """
    answered = _mapping(response)
    answers = _mapping(answered.get("answers")) if answered is not None else None
    if answers is None:
        return _unreadable()
    raw = _raw_score(answers.get(RISK_KEY))
    if raw is None:
        if _choice_word(answers) is not None:
            return FastVerdict(score_pct=None, noul=None, note=LEGACY_CHOICE_NOTE)
        return _unreadable()
    score_pct = normalize_score(raw, len(RISK_CRITERIA))
    if score_pct is None:
        return _unreadable(raw)
    confidence = _confidence(answers.get(RISK_KEY))
    return FastVerdict(
        score_pct=score_pct,
        noul=_flag(answers.get(DEEP_KEY)),
        raw_score=raw,
        band=band_of(raw, RISK_CRITERIA),
        note="" if confidence is not None else NOTE_CONFIDENCE_MISSING,
        confidence=confidence,
    )


def _json_object(text: str) -> Mapping[str, Any] | None:
    """Return the first JSON object in the text, tolerating fences and noise."""
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text, index)
        except ValueError:
            continue
        found = _mapping(value)
        if found is not None:
            return found
    return None


def _content_of(response: Any) -> str | None:
    """Return the message text of a chat-completions response, or None."""
    answered = _mapping(response)
    if answered is None:
        return None
    choices = answered.get("choices")
    if isinstance(choices, (str, bytes)) or not isinstance(choices, Sequence):
        return None
    if not choices:
        return None
    first = _mapping(choices[0])
    if first is None:
        return None
    message = _mapping(first.get("message"))
    if message is None:
        return None
    content = message.get("content")
    return content if isinstance(content, str) else None


def _int_score(value: Any) -> int | None:
    """Read a 0..100 score out of one answer, tolerant of its numeric shape.

    A model that means 72 writes `72`, `72.0` or `"72"` depending on the day and
    the provider; all three are the same answer, so all three are read. A boolean
    is never a score, a value outside 0..100 is not one either, and a word is not
    guessed at -- that would invent a band the model never stated.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        try:
            value = float(value.strip())
        except (TypeError, ValueError):
            return None
    if not isinstance(value, (int, float)):
        return None
    try:
        number = round(float(value))
    except (OverflowError, ValueError):
        return None
    if number != number:
        return None
    return number if 0 <= number <= 100 else None


def parse_llm_answer(response: Any) -> FastVerdict:
    """Read one OpenAI-compatible chat answer as a verdict.

    Requirement: Fail-Closed Triage. The content must contain one JSON object
    with a readable `score` on the 0..100 scale; `score` may be an integer, a
    float or a numeric string (see `_int_score`), because those are one answer
    written three ways. `noul` is read through `_flag`, and when it is missing
    or unusable it becomes False instead of voiding the answer: the flag only
    escalates a call to the deep layer, so losing it costs one escalation, while
    discarding the score would throw away the verdict the model did deliver. A
    `confidence` is read when the object carries a usable one; its absence
    changes nothing but the note.

    A fenced block or surrounding prose is tolerated, because the parse looks
    for the first object that decodes, not for a prefix.

    Args:
        response: The decoded JSON body of the chat-completions response.

    Returns:
        FastVerdict: The score as a percentage, the flag, the confidence (None
        when absent, with `NOTE_CONFIDENCE_MISSING`) and the band text. An
        unusable answer carries `score_pct=None`, which always denies.
    """
    content = _content_of(response)
    if content is None:
        return _unreadable()
    answered = _json_object(content)
    if answered is None:
        return _unreadable()
    score = _int_score(answered.get("score"))
    if score is None:
        return _unreadable(answered.get("score"))
    noul = _flag(answered.get("noul"))
    if noul is None:
        noul = False
    confidence = _confidence(answered)
    index = score / 100 * (len(RISK_CRITERIA) - 1)
    return FastVerdict(
        score_pct=score,
        noul=noul,
        raw_score=score,
        band=band_of(index, RISK_CRITERIA),
        note="" if confidence is not None else NOTE_CONFIDENCE_MISSING,
        confidence=confidence,
    )


def parse_text_answer(text: Any) -> FastVerdict:
    """Read plain completion text as a verdict, through the same parser.

    Requirement: Layered Consensus. The deep client returns completion text,
    not a chat-completions body, because two of its routes produce text directly
    (an OpenAI endpoint and the host provider). Wrapping it back into the body
    shape rather than writing a second parser is deliberate: one parser means
    the fast and deep layers cannot disagree about what a valid answer is, and
    the tolerance for fences and surrounding prose comes for free.

    Args:
        text: The completion text of the deep route.

    Returns:
        FastVerdict: The parsed answer, or an unreadable verdict when the text
        holds no usable JSON object.
    """
    if not isinstance(text, str):
        return _unreadable()
    return parse_llm_answer({"choices": [{"message": {"content": text}}]})


__all__ = [
    "NOTE_UNREADABLE",
    "parse_jev_answer",
    "parse_llm_answer",
    "parse_text_answer",
]
