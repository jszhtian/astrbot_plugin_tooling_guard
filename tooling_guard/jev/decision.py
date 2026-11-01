"""Fast judges hosted by AstrBot instead of by a configured endpoint.

Requirement: Layered Consensus; Fast Judge Backends.

AstrBot 4.29.4 adds a Decision Provider that is separate from the chat model:
'Context.decision' is a 'DecisionService' answering structured questions
(astrbot/core/provider/decision.py), and astrbot/api/provider/__init__.py
re-exports the question and answer entities. That is a better home for the fast
judge than a hand-written HTTP call, because the operator configures the model
once in the host instead of pasting a second endpoint and key into the plugin.

Two judges live here and both answer exactly like 'jev.client.FastJudge': they
take the same structured state and return a 'jev.score.FastVerdict', so the
banding, the confidence floor and the deep trigger stay in 'jev.score' and are
never duplicated per source.

'DecisionJudge' asks the host Decision Provider the same two System One
questions the native jev endpoint answers -- one risk score over the five bands
and one yes/no deep flag -- because that is the contract 'jev.schema' already
reads. 'ProviderJudge' asks a host chat provider for the JSON object
'prompts.single_call' describes, i.e. the llm backend without an endpoint.

Nothing here decides: an unusable answer is returned as a verdict without a
score, which 'jev.score.decide' treats as an abstention.
"""

from __future__ import annotations

import asyncio
import math
from collections.abc import Mapping
from typing import Any, Final

from ..prompts.single_call import SYSTEM_PROMPT as LLM_SYSTEM_PROMPT
from ..prompts.state import state_json
from ..prompts.systemone import (
    DEEP_INSTRUCTIONS,
    DEEP_KEY,
    RISK_CRITERIA,
    RISK_INSTRUCTIONS,
    RISK_KEY,
    STATE_PREAMBLE,
)
from .client import configured_timeout
from .schema import NOTE_UNREADABLE, parse_text_answer
from .score import (
    NOTE_CONFIDENCE_MISSING,
    FastThresholds,
    FastVerdict,
    band_of,
    normalize_confidence,
    normalize_score,
)

FLAG_THRESHOLD: Final[float] = 0.5
"""Probability at or above which the deep question counts as a yes.

The native protocol reads a numeric answer the same way ('jev.schema'), so the
two sources cannot disagree about what "the judge wants a deep review" means.
"""


def _number(value: Any) -> float | None:
    """Return one finite answer number, or None for anything else."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _flag(answer: Any) -> bool | None:
    """Read one boolean answer as a flag, or None when no probability is usable."""
    probability = _number(getattr(answer, "probability", None))
    if probability is None:
        return None
    return probability >= FLAG_THRESHOLD


def verdict_from_decision_answers(answers: Any) -> FastVerdict:
    """Read one Decision Provider answer set as a fast verdict.

    Requirement: Layered Consensus. The mapping is keyed by the same two heads
    'prompts.systemone.build_systemone_questions' sends, so an answer set from
    the host and an answer body from a native jev endpoint carry identical
    meaning: 'risk' is a score over the five criteria and 'deep' is the yes/no
    flag.

    Args:
        answers: The mapping 'DecisionService.ask' returned.

    Returns:
        FastVerdict: The score as a percentage, the flag and the confidence. An
        unusable score returns a verdict without a score, which abstains rather
        than releases.
    """
    if not isinstance(answers, Mapping):
        return FastVerdict(score_pct=None, noul=None, note=NOTE_UNREADABLE)
    risk = answers.get(RISK_KEY)
    raw = _number(getattr(risk, "score", None))
    if raw is None:
        return FastVerdict(score_pct=None, noul=None, note=NOTE_UNREADABLE)
    score_pct = normalize_score(raw, len(RISK_CRITERIA))
    if score_pct is None:
        return FastVerdict(score_pct=None, noul=None, note=NOTE_UNREADABLE)
    confidence = normalize_confidence(getattr(risk, "confidence", None))
    return FastVerdict(
        score_pct=score_pct,
        noul=_flag(answers.get(DEEP_KEY)),
        raw_score=raw,
        band=band_of(raw, RISK_CRITERIA),
        note="" if confidence is not None else NOTE_CONFIDENCE_MISSING,
        confidence=confidence,
    )


def build_decision_questions() -> dict[str, Any]:
    """Build the two question heads the host Decision Provider is asked.

    Requirement: Layered Consensus. Imported lazily and not at module scope: the
    plugin must keep importing under a host older than 4.29.4, where
    astrbot.api.provider exports no decision entity, and the assembly layer is
    what reports the missing host support.

    Raises:
        ImportError: The host does not export the decision entities.
    """
    from astrbot.api.provider import (
        DecisionBooleanQuestion,
        DecisionScoreQuestion,
    )

    return {
        RISK_KEY: DecisionScoreQuestion(
            instructions=RISK_INSTRUCTIONS,
            criteria=list(RISK_CRITERIA),
        ),
        DEEP_KEY: DecisionBooleanQuestion(instructions=DEEP_INSTRUCTIONS),
    }


class DecisionJudge:
    """One fast judge served by the host Decision Provider.

    The callable contract matches 'jev.client.FastJudge': 'thresholds' is read
    by the triage engine, 'timeout_s' by the assembly layer, and the object
    answers one state at a time.
    """

    def __init__(
        self,
        context: Any,
        *,
        provider_id: str = "",
        timeout_s: Any = None,
        thresholds: FastThresholds | None = None,
    ) -> None:
        """Bind the host context, the optional provider id and the budget.

        Args:
            context: The plugin Context, i.e. the object carrying 'decision'.
            provider_id: A decision provider id; empty asks the host default.
            timeout_s: Budget of one request, clamped into the legal range.
            thresholds: The band thresholds, carried for the triage engine.
        """
        self.context = context
        self.provider_id = provider_id.strip() if isinstance(provider_id, str) else ""
        self.timeout_s = configured_timeout(timeout_s)
        self.thresholds = (
            thresholds if isinstance(thresholds, FastThresholds) else FastThresholds()
        )

    async def __call__(
        self, state: Mapping[str, Any], *, timeout_s: Any = None
    ) -> FastVerdict:
        """Ask the host Decision Provider about one state.

        Requirement: Fast Judge Budget; Fast Judge Backends. One request, one
        answer: the two questions travel together so a judgement never costs a
        second round trip, and the budget is the caller's, narrowed by the
        configured ceiling.

        Raises:
            TypeError: The Context exposes no DecisionService, which means the
                host is older than 4.29.4.
            asyncio.TimeoutError: The budget ran out; the triage engine folds
                that into an abstention.
            Exception: Any provider failure; the engine folds it into an
                abstention rather than a denial.
        """
        service = getattr(self.context, "decision", None)
        ask = getattr(service, "ask", None)
        if not callable(ask):
            raise TypeError(
                "astrbot decision provider unavailable: the Context passed to "
                "the plugin exposes no DecisionService (AstrBot 4.29.4 or newer "
                "is required for jev_source=astrbot)"
            )
        questions = build_decision_questions()
        payload = STATE_PREAMBLE + "\n" + state_json(dict(state))
        answers = await asyncio.wait_for(
            ask(questions, payload, provider_id=self.provider_id or None),
            timeout=_narrowed(self.timeout_s, timeout_s),
        )
        return verdict_from_decision_answers(answers)


class ProviderJudge:
    """One fast judge served by a host chat provider, i.e. the llm backend.

    The request is the same chat completion 'prompts.single_call' describes, sent
    through 'Context.llm_generate' instead of a configured endpoint, and the
    answer goes through 'jev.schema.parse_text_answer' -- the same parser the
    endpoint route uses, so the two llm routes cannot disagree about what a valid
    answer is.
    """

    def __init__(
        self,
        context: Any,
        *,
        provider_id: str = "",
        timeout_s: Any = None,
        thresholds: FastThresholds | None = None,
    ) -> None:
        """Bind the host context, the chat provider id and the budget."""
        self.context = context
        self.provider_id = provider_id.strip() if isinstance(provider_id, str) else ""
        self.timeout_s = configured_timeout(timeout_s)
        self.thresholds = (
            thresholds if isinstance(thresholds, FastThresholds) else FastThresholds()
        )

    async def __call__(
        self, state: Mapping[str, Any], *, timeout_s: Any = None
    ) -> FastVerdict:
        """Ask the host chat provider about one state and read its JSON answer.

        Raises:
            TypeError: The Context exposes no 'llm_generate'.
            Exception: The provider route failed; the engine folds it into an
                abstention rather than a denial.
        """
        from ..provider.llm import DeepReviewClient

        client = DeepReviewClient(
            {"llm_mode": "astrbot_provider", "llm_provider_id": self.provider_id},
            context=self.context,
        )
        text = await client.review(
            state_json(dict(state)),
            timeout_s=_narrowed(self.timeout_s, timeout_s),
            system_prompt=LLM_SYSTEM_PROMPT,
        )
        return parse_text_answer(text)


def _narrowed(ceiling: float, requested: Any) -> float:
    """Return the budget of one request: the caller's, never above the ceiling."""
    if isinstance(requested, bool) or not isinstance(requested, (int, float)):
        return ceiling
    number = float(requested)
    if not math.isfinite(number) or number <= 0:
        return ceiling
    return min(number, ceiling)


__all__ = [
    "FLAG_THRESHOLD",
    "DecisionJudge",
    "ProviderJudge",
    "build_decision_questions",
    "verdict_from_decision_answers",
]
