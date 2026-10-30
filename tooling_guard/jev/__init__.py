"""Fast judge request and response contracts.

Requirement: Fast Judge Budget. The package is the boundary of one model
question: `client` spends the one request, `schema` reads the answer, and
`score` owns the single mapping from (score, noul, confidence) to a decision.
"""

from .client import FastJudge, JevClient
from .schema import parse_jev_answer, parse_llm_answer
from .score import (
    BACKEND_JEV,
    BACKEND_LLM,
    DEFAULT_FAST_ALLOW_SCORE,
    DEFAULT_FAST_BLOCK_SCORE,
    DEFAULT_FAST_MIN_CONFIDENCE,
    DEGRADED_FAST_LOW_CONFIDENCE,
    DEGRADED_JUDGE_LEGACY_CHOICE,
    DETAIL_FORCE_DEEP,
    FAST_JUDGE_BACKENDS,
    LEGACY_CHOICE_NOTE,
    NOTE_CONFIDENCE_MISSING,
    NOTE_LOW_CONFIDENCE,
    FastThresholds,
    FastVerdict,
    annotate_confidence,
    band_of,
    below_confidence_floor,
    decide,
    forces_deep,
    normalize_confidence,
    normalize_score,
)

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
    "FastJudge",
    "FastThresholds",
    "FastVerdict",
    "JevClient",
    "annotate_confidence",
    "band_of",
    "below_confidence_floor",
    "decide",
    "forces_deep",
    "normalize_confidence",
    "normalize_score",
    "parse_jev_answer",
    "parse_llm_answer",
]
