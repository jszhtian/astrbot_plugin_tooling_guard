"""Verdict vocabulary and the allow < suspend < deny fold.

Requirement: Reviewer Contract; Verdict Aggregation.

The twelve `decision` words stay where they already live —
`tooling_guard/triage/decisions.py` — and this module imports them: `Decision`
is the only decision vocabulary in the repository and no thirteenth word is
invented here. What this module adds is

- `ReviewOutcome`, the four-state reviewer answer (skip / allow / deny /
  suspend) MR3 fixes as the reviewer's only output vocabulary;
- `Verdict`, the frozen record of one reviewer's answer about one call;
- the fold from an outcome onto a canonical `Decision` and the strictness rank
  the pipeline aggregates with.

Ranking single source of truth: production ranks decisions in
`tooling_guard/main.py` (`_DECISION_RANK`: allow 0 < suspend 1 < deny 2). That
module is the Gateway and imports AstrBot, so it must not be imported from here;
`RANK_ALLOW` / `RANK_SUSPEND` / `RANK_DENY` below are this package's copy of the
same three numbers and the two tables must move together. The rank is per
reviewer *outcome*, not per decision word: "deny > suspend > allow/skip" is the
rule MR5 aggregates with.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Final

from ..triage.decisions import Decision, coerce_decision


class ReviewOutcome(str, Enum):
    """What one reviewer answers about one call. Requirement: Reviewer Contract.

    Four states and no fifth: there is no "modify" and no "retry". `SKIP` means
    "this call is not mine to judge", which is not the same as "I approve it" —
    the distinction survives in `Verdict` and is folded by the pipeline, never by
    the reviewer.
    """

    SKIP = "skip"
    ALLOW = "allow"
    DENY = "deny"
    SUSPEND = "suspend"


#: Outcomes that let a call proceed. A release needs every participant here.
RELEASING_OUTCOMES: Final[frozenset[ReviewOutcome]] = frozenset(
    {ReviewOutcome.ALLOW, ReviewOutcome.SKIP}
)

#: Fold of one reviewer outcome onto the canonical decision vocabulary. SKIP maps
#: to the allow word only so one verdict always renders as one decision word; the
#: release rule below still requires allow *or* skip from every participant.
OUTCOME_DECISIONS: Final[Mapping[ReviewOutcome, Decision]] = MappingProxyType(
    {
        ReviewOutcome.SKIP: Decision.ALLOW_PASSTHROUGH,
        ReviewOutcome.ALLOW: Decision.ALLOW_PASSTHROUGH,
        ReviewOutcome.SUSPEND: Decision.SUSPENDED,
        ReviewOutcome.DENY: Decision.DENY_RULE,
    }
)

RANK_ALLOW: Final[int] = 0
RANK_SUSPEND: Final[int] = 1
RANK_DENY: Final[int] = 2

_OUTCOME_RANK: Final[Mapping[ReviewOutcome, int]] = MappingProxyType(
    {
        ReviewOutcome.SKIP: RANK_ALLOW,
        ReviewOutcome.ALLOW: RANK_ALLOW,
        ReviewOutcome.SUSPEND: RANK_SUSPEND,
        ReviewOutcome.DENY: RANK_DENY,
    }
)


def coerce_outcome(value: Any) -> ReviewOutcome | None:
    """Read one value as a reviewer outcome, strictly.

    Requirement: Reviewer Contract.

    Only the four exact lowercase words, or the enum members themselves, are
    accepted. `"ALLOW"`, `"Allow"`, `None`, `True` and every other value return
    `None` so the pipeline can fail closed instead of guessing at intent.

    Args:
        value: Whatever a reviewer produced.

    Returns:
        ReviewOutcome | None: The matching member, or None when nothing matches.
    """
    if isinstance(value, ReviewOutcome):
        return value
    if isinstance(value, str):
        for outcome in ReviewOutcome:
            if value == outcome.value:
                return outcome
    return None


def outcome_rank(outcome: Any) -> int:
    """Return the strictness rank of one outcome; unknown ranks as deny."""
    coerced = coerce_outcome(outcome)
    return RANK_DENY if coerced is None else _OUTCOME_RANK[coerced]


def stricter(current: ReviewOutcome, candidate: ReviewOutcome) -> ReviewOutcome:
    """Return whichever of two outcomes is stricter: deny > suspend > allow/skip."""
    return candidate if outcome_rank(candidate) > outcome_rank(current) else current


@dataclass(frozen=True, slots=True)
class Verdict:
    """One reviewer's answer about one call. Requirement: Verdict Aggregation.

    Attributes:
        reviewer: The reviewer's stable name, as registered.
        outcome: The four-state answer.
        decision: The canonical `Decision` this verdict renders as. Left as None
            by the reviewer to inherit `OUTCOME_DECISIONS.outcome`; a reviewer
            that knows its own denial flavour (a judge denial, a policy denial)
            sets it explicitly and the aggregation keeps it.
        reason: Why, for the audit row and the administrator notification. The
            pipeline sanitises and truncates before anything is written.
        degraded: Degradation marker text, e.g. `reviewer_busy:<name>`, or None.
        elapsed_s: How long the answer took, filled by the pipeline when the
            reviewer leaves it at 0.
        busy: True when this answer is a busy fold rather than a real judgement.
        detail: Structured, sanitise-able extras for `/guard status`.

    Raises:
        ValueError: `outcome` is not one of the four reviewer words. A reviewer
            that reaches this raise is recorded as a deny by the pipeline.
    """

    reviewer: str
    outcome: ReviewOutcome
    decision: Decision | None = None
    reason: str = ""
    degraded: str | None = None
    elapsed_s: float = 0.0
    busy: bool = False
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Normalise the outcome and decision fields, and freeze `detail`."""
        outcome = coerce_outcome(self.outcome)
        if outcome is None:
            raise ValueError(f"unusable reviewer outcome: {self.outcome!r}")
        object.__setattr__(self, "outcome", outcome)
        if self.decision is None:
            object.__setattr__(self, "decision", OUTCOME_DECISIONS[outcome])
        else:
            object.__setattr__(self, "decision", coerce_decision(self.decision))
        object.__setattr__(self, "detail", MappingProxyType(dict(self.detail)))

    @property
    def denies(self) -> bool:
        """Return whether this verdict is a denial."""
        return self.outcome is ReviewOutcome.DENY

    @property
    def suspends(self) -> bool:
        """Return whether this verdict asks for an administrator decision."""
        return self.outcome is ReviewOutcome.SUSPEND

    @property
    def releases(self) -> bool:
        """Return whether this verdict lets the call proceed (allow or skip)."""
        return self.outcome in RELEASING_OUTCOMES
