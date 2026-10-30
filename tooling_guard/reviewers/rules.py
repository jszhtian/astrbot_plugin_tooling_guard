"""The rule catalogue adapter: R1 to R11. Order 10.

Requirement: Reviewer Contract; Rule Catalog.

This adapter owns the *rules* stage and runs the same `rule_stage` the engine
folds, so rule ids, severities and the deny/suspend split cannot drift from
`TriageEngine.decide`. A deny-class hit answers DENY, a suspend-class hit
answers SUSPEND, and an observe-only hit (R8) or no hit at all answers SKIP: R8
is a shadow marker, not a reason to hold a call.

Every hit id travels in Verdict.detail so an audit row can reuse the rule ids
without re-running the catalogue, and the merged hit text becomes the reason.

The trajectory the engine saw is not part of GuardCall, so it arrives through
the injected `trajectory_of` reader; without one R7, R9 and R11 see no window
and stay silent, exactly as `evaluate_rules(features, None)` does.

No model is consulted here and review() awaits nothing inside, so the declared
busy policy is SKIP.
"""

from __future__ import annotations

from typing import Final

from ..core.call import GuardCall
from ..core.reviewer import BusyPolicy
from ..core.verdict import Verdict
from ._common import (
    BuiltinReviewer,
    features_of,
    observe_of,
    policy_of,
    publish_fold,
    rules_of,
    rules_verdict,
)

#: Registry name of this reviewer.
NAME: Final[str] = "rules"

#: Presentation order: after the cheap policy stage, before any model call.
ORDER_RULES: Final[int] = 10


class RulesReviewer(BuiltinReviewer):
    """Judge one call against the rule catalogue only."""

    name = NAME
    order = ORDER_RULES
    enabled = True
    busy_policy = BusyPolicy.SKIP

    async def _answer(self, call: GuardCall) -> Verdict:
        """Answer from the rule stage alone, publishing the folded outcome."""
        features = features_of(self.snapshot, call)
        stage = rules_of(features, self.trajectory(call))
        verdict = rules_verdict(
            stage, reviewer=self.name, observe=observe_of(self.snapshot, call)
        )
        return publish_fold(
            verdict,
            features=features,
            policy=policy_of(self.snapshot, features, call),
            rules=stage,
        )


__all__ = ["NAME", "ORDER_RULES", "RulesReviewer"]
