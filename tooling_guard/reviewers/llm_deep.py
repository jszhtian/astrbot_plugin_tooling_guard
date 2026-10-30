"""The slow-path adapter: a deeper review, order 30, asked for by the fast judge.

Requirement: Reviewer Contract; Trajectory Review; Layered Consensus.

This adapter no longer decides for itself whether a call is worth a slow
analysis. The orchestration runs three rounds -- static, then the fast judge,
then this one only when the fast judge asked for it (JudgeStage.force_deep) --
so the only question left here is "what does the slow judge say". Two gates stay:

0. a whitelisted call spends nothing: the policy layer already released it as
   LAYER_WHITELIST, and a request cannot improve on the operator's own decision
   (_common.skips_model_review);
1. a call the static layer denied outright spends nothing either: judge_stage
   sees PolicyDecision.DENY and returns SKIP_POLICY_DECIDED without a request.
   The verdict only has to stay neutral in that case, which SKIP is.

Where the pre-screen used to live, the orchestrator now lives instead: it reads
DETAIL_FORCE_DEEP off the fast judge verdict. Moving the decision out is what
makes the fast judge authoritative over cost -- a rule table here could only ever
guess at what the trajectory review was wanted for, and would silently skip the
calls the judge flagged on purpose.

The budget is injected, never hardcoded: this module owns no clock and invents
no default. A caller that wants a timeout wraps the judge with

budgeted; a caller that passes none gets whatever the transport already does.
An exception and an unreadable answer become an abstention (SKIP with
Verdict.degraded), not a denial: a slow judge that never answered is evidence
about the judge, not about the call, and must not hard-block anything. The
denial path is only reached when the judge actually says deny, and that verdict
then opens a ticket rather than hard-blocking -- the consensus rule turns any
model denial into an approval request.

approve=ReviewOutcome.ALLOW on purpose, and this is a change of mind: the slow
review is one of exactly two votes the models get, so "the deep review saw the
trajectory and found nothing" must count as a vote for the call. With SKIP it
would count as silence, and a fast judge that abstained plus a deep review that
approved would be recorded as "nobody decided" -- a ticket, not a release.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from ..core.call import GuardCall
from ..core.reviewer import BusyPolicy
from ..core.verdict import ReviewOutcome, Verdict
from ..triage.engine import Judge, judge_stage
from ._common import (
    SKIP_NO_MATCH,
    BuiltinReviewer,
    budgeted,
    features_of,
    judge_verdict,
    policy_of,
    rules_of,
    skip_verdict,
    skips_model_review,
    whitelist_skip_verdict,
)

#: Registry name of this reviewer.
NAME: Final[str] = "llm_deep"

#: Presentation order: last, after every cheap stage.
ORDER_LLM_DEEP: Final[int] = 30


class DeepReviewReviewer(BuiltinReviewer):
    """Run one slow analysis; the orchestrator decides when it is asked."""

    name = NAME
    order = ORDER_LLM_DEEP
    enabled = True
    busy_policy = BusyPolicy.SKIP

    def __init__(
        self,
        *,
        snapshot: Any,
        deep_judge: Judge | None = None,
        budget_s: float | None = None,
        trajectory_of: Callable[[GuardCall], Any] | None = None,
        deadline_of: Callable[[GuardCall], float | None] | None = None,
    ) -> None:
        """Bind the adapter to one snapshot, one judge and one injected budget.

        Args:
            snapshot: The immutable policy snapshot to judge against.
            deep_judge: Optional slow judge; without one this adapter always skips.
            budget_s: Optional per-request budget in seconds, injected by the
                caller. None means the judge is called with no local timeout;
                this module never substitutes a default of its own.
            trajectory_of: Optional reader of the read-only trajectory window.
            deadline_of: Optional reader of the caller budget.
        """
        super().__init__(
            snapshot=snapshot,
            trajectory_of=trajectory_of,
            deadline_of=deadline_of,
        )
        self._deep_judge = deep_judge
        self._budget_s = budget_s

    async def _answer(self, call: GuardCall) -> Verdict:
        """Answer from the slow path, gated only by the static layer."""
        features = features_of(self.snapshot, call)
        policy = policy_of(self.snapshot, features, call)
        if skips_model_review(policy):
            return whitelist_skip_verdict(self.name, policy)
        trajectory = self.trajectory(call)
        rules = rules_of(features, trajectory)
        judge = budgeted(self._deep_judge, self._budget_s)
        if judge is None:
            return skip_verdict(self.name, skipped=SKIP_NO_MATCH)
        stage = await judge_stage(
            judge,
            features=features,
            policy=policy,
            rules=rules,
            subject_key=call.subject_key,
            session_key=call.session_key,
            deadline=self.deadline(call),
            trajectory=trajectory,
        )
        return judge_verdict(
            stage,
            reviewer=self.name,
            observe=policy.observe,
            approve=ReviewOutcome.ALLOW,
        )


__all__ = [
    "NAME",
    "ORDER_LLM_DEEP",
    "DeepReviewReviewer",
]
