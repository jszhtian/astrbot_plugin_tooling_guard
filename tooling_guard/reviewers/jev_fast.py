"""The fast judge adapter: one question to jev, order 20.

Requirement: Reviewer Contract; Rules Before Models; Fail-Closed Triage.

Preconditions are this adapter's own business: the pipeline runs every reviewer
concurrently and hands nobody else answer across, so jev_fast recomputes the
pure policy and rule stages and asks the model only when those two stayed
undecided. In the decided case it does not merely skip -- it must not spend a
request at all: a wasted question burns quota and poisons the observation-mode
false-positive statistics with verdicts no rule or policy ever justified.

The whitelist is honoured before any of that: when the policy stage says the
call was decided by LAYER_WHITELIST -- the requester or every target matched the
configured whitelist -- no request is spent at all, in observe mode too. That is
the only static approval this design has, and it is the caller's own decision
written down in advance, so it needs no second opinion. Everything else the
static layer can say is DENY (decided above, never reaching this adapter) or PASS
(no opinion), and PASS does not skip the models (_common.skips_model_review).

Recomputation instead of sharing is deliberate. `policy_stage` and `rule_stage`
are pure in-memory matching with no IO, no clock and no store; caching them
across reviewers would introduce shared mutable state and make one reviewer
answer depend on another arrival time, which is a far worse trade than one extra
regex pass.

Every judge answer goes through the engine own `judge_stage`, so the skip
order, the payload shape, the vocabulary check and the degradation words
(judge_abstained, judge_abstained_legacy_choice, judge_error:<Type>,
judge_decision_unrecognized, and fast_low_confidence when the confidence floor is
what suspended the call) are literally the same code the synchronous path uses.
An unreadable, empty or raising answer denies: this adapter may only tighten a
call, never release one.

review() also publishes the fold of the three stages it just computed, judge
included, so the caller reports the engine's own fold text instead of folding
the pipeline verdicts a second time.

The judge's deep-analysis recommendation travels out with the verdict: the
engine sets JudgeStage.force_deep when the answer asked for one (noul=true), and
this adapter republishes it in Verdict.detail under
jev.score.DETAIL_FORCE_DEEP, where the gateway reads it to run the synchronous
deep analysis before the call is delegated. A rule decides that too: any hit in
FORCED_DEEP_RULES (R7, a sensitive read followed by an outbound call inside 30
seconds) forces the deep layer to speak whatever the fast judge answered, because
that sequence is the one shape a single call cannot show. The flag releases
nothing by itself -- a forced deep review can only tighten the call further.

The module name is historical. jev_fast was written when the only fast judge
was a native jev endpoint; the backend is now chosen by fast_judge_backend and
may be llm. The name stays on purpose: NAME is a word in audit rows and in the
degradation vocabulary, so renaming it would rewrite history operators already
filter and correlate on. Read "jev" here as "fast judge", not as the protocol.

No local clock lives here; the caller injects the deadline reader and, if it
wants a budget, a budgeted judge. Nothing is written to the store, the notifier
or the ticket table -- degradation travels through Verdict.degraded.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import Any, Final

from ..core.call import GuardCall
from ..core.reviewer import BusyPolicy
from ..core.verdict import Verdict
from ..jev.score import DETAIL_FORCE_DEEP
from ..triage.engine import Judge, RulesStage, judge_stage
from ..triage.rules import RULE_R7
from ._common import (
    BuiltinReviewer,
    features_of,
    judge_verdict,
    policy_of,
    publish_fold,
    rules_of,
    skips_model_review,
    whitelist_skip_verdict,
)

#: Registry name of this reviewer.
NAME: Final[str] = "jev_fast"

#: Presentation order: after the two rule-based stages.
ORDER_JEV_FAST: Final[int] = 20

#: Rule ids whose mere hit forces the deep layer to speak.
#:
#: R7 is a sequence rule: a sensitive read followed by an outbound-capable call
#: inside the window. No single call can show it, and the static layer treats it
#: as an observation rather than a refusal (the operator's hard-deny list is
#: about what one call does, not about what a session does). Handing that shape
#: to the deep model -- which sees the whole trajectory -- is the middle path:
#: nothing is refused automatically, but a human never learns about it from a
#: call the fast judge approved alone.
FORCED_DEEP_RULES: Final[frozenset[str]] = frozenset({RULE_R7})


def forces_deep_by_rule(rules: RulesStage) -> bool:
    """Return whether a rule hit alone is enough to summon the deep layer."""
    return any(rule_id in FORCED_DEEP_RULES for rule_id in rules.rule_ids)


class JevFastReviewer(BuiltinReviewer):
    """Ask the fast judge once, but only when the cheap stages stayed silent."""

    name = NAME
    order = ORDER_JEV_FAST
    enabled = True
    busy_policy = BusyPolicy.FAIL_CLOSED

    def __init__(
        self,
        *,
        snapshot: Any,
        judge: Judge | None = None,
        trajectory_of: Callable[[GuardCall], Any] | None = None,
        deadline_of: Callable[[GuardCall], float | None] | None = None,
    ) -> None:
        """Bind the adapter to one snapshot and one injected judge.

        Args:
            snapshot: The immutable policy snapshot to judge against.
            judge: Optional fast judge; without one this adapter always skips.
            trajectory_of: Optional reader of the call trajectory window.
            deadline_of: Optional reader of the caller budget, recorded in the
                judge payload and never enforced here.
        """
        super().__init__(
            snapshot=snapshot,
            trajectory_of=trajectory_of,
            deadline_of=deadline_of,
        )
        self._judge = judge

    async def _answer(self, call: GuardCall) -> Verdict:
        """Answer from the judge stage, gated by the policy and rule stages."""
        features = features_of(self.snapshot, call)
        policy = policy_of(self.snapshot, features, call)
        if skips_model_review(policy):
            return whitelist_skip_verdict(self.name, policy)
        trajectory = self.trajectory(call)
        rules = rules_of(features, trajectory)
        stage = await judge_stage(
            self._judge,
            features=features,
            policy=policy,
            rules=rules,
            subject_key=call.subject_key,
            session_key=call.session_key,
            deadline=self.deadline(call),
            trajectory=trajectory,
        )
        verdict = judge_verdict(stage, reviewer=self.name, observe=policy.observe)
        folded = publish_fold(
            verdict, features=features, policy=policy, rules=rules, judge=stage
        )
        if not (stage.force_deep or forces_deep_by_rule(rules)):
            return folded
        return replace(folded, detail={**dict(folded.detail), DETAIL_FORCE_DEEP: True})


__all__ = [
    "FORCED_DEEP_RULES",
    "NAME",
    "ORDER_JEV_FAST",
    "JevFastReviewer",
    "forces_deep_by_rule",
]
