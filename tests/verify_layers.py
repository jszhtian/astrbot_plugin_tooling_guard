"""Layer harness for the 0.6.0 three-layer consensus rewrite.

Asserts the seven-row truth table from the design spec, plus the two facts the
rewrite rests on: rules never gate the models any more, and every model failure
mode reads as an abstention instead of a denial.

Run with:  py -3 _verify/verify_layers.py   (from the package root)
"""
from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace

import pathlib as _pathlib, sys as _sys
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
from _bootstrap import fixture_config  # noqa: E402,F401  (puts the repo root on sys.path)

from tooling_guard.core.consensus import (
    TICKET_ALL_ABSTAIN,
    TICKET_MODEL_DENY,
    TICKET_MODEL_SUSPEND,
    consensus,
)
from tooling_guard.core.pipeline import PipelineOutcome
from tooling_guard.core.verdict import ReviewOutcome, Verdict, coerce_outcome
from tooling_guard.jev.score import FastThresholds, FastVerdict
from tooling_guard.main import _needs_deep
from tooling_guard.policy.layers import (
    LAYER_SENSITIVE_CONFIG,
    LAYER_STATIC_PASS,
    LAYER_WHITELIST,
    SOURCE_DENY,
    SOURCE_STATIC_PASS,
    SOURCE_WHITELIST,
    PolicyDecision,
    PolicyOutcome,
)
from tooling_guard.reviewers._common import (
    DETAIL_SKIPPED,
    SKIP_ABSTAINED,
    SKIP_WHITELISTED,
    judge_verdict,
    policy_verdict,
    whitelist_skip_verdict,
)
from tooling_guard.triage.decisions import Decision
from tooling_guard.triage.engine import (
    RulesStage,
    PolicyStage,
    judge_stage,
    SKIP_POLICY_DECIDED,
)

FAILURES: list[str] = []


def check(name: str, actual: object, expected: object) -> None:
    if actual != expected:
        FAILURES.append(f"{name}: expected {expected!r}, got {actual!r}")
        print(f"FAIL {name}: expected {expected!r}, got {actual!r}")
    else:
        print(f"ok   {name}")


def features(**overrides: object) -> SimpleNamespace:
    base = dict(
        tool_name="astrbot_execute_shell",
        verb="execute",
        targets=("D:/tmp/x",),
        tier="medium",
        labels=(),
        texts=("Get-ChildItem -Force",),
        origin=None,
        destinations=(),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def policy_stage(
    decision: PolicyDecision,
    *,
    expected: PolicyDecision | None = None,
    mode: str = "enforce",
    hints: tuple[str, ...] = (),
) -> PolicyStage:
    exp = decision if expected is None else expected
    layer = {
        PolicyDecision.ALLOW: LAYER_WHITELIST,
        PolicyDecision.DENY: LAYER_SENSITIVE_CONFIG,
        PolicyDecision.PASS: LAYER_STATIC_PASS,
    }[exp]
    source = {
        PolicyDecision.ALLOW: SOURCE_WHITELIST,
        PolicyDecision.DENY: SOURCE_DENY,
        PolicyDecision.PASS: SOURCE_STATIC_PASS,
    }[exp]
    outcome = PolicyOutcome(
        decision=decision,
        expected=exp,
        layer=layer,
        source=source,
        reason="harness",
        policy_version="harness/1",
        hints=hints,
    )
    return PolicyStage(outcome=outcome, mode=mode)


class Judge:
    """A judge callable carrying the band thresholds, like FastJudge does."""

    def __init__(self, result: object) -> None:
        self.result = result
        self.thresholds = FastThresholds(allow_score=30, block_score=70, min_confidence=0.0)
        self.seen: list[dict] = []

    async def __call__(self, payload: dict) -> object:
        self.seen.append(payload)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


ALLOW_ANSWER = FastVerdict(score_pct=5)
DENY_ANSWER = FastVerdict(score_pct=95)
FORCE_DEEP_ANSWER = FastVerdict(score_pct=50, noul=True)


def verdict(name: str, outcome: ReviewOutcome, detail: dict | None = None) -> Verdict:
    return Verdict(reviewer=name, outcome=outcome, detail=detail or {})


# --------------------------------------------------------------------------
# A. the seven-row truth table
# --------------------------------------------------------------------------
print("\n== A. truth table ==")

c = consensus([verdict("policy", ReviewOutcome.DENY)])
check("row1 static deny -> deny", (c.decision, c.ticket_kind), (Decision.DENY_RULE, None))
check("row1 static deny is static", c.static_denial, True)

c = consensus([verdict("policy", ReviewOutcome.ALLOW), verdict("jev_fast", ReviewOutcome.SKIP)])
check("row2 whitelist allow -> allow", (c.decision, c.ticket_kind), (Decision.ALLOW_PASSTHROUGH, None))

c = consensus([verdict("policy", ReviewOutcome.SKIP), verdict("jev_fast", ReviewOutcome.ALLOW)])
check("row3 jev allow -> allow", (c.decision, c.ticket_kind), (Decision.ALLOW_PASSTHROUGH, None))

c = consensus([verdict("policy", ReviewOutcome.SKIP), verdict("jev_fast", ReviewOutcome.DENY)])
check("row4 jev deny -> ticket model_deny", (c.decision, c.ticket_kind), (Decision.SUSPENDED, TICKET_MODEL_DENY))

c = consensus([
    verdict("policy", ReviewOutcome.SKIP),
    verdict("jev_fast", ReviewOutcome.SKIP),
    verdict("llm_deep", ReviewOutcome.ALLOW),
])
check("row5 deep allow -> allow", (c.decision, c.ticket_kind), (Decision.ALLOW_PASSTHROUGH, None))

c = consensus([
    verdict("policy", ReviewOutcome.SKIP),
    verdict("jev_fast", ReviewOutcome.SKIP),
    verdict("llm_deep", ReviewOutcome.DENY),
])
check("row6 deep deny -> ticket model_deny", (c.decision, c.ticket_kind), (Decision.SUSPENDED, TICKET_MODEL_DENY))

c = consensus([
    verdict("policy", ReviewOutcome.SKIP),
    verdict("jev_fast", ReviewOutcome.SKIP),
    verdict("llm_deep", ReviewOutcome.SKIP),
])
check("row7 all abstain -> ticket all_abstain", (c.decision, c.ticket_kind), (Decision.SUSPENDED, TICKET_ALL_ABSTAIN))

c = consensus([])
check("empty -> all_abstain", (c.decision, c.ticket_kind), (Decision.SUSPENDED, TICKET_ALL_ABSTAIN))

c = consensus([verdict("policy", ReviewOutcome.DENY), verdict("jev_fast", ReviewOutcome.ALLOW)])
check("static deny beats a model allow", (c.decision, c.ticket_kind, c.static_denial), (Decision.DENY_RULE, None, True))

c = consensus([verdict("policy", ReviewOutcome.SKIP), verdict("jev_fast", ReviewOutcome.SUSPEND)])
check("model suspend -> ticket model_suspend", (c.decision, c.ticket_kind), (Decision.SUSPENDED, TICKET_MODEL_SUSPEND))

c = consensus([verdict("policy", ReviewOutcome.SKIP), verdict("jev_fast", ReviewOutcome.ALLOW), verdict("llm_deep", ReviewOutcome.SKIP)])
check("one allow wins over another abstention", c.decision, Decision.ALLOW_PASSTHROUGH)

from tooling_guard.core.consensus import MODEL_REVIEWERS
from tooling_guard.reviewers.jev_fast import NAME as JEV_NAME
from tooling_guard.reviewers.llm_deep import NAME as DEEP_NAME

check("model reviewer names still match consensus", MODEL_REVIEWERS, frozenset({JEV_NAME, DEEP_NAME}))
c = consensus([verdict("policy", ReviewOutcome.SKIP), verdict(JEV_NAME, ReviewOutcome.DENY)])
check("a bare model deny is a ticket, not a refusal", (c.decision, c.ticket_kind), (Decision.SUSPENDED, TICKET_MODEL_DENY))


# --------------------------------------------------------------------------
# B. policy stage mapping
# --------------------------------------------------------------------------
print("\n== B. policy stage ==")

stage = policy_stage(PolicyDecision.DENY)
check("static deny -> policy verdict DENY", policy_verdict(stage, reviewer="policy").outcome, ReviewOutcome.DENY)

stage = policy_stage(PolicyDecision.ALLOW)
check("whitelist -> policy verdict ALLOW", policy_verdict(stage, reviewer="policy").outcome, ReviewOutcome.ALLOW)

stage = policy_stage(PolicyDecision.PASS)
check("static pass -> policy verdict SKIP (not an approval)", policy_verdict(stage, reviewer="policy").outcome, ReviewOutcome.SKIP)

hinted = policy_stage(PolicyDecision.PASS, hints=("reduce_latency", "reduce_trajectory_depth"))
check(
    "an allow-side hint is not an approval",
    policy_verdict(hinted, reviewer="base_check").outcome,
    ReviewOutcome.SKIP,
)

stage = policy_stage(PolicyDecision.PASS)
check(
    "whitelist skip word",
    whitelist_skip_verdict("jev_fast", stage).detail.get(DETAIL_SKIPPED),
    SKIP_WHITELISTED,
)


# --------------------------------------------------------------------------
# C. judge_stage: no rules gate, every failure abstains
# --------------------------------------------------------------------------
print("\n== C. judge stage ==")


def run_judge_stage(judge_result: object, *, policy_decision=PolicyDecision.PASS, rules=None):
    judge = Judge(judge_result)
    stage = policy_stage(policy_decision)
    result = asyncio.run(
        judge_stage(
            judge,
            features=features(),
            policy=stage,
            rules=rules if rules is not None else RulesStage(),
            subject_key="qq:1",
            session_key="qq:1",
        )
    )
    return judge, result


deny_hit = SimpleNamespace(rule_id="R3", action="deny", severity="high")
judge, result = run_judge_stage(ALLOW_ANSWER, rules=RulesStage(hits=(deny_hit,), merged=deny_hit))
check("a deny-class rule no longer gates the judge", result.consulted, True)
check("the judge actually ran", len(judge.seen), 1)

judge, result = run_judge_stage(ALLOW_ANSWER, policy_decision=PolicyDecision.DENY)
check("static deny skips the judge", (result.consulted, result.skipped), (False, SKIP_POLICY_DECIDED))

judge, result = run_judge_stage(RuntimeError("boom"))
check("judge exception abstains", result.answer, None)
check("judge exception degraded", str(result.degraded).startswith("judge_error:"), True)
check("judge exception keeps verdict a SKIP", judge_verdict(result, reviewer="jev_fast", observe=False).outcome, ReviewOutcome.SKIP)

judge, result = run_judge_stage(None)
check("judge None abstains", result.answer, None)
check("abstain verdict detail", judge_verdict(result, reviewer="jev_fast", observe=False).detail.get(DETAIL_SKIPPED), SKIP_ABSTAINED)

judge, result = run_judge_stage(FastVerdict(score_pct=None))
check("unreadable score abstains", result.answer, None)
check(
    "abstain is a SKIP outcome",
    coerce_outcome(judge_verdict(result, reviewer="jev_fast", observe=False).outcome),
    ReviewOutcome.SKIP,
)

judge, result = run_judge_stage(ALLOW_ANSWER)
check("low score allows", result.answer, Decision.ALLOW_FAST)
check("allow verdict", judge_verdict(result, reviewer="jev_fast", observe=False).outcome, ReviewOutcome.ALLOW)

judge, result = run_judge_stage(DENY_ANSWER)
check("high score denies", result.answer, Decision.DENY_JUDGE)
check("deny verdict", judge_verdict(result, reviewer="jev_fast", observe=False).outcome, ReviewOutcome.DENY)

judge, result = run_judge_stage(FORCE_DEEP_ANSWER)
check("middle band noul=true forces deep", result.force_deep, True)
check("middle band abstains instead of voting", result.answer, None)
check("middle band abstention is a skip", judge_verdict(result, reviewer="jev_fast", observe=False).outcome, ReviewOutcome.SKIP)

judge, result = run_judge_stage(ALLOW_ANSWER)
verdict_observe = judge_verdict(result, reviewer="jev_fast", observe=True)
check("observe rewrites a model allow", verdict_observe.decision, Decision.ALLOW_PASSTHROUGH)


# --------------------------------------------------------------------------
# D. orchestration: deep only when the fast layer asks or abstains
# --------------------------------------------------------------------------
print("\n== D. deep round gating ==")


def outcome(*verdicts: Verdict) -> PipelineOutcome:
    return PipelineOutcome(decision=consensus(verdicts).decision, verdicts=verdicts)


check("no fast verdict -> deep runs", _needs_deep(outcome(verdict("policy", ReviewOutcome.SKIP))), True)
check(
    "fast allow -> deep skipped",
    _needs_deep(outcome(verdict("policy", ReviewOutcome.SKIP), verdict("jev_fast", ReviewOutcome.ALLOW))),
    False,
)
check(
    "fast abstain -> deep runs",
    _needs_deep(outcome(verdict("policy", ReviewOutcome.SKIP), verdict("jev_fast", ReviewOutcome.SKIP))),
    True,
)
check(
    "fast deny -> deep skipped",
    _needs_deep(outcome(verdict("policy", ReviewOutcome.SKIP), verdict("jev_fast", ReviewOutcome.DENY))),
    False,
)
check(
    "fast force_deep -> deep runs",
    _needs_deep(outcome(verdict("policy", ReviewOutcome.SKIP), verdict("jev_fast", ReviewOutcome.ALLOW, {"force_deep": True}))),
    True,
)
check(
    "whitelist skip -> deep skipped",
    _needs_deep(outcome(verdict("policy", ReviewOutcome.ALLOW), verdict("jev_fast", ReviewOutcome.SKIP, {DETAIL_SKIPPED: SKIP_WHITELISTED}))),
    False,
)


# --------------------------------------------------------------------------
# E. timeouts abstain
# --------------------------------------------------------------------------
print("\n== E. timeout ==")
from tooling_guard.core.pipeline import ReviewPipeline

pipeline = ReviewPipeline.__new__(ReviewPipeline)
timeout = ReviewPipeline._timeout_verdict(pipeline, "llm_deep", 0.0)
check("a timed-out reviewer abstains", timeout.outcome, ReviewOutcome.SKIP)


print()
if FAILURES:
    print(f"{len(FAILURES)} FAILURE(S)")
    for line in FAILURES:
        print(" -", line)
    raise SystemExit(1)
print("ALL CHECKS PASSED")
