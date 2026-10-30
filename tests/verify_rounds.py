"""Harness for the two review rounds: who runs, and how rounds merge."""
from __future__ import annotations

import asyncio
import sys

import pathlib as _pathlib, sys as _sys
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
from _bootstrap import fixture_config  # noqa: E402,F401  (puts the repo root on sys.path)

from tooling_guard.core.call import build_call
from tooling_guard.core.consensus import TICKET_ALL_ABSTAIN, TICKET_MODEL_DENY, consensus
from tooling_guard.core.pipeline import ReviewPipeline, merge_outcomes
from tooling_guard.core.registry import ReviewerRegistry
from tooling_guard.core.reviewer import BusyPolicy
from tooling_guard.core.verdict import ReviewOutcome, Verdict
from tooling_guard.triage.decisions import Decision

FAILURES: list[str] = []


def check(name: str, actual: object, expected: object) -> None:
    if actual != expected:
        FAILURES.append(f"{name}: expected {expected!r}, got {actual!r}")
        print(f"FAIL {name}: expected {expected!r}, got {actual!r}")
    else:
        print(f"ok   {name}")


class Stub:
    """A reviewer that records its calls and answers a fixed verdict."""

    busy_policy = BusyPolicy.SKIP
    enabled = True

    def __init__(self, name: str, order: int, verdict: Verdict) -> None:
        self.name = name
        self.order = order
        self.verdict = verdict
        self.calls = 0

    async def review(self, call):
        self.calls += 1
        return self.verdict

    def status(self):
        return None


def verdict(reviewer: str, outcome: ReviewOutcome, decision: Decision) -> Verdict:
    return Verdict(reviewer=reviewer, outcome=outcome, decision=decision)


policy_skip = verdict("policy", ReviewOutcome.SKIP, Decision.ALLOW_PASSTHROUGH)
jev_allow = verdict("jev_fast", ReviewOutcome.ALLOW, Decision.ALLOW_FAST)
jev_deny = verdict("jev_fast", ReviewOutcome.DENY, Decision.DENY_JUDGE)
jev_abstain = verdict("jev_fast", ReviewOutcome.SKIP, Decision.ALLOW_PASSTHROUGH)
deep_allow = verdict("llm_deep", ReviewOutcome.ALLOW, Decision.ALLOW_TRAJECTORY)
deep_deny = verdict("llm_deep", ReviewOutcome.DENY, Decision.DENY_JUDGE)


def registry(jev: Verdict, deep: Verdict) -> tuple[ReviewerRegistry, dict[str, Stub]]:
    stubs = {
        "policy": Stub("policy", -10, policy_skip),
        "jev_fast": Stub("jev_fast", 20, jev),
        "llm_deep": Stub("llm_deep", 30, deep),
    }
    reg = ReviewerRegistry()
    for stub in stubs.values():
        reg.register(stub)
    return reg, stubs


async def main() -> None:
    call = build_call(tool_name="astrbot_execute_shell", arguments={"command": "ls"}, mode="enforce")

    print("== round 1 only reviews the static and fast layers ==")
    reg, stubs = registry(jev_allow, deep_deny)
    first = await ReviewPipeline(reg, budget_s=5.0, only=("policy", "jev_fast")).run(call)
    check("round 1 names", first.by_reviewer.keys(), {"policy", "jev_fast"})
    check("round 1 never starts deep", stubs["llm_deep"].calls, 0)
    check("round 1 allow", first.decision, Decision.ALLOW_PASSTHROUGH)

    print("== round 2 only reviews the deep layer ==")
    second = await ReviewPipeline(reg, budget_s=5.0, only=("llm_deep",)).run(call)
    check("round 2 names", second.by_reviewer.keys(), {"llm_deep"})
    check("round 2 starts deep once", stubs["llm_deep"].calls, 1)

    print("== a deny in the second round still needs a human ==")
    merged = merge_outcomes(first, second)
    check("deep deny -> suspended", merged.decision, Decision.SUSPENDED)
    check("deep deny ticket wording", consensus(merged.verdicts).ticket_kind, TICKET_MODEL_DENY)

    print("== no deep round (None) changes nothing ==")
    reg, stubs = registry(jev_allow, deep_allow)
    first = await ReviewPipeline(reg, budget_s=5.0, only=("policy", "jev_fast")).run(call)
    check("merged with None keeps the allow", merge_outcomes(first, None).decision, Decision.ALLOW_PASSTHROUGH)
    check("merged with None keeps first verdicts", merge_outcomes(None, first).verdicts, first.verdicts)

    print("== fast abstains, deep approves -> allowed ==")
    reg, stubs = registry(jev_abstain, deep_allow)
    first = await ReviewPipeline(reg, budget_s=5.0, only=("policy", "jev_fast")).run(call)
    second = await ReviewPipeline(reg, budget_s=5.0, only=("llm_deep",)).run(call)
    merged = merge_outcomes(first, second)
    check("abstain + deep allow -> allow", merged.decision, Decision.ALLOW_PASSTHROUGH)
    check("abstain + deep allow -> no ticket", consensus(merged.verdicts).ticket_kind, None)

    print("== both abstain -> one ticket asking about an unusual call ==")
    reg, stubs = registry(jev_abstain, verdict("llm_deep", ReviewOutcome.SKIP, Decision.ALLOW_PASSTHROUGH))
    first = await ReviewPipeline(reg, budget_s=5.0, only=("policy", "jev_fast")).run(call)
    second = await ReviewPipeline(reg, budget_s=5.0, only=("llm_deep",)).run(call)
    merged = merge_outcomes(first, second)
    check("both abstain -> suspended", merged.decision, Decision.SUSPENDED)
    check("both abstain ticket wording", consensus(merged.verdicts).ticket_kind, TICKET_ALL_ABSTAIN)

    print("== a static denial is never softened by a later round ==")
    policy_deny = Stub("policy", -10, verdict("policy", ReviewOutcome.DENY, Decision.DENY_POLICY))
    reg, stubs = registry(jev_allow, deep_allow)
    reg.replace(policy_deny)
    first = await ReviewPipeline(reg, budget_s=5.0, only=("policy", "jev_fast")).run(call)
    merged = merge_outcomes(first, None)
    check("static deny stays a refusal", merged.decision, Decision.DENY_POLICY)
    check("static deny asks nobody", consensus(merged.verdicts).ticket_kind, None)

    print("== only=() cannot silently release ==")
    reg, stubs = registry(jev_allow, deep_allow)
    empty = await ReviewPipeline(reg, budget_s=5.0, only=()).run(call)
    check("an empty selection refuses", empty.verdicts, ())
    check("an empty selection is a rule denial", empty.decision, Decision.DENY_RULE)


asyncio.run(main())

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILURE(S)")
    raise SystemExit(1)
print("ALL CHECKS PASSED")
