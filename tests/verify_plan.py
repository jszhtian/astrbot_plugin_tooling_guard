"""Harness for the gateway plan: consensus -> _Plan, including observe mode."""
from __future__ import annotations

import sys
from types import SimpleNamespace

import pathlib as _pathlib, sys as _sys
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
from _bootstrap import fixture_config  # noqa: E402,F401  (puts the repo root on sys.path)

from tooling_guard.core.consensus import TICKET_ALL_ABSTAIN, TICKET_MODEL_DENY
from tooling_guard.core.pipeline import PipelineOutcome
from tooling_guard.core.verdict import ReviewOutcome, Verdict
from tooling_guard.main import Gateway, _needs_deep
from tooling_guard.triage.decisions import Decision, WouldBe

FAILURES: list[str] = []


def check(name: str, actual: object, expected: object) -> None:
    if actual != expected:
        FAILURES.append(f"{name}: expected {expected!r}, got {actual!r}")
        print(f"FAIL {name}: expected {expected!r}, got {actual!r}")
    else:
        print(f"ok   {name}")


def gate(mode: str) -> SimpleNamespace:
    host = SimpleNamespace(
        mode=mode,
        _redact=lambda text: text,
        _judge_route_of=lambda verdicts: None,
    )
    host._review_report = lambda verdicts: Gateway._review_report(host, verdicts)
    host._review_order = lambda verdicts: Gateway._review_order(host, verdicts)
    host._observed_plan = lambda plan: Gateway._observed_plan(host, plan)
    host._ask_human_plan = lambda *, reason, degraded: Gateway._ask_human_plan(
        host, reason=reason, degraded=degraded
    )
    return host


def plan(mode: str, *verdicts: Verdict):
    from tooling_guard.core.consensus import consensus

    outcome = PipelineOutcome(decision=consensus(verdicts).decision, verdicts=verdicts)
    return Gateway._plan_from_pipeline(gate(mode), outcome)


static_pass = Verdict(reviewer="policy", outcome=ReviewOutcome.SKIP, decision=Decision.ALLOW_PASSTHROUGH)
fast_allow = Verdict(reviewer="jev_fast", outcome=ReviewOutcome.ALLOW, decision=Decision.ALLOW_FAST)
fast_deny = Verdict(reviewer="jev_fast", outcome=ReviewOutcome.DENY, decision=Decision.DENY_JUDGE)
fast_abstain = Verdict(reviewer="jev_fast", outcome=ReviewOutcome.SKIP)
deep_allow = Verdict(reviewer="llm_deep", outcome=ReviewOutcome.ALLOW, decision=Decision.ALLOW_TRAJECTORY)

print("== enforce ==")
p = plan("enforce", static_pass, fast_allow)
check("fast allow -> allow", (p.decision, p.ticket_kind), (Decision.ALLOW_PASSTHROUGH, None))

p = plan("enforce", static_pass, fast_deny)
check("fast deny -> suspended + model_deny", (p.decision, p.ticket_kind), (Decision.SUSPENDED, TICKET_MODEL_DENY))
check("fast deny keeps force_deep False", p.force_deep, False)

p = plan("enforce", static_pass, fast_abstain)
check("all abstain -> suspended + all_abstain", (p.decision, p.ticket_kind), (Decision.SUSPENDED, TICKET_ALL_ABSTAIN))

p = plan("enforce", static_pass, fast_abstain, deep_allow)
check("abstain then deep allow -> allow", (p.decision, p.ticket_kind), (Decision.ALLOW_PASSTHROUGH, None))

static_deny = Verdict(reviewer="policy", outcome=ReviewOutcome.DENY, decision=Decision.DENY_POLICY)
p = plan("enforce", static_deny, fast_allow)
check("static deny wins, no ticket", (p.decision, p.ticket_kind), (Decision.DENY_POLICY, None))

print("== observe ==")
p = plan("observe", static_pass, fast_deny)
check("observe: model deny is recorded, not waited", (p.decision, p.ticket_kind), (Decision.ALLOW_PASSTHROUGH, None))
check("observe: would_be suspend", p.would_be, WouldBe.SUSPEND.value)

p = plan("observe", static_pass, fast_abstain)
check("observe: abstain is recorded, not waited", (p.decision, p.ticket_kind), (Decision.ALLOW_PASSTHROUGH, None))
check("observe: abstain would_be suspend", p.would_be, WouldBe.SUSPEND.value)

p = plan("observe", static_deny, fast_allow)
check("observe: static deny recorded, not enforced", (p.decision, p.ticket_kind), (Decision.ALLOW_PASSTHROUGH, None))
check("observe: static deny would_be deny_policy", p.would_be, WouldBe.DENY_POLICY.value)

print("== unconcluded round (budget exhausted / round timeout / round error) ==")
q = Gateway._ask_human_plan(gate("enforce"), reason="预算耗尽", degraded="triage_timeout")
check("enforce: unconcluded asks a human instead of refusing", q.decision, Decision.SUSPENDED)
check("enforce: unconcluded ticket wording is all_abstain", q.ticket_kind, TICKET_ALL_ABSTAIN)
q = Gateway._ask_human_plan(gate("observe"), reason="预算耗尽", degraded="triage_timeout")
check("observe: unconcluded is only recorded", q.decision, Decision.ALLOW_PASSTHROUGH)
check("observe: unconcluded keeps would_be suspend", q.would_be, WouldBe.SUSPEND.value)
check("observe: unconcluded clears the ticket wording", q.ticket_kind, None)

print("== no-decision round keeps observe quiet too ==")
empty = PipelineOutcome(decision=Decision.DENY_POLICY)
q = Gateway._plan_from_pipeline(gate("enforce"), empty)
check("enforce: missing decision still refuses", q.decision, Decision.DENY_POLICY)
q = Gateway._plan_from_pipeline(gate("observe"), empty)
check("observe: missing decision is recorded", q.decision, Decision.ALLOW_PASSTHROUGH)
check("observe: missing decision would_be deny_policy", q.would_be, WouldBe.DENY_POLICY.value)

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILURE(S)")
    raise SystemExit(1)
print("ALL CHECKS PASSED")
