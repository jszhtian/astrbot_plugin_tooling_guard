"""Harness for the 0.6.1 changes: middle-band abstention, late-decision dedupe,
approval-panel context and delivery evidence.

Pure python, no host: every check builds the value it asserts on. Exit 0 only
when all checks pass.
"""

from __future__ import annotations

import json
import sys

import pathlib as _pathlib, sys as _sys
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
from _bootstrap import fixture_config  # noqa: E402,F401  (puts the repo root on sys.path)

from tooling_guard.jev.score import (
    FastThresholds,
    FastVerdict,
    decide,
    forces_deep,
)
from tooling_guard.triage.decisions import Decision
from tooling_guard.ui import commands as ui_commands
from tooling_guard.web import queries

FAILS: list[str] = []
CHECKS = 0


def check(label: str, condition: bool) -> None:
    global CHECKS
    CHECKS += 1
    if not condition:
        FAILS.append(label)


def verdict(score: int | None, *, confidence: float | None = 0.9, noul: bool | None = None) -> FastVerdict:
    return FastVerdict(
        score_pct=score,
        noul=noul,
        raw_score=score,
        band="test",
        note="",
        confidence=confidence,
    )


T = FastThresholds(allow_score=30, block_score=70, min_confidence=0.6)

# A. fast judge bands: only the two outer bands vote.
check("low score releases", decide(verdict(10, noul=False), T) is Decision.ALLOW_FAST)
check("high score denies", decide(verdict(85, noul=False), T) is Decision.DENY_JUDGE)
check("middle band abstains (noul false)", decide(verdict(50, noul=False), T) is None)
check("middle band abstains (noul true)", decide(verdict(50, noul=True), T) is None)
check("middle band abstains (noul missing)", decide(verdict(50), T) is None)
check("middle + low confidence abstains", decide(verdict(50, confidence=0.2), T) is None)
check("low score + low confidence abstains (0.6.2)", decide(verdict(10, confidence=0.2), T) is None)
check("high score + low confidence abstains (0.6.2)", decide(verdict(90, confidence=0.2), T) is None)
check("no score abstains", decide(verdict(None), T) is None)
check("inverted thresholds abstain", decide(verdict(65), FastThresholds(80, 70, 0.6)) is None)
check("noul asks for deep", forces_deep(verdict(50, noul=True), T) is True)
check("noul asks for deep in the low band too", forces_deep(verdict(10, noul=True), T) is True)
check("no noul does not ask", forces_deep(verdict(50, noul=False), T) is False)
check("abstention does not itself ask for deep", forces_deep(verdict(50), T) is False)

# B. late decisions are disclosed once per (ticket, verb).
ui_commands._late_seen.clear()
check("first late deny is disclosed", ui_commands._late_disclosure_due("tk-1", "deny") is True)
check("second late deny is folded", ui_commands._late_disclosure_due("tk-1", "deny") is False)
check("a different verb is its own disclosure", ui_commands._late_disclosure_due("tk-1", "approve") is True)
for index in range(ui_commands._LATE_SEEN_LIMIT * 3):
    ui_commands._late_disclosure_due("bulk-%d" % index, "deny")
check("late memory is bounded", len(ui_commands._late_seen) <= ui_commands._LATE_SEEN_LIMIT)
ui_commands._late_seen.clear()

# C. approval panel context.
SUMMARY = {
    "verb": "exec",
    "tier": "T-strong",
    # 0.6.3 maps the real record field (args_head) onto the wire key arguments.
    "args_head": '{"command": "Get-ChildItem C:"}',
    "targets": ["C:"],
    "rule_hits": ["R8"],
    "labels": [],
    "review": {
        "policy": {"outcome": "skip", "decision": "allow_passthrough", "reason": "static pass"},
        "jev_fast": {
            "outcome": "suspend",
            "decision": "suspended",
            "reason": "middle band",
            "score": 55,
            "confidence": 0.7,
            "note": "low_confidence",
        },
    },
}
ROW = {"decision": "suspended", "would_be": None, "judge_route": "jev", "summary_json": json.dumps(SUMMARY)}
context = queries.serialize_call_context(None, ROW)
check("context is built", isinstance(context, dict))
check("context renders the verb in chinese (0.6.3)", context["verb"] == "执行")
check("context renders the tier in chinese (0.6.3)", context["tier"] == "强")
check("context keeps the arguments", "Get-ChildItem" in context["arguments"])
check("context keeps targets", context["targets"] == ["C:"])
check("context keeps rule hits", context["rule_hits"] == ["R8"])
check("context reports the decision", context["decision"] == "suspended")
check("context reports the judge route", context["judge_route"] == "jev")
check("context carries both reviewers", sorted(context["review"]) == ["jev_fast", "policy"])
check("review keeps the score", context["review"]["jev_fast"]["score"] == 55)
check("review keeps the confidence", context["review"]["jev_fast"]["confidence"] == 0.7)
check("review keeps the note", context["review"]["jev_fast"]["note"] == "low_confidence")
check("review keeps the reason", context["review"]["jev_fast"]["reason"] == "middle band")
check("review drops absent fields", "score" not in context["review"]["policy"])
check("missing summary yields None", queries.serialize_call_context(None, {"summary_json": None}) is None)
check("broken summary yields None", queries.serialize_call_context(None, {"summary_json": "{"}) is None)
check("summary list yields None", queries.serialize_call_context(None, {"summary_json": "[1]"}) is None)

long_args = "x" * 4000
bounded = queries.serialize_call_context(
    None, {"summary_json": json.dumps({"args_head": long_args})}
)
check("arguments are bounded", len(bounded["arguments"]) <= queries.ARGS_HEAD_LIMIT)

# D. the panel reads the suspension row, not the decision row.
decision_row = {"decision": "deny_policy", "summary_json": json.dumps({"verb": "exec"})}
check("suspension row wins", queries.pick_ticket_event([decision_row, ROW]) is ROW)
check("falls back to a readable summary", queries.pick_ticket_event([{"decision": "x", "summary_json": None}, ROW]) is ROW)
check("falls back to the first row", queries.pick_ticket_event([{"summary_json": None}]) is not None)
check("no rows means no context", queries.pick_ticket_event([]) is None)

# E. the delivery evidence row exists and is wired.
from tooling_guard.notify.sender import delivery_attempts

check("attempts reader tolerates None", delivery_attempts(None) == ())
check("attempts reader tolerates junk", delivery_attempts(object()) == ())
from tooling_guard import main as gateway_main

check("notify_sent marker exists", gateway_main.NOTIFY_SENT == "notify_sent")
check("notify error prefix exists", gateway_main.NOTIFY_ERROR_PREFIX.startswith("notify_error"))
check("sent row writer exists", callable(getattr(gateway_main.Gateway, "_record_notify_sent", None)))
check("attempted reader exists", callable(getattr(gateway_main.Gateway, "_attempted", None)))

print("%d checks, %d failed" % (CHECKS, len(FAILS)))
for label in FAILS:
    print("FAIL:", label)
print("ALL CHECKS PASSED" if not FAILS else "CHECKS FAILED")
sys.exit(0 if not FAILS else 1)
