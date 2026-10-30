
import pathlib as _pathlib, sys as _sys
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
from _bootstrap import fixture_config  # noqa: E402,F401  (puts the repo root on sys.path)
"""0.6.3 gate: the deep layer is reachable, and the approval panel sees the call."""
import asyncio
import json
import sys
import types

from tooling_guard.main import Gateway, _Plan
from tooling_guard.triage.decisions import Decision
from tooling_guard.core.verdict import ReviewOutcome
from tooling_guard.web import queries as q
from tooling_guard.notify.messages import TIER_LABELS, VERB_LABELS

FAILS = []
COUNT = [0]


def check(name, got, want):
    COUNT[0] += 1
    if got != want:
        FAILS.append("%s: got %r want %r" % (name, got, want))


# ---- A) the deep client is built lazily and cached ----
class FakeClient:
    def __init__(self):
        self.calls = []

    async def review(self, prompt, *, timeout_s, system_prompt=None, response_format=None):
        self.calls.append((prompt, timeout_s, system_prompt is not None, response_format is not None))
        return '{"score": 12, "noul": false, "confidence": 0.9}'


host = types.SimpleNamespace(_deep_client=None)
built = []


def build():
    COUNT[0] += 1
    built.append(1)
    return FakeClient()


host._build_deep_client = build
host._deep_review_client = lambda: Gateway._deep_review_client(host)
first = host._deep_review_client()
second = host._deep_review_client()
check("builds once", len(built), 1)
check("returns same client", first is second, True)
host._deep_judge_callable = lambda budget_s: Gateway._deep_judge_callable(host, budget_s)
judge = host._deep_judge_callable(5.0)
check("judge callable exists", callable(judge), True)

verdict = asyncio.run(judge({"tool": "astrbot_execute_shell"}))
check("deep answer is a banded verdict", type(verdict).__name__, "FastVerdict")
check("deep answer score", verdict.score_pct, 12)
sent = first.calls[0]
check("deep got a system prompt", sent[2], True)
check("deep got a response format", sent[3], True)
check("deep prompt is the state json", sent[0], json.dumps({"tool": "astrbot_execute_shell"}, ensure_ascii=False))
check("deep timeout is the budget", sent[1], 5.0)


# ---- B) no client still means no deep opinion (but a skip, not a denial) ----
dark = types.SimpleNamespace(_deep_client=None, _build_deep_client=lambda: None)
dark._deep_review_client = lambda: Gateway._deep_review_client(dark)
dark._deep_judge_callable = lambda budget_s: Gateway._deep_judge_callable(dark, budget_s)
check("no client means no judge", dark._deep_judge_callable(5.0), None)
check("no client is cached as None", dark._deep_review_client(), None)


# ---- C) the approval panel reads the arguments it stores ----
class Gate:
    pass


summary = {
    "verb": "exec",
    "tier": "T-strong",
    "args_head": '{"command": "Get-Date -Format o"}',
    "targets": ["C:/temp"],
    "rule_hits": ["R8"],
    "labels": ["sink_deliver"],
    "review": {"jev_fast": {"outcome": "skip", "decision": "allow_passthrough", "score": 28}},
}
row = {"summary_json": json.dumps(summary, ensure_ascii=False), "decision": "suspended", "would_be": None, "judge_route": "jev"}
ctx = q.serialize_call_context(Gate(), row)
check("arguments come from args_head", ctx["arguments"], '{"command": "Get-Date -Format o"}')
check("verb is readable", ctx["verb"], VERB_LABELS["exec"])
check("tier is readable", ctx["tier"], TIER_LABELS["T-strong"])
check("targets kept", ctx["targets"], ["C:/temp"])
check("rule hits kept", ctx["rule_hits"], ["R8"])
check("labels kept", ctx["labels"], ["sink_deliver"])
check("review kept", "jev_fast" in ctx["review"], True)
check("decision echoed", ctx["decision"], "suspended")
check("no summary still means no context", q.serialize_call_context(Gate(), {"summary_json": None}), None)
check("unknown verb is echoed", q._label(VERB_LABELS, "teleport"), "teleport")
check("absent verb is absent", q._label(VERB_LABELS, None), None)


# ---- D) the stored record carries verb and tier ----
rec_host = types.SimpleNamespace(
    _peek_sequence=lambda session: 7,
    _redact=lambda text: text,
    _redact_audited=lambda text: text,
)
rec_host._summary_line = lambda tool, args: Gateway._summary_line(rec_host, tool, args)
rec_host._targets_of = lambda tool, args: Gateway._targets_of(rec_host, tool, args)
plan = _Plan(decision=Decision.SUSPENDED, reason="x", labels=("sink_deliver",), call_id="abc")
record = Gateway._call_summary(
    rec_host,
    plan,
    tool="astrbot_execute_shell",
    subject="webchat:dsh_probe",
    session="webchat:FriendMessage:x",
    args={"command": "Get-Date -Format o"},
    digest_value="d",
    ticket_id="t",
    at="2026-10-30T18:27:45.119Z",
)
check("record verb", record.verb, "exec")
check("record tier", record.tier, "T-strong")
check("record keeps args head", "Get-Date" in record.args_head, True)
check("record labels", tuple(record.labels), ("sink_deliver",))
check("record rule hits empty", record.rule_hits, ())

print("%d checks, %d failed" % (COUNT[0], len(FAILS)))
for line in FAILS:
    print("FAIL " + line)
print("ALL CHECKS PASSED" if not FAILS else "CHECKS FAILED")
sys.exit(1 if FAILS else 0)
