"""Harness: trajectory history reaches both model layers (0.6.4).

Offline checks only; nothing here talks to a host, a model or a network.
"""

from __future__ import annotations

import asyncio
import sys
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pathlib as _pathlib, sys as _sys
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
from _bootstrap import fixture_config  # noqa: E402,F401  (puts the repo root on sys.path)

from tooling_guard.jev.schema import parse_text_answer
from tooling_guard.jev.score import FastVerdict
from tooling_guard.main import Gateway
from tooling_guard.policy.layers import PolicyDecision
from tooling_guard.prompts import deep_call, single_call, systemone
from tooling_guard.trace.recorder import TrajectoryRecorder
from tooling_guard.trace.summary import summarize_call
from tooling_guard.triage.classify import classify_call
from tooling_guard.triage.engine import (
    HISTORY_LIMIT,
    judge_payload,
    judge_stage,
    trajectory_history,
)
from tooling_guard.triage.rules import (
    RULE_R7,
    TrajectoryView,
    evaluate_rules,
)

CHECKS = 0
FAILED = 0


def check(name, actual, expected) -> None:
    global CHECKS, FAILED
    CHECKS += 1
    if actual != expected:
        FAILED += 1
        print(f"FAIL {name}: got {actual!r}, want {expected!r}")


def truthy(name, value) -> None:
    global CHECKS, FAILED
    CHECKS += 1
    if not value:
        FAILED += 1
        print(f"FAIL {name}: got {value!r}, want truthy")


def iso(offset_s: float) -> str:
    return (datetime.now(UTC) - timedelta(seconds=offset_s)).isoformat(timespec="milliseconds")


def host(**kwargs):
    gate = SimpleNamespace(**kwargs)
    gate._build_recorder = lambda: Gateway._build_recorder(gate)
    gate._trajectory = lambda session: Gateway._trajectory(gate, session)
    gate._trajectory_view = lambda session: Gateway._trajectory_view(gate, session)
    return gate


# --- A. the window is built by the gateway, not injected -------------------
recorder = Gateway._build_recorder(host(_config=SimpleNamespace(trajectory_retention_per_user=12)))
check("configured retention", recorder.keep, 12)
check(
    "missing retention falls back",
    Gateway._build_recorder(host(_config=SimpleNamespace())).keep,
    50,
)
check(
    "unusable retention falls back",
    Gateway._build_recorder(host(_config=SimpleNamespace(trajectory_retention_per_user="x"))).keep,
    50,
)
check(
    "zero retention falls back",
    Gateway._build_recorder(host(_config=SimpleNamespace(trajectory_retention_per_user=0))).keep,
    50,
)

real = TrajectoryRecorder(keep=8)
read = summarize_call(
    ts_seq=1,
    call_id="c1",
    tool="astrbot_file_read_tool",
    session="s",
    verb="read",
    targets=("/srv/app/.env",),
    summary_line="read .env",
    decision="allow_passthrough",
)
pop = summarize_call(
    ts_seq=2,
    call_id="c2",
    tool="astrbot_execute_shell",
    session="s",
    verb="exec",
    targets=("Get-ChildItem .",),
    summary_line="list",
    decision="suspended",
)
real.append(read)
real.append(pop)
gate = host(_recorder=real, _config=SimpleNamespace())
view = gate._trajectory_view("s")
truthy("view is a TrajectoryView", isinstance(view, TrajectoryView))
check("view keeps both entries", len(view.entries), 2)
check("view keeps the session", view.session_key, "s")
truthy("view carries wall clock", view.now > 1_000_000_000)
check("no window for unknown session", len(gate._trajectory_view("other").entries), 0)
check("no recorder means no view", host(_recorder=None)._trajectory_view("s"), None)

# --- B. the history text ---------------------------------------------------
text = trajectory_history(view)
truthy("history names the earlier read", "astrbot_file_read_tool read -> /srv/app/.env" in text)
truthy("history records the outcome", "(allow_passthrough)" in text)
truthy("history is oldest first", text.index("read ->") < text.index("exec ->"))
check("history is one line per call", len(text.splitlines()), 2)
check("history of no window", trajectory_history(None), "")
check("history of empty view", trajectory_history(TrajectoryView(entries=(), session_key="s", now=1.0)), "")

many = TrajectoryView(
    entries=tuple(
        summarize_call(ts_seq=i, call_id=f"c{i}", tool=f"tool{i}", session="s", verb="read")
        for i in range(12)
    ),
    session_key="s",
    now=time.time(),
)
long_text = trajectory_history(many)
check("history honours the limit", len(long_text.splitlines()), HISTORY_LIMIT)
truthy("history keeps the newest", long_text.splitlines()[-1].startswith("tool11"))
check(
    "history reads mappings too",
    trajectory_history(
        TrajectoryView(
            entries=({"tool": "t", "verb": "write", "targets": ["a"], "decision": "deny_rule"},),
            session_key="s",
            now=1.0,
        )
    ),
    "t write -> a (deny_rule)",
)

# --- C. the same state carries it to both layers ---------------------------
features = classify_call("send_message_to_user", {"text": "hi"})
payload = judge_payload(
    features=features,
    hits=(),
    mode="enforce",
    subject_key="asr:1",
    session_key="s",
    deadline=None,
    trajectory=view,
)
truthy("payload carries the history", "astrbot_file_read_tool" in payload.get("trajectory_summary", ""))
check(
    "payload without a window has no history",
    judge_payload(
        features=features,
        hits=(),
        mode="enforce",
        subject_key="asr:1",
        session_key="s",
        deadline=None,
    ).get("trajectory_summary", ""),
    "",
)


async def run_stage(trajectory):
    seen = {}

    async def judge(state):
        seen.update(state)
        return FastVerdict(score_pct=10, noul=False, raw_score=0, band="Low", note="")

    stage = await judge_stage(
        judge,
        features=features,
        policy=SimpleNamespace(expected=PolicyDecision.PASS, mode="enforce"),
        rules=SimpleNamespace(hits=(), merged=None),
        subject_key="asr:1",
        session_key="s",
        trajectory=trajectory,
    )
    return seen, stage


seen, stage = asyncio.run(run_stage(view))
truthy("fast layer sees the history", "astrbot_file_read_tool" in seen.get("trajectory_summary", ""))
truthy("fast layer still answers", stage.answer is not None)
seen2, _ = asyncio.run(run_stage(None))
check("fast layer without a window still runs", seen2.get("trajectory_summary", ""), "")

# --- D. window rules actually fire, and only inside the window -------------
deliver = classify_call("send_message_to_user", {"text": "hi"})


def r7_for(offset_s: float):
    window = TrajectoryView(
        entries=(summarize_call(
            ts_seq=1,
            call_id="c1",
            tool="astrbot_file_read_tool",
            session="s",
            verb="read",
            targets=("/srv/app/.env",),
            at=iso(offset_s),
        ),),
        session_key="s",
        now=time.time(),
    )
    hits = evaluate_rules(deliver, window)
    return {hit.rule_id for hit in hits}


truthy("R7 fires seconds after a sensitive read", RULE_R7 in r7_for(5))
check("R7 ignores a stale read", RULE_R7 in r7_for(120), False)
unreadable = TrajectoryView(
    entries=({"tool": "astrbot_file_read_tool", "verb": "read", "targets": ["/srv/app/.env"], "at": "not a time"},),
    session_key="s",
    now=time.time(),
)
truthy(
    "R7 treats an unreadable timestamp as recent",
    RULE_R7 in {hit.rule_id for hit in evaluate_rules(deliver, unreadable)},
)
check(
    "R7 needs an outbound call",
    RULE_R7
    in {
        hit.rule_id
        for hit in evaluate_rules(
            classify_call("astrbot_file_write_tool", {"path": "/srv/app/notes.txt", "content": "x"}),
            TrajectoryView(entries=(read,), session_key="s", now=time.time()),
        )
    },
    False,
)
truthy(
    "R7 treats shell as outbound",
    RULE_R7
    in {
        hit.rule_id
        for hit in evaluate_rules(
            classify_call("astrbot_execute_shell", {"command": "Get-Date"}),
            TrajectoryView(entries=(read,), session_key="s", now=time.time()),
        )
    },
)

# --- E. the prompts tell both layers to read the history -------------------
truthy("jev instructions mention history", "trajectory_summary" in systemone.RISK_INSTRUCTIONS)
truthy("deep prompt mentions history", "trajectory_summary" in deep_call.SYSTEM_PROMPT)
truthy("fast prompt mentions history", "trajectory_summary" in single_call.SYSTEM_PROMPT)
truthy("jev instructions judge the effect", "not the capability of the tool" in systemone.RISK_INSTRUCTIONS)
truthy("jeves criteria keep five bands", len(systemone.RISK_CRITERIA) == 5)
truthy("deep prompt demands json", '"score"' in deep_call.SYSTEM_PROMPT and '"confidence"' in deep_call.SYSTEM_PROMPT)
answer = parse_text_answer('{"score": 82, "noul": false, "confidence": 0.9}')
check("deep answer parses", answer.raw_score, 82)

print(f"{CHECKS} checks, {FAILED} failed")
print("ALL CHECKS PASSED" if FAILED == 0 else "CHECKS FAILED")
