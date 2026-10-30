"""0.6.6 checks: an R7 hit forces the deep layer, whatever the fast judge said."""
import asyncio, json, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _bootstrap import fixture_config  # noqa: E402  (also puts the repo root on sys.path)
from tooling_guard.core.call import build_call
from tooling_guard.core.pipeline import PipelineOutcome
from tooling_guard.core.verdict import ReviewOutcome, Verdict
from tooling_guard.jev.score import DETAIL_FORCE_DEEP, FastThresholds, FastVerdict
from tooling_guard.main import Gateway, _Plan, _needs_deep
from tooling_guard.reviewers.jev_fast import (
    FORCED_DEEP_RULES,
    JevFastReviewer,
    forces_deep_by_rule,
)
from tooling_guard.triage.classify import classify_call
from tooling_guard.triage.decisions import Decision
from tooling_guard.triage.engine import RulesStage
from tooling_guard.triage.rules import RULE_R7, evaluate_rules

ok = fail = 0
def check(name, got, want):
    global ok, fail
    if got == want:
        ok += 1
    else:
        fail += 1
        print("FAIL %-52s got=%r want=%r" % (name, got, want))

check("R7 is the forced rule", RULE_R7 in FORCED_DEEP_RULES, True)
check("empty stage forces nothing", forces_deep_by_rule(RulesStage()), False)
check("R7 stage forces", forces_deep_by_rule(RulesStage(hits=())), False)

# ---- real gateway, real window, real rules -------------------------------
raw, tmp = fixture_config()

class FakeCtx:
    async def send_message(self, *a, **k): return True
    async def llm_generate(self, **k): return "{}"

gw = Gateway.from_config(raw, data_dir=tmp, context=FakeCtx())
check("gateway valid", gw.validation.enabled, True)
snapshot = gw._snapshot
check("snapshot present", snapshot is not None, True)

session = "asr:GroupMessage:7"
def remember(tool, args, seq):
    gw._sequences[session] = seq
    plan = _Plan(decision=Decision.DENY_POLICY, reason="r", call_id="c%d" % seq)
    summary = gw._call_summary(plan, tool=tool, subject="asr:1", session=session,
                               args=args, digest_value="d", ticket_id=None, at="")
    gw._append_trajectory(summary, session=session)

remember("astrbot_file_read_tool", {"path": "D:/proj/.env"}, 1)
view = gw._trajectory_view(session)
shell = build_call(tool_name="astrbot_execute_shell", arguments={"command": "Get-Date -Format o"},
                   subject_key="asr:1", session_key=session, mode="enforce", at=0.0)

features = classify_call(shell.tool_name, shell.arguments)
r7_stage = RulesStage(hits=evaluate_rules(features, trajectory=view))
check("real R7 hit present", any(h.rule_id == RULE_R7 for h in r7_stage.hits), True)
check("forces_deep_by_rule on real stage", forces_deep_by_rule(r7_stage), True)

class Judge:
    def __init__(self, result):
        self.result = result
        self.thresholds = FastThresholds(allow_score=40, block_score=75, min_confidence=0.0)
    async def __call__(self, payload):
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result

def reviewer(answer):
    return JevFastReviewer(snapshot=snapshot, judge=Judge(answer),
                           trajectory_of=lambda call: view)

def run(rev):
    return asyncio.run(rev._answer(shell))

allowed = run(reviewer(FastVerdict(score_pct=5)))
check("fast allow still forces deep on R7", allowed.detail.get(DETAIL_FORCE_DEEP), True)
check("fast allow keeps its outcome", allowed.outcome, ReviewOutcome.ALLOW)

abstained = run(reviewer(None))
check("fast abstain still forces deep on R7", abstained.detail.get(DETAIL_FORCE_DEEP), True)
check("fast abstain is a skip", abstained.outcome, ReviewOutcome.SKIP)

# a benign session must not be forced
benign_session = "asr:GroupMessage:8"
gw._sequences[benign_session] = 10
plan = _Plan(decision=Decision.ALLOW_PASSTHROUGH, reason="r", call_id="c10")
gw._append_trajectory(
    gw._call_summary(plan, tool="astrbot_file_read_tool", subject="asr:1", session=benign_session,
                     args={"path": "D:/proj/README.md"}, digest_value="d", ticket_id=None, at=""),
    session=benign_session)
benign_view = gw._trajectory_view(benign_session)
benign_call = build_call(tool_name="astrbot_execute_shell", arguments={"command": "Get-Date -Format o"},
                         subject_key="asr:1", session_key=benign_session, mode="enforce", at=0.0)
benign_rev = JevFastReviewer(snapshot=snapshot, judge=Judge(FastVerdict(score_pct=5)),
                             trajectory_of=lambda call: benign_view)
calm = asyncio.run(benign_rev._answer(benign_call))
check("no R7 means no forced deep", DETAIL_FORCE_DEEP in dict(calm.detail), False)
check("calm call still allows", calm.outcome, ReviewOutcome.ALLOW)

# ---- the gateway must honour the flag ----------------------------------
forced_outcome = PipelineOutcome(decision=Decision.ALLOW_PASSTHROUGH,
                                 verdicts=(allowed,), preempted=(), terminated_early=False,
                                 degraded=(), elapsed_s=0.1, winner=None)
check("gateway runs deep for a forced allow", _needs_deep(forced_outcome), True)
calm_outcome = PipelineOutcome(decision=Decision.ALLOW_PASSTHROUGH,
                               verdicts=(calm,), preempted=(), terminated_early=False,
                               degraded=(), elapsed_s=0.1, winner=None)
check("gateway skips deep for a calm allow", _needs_deep(calm_outcome), False)

print("%d checks, %d failed" % (ok + fail, fail))
print("ALL CHECKS PASSED" if fail == 0 else "FAILURES")