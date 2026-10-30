"""0.6.5 checks: the stored window entry must carry its classified targets."""
import json, sys, tempfile, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _bootstrap import fixture_config  # noqa: E402  (also puts the repo root on sys.path)
from tooling_guard.main import Gateway, _Plan
from tooling_guard.triage.classify import classify_call
from tooling_guard.triage.decisions import Decision
from tooling_guard.triage.rules import evaluate_rules, RULE_R7

ok = fail = 0
def check(name, got, want):
    global ok, fail
    if got == want:
        ok += 1
    else:
        fail += 1
        print("FAIL %-50s got=%r want=%r" % (name, got, want))

raw, tmp = fixture_config()

class FakeCtx:
    async def send_message(self, *a, **k): return True
    async def llm_generate(self, **k): return "{}"

gw = Gateway.from_config(raw, data_dir=tmp, context=FakeCtx())
check("gateway valid", gw.validation.enabled, True)

session = "asr:GroupMessage:1"
def store(tool, args, decision, seq):
    gw._sequences[session] = seq
    plan = _Plan(decision=decision, reason="r", call_id="c%d" % seq)
    summary = gw._call_summary(plan, tool=tool, subject="asr:1", session=session,
                               args=args, digest_value="d", ticket_id=None, at="")
    gw._append_trajectory(summary, session=session)
    return summary

s = store("astrbot_file_read_tool", {"path": "D:/proj/.env"}, Decision.DENY_POLICY, 1)
check("read summary keeps targets", bool(s.targets), True)
check("target names the file", any(str(x).endswith(".env") for x in s.targets), True)
view = gw._trajectory_view(session)
check("window keeps one entry", len(view.entries), 1)
check("entry carries the path", any(".env" in str(x) for x in view.entries[0].targets), True)

def r7_for(tool, args):
    feats = classify_call(tool, args)
    hits = evaluate_rules(feats, trajectory=view)
    return any(h.rule_id == RULE_R7 for h in hits)

check("R7 fires on a later outbound shell", r7_for("astrbot_execute_shell", {"command": "Get-Date -Format o"}), True)

gw2_session = "asr:GroupMessage:2"
gw._sequences[gw2_session] = 10
plan = _Plan(decision=Decision.ALLOW_PASSTHROUGH, reason="r", call_id="c10")
benign = gw._call_summary(plan, tool="astrbot_file_read_tool", subject="asr:1", session=gw2_session,
                          args={"path": "D:/proj/README.md"}, digest_value="d", ticket_id=None, at="")
gw._append_trajectory(benign, session=gw2_session)
view2 = gw._trajectory_view(gw2_session)
hits2 = evaluate_rules(classify_call("astrbot_execute_shell", {"command": "Get-Date -Format o"}), trajectory=view2)
check("a benign read is not R7", any(h.rule_id == RULE_R7 for h in hits2), False)

print("%d checks, %d failed" % (ok + fail, fail))
print("ALL CHECKS PASSED" if fail == 0 else "FAILURES")