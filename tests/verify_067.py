"""0.6.7 checks: redirect targets must look like paths, and rows must say why.

Two defects this file pins down:

* A redirect operator is read out of command text, so a comparison such as
  "where ts > '2026-10-30T19'" used to contribute the fragment 2026-10-30T19 as
  a path target, which the denylist then judged.
* The audit row's rule_id column names the first rule that fired, and an observe
  rule fires on calls it never blocks, so a report reading rule_id as the cause
  of a denial blames an observer. The attribution now travels as the policy
  layer, in summary_json and as a marker on the summary line.
"""
import asyncio
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _bootstrap import fixture_config  # noqa: E402  (also puts the repo root on sys.path)

from tooling_guard.core.call import build_call  # noqa: E402
from tooling_guard.main import (  # noqa: E402
    Gateway,
    _attribution,
    _Plan,
    _reviewed_record_dict,
)
from tooling_guard.notify.messages import render_admin_message  # noqa: E402
from tooling_guard.policy.layers import (  # noqa: E402
    LAYER_DENY_PATH,
    LAYER_STATIC_PASS,
    LAYER_WHITELIST,
)
from tooling_guard.triage.classify import _absolute_literal, classify_call  # noqa: E402
from tooling_guard.triage.decisions import Decision, WouldBe  # noqa: E402
from tooling_guard.ui.commands import _stats_reply  # noqa: E402
from tooling_guard.web.queries import serialize_event  # noqa: E402

ok = fail = 0


def check(name, got, want):
    """Count one assertion."""
    global ok, fail
    if got == want:
        ok += 1
    else:
        fail += 1
        print("FAIL %-56s got=%r want=%r" % (name, got, want))


# ---- A. a target must be written as a path -------------------------------
def feats(tool, args):
    """Classify one call's features."""
    return classify_call(tool, args)


check("drive letter literal", _absolute_literal("D:\\AstrBot\\x.txt"), True)
check("UNC literal", _absolute_literal("\\\\srv\\share\\x.txt"), True)
check("relative name is not a path", _absolute_literal("out.txt"), False)
check("bare drive is not a path", _absolute_literal("y:"), False)
check("timestamp fragment is not a path", _absolute_literal("2026-10-30T19"), False)

python = feats(
    "astrbot_execute_python",
    {"code": "db.execute(\"select * from audit_events where ts > '2026-10-30T19'\")"},
)
check("python comparison yields no target", "2026-10-30T19" in python.targets, False)

shell_out = feats("astrbot_execute_shell", {"command": "Get-Date > out.txt"})
check("relative write stays out of targets", "out.txt" in shell_out.targets, False)
check("relative write stays in write_targets", "out.txt" in shell_out.write_targets, True)

shell_abs = feats(
    "astrbot_execute_shell", {"command": "Get-Date > D:\\AstrBot\\data\\probe.txt"}
)
check("absolute write stays a target", "D:\\AstrBot\\data\\probe.txt" in shell_abs.targets, True)

# ---- B. attribution is the layer, not the rule id ------------------------
static_deny = _Plan(
    decision=Decision.DENY_POLICY,
    reason="r",
    call_id="c1",
    rule_id="R8",
    layer=LAYER_DENY_PATH,
    source="deny_path",
)
block = _attribution(static_deny)
check("static denial attributed to static", block["stage"], "static")
check("layer travels", block["layer"], LAYER_DENY_PATH)
check("source travels", block["source"], "deny_path")
check("rule ids named as evidence", block["rule_ids_role"], "evidence")
check("rule id kept as evidence", block["rule_ids"], ["R8"])

rule_deny = _Plan(decision=Decision.DENY_RULE, reason="r", call_id="c2", rule_id="R3")
check("rule denial attributed to rules", _attribution(rule_deny)["stage"], "rules")

observed = _Plan(
    decision=Decision.ALLOW_PASSTHROUGH,
    reason="r",
    call_id="c3",
    would_be=WouldBe.SUSPEND,
    layer=LAYER_STATIC_PASS,
)
observed_block = _attribution(observed)
check("observe rewrite attributed to consensus", observed_block["stage"], "consensus")
check("observe keeps what would have happened", observed_block["would_be"], "suspend")

whitelisted = _Plan(
    decision=Decision.ALLOW_PASSTHROUGH,
    reason="r",
    call_id="c4",
    layer=LAYER_WHITELIST,
)
check("whitelisted release attributed to static", _attribution(whitelisted)["stage"], "static")

by_jev = _Plan(
    decision=Decision.SUSPENDED,
    reason="r",
    call_id="c5",
    review={"jev_fast": {"decision": "deny_judge"}, "llm_deep": {"decision": "allow"}},
)
check("model denial names jev", _attribution(by_jev)["stage"], "jev")

by_deep = _Plan(
    decision=Decision.SUSPENDED,
    reason="r",
    call_id="c6",
    review={"jev_fast": {"decision": "allow"}, "llm_deep": {"decision": "deny_judge"}},
)
check("model denial names deep", _attribution(by_deep)["stage"], "deep")

timed_out = _Plan(decision=Decision.TIMEOUT_DENY, reason="r", call_id="c7")
check("gateway denial attributed to the gateway", _attribution(timed_out)["stage"], "gateway")

# ---- C. the row carries it end to end ------------------------------------
raw, tmp = fixture_config()


class FakeCtx:
    """Minimal AstrBot context: the gateway only needs a sender."""

    async def send_message(self, *a, **k):
        return True

    async def llm_generate(self, **k):
        return "{}"


gw = Gateway.from_config(raw, data_dir=tmp, context=FakeCtx())
check("gateway valid", gw.validation.enabled, True)
snapshot = gw._snapshot
check("snapshot present", snapshot is not None, True)

plan = _Plan(
    decision=Decision.DENY_POLICY,
    reason="读取敏感配置文件",
    call_id="c8",
    rule_id="R8",
    layer=LAYER_DENY_PATH,
    source="deny_path",
)
written = gw._record(
    plan,
    tool="astrbot_execute_shell",
    subject="asr:1",
    session="asr:GroupMessage:7",
    args={"command": "Get-ChildItem D:\\AstrBot"},
    ticket_id=None,
    snapshot=snapshot,
    digest_value="digest",
)
check("audit row written", written, True)

dbs = sorted(Path(tmp).rglob("*.sqlite3"))
check("store created", len(dbs) >= 1, True)
row = None
for path in dbs:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        fetched = conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    except sqlite3.Error:
        fetched = None
    conn.close()
    if fetched is not None:
        row = dict(fetched)
        break
check("row present", row is not None, True)

if row is not None:
    check("rule_id column still holds the observer", row["rule_id"], "R8")
    check("summary line names the layer", "layer=deny_path" in row["summary_line"], True)
    payload = json.loads(row["summary_json"])
    check("summary_json keeps 22 spec keys", "ts_seq" in payload, True)
    check("summary_json carries attribution", payload["attribution"]["stage"], "static")
    check("summary_json attribution layer", payload["attribution"]["layer"], LAYER_DENY_PATH)

    view = serialize_event(gw, row)
    check("wire form exposes the layer", view["layer"], "deny_path")
    check("wire form still exposes the rule id", view["rule_id"], "R8")

    body_text = render_admin_message(
        {
            "ticket_id": "0" * 32,
            "tool_name": "astrbot_execute_shell",
            "verb": "execute",
            "tier": "strong",
            "decision": "deny_policy",
            "layer": LAYER_DENY_PATH,
            "rule_ids": ["R8"],
            "subject_key": "asr:1",
            "session_key": "asr:GroupMessage:7",
            "remaining_s": 30,
            "arguments": {"command": "Get-ChildItem D:\\AstrBot"},
        },
        anonymizer=None,
    )
    check("notice names the layer", "归因 deny_path" in body_text, True)
    check("notice labels the rules as hits", "命中规则 R8" in body_text, True)
    check(
        "notice names the rule as evidence next to the layer",
        body_text.index("归因") < body_text.index("命中规则"),
        True,
    )

    stats = _stats_reply(gw, ("all",))
    check("stats report the attribution layer", "归因层 Top" in stats, True)
    check("stats label the rule counts as evidence", "命中规则 Top" in stats and "证据，非归因" in stats, True)
    check("stats put the layer before the rules", stats.index("归因层") < stats.index("命中规则"), True)
    check("stats do not name the layer by the rule word", "R8" in stats, True)

print("%d checks, %d failed" % (ok, fail))
print("ALL CHECKS PASSED" if not fail else "FAILURES PRESENT")
sys.exit(1 if fail else 0)
