"""0.6.8 checks: the refusal a caller reads must name the stage, not a rule.

The fold appends every rule that fired to its reason text, and an observe rule
such as R8 fires on calls it never blocks. Observed live on 0.6.7: the refusal
text ended in "[rules=R8]", the model repeated it verbatim, told the user the
call "was blocked by rule R8", and advised widening a setting unrelated to the
refusal. The audit row already says which stage decided the call; this file pins
that the same fact reaches the text the caller sees.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _bootstrap import fixture_config  # noqa: E402

from tooling_guard.interface.results import denial_result  # noqa: E402
from tooling_guard.main import Gateway, _Plan  # noqa: E402
from tooling_guard.policy.layers import (  # noqa: E402
    LAYER_DENY_PATH,
    LAYER_STATIC_PASS,
)
from tooling_guard.triage.decisions import Decision, WouldBe  # noqa: E402

ok = fail = 0


def check(name, got, want):
    """Count one assertion."""
    global ok, fail
    if got == want:
        ok += 1
    else:
        fail += 1
        print("FAIL %-56s got=%r want=%r" % (name, got, want))


raw, tmp = fixture_config()


class FakeCtx:
    """Minimal AstrBot context: the gateway only needs a sender."""

    async def send_message(self, *a, **k):
        return True

    async def llm_generate(self, **k):
        return "{}"


gw = Gateway.from_config(raw, data_dir=tmp, context=FakeCtx())
check("gateway valid", gw.validation.enabled, True)

DENY_TEXT = "目标落在 path_deny 内或不可解析：D:\\AstrBot\\data\\logs [rules=R8]"
MARK = "（归因 static/deny_path；规则号 R8 只是证据，不是原因）"

# ---- A. the words a caller reads ------------------------------------------
static_deny = _Plan(
    decision=Decision.DENY_POLICY,
    reason=DENY_TEXT,
    call_id="c1",
    rule_id="R8",
    layer=LAYER_DENY_PATH,
    source="deny_path",
)
spoken = gw._spoken_reason(static_deny)
check("static denial names its stage", spoken.endswith(MARK), True)
check("the reason itself is intact", spoken.startswith(DENY_TEXT), True)
check("rule id no longer stands alone", "[rules=R8]" in spoken, True)
check("only one attribution marker", spoken.count("归因"), 1)

allow = _Plan(
    decision=Decision.ALLOW_PASSTHROUGH,
    reason="请求者或全部目标命中白名单",
    call_id="c2",
    layer=LAYER_STATIC_PASS,
)
check("a release is not annotated", gw._spoken_reason(allow), allow.reason)

observed = _Plan(
    decision=Decision.ALLOW_PASSTHROUGH,
    reason="模型拒绝（观察模式未阻断）",
    call_id="c3",
    would_be=WouldBe.SUSPEND,
)
check("an observe rewrite reads as the release it is", gw._spoken_reason(observed), observed.reason)

by_jev = _Plan(
    decision=Decision.SUSPENDED,
    reason="模型拒绝",
    call_id="c4",
    review={"jev_fast": {"decision": "deny_judge"}, "llm_deep": {"decision": "allow"}},
)
check("a model denial names the model", gw._spoken_reason(by_jev).endswith("（归因 jev）"), True)

rule_deny = _Plan(
    decision=Decision.DENY_RULE,
    reason="R3: 编码执行",
    call_id="c5",
    rule_id="R3",
)
spoken_rule = gw._spoken_reason(rule_deny)
check("a rule denial names the rule stage", "归因 rules" in spoken_rule, True)
check("a rule denial still marks evidence", "规则号 R3 只是证据" in spoken_rule, True)

gateway_deny = _Plan(decision=Decision.TIMEOUT_DENY, reason="预算耗尽", call_id="c6")
check("a gateway denial names the gateway", "归因 gateway" in gw._spoken_reason(gateway_deny), True)

empty = _Plan(decision=Decision.DENY_POLICY, reason="", call_id="c7")
check("an empty reason stays empty", gw._spoken_reason(empty), "")

# ---- B. the caller-facing result carries it -------------------------------
outcome = gw._outcome(static_deny)
check("the outcome text is the spoken reason", outcome.text.endswith(MARK), True)
block = denial_result(outcome.text).content[0].text
check("the tool result carries the stage", "归因 static/deny_path" in block, True)
check("the tool result keeps the prefix", block.startswith("工具调用已被拦截："), True)

print("%d checks, %d failed" % (ok, fail))
if fail:
    raise SystemExit(1)
print("ALL CHECKS PASSED")
