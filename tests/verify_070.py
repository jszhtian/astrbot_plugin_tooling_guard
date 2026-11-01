"""0.7.0 checks: the fast judge can be served by the AstrBot host.

Requirement: Fast Judge Backends; Layered Consensus.

AstrBot 4.29.4 adds a Decision Provider that is separate from the chat model, so
a fast judge no longer has to be a second endpoint pasted into the plugin. Two
new judges answer exactly like jev.client.FastJudge -- same structured state,
same FastVerdict -- so the banding, the confidence floor and the deep trigger
stay in jev.score and are never duplicated per source.

These checks pin down the answer mapping, the two judge callables, the
configuration keys that select them, and that nothing here imports astrbot at
module scope (the plugin still has to load on a host older than 4.29.4).

The suite runs with no AstrBot install, so the host decision entities are
replaced by a stand-in astrbot.api.provider module after the lazy import is
proven.
"""
import asyncio
import inspect
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _bootstrap import ROOT, fixture_config  # noqa: E402

from tooling_guard import __version__  # noqa: E402
from tooling_guard.jev import decision as decision_mod  # noqa: E402
from tooling_guard.jev.client import FastJudge  # noqa: E402
from tooling_guard.jev.decision import (  # noqa: E402
    FLAG_THRESHOLD,
    DecisionJudge,
    ProviderJudge,
    build_decision_questions,
    verdict_from_decision_answers,
)
from tooling_guard.jev.schema import NOTE_UNREADABLE  # noqa: E402
from tooling_guard.jev.score import (  # noqa: E402
    NOTE_CONFIDENCE_MISSING,
    FastThresholds,
)
from tooling_guard.main import Gateway  # noqa: E402
from tooling_guard.prompts.single_call import SYSTEM_PROMPT as LLM_SYSTEM_PROMPT  # noqa: E402
from tooling_guard.prompts.systemone import (  # noqa: E402
    DEEP_INSTRUCTIONS,
    DEEP_KEY,
    RISK_CRITERIA,
    RISK_INSTRUCTIONS,
    RISK_KEY,
    STATE_PREAMBLE,
)

ok = fail = 0


def check(name, got, want):
    """Count one assertion."""
    global ok, fail
    if got == want:
        ok += 1
    else:
        fail += 1
        print("FAIL %-58s got=%r want=%r" % (name, got, want))


def answers(score=2.0, probability=0.2, confidence=0.9):
    """Return one Decision Provider answer set for the two heads."""
    return {
        RISK_KEY: SimpleNamespace(
            score=score, legend={}, probabilities={}, confidence=confidence
        ),
        DEEP_KEY: SimpleNamespace(probability=probability),
    }


class Service:
    """Stand-in DecisionService: records one ask and replays one answer set."""

    def __init__(self, reply=None, delay=0.0):
        self.reply = reply if reply is not None else answers()
        self.delay = delay
        self.calls = []

    async def ask(self, questions, state=None, *, provider_id=None):
        self.calls.append((questions, state, provider_id))
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.reply


class Ctx:
    """Stand-in plugin Context: only the attributes a judge reads."""

    def __init__(self, *, decision=None, generate=None, completion=None):
        self.service = decision
        if decision is not None:
            self.decision = decision
        if generate is not None:
            self.generate = generate
            self.llm_generate = generate
        self.completion = completion


def run(coro):
    """Run one coroutine outside the event loop of the caller."""
    return asyncio.run(coro)


def outcome(fn):
    """Return the exception type one judge call raised, or None."""
    try:
        run(fn())
    except BaseException as exc:  # noqa: BLE001 - the type is the assertion
        return type(exc)
    return None


STATE = {"tool": "astrbot_execute_shell", "verb": "run"}

# ---- A. the answer mapping ----------------------------------------------
verdict = verdict_from_decision_answers(answers(score=0.0, probability=0.1))
check("a clean answer carries a score", verdict.score_pct, 0)
check("a low deep probability is a no", verdict.noul, False)
check("the band comes from the five criteria", verdict.band, RISK_CRITERIA[0])
check("the confidence is kept", verdict.confidence, 0.9)
check("a readable answer has no note", verdict.note, "")

high = verdict_from_decision_answers(answers(score=4.0, probability=0.5))
check("the top criterion is 100", high.score_pct, 100)
check("an exact half counts as yes", high.noul, True)
check("the threshold is half", FLAG_THRESHOLD, 0.5)

mid = verdict_from_decision_answers(answers(score=2.0, probability=0.49))
check("the middle criterion is 50", mid.score_pct, 50)
check("a probability below half is a no", mid.noul, False)

check(
    "a non-mapping answer is unreadable",
    verdict_from_decision_answers("nope").note,
    NOTE_UNREADABLE,
)
check(
    "a non-mapping answer has no score",
    verdict_from_decision_answers("nope").score_pct,
    None,
)
check("an empty answer set is unreadable", verdict_from_decision_answers({}).note, NOTE_UNREADABLE)
check(
    "a missing score is unreadable",
    verdict_from_decision_answers({RISK_KEY: SimpleNamespace(score=None)}).score_pct,
    None,
)
check(
    "a textual score is unreadable",
    verdict_from_decision_answers({RISK_KEY: SimpleNamespace(score="3")}).score_pct,
    None,
)
check(
    "a boolean score is unreadable",
    verdict_from_decision_answers({RISK_KEY: SimpleNamespace(score=True)}).score_pct,
    None,
)

bare = verdict_from_decision_answers(
    {RISK_KEY: SimpleNamespace(score=2.0), DEEP_KEY: SimpleNamespace(probability=0.7)}
)
check("a missing confidence still scores", bare.score_pct, 50)
check("a missing confidence is noted", bare.note, NOTE_CONFIDENCE_MISSING)
check("a missing confidence is not invented", bare.confidence, None)
check("the deep flag still reads", bare.noul, True)

no_deep = verdict_from_decision_answers({RISK_KEY: SimpleNamespace(score=1.0, confidence=1.0)})
check("an absent deep answer is unknown", no_deep.noul, None)
check("the score survives an absent deep answer", no_deep.score_pct, 25)
bad_flag = verdict_from_decision_answers(
    {RISK_KEY: SimpleNamespace(score=1.0), DEEP_KEY: SimpleNamespace(probability="0.9")}
)
check("a textual probability is unknown", bad_flag.noul, None)

# ---- B. the questions are built lazily ----------------------------------
check(
    "importing the module pulls no astrbot",
    "astrbot.api.provider" in sys.modules,
    False,
)
check(
    "the module exports the two judges",
    sorted(decision_mod.__all__),
    ["DecisionJudge", "FLAG_THRESHOLD", "ProviderJudge", "build_decision_questions", "verdict_from_decision_answers"],
)

try:
    build_decision_questions()
    lazy = False
except ImportError:
    lazy = True
check("without the host entities the questions refuse", lazy, True)
check(
    "the host import lives in the builder",
    "from astrbot.api.provider import" in inspect.getsource(build_decision_questions),
    True,
)
check(
    "the module imports no host entity at scope",
    hasattr(decision_mod, "DecisionScoreQuestion"),
    False,
)

astrbot = types.ModuleType("astrbot")
api = types.ModuleType("astrbot.api")
host_provider = types.ModuleType("astrbot.api.provider")


class StandInScore:
    """Stand-in DecisionScoreQuestion."""

    def __init__(self, instructions, criteria):
        self.instructions = instructions
        self.criteria = list(criteria)


class StandInBoolean:
    """Stand-in DecisionBooleanQuestion."""

    def __init__(self, instructions):
        self.instructions = instructions


host_provider.DecisionScoreQuestion = StandInScore
host_provider.DecisionBooleanQuestion = StandInBoolean
astrbot.api = api
api.provider = host_provider
sys.modules["astrbot"] = astrbot
sys.modules["astrbot.api"] = api
sys.modules["astrbot.api.provider"] = host_provider

questions = build_decision_questions()
check("the host is asked both heads", sorted(questions), sorted([RISK_KEY, DEEP_KEY]))
check("the risk head is a score question", isinstance(questions[RISK_KEY], StandInScore), True)
check("the risk head keeps five criteria", len(questions[RISK_KEY].criteria), 5)
check(
    "the risk head ships the native wording",
    questions[RISK_KEY].instructions,
    RISK_INSTRUCTIONS,
)
check(
    "the deep head is a boolean question",
    isinstance(questions[DEEP_KEY], StandInBoolean),
    True,
)
check("the deep head ships the native wording", questions[DEEP_KEY].instructions, DEEP_INSTRUCTIONS)

# ---- C. the decision judge ----------------------------------------------
check(
    "a context without a decision service is refused",
    outcome(lambda: DecisionJudge(object())(dict(STATE))),
    TypeError,
)
check("the decision judge defaults to the fast ceiling", DecisionJudge(object()).timeout_s, 10.0)
check("the decision judge never widens past the ceiling", DecisionJudge(object(), timeout_s=999).timeout_s, 50.0)
check("the decision judge carries default thresholds", DecisionJudge(object()).thresholds.block_score, 75)

service = Service(answers(score=3.0, probability=0.8, confidence=0.95))
judge = DecisionJudge(Ctx(decision=service), provider_id="  dec-1  ")
judged = run(judge(dict(STATE)))
check("the decision judge scores the answer", judged.score_pct, 75)
check("the decision judge reads the deep flag", judged.noul, True)
check("the answer travels as one state string", isinstance(service.calls[0][1], str), True)
check("the state starts with the native preamble", service.calls[0][1].startswith(STATE_PREAMBLE), True)
check("the state carries the tool", '"astrbot_execute_shell"' in service.calls[0][1], True)
check("the provider id is trimmed", service.calls[0][2], "dec-1")
check("both heads travel in one request", sorted(service.calls[0][0]), sorted([RISK_KEY, DEEP_KEY]))
check("one request per judgement", len(service.calls), 1)

default_service = Service()
run(DecisionJudge(Ctx(decision=default_service))({"tool": "x"}))
check("an empty provider id asks the host default", default_service.calls[0][2], None)

narrow = DecisionJudge(Ctx(decision=Service(delay=0.4)), timeout_s=50)
check(
    "the caller narrows the decision budget",
    outcome(lambda: narrow(dict(STATE), timeout_s=0.05)),
    asyncio.TimeoutError,
)
check(
    "an endless decision budget is capped",
    DecisionJudge(object(), timeout_s=None).timeout_s,
    10.0,
)
custom = FastThresholds(allow_score=10, block_score=60, min_confidence=0.5)
check(
    "the thresholds travel with the judge",
    DecisionJudge(object(), thresholds=custom).thresholds.block_score,
    60,
)
check(
    "an unusable answer set abstains",
    run(DecisionJudge(Ctx(decision=Service("junk")))(dict(STATE))).score_pct,
    None,
)

# ---- D. the provider judge ----------------------------------------------
check(
    "a context without llm_generate is refused",
    outcome(lambda: ProviderJudge(object())(dict(STATE))),
    TypeError,
)

seen = {}


async def generate(**kwargs):
    seen.update(kwargs)
    return SimpleNamespace(completion_text='{"score": 88, "noul": true}')


provider_judge = ProviderJudge(Ctx(generate=generate), provider_id=" chat-1 ")
answered = run(provider_judge(dict(STATE)))
check("the provider judge scores the JSON answer", answered.score_pct, 88)
check("the provider judge reads the deep flag", answered.noul, True)
check("the provider id is forwarded", seen.get("chat_provider_id"), "chat-1")
check("the schema reaches the provider route", seen.get("system_prompt"), LLM_SYSTEM_PROMPT)
check("the state is the prompt", '"astrbot_execute_shell"' in seen.get("prompt", ""), True)


async def prose(**kwargs):
    return SimpleNamespace(completion_text="I cannot decide.")


check(
    "prose abstains instead of denying",
    run(ProviderJudge(Ctx(generate=prose), provider_id="chat-1")({"tool": "x"})).score_pct,
    None,
)


async def textless(**kwargs):
    return SimpleNamespace(completion_text=None)


check(
    "a textless completion is an error, not a verdict",
    outcome(lambda: ProviderJudge(Ctx(generate=textless), provider_id="chat-1")({"tool": "x"})),
    TypeError,
)

# ---- E. the configuration selects the judge ------------------------------
raw, tmp = fixture_config()
plain = Gateway.from_config(raw, data_dir=tmp, context=Ctx())
check("the fixture still builds a gateway", plain.validation.enabled, True)
check("endpoint is the shipped jev source", plain.config.jev_source, "endpoint")
check("endpoint is the shipped llm source", plain.config.llm_fast_source, "endpoint")
check("the provider ids ship empty", plain.config.jev_provider_id, "")
check("the fast provider id ships empty", plain.config.llm_fast_provider_id, "")
check("the backend defaults to jev", plain._fast_judge_backend(), "jev")
check("the source defaults to the endpoint", plain._fast_judge_source(), "endpoint")
check("a disabled jev builds no judge", plain._fast_judge_callable(), None)

switched_off = dict(raw)
switched_off["jev_enabled"] = False
switched_off["jev_source"] = "astrbot"
gw_off = Gateway.from_config(switched_off, data_dir=tmp, context=Ctx(decision=Service()))
check("the host route obeys the jev switch", gw_off.validation.enabled, True)
check("a switched-off host route builds no judge", gw_off._fast_judge_callable(), None)

host_jev = dict(raw)
host_jev["jev_enabled"] = True
host_jev["jev_source"] = "astrbot"
host_jev["jev_provider_id"] = "dec-9"
gw_host = Gateway.from_config(host_jev, data_dir=tmp, context=Ctx(decision=Service()))
check("the host decision route needs no endpoint keys", gw_host.validation.enabled, True)
check("no endpoint client is built for the host route", gw_host._jev_client, None)
check("the fast judge is the decision judge", isinstance(gw_host._fast_judge_callable(), DecisionJudge), True)
check(
    "the configured decision provider is used",
    gw_host._fast_judge_callable().provider_id,
    "dec-9",
)
check(
    "the fast judge keeps the resolved thresholds",
    gw_host._fast_judge_callable().thresholds is gw_host._fast_thresholds,
    True,
)

host_llm = dict(raw)
host_llm["jev_enabled"] = True
host_llm["fast_judge_backend"] = "llm"
host_llm["llm_fast_source"] = "astrbot"
host_llm["llm_fast_provider_id"] = "chat-9"
gw_llm = Gateway.from_config(host_llm, data_dir=tmp, context=Ctx(generate=generate))
check("the host chat route needs no endpoint keys", gw_llm.validation.enabled, True)
check("the fast judge is the provider judge", isinstance(gw_llm._fast_judge_callable(), ProviderJudge), True)
check(
    "the configured chat provider is used",
    gw_llm._fast_judge_callable().provider_id,
    "chat-9",
)

endpoint = dict(raw)
endpoint["jev_enabled"] = True
endpoint["jev_api_key"] = "test-key"
endpoint["jev_timeout_s"] = 15
gw_endpoint = Gateway.from_config(endpoint, data_dir=tmp, context=Ctx())
check("the endpoint route still validates", gw_endpoint.validation.enabled, True)
check("the endpoint route builds a client", gw_endpoint._jev_client is None, False)
check("the endpoint route keeps FastJudge", isinstance(gw_endpoint._fast_judge_callable(), FastJudge), True)

bad_source = dict(raw)
bad_source["jev_source"] = "ollama"
gw_bad = Gateway.from_config(bad_source, data_dir=tmp, context=Ctx())
check("an unknown jev source is refused", gw_bad.validation.enabled, False)
check(
    "and the issue names the key",
    [i.key for i in gw_bad.validation.warnings],
    ["jev_source"],
)
check(
    "and the issue carries a code",
    [i.code for i in gw_bad.validation.warnings],
    ["jev_source_unknown"],
)

bad_llm_source = dict(raw)
bad_llm_source["llm_fast_source"] = "ollama"
gw_bad_llm = Gateway.from_config(bad_llm_source, data_dir=tmp, context=Ctx())
check("an unknown llm source is refused", gw_bad_llm.validation.enabled, False)
check(
    "and the llm issue carries a code",
    [i.code for i in gw_bad_llm.validation.warnings],
    ["llm_fast_source_unknown"],
)

missing_endpoint = dict(raw)
missing_endpoint["jev_enabled"] = True
gw_missing = Gateway.from_config(missing_endpoint, data_dir=tmp, context=Ctx())
check("the endpoint route still requires its keys", gw_missing.validation.enabled, False)
check(
    "the empty endpoint key is named",
    sorted(i.key for i in gw_missing.validation.warnings),
    ["jev_api_key"],
)
check(
    "and it carries the endpoint code",
    sorted({i.code for i in gw_missing.validation.warnings}),
    ["endpoint_field_required"],
)

blank_endpoint = dict(missing_endpoint)
blank_endpoint["jev_base_url"] = ""
blank_endpoint["jev_model"] = ""
gw_blank = Gateway.from_config(blank_endpoint, data_dir=tmp, context=Ctx())
check(
    "every blank endpoint key is named",
    sorted(i.key for i in gw_blank.validation.warnings),
    ["jev_api_key", "jev_base_url", "jev_model"],
)

llm_host_no_keys = dict(raw)
llm_host_no_keys["jev_enabled"] = True
llm_host_no_keys["fast_judge_backend"] = "llm"
llm_host_no_keys["llm_fast_source"] = "astrbot"
gw_no_keys = Gateway.from_config(llm_host_no_keys, data_dir=tmp, context=Ctx())
check("the host chat route skips the endpoint keys", gw_no_keys.validation.enabled, True)

# ---- F. the shipped package --------------------------------------------
schema = json.loads((ROOT / "_conf_schema.json").read_text(encoding="utf-8"))
check("jev_source ships", schema["jev_source"]["type"], "string")
check("jev_source offers two options", schema["jev_source"]["options"], ["endpoint", "astrbot"])
check("jev_source defaults to the endpoint", schema["jev_source"]["default"], "endpoint")
check("jev_provider_id ships", schema["jev_provider_id"]["type"], "string")
check("jev_provider_id defaults to empty", schema["jev_provider_id"]["default"], "")
check("llm_fast_source ships", schema["llm_fast_source"]["options"], ["endpoint", "astrbot"])
check("llm_fast_source defaults to the endpoint", schema["llm_fast_source"]["default"], "endpoint")
check("llm_fast_provider_id picks a provider", schema["llm_fast_provider_id"].get("_special"), "select_provider")
check("the deep provider id picks a provider", schema["llm_provider_id"].get("_special"), "select_provider")
names = list(schema)
check(
    "the backend and both sources precede the endpoint",
    [
        key
        for key in ("fast_judge_backend", "jev_source", "llm_fast_source")
        if names.index(key) > names.index("jev_base_url")
    ],
    [],
)
check(
    "both fast provider ids precede the endpoint",
    [key for key in ("jev_provider_id", "llm_fast_provider_id") if names.index(key) > names.index("jev_base_url")],
    [],
)
check(
    "the fast judge block starts at the switch",
    names[names.index("jev_enabled") : names.index("jev_enabled") + 6],
    ["jev_enabled", "fast_judge_backend", "jev_source", "jev_provider_id", "llm_fast_source", "llm_fast_provider_id"],
)
check(
    "the endpoint, model and key stay together",
    names[names.index("jev_base_url") : names.index("jev_base_url") + 3],
    ["jev_base_url", "jev_model", "jev_api_key"],
)
check("the deep provider id ships", "llm_provider_id" in names, True)
check(
    "every hint names its key",
    [key for key, item in schema.items() if not item["hint"].startswith("键 " + key + "。")],
    [],
)
check(
    "every new key explains its failure mode",
    [key for key in ("jev_source", "llm_fast_source") if "配置校验失败" not in schema[key]["hint"]],
    [],
)
check("the version is bumped", __version__, "0.7.2")
metadata = (ROOT / "metadata.yaml").read_text(encoding="utf-8")
check("the metadata ships the version", "version: 0.7.2" in metadata, True)
check("the minimum host is 4.29.4", 'astrbot_version: ">=4.29.4"' in metadata, True)

print("%d checks, %d failed" % (ok, fail))
if fail:
    raise SystemExit(1)
print("ALL CHECKS PASSED")
