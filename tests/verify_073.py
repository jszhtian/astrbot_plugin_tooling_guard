"""0.7.3 checks: the approval executes, and the deep layer answers.


Requirement: Approval Wait and Exact-Match Retry; Deep Answer Contract.

Two failures share this release and neither is a wording problem:

* the exact-match retry handed a byte-for-byte obligation to the party that had
  already rewritten its own arguments -- four of five production approvals never
  matched -- so the approval itself now executes the call it names;
* the deep layer's user message was a bare state document, which a chat-tuned
  model answers as a request from its user ("I don't have a comfyui_status tool
  available", a 92.2 s essay for a file write), so every deep vote was an
  abstention and every undecided call went to a human.

These checks pin: the data frame, the one retry, the parser tolerance that stops
72/72.0/"72" from being three different answers, and the execution path with its
audit row, its single use and its two refusal branches.
"""
import asyncio
import logging
import sys
import time
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _bootstrap import ROOT, fixture_config  # noqa: E402


def _stub_host():
    """Install the minimal astrbot.api surface the proxy module imports.

    Only the names the module binds at import time are provided: this harness
    asks how the wrapper reads a decision word, which is host-independent, and
    nothing here may need a real AstrBot install (the same rule as _bootstrap).
    """
    api = types.ModuleType("astrbot.api")
    api.FunctionTool = object
    api.logger = logging.getLogger("verify_073")
    event = types.ModuleType("astrbot.api.event")
    event.CommandResult = object
    event.MessageChain = object
    event.MessageEventResult = object
    api.event = event
    root = types.ModuleType("astrbot")
    root.api = api
    sys.modules.setdefault("astrbot", root)
    sys.modules.setdefault("astrbot.api", api)
    sys.modules.setdefault("astrbot.api.event", event)


_stub_host()

from tooling_guard import __version__  # noqa: E402
from tooling_guard import main as gateway_main  # noqa: E402
from tooling_guard.digest import args_digest  # noqa: E402
from tooling_guard.interface.wrapper import _decision  # noqa: E402
from tooling_guard.jev.schema import parse_text_answer  # noqa: E402
from tooling_guard.main import DEEP_RETRY_NOTE, Gateway  # noqa: E402
from tooling_guard.prompts.deep_call import (  # noqa: E402
    DATA_BEGIN,
    DATA_END,
    SYSTEM_PROMPT,
    build_deep_body,
    build_deep_retry_body,
)
from tooling_guard.store import tickets  # noqa: E402
from tooling_guard.triage.decisions import Decision  # noqa: E402

ok = fail = 0


def check(name, got, want):
    """Count one assertion."""
    global ok, fail
    if got == want:
        ok += 1
    else:
        fail += 1
        print("FAIL %-58s got=%r want=%r" % (name, got, want))


class FakeCtx:
    """Minimal host context: the gateway only needs a sender and a generator."""

    async def send_message(self, *a, **k):
        return True

    async def llm_generate(self, **k):
        return "{}"


STATE = {"tool_name": "astrbot_execute_shell", "verb": "exec", "targets": ["D:/out"]}


# ---- A. the deep message is a framed document, not a request ---------------

body = build_deep_body(state=STATE)
check("the frame opens before the data", body.index(DATA_BEGIN) < body.index(DATA_END), True)
check("the frame carries the state", '"tool_name": "astrbot_execute_shell"' in body, True)
check("the frame opens before the state", body.index(DATA_BEGIN) < body.index('"tool_name"'), True)
check("the frame closes after the state", body.index(DATA_END) > body.index('"tool_name"'), True)
check("the shape is restated after the data", body.rstrip().endswith("JSON object."), True)
check("a string state passes through", DATA_BEGIN in build_deep_body(state="plain text"), True)
retry = build_deep_retry_body(state=STATE)
check("the retry repeats the whole frame", retry.startswith(body), True)
check("the retry names what went wrong", "previous reply was not one JSON object" in retry, True)
check("the retry keeps the state", '"astrbot_execute_shell"' in retry, True)
check(
    "the system prompt forbids doing the call",
    "You do not run, continue, " in SYSTEM_PROMPT,
    True,
)
check("the system prompt marks the data untrusted", "untrusted evidence" in SYSTEM_PROMPT, True)
check("the system prompt pins the answer shape", '{"score": <integer 0-100>' in SYSTEM_PROMPT, True)

# ---- B. a readable score is a readable score whatever the JSON type ---------

def score_of(payload):
    """Return the score of one parsed answer, or None when it is unreadable."""
    return parse_text_answer(payload).score_pct


check("an integer score", score_of('{"score": 72, "confidence": 0.9}'), 72)
check("a float score is the same answer", score_of('{"score": 72.0, "confidence": 0.9}'), 72)
check("a numeric string is the same answer", score_of('{"score": "72"}'), 72)
check("a rounded float", score_of('{"score": 71.6}'), 72)
check("a missing score is still unreadable", score_of('{"noul": true}'), None)
check("a score out of range is unreadable", score_of('{"score": 120}'), None)
check("a boolean score is unreadable", score_of('{"score": true}'), None)
check("prose is unreadable", score_of("Sending pointcloud_cake.html to you now."), None)
check("a missing noul only loses the upgrade", parse_text_answer('{"score": 40}').noul, False)
check("noul true survives", parse_text_answer('{"score": 40, "noul": true}').noul, True)
check("a string noul survives", parse_text_answer('{"score": 40, "noul": "true"}').noul, True)

# ---- C. one retry, and only while the budget still holds it ---------------

class FakeDeepClient:
    """Deep client whose replies are fixed strings, in order."""

    def __init__(self, replies, delay=0.0):
        self.replies = list(replies)
        self.delay = delay
        self.bodies = []
        self.timeouts = []

    async def review(self, prompt, *, timeout_s=None, system_prompt=None, response_format=None):
        self.bodies.append(prompt)
        self.timeouts.append(timeout_s)
        if self.delay:
            await asyncio.sleep(self.delay)
        index = min(len(self.bodies) - 1, len(self.replies) - 1)
        return self.replies[index]


def judge_with(replies, budget_s, delay=0.0):
    """Return (verdict, client) of one deep judge built over the fake client."""
    raw, tmp = fixture_config()
    gw = Gateway.from_config(raw, data_dir=tmp, context=FakeCtx())
    client = FakeDeepClient(replies, delay=delay)
    gw._deep_review_client = lambda: client
    judge = gw._deep_judge_callable(budget_s)
    return asyncio.run(judge(STATE)), client


verdict, client = judge_with(["Sending pointcloud_cake.html to you now.", '{"score": 82}'], 5.0)
check("the retry makes an unreadable answer readable", verdict.score_pct, 82)
check("the retry is noted on the verdict", verdict.note, DEEP_RETRY_NOTE)
check("the retry spends exactly two requests", len(client.bodies), 2)
check("the first request is the plain frame", client.bodies[0], build_deep_body(state=STATE))
check("the second request is the retry frame", client.bodies[1], build_deep_retry_body(state=STATE))
check("the first request carries the configured budget", client.timeouts[0], 5.0)

verdict, client = judge_with(['{"score": 12, "confidence": 0.9}'], 5.0)
check("a readable first answer is not retried", len(client.bodies), 1)
check("a readable first answer is banded", verdict.score_pct, 12)
check("a readable first answer carries no retry note", verdict.note, "")

verdict, client = judge_with(["I don't have a comfyui_status tool available."], 5.0)
check("two prose answers stay unreadable", verdict.score_pct, None)
check("two prose answers spend both requests", len(client.bodies), 2)
check("an unreadable answer is never given a score", verdict.raw_score, None)

verdict, client = judge_with(["prose"], 0.05, delay=0.3)
check("an exhausted budget skips the retry", len(client.bodies), 1)
check("an exhausted budget keeps the abstention", verdict.score_pct, None)

# ---- D. the approval executes the call it names ---------------------------

raw, tmp = fixture_config()
gw = Gateway.from_config(raw, data_dir=tmp, context=FakeCtx())
check("the switch ships on", gw.config.execute_on_approval, True)

conn = gw._open_store()
SUBJECT = "asr:10001"
SESSION = "asr:FriendMessage:10001"
TOOL = "astrbot_execute_shell"
ARGS = {"command": "Get-ChildItem D:\\"}
DIGEST = args_digest(None, ARGS)

ticket = tickets.create_ticket(
    conn,
    subject_key=SUBJECT,
    session_key=SESSION,
    tool_name=TOOL,
    args_digest=DIGEST,
)
check("a ticket starts pending", ticket.state, tickets.PENDING)
tickets.transition(
    conn, ticket.ticket_id, (tickets.PENDING,), tickets.APPROVED, actor="10001"
)
check("the ticket is approved", tickets.get_ticket(conn, ticket.ticket_id).state, tickets.APPROVED)


def execute(ticket_id, *, gateway=None, deadline=None, digest_value=DIGEST, args=ARGS):
    """Run the approval execution for one ticket and return its outcome."""
    gateway = gw if gateway is None else gateway
    conn_ = gateway._open_store()
    plan = gateway_main._Plan(
        decision=Decision.SUSPENDED,
        reason="等待管理员审批",
        ticket_kind="all_abstain",
    )
    return gateway._execute_on_approval(
        conn_,
        plan,
        ticket_id=ticket_id,
        tool=TOOL,
        subject=SUBJECT,
        session=SESSION,
        args=args,
        snapshot=gateway._snapshot,
        digest_value=digest_value,
        deadline=time.monotonic() + 60 if deadline is None else deadline,
    )


outcome = execute(ticket.ticket_id)
check("the approval returns an outcome", outcome is not None, True)
check("the approval executes", outcome.decision, Decision.ALLOW_APPROVED_RETRY.value)
check("the outcome names the ticket", outcome.ticket_id, ticket.ticket_id)
check("the outcome says it executed", "已按批准直接执行" in outcome.text, True)
check("the ticket is consumed", tickets.get_ticket(conn, ticket.ticket_id).state, tickets.CONSUMED)
check(
    "the wrapper reads the decision as an allow",
    _decision(outcome),
    "allow",
)

rows = conn.execute(
    "SELECT decision, delegated, args_digest FROM audit_events WHERE ticket_id = ?",
    (ticket.ticket_id,),
).fetchall()
check("the execution is audited", [row[0] for row in rows], ["allow_approved_retry"])
check("the audited call is delegated", rows[0][1], "yes")
check("the audited row keeps the digest", rows[0][2], DIGEST)
check("a consumed approval cannot run twice", execute(ticket.ticket_id), None)

fresh_raw, fresh_tmp = fixture_config()
off_gw = Gateway.from_config(
    {**fresh_raw, "execute_on_approval": False}, data_dir=fresh_tmp, context=FakeCtx()
)
off_conn = off_gw._open_store()
off_ticket = tickets.create_ticket(
    off_conn,
    subject_key=SUBJECT,
    session_key=SESSION,
    tool_name=TOOL,
    args_digest=DIGEST,
)
tickets.transition(
    off_conn, off_ticket.ticket_id, (tickets.PENDING,), tickets.APPROVED, actor="10001"
)
check(
    "a switched-off approval does not execute",
    execute(off_ticket.ticket_id, gateway=off_gw),
    None,
)
check(
    "and the switch-off leaves the approval standing",
    tickets.get_ticket(off_conn, off_ticket.ticket_id).state,
    tickets.APPROVED,
)

tight_raw, tight_tmp = fixture_config()
tight_gw = Gateway.from_config(tight_raw, data_dir=tight_tmp, context=FakeCtx())
tight_conn = tight_gw._open_store()
tight_ticket = tickets.create_ticket(
    tight_conn,
    subject_key=SUBJECT,
    session_key=SESSION,
    tool_name=TOOL,
    args_digest=DIGEST,
)
tickets.transition(
    tight_conn,
    tight_ticket.ticket_id,
    (tickets.PENDING,),
    tickets.APPROVED,
    actor="10001",
)
check(
    "a call with no delegate budget left falls back",
    execute(
        tight_ticket.ticket_id,
        gateway=tight_gw,
        deadline=time.monotonic(),
    ),
    None,
)
check(
    "and the fallback keeps the approval for the resend",
    tickets.get_ticket(tight_conn, tight_ticket.ticket_id).state,
    tickets.APPROVED,
)
check(
    "the fallback text asks for the same arguments",
    "上一轮" in gateway_main._approval_resend_text("T") and "arguments" in
    gateway_main._approval_resend_text("T"),
    True,
)
check(
    "the fallback text names the ticket",
    "T" in gateway_main._approval_resend_text("T"),
    True,
)

# ---- E. a rewritten call after an approval is visible ---------------------

check(
    "the label exists",
    gateway_main.LABEL_CHANGED_AFTER_APPROVAL,
    "changed_after_approval",
)
label_raw, label_tmp = fixture_config()
label_gw = Gateway.from_config(label_raw, data_dir=label_tmp, context=FakeCtx())
approved_digest = args_digest(None, {"command": "a"})
rewritten_digest = args_digest(None, {"command": "b"})
allowed = gateway_main._Plan(decision=Decision.ALLOW_PASSTHROUGH, reason="放行")
label_gw._note_approval_use(SUBJECT, SESSION, TOOL, approved_digest, executed=False)
marked = label_gw._mark_changed_after_approval(
    allowed, subject=SUBJECT, session=SESSION, tool=TOOL, digest_value=rewritten_digest
)
check(
    "a rewrite of a standing approval is labelled",
    gateway_main.LABEL_CHANGED_AFTER_APPROVAL in marked.labels,
    True,
)
check(
    "the same arguments are not a rewrite",
    label_gw._mark_changed_after_approval(
        allowed, subject=SUBJECT, session=SESSION, tool=TOOL, digest_value=approved_digest
    ).labels,
    (),
)
label_gw._note_approval_use(SUBJECT, SESSION, TOOL, approved_digest, executed=True)
check(
    "an executed approval makes the next call a new call",
    label_gw._mark_changed_after_approval(
        allowed, subject=SUBJECT, session=SESSION, tool=TOOL, digest_value=rewritten_digest
    ).labels,
    (),
)
label_gw._note_approval_use(SUBJECT, SESSION, TOOL, approved_digest, executed=False)
label_gw._clock = lambda: time.monotonic() + gateway_main.APPROVAL_RETRY_TTL_S + 1
check(
    "an approval past its window labels nothing",
    label_gw._mark_changed_after_approval(
        allowed, subject=SUBJECT, session=SESSION, tool=TOOL, digest_value=rewritten_digest
    ).labels,
    (),
)
label_gw._clock = time.monotonic
check(
    "a refusal is never relabelled",
    label_gw._mark_changed_after_approval(
        gateway_main._Plan(decision=Decision.SUSPENDED, reason="等待"),
        subject=SUBJECT,
        session=SESSION,
        tool=TOOL,
        digest_value=rewritten_digest,
    ).labels,
    (),
)

# ---- F. wiring and version ----------------------------------------------

source = (ROOT / "tooling_guard" / "main.py").read_text(encoding="utf-8")
check("the waiter executes the approval", "self._execute_on_approval(" in source, True)
check("the executed text exists", "REASON_APPROVED_EXECUTED" in source, True)
check("the retry is one retry", "build_deep_retry_body(" in source, True)
check("the version is bumped", __version__, "0.7.3")
metadata = (ROOT / "metadata.yaml").read_text(encoding="utf-8")
check("the metadata ships the version", "version: 0.7.3" in metadata, True)
changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
check("the changelog names the release", "## 0.7.3" in changelog, True)
schema_text = (ROOT / "_conf_schema.json").read_text(encoding="utf-8")
check("the switch is documented in the config page", "execute_on_approval" in schema_text, True)

print("%d checks, %d failed" % (ok, fail))
if fail:
    raise SystemExit(1)
print("ALL CHECKS PASSED")
