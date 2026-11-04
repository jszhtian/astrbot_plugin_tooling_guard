"""0.7.4 checks: a reply names its ticket, and a refusal says so.


Requirement: Reply Approval Channel; Quoted Reply Resolution; Approver
Authorization.

Two failures share this release:

* a bare 同意 used to approve "the only pending ticket", a statement about the
  whole system rather than about the administrator who typed it -- and since
  0.7.3 an approval executes the call, so the mis-approval became a mis-execution;
* the reply channel refused a sender by returning None, which the host reads as
  "not my message" and hands to the model, so the administrator never learned
  that nothing happened.

The fix for the first is not "ask for a code": the notice can be *quoted*, and
aiocqhttp turns the quoted message into a Reply component, so the reply itself
carries the ticket. These checks pin the resolution order, the silent cases that
must stay silent, the visible refusal, and the one-audit-row-per-decision rule.
"""
import asyncio
import logging
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _bootstrap import ROOT, fixture_config  # noqa: E402


def _stub_host():
    """Install the minimal astrbot.api surface the proxy module imports."""
    api = types.ModuleType("astrbot.api")
    api.FunctionTool = object
    api.logger = logging.getLogger("verify_074")
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
from tooling_guard.main import Gateway  # noqa: E402
from tooling_guard.store import db, notices, tickets  # noqa: E402
from tooling_guard.ui import commands, reply_approval  # noqa: E402

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


class ChatType:
    """Stand-in for AstrBot's MessageType member."""

    def __init__(self, value):
        self.value = value


class Reply:
    """Stand-in for astrbot.api.message_components.Reply (matched by name)."""

    def __init__(self, message_str):
        self.message_str = message_str
        self.text = None
        self.chain = ()


class Text:
    """Stand-in for a Plain component inside an incoming chain."""

    def __init__(self, text):
        self.text = text


class FakeEvent:
    """One host message event the reply channel can read."""

    def __init__(self, *, text="", chat="FriendMessage", admin=True, sender="1234567",
                 quote=""):
        self.message_str = text
        self.plain_result = lambda value: value
        self.unified_msg_origin = "aiocqhttp:GroupMessage:999" if chat == "GroupMessage" else "aiocqhttp:FriendMessage:1234567"
        self._chat = chat
        self._admin = admin
        self._sender = sender
        self._quote = quote
        self.stopped = False

    def get_platform_id(self):
        return "aiocqhttp"

    def get_sender_id(self):
        return self._sender

    def get_message_type(self):
        return ChatType(self._chat)

    def is_admin(self):
        if isinstance(self._admin, Exception):
            raise self._admin
        return self._admin

    def get_messages(self):
        chain = []
        if self._quote:
            chain.append(Reply(self._quote))
        chain.append(Text(self.message_str))
        return chain

    def stop_event(self):
        self.stopped = True


ADMIN = "1234567"
NOTICE = (
    "[工具网关] 挂起等待（不是拒绝），等你决定｜票据：4cd67595-1111-2222-3333-444455556666\n"
    "工具：astrbot_execute_shell\n"
    "回复「同意 4cd67595」批准或「拒绝 4cd67595 原因」拒绝\n"
    "等价命令「/guard approve 4cd67595-1111-2222-3333-444455556666」"
)


class FakeRegistry:
    """Registry whose resolve() reports whether a waiter took the decision."""

    def __init__(self, woke):
        self.woke = woke

    def resolve(self, ticket_id, decision):
        return self.woke


# A live requester is normally still blocked on the ticket, so an approval lands
# to a waiter and the ticket stays APPROVED; without one the store withdraws the
# unconsumable approval. Tests assert the live shape by default.
_WOKEN = FakeRegistry(True)


def make_gateway(**overrides):
    """Return (gateway, connection) over a fresh fixture store."""
    raw, tmp = fixture_config()
    raw.update(overrides)
    gw = Gateway.from_config(raw, data_dir=tmp, context=FakeCtx())
    return gw, gw._open_store()


def new_ticket(conn, *, digest="a" * 32, tool="astrbot_execute_shell"):
    """Create one pending ticket and return it."""
    return tickets.create_ticket(
        conn,
        subject_key="aiocqhttp:10001",
        session_key="aiocqhttp:GroupMessage:123456789",
        tool_name=tool,
        args_digest=digest,
    )


def reply(gw, event, text, **kwargs):
    """Run one reply through the channel."""
    kwargs.setdefault("registry", _WOKEN)
    return reply_approval.handle_reply(text, gw, event, **kwargs)


# ---- A. the schema records which administrator was told ---------------------

gw, conn = make_gateway()
versions = [row[0] for row in conn.execute("SELECT version FROM schema_version")]
check("the migration reaches schema 2", max(versions), 2)
check("the table exists", "notice_deliveries" in [
    row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
], True)
check("TABLES names the new table", "notice_deliveries" in db.TABLES, True)

ticket = new_ticket(conn)
written = notices.record_deliveries(
    conn,
    ticket.ticket_id,
    [
        {"admin": ADMIN, "target": "aiocqhttp:FriendMessage:1234567", "result": "private"},
        {"admin": "9999999", "target": "aiocqhttp:FriendMessage:9999999", "result": "rejected"},
        {"admin": "8888888", "target": "", "result": "no_platform"},
    ],
)
check("only a real delivery is recorded", written, 1)
check("the delivered ticket is a candidate",
      notices.delivered_ticket_ids(conn, ADMIN), [ticket.ticket_id])
notices.record_deliveries(
    conn,
    ticket.ticket_id,
    [{"admin": ADMIN, "target": "aiocqhttp:FriendMessage:1234567", "result": "private"}],
    sent_at="2026-11-04T10:00:00Z",
)
rows = conn.execute(
    "SELECT sent_at FROM notice_deliveries WHERE ticket_id = ? AND admin = ?",
    (ticket.ticket_id, ADMIN),
).fetchall()
check("a repeated delivery replaces the earlier row", [r[0] for r in rows],
      ["2026-11-04T10:00:00Z"])
check("a rejected delivery names no candidate",
      notices.delivered_ticket_ids(conn, "9999999"), [])
tickets.transition(conn, ticket.ticket_id, (tickets.PENDING,), tickets.DENIED, actor=ADMIN)
check("a decided ticket is not a candidate",
      notices.delivered_ticket_ids(conn, ADMIN), [])

# ---- B. a quoted notice names the ticket with no code at all ----------------

gw, conn = make_gateway()
one = new_ticket(conn, digest="b" * 32)
notices.record_deliveries(
    conn, one.ticket_id, [{"admin": ADMIN, "target": "aiocqhttp:FriendMessage:1234567",
                           "result": "private"}]
)
event = FakeEvent(text="同意", quote="[工具网关] 挂起等待｜票据：" + one.ticket_id)
text = reply(gw, event, "同意")
check("a quoted notice is decided", text.startswith("已批准"), True)
check("the quoted ticket is the one decided",
      tickets.get_ticket(conn, one.ticket_id).state, tickets.APPROVED)

# ---- C. a quoted notice works in a group chat too ---------------------------

gw, conn = make_gateway()
group_ticket = new_ticket(conn, digest="c" * 32)
event = FakeEvent(text="同意", chat="GroupMessage",
                  quote="票据：" + group_ticket.ticket_id)
text = reply(gw, event, "同意")
check("a group quote decides", text.startswith("已批准"), True)
check("the group quote decides that ticket",
      tickets.get_ticket(conn, group_ticket.ticket_id).state, tickets.APPROVED)

# ---- D. a bare 同意 in a group decides nothing ------------------------------

gw, conn = make_gateway()
bare = new_ticket(conn, digest="d" * 32)
event = FakeEvent(text="同意", chat="GroupMessage")
check("a bare group 同意 is not consumed", reply(gw, event, "同意"), None)
check("and the ticket is untouched",
      tickets.get_ticket(conn, bare.ticket_id).state, tickets.PENDING)

# ---- E. a bare 同意 in private chat uses what was delivered ----------------

gw, conn = make_gateway()
mine = new_ticket(conn, digest="e" * 32)
other = new_ticket(conn, digest="f" * 32)
notices.record_deliveries(
    conn, mine.ticket_id, [{"admin": ADMIN, "target": "aiocqhttp:FriendMessage:1234567",
                            "result": "private"}]
)
text = reply(gw, FakeEvent(text="同意"), "同意")
check("the delivered ticket is decided", text.startswith("已批准"), True)
check("it decides the delivered one and not the other",
      (tickets.get_ticket(conn, mine.ticket_id).state,
       tickets.get_ticket(conn, other.ticket_id).state),
      (tickets.APPROVED, tickets.PENDING))

# ---- F. a bare 同意 with nothing delivered decides nothing ------------------

gw, conn = make_gateway()
lonely = new_ticket(conn, digest="1" * 32)
text = reply(gw, FakeEvent(text="同意"), "同意")
check("a bare 同意 does not settle the only pending ticket",
      tickets.get_ticket(conn, lonely.ticket_id).state, tickets.PENDING)
check("and it says so", "本次未做任何操作" in text, True)
check("the hint leads with quoting", "引用" in text, True)
check("the hint names the short code", lonely.ticket_id[:8] in text, True)

# ---- G. a short code still works, and it must be long enough ---------------

gw, conn = make_gateway()
coded = new_ticket(conn, digest="2" * 32)
text = reply(gw, FakeEvent(text="同意 " + coded.ticket_id[:8]),
             "同意 " + coded.ticket_id[:8])
check("a short code decides", text.startswith("已批准"), True)
check("the coded ticket is approved",
      tickets.get_ticket(conn, coded.ticket_id).state, tickets.APPROVED)

gw, conn = make_gateway()
short_ticket = new_ticket(conn, digest="3" * 32)
too_short = short_ticket.ticket_id[:3]
check("three characters are not a reference",
      reply_approval.parse_reply("同意 " + too_short).ref, "")
check("the minimum prefix is the documented one", reply_approval.MIN_PREFIX, 4)
check("the reference pattern enforces it",
      reply_approval._REFERENCE.match("abcd") is not None, True)
check("a two-character token is not a reference",
      reply_approval._REFERENCE.match("ab"), None)
text = reply(gw, FakeEvent(text="同意 " + too_short), "同意 " + too_short)
check("a stub code approves nothing",
      tickets.get_ticket(conn, short_ticket.ticket_id).state, tickets.PENDING)

# ---- H. an unknown code is answered, not swallowed -------------------------

gw, conn = make_gateway()
new_ticket(conn, digest="4" * 32)
text = reply(gw, FakeEvent(text="同意 deadbeef"), "同意 deadbeef")
check("an unknown code is answered", "没有找到以 deadbeef 开头的待批票据" in text, True)

# ---- I. the gate refusal is visible to the administrator -------------------

gw, conn = make_gateway()
new_ticket(conn, digest="5" * 32)
text = reply(gw, FakeEvent(text="同意", admin=False), "同意")
check("宿主管理员为否时给出可见拒绝", text is not None, True)
check("and it names the host condition", "宿主未把你判为管理员" in text, True)
check("it does not name the allowlist", "插件 admins 名单里没有你" in text, False)

text = reply(gw, FakeEvent(text="同意", sender="7777777", admin=True), "同意")
check("插件名单未命中时给出可见拒绝", text is not None, True)
check("and it names the allowlist", "插件 admins 名单里没有你" in text, True)
check("it does not blame the host", "宿主未把你判为管理员" in text, False)

check("a stranger's 同意 stays silent",
      reply(gw, FakeEvent(text="同意", sender="7777777", admin=False), "同意"), None)
check("a group stranger's 同意 stays silent",
      reply(gw, FakeEvent(text="同意", sender="7777777", admin=False,
                          chat="GroupMessage"), "同意"), None)

# ---- J. one decision, one audit row ---------------------------------------

gw, conn = make_gateway()
woken = new_ticket(conn, digest="6" * 32)
commands.decide_ticket(gw, woken.ticket_id, approve=True, actor=ADMIN,
                       registry=FakeRegistry(True))
rows = conn.execute(
    "SELECT decision FROM audit_events WHERE ticket_id = ?", (woken.ticket_id,)
).fetchall()
check("the woken path writes no decision row of its own", [r[0] for r in rows], [])
check("the state still moved",
      tickets.get_ticket(conn, woken.ticket_id).state, tickets.APPROVED)

idle = new_ticket(conn, digest="7" * 32)
commands.decide_ticket(gw, idle.ticket_id, approve=True, actor=ADMIN,
                       registry=FakeRegistry(False))
rows = conn.execute(
    "SELECT decision, rule_id FROM audit_events WHERE ticket_id = ?", (idle.ticket_id,)
).fetchall()
check("the waiter-less path keeps its row", [r[0] for r in rows],
      ["allow_approved_retry"])
check("and names the approval rule", rows[0][1], "guard_admin_approve")

retry_text = commands.decide_ticket(
    gw, new_ticket(conn, digest="8" * 32).ticket_id, approve=True, actor=ADMIN,
    registry=FakeRegistry(False),
).message
check("the text no longer promises a bare retry",
      "批准窗口内可重试一次" in retry_text, False)
check("the waiter-less text says the window was withdrawn",
      "重试窗口已撤回" in retry_text, True)

live_text = commands.decide_ticket(
    gw, new_ticket(conn, digest="9" * 32).ticket_id, approve=True, actor=ADMIN,
    registry=FakeRegistry(True),
).message
check("the woken text says the call runs now",
      "按批准的参数执行" in live_text, True)

# ---- K. parse_reply still refuses non-decisions ----------------------------

check("a normal sentence is not a decision", reply_approval.parse_reply("这个是干啥的"), None)
check("a slash command is not a decision", reply_approval.parse_reply("/guard stats"), None)
check("an approval is parsed", reply_approval.parse_reply("同意").approve, True)
check("a denial is parsed", reply_approval.parse_reply("拒绝 太危险").approve, False)
check("the denial keeps its reason",
      reply_approval.parse_reply("拒绝 4cd67595 太危险").reason, "太危险")
check("the approval keeps the code",
      reply_approval.parse_reply("同意 4cd67595").ref, "4cd67595")
check("a quoted notice is read from the chain",
      reply_approval.quoted_text(FakeEvent(text="同意", quote="票据：abc")) == "票据：abc",
      True)
check("a message without a quote reads as empty",
      reply_approval.quoted_text(FakeEvent(text="同意")), "")

# ---- L. wiring and version ------------------------------------------------

source = (ROOT / "tooling_guard" / "ui" / "reply_approval.py").read_text(encoding="utf-8")
check("the global unique fallback is gone", "elif len(pending) == 1" in source, False)
check("the deliveries are consulted", "notices.delivered_ticket_ids" in source, True)
main_source = (ROOT / "tooling_guard" / "main.py").read_text(encoding="utf-8")
check("deliveries are recorded at the send boundary",
      "notices.record_deliveries(" in main_source, True)
check("the version is bumped", __version__, "0.7.4")
metadata = (ROOT / "metadata.yaml").read_text(encoding="utf-8")
check("the metadata ships the version", "version: 0.7.4" in metadata, True)
changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
check("the changelog names the release", "## 0.7.4" in changelog, True)

print("%d checks, %d failed" % (ok, fail))
if fail:
    raise SystemExit(1)
print("ALL CHECKS PASSED")
