"""0.7.5 checks: a ticket records why it exists and how it ended.

Requirement: Ticket Lifecycle; Operator Introspection.

Two gaps survived 0.7.4 and both were invisible from the dashboard:

* the reason word a suspension was opened with ("model_deny" / "all_abstain")
  lived only in the notice text and in the audit row, so the ticket endpoint
  could not answer "why was this ticket opened";
* a ticket consumed by an approval-then-execute never left the consumed state:
  the gateway wrote its decision before the tool ran and had no way to learn the
  outcome, so result_summary and completed_at stayed empty forever.

These checks pin the persisted kind, the migration that adds the column to an
older file, and the closing hook -- including the rule that bookkeeping never
turns into authorization.
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
    api.logger = logging.getLogger("verify_075")
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
from tooling_guard.interface import wrapper  # noqa: E402
from tooling_guard.main import Gateway  # noqa: E402
from tooling_guard.store import db, tickets  # noqa: E402
from tooling_guard.web import queries  # noqa: E402

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


def make_gateway(**overrides):
    """Return (gateway, connection) over a fresh fixture store."""
    raw, tmp = fixture_config()
    raw.update(overrides)
    gw = Gateway.from_config(raw, data_dir=tmp, context=FakeCtx())
    return gw, gw._open_store()


def new_ticket(conn, *, digest="a" * 32, kind=None, tool="astrbot_execute_shell"):
    """Create one pending ticket and return it."""
    return tickets.create_ticket(
        conn,
        subject_key="aiocqhttp:10001",
        session_key="aiocqhttp:GroupMessage:123456789",
        tool_name=tool,
        args_digest=digest,
        ticket_kind=kind,
    )


class Outcome:
    """Stand-in for the gateway CallOutcome the proxy hands back."""

    def __init__(self, ticket_id=None, decision="allow_approved_retry"):
        self.decision = decision
        self.ticket_id = ticket_id
        self.state = "approved"


# ---- A. the schema carries the column on a fresh file ----------------------

gw, conn = make_gateway()
columns = [row[1] for row in conn.execute("PRAGMA table_info(tickets)")]
check("SCHEMA_VERSION is 3", db.SCHEMA_VERSION, 3)
check("tickets carries ticket_kind", "ticket_kind" in columns, True)
versions = [row[0] for row in conn.execute("SELECT version FROM schema_version")]
check("the migration records version 3", max(versions), 3)

# ---- B. create_ticket persists the reason word -----------------------------

kinned = new_ticket(conn, digest="b" * 32, kind="model_deny")
check("kind round-trips through the store",
      tickets.get_ticket(conn, kinned.ticket_id).ticket_kind, "model_deny")
plain = new_ticket(conn, digest="c" * 32)
check("no kind stays None",
      tickets.get_ticket(conn, plain.ticket_id).ticket_kind, None)
try:
    new_ticket(conn, digest="d" * 32, kind="")
    rejected = False
except ValueError:
    rejected = True
check("an empty kind is refused", rejected, True)

# ---- C. the dashboard view exposes it --------------------------------------

view = queries.serialize_ticket(gw, tickets.get_ticket(conn, kinned.ticket_id))
check("the wire form carries the keyword", view.get("ticket_kind"), "model_deny")
view2 = queries.serialize_ticket(gw, tickets.get_ticket(conn, plain.ticket_id))
check("and stays empty when there is none", view2.get("ticket_kind"), None)

# ---- D. the closing hook records how the approved call ended ---------------

gw, conn = make_gateway()
ran = new_ticket(conn, digest="e" * 32)
gw.note_call_result(Outcome(ran.ticket_id), ok=True, elapsed=1.25)
check("a pending ticket is never completed by bookkeeping",
      tickets.get_ticket(conn, ran.ticket_id).state, tickets.PENDING)

tickets.transition(conn, ran.ticket_id, (tickets.PENDING,), tickets.APPROVED,
                   actor="1234567")
tickets.consume_approved(
    conn,
    ran.ticket_id,
    subject_key="aiocqhttp:10001",
    session_key="aiocqhttp:GroupMessage:123456789",
    tool_name="astrbot_execute_shell",
    args_digest="e" * 32,
)
gw.note_call_result(Outcome(ran.ticket_id), ok=True, elapsed=1.25)
done = tickets.get_ticket(conn, ran.ticket_id)
check("a consumed ticket that returned is completed", done.state, tickets.COMPLETED)
check("its result summarises the success", "成功" in (done.result_summary or ""), True)
check("and it carries a completion stamp", bool(done.completed_at), True)

failed = new_ticket(conn, digest="f" * 32)
tickets.transition(conn, failed.ticket_id, (tickets.PENDING,), tickets.APPROVED,
                   actor="1234567")
tickets.consume_approved(
    conn,
    failed.ticket_id,
    subject_key="aiocqhttp:10001",
    session_key="aiocqhttp:GroupMessage:123456789",
    tool_name="astrbot_execute_shell",
    args_digest="f" * 32,
)
gw.note_call_result(Outcome(failed.ticket_id), ok=False, error="TypeError", elapsed=0.5)
bad = tickets.get_ticket(conn, failed.ticket_id)
check("a raise still settles the ticket", bad.state, tickets.COMPLETED)
check("and names the error class", "TypeError" in (bad.result_summary or ""), True)

gw.note_call_result(Outcome(failed.ticket_id), ok=True, elapsed=9.0)
check("a second report cannot rewrite the state",
      tickets.get_ticket(conn, failed.ticket_id).state, tickets.COMPLETED)
gw.note_call_result(Outcome(None), ok=True, elapsed=0.1)
check("an outcome without a ticket is ignored", True, True)

# ---- E. the proxy reports after delegating, and never swallows a raise -----

class Inner:
    """Tool the proxy delegates to, switching between return and raise."""

    parameters = {"properties": {"command": {"type": "string"}}}
    raises = False

    async def handler(self, command):
        if self.raises:
            raise RuntimeError("boom")
        return "ok:" + command


class FakeGateway:
    """Duck-typed gateway: one allow verdict plus the closing hook."""

    def __init__(self):
        self.reports = []

    async def guard_call(self, *, inner, tool_name, args, context=None):
        return Outcome("ticket-xyz")

    def note_call_result(self, outcome, *, ok, error=None, elapsed=None):
        self.reports.append((outcome.ticket_id, ok, error))

    def remaining_seconds(self, context=None):
        return 60.0


def make_proxy(gateway, inner):
    """Build a proxy without the host FunctionTool constructor."""
    proxy = object.__new__(wrapper.ManagedToolProxy)
    proxy._inner_tool = inner
    proxy._gateway = gateway
    proxy.name = "astrbot_execute_shell"
    return proxy


async def drive():
    """Run one returning and one raising call through the proxy."""
    gateway = FakeGateway()
    inner = Inner()
    proxy = make_proxy(gateway, inner)
    value = await proxy._run_call(None, {"command": "Get-ChildItem"})
    inner.raises = True
    raised = None
    try:
        await proxy._run_call(None, {"command": "Get-ChildItem"})
    except RuntimeError as exc:
        raised = str(exc)
    return value, raised, list(gateway.reports)


value, raised, reports = asyncio.run(drive())
check("the proxy forwards the delegated value", value, "ok:Get-ChildItem")
check("a delegated raise still reaches the host", raised, "boom")
check("a success is reported as ok", reports[0], ("ticket-xyz", True, None))
check("a raise is reported with its class", reports[1], ("ticket-xyz", False, "RuntimeError"))

# ---- F. a gateway without the hook keeps working ---------------------------

class NoHook:
    """Gateway from an older version: no closing hook at all."""

    async def guard_call(self, *, inner, tool_name, args, context=None):
        return Outcome("ticket-abc")


async def drive_bare():
    """Run one call against a gateway that has no hook."""
    inner = Inner()
    proxy = make_proxy(NoHook(), inner)
    return await proxy._run_call(None, {"command": "x"})


check("a missing hook is not an error", asyncio.run(drive_bare()), "ok:x")

# ---- G. the release names itself ------------------------------------------

check("the version is bumped", __version__, "0.7.5")
metadata = (ROOT / "metadata.yaml").read_text(encoding="utf-8")
check("the metadata ships the version", "version: 0.7.5" in metadata, True)
changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
check("the changelog names the release", "## 0.7.5" in changelog, True)

print("%d checks, %d failed (0.7.5)" % (ok + fail, fail))
if fail:
    raise SystemExit(1)
print("ALL CHECKS PASSED")
