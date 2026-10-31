"""0.6.9 checks: the unmanaged-side notice has a switch, and only the notice.

Requirement: Unmanaged Side Sources.  A cron wake-up reaches the tools outside
the managed proxy, so every tool call it makes is observed and announced to the
administrators one private message at a time.  An operator who reads the audit
trail does not need to be paged for each of them, so the delivery is switchable.
The switch stops the notice alone: the audit row is still written and no
judgement changes, which is what these checks pin down.
"""
import asyncio
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _bootstrap import fixture_config  # noqa: E402

from tooling_guard import observation as obs_mod  # noqa: E402
from tooling_guard.main import Gateway  # noqa: E402
from tooling_guard.observation import (  # noqa: E402
    KIND_CRON,
    SIDE_NOTICE_DISABLED_REASON,
    Observation,
    SideObserver,
    render_side_notice,
)

ok = fail = 0


def check(name, got, want):
    """Count one assertion."""
    global ok, fail
    if got == want:
        ok += 1
    else:
        fail += 1
        print("FAIL %-56s got=%r want=%r" % (name, got, want))


TITLE = "[工具网关] 未纳管侧的工具调用已被观察"


class FakeCtx:
    """Minimal AstrBot context: the gateway only needs a sender."""

    async def send_message(self, *a, **k):
        return True

    async def llm_generate(self, **k):
        return "{}"


class Recorder:
    """Sender that records what would have been delivered."""

    def __init__(self):
        self.sent = []

    async def __call__(self, admin, message):
        self.sent.append((admin, message))
        return True


def observation():
    """Return one cron-side observation to alert on."""
    return Observation(
        kind=KIND_CRON,
        tool_name="search_qq_chat_history",
        subject_key="aiocqhttp:10001",
        session_key="aiocqhttp:GroupMessage:123456789",
        decision=obs_mod.DECISION_OBSERVED,
        degraded=False,
        summary_line="search_qq_chat_history {}",
    )


# ---- A. the configuration key -------------------------------------------
raw, tmp = fixture_config()
gw = Gateway.from_config(raw, data_dir=tmp, context=FakeCtx())
check("fixture config builds a gateway", gw.validation.enabled, True)
check("the switch ships on", gw.config.side_notice_enabled, True)

defaulted = dict(raw)
defaulted.pop("side_notice_enabled", None)
gw_default = Gateway.from_config(defaulted, data_dir=tmp, context=FakeCtx())
check("an absent key keeps the notice on", gw_default.config.side_notice_enabled, True)

off = dict(raw)
off["side_notice_enabled"] = False
gw_off = Gateway.from_config(off, data_dir=tmp, context=FakeCtx())
check("false is honoured", gw_off.config.side_notice_enabled, False)
check("the gateway still runs with it off", gw_off.validation.enabled, True)

bad = dict(raw)
bad["side_notice_enabled"] = "no"
gw_bad = Gateway.from_config(bad, data_dir=tmp, context=FakeCtx())
check("a non-bool is refused", gw_bad.validation.enabled, False)
check(
    "and the issue names the key",
    [i.key for i in gw_bad.validation.warnings],
    ["side_notice_enabled"],
)

# ---- B. the switch gates the notice --------------------------------------


async def alert_with(enabled, admins=("10001",)):
    """Alert one observation with the switch in the given position."""
    sender = Recorder()
    observer = SideObserver(
        context=FakeCtx(),
        admins=admins,
        sender=sender,
        side_notice_enabled=enabled,
    )
    result = await observer.alert(observation())
    return result, sender


quiet, quiet_sender = asyncio.run(alert_with(False))
check("off sends nothing", len(quiet_sender.sent), 0)
check("off says why", quiet.skipped, SIDE_NOTICE_DISABLED_REASON)
check("off is not an alert", quiet.alerted, False)
check("the marker is stable text", SIDE_NOTICE_DISABLED_REASON, "side_notice_disabled")
check("the marker is exported", "SIDE_NOTICE_DISABLED_REASON" in obs_mod.__all__, True)

loud, loud_sender = asyncio.run(alert_with(True))
check("on delivers once", len(loud_sender.sent), 1)
check("on reaches the administrator", loud_sender.sent[0][0], "10001")
check("on is an alert", loud.alerted, True)
check("on leaves nothing skipped", loud.skipped, "")
check("the notice keeps its title", loud_sender.sent[0][1].splitlines()[0], TITLE)

no_admin, no_admin_sender = asyncio.run(alert_with(True, admins=()))
check("the switch is checked before the audience", len(no_admin_sender.sent), 0)
check("an empty audience still explains itself", no_admin.skipped, "no admin configured")

# ---- C. the switch touches the notice and nothing else -------------------
plain = render_side_notice(observation())
check("the notice text is unchanged", plain.splitlines()[0], TITLE)
check("the notice still states the coverage gap", "不在本网关拦截范围内" in plain, True)

record_src = inspect.getsource(SideObserver.record)
check("recording ignores the switch", "_side_notice_enabled" in record_src, False)
observe_src = inspect.getsource(SideObserver.observe)
check("observing ignores the switch", "_side_notice_enabled" in observe_src, False)

# ---- D. the plugin wires the configured value ----------------------------
src = (Path(__file__).resolve().parent.parent / "main.py").read_text(encoding="utf-8")
check(
    "the plugin passes the configured switch",
    'side_notice_enabled=bool(getattr(config, "side_notice_enabled", True)),' in src,
    True,
)

print("%d checks, %d failed" % (ok, fail))
if fail:
    raise SystemExit(1)
print("ALL CHECKS PASSED")
