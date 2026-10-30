"""0.6.2 checks: administrator platform resolution, delivery attempts, low-confidence abstention, ticket detail context."""
from __future__ import annotations
import pathlib as _pathlib, sys as _sys
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
from _bootstrap import fixture_config  # noqa: E402,F401  (puts the repo root on sys.path)

import asyncio
from types import SimpleNamespace

from tooling_guard.jev import score as fast_score
from tooling_guard.notify import sender
from tooling_guard.web import queries
from tooling_guard.triage.decisions import Decision

FAILED = 0
TOTAL = 0


def check(label, got, want):
    global FAILED, TOTAL
    TOTAL += 1
    if got != want:
        FAILED += 1
        print("FAIL", label, "got", repr(got), "want", repr(want))


class Meta:
    def __init__(self, pid):
        self.id = pid


class Inst:
    def __init__(self, pid):
        self._pid = pid

    def meta(self):
        return Meta(self._pid)


class Manager:
    def __init__(self, pids):
        self.platform_insts = [Inst(p) for p in pids]


class Host:
    def __init__(self, pids, answers=True):
        self.platform_manager = Manager(pids)
        self.sent = []
        self.answers = answers

    async def send_message(self, session, chain):
        self.sent.append(session)
        if isinstance(self.answers, dict):
            return self.answers.get(session, False)
        return self.answers


# --- host_platforms / delivery_platforms ---
host = Host(["webchat", "asr"])
check("host_platforms reads meta ids", sender.host_platforms(host), ("webchat", "asr"))
check("host with no manager", sender.host_platforms(object()), ())
check(
    "panel platform is never a candidate",
    sender.delivery_platforms(host, platform_id="webchat"),
    ("asr",),
)
check(
    "chat platform stays first",
    sender.delivery_platforms(host, platform_id="asr"),
    ("asr",),
)
check(
    "two chat platforms keep hint order",
    sender.host_platforms(Host(["webchat", "asr", "tg"])),
    ("webchat", "asr", "tg"),
)

# --- admin_sessions ---
check(
    "bare id expands over chat platforms only",
    sender.admin_sessions("1234567", context=host, platform_id="webchat"),
    ("asr:FriendMessage:1234567",),
)
check(
    "explicit origin is never re-guessed",
    sender.admin_sessions("asr:FriendMessage:1", context=host, platform_id="webchat"),
    ("asr:FriendMessage:1",),
)
check(
    "no platform at all resolves nothing",
    sender.admin_sessions("1234567", context=Host(["webchat"]), platform_id="webchat"),
    (),
)

# --- build_sender over a bare id triggered from the panel ---
async def delivery_cases():
    host = Host(["webchat", "asr"], answers=True)
    send = sender.build_sender(host, platform_id="webchat")
    check("delivery over the chat account succeeds", await send("1234567", "hi"), True)
    check("delivery used the qq origin", host.sent, ["asr:FriendMessage:1234567"])
    check(
        "attempts record the origin",
        sender.delivery_attempts(send),
        ({"admin": "1234567", "target": "asr:FriendMessage:1234567", "result": "private"},),
    )

    panel = Host(["webchat"], answers=True)
    send2 = sender.build_sender(panel, platform_id="webchat")
    check("a panel-only host delivers nothing", await send2("1234567", "hi"), False)
    check("a panel-only host sends nothing", panel.sent, [])
    check(
        "panel host reports no target",
        sender.delivery_attempts(send2),
        ({"admin": "1234567", "target": "", "result": "no_platform"},),
    )

    explicit = Host(["webchat", "asr"], answers=True)
    send3 = sender.build_sender(explicit, platform_id="")
    check("an explicit panel origin is refused", await send3("webchat:FriendMessage:1", "hi"), False)
    check(
        "an explicit panel origin is marked ephemeral",
        sender.delivery_attempts(send3),
        ({"admin": "webchat:FriendMessage:1", "target": "webchat:FriendMessage:1", "result": "ephemeral"},),
    )

    fallback = Host(["webchat", "asr"], answers={"asr:FriendMessage:1234567": False})
    send4 = sender.build_sender(fallback, platform_id="asr")
    check("a rejected chat origin is not delivery", await send4("1234567", "hi"), False)
    check(
        "a rejected chat origin is recorded",
        sender.delivery_attempts(send4),
        ({"admin": "1234567", "target": "asr:FriendMessage:1234567", "result": "rejected"},),
    )


asyncio.run(delivery_cases())

# --- low confidence abstains (0.6.2) ---
thresholds = fast_score.FastThresholds(allow_score=40, block_score=75, min_confidence=0.6)
confident_low = fast_score.FastVerdict(score_pct=10, noul=False, raw_score=10, band="x", note="", confidence=0.9)
nervous_low = fast_score.FastVerdict(score_pct=10, noul=False, raw_score=10, band="x", note="", confidence=0.2)
nervous_high = fast_score.FastVerdict(score_pct=90, noul=False, raw_score=90, band="x", note="", confidence=0.2)
confident_high = fast_score.FastVerdict(score_pct=90, noul=False, raw_score=90, band="x", note="", confidence=0.9)
middle = fast_score.FastVerdict(score_pct=55, noul=False, raw_score=55, band="x", note="", confidence=0.9)
check("confident low score allows", fast_score.decide(confident_low, thresholds), Decision.ALLOW_FAST)
check("nervous low score abstains", fast_score.decide(nervous_low, thresholds), None)
check("nervous high score abstains", fast_score.decide(nervous_high, thresholds), None)
check("confident high score denies", fast_score.decide(confident_high, thresholds), Decision.DENY_JUDGE)
check("middle band abstains", fast_score.decide(middle, thresholds), None)

# --- ticket detail picks the row that carries a summary ---
def row(idx, decision, summary=None):
    return {"id": idx, "decision": decision, "summary_json": summary}

rows = [
    row(841, "allow_approved_retry", '{"tool": "web_search_tavily"}'),
    row(840, "allow_approved_retry", None),
    row(839, "suspended", None),
    row(838, "suspended", '{"tool": "web_search_tavily", "review": {}}'),
]
picked = queries.pick_ticket_event(rows)
check("the suspended row with a summary wins", picked and picked["id"], 838)
check("a bare suspended row still wins over a newer side row", queries.pick_ticket_event(rows[1:3])["id"], 839)
check("a readable row beats a bare suspended row", queries.pick_ticket_event([row(1, "suspended", None), row(2, "allow", '{"tool": "x"}')])["id"], 2)
check("no rows picks nothing", queries.pick_ticket_event([]), None)
check(
    "an unreadable summary still picks a row",
    queries.pick_ticket_event([row(1, "suspended", None), row(2, "suspended", "{bad")])["id"],
    1,
)

print(f"{TOTAL} checks, {FAILED} failed")
if FAILED:
    raise SystemExit(1)
print("ALL CHECKS PASSED")
