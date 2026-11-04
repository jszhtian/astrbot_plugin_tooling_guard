"""0.7.2 checks: a pending ticket's notice is never merged away.

Requirement: Rate Limiting and Merging; Ticket Notice Is Never Merged Away;
Notification Delivery Failure.

A notification the limiter folds into an earlier one is a ticket nobody is told
about: it waits out its whole window and times out.  The degraded class shares a
ten-minute window per requester, and it used to drop the ticket from the key, so
a second suspension of the same tool inside ten minutes produced no private
message and no audit row at all.  These checks pin down that a pending notice is
keyed by its ticket, that a non-pending degraded alert still merges, and that a
suppressed notice leaves a notify_merged row behind.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _bootstrap import ROOT  # noqa: E402

from tooling_guard import __version__  # noqa: E402
from tooling_guard.notify.ratelimit import (  # noqa: E402
    DEGRADED_CLASS,
    NotifyRateLimiter,
    limit_key,
)
from tooling_guard import main as gateway_main  # noqa: E402
from tooling_guard.main import Gateway  # noqa: E402

ok = fail = 0


def check(name, got, want):
    """Count one assertion."""
    global ok, fail
    if got == want:
        ok += 1
    else:
        fail += 1
        print("FAIL %-58s got=%r want=%r" % (name, got, want))


# ---- the key keeps the ticket exactly when an answer is being asked for ----

ticket_a = limit_key(
    subject="webchat:probe",
    tool_name="astrbot_execute_python",
    mode="enforce",
    decision="suspended",
    degraded="fast_low_confidence",
    ticket_id="A",
    pending=True,
)
check("a degraded pending notice is classed degraded", ticket_a[3], DEGRADED_CLASS)
check("a pending notice keeps its ticket", ticket_a[4], "A")
check(
    "a pending notice keeps its ticket even while degraded",
    limit_key(
        subject="s",
        tool_name="t",
        mode="enforce",
        decision="suspended",
        degraded="judge_abstained",
        ticket_id="B",
        pending=True,
    )[4],
    "B",
)
check(
    "an alert keeps the shared degraded class",
    limit_key(
        subject="s",
        tool_name="hook",
        mode="enforce",
        decision="suspended",
        degraded="base_check_disabled",
    )[4],
    "",
)
check(
    "an ordinary notice keeps its ticket without the flag",
    limit_key(
        subject="s",
        tool_name="t",
        mode="enforce",
        decision="suspended",
        ticket_id="C",
    )[4],
    "C",
)

# ---- a second pending ticket inside the window is still delivered ----

limiter = NotifyRateLimiter()
first = limiter.admit(
    subject="webchat:probe",
    tool_name="astrbot_execute_python",
    mode="enforce",
    decision="suspended",
    degraded="fast_low_confidence",
    ticket_id="T1",
    pending=True,
    now=100.0,
)
second = limiter.admit(
    subject="webchat:probe",
    tool_name="astrbot_execute_python",
    mode="enforce",
    decision="suspended",
    degraded="fast_low_confidence",
    ticket_id="T2",
    pending=True,
    now=695.0,
)
check("the first pending notice is sent", first.send, True)
check("a new pending ticket inside the degraded window is sent", second.send, True)
check("the two tickets do not share one window class", second.window_s, 600.0)

repeat = limiter.admit(
    subject="webchat:probe",
    tool_name="astrbot_execute_python",
    mode="enforce",
    decision="suspended",
    degraded="fast_low_confidence",
    ticket_id="T2",
    pending=True,
    now=700.0,
)
check("a repeat notice of the same ticket is merged", repeat.send, False)

later = limiter.admit(
    subject="webchat:probe",
    tool_name="astrbot_execute_python",
    mode="enforce",
    decision="suspended",
    degraded="judge_abstained",
    ticket_id="T3",
    pending=True,
    now=1290.0,
)
check("a third ticket 590 s later is sent", later.send, True)

# ---- an alert that asks nobody still respects the window ----

alert_limiter = NotifyRateLimiter()
alert_first = alert_limiter.admit(
    subject="webchat:probe",
    tool_name="on_llm_request",
    mode="enforce",
    decision="suspended",
    degraded="base_check_disabled",
    now=10.0,
)
alert_second = alert_limiter.admit(
    subject="webchat:probe",
    tool_name="on_llm_request",
    mode="enforce",
    decision="suspended",
    degraded="base_check_disabled",
    now=70.0,
)
alert_third = alert_limiter.admit(
    subject="webchat:probe",
    tool_name="on_llm_request",
    mode="enforce",
    decision="suspended",
    degraded="base_check_disabled",
    now=680.0,
)
check("the first degraded alert is sent", alert_first.send, True)
check("a repeat degraded alert inside ten minutes is merged", alert_second.send, False)
check("the merged count rides on the next delivery", alert_third.merged, 1)

# ---- the suppressed path leaves a row behind ----

check("the merged marker exists", gateway_main.NOTIFY_MERGED, "notify_merged")
check(
    "the merged row writer exists",
    callable(getattr(Gateway, "_record_notify_merged", None)),
    True,
)
source = (ROOT / "tooling_guard" / "main.py").read_text(encoding="utf-8")
check("deliver_notice asks for the pending flag", "pending=pending" in source, True)
check(
    "deliver_notice marks a suspension with a ticket as pending",
    "pending = plan.decision is Decision.SUSPENDED and bool(ticket_id)" in source,
    True,
)
check(
    "a suppressed notice records itself",
    "self._record_notify_merged(" in source,
    True,
)
metadata = (ROOT / "metadata.yaml").read_text(encoding="utf-8")
check("the metadata ships the shipped version", f"version: {__version__}" in metadata, True)
changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
check("the changelog names the shipped release", f"## {__version__}" in changelog, True)

print("%d checks, %d failed" % (ok, fail))
if fail:
    raise SystemExit(1)
print("ALL CHECKS PASSED")
