"""Gateway assembly and the single-call decision pipeline.

Requirement: Single Call Orchestration; Fail-Closed on Broken Choke Point;
Dynamic Suspension Budget; External Cancellation Degradation; Sanitized
Persistence; Entry-Side Fragment Gate.

Dependency direction is interface -> main: this module therefore never imports
tooling_guard.interface. The capabilities the pipeline needs from that layer
(identity resolution and the request hook adapter) are injected by the root
main.py assembly point, so main only orchestrates existing layers.

Pipeline order per ARCHITECTURE.md section 4: deadline -> identity + digest ->
triage (policy + rules + decision word) -> audit -> trajectory -> suspension
(ticket -> notify -> wait) -> anonymized egress.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import math
import os
import re
import threading
import time
import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, replace
from inspect import isawaitable
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Protocol

from .anonymize import MAX_REDACT_SCAN, Anonymizer, PathRedactor
from .approval.waiter import (
    APPROVED,
    CANCELED_EXTERNAL,
    MAX_SUSPEND_WAIT_S,
    MIN_SUSPEND_REMAINING_S,
    TIMEOUT,
    WAITER_ACTOR,
    ApprovalRegistry,
    wait_for_decision,
)
from .compat import unwrap
from .core.call import build_call
from .core.consensus import TICKET_ALL_ABSTAIN, TICKET_MODEL_DENY, consensus
from .core.pipeline import ReviewPipeline, merge_outcomes
from .core.registry import ReviewerRegistry
from .core.reviewer import ReviewerStatus
from .core.verdict import ReviewOutcome, coerce_outcome
from .digest import args_digest, args_head
from .jev.client import DEFAULT_TIMEOUT_S, FastJudge, JevClient, configured_timeout
from .jev.score import DETAIL_FORCE_DEEP, FastThresholds
from .notify.admin import notify_admins, notify_timeout_seconds
from .notify.messages import (
    render_admin_message,
    render_canceled_notice,
    render_merged_notice,
)
from .notify.ratelimit import NotifyRateLimiter
from .notify.sender import build_sender, delivery_attempts, platform_from_admins
from .policy import paths
from .policy.layers import LAYER_STATIC_PASS, LAYER_WHITELIST
from .policy.allowlists import (
    SECRET_SCAN_INCOMPLETE,
    scan_secret_patterns,
    trusted_in_project_roots,
)
from .policy.config import (
    ConfigValidationResult,
    GatewayConfig,
    validate_config,
)
from .policy.snapshot import PolicySnapshot, build_snapshot
from .policy.tools import is_exec_tool
from .jev.schema import parse_text_answer
from .prompts.deep_call import (
    RESPONSE_FORMAT as DEEP_RESPONSE_FORMAT,
    SYSTEM_PROMPT as DEEP_SYSTEM_PROMPT,
    build_deep_body,
)
from .prompts.trajectory import MAX_EXCERPT_BYTES, build_trajectory_prompt
from .reviewers import register_builtin_reviewers
from .reviewers._common import (
    DETAIL_CONFIDENCE,
    DETAIL_CONSULTED,
    DETAIL_FOLD,
    DETAIL_LABELS,
    DETAIL_LAYER,
    DETAIL_REASON,
    DETAIL_NOTE,
    DETAIL_RULE_IDS,
    DETAIL_SCORE,
    DETAIL_SEVERITY,
    DETAIL_SKIPPED,
    DETAIL_SOURCE,
    DETAIL_WOULD_BE,
    SKIP_WHITELISTED,
)
from .reviewers.base_check import NAME as BASE_CHECK_NAME
from .reviewers.jev_fast import NAME as JEV_FAST_NAME
from .reviewers.llm_deep import NAME as DEEP_REVIEWER_NAME
from .reviewers.policy import NAME as POLICY_NAME
from .reviewers.rules import NAME as RULES_NAME
from .store import audit, db, tickets
from .trace import intent as intent_trace
from .trace.recorder import TrajectoryRecorder
from .trace.summary import CallSummary, summarize_call
from .trace.taint import SOURCE_FILE_READ, SOURCE_GROUP_HISTORY, SOURCE_KB_RETRIEVAL
from .trace.watch import CallFacts, TrajectoryWatch
from .triage.cache import ConclusionCache, ConclusionKey
from .triage.classify import (
    FILE_READ_TOOLS,
    LABEL_UNTRUSTED_SOURCE,
    TIER_STRONG,
    TIER_UNKNOWN,
    VERB_EDIT,
    VERB_EXEC,
    VERB_WRITE,
    classify_call,
    content_text,
    tier_of,
    verb_of,
)
from .triage.decisions import (
    ALLOW_DECISIONS,
    MODE_ENFORCE,
    MODE_OBSERVE,
    Decision,
    WouldBe,
    coerce_decision,
    effective_mode,
    is_allow,
    is_observe_mode,
    would_be_for,
)
from .triage.engine import call_base, classify_features
from .triage.rules import (
    RULE_SET_VERSION,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    TrajectoryView,
)
from .ui.contracts import FastJudgeStatus

#: Host default for one tool call (run_context.py:19 tool_call_timeout = 120),
#: read off the injected context instead of importing astrbot.core.
TOOL_CALL_TIMEOUT_S = 120.0
#: Budget kept in reserve so the answer still reaches the host in time.
DEADLINE_MARGIN_S = 10.0
#: Cap of the synchronous decision budget, in seconds. Layered Consensus spends
#: this on the layers themselves (fast judge first, deep reviewer only when the
#: fast one abstained or asked for it) instead of folding the models into a
#: 15 second window that only ever produced triage timeouts.
DECISION_BUDGET_CAP_S = 120.0
#: Seconds of the call deadline that the decision rounds must leave untouched:
#: either an administrator has to be asked, or the proxy has to delegate the call
#: to the host. Spending it inside the layers turns every allow into
#: delegate_window_exhausted, so the rounds are clamped to whatever is left after
#: this reserve (approval/waiter.py MIN_SUSPEND_REMAINING_S).
DECISION_RESERVE_S = 30.0
#: Deep-review cap used when the caller passes no configured timeout.
DEEP_REVIEW_BUDGET_CAP_S = 20.0
#: Fallback for config.deep_analysis_timeout_s when the setting is unreadable.
DEFAULT_DEEP_ANALYSIS_TIMEOUT_S = 60.0
#: Lower bound of the effective suspension cap, mirroring the (1, 110) range
#: policy/config.py INT_BOUNDS enforces for suspend_timeout_s.
MIN_SUSPEND_WAIT_S = 1.0
#: Remaining budget below which the call is delegated instead of blocked.
MIN_DELEGATE_REMAINING_S = 5.0
#: Fallback cap of one fast-judge round trip, used when `jev_timeout_s` is absent.
#: The live value comes from the configuration, because a local judge can cold
#: start slower than five seconds; this name stays for callers that build a judge
#: by hand (tests, manual probes) and always equals the client default.
JEV_TIMEOUT_S = DEFAULT_TIMEOUT_S
#: Reason recorded when the notification cap cancelled a send.
NOTIFY_TIMEOUT_REASON = "notify_timeout"
#: Reason recorded when a send inside the cap failed without timing out.
NOTIFY_DELIVERY_FAILED_REASON = "delivery failed"
#: Deadline of the call in flight, held in one task-local scope that survives the
#: whole call: the reviewer assembly reads it (GuardCall carries no clock) and so
#: does interface/wrapper.py, which asks for what is left after the verdict and
#: before delegating. Nothing re-derives it, so a review that already spent the
#: budget cannot hand the delegate a fresh one.
_REVIEW_DEADLINE: ContextVar[CallScope | None] = ContextVar(
    "tooling_guard_review_deadline", default=None
)
#: Judge routes recorded next to a model-produced verdict.
JUDGE_ROUTE_ENDPOINT = "endpoint"
JUDGE_ROUTE_PROVIDER = "astrbot_provider"
JUDGE_ROUTE_JEV = "jev"
#: Placeholders used when the host gives no identity (never a ticket identity).
UNKNOWN_SUBJECT = "unknown:unknown"
UNKNOWN_SESSION = "unknown:unknown"
#: Redaction placeholder used when redaction itself fails.
REDACTION_FAILED = "<REDACTION_FAILED>"
REASON_FAIL_CLOSED = "网关内部错误，按拦截处理"
REASON_NOT_READY = "网关组件未就绪，按拦截处理"
REASON_NO_DECISION = "网关未给出可识别的决策，按拦截处理"
REASON_SYNC_BUDGET = "同步判定预算不足，按超时拒绝（未执行）"
REASON_SUSPEND_BUDGET = "剩余等待预算不足 30 秒，按超时拒绝（未执行）"
REASON_DELEGATE_WINDOW = "委派前剩余时间不足 5 秒，已拒绝；请稍后重试同一调用"
REASON_STORE_UNAVAILABLE = "审计存储不可用，按拦截处理"
REASON_CLOSED = "网关已关闭，按拦截处理"
REASON_APPROVED = (
    "管理员已批准该工具的一次同参数调用，但本次调用不会自动重放；"
    "请由模型重新发起一次完全相同的调用。"
)
REASON_DENIED = "管理员拒绝了本次工具调用，请勿重试同一调用。"
REASON_TIMEOUT = "管理员在等待窗口内未作出决定，按超时拒绝（未执行）。"
REASON_CANCELED = "外层请求已取消，票据转 canceled_external（未执行）。"
REASON_APPROVED_RETRY = (
    "管理员已批准一次完全相同的调用，本次调用按批准放行；"
    "仍需重新判定、脱敏与审计，且该批准已在此次调用中消费。"
)
#: Reason recorded on every ticket that shutdown had to settle.
SHUTDOWN_REASON = "gateway shutdown"
#: Reason recorded on a ticket the gateway itself had to time out.
TIMEOUT_REASON = "waiter timeout"
#: Cap of the audit summary line.
SUMMARY_LINE_LIMIT = 200
#: Audit marker of a failed administrator notification.
NOTIFY_FAILED = "notify_failed"
#: Audit marker of a delivered administrator notification. It names the private
#: origin the notice was addressed to, so "the administrator saw nothing" can be
#: settled from the audit table instead of from the host's optimistic boolean.
NOTIFY_SENT = "notify_sent"
#: Reason prefix of a notice whose rendering or delivery raised.
NOTIFY_ERROR_PREFIX = "notify_error:"
#: Notice class of the request hook itself, used as the alert tool name.
HOOK_ALERT_TOOL = "on_llm_request"
#: Alert class of the reviewer-state notices. It is kept apart from the hook one
#: so a stripped toolset and a disabled base checker never merge into a single
#: message: they need different administrator action.
REVIEWER_ALERT_TOOL = "reviewers"
#: Degradation kind of a disabled base checker, recorded in the audit row and in
#: the summary line tail marker.
DEGRADED_BASE_CHECK_DISABLED = "base_check_disabled"
#: Degradation kind of the switch being turned back on: re-enabling is not a
#: degradation any more, but the audit still records who restored the checker.
DEGRADED_BASE_CHECK_RESTORED = "base_check_restored"
#: Alert class of the startup ticket sweep notices. It is kept apart from the hook
#: and reviewer classes because it asks for a different action: the storage is
#: broken, approvals are closed, and the operator has to run /guard sweep.
STARTUP_SWEEP_ALERT_TOOL = "startup_sweep"
#: Degradation kind of a startup sweep that left the approval side closed.
DEGRADED_STARTUP_SWEEP = "startup_sweep_failed"
#: Degradation marker of a call the observation hook never filed an intent for.
INTENT_UNPAIRED = intent_trace.UNPAIRED_REASON
#: Audit marker of a verdict reused from the conclusion cache (task 6.5).
DEEP_CACHE_HIT = "deep_cache=hit"
#: Audit marker prefix that carries a call's degradation reason on its line.
DEGRADED_MARKER_PREFIX = "degraded="
#: Audit marker prefix that carries the policy layer a verdict came from. The
#: row has no layer column and its rule_id column is evidence, so the line is
#: where a reader -- and a grep -- finds the attribution of a decision.
ATTRIBUTION_MARKER_PREFIX = "layer="
#: Call body the marker tail must leave; under it the cache-hit marker is shed.
SUMMARY_MARKER_BODY_MIN = 12
#: Audit marker of a summary line whose text the redactor scanned only in part.
#: anonymize.MAX_REDACT_SCAN truncates the input before any rule runs, so a
#: secret past the cap is not redacted; the row has to say so rather than look
#: like a fully scanned line.
REDACT_TRUNCATED = "redact_truncated"
#: Degradation fact of a synchronous deep review the 30 second reserve ate.
DEGRADED_DEEP_BUDGET = "deep_budget_exhausted"
#: Degradation prefix of a deep review whose request failed or timed out.
DEGRADED_DEEP_FAILED = "deep_review_failed"
#: Degradation fact of a background deep review that failed after the answer.
DEGRADED_DEEP_BACKGROUND = "deep_background_failed"
#: Degradation fact of a deep review the in-flight bound refused to start.
DEGRADED_DEEP_SATURATED = "deep_background_saturated"
#: Cap of background deep reviews in flight; anything over it is not queued.
DEEP_BACKGROUND_CONCURRENCY: Final[int] = 4
#: Severities that force a synchronous deep review before the verdict (task 6.3).
SYNC_DEEP_SEVERITIES = frozenset({SEVERITY_MEDIUM, SEVERITY_HIGH})
REASON_DEEP_DANGER = "深度分析判定危险，按拦截处理（未执行）"
REASON_DEEP_SUSPEND = "深度分析未能确认安全，转人工确认（未执行）"
#: Audit marker of the deep review an in-root non-exec call never needed.
DEEP_SKIPPED_TRUSTED_ROOT = "deep_skipped=trusted_project_root"
#: Degradation fact of a trajectory verdict the watch could not produce.
DEGRADED_TRAJECTORY_FAILED = "trajectory_failed"
#: Degradation fact of a trajectory trigger its deep review could not answer.
DEGRADED_TRAJECTORY_UNVERIFIED = "trajectory_unverified"
#: Degradation fact of a deep review the unusable judge never received.
DEGRADED_JUDGE_UNAVAILABLE = "judge_unavailable"
#: Consecutive judge failures that make the judge count as unusable.
JUDGE_FAILURE_THRESHOLD: Final[int] = 2
#: Seconds an unusable judge is not asked again.
JUDGE_COOLDOWN_S: Final[float] = 300.0
REASON_TRAJECTORY_FAILED = "轨迹判定不可用，按拦截处理（未执行）"
REASON_TRAJECTORY_UNVERIFIED = (
    "轨迹已触发，深度分析未能在预算内给出结论，转人工确认（未执行）"
)
REASON_JUDGE_UNAVAILABLE = "判定器不可用，按拦截处理（未执行）"
REASON_GATEWAY_OBSERVED = (
    "工具网关自身配置校验未通过，已降级为观察（只记录、不拦截）：本次调用照常执行"
)
REASON_IDENTITY_UNKNOWN = "无法确认本次调用的调用者身份，受管工具一律不执行"
#: Degradation fact of a gateway whose own configuration failed validation.
DEGRADED_GATEWAY_DISABLED = "gateway_disabled"
#: Degradation fact of a managed call the host gave no identity for.
DEGRADED_IDENTITY_UNKNOWN = "identity_unknown"
#: Reason recorded on a ticket an agent run left behind when it ended.
AGENT_RUN_END_REASON = "agent_run_end"
#: Actor recorded on a ticket an agent run voided.
AGENT_RUN_END_ACTOR = "system:agent_run_end"
#: Reason of a call denied because its session is listed in
#: suspend_disabled_sessions, so it may not wait for an approval.
REASON_SUSPEND_DISABLED = "该会话已关闭挂起（suspend_disabled_sessions），本次调用直接拒绝（未执行，不建票据、不等待审批）"
#: Degradation fact of a suspension a configured session turned into a denial.
DEGRADED_SUSPEND_DISABLED = "suspend_disabled_session"
#: Length cap of the session text a suppression marker carries on the audit line.
SUSPEND_MARKER_SESSION_LIMIT = 64

#: Failures the trajectory watch may raise while it records one call. Catching
#: this exact tuple keeps the gate total under the default ruff rules, which flag
#: a blind "except Exception" and forbid the suppression comment that would
#: silence it; anything outside still reaches guard_call, the fail-closed denial.
_WATCH_ERRORS: Final[tuple[type[BaseException], ...]] = (
    AttributeError,
    ArithmeticError,
    LookupError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
)

#: Failures that leave a provider client unbuildable. The tuple is explicit so
#: a real defect (anything outside it) still surfaces instead of being reported
#: as "not configured"; a construction failure is logged, never silent.
CLIENT_BUILD_ERRORS: Final[tuple[type[BaseException], ...]] = (
    AttributeError,
    ImportError,
    TypeError,
    ValueError,
)

_DENY_LABEL = Decision.DENY_POLICY.value
#: Reviewer names in fold-authority order: the adapter that consulted the judge
#: folded the widest chain, and the ones after it each publish the same fold for
#: the stages they could see. The gateway reports the first fold it finds and
#: never ranks words of its own. `policy` closes the list because it is the one
#: publisher that is still in the pipeline when `base_check_enabled=false`
#: (review finding S1): the fold must not disappear with the configuration key.
_FOLD_PUBLISHERS: Final[tuple[str, ...]] = (
    JEV_FAST_NAME,
    RULES_NAME,
    BASE_CHECK_NAME,
    POLICY_NAME,
)

#: The reviewers of the first consensus round, in registry order: everything
#: that can decide without a deep request. The deep reviewer is deliberately
#: absent -- it runs in the second round (see `_deep_round`), because a fast
#: denial already needs a human, a whitelist skip needs nobody, and every other
#: answer either asks for the deep opinion in so many words or is the
#: middle-band abstention that needs it by construction.
_STATIC_ROUND: Final[tuple[str, ...]] = (
    POLICY_NAME,
    BASE_CHECK_NAME,
    RULES_NAME,
    JEV_FAST_NAME,
)

#: The order the approval page lists reviewer accounts in: the same order the
#: consensus folds them in, so a reader follows the path the gateway took.
_REVIEW_ORDER: Final[tuple[str, ...]] = (
    POLICY_NAME,
    BASE_CHECK_NAME,
    RULES_NAME,
    JEV_FAST_NAME,
    DEEP_REVIEWER_NAME,
)

_LOGGER = logging.getLogger("tooling_guard")


def _admins_of(raw: Mapping[str, Any] | None) -> tuple[str, ...]:
    """Return the administrator ids of an unvalidated configuration.

    Requirement: Administrator Channel; Pipeline Failure Is Denial.  A gateway
    whose own configuration failed validation has no GatewayConfig, so the
    validated administrator list does not exist; the raw entries are the only way
    to tell somebody that managed calls are being denied.

    Args:
        raw: Raw plugin configuration mapping, possibly None.

    Returns:
        The non-empty string entries of raw["admins"], in configured order.
    """
    if not isinstance(raw, Mapping):
        return ()
    values = raw.get("admins")
    if not isinstance(values, (list, tuple)):
        return ()
    return tuple(
        item.strip() for item in values if isinstance(item, str) and item.strip()
    )


#: Resolved host logger, memoized. Importing `astrbot.api` is not free -- in a
#: venv that has the whole framework installed it pulls the framework in and took
#: seconds on the first call -- and the failure path below runs on every unusable
#: judge answer, so resolving it once keeps a broken judge from also costing
#: seconds of import time per call.
_HOST_LOGGER: list[Any] = []


def _host_logger() -> Any:
    """Return the host logger when it is importable, else a module logger."""
    if _HOST_LOGGER:
        return _HOST_LOGGER[0]
    try:
        from astrbot.api import logger as host_logger
    except (ImportError, AttributeError):
        resolved: Any = _LOGGER
    else:
        resolved = host_logger or _LOGGER
    _HOST_LOGGER.append(resolved)
    return resolved


#: Host layout below its data directory: per-session workspaces live in
#: `<data>/workspaces`, and the plugin data directory handed to this plugin is
#: `<data>/plugin_data/<plugin>` (astrbot/core/utils/astrbot_path.py:60-87).
_PLUGIN_DATA_DIRNAME: Final[str] = "plugin_data"
_WORKSPACES_DIRNAME: Final[str] = "workspaces"
#: Characters the host replaces when it turns a umo into a directory name
#: (astrbot/core/workspace.py:22-32).
_UMO_UNSAFE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9._-]+")
#: Name the host falls back to when a umo normalizes away (workspace.py:22-32).
_UMO_FALLBACK_NAME: Final[str] = "unknown"


def _data_root(data_dir: Path | str | None) -> str | None:
    """Return the host data directory that owns the given plugin data directory.

    Requirement: Policy Layers and Precedence. `astrbot.api` hands this plugin
    `<data>/plugin_data/<plugin>` and nothing above it, so the data root -- the
    directory the host builds workspace paths from -- is two levels up. The shape
    is checked rather than assumed: any other layout yields no base at all instead
    of resolving relative targets against a directory that means nothing.

    Args:
        data_dir: This plugin's data directory.

    Returns:
        The host data directory, or None when data_dir is not that shape.
    """
    if data_dir is None:
        return None
    try:
        path = Path(data_dir)
    except (OSError, TypeError, ValueError):
        return None
    if path.parent.name != _PLUGIN_DATA_DIRNAME:
        return None
    return str(path.parent.parent)


def _workspace_name(umo: str) -> str | None:
    """Return the host directory name of one session workspace.

    Requirement: Policy Layers and Precedence. This mirrors the host's own
    function (substitute every run of unsafe characters, fall back to one fixed
    name when nothing survives) so the gateway and the host cannot disagree about
    which directory a session owns.

    Args:
        umo: Unified message origin of the session.

    Returns:
        The directory name, or None when the umo is empty.
    """
    key = str(umo or "").strip()
    if not key:
        return None
    return _UMO_UNSAFE.sub("_", key) or _UMO_FALLBACK_NAME


def _session_umos(context: Any, event: Any) -> tuple[str, ...]:
    """Return the umo candidates of this call, most specific first.

    Requirement: Policy Layers and Precedence. Only origins the host itself put on
    the call are read. A session key is deliberately not a candidate: feeding a
    key the identity provider composed into the host's umo-to-workspace mapping
    would mint a workspace that does not exist and then resolve targets against
    it, which is worse than having no base at all.

    Args:
        context: Host tool-call context, mapping or object.
        event: Host event of this call, possibly None.

    Returns:
        The distinct non-empty candidates, in resolution order.
    """
    candidates: list[str] = []
    for source in (event, _run_context_of(context), context):
        for name in ("unified_msg_origin", "umo"):
            value = _field_of(source, name)
            if not isinstance(value, str):
                continue
            text = value.strip()
            if text and text not in candidates:
                candidates.append(text)
    return tuple(candidates)


# Known boundary, stated rather than papered over: this reproduces the host's
# LEGACY per-session workspace rule only (`<data>/workspaces/<normalized umo>`).
# The host also serves custom/project workspaces through
# `workspace_root_for_context` -> `resolve_workspace_root_for_umo(umo, db)`
# (astrbot/core/tools/computer_tools/util.py:62-80, core/workspace.py:191-217),
# which reads a database this plugin does not have; for a session bound to such a
# workspace a relative target can therefore expand against the legacy root here
# and disagree with where the host will actually read the file. Reaching those
# would mean reading host internals, which the runtime import rule (AGENTS.md H1)
# forbids, so the gap is accepted, documented and pinned by a test.
def _workspace_base(
    context: Any, event: Any, *, data_dir: Path | str | None
) -> str | None:
    """Return the workspace base that resolves this call's relative targets.

    Requirement: Policy Layers and Precedence. Nothing is guessed: with no data
    root, or no origin on the call, the answer is None, which keeps every relative
    target on the fail-closed path the policy layers own.

    Args:
        context: Host tool-call context, mapping or object.
        event: Host event of this call, possibly None.
        data_dir: This plugin's data directory, `<data>/plugin_data/<plugin>`.

    Returns:
        The workspace directory, or None when this call has no usable one.
    """
    root = _data_root(data_dir)
    if root is None:
        return None
    for umo in _session_umos(context, event):
        name = _workspace_name(umo)
        if name is None:
            continue
        try:
            return os.path.realpath(os.path.join(root, _WORKSPACES_DIRNAME, name))
        except (OSError, TypeError, ValueError):
            continue
    return None


class IdentityProvider(Protocol):
    """Minimal identity surface injected by the assembly point.

    interface/identity.py owns the implementation; main only calls it, so no
    dependency edge from main to interface is created.
    """

    def subject_key(self, event: Any) -> str:
        """Return platform_id:sender_id, or an empty string."""
        ...

    def session_key(self, event: Any) -> str:
        """Return the minimized session key."""
        ...


@dataclass(frozen=True, slots=True)
class CallOutcome:
    """One answer for the proxy: decision word plus optional rendering fields.

    Requirement: Single Call Orchestration. interface/wrapper.py reads these
    fields by name, renders the result and delegates on an allow decision;
    result is left None so rendering and delegation stay in the wrapper.

    Args:
        decision: Decision word; the wrapper prefix-matches allow/deny/suspend.
        text: Ready rendering input for a deny or a suspension.
        ticket_id: Suspension ticket, when one was created.
        state: Ticket state for a suspension.
        result: Fully built result; always None here.
        would_be: Observe-mode potential verdict, for audit and diagnostics.
        rule_id: First matched rule, when known.
        judge_route: Model route consulted for this verdict, when known.
    """

    decision: str
    text: str = ""
    ticket_id: str = ""
    state: str = ""
    result: Any = None
    would_be: str | None = None
    rule_id: str | None = None
    judge_route: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return the field mapping the wrapper reads."""
        return {
            "decision": self.decision,
            "text": self.text,
            "ticket_id": self.ticket_id,
            "state": self.state,
            "result": self.result,
            "would_be": self.would_be,
            "rule_id": self.rule_id,
            "judge_route": self.judge_route,
        }


@dataclass(frozen=True, slots=True)
class FragmentFilter:
    """Outcome of the entry-side fragment gate (task 6.4).

    Requirement: Entry-Side Fragment Gate; Deep Analysis Input Budget. An
    excerpt matching a secret pattern never reaches deep analysis. An excerpt
    whose absolute literals sit outside the project roots is kept after each of
    them is replaced with a stable `<EXT>/<basename>` placeholder, so the
    content still informs the review while the location does not. An empty
    project_roots is a configuration error and still drops every excerpt. Every
    count is recorded without a path.

    Args:
        kept: Fragments that passed the gate, in input order.
        dropped_secret: Fragments dropped for matching a secret pattern.
        dropped_outside_roots: Fragments dropped because no project root was
            configured, which is a configuration error and not a scope.
        truncated_marker: Degradation markers, space-joined, of a scan that read
            only part of a fragment or of an excerpt the gate cut, empty when
            nothing was degraded.
        outside_project_roots_kept: Fragments kept after their out-of-root
            literals were rewritten to placeholders.
        roots_configured: Whether the snapshot configured at least one root;
            when it did not, the census says `project_roots=missing`.
    """

    kept: tuple[str, ...] = ()
    dropped_secret: int = 0
    dropped_outside_roots: int = 0
    truncated_marker: str = ""
    outside_project_roots_kept: int = 0
    roots_configured: bool = True

    @property
    def dropped(self) -> int:
        """Return the total number of dropped fragments."""
        return self.dropped_secret + self.dropped_outside_roots

    @property
    def reason(self) -> str:
        """Return the drop census; it holds no path and no secret."""
        census = (
            f"secret_pattern={self.dropped_secret};"
            f"outside_project_roots_kept={self.outside_project_roots_kept};"
            f"outside_project_roots={self.dropped_outside_roots}"
        )
        if not self.roots_configured:
            census = f"{census} project_roots=missing"
        if not self.truncated_marker:
            return census
        return f"{census} {self.truncated_marker}"


@dataclass(frozen=True, slots=True)
class DeepReviewResult:
    """One deep-analysis answer together with its gate and route.

    Requirement: Deep Analysis Sampling; Entry-Side Fragment Gate.

    Args:
        route: Judge route recorded next to the verdict, None when no model was
            consulted.
        answer: Model answer, None when nothing was sent.
        gate: Fragment gate result for this round.
        degraded: Reason nothing was sent, when applicable.
    """

    route: str | None = None
    answer: Any = None
    gate: FragmentFilter = FragmentFilter()
    degraded: str | None = None


@dataclass(frozen=True, slots=True)
class _Plan:
    """Internal, side-effect-free verdict produced inside the per-key lock."""

    decision: Decision
    reason: str
    would_be: str | None = None
    rule_id: str | None = None
    judge_route: str | None = None
    degraded: str | None = None
    labels: tuple[str, ...] = ()
    #: The policy layer that produced this verdict (deny_path, sensitive_config,
    #: whitelist, static_pass, ...), read back from the fold the reviewer
    #: published. It is the attribution of the decision: the rule identifiers on
    #: the same fold are evidence -- an observe rule fires on calls it never
    #: blocks -- so a report names this layer, never a rule identifier alone.
    layer: str = ""
    #: The policy source word behind `layer` (deny, suspend, whitelist,
    #: static_pass). Published next to it so a reader keeps the two apart.
    source: str = ""
    call_id: str | None = None
    intent_unpaired: bool = False
    severity: str | None = None
    deep_cache_hit: bool = False
    #: The fast judge asked for the deep analysis in so many words (noul=true),
    #: read from the fold the fast reviewer published. It can only tighten: the
    #: deep round runs before the call is delegated, and an abstention there
    #: still leaves the fast release standing.
    force_deep: bool = False
    #: Why this call needs a human, when it does. Set from the same
    #: core.consensus fold that produced the decision, so the notice cannot
    #: disagree with the verdict: `model_deny` is a model refusing a call the
    #: static layer passed, `all_abstain` is a call nobody approved. The value
    #: never reaches the tickets table -- it shapes the notice wording only.
    ticket_kind: str | None = None
    #: What each reviewer actually said about this call, keyed by reviewer name:
    #: its outcome word, the decision word, its reason, and -- for a consulted
    #: judge -- the score and confidence the banding was made from. It is the
    #: evidence the approval page shows next to the arguments, and it rides
    #: inside summary_json, so the audit table keeps its column set.
    review: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class _NoticeAudit:
    """Audit identity one failed delivery records itself under (R10-02).

    The delivery boundary is shared by every notice path, so the failure row is
    written where the failure happens; this record carries only what the row
    needs, and a path that has no plan of its own passes a minimal one.

    The label names the alert whose delivery failed, because an alert has no
    ticket an administrator could look up: without it the failure row would say
    "notify_failed" and lose what it was announcing.
    """

    plan: _Plan
    ticket_id: str = ""
    tool: str = ""
    subject: str = ""
    session: str = ""
    label: str = ""


#: Rank of a decision in the tightening order allow < suspended < deny (task 6.3).
_DECISION_RANK: dict[Decision, int] = {
    Decision.ALLOW_PASSTHROUGH: 0,
    Decision.ALLOW_FAST: 0,
    Decision.ALLOW_TRAJECTORY: 0,
    Decision.ALLOW_APPROVED_RETRY: 0,
    Decision.SUSPENDED: 1,
    Decision.CANCELED_EXTERNAL: 1,
    Decision.TIMEOUT_DENY: 2,
    Decision.DENY_RULE: 2,
    Decision.DENY_JUDGE: 2,
    Decision.DENY_POLICY: 2,
    Decision.DENY_REQUESTER: 2,
    Decision.DENIED_NO_WRAPPER: 2,
}
#: Rank of an observe-mode expectation, same order as _DECISION_RANK.
_WOULD_BE_RANK: dict[str, int] = {
    "suspend": 1,
    "deny_rule": 2,
    "deny_judge": 2,
    "deny_policy": 2,
    "deny_requester": 2,
}
#: Suspicion word of a deep-analysis answer mapped to the verdict it justifies.
_DEEP_SUSPICION: dict[str, Decision] = {
    "critical": Decision.DENY_JUDGE,
    "high": Decision.DENY_JUDGE,
    "medium": Decision.SUSPENDED,
}


def _severity_of(outcome: Any) -> str | None:
    """Read the severity of a triage outcome, when it carries one.

    Requirement: Deep Analysis Sampling (task 6.3). The severity decides whether
    a deep review runs synchronously, so it is normalized to a lower-case word
    and anything unreadable counts as "no severity".

    Args:
        outcome: TriageOutcome or a mapping with the same fields.

    Returns:
        The normalized severity word, or None.
    """
    value = _field_of(outcome, "severity")
    if isinstance(value, str):
        return value.strip().lower() or None
    return None


def _decision_word(value: Any) -> Decision | None:
    """Read one decision word strictly, None when it is no known word.

    Requirement: Fail-Closed Triage. coerce_decision() maps an unknown word to
    deny_rule, which is correct for a host-supplied decision and wrong for a
    model answer: an answer nobody can parse is uncertain, not a denial.

    Args:
        value: Candidate value from a deep-analysis answer.

    Returns:
        The matching Decision, or None for anything unrecognisable.
    """
    if isinstance(value, Decision):
        return value
    if not isinstance(value, str):
        return None
    word = value.strip().lower()
    if not word:
        return None
    for decision in Decision:
        if word == decision.value or word == decision.name.lower():
            return decision
    return None


def _structured_answer(answer: Any) -> Any:
    """Return a mapping-shaped deep-analysis answer, or None.

    Requirement: Deep Analysis Sampling. provider/llm.py returns the completion
    text, so the shapes that carry a machine-readable verdict are a mapping, a
    string that decodes to one, or an object exposing a verdict field; anything
    else is prose and stays unparsed.

    Args:
        answer: Raw answer returned by the deep-review client.

    Returns:
        The mapping-like answer, or None.
    """
    if isinstance(answer, Mapping):
        return answer
    if isinstance(answer, str):
        text = answer.strip()
        if not text.startswith("{"):
            return None
        with contextlib.suppress(Exception):
            decoded = json.loads(text)
            if isinstance(decoded, Mapping):
                return decoded
        return None
    for name in ("decision", "verdict", "suspicion"):
        if hasattr(answer, name):
            return answer
    return None


def _deep_answer_decision(answer: Any) -> Decision | None:
    """Read one deep-analysis answer as the verdict it justifies, or None.

    Requirement: Deep Analysis Sampling; Fail-Closed Triage. Only a structured
    answer names a verdict: an explicit decision/verdict word, or a suspicion
    level. Prose is uncertain by construction -- the gateway never greps a model
    answer for words, because a sentence containing "deny" is not a denial and a
    sentence containing "safe" is not an allow.

    Args:
        answer: Raw answer returned by the deep-review client.

    Returns:
        The verdict the answer justifies, or None when it justifies none.
    """
    value = _structured_answer(answer)
    if value is None:
        return None
    for name in ("decision", "verdict"):
        decision = _decision_word(_field_of(value, name))
        if decision is not None:
            return decision
    suspicion = _field_of(value, "suspicion")
    if isinstance(suspicion, str):
        return _DEEP_SUSPICION.get(suspicion.strip().lower())
    return None


def _raised(plan: _Plan, verdict: Decision) -> _Plan:
    """Return plan raised to verdict, never relaxed.

    Requirement: Fail-Closed Triage; Analysis Result Caching. This comparison is
    the invariant behind "a deep conclusion may only tighten": a rank that is not
    higher than the current one returns the plan untouched, so no conclusion --
    cached or fresh -- can widen a denial or a suspension into an allow.

    Args:
        plan: The plan triage produced.
        verdict: The verdict the deep analysis justifies.

    Returns:
        The strictly stronger plan, or plan itself.
    """
    if _DECISION_RANK.get(verdict, 2) <= _DECISION_RANK.get(plan.decision, 2):
        return plan
    reason = REASON_DEEP_SUSPEND
    if _DECISION_RANK.get(verdict, 2) >= 2:
        reason = REASON_DEEP_DANGER
    return replace(plan, decision=verdict, reason=reason, would_be=None)


def _observed(plan: _Plan, verdict: Decision) -> _Plan:
    """Record verdict as the expectation of an observe-mode call, never its outcome.

    Requirement: Shadow Observation Mode. Observe mode never blocks a call, so a
    deep verdict may only raise would_be; the decision the wrapper acts on stays
    exactly what triage produced.

    Args:
        plan: The plan triage produced.
        verdict: The verdict the deep analysis justifies.

    Returns:
        The plan with a stronger expectation, or plan itself.
    """
    expected = would_be_for(verdict)
    if expected is None:
        return plan
    current = _WOULD_BE_RANK.get(plan.would_be or "", 0)
    if current >= _WOULD_BE_RANK.get(expected.value, 2):
        return plan
    return replace(plan, would_be=expected.value)


def _resolved_targets(features: Any, *, base: str | None) -> tuple[paths.PathKey, ...]:
    """Resolve a classified call's targets the way the policy layers do.

    Requirement: Policy Layers and Precedence. `policy/layers.py` judges a call
    by its path arguments plus every absolute literal inside its texts, all
    resolved against the workspace base of the call. The deep-analysis skip has
    to read the same set, or it would call a call "inside the project roots"
    that the layers deny: an absolute target resolves the same way either way,
    and a relative one only counts when the host supplied a workspace.

    Args:
        features: The classified call.
        base: Workspace root that resolves relative targets.

    Returns:
        The resolved targets, in the order the layers build them.
    """
    keys: list[paths.PathKey] = [
        paths.normalize_path(raw, base=base) for raw in features.targets
    ]
    for text in features.texts:
        for literal in paths.extract_absolute_paths(text):
            keys.append(paths.normalize_path(literal, base=base))
    return tuple(keys)


def _deep_tightened(
    plan: _Plan, result: DeepReviewResult, *, mode: str, cache_hit: bool
) -> _Plan:
    """Apply one deep-review conclusion to a plan (tasks 6.3 and 6.5).

    Requirement: Fail-Closed Triage; Shadow Observation Mode; Analysis Result
    Caching. A conclusion may only keep or raise the verdict; a failed request
    fails closed as a suspension; an absent conclusion changes nothing unless
    the fast judge forced this review (plan.force_deep), in which case the
    missing conclusion suspends rather than releases; an observe-mode plan is
    recorded in would_be and never blocked. Neither a cached hit nor a
    background conclusion can therefore turn a denial into an allow.

    Args:
        plan: The plan triage produced.
        result: The deep-review result, cached or fresh.
        mode: Effective mode of this session.
        cache_hit: Whether result came from the conclusion cache.

    Returns:
        The plan with the conclusion applied.
    """
    verdict = _deep_answer_decision(result.answer)
    degraded = result.degraded or ""
    if verdict is None and degraded.startswith(DEGRADED_DEEP_FAILED):
        verdict = Decision.SUSPENDED
    if verdict is None and degraded == DEGRADED_JUDGE_UNAVAILABLE:
        # A judge nobody can ask is not a missing conclusion to wait on: refusing
        # the call is the only answer that neither executes unjudged work nor
        # parks the caller for the whole suspension window.
        verdict = Decision.DENY_JUDGE
    if verdict is None and plan.force_deep:
        # The fast judge told us to run the deep analysis before delegating and
        # the review produced no conclusion to apply -- an exhausted budget
        # lands here with degraded=deep_budget_exhausted. Parking the call is
        # the only outcome that keeps the promise: force_deep may tighten the
        # verdict, so it can never end as a silent release.
        verdict = Decision.SUSPENDED
    tightened = plan
    if verdict is not None:
        if is_observe_mode(mode):
            tightened = _observed(plan, verdict)
        else:
            tightened = _raised(plan, verdict)
    if (
        degraded == DEGRADED_JUDGE_UNAVAILABLE
        and verdict is Decision.DENY_JUDGE
        and tightened is not plan
    ):
        # Name the real cause: an operator reading the refusal must see that the
        # judge was unreachable, not that a review found the call dangerous.
        tightened = replace(tightened, reason=REASON_JUDGE_UNAVAILABLE)
    if tightened.judge_route is None and result.route is not None:
        tightened = replace(tightened, judge_route=result.route)
    if tightened.degraded is None and result.degraded is not None:
        tightened = replace(tightened, degraded=result.degraded)
    if cache_hit:
        tightened = replace(tightened, deep_cache_hit=True)
    return tightened


def _degraded_with(current: str | None, marker: str | None) -> str | None:
    """Return one degraded value carrying the marker after the facts already set.

    Requirement: Degraded Mode Alert. The audit column holds a single value, so a
    marker is appended rather than substituted: an operator has to see both that
    the deep review had no budget and that the trigger stayed unverified.

    Args:
        current: Degraded value already on the plan, possibly None.
        marker: Marker of this round, possibly None.

    Returns:
        The combined value, None when neither side has one.
    """
    current_text = str(current or "").strip()
    marker_text = str(marker or "").strip()
    if not marker_text:
        return current_text or None
    if not current_text:
        return marker_text
    if marker_text in current_text:
        return current_text
    return f"{current_text},{marker_text}"


def _scan_incomplete_code(plan: _Plan) -> str:
    """Return the scan-integrity word this plan's reason proves, empty otherwise.

    Requirement: Content Whitelist and Secret Blocking; Degradation Reason on the
    Call Row. A deny layer that reports an incomplete secret scan has decided a
    fact the audit row must keep machine-readable: the row owns one boolean slot
    and one summary-line marker, and neither may wait for a human to read the
    reason. The deny layer is the only producer of the word, so the reason it
    wrote is where it is read back from.

    Args:
        plan: The plan the row is written for.

    Returns:
        The stable word, or an empty string when the plan does not carry it.
    """
    if SECRET_SCAN_INCOMPLETE not in str(plan.reason or ""):
        return ""
    if SECRET_SCAN_INCOMPLETE in str(plan.degraded or ""):
        return ""
    return SECRET_SCAN_INCOMPLETE


def _trajectory_tightened(
    plan: _Plan, result: DeepReviewResult, *, mode: str, cache_hit: bool
) -> _Plan:
    """Tighten a plan the trajectory watch triggered, fail-closed without verdict.

    Requirement: Trajectory Review Trigger; Fail-Closed Triage.

    A trigger whose deep review produced a verdict keeps _deep_tightened's answer
    untouched. A trigger the review could not answer -- no budget left inside the
    30 second reserve, or no fragment in scope -- used to fall back to the plan
    under review, and that plan allowed the call, so the one call the trajectory
    watch had just flagged was the one call that passed. It now suspends:
    suspension rather than refusal because a trigger means a human has to look,
    and a suspension still mints the approval ticket that lets one look, while a
    denial would end the call with no way back. It ranks above allow and below
    deny, so a plan already refused keeps its own stronger decision and reason,
    and the fact that no conclusion came back stays in the tail marker. In
    observe mode the same word is recorded as would_be and nothing is blocked.

    Args:
        plan: The plan triage produced for this call.
        result: The deep review result, cached or fresh.
        mode: Effective mode of this session.
        cache_hit: Whether result came from the conclusion cache.

    Returns:
        The plan, tightened when the trigger reached no verdict.
    """
    tightened = _deep_tightened(plan, result, mode=mode, cache_hit=cache_hit)
    if result.answer is not None:
        return tightened
    marker = f"{DEGRADED_TRAJECTORY_UNVERIFIED}:{result.degraded or 'no_conclusion'}"
    tightened = replace(tightened, degraded=_degraded_with(tightened.degraded, marker))
    if _DECISION_RANK.get(tightened.decision, 2) >= _DECISION_RANK[Decision.SUSPENDED]:
        return tightened
    if is_observe_mode(mode):
        return _observed(tightened, Decision.SUSPENDED)
    return replace(
        tightened, decision=Decision.SUSPENDED, reason=REASON_TRAJECTORY_UNVERIFIED
    )


async def _guarded_review(
    review: Awaitable[DeepReviewResult], *, route: str | None, degraded: str
) -> DeepReviewResult:
    """Await one deep review, turning its failure into a degraded result.

    Requirement: Fail-Closed Triage; Degraded Mode Alert. A review that raises
    must never escape the gateway: the caller alone decides what a missing
    conclusion means, so the failure is reported as a degradation fact carrying
    the exception type instead of an exception. Cancellation is not a failure and
    always propagates untouched.

    Args:
        review: The pending review coroutine.
        route: Judge route to report on a degraded result.
        degraded: Degradation prefix to report, with the exception type appended.

    Returns:
        The review result, or a degraded result when the request failed.
    """
    task = asyncio.ensure_future(review)
    with contextlib.suppress(Exception):
        return await task
    failure = task.exception()
    name = type(failure).__name__ if failure is not None else "unknown"
    return DeepReviewResult(route=route, degraded=f"{degraded}:{name}")


def remaining_seconds(deadline: float, now: float) -> float:
    """Return the clamped remaining budget.

    Args:
        deadline: Deadline instant on the caller clock.
        now: Current instant on the same clock.

    Returns:
        max(0, deadline - now); 0.0 for a non-numeric input.
    """
    try:
        return max(0.0, float(deadline) - float(now))
    except (TypeError, ValueError):
        return 0.0


def read_tool_call_timeout(source: Any) -> float:
    """Read tool_call_timeout off an injected object without importing it.

    Requirement: Dynamic Suspension Budget. The host attribute lives on
    astrbot/core/agent/run_context.py:19, which the plugin must not import; the
    value is therefore read duck-typed and falls back to 120 seconds.

    Args:
        source: A run context, a mapping, a tool-call context, or None.

    Returns:
        A positive timeout in seconds; 120.0 when nothing usable is readable.
    """
    if source is None:
        return TOOL_CALL_TIMEOUT_S
    value = _field_of(source, "tool_call_timeout")
    if value is None:
        for holder in ("run_context", "context"):
            inner = _field_of(source, holder)
            if inner is None:
                continue
            value = _field_of(inner, "tool_call_timeout")
            if value is not None:
                break
    try:
        number = float(value)
    except (TypeError, ValueError):
        return TOOL_CALL_TIMEOUT_S
    return number if number > 0 else TOOL_CALL_TIMEOUT_S


@dataclass(slots=True)
class CallScope:
    """The one deadline a guarded call publishes to everything taking part in it.

    Requirement: Delegation Fidelity; Notification Delivery Failure. The gateway
    computes the call deadline once and writes it here; the reviewer assembly,
    the administrator notice, the approval wait and the proxy's yield clamp then
    read the same instant. The scope is task-local (one ContextVar), so it is
    never global mutable state, and it deliberately outlives `guard_call`: the
    proxy only asks for the remaining budget after the verdict, when it is about
    to delegate.
    """

    deadline: float | None = None

    def remaining(self, now: float) -> float | None:
        """Return what is left of the deadline, or None while it is unset."""
        if self.deadline is None:
            return None
        return max(0.0, float(self.deadline) - float(now))


def call_deadline(now: float, timeout_s: float = TOOL_CALL_TIMEOUT_S) -> float:
    """Return now + tool_call_timeout - 10 for one call.

    Requirement: Dynamic Suspension Budget.

    Args:
        now: Current instant on the caller clock.
        timeout_s: Host tool-call timeout in seconds.

    Returns:
        The deadline instant on the same clock.
    """
    return float(now) + max(0.0, float(timeout_s)) - DEADLINE_MARGIN_S


def sync_budget_seconds(
    deadline: float, now: float, *, cap: float = DECISION_BUDGET_CAP_S
) -> float:
    """Return the synchronous decision budget of one call, in seconds.

    Requirement: Layer Budgets; Dynamic Suspension Budget.

    The decision rounds may spend the whole call deadline, less the reserve the
    approval and delegation paths need. There is no "half of what is left" and
    no 15 second ceiling any more: those numbers were what turned every slow
    judge into triage_timeout, that is a denial for a call nobody had judged yet.

    Args:
        deadline: Deadline instant on the caller clock.
        now: Current instant on the same clock.
        cap: Upper bound from configuration (decision_budget_s).

    Returns:
        The synchronous decision budget, 0.0 when the reserve eats the deadline.
    """
    limit = float(cap)
    if limit <= 0.0:
        return 0.0
    remaining = remaining_seconds(deadline, now) - DECISION_RESERVE_S
    return max(0.0, min(limit, remaining))


def deep_budget_seconds(
    deadline: float, now: float, *, cap: float | None = None
) -> float:
    """Return min(cap, deadline - now - 30) for a synchronous deep review.

    Requirement: Dynamic Suspension Budget; Deep Analysis Sampling.  The cap is
    config.deep_analysis_timeout_s, so a deployment that allows a 60 second
    review is not silently clamped to 20; the 30 second reserve still keeps the
    answer inside the call deadline, and a cap that consumes the reserve leaves
    no budget at all rather than a negative one.

    Args:
        deadline: Deadline instant on the caller clock.
        now: Current instant on the same clock.
        cap: Deep-analysis timeout; DEEP_REVIEW_BUDGET_CAP_S when omitted.

    Returns:
        The deep-review budget, 0.0 when the 30 second reserve eats it.
    """
    limit = float(DEEP_REVIEW_BUDGET_CAP_S if cap is None else cap)
    if limit <= 0:
        return 0.0
    return max(
        0.0, min(limit, remaining_seconds(deadline, now) - MIN_SUSPEND_REMAINING_S)
    )


def suspension_wait_seconds(deadline: float, now: float) -> float:
    """Return min(110, deadline - now) for the approval wait.

    Requirement: Dynamic Suspension Budget.

    Args:
        deadline: Deadline instant on the caller clock.
        now: Current instant on the same clock.

    Returns:
        The wait budget in seconds, never negative.
    """
    return min(MAX_SUSPEND_WAIT_S, remaining_seconds(deadline, now))


def suspension_cap_seconds(configured: Any) -> float:
    """Return min(110, suspend_timeout_s): the cap one suspension may use.

    Requirement: Approval Wait and Exact-Match Retry.  policy/config.py already refuses
    a value outside (1, 110) rather than clamping it, so this function guards the
    paths that carry no usable value at all: a gateway assembled without a
    configuration snapshot, a missing key, or a non-numeric one each fall back to
    MAX_SUSPEND_WAIT_S.  It never widens a wait beyond MAX_SUSPEND_WAIT_S and
    never narrows it below MIN_SUSPEND_WAIT_S, so no stray value can starve or
    outlive the host's tool-call horizon.

    Args:
        configured: The configured suspend_timeout_s, whatever its type.

    Returns:
        The effective cap in seconds, inside [MIN_SUSPEND_WAIT_S,
        MAX_SUSPEND_WAIT_S].
    """
    try:
        number = float(configured)
    except (TypeError, ValueError):
        return MAX_SUSPEND_WAIT_S
    if not math.isfinite(number):
        return MAX_SUSPEND_WAIT_S
    return min(MAX_SUSPEND_WAIT_S, max(MIN_SUSPEND_WAIT_S, number))


def effective_suspend_deadline(deadline: float, now: float, cap: float) -> float:
    """Return min(deadline, now + cap): the instant a suspension ends at.

    Requirement: Approval Wait and Exact-Match Retry.  One instant serves every later
    step of the suspension path (the can_suspend test, the ticket's pending
    window, the waiter and the notice's remaining seconds), so a shortened cap
    cannot disagree with itself.  A cap below MIN_SUSPEND_REMAINING_S therefore
    collapses into the existing below-30-seconds path on its own: no ticket, no
    wait, timeout_deny.

    Args:
        deadline: The call deadline on the caller clock.
        now: Current instant on the same clock.
        cap: Effective cap from suspension_cap_seconds.

    Returns:
        The earlier of the call deadline and now + cap.
    """
    return min(float(deadline), float(now) + max(0.0, float(cap)))


def can_suspend(deadline: float, now: float) -> bool:
    """Return whether at least 30 seconds remain for a suspension.

    Requirement: Dynamic Suspension Budget.
    """
    return remaining_seconds(deadline, now) >= MIN_SUSPEND_REMAINING_S


def can_delegate(deadline: float, now: float) -> bool:
    """Return whether at least 5 seconds remain before delegating.

    Requirement: Dynamic Suspension Budget.
    """
    return remaining_seconds(deadline, now) >= MIN_DELEGATE_REMAINING_S


def filter_fragments(
    fragments: Iterable[Any],
    snapshot: Any,
    *,
    limit: int | None = None,
) -> FragmentFilter:
    """Gate fragments for deep analysis by project root and secret pattern.

    Requirement: Entry-Side Fragment Gate (task 6.4); Deep Analysis Input Budget.

    The secret scan decides first and unchanged: an excerpt matching a secret
    pattern is dropped and counted. An excerpt that matches no secret but
    carries an absolute literal outside every configured root is no longer
    dropped for that reason alone. Each such literal is replaced by the stable
    placeholder `<EXT>/<basename>` -- the convention prompts/state.py already
    uses -- so one path always becomes one placeholder and the location no
    longer reaches the model. The rewritten text is scanned once more, cut to
    the same 2 KB bound deep analysis uses, and kept.

    The cost is stated where it is paid: out-of-root content now enters the
    deep-analysis input, bounded only by the placeholder and that 2 KB bound.
    An in-root excerpt keeps its previous treatment; its bound is enforced by
    `tooling_guard.prompts.trajectory`, which drops an oversized excerpt whole.

    An empty `project_roots` still drops every fragment, because that is a
    configuration error and not a scope: no location is provably in scope, and
    whoever forgot the roots must read why nothing was analysed. The census
    tells the two cases apart -- `outside_project_roots` only ever counts drops
    caused by a missing root set and `project_roots=missing` says so in words,
    while `outside_project_roots_kept` counts what was kept.

    The secret scan is bounded, so a fragment longer than the bound is read only
    in part; every marker rides the census, space-joined, and the census is
    byte-identical to the unmarked one when nothing was read in part and nothing
    was cut.

    Args:
        fragments: Candidate excerpt strings; non-strings are skipped.
        snapshot: PolicySnapshot or GatewayConfig carrying secret_patterns and
            project_roots.
        limit: Maximum number of fragments kept, None for no limit.

    Returns:
        A FragmentFilter with the kept fragments and the drop census.
    """
    kept: list[str] = []
    dropped_secret = 0
    dropped_outside = 0
    kept_outside = 0
    markers: list[str] = []
    patterns = _compiled_patterns(getattr(snapshot, "secret_patterns", ()) or ())
    roots = tuple(getattr(snapshot, "project_roots", None) or ())
    for item in fragments:
        if not isinstance(item, str) or not item.strip():
            continue
        scan = scan_secret_patterns(item, patterns)
        _note_marker(markers, scan.marker)
        if scan.pattern is not None:
            dropped_secret += 1
            continue
        if not roots:
            dropped_outside += 1
            continue
        anchors = paths.extract_absolute_paths(item)
        text = item
        if anchors and not all(
            paths.is_in_project_roots(anchor, snapshot) for anchor in anchors
        ):
            text = _placeholder_outside_roots(item, anchors, snapshot)
            rescan = scan_secret_patterns(text, patterns)
            _note_marker(markers, rescan.marker)
            if rescan.pattern is not None:
                dropped_secret += 1
                continue
            cut = _truncate_utf8(text, MAX_EXCERPT_BYTES)
            if cut != text:
                _note_marker(markers, f"fragment_truncated limit={MAX_EXCERPT_BYTES}")
            text = cut
            kept_outside += 1
        kept.append(text)
        if limit is not None and len(kept) >= limit:
            break
    return FragmentFilter(
        kept=tuple(kept),
        dropped_secret=dropped_secret,
        dropped_outside_roots=dropped_outside,
        outside_project_roots_kept=kept_outside,
        truncated_marker=" ".join(markers),
        roots_configured=bool(roots),
    )


def _note_marker(markers: list[str], marker: str) -> None:
    """Append a degradation marker once, in first-seen order."""
    if marker and marker not in markers:
        markers.append(marker)


def _placeholder_outside_roots(
    text: str, anchors: tuple[str, ...], snapshot: Any
) -> str:
    """Replace each out-of-root absolute literal with `<EXT>/<basename>`.

    Requirement: Deep Analysis Input Budget. The placeholder matches the one
    `prompts.state` and `anonymize.PathRedactor` already produce, so an operator
    reads one convention everywhere. Literals are replaced longest first, so a
    longer path is never half-rewritten by a shorter one, and one literal always
    maps to one placeholder inside the fragment.
    """
    mapping: dict[str, str] = {}
    for anchor in anchors:
        if paths.is_in_project_roots(anchor, snapshot):
            continue
        name = _placeholder_name(anchor)
        mapping[anchor] = f"<EXT>/{name}" if name else "<EXT>"
    for literal in sorted(mapping, key=len, reverse=True):
        text = text.replace(literal, mapping[literal])
    return text


def _placeholder_name(value: str) -> str:
    """Return the basename the `<EXT>` placeholder keeps, or an empty string."""
    text = value.strip().strip("\"'").replace("\\", "/").rstrip("/")
    name = text.rsplit("/", 1)[-1]
    return name.strip("\"',;)")


def _truncate_utf8(text: str, limit: int) -> str:
    """Return text cut to at most limit UTF-8 bytes without splitting a char.

    Requirement: Deep Analysis Input Budget. The bound counts encoded bytes, so
    a multi-byte character that would straddle the limit is dropped whole; the
    cut never leaves a partial character for the redactor or for the model.
    """
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", "ignore")


def _audit_sink(conn: Any, event: Mapping[str, Any]) -> int:
    """Hand one queued event to `audit.record_event`, the only row writer.

    Requirement: Retention and Rotation (single write queue). This is the
    `AuditWriter` sink of the production path, and it resolves
    `audit.record_event` through the module at call time rather than binding it
    when the gateway is built, so a test that swaps the module attribute still
    observes exactly the path production takes. It writes one row and nothing
    else -- ordering, retention and failure handling belong to the writer.

    Args:
        conn: Open store connection owned by the writer.
        event: Already-redacted event mapping.

    Returns:
        The rowid of the inserted audit row.
    """
    return audit.record_event(conn, event)


class Gateway:
    """Assemble the layers and run one decision per managed tool call.

    Requirement: Single Call Orchestration; Storage Unavailable Is Deny.

    Args:
        validation: Result of policy/config.validate_config.
        clock: Monotonic clock reader; time.monotonic when omitted.
        store: Open store connection; opened on demand when omitted.
        data_dir: Plugin data directory used to open the default store.
        snapshot: PolicySnapshot; built from the validated config when omitted.
        anonymizer: Central anonymizer; built from the config when omitted.
        notifier: notify_admin callable; notify.notify_admins by default.
        registry: Shared ApprovalRegistry; a private one when omitted.
        recorder: TrajectoryRecorder for the per-session window, optional.
        identity: IdentityProvider injected by the assembly point, optional.
        request_hook: Request hook adapter injected by the assembly point.
        deep_client: DeepReviewClient for background analysis, optional.
        deep_cache: Conclusion cache; a bounded private one when omitted.
        jev_client: Fast-judge client, optional; built from the config.
        context: Host plugin context used for notifications, optional.
        reviewer_registry: Reviewer registry injected by the assembly point or a
            test; assembled from the configuration when omitted.
        notify_timeout_s: Cap of one whole administrator notification, in
            seconds; NOTIFY_TIMEOUT_S when omitted.
    """

    def __init__(
        self,
        validation: ConfigValidationResult,
        *,
        clock: Callable[[], float] | None = None,
        store: Any = None,
        data_dir: Path | str | None = None,
        snapshot: PolicySnapshot | None = None,
        anonymizer: Anonymizer | None = None,
        notifier: Callable[..., Awaitable[Any]] | None = None,
        registry: ApprovalRegistry | None = None,
        recorder: Any = None,
        watch: TrajectoryWatch | None = None,
        identity: IdentityProvider | None = None,
        request_hook: Callable[[Any, Any], Any] | None = None,
        deep_client: Any = None,
        deep_cache: ConclusionCache | None = None,
        jev_client: JevClient | None = None,
        context: Any = None,
        raw: Mapping[str, Any] | None = None,
        reviewer_registry: ReviewerRegistry | None = None,
        notify_timeout_s: float | None = None,
    ) -> None:
        self.validation = validation
        self._raw_admins = _admins_of(raw)
        config = getattr(validation, "config", None)
        self._config: GatewayConfig | None = (
            config if isinstance(config, GatewayConfig) else None
        )
        # Requirement: Fast Judge Observability. The bands are resolved exactly
        # once, from the same configuration the fast judge itself is built from
        # (see _fast_judge_callable), and frozen into one immutable status view.
        # Both status faces read that view, so neither can render a threshold
        # the banding decision does not use -- or re-derive the shipped 30/75/0.6
        # defaults as if they were the configuration.
        self._fast_thresholds = FastThresholds.from_config(self._config)
        self._fast_judge_status = FastJudgeStatus(
            enabled=bool(getattr(self._config, "jev_enabled", False)),
            backend=_text_of(self._config, "fast_judge_backend"),
            allow_score=self._fast_thresholds.allow_score,
            block_score=self._fast_thresholds.block_score,
            min_confidence=self._fast_thresholds.min_confidence,
        )
        self._clock: Callable[[], float] = clock or time.monotonic
        self._store = store
        self._store_failed = False
        self._data_dir = data_dir
        # The host Context is needed by everything built below that resolves a
        # provider -- the deep client most of all: a client built without it turns
        # every request into a TypeError. It used to be assigned far below the
        # registry build, which made the registry capture a client-less judge.
        self._context = context
        self._snapshot = snapshot if snapshot is not None else self._build_snapshot()
        self._anonymizer = (
            anonymizer if anonymizer is not None else self._build_anonymizer()
        )
        self._jev_client = (
            jev_client if jev_client is not None else self._build_jev_client()
        )
        # Requirement: Fast Judge Budget. The per-request timeout is configuration,
        # not a constant: a local endpoint that cold starts slower than five seconds
        # would otherwise be unusable and every judgement would degrade. Read it off
        # the client when there is one (that object already clamped the key) so the
        # judge, the pipeline budget and the status surface cannot disagree.
        # An injected client need not carry the attribute (test doubles, older
        # three-line stubs), so the client is asked first and the configuration is
        # the fallback. Both paths clamp, and neither ever widens past the ceiling.
        injected_timeout = getattr(self._jev_client, "timeout_s", None)
        self._jev_timeout = (
            configured_timeout(injected_timeout)
            if self._jev_client is not None and injected_timeout is not None
            else configured_timeout(getattr(self._config, "jev_timeout_s", None))
        )
        self._deep_client = deep_client
        self._reviewer_injected = reviewer_registry is not None
        self._reviewers = (
            reviewer_registry
            if reviewer_registry is not None
            else self._build_reviewers()
        )
        self._deep_cache = deep_cache if deep_cache is not None else ConclusionCache()
        self._deep_tasks: set[asyncio.Task[Any]] = set()
        self._notice_tasks: set[asyncio.Task[Any]] = set()
        self._notifier = notifier or notify_admins
        self._notify_timeout_s = notify_timeout_seconds(notify_timeout_s)
        self._notify_limiter = NotifyRateLimiter()
        self._registry = registry if registry is not None else ApprovalRegistry()
        # Requirement: Trajectory Window.  The recorder used to be injection only
        # and no production path injected one, so the window was always empty:
        # R7/R9/R11 could not fire and no model layer was ever shown an earlier
        # call. A gateway without a window judges every call as if it were the
        # first, which is the opposite of what a trajectory review is for.
        self._recorder = recorder if recorder is not None else self._build_recorder()
        self._watch = watch if watch is not None else self._build_watch()
        self._judge_failures = 0
        self._judge_retry_at = 0.0
        self._identity = identity
        self._request_hook = request_hook
        self._hook_degraded: str | None = None
        self._context = context
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._sequences: dict[str, int] = {}
        self._wait_tasks: set[asyncio.Task[Any]] = set()
        self._wait_tickets: dict[str, asyncio.Task[Any]] = {}
        self._assembly_lock = threading.Lock()
        self._closed = False
        self._writer: audit.AuditWriter | None = None
        self._writer_conn: Any = None
        self._reviewer_disabled: bool | None = None
        self._reviewer_alert_pending = False
        self._sweep_alert_pending = False
        self._sweep_alert_attempts = 0
        self._note_reviewer_state()

    @classmethod
    def from_config(
        cls,
        config: Mapping[str, Any] | None = None,
        *,
        data_dir: Path | str | None = None,
        context: Any = None,
        clock: Callable[[], float] | None = None,
        store: Any = None,
        identity: IdentityProvider | None = None,
        request_hook: Callable[[Any, Any], Any] | None = None,
        recorder: Any = None,
        deep_client: Any = None,
    ) -> Gateway:
        """Build the gateway from a raw configuration mapping.

        Requirement: Single Call Orchestration.

        Args:
            config: Raw plugin configuration.
            data_dir: Plugin data directory for the default store.
            context: Host plugin context, used for admin notifications.
            clock: Monotonic clock reader.
            store: Pre-opened store connection, injected by tests.
            identity: IdentityProvider from the interface layer.
            request_hook: Request hook adapter from the interface layer.
            recorder: TrajectoryRecorder, optional.
            deep_client: DeepReviewClient, optional.

        Returns:
            A Gateway wired with every component the pipeline needs.
        """
        return cls(
            validate_config(config or {}),
            clock=clock,
            store=store,
            data_dir=data_dir,
            context=context,
            identity=identity,
            request_hook=request_hook,
            recorder=recorder,
            deep_client=deep_client,
            raw=config,
        )

    def remaining_seconds(self, context: Any = None) -> float | None:
        """Return the seconds this call has left before its own deadline.

        Requirement: Dynamic Suspension Budget; Delegation Fidelity. The answer
        is what the call scope holds: `_guard` wrote the one deadline of this
        call there before the review ran, and it stands until the call ends, so a
        review that already spent 100 of the 110 seconds reports 10 and not a
        freshly derived 110.

        Args:
            context: Host tool-call context. Kept for callers that hold one; the
                value is never re-derived from it, because doing so is exactly the
                bug this answers (R9-01).

        Returns:
            The remaining seconds, or None when no call scope is open, which the
            wrapper reports and then declines to clamp.
        """
        del context
        scope = _REVIEW_DEADLINE.get()
        if scope is None:
            return None
        try:
            now = float(self._clock())
        except (TypeError, ValueError):
            return None
        return scope.remaining(now)

    @property
    def config(self) -> GatewayConfig | None:
        """Return the validated configuration, None when disabled."""
        return self._config

    @property
    def snapshot(self) -> PolicySnapshot | None:
        """Return the policy snapshot of this session."""
        return self._snapshot

    @property
    def enabled(self) -> bool:
        """Return whether the gateway is enabled and fully assembled."""
        return bool(
            getattr(self.validation, "enabled", False) and self._config is not None
        )

    @property
    def closed(self) -> bool:
        """Return whether shutdown already ran."""
        return self._closed

    @property
    def mode(self) -> str:
        """Return the effective enforcement mode of this session."""
        snapshot_mode = getattr(self._snapshot, "mode", None)
        return effective_mode(getattr(self._config, "mode", None), snapshot_mode)

    @property
    def strip_unmanaged_tools(self) -> bool:
        """Return whether every unmanaged tool kind is stripped from the toolset.

        Requirement: Proxy Installation Through Public Surface (Scenario:
        不可纳管工具默认原样放行并披露 / 开关开启时强制剥离不可纳管工具).
        Off by default, so MCP tools, hand-off tools, background task tools,
        future_task and every shape the gateway cannot classify keep working
        as the host built them; install.py reads this attribute to decide between
        pass-through and strip. Without a validated configuration there is
        nothing to read and the default stands -- the same answer the hook uses
        for a missing gateway.
        """
        return bool(getattr(self._config, "strip_unmanaged_tools", False))

    @property
    def deep_cache(self) -> ConclusionCache:
        """Return the bounded conclusion cache of deep analysis."""
        return self._deep_cache

    @property
    def background_tasks(self) -> int:
        """Return how many background deep reviews are unfinished."""
        return len(self._deep_tasks)

    @property
    def hook_degraded(self) -> str | None:
        """Return why the last request hook round degraded, when it did."""
        return self._hook_degraded

    def set_mode(self, mode: str) -> bool:
        """Switch the enforcement mode of this session atomically.

        Requirement: Policy Snapshot Consistency; Fail-Closed Enforcement.
        policy/config.py and policy/snapshot.py own the mode, so the switch
        replaces the config and the rebuilt snapshot together: both fields are
        written inside one assembly-level lock with no ``await`` between the two
        assignments, so a call starting afterwards sees the new mode while a
        call already inside the pipeline keeps the immutable snapshot it entered
        with. An injected engine owns its own mode and is left alone; the
        pipeline still passes the new mode to it on every decide().

        The reviewer registry is rebuilt in the same lock window and it has no
        injection guard: every reviewer holds the snapshot, so a registry left
        over from the previous mode would keep judging against the old policy.
        The two rebuilds are assigned one after the other inside the same lock
        block with no ``await`` between them, so another ``set_mode`` cannot
        interleave and no coroutine can observe half of the pair.

        Args:
            mode: Target mode, case and surrounding whitespace ignored.

        Returns:
            True when the mode changed; False when it already holds or when the
            safety precondition refused the switch, in which case no state was
            touched at all.

        Raises:
            ValueError: mode is not observe or enforce, or no validated config
                is loaded and the gateway therefore cannot honour it.
        """
        target = _mode_value(mode)
        with self._assembly_lock:
            config = self._config
            if config is None:
                raise ValueError("网关尚未加载有效配置，无法切换模式")
            if target == self.mode:
                return False
            admins = tuple(getattr(config, "admins", ()) or ())
            if target == MODE_ENFORCE and not admins:
                return False
            new_config = replace(config, mode=target)
            new_snapshot = self._snapshot_for(new_config)
            self._config = new_config
            self._snapshot = new_snapshot
            if not self._reviewer_injected:
                self._reviewers = self._build_reviewers()
                self._note_reviewer_state()
            return True

    @property
    def judge_route(self) -> str | None:
        """Return the deep-analysis route recorded next to a verdict (6.8).

        Requirement: Judge Route Audit. policy/config.llm_mode is the single
        source of truth; store/audit.py persists the value in the judge_route
        column of every decision row it records.
        """
        mode = str(getattr(self._config, "llm_mode", "") or "").strip().lower()
        if mode == JUDGE_ROUTE_PROVIDER:
            return JUDGE_ROUTE_PROVIDER
        if mode == JUDGE_ROUTE_ENDPOINT:
            return JUDGE_ROUTE_ENDPOINT
        return None

    @property
    def store(self) -> Any:
        """Return the store connection, opening it on demand."""
        return self._open_store()

    @property
    def anonymizer(self) -> Anonymizer | None:
        """Return the central anonymizer used for every egress."""
        return self._anonymizer

    @property
    def registry(self) -> ApprovalRegistry:
        """Return the shared approval registry."""
        return self._registry

    @property
    def reviewers(self) -> ReviewerRegistry | None:
        """Return the reviewer registry of the current assembly.

        Requirement: Reviewer Registry. This is the live registry, not a copy: the
        four built-in adapters are registered with ``builtin=True``, so the
        registry itself refuses to unregister them and a duplicate name raises
        instead of silently replacing a stage. It is replaced when the mode
        switches, so a caller that needs an answer stable across a switch reads
        ``reviewer_statuses()`` instead of holding this object.
        """
        return self._reviewers

    @property
    def fast_judge_status(self) -> FastJudgeStatus:
        """Return the fast judge's effective configuration as one frozen view.

        Requirement: Fast Judge Observability. ``/guard status`` and the Web
        ``/status`` endpoint both read this object: whether the fast judge takes
        part, which backend the client actually speaks, and the two score bands
        plus the confidence floor the same score is banded with. It is assembled
        once in ``__init__`` from the configuration the fast judge is built from
        and never recomputed, so the two faces cannot disagree and neither can
        hardcode a backend or re-invent a threshold. A switched-off judge still
        reports its configuration -- the numbers say what would run, the switch
        says whether it runs -- and the tolerant reader in ``ui/commands.py``
        maps a gateway without this property to ``None`` instead of raising.
        """
        return self._fast_judge_status

    def reviewer_statuses(self) -> tuple[ReviewerStatus, ...]:
        """Return one status per registered reviewer, in presentation order.

        Requirement: Reviewer Registry. 11.5 renders ``/guard status`` and the web
        status endpoint from this tuple: disabled reviewers stay in it, and the
        registry owns ``name``, ``enabled`` and ``order``, so a status page never
        has to guess who takes part.
        """
        registry = self._reviewers
        if registry is None:
            return ()
        return tuple(registry.statuses())

    @property
    def locks(self) -> Mapping[tuple[str, str], asyncio.Lock]:
        """Return a read-only view of the per-key decision locks."""
        return MappingProxyType(self._locks)

    async def on_llm_request(self, event: Any = None, request: Any = None) -> Any:
        """Forward one request hook round to the injected interface adapter.

        Requirement: Hook Delivery and Canary; Degraded Mode Alert; Operator
        Introspection. This method stays interface-free: the root main.py
        injects interface/hooks.on_llm_request so the mechanism layer keeps
        ownership of the hook. The outcome of that round is not dropped: its
        degradation becomes one audit row, one rate-limited administrator
        notice and the `hook_degraded` status field, because a stripped toolset
        with no recorded reason is exactly the failure this hook exists to
        prevent.

        Args:
            event: Host message or cron event.
            request: Host ProviderRequest.

        Returns:
            The adapter result, or None when no adapter was injected.
        """
        if self._reviewer_alert_pending:
            self._reviewer_alert_pending = False
            with contextlib.suppress(Exception):
                await self._alert_reviewer_state(DEGRADED_BASE_CHECK_DISABLED)
        if self._sweep_alert_pending:
            self._sweep_alert_pending = False
            with contextlib.suppress(Exception):
                await self._alert_startup_sweep_failed(
                    attempts=self._sweep_alert_attempts, event=event
                )
        if self._request_hook is None:
            return None
        outcome = self._request_hook(event, request)
        if isawaitable(outcome):
            outcome = await outcome
        await self._note_hook_outcome(outcome, event=event)
        return outcome

    async def on_agent_done(self, event: Any = None) -> int:
        """Void the tickets an agent run left pending when its session ended.

        Requirement: External Cancellation Degradation.  A run that ends can no
        longer deliver the suspended call, so every undecided ticket of that
        session is settled as canceled_external, its waiter is cancelled and one
        audit row records that the session ended and the tickets are void.

        This method runs inside a host hook, so it never raises: an escaping
        error would abort the host's own end-of-run pipeline.  Cancellation of the
        hook itself still propagates, because that is the host's decision.

        Args:
            event: Host message event of the run that just ended, or None.

        Returns:
            How many tickets were voided.
        """
        try:
            return self._void_run_tickets(event)
        except _WATCH_ERRORS:
            return 0

    def _void_run_tickets(self, event: Any) -> int:
        """Settle every undecided ticket of one finished agent run.

        Args:
            event: Host message event of the run that ended, or None.

        Returns:
            How many tickets were settled as canceled_external.
        """
        identity = self._identity
        if event is None or identity is None:
            return 0
        session = _safe_text(identity.session_key, event)
        if not session or session == UNKNOWN_SESSION:
            return 0
        subject = _safe_text(identity.subject_key, event) or UNKNOWN_SUBJECT
        conn = self._open_store()
        if conn is None:
            return 0
        voided: list[str] = []
        for ticket in tickets.list_pending(conn, session_key=session):
            ticket_id = str(getattr(ticket, "ticket_id", "") or "")
            if not ticket_id:
                continue
            with contextlib.suppress(*_WATCH_ERRORS):
                tickets.cancel_external(
                    conn,
                    ticket_id,
                    actor=AGENT_RUN_END_ACTOR,
                    reason=AGENT_RUN_END_REASON,
                )
            self._registry.discard(ticket_id)
            waiting = self._wait_tickets.get(ticket_id)
            if waiting is not None and not waiting.done():
                waiting.cancel()
            voided.append(ticket_id)
        if not voided:
            return 0
        self._record_run_voided(subject=subject, session=session, ids=voided)
        return len(voided)

    def _record_run_voided(self, *, subject: str, session: str, ids: list[str]) -> None:
        """Write the audit row of a finished agent run whose tickets were voided.

        Requirement: External Cancellation Degradation.

        Args:
            subject: Requester key of the finished run.
            session: Session key of the finished run.
            ids: Ticket identifiers settled by on_agent_done.
        """
        writer = self.audit_writer()
        if writer is None:
            return
        line = f"{AGENT_RUN_END_REASON}: 会话结束，票据作废 {len(ids)} 张 ({', '.join(ids)})"
        writer.submit(
            {
                "decision": Decision.CANCELED_EXTERNAL.value,
                "source": audit.SOURCE_NATIVE,
                "would_be": "",
                "rule_id": "",
                "tool_name": "",
                "subject_key": subject,
                "session_key": session,
                "ticket_id": ids[0],
                "summary_line": self._redact_audited(line),
                "degraded": True,
                "observe": False,
                "mode": self.mode,
                "judge_route": self.judge_route,
                "rule_set_version": RULE_SET_VERSION,
            }
        )
        self._drain_audit()

    async def _note_hook_outcome(self, outcome: Any, *, event: Any = None) -> None:
        """Record and report the degradation one hook round returned (9.1).

        Requirement: Degraded Mode Alert; Operator Introspection. The hook
        reports its facts as a return value, so nothing survives the call unless
        it is stored here: the managed tools were already stripped fail-closed,
        and the reason they were stripped leaves no trace otherwise. Every step
        is best-effort -- the strip already happened and raising out of this
        hook would fail the whole LLM request, which is worse than losing one
        audit row.

        Args:
            outcome: Whatever the injected adapter returned, of any shape.
            event: Host event of this round, used for the administrator notice.
        """
        degraded = _hook_field(outcome, "degraded")
        if degraded is None:
            return
        skipped = _hook_field(outcome, "skipped")
        self._hook_degraded = degraded
        with contextlib.suppress(Exception):
            self._record_hook_degraded(degraded, skipped)
        with contextlib.suppress(Exception):
            await self._alert_hook_degraded(degraded, skipped, event=event)

    def _record_hook_degraded(self, degraded: str, skipped: str | None) -> None:
        """Write one hook-degradation row through the shared audit queue.

        Requirement: Degraded Mode Alert; Retention and Rotation (single write
        queue). The row is submitted and drained like every other one and
        carries the rule set version like every other one; an unavailable store
        is logged instead of raised, because this runs inside the request hook.
        """
        line = f"hook degraded={degraded}"
        if skipped is not None:
            line = f"{line} skipped={skipped}"
        writer = self.audit_writer()
        if writer is None:
            _host_logger().warning(
                "tooling_guard: hook degraded=%s not recorded, store unavailable",
                degraded,
            )
            return
        writer.submit(
            {
                "decision": Decision.ALLOW_PASSTHROUGH.value,
                "source": audit.SOURCE_NATIVE,
                "summary_line": self._redact_audited(line),
                "degraded": True,
                "observe": False,
                "mode": self.mode,
                "judge_route": self.judge_route,
                "rule_set_version": RULE_SET_VERSION,
            }
        )
        try:
            writer.drain()
        except db.StorageUnavailableError:
            _host_logger().warning(
                "tooling_guard: hook degraded=%s row dropped, store unavailable",
                degraded,
            )

    async def _alert_hook_degraded(
        self, degraded: str, skipped: str | None, *, event: Any = None
    ) -> bool:
        """Tell the administrators about one hook degradation, rate-limited.

        Requirement: Degraded Mode Alert; Rate Limiting and Merging. The
        degraded kind is part of the alert class, so the same degradation is
        reported at most once per degraded window while two different kinds
        inside that window are still reported separately.

        Args:
            degraded: Degradation kind the hook reported.
            skipped: Stage the hook skipped, when it named one.
            event: Host event of this round, when available.

        Returns:
            True when an administrator was reached.
        """
        admins = tuple(getattr(self._config, "admins", ()) or ())
        if not admins:
            return False
        admission = self._notify_limiter.admit(
            subject=UNKNOWN_SUBJECT,
            tool_name=f"{HOOK_ALERT_TOOL}:{degraded}",
            mode=self.mode,
            decision=Decision.DENIED_NO_WRAPPER,
            degraded=degraded,
            now=self._clock(),
        )
        if not admission.send:
            return False
        message = f"工具集安装降级 degraded={degraded}"
        if skipped is not None:
            message = f"{message}（skipped={skipped}）"
        message = (
            f"{message}：本轮受管工具已按 fail-closed 从请求工具集中移除，"
            "canary 指纹或工具集安装与宿主不匹配；请核对宿主版本与工具集形态。"
        )
        merged_line = render_merged_notice(admission.merged)
        if merged_line:
            message = f"{message}\n{merged_line}"
        delivered = await self._send_notice(
            message,
            admins=admins,
            context=None,
            event=event,
            audit=_NoticeAudit(
                _Plan(decision=Decision.DENIED_NO_WRAPPER, reason=degraded),
                tool=HOOK_ALERT_TOOL,
                subject=UNKNOWN_SUBJECT,
                label=f"hook degraded={degraded}",
            ),
        )
        return bool(delivered)

    def _base_check_enabled(self) -> bool:
        """Return whether the configuration keeps the base checker at work.

        Requirement: Built-in Base Checker. The switch defaults to on, so a
        configuration written before the switch existed keeps the checker; the
        reviewer itself never reads it, it is the assembly that leaves the
        checker out and the status surface that reports the fact.
        """
        return bool(getattr(self._config, "base_check_enabled", True))

    def _jev_enabled(self) -> bool:
        """Return whether the configuration asks for the fast judge at all.

        Requirement: Reviewer Registry; Fail-Closed Triage. The switch is read by
        the assembly, never by ``reviewers/jev_fast.py``: a switched-off fast
        reviewer must cost nothing, so no client is built and the adapter reports
        ``no_judge`` instead of inventing a verdict. The default is off, the same
        default ``policy/config.py`` applies, and a gateway with no readable
        configuration has nothing to build either.
        """
        return bool(getattr(self._config, "jev_enabled", False))

    def _llm_enabled(self) -> bool:
        """Return whether the configuration asks for the deep reviewer at all.

        Requirement: Deep Analysis Client; Deep Analysis Sampling. Off means no
        deep client is built, so ``deep_review`` answers ``judge_unavailable``
        before any request: the synchronous dispatch and the background task both
        stop at that same branch. It never relaxes a verdict -- the policy stage,
        which owns paths, credentials and T-strong suspends, is not switchable.
        """
        return bool(getattr(self._config, "llm_enabled", True))

    def _note_reviewer_state(self) -> None:
        """Record and report a base-checker switch that actually moved.

        Requirement: Built-in Base Checker. Disabling the base checker is
        allowed, but it must not be silent: one degraded audit row, one
        rate-limited administrator alert and a status entry that says disabled.
        The reviewer itself stays free of all three (reviewers/ never writes the
        store or notifies). Only a real transition is recorded, so a restart with
        the same configuration does not replay the row, and the very first
        observation of an enabled checker writes nothing at all.
        """
        disabled = not self._base_check_enabled()
        previous = self._reviewer_disabled
        self._reviewer_disabled = disabled
        if previous is None:
            if not disabled:
                return
        elif previous == disabled:
            return
        kind = (
            DEGRADED_BASE_CHECK_DISABLED if disabled else DEGRADED_BASE_CHECK_RESTORED
        )
        with contextlib.suppress(Exception):
            self._record_reviewer_state(kind, disabled=disabled)
        if disabled:
            self._schedule_reviewer_alert(kind)

    def _record_reviewer_state(self, kind: str, *, disabled: bool) -> None:
        """Write one reviewer-state row through the shared audit queue.

        Requirement: Built-in Base Checker; Observability. The row is submitted
        and drained like every other one, carries the rule set version like every
        other one, and sets `degraded` so the tail marker `degraded=<kind>`
        lands in the summary line; an unavailable store is logged instead of
        raised, because assembly must not fail over one observation.

        Args:
            kind: Degradation kind of the transition.
            disabled: Whether the checker is now disabled.
        """
        line = f"reviewer degraded={kind}"
        if disabled:
            line = f"{line} base_check=disabled"
        writer = self.audit_writer()
        if writer is None:
            _host_logger().warning(
                "tooling_guard: reviewer degraded=%s not recorded, store unavailable",
                kind,
            )
            return
        writer.submit(
            {
                "decision": Decision.ALLOW_PASSTHROUGH.value,
                "source": audit.SOURCE_NATIVE,
                "summary_line": self._redact_audited(line),
                "degraded": True,
                "observe": False,
                "mode": self.mode,
                "judge_route": self.judge_route,
                "rule_set_version": RULE_SET_VERSION,
            }
        )
        try:
            writer.drain()
        except db.StorageUnavailableError:
            _host_logger().warning(
                "tooling_guard: reviewer degraded=%s row dropped, store unavailable",
                kind,
            )

    def _schedule_reviewer_alert(self, kind: str) -> None:
        """Deliver the reviewer-state alert without blocking assembly.

        Requirement: Built-in Base Checker (rate-limited alert). Assembly is
        synchronous and may run outside a loop, so the notice travels as its own
        task when a loop is running and is otherwise left pending for the next
        hook round; either way the audit row above is already written.

        Args:
            kind: Degradation kind of the transition.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._reviewer_alert_pending = True
            return
        task = loop.create_task(self._alert_reviewer_state(kind))
        self._notice_tasks.add(task)
        task.add_done_callback(self._notice_done)

    async def _alert_reviewer_state(self, kind: str) -> bool:
        """Tell the administrators about one reviewer-state change, rate-limited.

        Requirement: Built-in Base Checker; Rate Limiting and Merging. The kind
        is part of the alert class, so one window carries at most one message per
        kind while a different kind inside that window is still reported.

        Args:
            kind: Degradation kind of the transition.

        Returns:
            True when an administrator was reached.
        """
        admins = tuple(getattr(self._config, "admins", ()) or ())
        if not admins:
            return False
        admission = self._notify_limiter.admit(
            subject=UNKNOWN_SUBJECT,
            tool_name=f"{REVIEWER_ALERT_TOOL}:{kind}",
            mode=self.mode,
            decision=Decision.DENIED_NO_WRAPPER,
            degraded=kind,
            now=self._clock(),
        )
        if not admission.send:
            return False
        message = f"审查器降级 degraded={kind}：基础检查器 base_check 已停用，"
        message = (
            f"{message}该审查器只负责白名单提示，路径与用户黑名单、私钥与严格白名单"
            f"仍由不可停用的 policy 阶段判定，/guard status 会显示已停用；"
            "其余审查器照常运行，放行仍要求它们全部返回 allow 或 skip。"
        )
        merged_line = render_merged_notice(admission.merged)
        if merged_line:
            message = f"{message}\n{merged_line}"
        delivered = await self._send_notice(
            message,
            admins=admins,
            context=None,
            event=None,
            audit=_NoticeAudit(
                _Plan(decision=Decision.DENIED_NO_WRAPPER, reason=kind),
                tool=REVIEWER_ALERT_TOOL,
                subject=UNKNOWN_SUBJECT,
                label=f"reviewer state {kind}",
            ),
        )
        return bool(delivered)

    def schedule_startup_sweep_alert(self, *, attempts: int = 0) -> None:
        """Deliver the startup-sweep alert without blocking the caller.

        Requirement: Degraded Mode Alert. Opening the store is synchronous and may
        run outside a loop, so the notice travels as its own task when a loop is
        running and is otherwise left pending for the next hook round; either way
        the state it reports is already visible through /guard status.

        The name is public because the command face owns the other producer: a
        failed /guard sweep recovery has to reach this same scheduler, and
        ui/commands.py probes it by this name. A private name here would make that
        probe silently resolve to None and drop the alert.

        Args:
            attempts: Startup sweep attempts made so far.
        """
        self._sweep_alert_attempts = int(attempts)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._sweep_alert_pending = True
            return
        task = loop.create_task(
            self._alert_startup_sweep_failed(attempts=int(attempts))
        )
        self._notice_tasks.add(task)
        task.add_done_callback(self._notice_done)

    async def _alert_startup_sweep_failed(
        self, *, attempts: int = 0, event: Any = None
    ) -> bool:
        """Tell the administrators that approvals are closed, rate-limited.

        Requirement: Degraded Mode Alert; Rate Limiting and Merging; Ticket
        Persistence (review R11-03). The admission is a degraded one, so the same
        failure is reported at most once per degraded window (600 s) however often
        status is polled or the recovery is retried; a retry that fails again
        inside the window is folded into the next message, not sent twice.

        Args:
            attempts: Startup sweep attempts made so far.
            event: Host event of this round, when available.

        Returns:
            True when an administrator was reached.
        """
        admins = tuple(getattr(self._config, "admins", ()) or ())
        if not admins:
            return False
        admission = self._notify_limiter.admit(
            subject=UNKNOWN_SUBJECT,
            tool_name=STARTUP_SWEEP_ALERT_TOOL,
            mode=self.mode,
            decision=Decision.DENIED_NO_WRAPPER,
            degraded=DEGRADED_STARTUP_SWEEP,
            now=self._clock(),
        )
        if not admission.send:
            return False
        message = (
            f"启动票据清理失败 degraded={DEGRADED_STARTUP_SWEEP}"
            f" attempts={int(attempts)}："
            "批准侧已关闭 —— 已批准票据的四元匹配与消费一律拒绝（fail-closed），"
            "进程照常运行但无法消费任何批准。"
        )
        message = (
            f"{message}排除存储故障后请由管理员执行 /guard sweep 重新清理并重新打开批准闸门；"
            "该动作只作废本进程启动前创建的票据，不会动本进程的活票据。"
        )
        merged_line = render_merged_notice(admission.merged)
        if merged_line:
            message = f"{message}\n{merged_line}"
        delivered = await self._send_notice(
            message,
            admins=admins,
            context=None,
            event=event,
            audit=_NoticeAudit(
                _Plan(
                    decision=Decision.DENIED_NO_WRAPPER,
                    reason=DEGRADED_STARTUP_SWEEP,
                ),
                tool=STARTUP_SWEEP_ALERT_TOOL,
                subject=UNKNOWN_SUBJECT,
                label=f"startup sweep failed attempts={int(attempts)}",
            ),
        )
        return bool(delivered)

    def _note_startup_sweep_state(self, conn: Any) -> None:
        """Alert the administrators once when opening left approvals closed.

        Requirement: Degraded Mode Alert; Ticket Persistence (review R11-03). A
        failed startup sweep leaves find_approved and consume_approved failing
        closed while the process keeps running, so the operator has to learn about
        it: this is the alert half, the /guard status line and the web /status
        payload are the visible half. It fires only when the state is actually
        closed and never retries the sweep -- the explicit /guard sweep command is
        the only retry, so opening the store cannot loop.

        Args:
            conn: Connection that was just opened.
        """
        try:
            state = db.startup_sweep_state(conn)
        except Exception:  # noqa: BLE001 - an unreadable state must not fail an open
            return
        if state.ok:
            return
        self.schedule_startup_sweep_alert(attempts=int(state.attempts))

    def _publish_deadline(self, deadline: float) -> None:
        """Write this call's deadline into the open scope, once.

        Requirement: Delegation Fidelity. First writer wins: a scope already
        carrying a deadline belongs to a call in progress, and re-writing it
        would reset the very budget this scope exists to keep.

        Args:
            deadline: Absolute deadline _guard derived for this call.
        """
        scope = _REVIEW_DEADLINE.get()
        if scope is not None and scope.deadline is None:
            scope.deadline = deadline

    def begin_call_scope(self) -> Any:
        """Open the deadline scope of one guarded call.

        Requirement: Delegation Fidelity (R9-01). The scope has to outlive
        `guard_call`, because interface/wrapper.py asks for the remaining budget
        after the verdict and before delegating; the proxy therefore opens it and
        the gateway only fills it. A scope that is open but still empty belongs to
        this call and is reused, so the deadline is set exactly once and the
        opener keeps ownership of the token.

        Returns:
            The token to hand to `end_call_scope`, or None when a scope for this
            call is already open.
        """
        scope = _REVIEW_DEADLINE.get()
        if scope is not None and scope.deadline is None:
            return None
        return _REVIEW_DEADLINE.set(CallScope())

    def end_call_scope(self, token: Any) -> None:
        """Close the scope `begin_call_scope` opened, and nothing else.

        Args:
            token: Token returned by `begin_call_scope`; None is a no-op.
        """
        if token is not None:
            _REVIEW_DEADLINE.reset(token)

    async def guard_call(
        self,
        *,
        inner: Any,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        context: Any = None,
    ) -> CallOutcome:
        """Answer one managed tool call before the proxy delegates it.

        Requirement: Single Call Orchestration; Fail-Closed on Broken Choke
        Point. Every failure becomes a non-empty denial; cancellation of the
        enclosing request is the only outcome that propagates.

        Args:
            inner: Original toolset entry the proxy would delegate to.
            tool_name: Public tool name the model called.
            args: Raw arguments the model produced.
            context: Host tool-call context, when the caller has one.

        Returns:
            A CallOutcome the proxy renders or delegates on.
        """
        scope = self.begin_call_scope()
        try:
            return await self._guard(
                inner=inner,
                tool_name=tool_name,
                args=dict(args or {}),
                context=context,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - the choke point fails closed
            return self._deny(f"{REASON_FAIL_CLOSED}（{type(exc).__name__}）")
        finally:
            self.end_call_scope(scope)

    async def handle_call(
        self,
        tool: Any,
        arguments: Mapping[str, Any] | None = None,
        *,
        context: Any = None,
    ) -> CallOutcome:
        """Answer one call through the positional entry point.

        Requirement: Single Call Orchestration. Kept because
        interface/wrapper.py:289-291 falls back to it when guard_call is absent;
        both entry points run the same pipeline.

        Args:
            tool: Tool object the proxy received.
            arguments: Raw arguments the model produced.
            context: Host tool-call context, when the caller has one.

        Returns:
            A CallOutcome the proxy renders or delegates on.
        """
        return await self.guard_call(
            inner=tool,
            tool_name=_tool_name(tool),
            args=arguments,
            context=context,
        )

    async def shutdown(self) -> None:
        """Settle open tickets, cancel waiters and close the store, once.

        Requirement: External Cancellation Degradation; Storage Location
        (lifecycle); Deep Analysis Sampling. Unfinished background deep reviews
        are cancelled and settled first, so no task of this gateway outlives the
        loop that owns it; every undecided ticket becomes canceled_external and
        the call is idempotent: a second shutdown is a no-op that never raises.
        """
        if self._closed:
            return
        self._closed = True
        for task in tuple(self._deep_tasks):
            task.cancel()
        if self._deep_tasks:
            await asyncio.gather(*tuple(self._deep_tasks), return_exceptions=True)
            self._deep_tasks.clear()
        for task in tuple(self._wait_tasks):
            task.cancel()
        if self._wait_tasks:
            await asyncio.gather(*tuple(self._wait_tasks), return_exceptions=True)
            self._wait_tasks.clear()
        for task in tuple(self._notice_tasks):
            task.cancel()
        if self._notice_tasks:
            await asyncio.gather(*tuple(self._notice_tasks), return_exceptions=True)
            self._notice_tasks.clear()
        conn = self._store
        if conn is not None:
            self._drain_audit()
            self._settle_tickets(conn)
            db.close_db(conn)
            self._store = None
        self._writer = None
        self._writer_conn = None
        self._locks.clear()
        self._sequences.clear()

    def _settle_tickets(self, conn: Any) -> int:
        """Cancel every undecided ticket, tolerating a broken store.

        Requirement: External Cancellation Degradation.

        Args:
            conn: Open store connection.

        Returns:
            The number of tickets settled as canceled_external.
        """
        settled = 0
        try:
            for ticket in tickets.list_pending(conn):
                tickets.cancel_external(
                    conn,
                    ticket.ticket_id,
                    actor=WAITER_ACTOR,
                    reason=SHUTDOWN_REASON,
                )
                settled += 1
        except Exception:  # noqa: BLE001 - shutdown must never raise
            self._store_failed = True
        return settled

    def sample_fragments(
        self, fragments: Iterable[Any], *, limit: int | None = None
    ) -> FragmentFilter:
        """Run the entry-side fragment gate and audit every drop (task 6.4).

        Requirement: Entry-Side Fragment Gate. The recorded fact is a count plus
        a reason, never a path and never a secret.

        Args:
            fragments: Candidate excerpts for deep analysis.
            limit: Maximum number of fragments kept, None for no limit.

        Returns:
            The FragmentFilter for this round.
        """
        gate = filter_fragments(fragments, self._snapshot, limit=limit)
        if gate.dropped or gate.outside_project_roots_kept:
            self._record_fragment_census(gate)
        return gate

    async def deep_review(
        self,
        summary: Any,
        *,
        deadline: float | None = None,
        timeout_s: float | None = None,
    ) -> DeepReviewResult:
        """Run one redacted deep review over in-scope fragments only.

        Requirement: Deep Analysis Sampling; Sanitized Persistence.

        Args:
            summary: Trajectory summary (mapping or object) supplying fragments.
            deadline: Call deadline; the 30 second reserve is respected.
            timeout_s: Explicit timeout, clamped by the remaining deep budget.
                Without it the budget is min(config.deep_analysis_timeout_s,
                remaining - 30), so the configuration decides how long a review
                may take.

        Returns:
            A DeepReviewResult carrying the route, the answer and the gate.  A
            budget consumed by the 30 second reserve yields degraded
            "deep_budget_exhausted" and no request at all.
        """
        gate = self.sample_fragments(_summary_fragments(summary))
        if not gate.kept:
            return DeepReviewResult(gate=gate, degraded="no_fragment_in_scope")
        client = (
            self._deep_client
            if self._deep_client is not None
            else self._build_deep_client()
        )
        if client is None:
            return DeepReviewResult(
                route=self.judge_route, degraded=DEGRADED_JUDGE_UNAVAILABLE
            )
        cap = self._deep_timeout_cap()
        budget = timeout_s
        if deadline is not None:
            remaining_budget = deep_budget_seconds(deadline, self._clock(), cap=cap)
            if remaining_budget <= 0:
                return DeepReviewResult(
                    route=self.judge_route,
                    gate=gate,
                    degraded="deep_budget_exhausted",
                )
            budget = (
                min(timeout_s, remaining_budget)
                if timeout_s is not None
                else remaining_budget
            )
        if budget is None:
            budget = cap
        prompt = build_trajectory_prompt({"excerpts": list(gate.kept)})
        answer = await client.review(self._redact(prompt), timeout_s=budget)
        return DeepReviewResult(route=self.judge_route, answer=answer, gate=gate)

    def _deep_timeout_cap(self) -> float:
        """Return config.deep_analysis_timeout_s, or its documented fallback.

        Requirement: Deep Analysis Sampling.  policy/config.py already rejects a
        non-positive setting, so the conversion here only keeps a hand-built
        GatewayConfig from producing a nonsense budget.

        Returns:
            The configured deep-analysis timeout in seconds.
        """
        raw = getattr(self._config, "deep_analysis_timeout_s", None)
        try:
            cap = float(raw)
        except (TypeError, ValueError):
            return DEFAULT_DEEP_ANALYSIS_TIMEOUT_S
        return cap if cap > 0 else DEFAULT_DEEP_ANALYSIS_TIMEOUT_S

    async def drain_background(self) -> int:
        """Await every unfinished background deep review, returning how many.

        Requirement: Deep Analysis Sampling (task 6.3). A background review never
        holds up a call, so whoever needs what it wrote -- a test, an operator
        tool -- waits here instead of sleeping: the reviews are ordinary tasks of
        this loop and only shutdown() cancels them.

        Returns:
            The number of background reviews this round waited for.
        """
        tasks = tuple(self._deep_tasks)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return len(tasks)

    def _peek_sequence(self, session: str) -> int:
        """Return the ts_seq the next _append_trajectory stores for this session.

        Requirement: Analysis Result Caching (task 6.5). The pending sequence is
        what names the analyzed segment, so the key is computable before the row
        exists.
        """
        return self._sequences.get(session, 0) + 1

    def _deep_summary(
        self,
        *,
        tool: str,
        args: Mapping[str, Any],
        subject: str,
        session: str,
        digest_value: str,
        plan: _Plan,
    ) -> dict[str, Any]:
        """Build the trajectory summary one deep review reads.

        Requirement: Deep Analysis Sampling; Entry-Side Fragment Gate. The
        summary mirrors what _append_trajectory would store for this call plus the
        window that precedes it, so the reviewed segment is the segment the cache
        key names; every excerpt still passes the entry-side gate afterwards.
        """
        excerpts: list[str] = []
        window = self._trajectory(session)
        if isinstance(window, Iterable):
            for record in window:
                line = _field_of(record, "summary_line")
                if isinstance(line, str) and line.strip():
                    excerpts.append(line)
        return {
            "ts_seq": self._peek_sequence(session),
            "call_id": plan.call_id or "",
            "user": subject,
            "session": session,
            "tool": tool,
            "args_digest": digest_value,
            "rule_hits": () if plan.rule_id is None else (plan.rule_id,),
            "labels": plan.labels,
            "summary_line": self._summary_line(tool, args),
            "decision": plan.decision.value,
            "excerpts": tuple(excerpts),
        }

    def _deep_cache_key(
        self, *, subject: str, sequence: int, digest_value: str
    ) -> ConclusionKey:
        """Return the conclusion-cache key of one analyzed segment (task 6.5).

        Requirement: Analysis Result Caching; Rule Set Versioning. The key names
        the subject, the ts_seq range and the catalog version that produced the
        conclusion, plus the argument digest: the same segment judged for a
        different argument set is a different question. RULE_SET_VERSION is read
        from triage/rules.py at call time and never copied, so a catalog bump
        invalidates every earlier conclusion by itself.
        """
        return ConclusionKey(
            subject=subject,
            ts_seq_start=sequence,
            ts_seq_end=sequence,
            rule_set_version=RULE_SET_VERSION,
            args_digest=digest_value,
        )

    async def _sync_deep_review(
        self, summary: Mapping[str, Any], *, deadline: float, now: float
    ) -> DeepReviewResult:
        """Run the synchronous deep review inside the request budget (task 6.3).

        Requirement: Deep Analysis Sampling; Fail-Closed Triage; Dynamic
        Suspension Budget. The budget is min(20, deadline - now - 30) through
        deep_budget_seconds and never the 60 second background default; a budget
        the 30 second reserve already consumed issues no request at all and says
        so; a broken request degrades into a suspension, never into an allow.
        """
        if self._judge_retry_at > now:
            return DeepReviewResult(
                route=self.judge_route, degraded=DEGRADED_JUDGE_UNAVAILABLE
            )
        budget = deep_budget_seconds(deadline, now, cap=DEEP_REVIEW_BUDGET_CAP_S)
        if budget <= 0:
            return DeepReviewResult(
                route=self.judge_route, degraded=DEGRADED_DEEP_BUDGET
            )
        result = await _guarded_review(
            self.deep_review(summary, deadline=deadline, timeout_s=budget),
            route=self.judge_route,
            degraded=DEGRADED_DEEP_FAILED,
        )
        self._note_judge_result(result, now=now)
        return result

    def _note_judge_result(self, result: DeepReviewResult, *, now: float) -> None:
        """Track consecutive judge failures and trip the breaker when they add up.

        Requirement: Judge Unavailability; Fail-Closed Triage. An answer resets the
        count, so only an unbroken run of unusable judges opens the breaker and a
        single timeout still fails closed as a suspension. The breaker then lasts
        JUDGE_COOLDOWN_S, after which the judge is probed again.

        Args:
            result: The deep-review result just produced.
            now: Current instant on the gateway clock.
        """
        degraded = result.degraded or ""
        if result.answer is not None:
            self._judge_failures = 0
            self._judge_retry_at = 0.0
            return
        unusable = degraded == DEGRADED_JUDGE_UNAVAILABLE or degraded.startswith(
            DEGRADED_DEEP_FAILED
        )
        if not unusable:
            return
        self._judge_failures += 1
        # Requirement: Judge Unavailability. One log line per failure burst: the
        # audit row carries the marker, but a marker read as "judge_unavailable"
        # says nothing about why, and the circuit breaker then hides every later
        # attempt for JUDGE_COOLDOWN_S. Naming the first fact in the process log is
        # what turns "everything is degraded" into a cause an operator can act on.
        if self._judge_failures == 1:
            _LOGGER.warning(
                "tooling_guard: deep review unusable (%s); %s more failure(s) open "
                "the breaker for %ss",
                degraded or "no answer",
                max(JUDGE_FAILURE_THRESHOLD - 1, 0),
                int(JUDGE_COOLDOWN_S),
            )
        if self._judge_failures >= JUDGE_FAILURE_THRESHOLD:
            if self._judge_retry_at <= now:
                _LOGGER.warning(
                    "tooling_guard: deep review breaker open for %ss after %s "
                    "consecutive failures (last: %s)",
                    int(JUDGE_COOLDOWN_S),
                    self._judge_failures,
                    degraded or "no answer",
                )
            self._judge_retry_at = now + JUDGE_COOLDOWN_S

    def _trusted_root_skip(
        self, *, tool: str, args: Mapping[str, Any], base: str | None
    ) -> tuple[paths.PathKey, ...] | None:
        """Return the in-root targets that let this call skip deep analysis.

        Requirement: Deep Analysis Sampling. Three facts must hold at once: the
        trust switch is on in the live snapshot, every target of this call
        resolves inside a project root, and the tool is not one of the exec
        family. The exec family stays under review every time because an in-root
        shell call can still reach anything the process can reach (see the note
        in `policy/tools.py`); a call with no target at all is not "inside the
        roots" either, so `trusted_in_project_roots` refuses it.

        Args:
            tool: Public tool name of the call being judged.
            args: Raw arguments of that call.
            base: Workspace root that resolves its relative targets.

        Returns:
            The resolved targets when the review may be skipped, else None.
        """
        snapshot = self._snapshot
        if snapshot is None or not getattr(snapshot, "trust_project_roots", False):
            return None
        if is_exec_tool(tool):
            return None
        try:
            features = classify_features(snapshot, tool, args)
            targets = _resolved_targets(features, base=base)
        except _WATCH_ERRORS:
            return None
        if not trusted_in_project_roots(targets, snapshot):
            return None
        return targets

    async def _deep_dispatch(
        self,
        plan: _Plan,
        *,
        tool: str,
        args: Mapping[str, Any],
        subject: str,
        session: str,
        digest_value: str,
        deadline: float,
        now: float,
        base: str | None = None,
    ) -> _Plan:
        """Dispatch the deep review of this call before its verdict settles.

        Requirement: Deep Analysis Sampling; Analysis Result Caching; Fail-Closed
        Triage. A rule hit, a medium/high severity, or a fast-judge request for
        the deep analysis (plan.force_deep) runs the review synchronously,
        inside the request budget, because that is the only case where a
        conclusion can still change what the model is told. Everything else is
        analysed on a background task whose conclusion reaches the audit trail
        and the cache only: the verdict this call returns is what triage
        produced and stays that way.

        A call the trust switch already cleared -- every target inside a project
        root, tool outside the exec family -- is not analysed at all: it leaves
        one audit row carrying `deep_skipped=trusted_project_root` and neither
        the synchronous nor the background path is entered.

        Returns:
            The plan a deep conclusion may have tightened; unchanged otherwise.
        """
        trusted = self._trusted_root_skip(tool=tool, args=args, base=base)
        if trusted is not None:
            # Requirement: Deep Analysis Sampling. The policy layer already
            # allowed this in-root call of a non-exec tool, so a conclusion
            # could only tighten a verdict nobody denies; no request is sent and
            # no budget is spent. The skip itself is the audited fact.
            self._record_deep_degraded(
                f"deep dispatch {DEEP_SKIPPED_TRUSTED_ROOT} tool={tool}"
                f" targets={len(trusted)}",
                degraded=False,
            )
            return plan
        summary = self._deep_summary(
            tool=tool,
            args=args,
            subject=subject,
            session=session,
            digest_value=digest_value,
            plan=plan,
        )
        key = self._deep_cache_key(
            subject=subject,
            sequence=int(summary["ts_seq"]),
            digest_value=digest_value,
        )
        if (
            not plan.force_deep
            and plan.rule_id is None
            and plan.severity not in SYNC_DEEP_SEVERITIES
        ):
            self._schedule_deep_review(key, summary)
            return plan
        cached = self._deep_cache.get(key)
        if cached is not None:
            return _deep_tightened(plan, cached, mode=self.mode, cache_hit=True)
        result = await self._sync_deep_review(summary, deadline=deadline, now=now)
        if result.answer is not None:
            self._deep_cache.put(key, result)
        elif result.degraded == DEGRADED_DEEP_BUDGET:
            # Design D8: a short budget must not lose the analysis, it moves it
            # to the background instead of blocking the answer on it.
            self._schedule_deep_review(key, summary)
        self._record_deep_review(result, key)
        return _deep_tightened(plan, result, mode=self.mode, cache_hit=False)

    def _schedule_deep_review(
        self, key: ConclusionKey, summary: Mapping[str, Any]
    ) -> None:
        """Start one tracked background deep review, or none when it cannot run.

        Requirement: Deep Analysis Sampling; External Cancellation Degradation. A
        gateway without a recorded trajectory window has no segment to analyse,
        and a gateway that already shut down must not create a task, so both
        cases start nothing. Every task started here is tracked, which is what
        lets shutdown() cancel it.

        Args:
            key: Conclusion-cache key of the analyzed segment.
            summary: The trajectory summary the review reads.
        """
        if self._closed or self._recorder is None:
            return
        in_flight = len(self._deep_tasks)
        if in_flight >= DEEP_BACKGROUND_CONCURRENCY:
            # Unbounded background reviews amplify themselves: every allowed
            # call would start another LLM request. Refuse and say so.
            self._record_deep_degraded(
                f"{DEGRADED_DEEP_SATURATED} in_flight={in_flight}"
                f" limit={DEEP_BACKGROUND_CONCURRENCY}"
            )
            return
        task = asyncio.create_task(self._background_deep_review(key, summary))
        self._deep_tasks.add(task)
        task.add_done_callback(self._deep_task_done)

    async def _background_deep_review(
        self, key: ConclusionKey, summary: Mapping[str, Any]
    ) -> None:
        """Run one background deep review and record its conclusion.

        Requirement: Deep Analysis Sampling; Sanitized Persistence. The result
        reaches the audit trail and the conclusion cache only: it is produced
        after the call was answered, so it can never change that answer. No call
        deadline is passed, so the background default of
        config.deep_analysis_timeout_s applies.
        """
        result = await _guarded_review(
            self.deep_review(summary),
            route=self.judge_route,
            degraded=DEGRADED_DEEP_BACKGROUND,
        )
        if result.answer is not None:
            self._deep_cache.put(key, result)
        self._record_deep_review(result, key)

    def _deep_task_done(self, task: asyncio.Task[Any]) -> None:
        """Forget one settled background review, recording an unexpected failure.

        Requirement: Deep Analysis Sampling; Degraded Mode Alert. Retrieving the
        exception is what keeps the loop from reporting "Task exception was never
        retrieved": an unexpected failure becomes one audit row instead of a
        stderr trace nobody reads.
        """
        self._deep_tasks.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            fact = f"{DEGRADED_DEEP_BACKGROUND}:{type(exc).__name__}"
            self._record_deep_degraded(fact)

    def _record_deep_review(self, result: DeepReviewResult, key: ConclusionKey) -> None:
        """Write one background deep-review conclusion as an audit row.

        Requirement: Deep Analysis Sampling; Analysis Result Caching; Sanitized
        Persistence. The row carries key facts and the verdict word only: no
        prompt, no answer text and no path ever leaves a review, so reading the
        audit trail cannot re-disclose what the fragment gate withheld.
        """
        verdict = _deep_answer_decision(result.answer)
        word = verdict.value if verdict is not None else "uncertain"
        line = (
            f"deep review ts_seq={key.ts_seq_start}-{key.ts_seq_end}"
            f" rule_set={key.rule_set_version} verdict={word}"
        )
        if result.degraded:
            line = f"{line} degraded={result.degraded}"
        self._record_deep_degraded(
            line, degraded=result.degraded is not None or result.answer is None
        )

    def _record_deep_degraded(self, line: str, *, degraded: bool = True) -> None:
        """Submit one deep-analysis fact to the audit queue, never blocking a call.

        Requirement: Deep Analysis Sampling; Retention and Rotation (single write
        queue). The fact shares the decision queue and is drained at once, and a
        storage failure is swallowed: a degradation record can never turn into a
        second failure.
        """
        writer = self.audit_writer()
        if writer is None:
            return
        writer.submit(
            {
                "decision": Decision.ALLOW_PASSTHROUGH.value,
                "source": audit.SOURCE_NATIVE,
                "summary_line": self._redact_audited(line),
                "degraded": bool(degraded),
                "observe": False,
                "mode": self.mode,
                "judge_route": self.judge_route,
                "rule_set_version": RULE_SET_VERSION,
            }
        )
        self._drain_audit()

    async def _trajectory_gate(
        self,
        plan: _Plan,
        *,
        tool: str,
        args: Mapping[str, Any],
        subject: str,
        session: str,
        digest_value: str,
        deadline: float,
        now: float,
    ) -> _Plan:
        """Record this call's trajectory facts and review a suspicious shape.

        Requirement: Taint Escalation; Trajectory Review Trigger; Fail-Closed
        Triage. Every finished call feeds the watch, which is the only place where
        a write followed by an execution of that same path, or private content
        leaving the session, becomes visible at all. A trigger starts the same
        deep-analysis channel the per-call rules use and its conclusion may only
        tighten the plan. A trajectory that cannot be recorded is refused: an
        unobserved call must never read as a clean one.

        Args:
            plan: The plan triage produced for this call.
            tool: Managed tool name.
            args: Call arguments.
            subject: Subject key of the call.
            session: Session key of the call.
            digest_value: Argument digest of the call.
            deadline: Deadline instant of the call.
            now: Current instant on the gateway clock.

        Returns:
            The plan, tightened by a deep conclusion when a trigger fired.
        """
        try:
            trigger = self._watch.observe(
                session_key=session,
                facts=_call_facts(tool, args),
                args=args,
                ts_seq=self._peek_sequence(session),
                now=now,
            )
        except _WATCH_ERRORS as exc:
            return _Plan(
                decision=Decision.DENY_POLICY,
                reason=REASON_TRAJECTORY_FAILED,
                would_be=plan.would_be,
                rule_id=plan.rule_id,
                judge_route=plan.judge_route,
                degraded=f"{DEGRADED_TRAJECTORY_FAILED}:{type(exc).__name__}",
                call_id=plan.call_id,
                intent_unpaired=plan.intent_unpaired,
            )
        if not trigger.fired:
            return plan
        self._record_deep_degraded(
            f"trajectory trigger={trigger.trigger} tool={tool}"
            f" ts_seq={trigger.ts_seq} reason={trigger.reason}",
            degraded=False,
        )
        summary = self._deep_summary(
            tool=tool,
            args=args,
            subject=subject,
            session=session,
            digest_value=digest_value,
            plan=plan,
        )
        key = self._deep_cache_key(
            subject=subject,
            sequence=int(summary["ts_seq"]),
            digest_value=digest_value,
        )
        cached = self._deep_cache.get(key)
        if cached is not None:
            return _trajectory_tightened(plan, cached, mode=self.mode, cache_hit=True)
        result = await self._sync_deep_review(summary, deadline=deadline, now=now)
        if result.answer is not None:
            self._deep_cache.put(key, result)
        self._record_deep_review(result, key)
        return _trajectory_tightened(plan, result, mode=self.mode, cache_hit=False)

    async def _guard(
        self,
        *,
        inner: Any,
        tool_name: str,
        args: dict[str, Any],
        context: Any,
    ) -> CallOutcome:
        """Run the whole pipeline for one call.

        Requirement: Single Call Orchestration; Write Before Forward.

        Args:
            inner: Original toolset entry.
            tool_name: Public tool name.
            args: Raw arguments.
            context: Host tool-call context, when available.

        Returns:
            The CallOutcome for this call.
        """
        if self._closed:
            return self._deny(REASON_CLOSED)
        tool = str(tool_name or "").strip() or _tool_name(inner)
        if not self.enabled:
            return await self._observe_disabled(context, tool)
        reviewers = self._reviewers
        snapshot = self._snapshot
        if reviewers is None or snapshot is None:
            return self._deny(REASON_NOT_READY)
        subject, session, event = self._identify(context)
        if subject == UNKNOWN_SUBJECT or session == UNKNOWN_SESSION:
            return self._deny_unidentified(tool)
        base = _workspace_base(context, event, data_dir=self._data_dir)
        schema = _schema_of(inner)
        digest_value = args_digest(schema, args)
        call_id: str | None = None
        with contextlib.suppress(Exception):
            call_id = intent_trace.pop_intent(
                intent_trace.event_key_of(subject, session),
                tool,
                intent_trace.args_digest(args),
            )
        now = self._clock()
        deadline = call_deadline(now, read_tool_call_timeout(_run_context_of(context)))
        self._publish_deadline(deadline)
        lock = self._lock_for(subject, session)
        async with lock:
            plan = await self._decide(
                reviewers,
                tool=tool,
                args=args,
                subject=subject,
                session=session,
                deadline=deadline,
                now=now,
                base=base,
            )
            plan = _stamp_intent(plan, call_id)
            # Requirement: Layered Consensus.  The deep reviewer is one of the
            # three layers and has already run inside _decide, on the same payload
            # as the fast judge.  There is no second deep pass here: _deep_dispatch
            # and _trajectory_gate used to add one after the verdict, which meant a
            # call could be deep-reviewed twice, once without the current tool and
            # arguments, and once with a conclusion that could only tighten a
            # decision the models had already been asked about.
            ticket: Any = None
            retry_ticket = ""
            suppression = ""
            suspend_deadline = deadline
            # Requirement: OneBot v11 Compatibility.  A session that may not wait is
            # decided before any approval is looked up: an approved retry exists
            # only for a suspension somebody could answer.
            if plan.decision is Decision.SUSPENDED:
                plan, suppression = self._suppress_suspend(plan, session=session)
            if plan.decision is Decision.SUSPENDED:
                plan, retry_ticket = self._consume_approved_retry(
                    plan,
                    subject=subject,
                    session=session,
                    tool=tool,
                    digest_value=digest_value,
                )
            if plan.decision is Decision.SUSPENDED:
                # Requirement: Approval Wait and Exact-Match Retry.  The suppression
                # checks above decide WHO may wait; this decides HOW LONG.  Both
                # verdicts keep the order they always had -- suppression first,
                # then the budget -- and only the budget is redrawn, from the
                # call deadline to the earlier of it and now + configured cap.
                suspend_now = self._clock()
                suspend_deadline = effective_suspend_deadline(
                    deadline, suspend_now, self._suspend_cap()
                )
                if not can_suspend(suspend_deadline, suspend_now):
                    plan = _Plan(
                        decision=Decision.TIMEOUT_DENY,
                        reason=REASON_SUSPEND_BUDGET,
                        would_be=plan.would_be,
                        rule_id=plan.rule_id,
                        judge_route=plan.judge_route,
                        degraded="suspend_budget_exhausted",
                        call_id=plan.call_id,
                        intent_unpaired=plan.intent_unpaired,
                    )
                else:
                    ticket = self._create_ticket(
                        subject=subject,
                        session=session,
                        tool=tool,
                        digest_value=digest_value,
                    )
                    if ticket is None:
                        plan = _Plan(
                            decision=Decision.DENY_POLICY,
                            reason=REASON_STORE_UNAVAILABLE,
                            rule_id=plan.rule_id,
                            degraded="store_unavailable",
                            call_id=plan.call_id,
                            intent_unpaired=plan.intent_unpaired,
                        )
            if plan.decision is not Decision.SUSPENDED:
                if plan.decision in ALLOW_DECISIONS and not can_delegate(
                    deadline, self._clock()
                ):
                    plan = _Plan(
                        decision=Decision.TIMEOUT_DENY,
                        reason=REASON_DELEGATE_WINDOW,
                        would_be=plan.would_be,
                        rule_id=plan.rule_id,
                        judge_route=plan.judge_route,
                        degraded="delegate_window_exhausted",
                        call_id=plan.call_id,
                        intent_unpaired=plan.intent_unpaired,
                    )
                ticket_marker = retry_ticket or None
            else:
                ticket_marker = getattr(ticket, "ticket_id", "") or None
            summary = self._call_summary(
                plan,
                tool=tool,
                subject=subject,
                session=session,
                args=args,
                digest_value=digest_value,
                ticket_id=ticket_marker,
                at=db.utc_iso(),
            )
            if not self._record(
                plan,
                tool=tool,
                subject=subject,
                session=session,
                args=args,
                ticket_id=ticket_marker,
                snapshot=snapshot,
                digest_value=digest_value,
                summary=summary,
            ):
                return self._deny(REASON_STORE_UNAVAILABLE)
            self._append_trajectory(summary, session=session)
            if suppression:
                # The row is written first, so a failed alert is a second row and
                # never the only record of the denial.
                await self._alert_suspend_suppressed(
                    plan,
                    tool=tool,
                    subject=subject,
                    session=session,
                    args=args,
                    deadline=deadline,
                    context=context,
                    event=event,
                )
        if ticket is None:
            return self._outcome(plan, ticket_id=retry_ticket)
        return await self._await_approval(
            plan,
            ticket=ticket,
            tool=tool,
            subject=subject,
            session=session,
            args=args,
            deadline=suspend_deadline,
            snapshot=snapshot,
            context=context,
            event=event,
            digest_value=digest_value,
        )

    async def _decide(
        self,
        reviewers: ReviewerRegistry,
        *,
        tool: str,
        args: Mapping[str, Any],
        subject: str,
        session: str,
        deadline: float,
        now: float,
        base: str | None = None,
    ) -> _Plan:
        """Run the layered review rounds inside the synchronous budget.

        Requirement: Layered Consensus; Layer Budgets; Rules Before Models.

        One call is judged in two rounds, in this order and for these reasons:

        1. The static layer, the label rules, the base check and the fast judge run
           together. The static layer alone may refuse, and a refusal preempts the
           rest of the round -- a static denial never spends a model request.
        2. The deep reviewer runs only when the fast judge abstained (no readable
           score, an unreadable answer, a timeout or an unavailable model) or
           asked for it. A fast approval is enough to approve and a fast denial
           already needs a human, so neither spends a second request.

        Both rounds are ordinary pipelines over a subset of the registry, and the
        single aggregate is rebuilt from every verdict (core.pipeline.merge_outcomes)
        and folded by core.consensus, i.e. the same fold the one-round reader uses.

        A budget that runs out is not a denial: nothing was refused, so the call
        goes to a human with ticket_kind=all_abstain. Only the static layer refuses
        on its own.

        Args:
            reviewers: The reviewer registry assembled for this call.
            tool: Public tool name.
            args: Raw arguments.
            subject: Requester key.
            session: Session key.
            deadline: Call deadline.
            now: Current instant.
            base: Workspace root that resolves relative targets of this call;
                None leaves them on the fail-closed path of the policy layers.

        Returns:
            The _Plan produced by the rounds.
        """
        budget = sync_budget_seconds(deadline, now, cap=self._decision_budget_cap())
        if budget <= 0:
            return self._ask_human_plan(
                reason=REASON_SYNC_BUDGET, degraded="triage_timeout"
            )
        try:
            call = build_call(
                tool_name=tool,
                arguments=args,
                subject_key=subject,
                session_key=session,
                mode=self.mode,
                at=now,
            )
            with call_base(base):
                first = await self._review_round(
                    reviewers,
                    call,
                    only=_STATIC_ROUND,
                    budget_s=budget,
                    budgets={JEV_FAST_NAME: min(self._jev_timeout, budget)},
                )
                second = await self._deep_round(reviewers, call, first, budget=budget)
            outcome = merge_outcomes(first, second)
        except TimeoutError:
            return self._ask_human_plan(
                reason=REASON_SYNC_BUDGET, degraded="triage_timeout"
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a broken triage asks, never refuses
            return self._ask_human_plan(
                reason=REASON_FAIL_CLOSED,
                degraded=f"triage_error:{type(exc).__name__}",
            )
        return self._plan_from_pipeline(outcome)

    async def _review_round(
        self,
        reviewers: ReviewerRegistry,
        call: Any,
        *,
        only: tuple[str, ...],
        budget_s: float,
        budgets: Mapping[str, float] | None = None,
    ) -> Any:
        """Run one round of the consensus over a named subset of reviewers.

        Requirement: Layered Consensus. The round is a normal pipeline: the same
        fan-out, the same verdict words and the same per-reviewer budgets, only
        over fewer names. The outer wait_for is a backstop for a reviewer that
        ignores its own budget, and it is the caller that decides what a spent
        budget means.

        Args:
            reviewers: The registry assembled for this call.
            call: The immutable facts reviewers may see.
            only: Reviewer names this round may run.
            budget_s: Budget of the whole round, in seconds.
            budgets: Per-reviewer overrides, keyed by reviewer name.

        Returns:
            The PipelineOutcome of this round.
        """
        pipeline = ReviewPipeline(
            reviewers,
            budget_s=budget_s,
            budgets=budgets,
            only=only,
        )
        return await asyncio.wait_for(pipeline.run(call), timeout=budget_s)

    async def _deep_round(
        self,
        reviewers: ReviewerRegistry,
        call: Any,
        first: Any,
        *,
        budget: float,
    ) -> Any:
        """Run the deep reviewer when the fast judge left the call undecided.

        Requirement: Layered Consensus; Layer Budgets.

        The deep reviewer is asked in exactly two situations: the fast judge
        abstained (its verdict is a SKIP that is not the whitelist shortcut), or
        it explicitly asked for a deep review. A fast approval needs no second
        opinion, and a fast denial already asks a human, so neither runs deep.

        Args:
            reviewers: The registry assembled for this call.
            call: The immutable facts reviewers may see.
            first: The outcome of the static/fast round.
            budget: Budget the whole decision had, in seconds.

        Returns:
            The PipelineOutcome of the deep round, or None when it must not run.
        """
        if not reviewers.is_enabled(DEEP_REVIEWER_NAME):
            return None
        if not _needs_deep(first):
            return None
        spent = float(getattr(first, "elapsed_s", 0.0) or 0.0)
        remaining = max(0.0, float(budget) - spent) - DECISION_RESERVE_S
        deep_budget = min(self._reviewer_deep_budget(), remaining)
        if deep_budget <= 0.0:
            return None
        return await self._review_round(
            reviewers,
            call,
            only=(DEEP_REVIEWER_NAME,),
            budget_s=deep_budget,
            budgets={DEEP_REVIEWER_NAME: deep_budget},
        )

    def _decision_budget_cap(self) -> float:
        """Return config.decision_budget_s, or its documented fallback.

        Requirement: Layer Budgets. The cap bounds how long the layers may spend
        on one call; the call deadline minus DECISION_RESERVE_S still bounds it
        from above, so a configuration larger than the host timeout cannot spend
        time the call does not have.

        Returns:
            The configured decision budget in seconds.
        """
        raw = getattr(self._config, "decision_budget_s", None)
        try:
            cap = float(raw)
        except (TypeError, ValueError):
            return DECISION_BUDGET_CAP_S
        if not math.isfinite(cap) or cap <= 0.0:
            return DECISION_BUDGET_CAP_S
        return cap

    def _plan_from(self, outcome: Any) -> _Plan:
        """Map one triage outcome onto an internal plan, fail-closed.

        Requirement: Fail-Closed Triage; Decision Taxonomy; Judge Route Audit.

        Kept as the parity oracle only: production decides through
        _plan_from_pipeline, and no runtime path calls this mapper. It stays
        because tests/unit/gateway/test_guard_parity.py compares its reading of a
        TriageEngine outcome against the pipeline's fold reading -- mapping both
        sides through _plan_from_pipeline would hide a bug in the fold reader, so
        this independent mapping is the second opinion that makes the comparison
        mean something.

        Args:
            outcome: TriageOutcome or a mapping with the same fields.

        Returns:
            The plan for this verdict; an unrecognisable verdict denies.
        """
        decision = _decision_of(outcome)
        if decision is None:
            return _Plan(
                decision=Decision.DENY_POLICY,
                reason=REASON_NO_DECISION,
                degraded="gateway_missing_decision",
            )
        return _Plan(
            decision=decision,
            reason=self._redact(_reason_of(outcome)) or _DENY_LABEL,
            would_be=_would_be_of(outcome),
            rule_id=_rule_id_of(outcome),
            judge_route=self._judge_route_for(decision),
            degraded=_degraded_of(outcome),
            labels=_labels_of(outcome),
            severity=_severity_of(outcome),
        )

    def _plan_from_pipeline(self, outcome: Any) -> _Plan:
        """Map one pipeline outcome onto an internal plan, fail-closed.

        Requirement: Verdict Aggregation; Decision Taxonomy; Judge Route Audit.

        The pipeline already decided, so its aggregate word is the plan's
        decision, and every other field is the fold a reviewer published, read
        back verbatim: the reason text, the observe word, the severity, the taint
        labels and the rule identifiers all come from fold_stages through the
        adapter, so the gateway reports one fold instead of deriving a second one.
        A missing decision still denies, exactly as the engine mapping does, so an
        unreadable round can never become an allow.

        Args:
            outcome: The PipelineOutcome of this round.

        Returns:
            The plan for this verdict; an unrecognisable verdict denies.
        """
        decision = _decision_of(outcome)
        if decision is None:
            # A round that reported no decision reached no conclusion, so even
            # this fail-closed deny is only recorded when the gateway observes.
            return self._observed_plan(
                _Plan(
                    decision=Decision.DENY_POLICY,
                    reason=REASON_NO_DECISION,
                    degraded="gateway_missing_decision",
                )
            )
        verdicts = _verdicts_of(outcome)
        fold = _published_fold(verdicts)
        rule_ids = _fold_rule_ids(fold)
        forced = _verdict_detail(verdicts.get(JEV_FAST_NAME), DETAIL_FORCE_DEEP) is True
        # Requirement: Layered Consensus. The reason a call needs a human is
        # folded from the same verdicts that produced the decision, never
        # inferred from the decision word afterwards: observe mode rewrites the
        # word, so an inference would mislabel every model denial as a release.
        folded = consensus(verdicts.values())
        # Requirement: Shadow Observation Mode.  The consensus is the layer that
        # creates suspensions (a model denial, or two models with no opinion), so
        # observe is applied here too: the call is recorded as allow_passthrough
        # with would_be=suspend and no ticket is opened, exactly like the static
        # layer's own rewrite.  Without this, switching the gateway to observe
        # would have left every model denial waiting for an administrator -- the
        # one mode in which a model must never gain a blocking vote.
        return self._observed_plan(
            _Plan(
                decision=decision,
                reason=self._redact(_fold_text(fold, DETAIL_REASON)) or _DENY_LABEL,
                would_be=_fold_text(fold, DETAIL_WOULD_BE) or None,
                rule_id=rule_ids[0] if rule_ids else None,
                judge_route=self._judge_route_of(verdicts),
                degraded=_outcome_degraded(outcome),
                labels=_fold_labels(fold),
                layer=_fold_text(fold, DETAIL_LAYER),
                source=_fold_text(fold, DETAIL_SOURCE),
                severity=_fold_text(fold, DETAIL_SEVERITY) or None,
                force_deep=forced,
                ticket_kind=folded.ticket_kind,
                review=self._review_report(verdicts),
            )
        )

    def _observed_plan(self, plan: _Plan) -> _Plan:
        """Return the plan that observe mode actually acts on.

        Requirement: Shadow Observation Mode; Layered Consensus. Observation
        records every action it would have taken and blocks nothing -- that is
        what the mode is for -- so a denial or a wait becomes a recorded
        allow_passthrough with the action in would_be and no ticket. The static
        layer already rewrites its own conclusions; this covers everything the
        consensus and the fail-closed paths produce, which is why every plan this
        gateway returns passes through here exactly once.

        Args:
            plan: The plan the layers produced.

        Returns:
            The same plan in enforce mode, or the recorded release in observe.
        """
        if not is_observe_mode(self.mode) or is_allow(plan.decision):
            return plan
        recorded = would_be_for(plan.decision)
        return replace(
            plan,
            decision=Decision.ALLOW_PASSTHROUGH,
            would_be=plan.would_be
            or (recorded.value if recorded else WouldBe.SUSPEND.value),
            ticket_kind=None,
        )

    def _ask_human_plan(self, *, reason: str, degraded: str) -> _Plan:
        """Return the plan for a round that reached no conclusion at all.

        Requirement: Layered Consensus. A budget that ran out or a broken round
        refused nothing, so it does not refuse now: an administrator is asked
        with the "unusual call" wording, and observe mode only records it.

        Args:
            reason: Administrator-facing text.
            degraded: Degradation marker for the audit row.

        Returns:
            The plan for an unconcluded round.
        """
        return self._observed_plan(
            _Plan(
                decision=Decision.SUSPENDED,
                reason=reason,
                degraded=degraded,
                ticket_kind=TICKET_ALL_ABSTAIN,
            )
        )

    async def _await_approval(
        self,
        plan: _Plan,
        *,
        ticket: Any,
        tool: str,
        subject: str,
        session: str,
        args: Mapping[str, Any],
        deadline: float,
        snapshot: PolicySnapshot,
        context: Any,
        event: Any,
        digest_value: str,
    ) -> CallOutcome:
        """Notify the administrators and wait inside the call budget.

        Requirement: Approval Wait and Exact-Match Retry; Late Decision
        Disclosure. Approval never replays the call: this round returns a
        suspension answer and the model may issue one fresh identical call.

        Args:
            plan: The suspension plan.
            ticket: Created ticket.
            tool: Public tool name.
            subject: Requester key.
            session: Session key.
            args: Raw arguments.
            deadline: Call deadline.
            snapshot: Policy snapshot.
            context: Host tool-call context.
            event: Host message event, when available.
            digest_value: Digest of the raw arguments computed upstream.

        Returns:
            The CallOutcome for this call.
        """
        ticket_id = str(getattr(ticket, "ticket_id", "") or "")
        conn = self._open_store()
        if conn is None:
            return self._deny(REASON_STORE_UNAVAILABLE)
        # Requirement: Approval Window Has No Gap.  The registry entry exists
        # before the notice can reach anybody: an administrator who answers while
        # the notice is being delivered would otherwise answer a ticket nothing is
        # waiting on yet.  wait_for_decision checks the recorded decision before it
        # registers, so a decision taken inside this window still counts.
        self._registry.register(ticket_id)
        task = asyncio.current_task()
        if task is not None:
            self._wait_tasks.add(task)
            self._wait_tickets[ticket_id] = task
        try:
            await self._notify(
                plan,
                ticket_id=ticket_id,
                tool=tool,
                subject=subject,
                session=session,
                args=args,
                deadline=deadline,
                context=context,
                event=event,
            )
            state = await wait_for_decision(
                ticket_id,
                deadline=deadline,
                store=conn,
                registry=self._registry,
                now=self._clock,
                ticket=ticket,
            )
        except asyncio.CancelledError:
            # Requirement: External Cancellation Degradation. The waiter already
            # settled the ticket as canceled_external and re-raised, so this row
            # is the only audit evidence the call leaves behind. _record submits to
            # the write queue and drains it without awaiting, which is what makes
            # writing it inside a cancelled task safe.
            final = _stamp_intent(_settled_plan(plan, CANCELED_EXTERNAL), plan.call_id)
            self._record(
                final,
                tool=tool,
                subject=subject,
                session=session,
                args=args,
                ticket_id=ticket_id,
                snapshot=snapshot,
                digest_value=digest_value,
            )
            self._schedule_closed_notice(
                final,
                ticket_id=ticket_id,
                tool=tool,
                subject=subject,
                session=session,
                args=args,
                context=context,
                event=event,
            )
            raise
        finally:
            # Requirement: Approval Window Has No Gap.  Nothing may outlive this
            # call: a registered event nobody awaits would accept a later decision
            # forever, and the wait-ticket map would pin a finished task.
            self._registry.discard(ticket_id)
            self._wait_tickets.pop(ticket_id, None)
            if task is not None:
                self._wait_tasks.discard(task)
        if state == APPROVED:
            return CallOutcome(
                decision=Decision.SUSPENDED.value,
                text=REASON_APPROVED,
                ticket_id=ticket_id,
                state=APPROVED,
                would_be=plan.would_be,
                rule_id=plan.rule_id,
                judge_route=plan.judge_route,
            )
        if state == TIMEOUT:
            self._settle_timeout(conn, ticket_id)
        final = _stamp_intent(_settled_plan(plan, state), plan.call_id)
        self._record(
            final,
            tool=tool,
            subject=subject,
            session=session,
            args=args,
            ticket_id=ticket_id,
            snapshot=snapshot,
            digest_value=digest_value,
        )
        if state == CANCELED_EXTERNAL:
            # The waiter settles a cancellation by re-raising, so this branch only
            # covers a waiter that still reports the verdict; it must not block
            # either, which is why the notice is scheduled the same way here.
            self._schedule_closed_notice(
                final,
                ticket_id=ticket_id,
                tool=tool,
                subject=subject,
                session=session,
                args=args,
                context=context,
                event=event,
            )
        return CallOutcome(
            decision=final.decision.value,
            text=self._redact(final.reason),
            ticket_id=ticket_id,
            state=state,
            would_be=final.would_be,
            rule_id=final.rule_id,
            judge_route=final.judge_route,
        )

    def _suspend_cap(self) -> float:
        """Return this gateway's effective suspension cap in seconds.

        Requirement: Approval Wait and Exact-Match Retry.  A gateway assembled without a
        validated configuration has no operator value to honour, so the documented
        110 second ceiling applies; a configured value is only ever narrowed.

        Returns:
            min(110, config.suspend_timeout_s), or 110 when it is unusable.
        """
        config = self._config
        return suspension_cap_seconds(
            None if config is None else getattr(config, "suspend_timeout_s", None)
        )

    def _suspend_suppression(self, session: str) -> str:
        """Return the reason this session must not wait for an approval.

        Requirement: OneBot v11 Compatibility.  One check, and it is an exact
        ordinary string comparison rather than a substring match, so an entry
        "p:1" cannot silently cover the session "p:10": an entry of
        ``suspend_disabled_sessions`` equal to the whole session key -- the
        value ``audit_events.session_key`` stores -- disables the wait for
        exactly that session.  The operator's entry wins over any requester: who
        asked cannot re-open a wait the operator closed.  What the list removes is
        the wait, never the denial, and it grants nothing -- approving still needs
        the host's event.is_admin() *and* the configured list
        (ui/commands.py _admin_actor).

        Nothing else suppresses a wait.  A group session suspends for any
        requester exactly like a private one, because waiting is not approving: a
        ticket is created against the group session key, the notice offers the
        approval, and the approved retry is consumed once.

        Args:
            session: Session key of this call.

        Returns:
            DEGRADED_SUSPEND_DISABLED when the operator named this exact session,
            or "" when this session may suspend.
        """
        key = str(session or "").strip()
        for entry in getattr(self._config, "suspend_disabled_sessions", ()) or ():
            if isinstance(entry, str) and entry.strip() and entry.strip() == key:
                return DEGRADED_SUSPEND_DISABLED
        return ""

    def _suppress_suspend(self, plan: _Plan, *, session: str) -> tuple[_Plan, str]:
        """Turn one suspension into a denial when the session forbids waiting.

        Requirement: OneBot v11 Compatibility.  The call ends as ``deny_policy``
        with no ticket and no wait, because a wait the operator switched off by
        naming the session in ``suspend_disabled_sessions`` is a denial that
        also spends the remaining call budget.  The rule may only ever remove the
        wait, never grant one, and it is the only rule left: a group session waits
        like any other, whatever the requester's identity.

        Args:
            plan: The suspension plan produced by triage.
            session: Session key of this call.

        Returns:
            The plan to record plus the suppression reason, or the unchanged plan
            and "" when this session may suspend.
        """
        reason = self._suspend_suppression(session)
        if not reason:
            return plan, ""
        # The session key rides the existing degradation marker so the row stays
        # greppable by the key that caused the denial; _audited_summary_line
        # redacts the whole line before it is stored.
        marker = f"{reason} session={self._redact(session)}"
        marker = marker[:SUSPEND_MARKER_SESSION_LIMIT]
        return (
            replace(
                plan,
                decision=Decision.DENY_POLICY,
                reason=REASON_SUSPEND_DISABLED,
                degraded=marker,
            ),
            reason,
        )

    async def _alert_suspend_suppressed(
        self,
        plan: _Plan,
        *,
        tool: str,
        subject: str,
        session: str,
        args: Mapping[str, Any],
        deadline: float,
        context: Any,
        event: Any,
    ) -> bool:
        """Tell the administrators that a suspension became a denial.

        Requirement: OneBot v11 Compatibility; Notification Delivery Failure.  The
        only reason a suspension still becomes a denial is the operator's explicit
        ``suspend_disabled_sessions`` entry for this exact session, so the body
        names that list instead of promising a wait the gateway never offered.

        The alert rides the ordinary administrator channel, so a delivery failure
        is audited as ``notify_failed`` and changes nothing: this call is
        already denied whether or not anybody hears about it.

        Args:
            plan: The denial plan this call is recorded with.
            tool: Public tool name.
            subject: Requester key.
            session: Session key.
            args: Raw arguments.
            deadline: Call deadline.
            context: Host tool-call context.
            event: Host message event, when available.

        Returns:
            True when at least one administrator was reached.
        """
        body = "\n".join(
            (
                "[工具网关] 该会话不等待审批：本次调用直接拒绝（未执行），未建票据。",
                f"{DEGRADED_MARKER_PREFIX}{plan.degraded}",
                f"工具：{tool}",
                f"判定：{plan.decision.value}",
                f"主体：{subject}",
                f"会话：{session}",
                (
                    "该会话被 suspend_disabled_sessions 点名，因此不等待审批；"
                    "如需人工放行，请先把该会话从名单移除，再重新发起调用。"
                ),
            )
        )
        return await self._notify(
            plan,
            ticket_id="",
            tool=tool,
            subject=subject,
            session=session,
            args=args,
            deadline=deadline,
            context=context,
            event=event,
            body=body,
            alert_scope=session,
        )

    def _delivery_cap(self, deadline: float | None, now: float | None = None) -> float:
        """Return how long one delivery attempt may take.

        Requirement: Notification Delivery Failure (R9-06, R10-02). One ceiling,
        enforced at the single boundary every notice path goes through: the
        configured cap bounded by what is left of the call. A path that carries
        no call budget -- a hook alert, a disabled gateway, a closing notice --
        still gets the ceiling, so no send on any path can outlive it.

        Args:
            deadline: Deadline of the call the notice belongs to, when it has
                one.
            now: Current instant on the caller clock; read from the clock when
                omitted.

        Returns:
            The seconds the delivery may take, never negative.
        """
        if deadline is None:
            return self._notify_timeout_s
        instant = now
        if instant is None:
            try:
                instant = float(self._clock())
            except (TypeError, ValueError):
                return self._notify_timeout_s
        return min(self._notify_timeout_s, remaining_seconds(deadline, instant))

    def _notify_timeout(self, deadline: float) -> float:
        """Return how long one notification of this call may take.

        Requirement: Notification Delivery Failure (R9-06). The notice announces
        a wait, so the send must not spend it: the cap is the configured ceiling
        bounded by what is left of the call. One slow administrator therefore
        costs the cap, never the whole wait.

        Args:
            deadline: Deadline of the call the notice belongs to.

        Returns:
            The seconds the notification may take, never negative.
        """
        return self._delivery_cap(deadline)

    def _announced_remaining(self, deadline: float) -> int:
        """Return the remaining seconds a notice may announce.

        Requirement: Notification Content; Notification Delivery Failure
        (R10-04). The number an administrator reads decides how long they think
        they still have, so it may never exceed the window that is really left
        once the notice is out. The send itself may spend up to the delivery cap
        before the wait begins, so the announcement is what survives that worst
        case -- a promise the wait can always keep.

        Args:
            deadline: Deadline of the call the notice belongs to.

        Returns:
            The announced seconds, never negative and never above the wait.
        """
        try:
            now = float(self._clock())
        except (TypeError, ValueError):
            return 0
        wait = suspension_wait_seconds(deadline, now)
        return int(max(0.0, wait - self._delivery_cap(deadline, now)))

    async def _notify(
        self,
        plan: _Plan,
        *,
        ticket_id: str,
        tool: str,
        subject: str,
        session: str,
        args: Mapping[str, Any],
        deadline: float,
        context: Any,
        event: Any,
        body: str = "",
        alert_scope: str = "",
    ) -> bool:
        """Notify the configured administrators, never raising or consenting.

        Requirement: Notification Content; Sanitized Persistence; Notification
        Delivery Failure; Rate Limiting and Merging.

        Args:
            plan: The suspension plan.
            ticket_id: Created ticket identifier.
            tool: Public tool name.
            subject: Requester key.
            session: Session key.
            args: Raw arguments.
            deadline: Call deadline.
            context: Host tool-call context.
            event: Host message event, when available.
            body: Rendered notice that replaces the suspension template; used by
                an alert that has no ticket to approve.
            alert_scope: Extra rate-limit dimension only, so notices of two
                sessions are never merged. Never rendered.

        Returns:
            True when at least one administrator was reached.
        """
        admins = tuple(getattr(self._config, "admins", ()) or ())
        if not admins:
            self._record_notify_failed(
                plan,
                ticket_id=ticket_id,
                tool=tool,
                subject=subject,
                session=session,
                reason="no admin configured",
            )
            return False
        # The delivery cap lives in _send_notice, the one boundary every notice
        # path goes through, so this method no longer times the send itself: it
        # wraps nothing and records nothing of its own, or a capped send would
        # leave two failure rows for one delivery.
        try:
            outcome = await self._deliver_notice(
                plan,
                ticket_id=ticket_id,
                tool=tool,
                subject=subject,
                session=session,
                args=args,
                deadline=deadline,
                context=context,
                event=event,
                admins=admins,
                body=body,
                alert_scope=alert_scope,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - notification failure never blocks
            # A raise inside rendering or delivery used to vanish: the caller
            # saw False and no row was written, so an approval could wait with
            # no trace that the administrator was never told. The row is the
            # only evidence this path has.
            self._record_notify_failed(
                plan,
                ticket_id=ticket_id,
                tool=tool,
                subject=subject,
                session=session,
                reason=f"{NOTIFY_ERROR_PREFIX}{type(exc).__name__}",
            )
            outcome = False
        return bool(outcome)

    async def _deliver_notice(
        self,
        plan: _Plan,
        *,
        ticket_id: str,
        tool: str,
        subject: str,
        session: str,
        args: Mapping[str, Any],
        deadline: float,
        context: Any,
        event: Any,
        admins: tuple[str, ...],
        body: str = "",
        alert_scope: str = "",
    ) -> bool | None:
        """Render and deliver one administrator notice.

        Requirement: Notification Content; Rate Limiting and Merging; Degraded
        Mode Alert.

        The limiter is consulted before rendering and only ever suppresses a
        duplicate notice: it never touches the audit row, the ticket, or the
        wait that follows.

        Args:
            plan: The suspension plan.
            ticket_id: Created ticket identifier.
            tool: Public tool name.
            subject: Requester key.
            session: Session key.
            args: Raw arguments.
            deadline: Call deadline.
            context: Host tool-call context.
            event: Host message event, when available.
            admins: Configured administrator addresses.
            body: Rendered notice that replaces the suspension template.
            alert_scope: Extra rate-limit dimension only, never rendered.

        Returns:
            True when an administrator was reached, None when the notice was
            merged into a later one, False when delivery failed.
        """
        # Requirement: Rate-Limited Notifications.  Two suspended calls are two
        # decisions to make, so the ticket belongs to the limit key: only a repeat
        # notice of the SAME ticket may be folded into the next window.
        admission = self._notify_limiter.admit(
            subject=subject,
            # The alert scope is spent here only: it keeps two sessions from
            # merging into one notice, and is never rendered to an administrator.
            tool_name=f"{tool}:{alert_scope}" if alert_scope else tool,
            mode=self.mode,
            decision=plan.decision,
            degraded=_delivery_degradation(plan),
            ticket_id=ticket_id,
            now=self._clock(),
        )
        if not admission.send:
            return None
        if body:
            # A denial has no ticket and no wait, so the suspension template --
            # which offers "/guard approve" -- would be a lie.
            message = body
        else:
            message = render_admin_message(
                {
                    "ticket_id": ticket_id,
                    "tool_name": tool,
                    "subject_key": subject,
                    "session_key": session,
                    "decision": plan.decision.value,
                    "rule_ids": [] if plan.rule_id is None else [plan.rule_id],
                    # Requirement: Verdict Aggregation.  The notice names the
                    # layer that decided; the rule identifiers stay next to it
                    # as evidence, because an observe rule fires on calls it
                    # never blocks and a reader would take it for the cause.
                    "layer": plan.layer,
                    "arguments": args,
                    "remaining_s": self._announced_remaining(deadline),
                    # The notice names the coarse verb and tier instead of
                    # printing "未知动作 · 未定级" for every tool the classifier
                    # had no row for: both are description, not verdicts.
                    "verb": verb_of(tool),
                    "tier": tier_of(tool),
                    # Requirement: Layered Consensus.  The notice names why a
                    # human is being asked: a model denial of an otherwise
                    # static-clean call, a model that would not release it, or
                    # two models that both abstained.  The wording lives in
                    # notify/messages.py; this only carries the folded kind.
                    "ticket_kind": plan.ticket_kind,
                },
                anonymizer=self._anonymizer,
            )
        merged_line = render_merged_notice(admission.merged)
        if merged_line:
            message = f"{message}\n{merged_line}"
        return await self._send_notice(
            message,
            admins=admins,
            context=context,
            event=event,
            deadline=deadline,
            audit=_NoticeAudit(
                plan,
                ticket_id=ticket_id,
                tool=tool,
                subject=subject,
                session=session,
            ),
        )

    def _platform_hint(self, event: Any, context: Any) -> str:
        """Return the platform an administrator id of this call must be prefixed with.

        Requirement: Administrator Channel.  A bare administrator id names no
        platform, so one has to come from this call: the platform of the event the
        call belongs to first, then the single platform the configured
        administrator ids already agree on.  Ambiguity is never guessed — an empty
        result leaves the sender to report that the id could not be addressed.

        Args:
            event: Host message event of this call, when available.
            context: Host tool-call context, whose event is the fallback.

        Returns:
            The platform name, or an empty string when none is determinable.
        """
        for candidate in (event, _event_of(context)):
            getter = getattr(candidate, "get_platform_id", None)
            if not callable(getter):
                continue
            with contextlib.suppress(*_WATCH_ERRORS):
                platform = str(getter() or "").strip()
                if platform:
                    return platform
        return platform_from_admins(self._admins())

    async def _send_notice(
        self,
        message: str,
        *,
        admins: tuple[str, ...],
        context: Any,
        event: Any,
        redact: bool = True,
        deadline: float | None = None,
        audit: _NoticeAudit | None = None,
    ) -> bool:
        """Redact and deliver one rendered notice through the host.

        Requirement: Notification Content; Notification Delivery Failure
        (R10-02). This is the one boundary every notice path shares -- the
        suspension notice, the hook alert, the reviewer alert, the disabled
        gateway alert and the closing notice all end here -- so the delivery cap
        and the failure row live here too: no path can send without the cap, and
        no path can fail a send without the row.

        A capped send never changes a verdict: the caller sees False and keeps
        its own decision, which is why the timeout is swallowed here instead of
        raised at the call sites, most of which sit inside a suppress().

        Args:
            message: Rendered notice text, not yet redacted.
            admins: Administrator identities to address.
            context: Host tool-call context, used when no context was injected.
            event: Host message event, when available.
            redact: Whether to redact the message first. A message composed only
                of module constants may skip it: a disabled gateway has no
                anonymizer, and redacting there would replace the whole notice
                with the redaction-failure sentinel.
            deadline: Deadline of the call the notice belongs to, when it has
                one; a path without a budget still gets the configured ceiling.
            audit: Audit identity of the failure row; no row is written when it
                is omitted or when the store is unavailable.

        Returns:
            True when at least one administrator was reached.
        """
        host = self._context if self._context is not None else context
        try:
            sender = build_sender(
                host,
                platform_id=self._platform_hint(event, context),
                inline_reply=bool(getattr(self._config, "inline_reply", False)),
                event=event,
            )
        except Exception:  # noqa: BLE001 - a broken sender must not block the wait
            sender = None
        text = self._redact(message) if redact else message
        try:
            reached = await asyncio.wait_for(
                self._notifier(host, admins, text, sender=sender),
                timeout=self._delivery_cap(deadline),
            )
        except TimeoutError:
            self._record_notice_failure(
                audit, NOTIFY_TIMEOUT_REASON, targets=self._attempted(sender)
            )
            return False
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a broken channel must not block the wait
            self._record_notice_failure(
                audit, NOTIFY_DELIVERY_FAILED_REASON, targets=self._attempted(sender)
            )
            return False
        if not reached:
            self._record_notice_failure(
                audit, NOTIFY_DELIVERY_FAILED_REASON, targets=self._attempted(sender)
            )
            return False
        # Requirement: Administrator Channel; Notification Delivery Failure. The
        # host answers True for an origin nobody is listening on, so the row
        # names the origins the notice was addressed to instead of claiming an
        # account received it.
        self._record_notify_sent(audit, targets=self._attempted(sender))
        return True

    def _attempted(self, sender: Any) -> tuple[str, ...]:
        """Return the private origins one delivery attempt was addressed to.

        Requirement: Administrator Channel. Rendered as one short field so the
        audit row stays a single scannable line.

        Args:
            sender: The sender build_sender returned, possibly None.

        Returns:
            One entry per attempted origin; empty when the sender kept none.
        """
        out: list[str] = []
        for attempt in delivery_attempts(sender):
            target = str(attempt.get("target") or "").strip()
            result = str(attempt.get("result") or "").strip()
            admin = str(attempt.get("admin") or "").strip()
            if not target:
                target = f"{admin}->(none)"
            out.append(f"{target}={result}" if result else target)
        return tuple(out)

    def _record_notify_failed(
        self,
        plan: _Plan,
        *,
        ticket_id: str,
        tool: str,
        subject: str,
        session: str,
        reason: str,
        targets: tuple[str, ...] = (),
    ) -> None:
        """Write the audit row of a failed administrator notification.

        Requirement: Notification Delivery Failure.

        The row is secondary evidence and never a precondition: an unavailable
        store or a rejected event is swallowed, so the call keeps waiting for its
        decision exactly as if the notice had been delivered.

        Args:
            plan: The suspension plan.
            ticket_id: Created ticket identifier.
            tool: Public tool name.
            subject: Requester key.
            session: Session key.
            reason: Short, non-sensitive failure cause.
            targets: Private origins the attempt was addressed to, in order.
        """
        writer = self.audit_writer()
        if writer is None:
            return
        line = f"{NOTIFY_FAILED}: {reason}"
        if targets:
            line = f"{line} | {', '.join(targets)}"
        writer.submit(
            {
                "decision": plan.decision.value,
                "source": audit.SOURCE_NATIVE,
                "would_be": plan.would_be,
                "rule_id": plan.rule_id,
                "tool_name": tool,
                "subject_key": subject,
                "session_key": session,
                "ticket_id": ticket_id,
                "summary_line": self._redact_audited(line),
                "degraded": True,
                "observe": False,
                "mode": self.mode,
                "judge_route": self.judge_route,
                "rule_set_version": RULE_SET_VERSION,
            }
        )
        self._drain_audit()

    def _record_notice_failure(
        self,
        audit: _NoticeAudit | None,
        reason: str,
        *,
        targets: tuple[str, ...] = (),
    ) -> None:
        """Write the failure row of one delivery attempt, when one is due.

        Requirement: Notification Delivery Failure (R10-02). The reason word is
        what tells a capped send (notify_timeout) from a send that came back
        empty or raised (delivery failed); the two never overwrite each other.
        The targets are the private origins the notice was addressed to, which is
        the one fact a "no private message arrived" report needs.

        Args:
            audit: Audit identity of the notice, or None for a path that records
                nothing.
            reason: Short, non-sensitive failure cause.
            targets: Private origins the attempt was addressed to, in order.
        """
        if audit is None:
            return
        self._record_notify_failed(
            audit.plan,
            ticket_id=audit.ticket_id,
            tool=audit.tool,
            subject=audit.subject,
            session=audit.session,
            reason=f"{reason} ({audit.label})" if audit.label else reason,
            targets=targets,
        )

    def _record_notify_sent(
        self, notice: _NoticeAudit | None, *, targets: tuple[str, ...] = ()
    ) -> None:
        """Write the delivery evidence row of one administrator notification.

        Requirement: Administrator Channel; Notification Delivery Failure. The
        row is the counterpart of notify_failed: it says the host accepted the
        send and names the private origin it was addressed to. AstrBot answers
        True for an origin with no live session, so this row proves the address
        the gateway used, not that an account read the message -- which is
        exactly what tells the two failure modes apart afterwards.

        Args:
            notice: Audit identity of the notice, or None for a path that records
                nothing. It is named apart from the audit module on purpose: the
                star import of .store.audit is where SOURCE_NATIVE comes from, and
                a parameter called audit shadowed it. That raised AttributeError
                inside the notification path, so every delivered notice also wrote
                a notify_failed row and reported itself as undelivered.
            targets: Private origins the notice was addressed to, in order.
        """
        if notice is None:
            return
        writer = self.audit_writer()
        if writer is None:
            return
        plan = notice.plan
        line = NOTIFY_SENT
        if targets:
            line = f"{line}: {', '.join(targets)}"
        if notice.label:
            line = f"{line} ({notice.label})"
        writer.submit(
            {
                "decision": plan.decision.value,
                "source": audit.SOURCE_NATIVE,
                "would_be": plan.would_be,
                "rule_id": plan.rule_id,
                "tool_name": notice.tool,
                "subject_key": notice.subject,
                "session_key": notice.session,
                "ticket_id": notice.ticket_id,
                "summary_line": self._redact_audited(line),
                "degraded": False,
                "observe": False,
                "mode": self.mode,
                "judge_route": self.judge_route,
                "rule_set_version": RULE_SET_VERSION,
            }
        )
        self._drain_audit()

    def _admins(self) -> tuple[str, ...]:
        """Return the administrator ids one alert of this session may reach.

        Requirement: Administrator Channel.  The validated configuration is
        authoritative when it exists; a gateway whose own configuration failed
        validation has none, so its raw entries are used instead — otherwise the
        degraded alert this disabled gateway must send could never be delivered.

        Returns:
            The configured administrator ids, possibly empty.
        """
        admins = tuple(getattr(self._config, "admins", ()) or ())
        return admins or self._raw_admins

    async def _observe_disabled(self, context: Any, tool: str) -> CallOutcome:
        """Observe (never deny) one managed call while the settings are invalid.

        Requirement: Configuration Failure Degrades To Observation.  A loaded
        plugin whose configuration failed validation has no policy snapshot, no
        judge and no anonymizer, so it cannot review anything -- and denying
        every managed call would turn a fresh install into a dead agent.  The
        call is therefore let through untouched with the passthrough decision a
        call that ran un-reviewed already carries, and the degradation is
        labelled on every surface an operator can reach: one audit row carries
        the gateway_disabled reason and the degraded marker, and the
        administrators hear about it once per rate-limit window.  Only the
        stable warning keys are quoted, never an offending value, because no
        anonymizer exists on this path to redact one.

        Args:
            context: Host tool-call context, when available.
            tool: Public tool name of the observed call.

        Returns:
            The passthrough outcome of this call; the proxy delegates on it.
        """
        subject, session, event = self._identify(context)
        issues = getattr(self.validation, "warnings", ()) or ()
        keys = sorted(
            {
                key
                for key in (getattr(issue, "key", "") for issue in issues)
                if isinstance(key, str) and key.strip()
            }
        )
        reasons = ", ".join(key for key in keys if key) or "config_unusable"
        markers = ""
        if subject == UNKNOWN_SUBJECT or session == UNKNOWN_SESSION:
            markers = f" {DEGRADED_MARKER_PREFIX}{DEGRADED_IDENTITY_UNKNOWN}"
        body = (
            f"{DEGRADED_GATEWAY_DISABLED}"
            f" {DEGRADED_MARKER_PREFIX}{DEGRADED_GATEWAY_DISABLED}"
            f" keys={reasons}"
        )
        line = f"{body[: SUMMARY_LINE_LIMIT - len(markers)]}{markers}"
        with contextlib.suppress(*_WATCH_ERRORS):
            writer = self.audit_writer()
            if writer is not None:
                writer.submit(
                    {
                        "decision": Decision.ALLOW_PASSTHROUGH.value,
                        "source": audit.SOURCE_NATIVE,
                        "would_be": "",
                        "rule_id": "",
                        "tool_name": tool,
                        "subject_key": subject,
                        "session_key": session,
                        "ticket_id": "",
                        "summary_line": line,
                        "degraded": True,
                        "observe": False,
                        "mode": self.mode,
                        "judge_route": self.judge_route,
                        "rule_set_version": RULE_SET_VERSION,
                    }
                )
                self._drain_audit()
        admins = self._admins()
        if admins:
            await self._alert_disabled(
                admins=admins,
                reasons=reasons,
                subject=subject,
                context=context,
                event=event,
            )
        # The text is a string constant of this module and a disabled gateway has
        # no anonymizer, so redacting here would only replace it with the
        # redaction-failure sentinel and tell the requester nothing.
        return CallOutcome(
            decision=Decision.ALLOW_PASSTHROUGH.value, text=REASON_GATEWAY_OBSERVED
        )

    async def _alert_disabled(
        self,
        *,
        admins: tuple[str, ...],
        reasons: str,
        subject: str,
        context: Any,
        event: Any,
    ) -> None:
        """Tell the administrators that managed calls are only being observed.

        Requirement: Degraded Mode Alert.  The notice is rate limited like every
        other one, so a degraded gateway stays visible without flooding the admin
        channel; a failed delivery is swallowed because the observation is already
        in force and the audit row is the primary evidence.

        Args:
            admins: Administrator ids to notify.
            reasons: Stable key names of the failed configuration rules.
            subject: Requester key of the observed call.
            context: Host tool-call context, when available.
            event: Host event of the observed call, when available.
        """
        with contextlib.suppress(*_WATCH_ERRORS):
            admission = self._notify_limiter.admit(
                subject=subject,
                tool_name=DEGRADED_GATEWAY_DISABLED,
                mode=self.mode,
                decision=Decision.ALLOW_PASSTHROUGH,
                degraded=DEGRADED_GATEWAY_DISABLED,
                now=self._clock(),
            )
            if not admission.send:
                return
            message = (
                "工具网关配置校验未通过，已降级为观察：受管调用不会被拦截，"
                "工具照常执行，审计行按 degraded=gateway_disabled 标注。"
                f"需要修正的配置项：{reasons}。"
            )
            merged_line = render_merged_notice(admission.merged)
            if merged_line:
                message = f"{message}\n{merged_line}"
            # The notice is built from module constants and configuration key
            # names only, so it carries nothing to redact — and this gateway has
            # no anonymizer to redact with.
            await self._send_notice(
                message,
                admins=admins,
                context=context,
                event=event,
                redact=False,
                audit=_NoticeAudit(
                    _Plan(
                        decision=Decision.ALLOW_PASSTHROUGH,
                        reason=DEGRADED_GATEWAY_DISABLED,
                    ),
                    tool=DEGRADED_GATEWAY_DISABLED,
                    subject=subject,
                    label="gateway degraded",
                ),
            )

    def _deny_unidentified(self, tool: str) -> CallOutcome:
        """Deny one managed call the host gave no identity for.

        Requirement: Requester Allowlist and Denylist.  A suspension binds its
        ticket to one subject, so a call without an identity cannot be suspended
        and must not be allowed either; the placeholder key appears only on this
        non-granting record, always together with the identity_unknown marker.

        Args:
            tool: Public tool name of the denied call.

        Returns:
            The denial outcome of this call.
        """
        line = (
            f"{REASON_IDENTITY_UNKNOWN} "
            f"{DEGRADED_MARKER_PREFIX}{DEGRADED_IDENTITY_UNKNOWN}"
        )
        with contextlib.suppress(*_WATCH_ERRORS):
            writer = self.audit_writer()
            if writer is not None:
                writer.submit(
                    {
                        "decision": Decision.DENY_POLICY.value,
                        "source": audit.SOURCE_NATIVE,
                        "would_be": "",
                        "rule_id": "",
                        "tool_name": tool,
                        "subject_key": UNKNOWN_SUBJECT,
                        "session_key": UNKNOWN_SESSION,
                        "ticket_id": "",
                        "summary_line": line[:SUMMARY_LINE_LIMIT],
                        "degraded": True,
                        "observe": False,
                        "mode": self.mode,
                        "judge_route": self.judge_route,
                        "rule_set_version": RULE_SET_VERSION,
                    }
                )
                self._drain_audit()
        # Both strings are fixed constants of this module and carry no call data,
        # so they are recorded and returned verbatim.
        return CallOutcome(
            decision=Decision.DENY_POLICY.value, text=REASON_IDENTITY_UNKNOWN
        )

    async def _notify_closed(
        self,
        plan: _Plan,
        *,
        ticket_id: str,
        tool: str,
        subject: str,
        session: str,
        args: Mapping[str, Any],
        context: Any,
        event: Any,
    ) -> bool:
        """Send the closing notice of a ticket closed by outer cancellation.

        Requirement: External Cancellation Degradation; Notification Delivery
        Failure.

        The ticket is already canceled_external and the call is denied before
        this runs; the notice only tells the administrators that the approval
        can no longer apply and that the agent may ask again.  Delivery never
        changes that verdict: a failure is audited as notify_failed and the
        denial stands.

        Args:
            plan: The settled cancellation plan.
            ticket_id: Closed ticket identifier.
            tool: Public tool name.
            subject: Requester key.
            session: Session key.
            args: Raw arguments.
            context: Host tool-call context.
            event: Host message event, when available.

        Returns:
            True when at least one administrator was reached.
        """
        admins = tuple(getattr(self._config, "admins", ()) or ())
        if not admins:
            self._record_notify_failed(
                plan,
                ticket_id=ticket_id,
                tool=tool,
                subject=subject,
                session=session,
                reason="no admin configured",
            )
            return False
        admission = self._notify_limiter.admit(
            subject=subject,
            tool_name=tool,
            mode=self.mode,
            decision=Decision.CANCELED_EXTERNAL,
            degraded=None,
            ticket_id=ticket_id,
            now=self._clock(),
        )
        if not admission.send:
            return False
        message = render_canceled_notice(
            {
                "ticket_id": ticket_id,
                "tool_name": tool,
                "subject_key": subject,
                "session_key": session,
                "state": CANCELED_EXTERNAL,
                "arguments": args,
            },
            anonymizer=self._anonymizer,
        )
        merged_line = render_merged_notice(admission.merged)
        if merged_line:
            message = f"{message}\n{merged_line}"
        # The failure row is written by the delivery boundary itself, so a
        # capped send and an empty one stay one row each, with their own reason.
        delivered = False
        with contextlib.suppress(Exception):
            delivered = await self._send_notice(
                message,
                admins=admins,
                context=context,
                event=event,
                audit=_NoticeAudit(
                    plan,
                    ticket_id=ticket_id,
                    tool=tool,
                    subject=subject,
                    session=session,
                ),
            )
        return delivered

    def _schedule_closed_notice(
        self,
        final: _Plan,
        *,
        ticket_id: str,
        tool: str,
        subject: str,
        session: str,
        args: Mapping[str, Any],
        context: Any,
        event: Any,
    ) -> None:
        """Deliver the closing notice without holding up the cancellation.

        Requirement: External Cancellation Degradation; Notification Delivery
        Failure. The task that was waiting is being cancelled, so awaiting the
        notice here would either take a second CancelledError through the notifier
        or keep the caller parked after the ticket is already closed. The notice
        travels as its own task instead: the ticket state and the audit row are
        what record the cancellation, and a failed delivery is audited by
        _notify_closed itself.

        Args:
            final: The settled plan the notice describes.
            ticket_id: Closed ticket.
            tool: Managed tool name.
            subject: Subject key of the call.
            session: Session key of the call.
            args: Call arguments.
            context: Host context of the call.
            event: Host event of the call.
        """
        task = asyncio.ensure_future(
            self._notify_closed(
                final,
                ticket_id=ticket_id,
                tool=tool,
                subject=subject,
                session=session,
                args=args,
                context=context,
                event=event,
            )
        )
        self._notice_tasks.add(task)
        task.add_done_callback(self._notice_done)

    def _notice_done(self, task: asyncio.Task[Any]) -> None:
        """Forget a finished closing notice; its failure is already audited."""
        self._notice_tasks.discard(task)
        if not task.cancelled():
            task.exception()

    def _outcome(self, plan: _Plan, *, ticket_id: str = "") -> CallOutcome:
        """Render one settled plan as a CallOutcome.

        Requirement: Approval Retry Binding.  A retry allowed by a consumed
        approval reports that ticket, so the caller and the administrator can
        trace which authorization was spent on this call.

        Args:
            plan: The settled plan.
            ticket_id: Consumed authorization ticket, empty when none applied.

        Returns:
            The public outcome.
        """
        return CallOutcome(
            decision=plan.decision.value,
            text=self._redact(plan.reason),
            ticket_id=ticket_id,
            would_be=plan.would_be,
            rule_id=plan.rule_id,
            judge_route=plan.judge_route,
        )

    def _deny(
        self, reason: str, *, decision: Decision = Decision.DENY_POLICY
    ) -> CallOutcome:
        """Build a fail-closed denial with a non-empty, redacted reason."""
        text = self._redact(reason) or REASON_FAIL_CLOSED
        return CallOutcome(decision=decision.value, text=text)

    def _targets_of(self, tool: str, args: Mapping[str, Any]) -> tuple[str, ...]:
        """Return the classified targets of one call, for the session window.

        Requirement: Rule Catalog (R7). A window rule decides whether this
        session just read a sensitive configuration file by reading the stored
        entry's targets; a record stored without them left R7 unreachable in
        production while the rule itself kept passing its unit tests.
        """
        try:
            return tuple(str(item) for item in classify_call(tool, args).targets)
        except Exception:  # noqa: BLE001 - a summary never blocks a call
            return ()

    def _call_summary(
        self,
        plan: _Plan,
        *,
        tool: str,
        subject: str,
        session: str,
        args: Mapping[str, Any],
        digest_value: str,
        ticket_id: str | None,
        at: str,
    ) -> CallSummary:
        """Build the one 22-key trajectory record of a managed call.

        Requirement: Trajectory Summary Record. The record is built once and
        handed to both the audit row and the session window, so summary_json
        and the window can never disagree on keys or values: one ts_seq, one
        call_id, one delegated verdict, one at.

        The head and the summary line are redacted here, before the record can
        be stored, and the digest is the raw-argument digest computed upstream:
        digesting must see the original bytes while redaction happens on the way
        into storage.

        Args:
            plan: The plan the record belongs to.
            tool: Public tool name.
            subject: Requester key, platform_id:sender_id.
            session: Session key.
            args: Raw arguments.
            digest_value: Digest of the raw arguments computed upstream.
            ticket_id: Suspension ticket marker, None otherwise.
            at: ISO-8601 text, shared with the audit row's ts column.

        Returns:
            The single summary record of this call.
        """
        return summarize_call(
            ts_seq=self._peek_sequence(session),
            targets=self._targets_of(tool, args),
            call_id=plan.call_id or uuid.uuid4().hex,
            at=at,
            tool=tool,
            user=subject,
            session=session,
            arguments=args,
            args_digest=digest_value,
            args_head=self._redact(args_head(args)),
            verb=verb_of(tool),
            tier=tier_of(tool),
            rule_hits=() if plan.rule_id is None else (plan.rule_id,),
            summary_line=self._summary_line(tool, args),
            decision=plan.decision.value,
            ticket=ticket_id or None,
            labels=plan.labels,
            delegated=(
                audit.DELEGATED_YES
                if plan.decision in ALLOW_DECISIONS
                else audit.DELEGATED_NO
            ),
        )

    def _record(
        self,
        plan: _Plan,
        *,
        tool: str,
        subject: str,
        session: str,
        args: Mapping[str, Any],
        ticket_id: str | None,
        snapshot: PolicySnapshot,
        digest_value: str,
        summary: CallSummary | None = None,
    ) -> bool:
        """Write one audit row before anything is forwarded.

        Requirements: Write Before Forward; Observe Verdict Persistence; Judge
        Route Audit; Retention and Rotation (single write queue); Rule Set
        Versioning.

        The row is queued and drained inside this call, so the process has one
        commit order. The queue must never weaken Write Before Forward: when
        `drain` cannot commit the row, the writer keeps it at the head of the
        queue and this method still reports failure, so the caller denies. A row
        the store rejects on its own merits (a malformed event) is charged to
        `AuditWriter.failures` and skipped instead, because it would never be
        accepted and blocking every later row on it is worse than losing one.

        The row also carries the four correlation columns of task 5.3:
        args_digest, labels, delegated and summary_json. summary_json is the
        same record the session window stores, all 22 keys in spec order and
        already redacted, so one audit row can be read back as the trajectory
        record of its call without joining anything.

        Args:
            plan: The plan to record.
            tool: Public tool name.
            subject: Requester key.
            session: Session key.
            args: Raw arguments.
            ticket_id: Suspension ticket, None otherwise.
            snapshot: Policy snapshot supplying the version.
            digest_value: Digest of the raw arguments computed upstream.
            summary: Record built by the caller; rebuilt here when omitted.

        Returns:
            True when the row was written; False means the caller must deny.
        """
        writer = self.audit_writer()
        if writer is None:
            return False
        record = summary
        if record is None:
            record = self._call_summary(
                plan,
                tool=tool,
                subject=subject,
                session=session,
                args=args,
                digest_value=digest_value,
                ticket_id=ticket_id,
                at=db.utc_iso(),
            )
        observe = is_observe_mode(self.mode) and plan.would_be is not None
        event = {
            "ts": record.at,
            "decision": plan.decision.value,
            "source": audit.SOURCE_NATIVE,
            "would_be": plan.would_be,
            "rule_id": plan.rule_id,
            "tool_name": tool,
            "subject_key": subject,
            "session_key": session,
            "ticket_id": ticket_id or None,
            "policy_version": snapshot.policy_version,
            "summary_line": self._audited_summary_line(plan, tool, args),
            "degraded": bool(plan.degraded) or bool(_scan_incomplete_code(plan)),
            "observe": observe,
            "mode": self.mode,
            "judge_route": plan.judge_route,
            "rule_set_version": RULE_SET_VERSION,
            "args_digest": record.args_digest,
            "labels": ",".join(sorted(record.labels)) or None,
            "delegated": record.delegated,
            "summary_json": json.dumps(
                _reviewed_record_dict(record, plan.review, _attribution(plan)),
                ensure_ascii=False,
            ),
        }
        writer.submit(event)
        try:
            writer.drain()
        except db.StorageUnavailableError:
            # Write Before Forward: nothing reached the store, so the verdict is
            # not evidence yet and the call must deny. The row stays queued and
            # the next drain retries it instead of dropping the decision.
            return False
        except Exception:  # noqa: BLE001 - storage failure is a denial
            return False
        return True

    def _record_fragment_census(self, gate: FragmentFilter) -> None:
        """Record one fragment-gate census without any path text.

        Requirement: Entry-Side Fragment Gate; Retention and Rotation (single
        write queue). The census shares the decision queue, so a round is never
        reordered into an earlier one; it is submitted and drained at once, and
        a storage failure is swallowed because the record never blocks a call.

        A round that only rewrote out-of-root literals lost nothing, so its row
        is not marked degraded -- but it still writes one: a kept count no
        operator can read is a count nobody can audit, and the whole point of
        keeping those fragments is that the deep review now has input.
        """
        writer = self.audit_writer()
        if writer is None:
            return
        if gate.dropped:
            line = f"deep-analysis fragments dropped: {gate.reason}"
            degraded = True
        else:
            line = f"deep-analysis fragments kept outside project roots: {gate.reason}"
            degraded = False
        writer.submit(
            {
                "decision": Decision.ALLOW_PASSTHROUGH.value,
                "source": audit.SOURCE_NATIVE,
                "summary_line": line,
                "degraded": degraded,
                "observe": False,
                "mode": self.mode,
                "judge_route": self.judge_route,
                "rule_set_version": RULE_SET_VERSION,
            }
        )
        self._drain_audit()

    def _summary_line(self, tool: str, args: Mapping[str, Any]) -> str:
        """Return one redacted, truncated summary line for the audit row."""
        return self._redact_audited(f"{tool}: {args_head(args)}")

    def _audited_summary_line(
        self, plan: _Plan, tool: str, args: Mapping[str, Any]
    ) -> str:
        """Return the audit summary line, keeping the markers the row cannot hold.

        Requirement: Pre-execution Intent Record; Analysis Result Caching;
        Degradation Reason on the Call Row.

        The audit row owns one boolean degradation slot and no text column, so
        the slot keeps the decision-level fact ("this call degraded") while the
        line keeps the reason ("degraded=<kind>"): a boolean alone leaves
        suspend_budget_exhausted, triage_timeout and hook_error indistinguishable
        once they are stored. A cache hit is one of those markers too: a reused
        conclusion is still audited, and the row says so, because "no new model
        request" must never look like "no row".

        The markers ride a reserved tail, so truncation shortens the argument
        summary and never a marker. When that reservation would leave too little
        of the call to read, the cache-hit marker is shed first: a reused
        conclusion is inferable from the trajectory, a degradation reason is not.

        Every marker is derived from the plan alone, never from the summary body.
        The body is argument text, so it is attacker-controlled: a call whose
        arguments already contain the word secret_scan_incomplete must still get
        the marker appended, or the stored row loses the one stable word that
        tells an operator (and a grep) why the call was denied. Duplication
        between body and marker is the accepted price; a suppressed marker is not.

        Args:
            plan: The plan the row is written for.
            tool: Public tool name.
            args: Raw arguments.

        Returns:
            The redacted summary line, with the markers appended when needed.
        """
        line = self._summary_line(tool, args)
        markers: list[str] = []
        if plan.intent_unpaired:
            markers.append(INTENT_UNPAIRED)
        if plan.deep_cache_hit:
            markers.append(DEEP_CACHE_HIT)
        reason = _degraded_marker(plan)
        if reason and reason not in markers:
            markers.append(reason)
        # Requirement: Verdict Aggregation.  The row's rule_id column is
        # evidence, not attribution, and an observe rule fires on calls it never
        # blocks; the layer marker is what a reader greps to find why the row is
        # there.  It is derived from the plan alone, like every other marker.
        layer = str(getattr(plan, "layer", "") or "").strip()
        if layer:
            marker = f"{ATTRIBUTION_MARKER_PREFIX}{layer}"
            if marker not in markers:
                markers.append(marker)
        incomplete = _scan_incomplete_code(plan)
        if incomplete:
            marker = f"{DEGRADED_MARKER_PREFIX}{incomplete}"
            if marker not in markers:
                markers.append(marker)
        if not markers:
            return line
        tail = f" {' '.join(markers)}"
        if reason and SUMMARY_LINE_LIMIT - len(tail) < SUMMARY_MARKER_BODY_MIN:
            markers = [name for name in markers if name != DEEP_CACHE_HIT]
            tail = f" {' '.join(markers)}"
        return f"{line[: max(0, SUMMARY_LINE_LIMIT - len(tail))]}{tail}"

    def _append_trajectory(self, summary: CallSummary, *, session: str) -> None:
        """Append one summary to the session window, keeping it ordered.

        Requirement: Trajectory Window; Trajectory Summary Record. The record is
        the instance the audit row persisted, so the window and summary_json
        cannot drift apart, and its ts_seq stays the sequence the window names.

        Args:
            summary: Record built once for this call.
            session: Session key the window is bound to.
        """
        recorder = self._recorder
        if recorder is None:
            return
        try:
            self._sequences[session] = summary.ts_seq
            recorder.append(summary)
        except Exception:  # noqa: BLE001 - the window is an observation only
            return

    def _trajectory(self, session: str) -> Any:
        """Return the read-only session window, or None without a recorder."""
        recorder = self._recorder
        if recorder is None:
            return None
        try:
            return recorder.snapshot(session)
        except Exception:  # noqa: BLE001 - a broken window never blocks a call
            return None

    def _trajectory_view(self, session: str) -> Any:
        """Return the session window as the view the window rules expect.

        Requirement: Rule Catalog (R7, R9, R11); Layered Consensus. `_trajectory`
        returns the bare records; the rules read `entries` and `now`, and a bare
        tuple has neither -- handing one to `evaluate_rules` made every window
        rule an AttributeError the moment a recorder existed. `now` is wall-clock
        epoch seconds because that is the unit a record's `at` is compared in.
        """
        entries = self._trajectory(session)
        if entries is None:
            return None
        return TrajectoryView(
            entries=tuple(entries),
            session_key=session,
            now=time.time(),
        )

    def _consume_approved_retry(
        self,
        plan: _Plan,
        *,
        subject: str,
        session: str,
        tool: str,
        digest_value: str,
    ) -> tuple[_Plan, str]:
        """Replace one suspension with an exact-match consumed approval.

        Requirement: Approval Retry Binding; Approved Retry Outcome and Window.

        Only the suspension branch of the decision path calls this, so a deny
        rule, a policy denial and a denied judge can never be overwritten by a
        standing approval.  The authorization is matched on the canonical
        quadruple (subject_key, session_key, tool_name, args_digest) and consumed
        by one atomic statement, so the next identical call finds nothing and is
        judged again from scratch.  Every failure -- no match, already consumed,
        closed window, unreadable storage -- returns the suspension unchanged,
        which is the fail-closed outcome.

        Args:
            plan: Suspension plan produced by the triage engine.
            subject: Requester key of this call.
            session: Session key of this call.
            tool: Public tool name of this call.
            digest_value: Canonical argument digest recorded on the ticket.

        Returns:
            The allow plan and the consumed ticket id, or the suspension and an
            empty ticket id when no authorization applied.
        """
        conn = self._open_store()
        if conn is None:
            return plan, ""
        found: Any = None
        consumed = False
        with contextlib.suppress(Exception):
            found = tickets.find_approved(
                conn,
                subject_key=subject,
                session_key=session,
                tool_name=tool,
                args_digest=digest_value,
            )
            if found is not None:
                consumed = tickets.consume_approved(
                    conn,
                    found.ticket_id,
                    subject_key=subject,
                    session_key=session,
                    tool_name=tool,
                    args_digest=digest_value,
                )
        if not consumed or found is None:
            return plan, ""
        authorized = replace(
            plan,
            decision=Decision.ALLOW_APPROVED_RETRY,
            reason=REASON_APPROVED_RETRY,
        )
        return authorized, str(getattr(found, "ticket_id", "") or "")

    def _create_ticket(
        self,
        *,
        subject: str,
        session: str,
        tool: str,
        digest_value: str,
    ) -> Any:
        """Create one suspension ticket, None when storage is unavailable.

        Requirement: Approval Ticket Lifecycle.

        Args:
            subject: Requester key.
            session: Session key.
            tool: Public tool name.
            digest_value: Canonical argument digest.

        Returns:
            The created Ticket, or None when the store refused the write.
        """
        conn = self._open_store()
        if conn is None:
            return None
        try:
            return tickets.create_ticket(
                conn,
                subject_key=subject,
                session_key=session,
                tool_name=tool,
                args_digest=digest_value,
            )
        except Exception:  # noqa: BLE001 - no ticket means no suspension
            return None

    def _open_store(self) -> Any:
        """Open the store once, returning None when it is unavailable."""
        if self._closed:
            return None
        if self._store is not None:
            return self._store
        if self._store_failed:
            return None
        try:
            if self._data_dir is not None:
                connection = db.open_store(self._data_dir)
            else:
                connection = db.open_db(db.default_db_path())
        except Exception:  # noqa: BLE001 - unavailability is a denial, not a crash
            self._store_failed = True
            return None
        self._store = connection
        self._note_startup_sweep_state(connection)
        return connection

    def audit_writer(self) -> audit.AuditWriter | None:
        """Return the ordered audit queue of this store, creating it on demand.

        Requirement: Retention and Rotation (single write queue); Write Before
        Forward. Every row this process writes -- decisions, suspensions,
        degradations, fragment-drop censuses and the operator actions of
        `/guard` -- is submitted here and committed by the following drain, so
        one queue owns the commit order. The writer is bound to one connection,
        therefore it is rebuilt when the connection changes and discarded on
        shutdown.

        Returns:
            The queue, or None when the store is unavailable; every caller reads
            that as a failed write, which is a denial on the decision path.
        """
        conn = self._open_store()
        if conn is None:
            return None
        if self._writer is None or self._writer_conn is not conn:
            self._writer = audit.AuditWriter(
                conn,
                sink=_audit_sink,
                retention=self._retention_pass,
            )
            self._writer_conn = conn
        return self._writer

    def _retention_pass(self, conn: Any) -> dict[str, int]:
        """Trim audit rows and trajectory snippets after one write batch.

        Requirement: Retention and Rotation (audit window 7 days, trajectory 50
        snippets per subject). This is the writer's `retention` callback, so
        trimming always follows a drain instead of racing the write it trims
        around, and there is no second cleanup path. A non-positive configured
        value falls back to the store default rather than being read as "keep
        nothing".

        Args:
            conn: Open store connection the writer drained.

        Returns:
            Deleted row count per table, as `audit.apply_retention` reports it.
        """
        config = self._config
        days = getattr(config, "audit_retention_days", None)
        keep = getattr(config, "trajectory_retention_per_user", None)
        return audit.apply_retention(
            conn,
            audit_days=days if isinstance(days, int) and days > 0 else None,
            per_subject_keep=keep if isinstance(keep, int) and keep > 0 else None,
        )

    def _drain_audit(self) -> int:
        """Drain the audit queue where a lost row must not raise.

        Requirement: Retention and Rotation (single write queue). Used by the
        callers whose row is secondary evidence -- the fragment-drop census, a
        failed administrator notification, and shutdown -- so an unavailable
        store cannot turn an observation into an exception. The decision path
        never uses this: it calls `drain` itself and denies on failure.

        Returns:
            Number of rows this drain wrote, 0 when nothing was written.
        """
        writer = self._writer
        if writer is None:
            return 0
        written = 0
        with contextlib.suppress(Exception):
            written = writer.drain()
        return written

    def _lock_for(self, subject: str, session: str) -> asyncio.Lock:
        """Return the decision lock of one (subject, session) pair.

        Requirement: Concurrent Sessions. Decisions for one key are serialized;
        different keys never share a lock, so a suspension of one subject cannot
        block another.  The key is the (subject, session) tuple itself: joining
        the two with a separator lets a subject or session that contains the
        separator produce another pair's key, and such a collision silently
        serializes two unrelated sessions.

        Args:
            subject: Requester key.
            session: Session key.

        Returns:
            The lock for this pair, created on first use.
        """
        key = (subject, session)
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    def _identify(self, context: Any) -> tuple[str, str, Any]:
        """Resolve (subject, session, event) from this call's own context only.

        Requirement: Requester Allowlist and Denylist; Ticket Persistence. The
        root main.py injects interface/identity so main stays free of an
        interface import.  The only sources are the context of *this* call (its
        subject_key/session_key, else its event through the identity provider):
        nothing is remembered across calls, because a remembered identity is
        another session's identity, and a ticket bound to it would hand one
        requester's approval to another.

        Args:
            context: Host tool-call context, mapping or object.

        Returns:
            The requester key, the session key and the host event (or None); a
            key that could not be resolved is the UNKNOWN placeholder, which
            _guard turns into a denial before any ticket exists.
        """
        event = _event_of(context)
        subject = _text_of(context, "subject_key")
        session = _text_of(context, "session_key")
        if self._identity is not None and event is not None:
            if not subject:
                subject = _safe_text(self._identity.subject_key, event)
            if not session:
                session = _safe_text(self._identity.session_key, event)
        return (subject or UNKNOWN_SUBJECT, session or UNKNOWN_SESSION, event)

    def _settle_timeout(self, conn: Any, ticket_id: str) -> None:
        """Move a still-pending ticket to timeout once the wait ended.

        Requirement: Approval Ticket Lifecycle. approval/waiter.py persists the
        timeouts it measured itself; the early "not enough remaining budget"
        return does not, so the ticket creator settles its own ticket.

        Args:
            conn: Store connection.
            ticket_id: Ticket created for this call.
        """
        try:
            tickets.transition(
                conn,
                ticket_id,
                (tickets.PENDING,),
                tickets.TIMEOUT,
                actor=WAITER_ACTOR,
                reason=TIMEOUT_REASON,
            )
        except Exception:  # noqa: BLE001 - a settled ticket is best effort
            return

    def _judge_route_for(self, decision: Decision) -> str | None:
        """Return the route that would answer a legacy decision word.

        Requirement: Judge Route Audit (task 6.8).

        Kept for the parity oracle only: it infers the route from the decision
        word, which is exactly the inference that made every observe-mode row read
        "astrbot_provider". Production reads the route off the verdicts instead
        (`_judge_route_of`), because a reviewer publishes `consulted` itself and
        observe mode rewrites the decision without touching that flag.

        Args:
            decision: Decision word of this round.

        Returns:
            jev for a fast-judge verdict, the deep route otherwise.
        """
        if decision in (Decision.ALLOW_FAST, Decision.DENY_JUDGE) and (
            self._jev_client is not None
        ):
            return JUDGE_ROUTE_JEV
        return self.judge_route

    def _judge_route_of(self, verdicts: Mapping[str, Any]) -> str | None:
        """Return the model route a call was actually reviewed by, or None.

        Requirement: Judge Route Audit (task 6.8); Layered Consensus.

        The route is read where it is a fact: the verdict detail of the reviewer
        that consulted a model. `consulted` is written by the reviewer itself
        (`reviewers/_common.judge_verdict`), so it survives every rewrite that
        happens after the answer -- observe mode turning a denial into an allow,
        the consensus turning a model denial into a suspension, a second round
        adding the deep reviewer. Nobody has to infer it from a decision word.

        Args:
            verdicts: The round's verdicts, keyed by reviewer name.

        Returns:
            The fast judge route when it was consulted, else the deep route when
            that one was, else None because no model saw this call.
        """
        if _verdict_detail(verdicts.get(JEV_FAST_NAME), DETAIL_CONSULTED) is True:
            return JUDGE_ROUTE_JEV
        if _verdict_detail(verdicts.get(DEEP_REVIEWER_NAME), DETAIL_CONSULTED) is True:
            return self.judge_route
        return None

    def _review_report(self, verdicts: Mapping[str, Any]) -> dict[str, Any]:
        """Summarize every reviewer's vote for the approval page.

        Requirement: Layered Consensus; Sanitized Persistence.

        An administrator approving a suspension has to see why each layer voted
        the way it did, so this reads the verdicts once and keeps the facts a
        reader needs to re-take the decision: the reviewer's own outcome word,
        the decision word it produced, its reason, its skip word, its degradation
        kind, the rule identifiers and labels it saw, and -- for a consulted
        judge -- the score, confidence and confidence annotation the banding was
        computed from. Reason text is redacted here because it becomes part of
        summary_json; everything else is a fixed vocabulary word or a number.

        Args:
            verdicts: The rounds' verdicts, keyed by reviewer name.

        Returns:
            A JSON-ready mapping of reviewer name to that reviewer's account.
            Empty when no reviewer published a verdict at all.
        """
        entries: dict[str, Any] = {}
        for name in self._review_order(verdicts):
            verdict = verdicts.get(name)
            if verdict is None:
                continue
            entry: dict[str, Any] = {
                "outcome": str(coerce_outcome(getattr(verdict, "outcome", None)).value),
                "decision": str(getattr(verdict, "decision", "") or ""),
                "reason": self._redact(str(getattr(verdict, "reason", "") or "")),
            }
            skipped = _verdict_detail(verdict, DETAIL_SKIPPED)
            if skipped:
                entry[DETAIL_SKIPPED] = str(skipped)
            degraded = getattr(verdict, "degraded", None)
            if degraded:
                entry["degraded"] = str(degraded)
            rule_ids = _verdict_detail(verdict, DETAIL_RULE_IDS)
            if rule_ids:
                entry["rule_ids"] = [str(item) for item in rule_ids]
            labels = _verdict_detail(verdict, DETAIL_LABELS)
            if labels:
                entry["labels"] = [str(item) for item in labels]
            # Requirement: Verdict Aggregation.  The layer the reviewer read is
            # attribution; the rule identifiers it saw are evidence.  Both ride
            # here so an approval page can say which stage denied a call instead
            # of leaving the reader to infer it from a rule word.
            for key in (DETAIL_LAYER, DETAIL_SOURCE):
                value = _verdict_detail(verdict, key)
                if value:
                    entry[key] = str(value)
            for key in (DETAIL_SCORE, DETAIL_CONFIDENCE, DETAIL_NOTE):
                value = _verdict_detail(verdict, key)
                if value is not None and value != "":
                    entry[key] = value
            entries[str(name)] = entry
        return entries

    def _review_order(self, verdicts: Mapping[str, Any]) -> tuple[str, ...]:
        """Return the reviewer names in the order the approval page shows them.

        The static layer, the rules, the fast judge and then the deep judge: the
        order the consensus folds them in, so a reader follows the same path the
        gateway did. Reviewers of another module sort after these by name, which
        keeps the report stable for installs that register their own.
        """
        known = {name: index for index, name in enumerate(_REVIEW_ORDER)}
        return tuple(
            sorted(
                (str(name) for name in verdicts),
                key=lambda name: (known.get(name, len(known)), name),
            )
        )

    def _redact(self, text: Any) -> str:
        """Return text redacted by the central anonymizer, fail-closed."""
        raw = text if isinstance(text, str) else str(text)
        anonymizer = self._anonymizer
        if anonymizer is None:
            return REDACTION_FAILED
        try:
            return anonymizer.redact(raw)
        except Exception:  # noqa: BLE001 - never leak an unredacted string
            return REDACTION_FAILED

    def _redact_audited(self, text: Any) -> str:
        """Redact audit-side text, keeping a visible marker when it was cut.

        Requirement: Sanitized Persistence. `anonymize.MAX_REDACT_SCAN`
        truncates the input before any rule runs, so a secret past the cap is
        never redacted. The row must not read like a fully scanned line: the
        marker rides a reserved tail so the truncation limit cannot eat it.

        Args:
            text: Text headed for one audit summary line.

        Returns:
            The redacted line, at most `SUMMARY_LINE_LIMIT` characters, with
            `REDACT_TRUNCATED` appended when the scan saw only part of it.
        """
        raw = text if isinstance(text, str) else str(text)
        line = self._redact(raw)[:SUMMARY_LINE_LIMIT]
        if len(raw) <= MAX_REDACT_SCAN:
            return line
        marker = f" {REDACT_TRUNCATED}"
        return f"{line[: max(0, SUMMARY_LINE_LIMIT - len(marker))]}{marker}"

    def _build_snapshot(self) -> PolicySnapshot | None:
        """Build the policy snapshot, None when the config is not validated."""
        if self._config is None:
            return None
        try:
            return build_snapshot(self._config)
        except Exception:  # noqa: BLE001 - a broken config disables the gateway
            return None

    def _snapshot_for(self, config: GatewayConfig) -> PolicySnapshot | None:
        """Build the snapshot of a switched configuration, never raising.

        Requirement: Policy Snapshot Consistency. build_snapshot owns the
        version, the digest and the compiled patterns, so the switch goes
        through it; replacing the mode field is only the fallback for a snapshot
        that cannot be rebuilt from this config, mirroring ui/commands.py.

        Args:
            config: The configuration that replaces the current one.

        Returns:
            The new snapshot, or None when it cannot be built.
        """
        previous = self._snapshot
        try:
            return build_snapshot(config, previous=previous)
        except (TypeError, ValueError):
            if previous is None:
                return None
            return replace(previous, mode=config.mode)
        except Exception:  # noqa: BLE001 - a broken config disables the snapshot
            return None

    def _build_anonymizer(self) -> Anonymizer | None:
        """Build the central anonymizer from the validated configuration."""
        config = self._config
        if config is None:
            return None
        roots = tuple(str(item) for item in getattr(config, "project_roots", ()) or ())
        try:
            home = str(Path.home())
        except Exception:  # noqa: BLE001 - home is a redaction hint only
            home = None
        redactor = PathRedactor(home=home, roots=roots)
        return Anonymizer(
            tuple(getattr(config, "secret_patterns", ()) or ()), paths=redactor
        )

    def _build_jev_client(self) -> JevClient | None:
        """Build the fast-judge client, None when it is not configured.

        Requirement: Reviewer Registry. ``jev_enabled`` is the assembly switch: a
        switched-off fast reviewer builds no transport at all, so nothing in this
        process can spend a JEV request however the rest of the pipeline behaves.
        """
        if self._config is None or not self._jev_enabled():
            return None
        try:
            return JevClient(self._config)
        except CLIENT_BUILD_ERRORS as exc:
            _host_logger().warning(f"fast judge disabled: {type(exc).__name__}: {exc}")
            return None

    def _build_recorder(self) -> TrajectoryRecorder:
        """Build the per-session window every managed call is recorded into.

        Requirement: Trajectory Window; Retention and Rotation. The cap is the
        configured per-subject retention (`trajectory_retention_per_user`, fifty
        by default); a config that cannot produce a number falls back to the
        recorder's own default instead of leaving the window absent.
        """
        keep = getattr(self._config, "trajectory_retention_per_user", None)
        try:
            return TrajectoryRecorder(keep=int(keep)) if keep else TrajectoryRecorder()
        except (TypeError, ValueError):
            return TrajectoryRecorder()

    def _build_watch(self) -> TrajectoryWatch:
        """Build the trajectory watch from the loaded configuration.

        Requirement: Taint Escalation; Trajectory Review Trigger. The taint TTL,
        the secret patterns and the project roots the gateway already validates
        are the same ones the watch needs; a config that cannot produce a watch
        falls back to the documented defaults instead of failing the gateway.
        """
        config = self._config
        if config is None:
            return TrajectoryWatch()
        try:
            return TrajectoryWatch(
                session_ttl=float(config.taint_ttl_s),
                secret_patterns=tuple(config.secret_patterns),
                project_roots=tuple(str(root) for root in config.project_roots),
            )
        except (TypeError, ValueError):
            return TrajectoryWatch()

    def _deep_review_client(self) -> Any:
        """Return the deep-review client, building it once on first use.

        Requirement: Deep Analysis Client. The client cannot be built in the
        constructor before the boundary that resolves providers, and it cannot be
        built only in the historical deep_review path either: since the deep
        reviewer became one of the three layers it is the registry that asks, and
        the registry was handed deep_judge=None whenever no client had been
        injected. That is why an enabled llm_deep answered "no_match" in 0 ms on
        every call while the status page called it healthy.

        The result is cached when it exists; a build that fails is retried on the
        next registry rebuild, so a provider configured later still takes effect.

        Returns:
            The deep-review client, or None when none can be configured.
        """
        if self._deep_client is None:
            self._deep_client = self._build_deep_client()
        return self._deep_client

    def _build_deep_client(self) -> Any:
        """Build the deep-review client, None when it cannot be configured.

        Requirement: Deep Analysis Client. A provider that cannot be built is not
        fatal, but it is never silent: the failure is logged with its exception
        type so a production run can tell "unconfigured" from "deep analysis
        never happened again".

        ``llm_enabled`` is the assembly switch: switched off, no client exists, so
        ``deep_review`` stops at its own ``client is None`` branch -- the branch both
        the synchronous dispatch and the background task already pass through --
        and no request leaves the process.
        """
        if self._config is None or not self._llm_enabled():
            return None
        try:
            from .provider.llm import DeepReviewClient

            # The host Context is what resolves an empty `llm_provider_id` to the
            # provider the host currently serves (context.llm_generate). Building
            # the client without it made every `astrbot_provider` request raise
            # TypeError("... does not expose the public llm_generate method"), which
            # the circuit breaker then reported as `judge_unavailable` on every
            # call -- a permanent full degradation with the real cause nowhere.
            return DeepReviewClient(self._config, context=self._context)
        except CLIENT_BUILD_ERRORS as exc:
            _host_logger().warning(f"deep review disabled: {type(exc).__name__}: {exc}")
            return None

    def _build_reviewers(self) -> ReviewerRegistry:
        """Assemble the reviewer registry of this gateway.

        Requirement: Reviewer Registry; Reviewer Contract. The five built-in
        adapters are registered in presentation order whatever their clients are
        worth: a missing fast or deep client becomes ``None`` and the adapter then
        answers SKIP from its own preconditions, so a status page reports the stage
        instead of a set of reviewers quietly shrunk by availability.

        ``policy`` is the one adapter no switch may remove (review finding S1): it
        runs the hard-deny half of the policy stage, so the switch below can only
        take ``base_check``'s whitelist behaviour out of the pipeline and the
        blacklist, path denials, secret content, private keys, sensitive
        configuration, write whitelist and T-strong suspend default keep running.
        Its registry entry refuses ``disable`` as well as ``unregister``.

        Deep analysis is registered but disabled: it stays the gateway's own
        ``_deep_dispatch``, which owns the cache, the background task, the deep
        budget and the ``deep_background_saturated`` state, so an enabled adapter
        would judge the same call twice. 11.3c flips that switch and deletes
        ``_deep_dispatch``; until then ``reviewer_statuses()`` reports the stage as
        disabled on purpose rather than hiding it.

        The slow path takes its budget from the configuration
        (``deep_analysis_timeout_s``); ``reviewers/llm_deep.py`` owns no default of
        its own, so the fallback lives here, next to the key it guards.

        A registry handed in at construction is injection protected: it holds the
        decisions the embedder asked for, so ``set_mode`` leaves it alone instead of
        rebuilding over it. A registry built here holds the snapshot of the mode it
        was built in, so ``set_mode`` rebuilds that one on every switch; both
        assignments happen in one lock window.

        The rules reviewer needs the trajectory window and the fast reviewer needs
        the caller budget, and neither travels inside ``GuardCall``; they are
        injected here as readers, one per fact.

        Returns:
            A registry holding policy, base_check, rules, jev_fast and llm_deep.
        """
        registry = ReviewerRegistry()
        budget_s = self._reviewer_deep_budget()

        def _trajectory_of(call: Any) -> Any:
            return self._trajectory_view(getattr(call, "session_key", ""))

        def _deadline_of(_call: Any) -> float | None:
            scope = _REVIEW_DEADLINE.get()
            return None if scope is None else scope.deadline

        try:
            register_builtin_reviewers(
                registry,
                snapshot=self._snapshot,
                fast_judge=self._fast_judge_callable(),
                deep_judge=self._deep_judge_callable(budget_s),
                deep_budget_s=budget_s,
                trajectory_of=_trajectory_of,
                deadline_of=_deadline_of,
            )
            # Requirement: Layered Consensus; Deep Analysis Sampling.  The deep
            # reviewer is switched by configuration, not by this assembly: with
            # llm_enabled=false it is disabled here, and with it on it is a
            # full member of the second round.  Disabling it unconditionally is
            # what made every audit row say "deep review" while the layer never
            # ran.
            if not self._llm_enabled():
                registry.disable(DEEP_REVIEWER_NAME)
            if not self._base_check_enabled():
                # The switch owns base_check's whitelist promotion only; the
                # hard denials live in POLICY_NAME, whose entry refuses to be
                # disabled at all (review finding S1).
                registry.disable(BASE_CHECK_NAME)
        except Exception as exc:  # noqa: BLE001 - a partial registry is reported
            _host_logger().warning(
                f"reviewer assembly degraded: {type(exc).__name__}: {exc}"
            )
        return registry

    def _fast_judge_callable(
        self,
    ) -> Callable[[Mapping[str, Any]], Awaitable[Any]] | None:
        """Return a Judge over the fast-judge client, None when there is none.

        Requirement: Reviewer Contract. ``reviewers/jev_fast.py`` takes the Judge
        callable, not the client, and the per-request timeout is the one this
        module already applies; binding it once here keeps both call sites honest.

        The judge is a FastJudge rather than a bare closure because the band
        thresholds travel with it: the engine reads judge.thresholds to call
        jev/score.decide, so the two numbers this process validates are the two
        numbers the single banding decision uses. These are the same frozen
        thresholds the status view reports (`fast_judge_status`), taken from the
        one resolution in `__init__` -- reading the configuration again here
        would let the status page and the decision drift apart.
        """
        jev = self._jev_client
        if jev is None:
            return None
        return FastJudge(
            jev,
            timeout_s=self._jev_timeout,
            thresholds=self._fast_thresholds,
        )

    def _deep_judge_callable(
        self, budget_s: float
    ) -> Callable[[Mapping[str, Any]], Awaitable[Any]] | None:
        """Return a Judge over the deep-review client, None when there is none.

        Requirement: Layered Consensus; Deep Analysis Sampling. The Judge
        contract is a callable from the state document to a FastVerdict, and the
        deep reviewer is now one of the three layers, so it is answered the same
        way the fast judge is:

        * the input is the state ``triage.engine.judge_payload`` built once per
          call -- the exact document the fast judge saw, not a trajectory summary
          of other calls, which used to leave the current tool, verb, targets and
          arguments out of the deep reviewer's view entirely;
        * the output goes back through the one parser
          (``jev.schema.parse_text_answer``), so a deep answer is a banded
          FastVerdict instead of a string the engine could only call unreadable.

        The payload is redacted inside the client as well; ``build_state`` already
        anonymized it, and neither layer may send a raw field out.

        Args:
            budget_s: Per-request budget, also handed to the client as its own
                timeout so the reviewer and the transport cannot disagree.

        Returns:
            The Judge, or None when no deep client was injected.
        """
        client = self._deep_review_client()
        if client is None:
            return None

        async def _judge(payload: Mapping[str, Any]) -> Any:
            text = await client.review(
                build_deep_body(state=payload),
                timeout_s=budget_s,
                system_prompt=DEEP_SYSTEM_PROMPT,
                response_format=DEEP_RESPONSE_FORMAT,
            )
            return parse_text_answer(text)

        return _judge

    def _reviewer_deep_budget(self) -> float:
        """Return the budget one deep reviewer request may spend.

        Requirement: Reviewer Contract. ``reviewers/llm_deep.py`` deliberately owns
        neither a clock nor a default, so the assembly supplies the number: the
        configured ``deep_analysis_timeout_s`` when it converts to a finite
        positive float, and ``DEFAULT_DEEP_ANALYSIS_TIMEOUT_S`` otherwise. That
        fallback is a configuration default -- the same one ``deep_review`` uses --
        never a constant owned by a reviewer, because a reviewer that invented its
        own timeout would silently disagree with the synchronous deep path.

        Returns:
            The per-request slow-path budget in seconds.
        """
        raw = getattr(self._config, "deep_analysis_timeout_s", None)
        try:
            budget = float(raw)
        except (TypeError, ValueError):
            return DEFAULT_DEEP_ANALYSIS_TIMEOUT_S
        if not math.isfinite(budget) or budget <= 0:
            return DEFAULT_DEEP_ANALYSIS_TIMEOUT_S
        return budget


def _compiled_patterns(values: Iterable[Any]) -> tuple[re.Pattern[str], ...]:
    """Compile string secret patterns and pass compiled ones through.

    Requirement: Entry-Side Fragment Gate. A policy snapshot already holds
    compiled patterns while a bare GatewayConfig holds the source strings.

    Args:
        values: Pattern sources or compiled patterns.

    Returns:
        Compiled patterns; an expression that does not compile is skipped.
    """
    output: list[re.Pattern[str]] = []
    for value in values:
        if isinstance(value, re.Pattern):
            output.append(value)
            continue
        if isinstance(value, str):
            try:
                output.append(re.compile(value))
            except re.error:
                continue
    return tuple(output)


def _field_of(source: Any, name: str) -> Any:
    """Read one field from a mapping or an object, tolerantly."""
    try:
        if isinstance(source, Mapping):
            return source.get(name)
        return getattr(source, name, None)
    except Exception:  # noqa: BLE001 - tolerant read across host shapes
        return None


def _text_of(source: Any, name: str) -> str:
    """Read one optional text override from a context."""
    value = _field_of(source, name)
    return value.strip() if isinstance(value, str) else ""


def _safe_text(reader: Callable[[Any], Any], event: Any) -> str:
    """Call one identity accessor, returning an empty string when it raises."""
    try:
        value = reader(event)
    except Exception:  # noqa: BLE001 - identity failure denies upstream
        return ""
    return value if isinstance(value, str) else ""


def _event_of(context: Any) -> Any:
    """Find the host event on a tool-call context, without importing it."""
    if context is None:
        return None
    for source in (context, _field_of(context, "context")):
        if source is None:
            continue
        for name in ("event", "message_event"):
            value = _field_of(source, name)
            if value is not None:
                return value
    return None


def _run_context_of(context: Any) -> Any:
    """Find the run context carrying tool_call_timeout."""
    holder = _field_of(context, "run_context")
    if holder is not None:
        return holder
    return context


def _tool_name(tool: Any) -> str:
    """Return the public tool name of a toolset entry."""
    name = _field_of(tool, "name")
    return name.strip() if isinstance(name, str) and name.strip() else "<unknown>"


def _schema_of(inner: Any) -> Any:
    """Return the inner tool schema, unwrapping the host permission layer."""
    if inner is None:
        return None
    try:
        parameters = getattr(unwrap(inner), "parameters", None)
    except Exception:  # noqa: BLE001 - an unreadable schema keeps all keys
        return None
    return parameters if isinstance(parameters, Mapping) else None


#: Private source kind of every tool whose output carries private content. A tool
#: absent here contributes nothing to the taint store, so an external result can
#: never become the source of a taint escalation (triage/classify.py:109).
_PRIVATE_SOURCES: dict[str, str] = {
    **{tool: SOURCE_FILE_READ for tool in FILE_READ_TOOLS},
    "get_group_message_history": SOURCE_GROUP_HISTORY,
    "astr_kb_search": SOURCE_KB_RETRIEVAL,
}


def _private_source_of(tool: str) -> str:
    """Return the private source kind of a tool, "" when it reads nothing private."""
    return _PRIVATE_SOURCES.get(tool, "")


def _dedupe(values: Iterable[Any]) -> tuple[str, ...]:
    """Return the non-empty texts in first-seen order, without duplicates."""
    seen: dict[str, None] = {}
    for value in values:
        if isinstance(value, str) and value:
            seen.setdefault(value, None)
    return tuple(seen)


def _call_facts(tool: str, args: Mapping[str, Any]) -> CallFacts:
    """Project one call onto the facts the trajectory watch consumes.

    Requirement: Taint Escalation; Trajectory Review Trigger. Classification
    belongs to triage and the tracking to trace/, so this adapter is the only
    place that knows both: it hands the watch what it needs and keeps the trace
    package free of any dependency on the triage package.

    Args:
        tool: Managed tool name.
        args: Call arguments.

    Returns:
        The facts one call contributes to its session's trajectory.
    """
    features = classify_call(tool, args)
    payload = content_text(args)
    writes: tuple[str, ...] = ()
    executes: tuple[str, ...] = ()
    if features.verb in (VERB_WRITE, VERB_EDIT):
        writes = _dedupe([*features.write_targets, *features.targets])
    elif features.verb == VERB_EXEC:
        executes = _dedupe([*features.targets, *features.tokens])
    return CallFacts(
        tool=tool,
        labels=tuple(features.labels),
        destinations=tuple(features.destinations),
        texts=_dedupe([*features.texts, *features.targets, payload]),
        payload=payload,
        source=_private_source_of(tool),
        writes=writes,
        executes=executes,
        untrusted=LABEL_UNTRUSTED_SOURCE in features.labels,
        tier=features.tier if features.tier != TIER_UNKNOWN else TIER_STRONG,
    )


def _decision_of(outcome: Any) -> Decision | None:
    """Return the enumerated decision of an outcome, None when it is missing.

    Requirement: Fail-Closed Triage. A missing decision field is not an allow:
    the pipeline converts it into a denial.

    Args:
        outcome: Mapping or object describing one verdict.

    Returns:
        The enumerated Decision, or None when the field is absent.
    """
    raw = _field_of(outcome, "decision")
    if raw is None:
        return None
    return coerce_decision(raw)


def _would_be_of(outcome: Any) -> str | None:
    """Return the observe-mode potential verdict of an outcome."""
    raw = _field_of(outcome, "would_be")
    if raw is None:
        return None
    text = raw if isinstance(raw, str) else str(getattr(raw, "value", raw))
    return text.strip() or None


def _rule_id_of(outcome: Any) -> str | None:
    """Return the first rule identifier of an outcome, when one matched."""
    hits = _field_of(outcome, "rule_hits")
    if not hits:
        return None
    first = next(iter(hits), None)
    rule_id = _field_of(first, "rule_id")
    return rule_id if isinstance(rule_id, str) and rule_id else None


def _labels_of(outcome: Any) -> tuple[str, ...]:
    """Return the sorted labels of an outcome."""
    labels = _field_of(outcome, "labels")
    if not labels:
        return ()
    return tuple(sorted(str(item) for item in labels))


def _verdicts_of(outcome: Any) -> dict[str, Any]:
    """Return one pipeline outcome's verdicts keyed by reviewer name."""
    verdicts = getattr(outcome, "verdicts", ()) or ()
    named: dict[str, Any] = {}
    for verdict in verdicts:
        name = getattr(verdict, "reviewer", None)
        if isinstance(name, str) and name:
            named[name] = verdict
    return named


def _verdict_detail(verdict: Any, key: str) -> Any:
    """Return one published detail field of a verdict, or None."""
    detail = getattr(verdict, "detail", None)
    if not isinstance(detail, Mapping):
        return None
    return detail.get(key)


def _needs_deep(outcome: Any) -> bool:
    """Return whether the fast round left this call for the deep reviewer.

    Requirement: Layered Consensus; Rules Before Models. The deep reviewer is
    never a second opinion on a decision that was already taken: it runs when the
    fast judge asked for it (its middle band with noul=true), and when the fast
    judge abstained -- no readable score, an unreadable answer, a timeout or an
    unavailable model all fold to a SKIP. Two skips must not run it: a whitelist
    hit (the static layer already approved) and an unverified fast judge that was
    never asked. A fast approval and a fast denial both end the layers here.

    Args:
        outcome: The PipelineOutcome of the static/fast round.

    Returns:
        True when the deep round must run.
    """
    verdicts = getattr(outcome, "by_reviewer", None)
    if not isinstance(verdicts, Mapping):
        return True
    fast = verdicts.get(JEV_FAST_NAME)
    if fast is None:
        return True
    if _verdict_detail(fast, DETAIL_FORCE_DEEP) is True:
        return True
    fast_outcome = coerce_outcome(getattr(fast, "outcome", None))
    if fast_outcome is ReviewOutcome.ALLOW:
        return False
    # A fast denial is already the finding that asks a human; a second opinion
    # could not change it, because the deep layer can never remove a model deny.
    if fast_outcome is ReviewOutcome.DENY:
        return False
    if getattr(outcome, "denies", False):
        return False
    skipped = _verdict_detail(fast, DETAIL_SKIPPED)
    return str(skipped or "") != SKIP_WHITELISTED


def _published_fold(verdicts: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return the folded outcome one reviewer published, when one did.

    Requirement: Verdict Aggregation.

    The reviewers own the fold: fold_stages is the only place the three stages
    are combined, so this reads one back instead of deriving a second one. The
    pick follows fold authority -- the adapter that consulted the judge folded
    the widest chain, and the two before it publish the same fold for the stages
    they could see -- so it is a lookup, never a ranking of decision words.

    Args:
        verdicts: The outcome's verdicts, keyed by reviewer name.

    Returns:
        The published fold, empty when no verdict carries one.
    """
    for name in _FOLD_PUBLISHERS:
        fold = _verdict_detail(verdicts.get(name), DETAIL_FOLD)
        if isinstance(fold, Mapping):
            return fold
    return {}


def _outcome_degraded(outcome: Any) -> str | None:
    """Return the first degradation marker of a pipeline outcome."""
    markers = getattr(outcome, "degraded", ()) or ()
    first = next(iter(markers), None)
    return first if isinstance(first, str) and first else None


def _fold_text(fold: Mapping[str, Any], key: str) -> str:
    """Return one published fold field as text, empty when it carries none."""
    value = fold.get(key)
    return value if isinstance(value, str) else ""


def _fold_rule_ids(fold: Mapping[str, Any]) -> tuple[str, ...]:
    """Return the rule identifiers the published fold names, in hit order."""
    published = fold.get(DETAIL_RULE_IDS)
    if not isinstance(published, (list, tuple)):
        return ()
    return tuple(str(item) for item in published if str(item))


def _fold_labels(fold: Mapping[str, Any]) -> tuple[str, ...]:
    """Return the sorted taint labels of the published fold."""
    published = fold.get(DETAIL_LABELS)
    if not isinstance(published, (list, tuple)):
        return ()
    return tuple(sorted(str(item) for item in published))


#: Stage words of the attribution block. A decision is attributed to the stage
#: that took it -- the static layer, the rules, one of the two models, the
#: consensus vote, or the gateway's own budget -- never to a rule identifier.
STAGE_STATIC: Final[str] = "static"
STAGE_RULES: Final[str] = "rules"
STAGE_JEV: Final[str] = "jev"
STAGE_DEEP: Final[str] = "deep"
STAGE_CONSENSUS: Final[str] = "consensus"
STAGE_GATEWAY: Final[str] = "gateway"

#: Decisions the gateway itself produces, so no reviewer is the author of them.
_GATEWAY_DECISIONS: Final[frozenset[Decision]] = frozenset(
    {
        Decision.TIMEOUT_DENY,
        Decision.DENIED_NO_WRAPPER,
        Decision.CANCELED_EXTERNAL,
    }
)

#: Reviewer names whose own verdict word identifies the model stage, in the
#: order the consensus folds them.
_MODEL_STAGES: Final[tuple[tuple[str, str], ...]] = (
    (JEV_FAST_NAME, STAGE_JEV),
    (DEEP_REVIEWER_NAME, STAGE_DEEP),
)


def _attribution(plan: Any) -> dict[str, Any]:
    """Return the attribution block of one decision, for summary_json.

    Requirement: Verdict Aggregation; Judge Route Audit.

    The audit row keeps a rule_id column -- the first rule that fired -- and the
    fold keeps every rule that fired. Both are evidence: an observe rule such as
    R8 fires on calls it never blocks, so a report that reads rule_id as the
    cause of a denial blames an observer. The cause is a stage, so this block
    names the stage from the decision word and the policy layer behind it, and
    marks the rule identifiers as evidence so a reader cannot mistake them.

    Args:
        plan: The plan the audit row is written for.

    Returns:
        The attribution block: stage, layer, source, the rule identifiers with
        their evidence role, and the ticket kind when a human is asked.
    """
    layer = str(getattr(plan, "layer", "") or "").strip()
    source = str(getattr(plan, "source", "") or "").strip()
    decision = getattr(plan, "decision", None)
    rule_id = getattr(plan, "rule_id", None)
    block: dict[str, Any] = {
        "stage": _attribution_stage(plan, decision, layer),
        "layer": layer,
        "source": source,
        "rule_ids": [] if rule_id is None else [str(rule_id)],
        # The word a report must not read as the cause: a rule identifier on
        # this row says what fired, never what decided.
        "rule_ids_role": "evidence",
    }
    would_be = getattr(plan, "would_be", None)
    if would_be:
        block["would_be"] = _value_word(would_be)
    kind = getattr(plan, "ticket_kind", None)
    if kind:
        block["ticket_kind"] = _value_word(kind)
    return block


def _value_word(value: Any) -> str:
    """Return the stored word of one enum or word value.

    A str-mixin enum prints as "WouldBe.SUSPEND", which is not the word the
    column vocabulary uses, so the value is read first and the printable form
    is only the fallback.

    Args:
        value: An enum member, a string or anything with a printable form.

    Returns:
        The vocabulary word.
    """
    word = getattr(value, "value", None)
    if isinstance(word, str) and word:
        return word
    return str(value)


def _attribution_stage(plan: Any, decision: Any, layer: str) -> str:
    """Return the stage word that decided one call.

    Args:
        plan: The plan the audit row is written for.
        decision: Its decision word.
        layer: The policy layer the fold named, empty when it named none.

    Returns:
        One of the STAGE_* words.
    """
    if decision in _GATEWAY_DECISIONS:
        return STAGE_GATEWAY
    if decision in (Decision.DENY_POLICY, Decision.DENY_REQUESTER):
        return STAGE_STATIC
    if decision is Decision.DENY_RULE:
        return STAGE_RULES
    if decision in (Decision.DENY_JUDGE, Decision.SUSPENDED):
        # A model denial is not a hard refusal, so it reaches the store as a
        # suspension; the reviewer's own word still says which model said it.
        return _model_stage_of(plan) or STAGE_CONSENSUS
    if getattr(plan, "would_be", None):
        # Observe mode records what a stage would have done; the stage that
        # would have acted is the attribution, not the rewrite of the word.
        return STAGE_CONSENSUS
    if layer in (LAYER_WHITELIST, LAYER_STATIC_PASS):
        return STAGE_STATIC
    return STAGE_CONSENSUS


def _model_stage_of(plan: Any) -> str:
    """Return the model stage whose own verdict word denied the call.

    A model denial keeps the reviewer's word on the review report, so the stage
    is read from the reviewer rather than guessed from the decision, which is
    the same word for both models.

    Args:
        plan: The plan carrying the review report.

    Returns:
        STAGE_JEV or STAGE_DEEP, empty when neither model denied the call.
    """
    review = getattr(plan, "review", None)
    if not isinstance(review, Mapping):
        return ""
    denied = Decision.DENY_JUDGE.value
    for name, stage in _MODEL_STAGES:
        entry = review.get(name)
        if isinstance(entry, Mapping) and str(entry.get("decision") or "") == denied:
            return stage
    return ""


def _reviewed_record_dict(
    record: CallSummary,
    review: Mapping[str, Any] | None,
    attribution: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the trajectory record plus the per-reviewer account, when there is one.

    Requirement: Trajectory Summary Record; Layered Consensus; Verdict
    Aggregation. The 22 spec keys stay exactly as they are, and the reviewer
    account and the attribution block are extra keys, so a reader of
    summary_json still finds the record where the specification puts it, and an
    approval page finds the evidence next to it.

    The attribution block exists because a rule identifier is not an
    attribution. The audit row keeps its rule_id column -- it is the first rule
    that fired, and it is evidence -- but an observe rule such as R8 fires on
    calls it never blocks, so a report that reads rule_id as \"what denied this
    call\" blames the observer. The block names the stage and the policy layer
    that actually decided, and marks the rule identifiers as evidence.
    """
    payload = _record_dict(record)
    if review:
        payload["review"] = dict(review)
    if attribution:
        payload["attribution"] = dict(attribution)
    return payload


def _record_dict(record: CallSummary) -> dict[str, Any]:
    """Return one summary as the 22-key mapping with JSON-safe labels.

    Requirement: Trajectory Summary Record. `as_dict` keeps the spec key order
    but holds labels as a frozenset, which json cannot encode; replacing that
    value in place keeps the order and never adds or drops a key.

    Args:
        record: Summary built for one managed call.

    Returns:
        All 22 keys, in spec order, ready for json.dumps.
    """
    data = record.as_dict()
    data["labels"] = sorted(record.labels)
    return data


def _degraded_of(outcome: Any) -> str | None:
    """Return the degradation marker of an outcome, when present."""
    raw = _field_of(outcome, "degraded")
    return raw if isinstance(raw, str) and raw else None


def _hook_field(outcome: Any, name: str) -> str | None:
    """Read one degradation field of a hook outcome, tolerantly.

    Requirement: Degraded Mode Alert. main must not import interface/hooks, so
    the decorated HookOutcome is read by duck typing and any other shape
    (None, a string, a host object) simply carries no fact.
    """
    raw = _field_of(outcome, name)
    return raw.strip() if isinstance(raw, str) and raw.strip() else None


def _reason_of(outcome: Any) -> str:
    """Return the reason text of an outcome."""
    raw = _field_of(outcome, "reason")
    return raw if isinstance(raw, str) and raw.strip() else _DENY_LABEL


def _delivery_degradation(plan: _Plan) -> str | None:
    """Return the degradation that changes how a notice is rate-limited.

    Requirement: Rate Limiting and Merging; Pre-execution Intent Record.

    An unpaired intent is an audit fact about the trajectory link, not a
    degraded decision, so it keeps the ordinary suspended-alert window instead
    of collapsing every suspension into the longer degraded window.

    Args:
        plan: The plan the notice is rendered for.

    Returns:
        The degradation marker to classify the notice with, or None.
    """
    if plan.degraded == INTENT_UNPAIRED:
        return None
    return plan.degraded


def _stamp_intent(plan: _Plan, call_id: str | None) -> _Plan:
    """Carry the intent pairing of one call onto its plan.

    Requirement: Pre-execution Intent Record.

    Args:
        plan: The plan to stamp.
        call_id: Paired call identity, or None when nothing paired.

    Returns:
        The plan with the pairing fields set. A plan that owns no degradation of
        its own takes the unpaired marker, so the audit row states the fact.
    """
    if call_id is not None:
        return replace(plan, call_id=call_id, intent_unpaired=False)
    return replace(
        plan,
        degraded=plan.degraded or INTENT_UNPAIRED,
        intent_unpaired=True,
    )


def _settled_plan(plan: _Plan, state: str) -> _Plan:
    """Map one settled ticket state onto the final plan of this call.

    Requirement: Approval Wait and Exact-Match Retry; Late Decision Disclosure.

    Args:
        plan: The suspension plan.
        state: Outcome returned by approval/waiter.

    Returns:
        The plan whose decision the caller returns for this round.
    """
    if state == TIMEOUT:
        return _Plan(
            decision=Decision.TIMEOUT_DENY,
            reason=REASON_TIMEOUT,
            would_be=plan.would_be,
            rule_id=plan.rule_id,
            judge_route=plan.judge_route,
            degraded="suspend_timeout",
        )
    if state == CANCELED_EXTERNAL:
        return _Plan(
            decision=Decision.CANCELED_EXTERNAL,
            reason=REASON_CANCELED,
            would_be=plan.would_be,
            rule_id=plan.rule_id,
            judge_route=plan.judge_route,
            degraded="outer_cancelled",
        )
    return _Plan(
        decision=Decision.DENY_POLICY,
        reason=REASON_DENIED,
        would_be=plan.would_be,
        rule_id=plan.rule_id,
        judge_route=plan.judge_route,
    )


def _summary_fragments(summary: Any) -> tuple[str, ...]:
    """Collect the fragment candidates of a trajectory summary.

    Requirement: Deep Analysis Sampling.

    Args:
        summary: Mapping or object with targets/links/args_head/summary_line, or
            an explicit excerpts list.

    Returns:
        The fragment candidates in reading order.
    """
    if summary is None:
        return ()
    collected: list[str] = []
    for name in ("excerpts", "fragments", "targets", "links"):
        value = _field_of(summary, name)
        if isinstance(value, str):
            collected.append(value)
        elif isinstance(value, Iterable) and not isinstance(value, Mapping):
            collected.extend(item for item in value if isinstance(item, str))
    for name in ("args_head", "summary_line"):
        value = _field_of(summary, name)
        if isinstance(value, str) and value.strip():
            collected.append(value)
    return tuple(collected)


def _degraded_marker(plan: _Plan) -> str:
    """Return the degradation marker one call's summary line must carry.

    Requirement: Degradation Reason on the Call Row. The reason is the plan's
    own word -- an already stable grep target such as suspend_budget_exhausted,
    triage_timeout, deep_budget_exhausted, gateway_missing_decision or
    delegate_window_exhausted -- so searching the stored row finds the cause
    instead of a boolean that says only "something degraded".

    The marker is derived from the plan alone, never from the summary body: the
    body is argument text, so it is attacker-controlled. A call whose arguments
    already spell the marker must still get it appended, or the stored row loses
    the one stable word that tells an operator (and a grep) why the call
    degraded. De-duplication belongs to the caller's marker list; the body is not
    consulted at all.

    Args:
        plan: The plan the row is written for.

    Returns:
        The marker to append, or an empty string when the plan names no reason.
    """
    reason = str(plan.degraded or "").strip()
    if not reason or reason == INTENT_UNPAIRED:
        # INTENT_UNPAIRED rides its own marker; writing it twice says nothing.
        return ""
    if reason.startswith(DEGRADED_MARKER_PREFIX):
        return reason
    return f"{DEGRADED_MARKER_PREFIX}{reason}"


def _mode_value(mode: Any) -> str:
    """Normalize and validate one requested enforcement mode.

    Requirement: Fail-Closed Enforcement.  Only the two modes
    triage/decisions.py defines are accepted, so a typo from the command layer
    is reported instead of silently leaving the session in observe mode.

    Args:
        mode: Candidate mode, any case, surrounding whitespace ignored.

    Returns:
        MODE_OBSERVE or MODE_ENFORCE.

    Raises:
        ValueError: mode is not one of those two.
    """
    text = mode.strip().lower() if isinstance(mode, str) else ""
    if text not in (MODE_OBSERVE, MODE_ENFORCE):
        raise ValueError(
            f"unsupported mode: {mode!r}; expected {MODE_OBSERVE} or {MODE_ENFORCE}"
        )
    return text


__all__ = [
    "CallOutcome",
    "DeepReviewResult",
    "FragmentFilter",
    "Gateway",
    "IdentityProvider",
    "call_deadline",
    "can_delegate",
    "can_suspend",
    "deep_budget_seconds",
    "effective_suspend_deadline",
    "filter_fragments",
    "read_tool_call_timeout",
    "remaining_seconds",
    "suspension_cap_seconds",
    "suspension_wait_seconds",
    "sync_budget_seconds",
]
