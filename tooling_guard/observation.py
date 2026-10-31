"""Side observation of tool calls the managed proxy never saw.

Requirement: Unmanaged Side Sources; Fail-Closed on Broken Choke Point.

The public `on_using_llm_tool` hook fires before every tool executes, including
the paths the gateway cannot manage: a cron/background wake-up, a request served
while the gateway is disabled, and a managed tool name that reached execution
without a `ManagedToolProxy`. Those calls are recorded as
`unmanaged_side_observation` rows and alerted, because silence there would
read as coverage.

Two invariants hold for every function here:

* the observation never rewrites tool arguments and never blocks a call. It only
  reads a tool name, the arguments (for a redacted summary) and the event.
  Neither the audit write nor the alert runs inline in the hook: the row is
  written on a worker thread (record_async) and the alert is capped by
  ALERT_TIMEOUT_S, so a lock held by another process and a slow platform cost the
  hook a bounded wait instead of the whole call. A row that did not land is not
  swallowed -- the observation carries STORE_FAILED_REASON, so "we recorded
  nothing" never reads as "nothing happened".
* every persisted or delivered fragment passes through
  `tooling_guard.anonymize` first. The redactor is rebuilt with a
  `PathRedactor` when the injected anonymizer carries none, because
  `Anonymizer.redact` only normalizes absolute paths when `paths` is set
  (tooling_guard/anonymize.py:375).

A third invariant qualifies the verdict field:

* `denied_no_wrapper` (triage/decisions.py:41) is the only verdict filed
  beyond `allow_passthrough`, and it is filed for a dangerous managed call — a
  member of `EXEC_TOOLS` or `WRITE_TOOLS`, decided by
  tooling_guard/triage/classify.py:420 `is_exec_tool` and :425
  `is_write_tool`, never by a tool-name table kept here — that reached
  execution with no proxy in front of it. The row states what the call *was*
  ("it should have been proxied and it was not"), not what this hook did:
  nothing here blocks, cancels or rewrites the call, so the verdict is filed
  after the fact. It applies to the degraded path only (`KIND_UNPROXIED`, the
  row that already carries `degraded=1`): a harmless managed call, a dangerous
  call seen while the gateway was off, and every cron/background call keep
  `allow_passthrough`.

The managed-name decision is a pure function over
`tooling_guard.policy.tools.KNOWN_TOOLS`, so it works without a gateway
instance and without importing the host.

Gateway wiring (root main.py, the only allowed call site)::

    @filter.on_using_llm_tool()
    async def on_using_llm_tool(self, event, tool, tool_args=None) -> None:
        await self.observer.observe(event=event, tool=tool, arguments=tool_args)

SideObserver.observe files the pre-execution intent for managed calls that will
reach the proxy, audits and alerts the side observations, and never raises.

The other half of that contract belongs to the proxy, which consumes the intent
exactly once::

    call_id = pop_intent(event_key_of(subject, session), tool, args_digest(args))

where args_digest is tooling_guard.trace.intent.args_digest over the raw
arguments, never a schema-canonicalized digest. No intent, no pairing: the
caller records intent_unpaired and runs the call anyway.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

from .anonymize import Anonymizer, PathRedactor
from .digest import args_head
from .interface.identity import is_cron_event, session_key, subject_key
from .notify.admin import notify_admins
from .notify.ratelimit import Admission, NotifyRateLimiter
from .policy.tools import KNOWN_TOOLS
from .store.audit import (
    SOURCE_UNMANAGED_SIDE_OBSERVATION,
    StorageUnavailableError,
    record_side_observation,
)
from .store.db import write_lock
from .trace import intent as intent_mod
from .triage import classify
from .triage.decisions import Decision

KIND_CRON = "cron"
"""Tool call seen from a cron/background wake-up."""

KIND_UNMANAGED = "unmanaged"
"""Tool call seen while the gateway was not managing this request."""

KIND_UNPROXIED = "unproxied"
"""Managed tool name observed without the managed proxy in front of it."""

DECISION_OBSERVED = "allow_passthrough"
"""Verdict recorded for an observed call: it ran unreviewed, and it was not
denied. The `degraded` flag and the `unmanaged_side_observation` source carry
the "not reviewed" meaning. A dangerous managed call that reached execution
without the proxy is filed as DECISION_DENIED instead."""

DECISION_DENIED = Decision.DENIED_NO_WRAPPER.value
"""Verdict recorded for a dangerous managed call that ran with no proxy in front
of it, on the degraded path (`KIND_UNPROXIED`). "Denied" names what the call
was — it should have been proxied and was not — not something this module did:
the call already ran, and nothing here blocks, cancels or rewrites it."""

DENIED_REASON = "受管工具名到达执行面但代理缺失，本行按拒绝记录"
"""Readable clause appended to the summary line of a DECISION_DENIED row,
placed before the redacted arguments so truncation never drops it."""

DEGRADED_REASON = "unproxied_managed_tool"
"""Degradation marker written into the summary line of a degraded row."""

SUMMARY_LIMIT = 200
"""Maximum characters of one redacted summary line."""

ARG_HEAD_LIMIT = 160
"""Maximum characters of the redacted argument head kept in a summary line."""

ALERT_TIMEOUT_S = 5.0
"""Hard cap on one administrator alert.

Requirement: Notification Delivery.  observe() is the body of a host hook: it
runs before the tool executes, so anything it awaits is latency the caller pays.
The audit row already holds the fact, so a delivery that has not finished in
five seconds is abandoned and marked on the observation rather than allowed to
stall the call.
"""

SIDE_NOTICE_DISABLED_REASON = "side_notice_disabled"
"""Why no administrator notice was sent: the switch is off.

Requirement: Unmanaged Side Sources.  ``side_notice_enabled=false`` suppresses
the private notice only.  The audit row is written exactly as before, so an
operator who reads the trail on purpose stops being paged per call -- a cron
wake-up produces one notice for every tool call it makes.
"""

STORE_FAILED_REASON = "audit_store_unavailable"
"""Degradation marker kept when the audit row of an observation was not written.

Requirement: Unmanaged Side-Observation Audit.  A side observation whose row did
not land is exactly the "silence reads as coverage" failure this module exists
to prevent, so the failure is neither raised nor dropped: it is marked on the
observation and repeated in the notice the administrators receive.
"""

_LOGGER = logging.getLogger("tooling_guard")
"""Logger shared with the gateway (tooling_guard/main.py)."""

PROXY_MARKER = "_guard_proxy"
"""Attribute the managed proxy sets on itself (interface/wrapper.py:203).

Duck-typed instead of importing tooling_guard.interface.wrapper, which pulls in
`astrbot.api` at import time and would make this module unusable without the
host.
"""

KIND_LABELS = {
    KIND_CRON: "cron/后台唤醒来源",
    KIND_UNMANAGED: "网关未启用期间的调用",
    KIND_UNPROXIED: "受管工具未经代理",
}


def _text(value: Any) -> str:
    """Return a str value unchanged and anything else as an empty string.

    Args:
        value: Arbitrary object expected to be a str.

    Returns:
        The value when it is a str, else "".
    """
    return value if isinstance(value, str) else ""


def tool_name_of(tool: Any) -> str:
    """Return the tool name of a toolset entry or a bare name.

    Args:
        tool: Toolset entry carrying `name`, or the name itself.

    Returns:
        The stripped name, or "" when it is absent or not a string.
    """
    raw: Any = ""
    with suppress(Exception):
        raw = tool if isinstance(tool, str) else getattr(tool, "name", "")
    return _text(raw).strip()


def is_managed_name(tool: Any) -> bool:
    """Return whether the name belongs to the managed tool set.

    Requirement: Unmanaged Side Sources.

    The check is a pure membership test over tooling_guard.policy.tools, so it
    answers without a gateway, a request, or the host.

    Args:
        tool: Toolset entry or bare tool name.

    Returns:
        True when the name is a known managed tool.
    """
    return tool_name_of(tool) in KNOWN_TOOLS


def is_proxied(tool: Any) -> bool:
    """Return whether the toolset entry is already the managed proxy.

    Args:
        tool: Toolset entry handed to the observation hook.

    Returns:
        True when the entry carries the proxy marker.
    """
    proxied = False
    with suppress(Exception):
        proxied = getattr(tool, PROXY_MARKER, False) is True
    return proxied


def is_dangerous_name(tool: Any) -> bool:
    """Return whether a tool name executes a command or writes a file.

    Requirement: Fail-Closed on Broken Choke Point; Degraded Mode Verdict.

    The criterion is the existing triage classification and never a tool-name
    table kept here: tooling_guard/triage/classify.py:420 `is_exec_tool` covers
    EXEC_TOOLS (:120) and :425 `is_write_tool` covers WRITE_TOOLS (:112).

    Args:
        tool: Toolset entry or bare tool name.

    Returns:
        True when the name runs a command or writes/edits a file.
    """
    name = tool_name_of(tool)
    return classify.is_exec_tool(name) or classify.is_write_tool(name)


def observation_kind(*, cron: bool, proxied: bool, enabled: bool, managed: bool) -> str:
    """Return what kind of side observation a call is, if any.

    Requirement: Unmanaged Side Sources; Sub-agent Boundary Declaration.

    Args:
        cron: Whether the event comes from a cron/background wake-up.
        proxied: Whether the toolset entry is the managed proxy.
        enabled: Whether the gateway manages the current request.
        managed: Whether the tool name is a known managed tool.

    Returns:
        One of KIND_CRON, KIND_UNMANAGED, KIND_UNPROXIED, or "" when the call is
        on the managed path (or is an intentionally unmanaged dynamic tool while
        the gateway is active, which task 3.1 strips rather than proxies).
    """
    if proxied:
        return ""
    if cron:
        return KIND_CRON
    if not enabled:
        return KIND_UNMANAGED
    if managed:
        return KIND_UNPROXIED
    return ""


def redactor_of(anonymizer: Any) -> Anonymizer:
    """Return an anonymizer that also normalizes absolute paths.

    Args:
        anonymizer: The gateway anonymizer, or None.

    Returns:
        The given anonymizer when it already normalizes paths, else a rebuilt one
        that does, else a default one that does.
    """
    if isinstance(anonymizer, Anonymizer) and anonymizer.paths is not None:
        return anonymizer
    if isinstance(anonymizer, Anonymizer):
        return Anonymizer(anonymizer.patterns, paths=PathRedactor())
    return Anonymizer(paths=PathRedactor())


def _redact(anonymizer: Any) -> Any:
    """Return whatever the caller injected after normalizing it.

    Args:
        anonymizer: An object providing redact and redact_head, or None.

    Returns:
        The redactor to use.
    """
    if anonymizer is None:
        return Anonymizer(paths=PathRedactor())
    if isinstance(anonymizer, Anonymizer):
        return redactor_of(anonymizer)
    return anonymizer


def describe(
    *,
    tool: Any,
    arguments: Mapping[str, Any] | None = None,
    event: Any = None,
    kind: str,
    anonymizer: Any = None,
) -> Observation:
    """Build one redacted observation of a tool call.

    Requirement: Unmanaged Side-Observation Audit.

    Args:
        tool: Toolset entry or bare tool name.
        arguments: Raw call arguments; only a redacted head is kept.
        event: The AstrBot event the call belongs to.
        kind: Observation kind from observation_kind.
        anonymizer: The central anonymizer.

    Returns:
        Observation: The redacted observation, with identity and summary line.
        A dangerous managed call with no proxy on it carries DECISION_DENIED;
        every other observed call carries DECISION_OBSERVED.
    """
    redactor = _redact(anonymizer)
    name = tool_name_of(tool)
    label = KIND_LABELS.get(kind, kind)
    degraded = kind == KIND_UNPROXIED
    denied = degraded and is_dangerous_name(name)
    head = redactor.redact_head(
        args_head(dict(arguments or {}), ARG_HEAD_LIMIT), ARG_HEAD_LIMIT
    )
    verdict = f"；{DENIED_REASON}" if denied else ""
    summary = f"{label}：{name}{verdict} args={head}"
    return Observation(
        kind=kind,
        tool_name=name,
        subject_key=redactor.redact(subject_key(event)),
        session_key=redactor.redact(session_key(event)),
        decision=DECISION_DENIED if denied else DECISION_OBSERVED,
        degraded=degraded,
        summary_line=redactor.redact(summary)[:SUMMARY_LIMIT],
    )


def render_side_notice(observation: Observation, *, anonymizer: Any = None) -> str:
    """Render the administrator notice for one side observation.

    Requirement: Notification Content; Unmanaged Side Sources.

    The shape follows tooling_guard/notify/messages.py: a bracketed first line,
    one `键：值` line per field, and a closing action line.

    Args:
        observation: The observation to report.
        anonymizer: The central anonymizer.

    Returns:
        A Chinese notice stating the call ran without review and was not blocked.
    """
    redactor = _redact(anonymizer)
    kind = KIND_LABELS.get(observation.kind, observation.kind)
    lines = [
        "[工具网关] 未纳管侧的工具调用已被观察",
        f"来源：{redactor.redact(kind)}",
        f"工具：{redactor.redact(observation.tool_name or '<unknown>')}",
        f"主体：{redactor.redact(observation.subject_key or '<unknown>')}",
        f"会话：{redactor.redact(observation.session_key or '<unknown>')}",
        f"记录：{redactor.redact(observation.summary_line or '<empty>')}",
    ]
    if observation.decision == DECISION_DENIED:
        lines.append(
            f"判决：{observation.decision}，该受管工具名本应经过代理执行，"
            "却到达了执行面；观察层不阻断执行，此行记录的是判决语义。"
        )
    if observation.degraded:
        lines.append(f"降级：{DEGRADED_REASON}，该受管工具名未经代理执行。")
    if observation.record_error:
        lines.append(
            f"降级：{observation.record_error}，本次旁路观测的审计行没有写入；"
            "该事实只存在于这条通知里。"
        )
    lines.extend(
        [
            "处理：本行仅供观察，参数未被改写，调用未被阻断；该调用没有经过规则/策略判定。",
            "覆盖范围：cron/后台唤醒与子 agent 内部调用不在本网关拦截范围内。",
        ]
    )
    return "\n".join(lines)


@dataclass(slots=True)
class Observation:
    """One redacted side observation and what became of it.

    Requirement: Unmanaged Side-Observation Audit.

    Attributes:
        kind: Observation kind from observation_kind.
        tool_name: Observed tool name.
        subject_key: Redacted platform_id:sender_id.
        session_key: Redacted conversation correlation key.
        decision: Verdict recorded for the call; the call itself was not blocked.
        degraded: Whether the row marks the managed path as degraded.
        summary_line: One redacted line describing the call.
        stored: Whether the audit row was written.
        alerted: Whether an alert was delivered.
        skipped: Why no alert was delivered, "" when one was.
        record_error: Why the audit row was not written, "" when it was.
    """

    kind: str
    tool_name: str
    subject_key: str
    session_key: str
    decision: str
    degraded: bool
    summary_line: str
    stored: bool = False
    alerted: bool = False
    skipped: str = ""
    record_error: str = ""


def _probe_worker_read(conn: Any) -> None:
    """Prove that one throw-away read works from this worker thread.

    Requirement: Unmanaged Side-Observation Audit.  The probe is a real use of
    the shared connection from another thread, so it takes the connection's
    commit owner first: a read issued beside the event loop's write transaction
    would be ordered inside it, and the whole point of the owner is that only one
    thread is ever inside the connection's transaction.

    Args:
        conn: The audit connection.
    """
    with write_lock(conn):
        conn.execute("SELECT 1")


class SideObserver:
    """Audit and alert tool calls observed outside the managed proxy.

    Requirement: Unmanaged Side Sources; Trajectory Record.

    The observer reads the gateway through its public attributes only
    (`enabled`, `mode`, `store`, `anonymizer`) and never imports
    tooling_guard.main, so the dependency direction stays
    main -> observation -> {store, notify, trace}.

    Args:
        gateway: Gateway whose public state is read, or None in tests.
        context: Star context used by the administrator sender.
        admins: Administrator identifiers to alert.
        sender: Sender built by notify.sender.build_sender.
        anonymizer: Central anonymizer, overriding the gateway one.
        limiter: Rate limiter, replacing the default one.
        clock: Callable returning wall-clock seconds.
        side_notice_enabled: Whether an observed call also sends the private
            administrator notice.  False suppresses the notice only; the audit
            row is still written and nothing about a judgement changes.
    """

    def __init__(
        self,
        *,
        gateway: Any = None,
        context: Any = None,
        admins: Any = (),
        sender: Any = None,
        anonymizer: Any = None,
        limiter: NotifyRateLimiter | None = None,
        clock: Any = None,
        side_notice_enabled: bool = True,
    ) -> None:
        self._gateway = gateway
        self._context = context
        self._admins = tuple(admins or ())
        self._sender = sender
        self._anonymizer = _redact(
            anonymizer
            if anonymizer is not None
            else getattr(gateway, "anonymizer", None)
        )
        self._limiter = NotifyRateLimiter() if limiter is None else limiter
        self._clock = time.time if clock is None else clock
        self._side_notice_enabled = bool(side_notice_enabled)
        self._worker_key = 0
        self._worker_ok = False

    @property
    def anonymous(self) -> Any:
        """Return the redactor every persisted and delivered fragment uses."""
        return self._anonymizer

    @property
    def limiter(self) -> NotifyRateLimiter:
        """Return the rate limiter gating administrator alerts."""
        return self._limiter

    def _gateway_enabled(self) -> bool:
        """Return whether the gateway manages the current request."""
        enabled = False
        with suppress(Exception):
            enabled = bool(getattr(self._gateway, "enabled", False))
        return enabled

    def _gateway_mode(self) -> str:
        """Return the effective gateway mode as plain text."""
        value: Any = "observe"
        with suppress(Exception):
            value = getattr(self._gateway, "mode", "observe")
        with suppress(Exception):
            value = value.value
        return _text(value) or "observe"

    def _store(self) -> Any:
        """Return the audit connection, or None when it is unavailable."""
        conn: Any = None
        with suppress(Exception):
            conn = getattr(self._gateway, "store", None)
        return conn

    def record(self, observation: Observation) -> Observation:
        """Write the audit row of one observation, never raising.

        Requirement: Unmanaged Side-Observation Audit.

        Args:
            observation: The observation to persist.

        Returns:
            The same observation with `stored` set when the row was written, or
            with `record_error` set to STORE_FAILED_REASON when it was not.
        """
        conn = self._store()
        if conn is None:
            observation.record_error = STORE_FAILED_REASON
            _LOGGER.warning("side observation audit row dropped: store unavailable")
            return observation
        try:
            record_side_observation(
                conn,
                decision=observation.decision,
                tool_name=observation.tool_name,
                subject_key=observation.subject_key,
                session_key=observation.session_key,
                summary_line=observation.summary_line,
                degraded=observation.degraded,
            )
        except (StorageUnavailableError, sqlite3.Error) as exc:
            observation.record_error = STORE_FAILED_REASON
            _LOGGER.warning("side observation audit row failed: %s", exc)
            return observation
        observation.stored = True
        return observation

    async def record_async(self, observation: Observation) -> Observation:
        """Write the audit row off the event loop, never raising.

        Requirement: Unmanaged Side-Observation Audit; Fail-Closed on Broken
        Choke Point.  The row goes through the process-wide SQLite connection,
        and a write there can wait for a lock another connection or process
        holds.  Inline, that wait is spent inside the caller's coroutine: at a
        5 s busy timeout the review measured a 5.5 s freeze of the event loop,
        which no heartbeat could interrupt.  The write moves to a worker thread
        here, so the wait costs the loop nothing, and the busy timeout stays the
        bound on how long the thread waits before reporting failure.

        The worker thread does not get its own transaction on the shared
        connection: store.audit takes the connection's commit owner
        (store.db.write_transaction) around the insert and its commit, so this
        thread and the queued audit drain on the event loop queue up instead of
        sharing one transaction.  Sharing was the defect review R10-01 measured:
        the drain's rollback discarded this side's uncommitted row, and the
        drain's commit committed it.  A worker
        write that produced no row is retried once inline: a connection created
        with the default thread affinity refuses worker threads outright, and
        without the retry every side observation of such a store would vanish
        silently.  The retry costs at most one more busy timeout and is the only
        path that can still record the fact in that configuration.

        Args:
            observation: The observation to persist.

        Returns:
            The same observation, marked exactly as `record` marks it.
        """
        conn = self._store()
        if conn is None:
            return self.record(observation)
        if not await self._worker_capable(conn):
            return self.record(observation)
        await asyncio.to_thread(self.record, observation)
        if observation.stored:
            return observation
        observation.record_error = ""
        return self.record(observation)

    async def _worker_capable(self, conn: Any) -> bool:
        """Report whether the store connection can be written from a worker.

        Requirement: Unmanaged Side-Observation Audit.  sqlite3 refuses a
        connection created with the default thread affinity from any other
        thread, and asking costs one throw-away read -- taken under the
        connection's commit owner, see _probe_worker_read -- so the answer is
        cached per connection: a store opened through store.db.open_db
        (check_same_thread=False) takes the worker path, and an injected
        connection that cannot leaves the write inline instead of failing it.

        Args:
            conn: The audit connection.

        Returns:
            bool: True when worker-thread use is allowed.
        """
        key = id(conn)
        if self._worker_key == key:
            return self._worker_ok
        capable = True
        try:
            await asyncio.to_thread(_probe_worker_read, conn)
        except sqlite3.Error:
            capable = False
        self._worker_key = key
        self._worker_ok = capable
        return capable

    def admit(self, observation: Observation, *, mode: str | None = None) -> Admission:
        """Return whether this observation may be alerted now.

        Requirement: Rate Limiting and Merging; Degraded Mode Alert.

        Args:
            observation: The observation being alerted.
            mode: Effective gateway mode, defaulting to the gateway one.

        Returns:
            The admission decision; `send` is False when the alert is merged.
        """
        return self._limiter.admit(
            subject=observation.subject_key,
            tool_name=observation.tool_name,
            mode=observation.kind if mode is None else mode,
            decision=observation.decision,
            degraded=DEGRADED_REASON if observation.degraded else None,
            now=self._clock(),
        )

    async def alert(
        self, observation: Observation, *, mode: str | None = None
    ) -> Observation:
        """Deliver one rate-limited administrator alert, never raising.

        Requirement: Notification Delivery; Rate Limiting and Merging.

        Args:
            observation: The observation being alerted.
            mode: Effective gateway mode, defaulting to the gateway one.

        Returns:
            The same observation with `alerted` set, or `skipped` explaining why no
            alert was delivered. A delivery that exceeds ALERT_TIMEOUT_S is
            abandoned rather than awaited: the row is already stored, so the
            notice is best effort and the call must not wait for it.
        """
        if not self._side_notice_enabled:
            observation.skipped = SIDE_NOTICE_DISABLED_REASON
            return observation
        if self._context is None or not self._admins:
            observation.skipped = "no admin configured"
            return observation
        admission = self.admit(observation, mode=mode)
        if not admission.send:
            observation.skipped = "rate limited"
            return observation
        message = render_side_notice(observation, anonymizer=self._anonymizer)
        delivered: Any = None
        timed_out = False
        # The delivery surface raises whatever the platform adapter raises, so
        # the whole attempt is contained; the timeout is re-raised into that same
        # containment after being recorded, because a notice that ran out of time
        # and a notice that failed are different facts.
        with suppress(Exception):
            try:
                delivered = await asyncio.wait_for(
                    notify_admins(
                        self._context,
                        self._admins,
                        message,
                        sender=self._sender,
                    ),
                    timeout=ALERT_TIMEOUT_S,
                )
            except TimeoutError:
                timed_out = True
                raise
        if timed_out:
            observation.skipped = "notify timeout"
            _LOGGER.warning("side observation alert timed out")
            return observation
        if delivered is None:
            observation.skipped = "notify failed"
            _LOGGER.warning("side observation alert failed")
            return observation
        observation.alerted = bool(delivered)
        if not observation.alerted:
            observation.skipped = "notify failed"
        return observation

    async def observe(
        self,
        *,
        event: Any = None,
        tool: Any = None,
        arguments: Mapping[str, Any] | None = None,
    ) -> Observation | None:
        """Record the intent of a managed call and audit side observations.

        Requirement: Pre-execution Intent Record; Unmanaged Side Sources.

        This is the whole body of the public `on_using_llm_tool` hook: it never
        raises, never blocks, and never rewrites `arguments`.

        Args:
            event: The AstrBot event the call belongs to.
            tool: The toolset entry about to execute.
            arguments: The arguments the host is about to pass to the tool.

        Returns:
            Observation | None: The side observation when the call was outside
            the managed path, else None.
        """
        name = tool_name_of(tool)
        kind = ""
        with suppress(Exception):
            managed = name in KNOWN_TOOLS
            proxied = is_proxied(tool)
            cron = is_cron_event(event)
            enabled = self._gateway_enabled()
            if managed and proxied and not cron:
                intent_mod.record_intent(
                    tool_name=name,
                    subject_key=subject_key(event),
                    session_key=session_key(event),
                    arguments=arguments,
                )
            kind = observation_kind(
                cron=cron,
                proxied=proxied,
                enabled=enabled,
                managed=managed,
            )
        if not kind:
            return None
        observation: Observation | None = None
        with suppress(Exception):
            observation = describe(
                tool=tool,
                arguments=arguments,
                event=event,
                kind=kind,
                anonymizer=self._anonymizer,
            )
        if observation is None:
            return None
        with suppress(Exception):
            await self.record_async(observation)
        with suppress(Exception):
            await self.alert(observation, mode=self._gateway_mode())
        return observation


__all__ = [
    "ALERT_TIMEOUT_S",
    "ARG_HEAD_LIMIT",
    "DECISION_DENIED",
    "DECISION_OBSERVED",
    "DEGRADED_REASON",
    "DENIED_REASON",
    "KIND_CRON",
    "KIND_LABELS",
    "KIND_UNMANAGED",
    "KIND_UNPROXIED",
    "PROXY_MARKER",
    "SOURCE_UNMANAGED_SIDE_OBSERVATION",
    "SIDE_NOTICE_DISABLED_REASON",
    "STORE_FAILED_REASON",
    "SUMMARY_LIMIT",
    "Observation",
    "SideObserver",
    "describe",
    "is_dangerous_name",
    "is_managed_name",
    "is_proxied",
    "observation_kind",
    "redactor_of",
    "render_side_notice",
    "tool_name_of",
]
