"""Hook adapter. Requirement: Hook Delivery and Canary.

Mechanism only: validate the public toolset surface, skip paths this hook cannot
cover, and forward installation to ``interface/install.py``. No policy decision,
no storage, no network, no model call, and no ``gateway.*`` method is invoked
here — the gateway stays an opaque object handed to ``install_proxies``, and a
degraded round reads at most its ``config.exempt_tools`` attribute.
"""

from __future__ import annotations

import contextvars
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final

from astrbot.api import FunctionTool, ToolSet, logger

from .. import compat
from . import identity, install
from .wrapper import ManagedToolProxy

# Reserved name for the add/remove round trip; removed again before returning.
CANARY_SENTINEL: Final[str] = "__tooling_guard_canary__"

# ``id()`` values are cheap but unbounded, so only a short re-entry window is
# kept: a request re-entered immediately is caught, an old id is forgotten
# instead of growing the context for the lifetime of the session.
PROCESSED_LIMIT: Final[int] = 64

# Each entry is one (request, toolset) pair already handled, both held weakly: an
# id is only reused after its object dies, so comparing the live objects is what
# keeps a fresh round from being mistaken for a re-entry.
_Entry = tuple[Callable[[], Any], Callable[[], Any]]
_PROCESSED: Final[contextvars.ContextVar[tuple[_Entry, ...]]] = contextvars.ContextVar(
    "tooling_guard_processed_requests", default=()
)


@dataclass(frozen=True, slots=True)
class HookOutcome:
    """Result of one hook dispatch.

    Requirement: Hook Delivery and Canary.

    Attributes:
        installed: Count of proxies this dispatch installed.
        subject_key: ``platform_id:sender_id`` of the requester, or ``""``.
        session_key: Minimized session key, or ``""``.
        degraded: Degradation reason, ``None`` on the normal path. Reporting it is
            the gateway's job; this adapter never hides a degradation.
        skipped: Skip reason, ``None`` when installation was attempted.
    """

    installed: int = 0
    subject_key: str = ""
    session_key: str = ""
    degraded: str | None = None
    skipped: str | None = None


def _provider_request_field() -> str:
    """Return the declared ``func_tool`` field of the public request type.

    The field is read from the public ``astrbot.api.provider`` re-export, so no
    host-internal module below the public API is imported here.

    Returns:
        Textual form of the ``func_tool`` annotation.

    Raises:
        LookupError: The field is no longer declared; the canary then fails.
    """
    from astrbot.api.provider import ProviderRequest

    annotations = getattr(ProviderRequest, "__annotations__", None)
    if not isinstance(annotations, dict) or "func_tool" not in annotations:
        raise LookupError("ProviderRequest.func_tool is gone")
    return repr(annotations["func_tool"])


def _fingerprint_targets() -> dict[str, Any]:
    """Resolve every fingerprint key to the public symbol that must still exist.

    Returns:
        One existing symbol per ``compat.GATE_FINGERPRINT`` key.

    Raises:
        Exception: Whatever the public surface raises while a symbol is read; the
            caller turns that into a canary failure.
    """
    from astrbot.api.event import filter as event_filter

    return {
        "function_tool_init": FunctionTool.__init__,
        "function_tool_call": FunctionTool.call,
        "toolset_init": ToolSet.__init__,
        "toolset_names": ToolSet.names,
        "toolset_remove_tool": ToolSet.remove_tool,
        "toolset_add_tool": ToolSet.add_tool,
        "provider_request_func_tool": _provider_request_field(),
        # ``filter`` re-exports the registration callable under the hook name, so
        # one public attribute proves both declared names.
        "filter_on_llm_request": event_filter.on_llm_request,
        "register_on_llm_request": event_filter.on_llm_request,
    }


def _canary_fingerprint() -> str | None:
    """Verify every key ``compat.GATE_FINGERPRINT`` declares still resolves.

    Returns:
        ``None`` when each declared key maps to a present symbol, else a bounded
        reason string.
    """
    try:
        targets = _fingerprint_targets()
    except Exception as exc:  # noqa: BLE001 - an unreadable surface is a failure.
        return f"fingerprint_unreadable:{type(exc).__name__}"
    declared = compat.GATE_FINGERPRINT
    if not declared:
        return "fingerprint_empty"
    unknown = sorted(key for key in declared if key not in targets)
    if unknown:
        return f"fingerprint_unmapped:{','.join(unknown)}"
    unset = sorted(
        key for key, target in targets.items() if key in declared and target is None
    )
    if unset:
        return f"fingerprint_missing:{','.join(unset)}"
    return None


def _canary_shape(toolset: Any) -> str | None:
    """Check the public ``ToolSet`` shape the adapter depends on.

    Args:
        toolset: ``ProviderRequest.func_tool`` of this round.

    Returns:
        ``None`` when the four methods exist and ``names()`` is iterable, else a
        bounded reason string.
    """
    for method in ("names", "add_tool", "remove_tool", "get_tool"):
        if not callable(getattr(toolset, method, None)):
            return f"toolset_missing_{method}"
    try:
        iter(toolset.names())
    except Exception as exc:  # noqa: BLE001 - an unlistable toolset is a failure.
        return f"toolset_names_unreadable:{type(exc).__name__}"
    return None


def _canary_sentinel(toolset: Any) -> str | None:
    """Prove ``add_tool``/``get_tool``/``remove_tool`` with one throwaway tool.

    Requirement: Hook Delivery and Canary.

    Args:
        toolset: ``ProviderRequest.func_tool`` of this round.

    Returns:
        ``None`` when the sentinel goes in, comes back and leaves again, else a
        bounded reason string. The toolset is left exactly as it was found.
    """
    try:
        sentinel = FunctionTool(
            name=CANARY_SENTINEL,
            description="tooling_guard canary entry; never executed",
            parameters={"type": "object", "properties": {}},
            handler=None,
        )
    except Exception as exc:  # noqa: BLE001 - the sentinel is the probe itself.
        return f"sentinel_unbuildable:{type(exc).__name__}"
    try:
        displaced = toolset.get_tool(CANARY_SENTINEL)
    except Exception as exc:  # noqa: BLE001 - an unreadable toolset is a failure.
        return f"toolset_get_tool_failed:{type(exc).__name__}"
    reason: str | None = None
    try:
        toolset.add_tool(sentinel)
        if toolset.get_tool(CANARY_SENTINEL) is not sentinel:
            reason = "sentinel_not_retrievable"
        elif CANARY_SENTINEL not in list(toolset.names()):
            reason = "sentinel_not_listed"
    except Exception as exc:  # noqa: BLE001 - a broken mutator is a failure.
        reason = f"sentinel_add_failed:{type(exc).__name__}"
    try:
        toolset.remove_tool(CANARY_SENTINEL)
    except Exception as exc:  # noqa: BLE001 - removal stays best effort.
        logger.error("[tooling_guard] canary 哨兵移除失败：%s", exc)
        reason = reason or f"sentinel_remove_failed:{type(exc).__name__}"
    if displaced is not None and displaced is not sentinel:
        # The reserved name was already taken; put that tool back.
        try:
            toolset.add_tool(displaced)
        except Exception as exc:  # noqa: BLE001 - restore stays best effort.
            logger.error("[tooling_guard] canary 哨兵占位工具回填失败：%s", exc)
            reason = reason or "sentinel_restore_failed"
    return reason


def _canary(toolset: Any) -> str | None:
    """Validate the public toolset shape, its mutators and the fingerprints.

    Requirement: Hook Delivery and Canary.

    Args:
        toolset: ``ProviderRequest.func_tool`` of this round.

    Returns:
        ``None`` when every check holds, else a bounded reason string. Never
        raises: a canary that cannot answer counts as failed.
    """
    try:
        reason = _canary_shape(toolset)
        if reason is not None:
            return reason
        reason = _canary_sentinel(toolset)
        if reason is not None:
            return reason
        return _canary_fingerprint()
    except Exception as exc:  # noqa: BLE001 - an unanswerable canary is a failure.
        return f"canary_error:{type(exc).__name__}"


def _strip(request: Any, gateway: Any) -> str:
    """Keep the exemptions only, or empty the toolset, when a strip must happen.

    Requirement: Fail-Closed on Broken Choke Point.

    A degraded round must not be wider than a guarded one: the normal path
    removes every unproxied entry, so this path removes every entry that is not
    in ``gateway.config.exempt_tools`` — managed, MCP, handoff, background,
    ``future_task`` and unknown alike. When that strip itself raises, the round
    loses the whole toolset instead (``install.clear_toolset``): an exemption list
    that could not be applied is no longer a trustworthy filter, and leaving the
    entries in place would execute exactly the surfaces this path exists to
    remove. Returning "done" without doing anything is what this ladder forbids.

    Args:
        request: Host ``ProviderRequest``; only ``func_tool`` is read.
        gateway: Opaque object; only its ``config.exempt_tools`` attribute is
            read, so no gateway method is invoked here.

    Returns:
        An empty string when the strip narrowed the round to the exemptions, or
        when the request exposes no readable toolset (there is no entry left to
        execute then). Otherwise the suffix naming what went wrong:
        ``+strip_failed`` when the strip raised and the fallback emptied the
        toolset, ``+strip_failed+empty_failed`` when not even the fallback could
        prove the toolset empty.
    """
    try:
        toolset = getattr(request, "func_tool", None)
    except Exception as exc:  # noqa: BLE001 - nothing can be cleared either.
        logger.error(
            "[tooling_guard] 钩子剥离：请求工具集不可读，本轮无工具可执行：%s", exc
        )
        return ""
    if toolset is None:
        return ""
    try:
        install.strip_untrusted_candidates(
            request, exempt=install.exempt_tool_names(gateway)
        )
        return ""
    except Exception as exc:  # noqa: BLE001 - the fallback below is the next step.
        logger.error("[tooling_guard] 钩子剥离未豁免工具失败，整体置空工具集：%s", exc)
    try:
        cleared = install.clear_toolset(request)
    except Exception as exc:  # noqa: BLE001 - the hook must still return a verdict.
        logger.error("[tooling_guard] 剥离兜底自身异常：%s", exc)
        cleared = False
    if cleared:
        return "+strip_failed"
    logger.error("[tooling_guard] 剥离兜底未能清空工具集，本轮留下无法移除的工具")
    return "+strip_failed+empty_failed"


def _degraded_kind(kind: str, suffix: str) -> str:
    """Name one degradation, carrying what a failed strip left behind.

    Requirement: Degraded Mode Alert.

    The kind is what the gateway persists (``hook degraded=<kind>``) and what its
    rate limiter keys the administrator notice on, so a failed strip must not hide
    behind the reason that triggered it: it gets its own kind, hence its own audit
    row and its own alert window.

    Args:
        kind: Degradation kind of the branch that asked for the strip.
        suffix: Strip suffix returned by ``_strip``, empty when it worked.

    Returns:
        ``kind`` unchanged, or ``kind`` with the suffix appended.
    """
    return f"{kind}{suffix}"


def _count_candidates(toolset: Any) -> int:
    """Count the entries ``install_proxies`` would manage on this toolset.

    Classification is delegated to ``install._surface_kind`` on purpose: the
    clues and their order live in one module only, and a copy here would drift.

    Args:
        toolset: ``ProviderRequest.func_tool`` of this round.

    Returns:
        Count of un-wrapped managed candidates.
    """
    classify = install._surface_kind
    count = 0
    for tool in list(getattr(toolset, "tools", None) or []):
        if isinstance(tool, ManagedToolProxy) or getattr(tool, "_guard_proxy", False):
            continue
        if classify(tool) == "managed":
            count += 1
    return count


def _as_ref(request: Any) -> Callable[[], Any]:
    """Return an accessor for ``request`` that keeps it alive only weakly.

    Args:
        request: Object to watch.

    Returns:
        A callable returning the object while it lives, or a strong closure when
        the object cannot be weakly referenced.
    """
    try:
        return weakref.ref(request)
    except TypeError:
        return lambda: request


def _seen(request: Any, toolset: Any) -> bool:
    """Report whether this request was already handled with this very toolset.

    Requirement: Single Wrap Per Call.

    The pair matters, not the request alone: rebinding ``req.func_tool`` for the
    same request hands over a toolset that holds no proxy yet, and skipping it
    would leave every managed call of that round unguarded.

    Args:
        request: Host ``ProviderRequest`` of this round.
        toolset: Its ``func_tool`` object right now.

    Returns:
        ``True`` only when a recorded entry names both live objects.
    """
    return any(
        live_request() is request and live_toolset() is toolset
        for live_request, live_toolset in _PROCESSED.get()
    )


def _remember(request: Any, toolset: Any) -> None:
    """Record one handled (request, toolset) pair, keeping the window bounded.

    Requirement: Single Wrap Per Call.

    Args:
        request: Host ``ProviderRequest`` handled by this dispatch.
        toolset: The ``func_tool`` object this dispatch installed into.
    """
    kept = tuple(
        (live_request, live_toolset)
        for live_request, live_toolset in _PROCESSED.get()
        if live_request() is not None and live_toolset() is not None
    )
    _PROCESSED.set(((_as_ref(request), _as_ref(toolset)), *kept)[:PROCESSED_LIMIT])


def _dispatch(event: Any, request: Any, gateway: Any) -> HookOutcome:
    """Run the ordered gate sequence and report one outcome, never raising.

    Requirement: Hook Delivery and Canary; Coverage Boundary Declaration.

    Args:
        event: Host message or cron event for this request.
        request: Host ``ProviderRequest``; only ``func_tool`` is read.
        gateway: Opaque object forwarded to ``install_proxies``.

    Returns:
        The outcome of the first condition that settles this round, or a
        ``hook_error`` degradation when the round could not be settled at all.
        A branch whose strip could not narrow the round reports its kind with a
        ``+strip_failed`` suffix, so the toolset that lost every entry and the
        reason for it stay two separate facts. The host swallows hook exceptions
        and keeps going, so raising here would forward the round unguarded.
    """
    try:
        toolset = getattr(request, "func_tool", None)
        if toolset is None:
            return HookOutcome(degraded="toolset_missing", skipped="no_toolset")
        reason = _canary(toolset)
        if reason is not None:
            logger.error(
                "[tooling_guard] canary 校验失败，剥离本轮未豁免工具：%s", reason
            )
            return HookOutcome(
                degraded=_degraded_kind("canary_failed", _strip(request, gateway))
            )
        if identity.is_cron_event(event):
            # Cron builds its own ProviderRequest, so this hook never covered it.
            return HookOutcome(degraded="cron_not_covered", skipped="cron")
        subject = identity.subject_key(event)
        session = identity.session_key(event)
        if not subject:
            logger.error("[tooling_guard] 无法识别请求者身份，剥离本轮未豁免工具")
            return HookOutcome(
                session_key=session,
                degraded=_degraded_kind("identity_missing", _strip(request, gateway)),
            )
        if _seen(request, toolset):
            return HookOutcome(
                subject_key=subject, session_key=session, skipped="already_installed"
            )
        candidates = _count_candidates(toolset)
        installed = install.install_proxies(request, gateway)
        # Record the toolset that was actually installed into, not the one read
        # before the call: a host that rebinds func_tool mid-install must not
        # leave a stale pair behind.
        _remember(request, getattr(request, "func_tool", toolset))
        if installed == 0 and candidates > 0:
            logger.error(
                "[tooling_guard] 代理安装失败，剥离本轮 %d 个未豁免工具", candidates
            )
            return HookOutcome(
                subject_key=subject,
                session_key=session,
                degraded=_degraded_kind("install_failed", _strip(request, gateway)),
            )
        return HookOutcome(
            installed=installed, subject_key=subject, session_key=session
        )
    except Exception as exc:  # noqa: BLE001 - the hook must never reach AstrBot.
        logger.error("[tooling_guard] 钩子适配层异常，按 fail-closed 降级：%s", exc)
        return HookOutcome(
            degraded=_degraded_kind("hook_error", _strip(request, gateway))
        )


async def on_llm_request(event: Any, request: Any, gateway: Any) -> HookOutcome:
    """Adapt the public request hook to the gateway, without policy logic.

    Requirement: Hook Delivery and Canary; Fail-Closed on Broken Choke Point.

    The entry point is a coroutine function because the host requires one: it
    asserts ``inspect.iscoroutinefunction(handler.handler)`` before awaiting every
    registered plugin hook handler (``core/pipeline/context_utils.py:115``) and
    only logs the resulting failure, so a synchronous adapter would never run at
    all — a silent fail-open. Nothing is awaited here: every mechanism step is
    synchronous, and every failure is turned into a degradation inside
    ``_dispatch``.

    Args:
        event: Host message or cron event for this request.
        request: Host ``ProviderRequest``; only ``func_tool`` is read.
        gateway: Opaque object forwarded to ``install_proxies``; never called.

    Returns:
        One ``HookOutcome`` for every path, including every failure path.
    """
    return _dispatch(event, request, gateway)
