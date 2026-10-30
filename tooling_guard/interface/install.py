"""Proxy lifecycle adapter. Requirement: Proxy Installation Through Public Surface."""

from __future__ import annotations

import contextlib
from typing import Any

from astrbot.api import FunctionTool, logger

from ..compat import (
    BACKGROUND_TASK_ATTR,
    HANDOFF_AGENT_ATTR,
    HANDOFF_NAME_PREFIX,
    MCP_SOURCE_ATTRS,
    unwrap_chain,
)
from ..policy.tools import KNOWN_TOOLS
from .wrapper import ManagedToolProxy

# Self-declared background tool stripped by default (policy/tools.py:31).
FUTURE_TASK_NAME = "future_task"
# Sentinel for "the attribute could not be read", so a raise and a real value
# stay distinguishable without a blind except.
_UNREADABLE = object()


def _surface_kind(tool: Any) -> str:
    """Classify one toolset entry after unwrapping the whole host proxy chain.

    Requirement: Managed Tool Scope.

    A tool counts as managed as soon as ONE ownership clue is readable, because
    neither clue survives the host's own wrapping intact: ``_PermissionGuardedTool``
    keeps ``handler`` as ``None`` on purpose so execution falls through to its
    ``call()`` override (``astrbot/core/provider/func_tool_manager.py:233-244``), and
    ``handler_module_path`` is derived from the tool class's ``__module__``
    (``astrbot/core/star/context.py:109-122``, assigned at ``:747-754``), which for a
    plugin instance tool is often not the plugin's own module. Requiring both clues
    therefore classified callable third-party tools as unknown and lost them.

    The unwrap is deep (``compat.unwrap_chain``, bounded and cycle-safe) because a
    guarded plugin tool can sit behind more than one host layer; an incomplete chain
    proves nothing about the entry and stays ``"unknown"``.

    Args:
        tool: One element of ``ProviderRequest.func_tool.tools``.

    Returns:
        ``"managed"`` when policy must decide every call, otherwise the strip label
        ``"mcp"``, ``"handoff"``, ``"background"``, ``"future_task"`` or ``"unknown"``.
        ``"unknown"`` means "cannot be proven managed"; every non-managed kind is
        unmanaged, and the caller only deletes those when the operator turns the
        strip switch on — the default forwards them untouched.

    Raises:
        Exception: Whatever the tool raises while its clues are read; the caller
            treats that as fail-closed and strips the round's managed candidates.
    """
    inner, complete = unwrap_chain(tool)
    if not complete:
        return "unknown"
    name = getattr(inner, "name", "")
    if not isinstance(name, str):
        return "unknown"
    for attr in MCP_SOURCE_ATTRS:
        if getattr(inner, attr, None) is not None:
            return "mcp"
    if name.startswith(HANDOFF_NAME_PREFIX) or (
        getattr(inner, HANDOFF_AGENT_ATTR, None) is not None
    ):
        return "handoff"
    if getattr(inner, BACKGROUND_TASK_ATTR, False):
        return "background"
    if name == FUTURE_TASK_NAME:
        return "future_task"
    if not name or not isinstance(inner, FunctionTool):
        return "unknown"
    if name in KNOWN_TOOLS:
        return "managed"
    if getattr(inner, "handler", None) is not None:
        return "managed"
    if getattr(inner, "handler_module_path", None):
        return "managed"
    return "unknown"


def _discard(func_tool: Any, name: str) -> None:
    """Remove one tool by name, tolerating a toolset that no longer holds it.

    Args:
        func_tool: The ``ToolSet`` being rewritten in place.
        name: Tool name to remove.
    """
    if not name:
        return
    try:
        func_tool.remove_tool(name)
        return
    except Exception as exc:  # noqa: BLE001 - removal stays best effort.
        logger.error("[tooling_guard] 移除工具 %r 失败：%s", name, exc)
    # remove_tool() compares names across the whole list, so a single entry whose
    # name cannot be read breaks it. Rebuild the list in place instead and leave
    # the unreadable entries alone: they were never classified as managed.
    try:
        kept: list[Any] = []
        for tool in list(getattr(func_tool, "tools", None) or []):
            try:
                tool_name = tool.name
            except Exception as exc:  # noqa: BLE001 - keep entries we cannot inspect.
                logger.error("[tooling_guard] 工具名不可读，保留该项：%s", exc)
                kept.append(tool)
                continue
            if tool_name != name:
                kept.append(tool)
        func_tool.tools[:] = kept
    except Exception as exc:  # noqa: BLE001 - best effort, never raises.
        logger.error("[tooling_guard] 重建工具集以移除 %r 失败：%s", name, exc)


def strip_managed_candidates(request: Any) -> int:
    """Remove every managed candidate from the current toolset.

    Requirement: Fail-Closed on Broken Choke Point.

    Used by the hook adapter when this round cannot be guarded: a tool policy
    must decide about is removed from the round instead of being forwarded
    unguarded. Classification is ``_surface_kind``, so the clues and their order
    exist in exactly one place.

    Args:
        request: Host ``ProviderRequest``; only ``func_tool`` is read.

    Returns:
        Count of managed candidates removed.
    """
    func_tool = getattr(request, "func_tool", None)
    if func_tool is None:
        return 0
    names: list[str] = []
    for tool in list(getattr(func_tool, "tools", None) or []):
        try:
            if _surface_kind(tool) != "managed":
                continue
            names.append(tool.name)
        except Exception as exc:  # noqa: BLE001 - keep entries we cannot inspect.
            logger.error("[tooling_guard] 剥离时工具不可识别，保留该项：%s", exc)
    for name in names:
        _discard(func_tool, name)
    if names:
        logger.error("[tooling_guard] 已剥离 %d 个受管候选工具", len(names))
    return len(names)


def _exempt_set(exempt: Any) -> frozenset[str]:
    """Normalize an exemption list to stripped, casefolded tool names.

    Args:
        exempt: Iterable of tool names, one name, or `None`.

    Returns:
        The normalized names; missing, blank and non-text entries contribute
        nothing, so an unusable list keeps no tool at all.
    """
    if exempt is None:
        return frozenset()
    if isinstance(exempt, str):
        exempt = (exempt,)
    try:
        items = list(exempt)
    except TypeError:
        return frozenset()
    names: set[str] = set()
    for item in items:
        if not isinstance(item, str):
            continue
        normalized = item.strip().casefold()
        if normalized:
            names.add(normalized)
    return frozenset(names)


def exempt_tool_names(gateway: Any) -> frozenset[str]:
    """Read the configured exemption list from an opaque gateway.

    Requirement: Fail-Closed on Broken Choke Point.

    The list is read as an attribute (`gateway.config.exempt_tools`), never by
    calling the gateway: the hook adapter still invokes no gateway method.

    Args:
        gateway: Object carrying `config.exempt_tools`; may be `None`.

    Returns:
        Normalized exempt tool names, or an empty set when nothing usable is
        exposed — an unknown exemption list keeps no tool.
    """
    raw: Any = _UNREADABLE
    with contextlib.suppress(Exception):
        raw = getattr(getattr(gateway, "config", None), "exempt_tools", ())
    if raw is _UNREADABLE:
        logger.error("[tooling_guard] 读取豁免名单失败，按无豁免处理")
        return frozenset()
    return _exempt_set(raw)


def strip_unmanaged(gateway: Any) -> bool:
    """Read the optional strip switch for every unmanaged tool kind.

    Requirement: Proxy Installation Through Public Surface (Scenario:
    不可纳管工具默认原样放行并披露 / 开关开启时强制剥离不可纳管工具).

    Read as an attribute (gateway.strip_unmanaged_tools), never by calling
    the gateway: the hook adapter still invokes no gateway method.

    Args:
        gateway: Object carrying the switch; may be None.

    Returns:
        True only when the switch is genuinely on. Anything unreadable reads as
        off, which keeps the tool and discloses it -- deleting a tool on a failed
        read would be a strip the operator never asked for.
    """
    raw: Any = _UNREADABLE
    with contextlib.suppress(Exception):
        raw = getattr(gateway, "strip_unmanaged_tools", False)
    if raw is _UNREADABLE:
        logger.error("[tooling_guard] 读取不可纳管工具剥离开关失败，按默认不剥离处理")
        return False
    return bool(raw)


def _drop_entries(func_tool: Any, entries: list[Any]) -> int:
    """Remove toolset entries that cannot be addressed by name.

    Args:
        func_tool: The `ToolSet` being rewritten in place.
        entries: Objects to remove, matched by identity.

    Returns:
        Count removed, or `0` when the list cannot be rewritten.
    """
    doomed = {id(entry) for entry in entries}
    with contextlib.suppress(Exception):
        kept = [
            tool
            for tool in list(getattr(func_tool, "tools", None) or [])
            if id(tool) not in doomed
        ]
        func_tool.tools[:] = kept
        return len(entries)
    logger.error("[tooling_guard] 重建工具集以移除无名条目失败")
    return 0


def strip_untrusted_candidates(request: Any, *, exempt: Any = ()) -> int:
    """Keep the exempt tools only and remove everything else from the toolset.

    Requirement: Fail-Closed on Broken Choke Point.

    A round this adapter cannot guard must not be wider than a guarded one: the
    normal path proxies every managed candidate and strips every other entry
    (`install_proxies`), so the degraded path keeps exactly the configured
    exemptions and drops managed, MCP, handoff, background, `future_task` and
    unknown entries alike. An entry whose name is missing or unreadable cannot
    be proven exempt, so it is removed as well.

    Args:
        request: Host `ProviderRequest`; only `func_tool` is read.
        exempt: Tool names to keep, compared after strip and casefold. Missing
            or empty means nothing is kept.

    Returns:
        Count of entries removed.
    """
    func_tool = getattr(request, "func_tool", None)
    if func_tool is None:
        return 0
    keep = _exempt_set(exempt)
    names: list[str] = []
    unnamed: list[Any] = []
    for tool in list(getattr(func_tool, "tools", None) or []):
        name: Any = _UNREADABLE
        with contextlib.suppress(Exception):
            name = tool.name
        if name is _UNREADABLE:
            logger.error("[tooling_guard] 降级剥离：工具名不可读，按未豁免移除")
            unnamed.append(tool)
            continue
        if isinstance(name, str) and name.strip().casefold() in keep:
            continue
        if isinstance(name, str) and name:
            names.append(name)
        else:
            unnamed.append(tool)
    for name in names:
        _discard(func_tool, name)
    removed = len(names)
    if unnamed:
        removed += _drop_entries(func_tool, unnamed)
    if removed:
        logger.error(
            "[tooling_guard] 降级剥离 %d 个未豁免工具，保留豁免项：%s",
            removed,
            ", ".join(sorted(keep)) or "无",
        )
    return removed


def clear_toolset(request: Any) -> bool:
    """Empty the whole toolset, the last resort when stripping itself failed.

    Requirement: Fail-Closed on Broken Choke Point.

    ``strip_untrusted_candidates`` keeps the configured exemptions, but it cannot
    report a reliable verdict once it raises: nothing is provably exempt any more,
    so the round loses every entry instead of keeping the unproven ones. Three
    mutations are tried in order — clearing the live list in place, rebinding the
    attribute, then removing every listed name — because a host may hand back a
    copy of ``tools`` or refuse the attribute write; each step runs only while the
    previous one left entries behind.

    Args:
        request: Host ``ProviderRequest``; only ``func_tool`` is read.

    Returns:
        ``True`` when no entry is left, or when the request exposes no toolset at
        all (there is no callable entry then); ``False`` when entries may remain
        but could not be removed.
    """
    try:
        func_tool = getattr(request, "func_tool", None)
    except Exception as exc:  # noqa: BLE001 - an unreadable toolset has no entries.
        logger.error(
            "[tooling_guard] 兜底清空：读取 func_tool 失败，本轮无工具可执行：%s", exc
        )
        return True
    if func_tool is None:
        return True

    def remaining() -> int | None:
        """Count the entries still present, or ``None`` when that is unreadable."""
        readers = (
            lambda: list(getattr(func_tool, "tools", None) or ()),
            lambda: list(func_tool.names()),
        )
        for read in readers:
            try:
                return len(read())
            except Exception as exc:  # noqa: BLE001 - 读不到就换下一种读法。
                logger.error("[tooling_guard] 兜底清空：工具集条目数不可读：%s", exc)
        return None

    try:
        tools = getattr(func_tool, "tools", None)
        if tools is not None:
            tools[:] = []
    except Exception as exc:  # noqa: BLE001 - the next step is the fallback.
        logger.error("[tooling_guard] 兜底清空：就地清空工具集失败：%s", exc)
    left = remaining()
    if left == 0:
        logger.error("[tooling_guard] 兜底清空：本轮工具集已整置空")
        return True
    try:
        func_tool.tools = []
    except Exception as exc:  # noqa: BLE001 - the next step is the fallback.
        logger.error("[tooling_guard] 兜底清空：换绑空列表失败：%s", exc)
    left = remaining()
    if left == 0:
        logger.error("[tooling_guard] 兜底清空：本轮工具集已整置空（换绑）")
        return True
    try:
        for name in list(func_tool.names()):
            func_tool.remove_tool(name)
    except Exception as exc:  # noqa: BLE001 - nothing further is available.
        logger.error("[tooling_guard] 兜底清空：按名移除工具失败：%s", exc)
    left = remaining()
    if left == 0:
        logger.error("[tooling_guard] 兜底清空：本轮工具集已整置空（按名移除）")
        return True
    logger.error("[tooling_guard] 兜底清空后仍无法证明工具集为空")
    return False


def install_proxies(request: Any, gateway: Any = None) -> int:
    """Install each supported tool proxy into the current public toolset.

    Requirement: Proxy Installation Through Public Surface (Scenario:
    不可纳管工具默认原样放行并披露 / 开关开启时强制剥离不可纳管工具).

    Only managed entries get a proxy. Every unmanaged entry — MCP, handoff,
    background, ``future_task`` and the shapes that cannot be proven managed —
    follows the one switch ``strip_unmanaged_tools``: off (the shipped default)
    keeps it in the toolset exactly as the host built it, on strips it. Nothing
    is deleted by default, because a recognition failure must not delete a tool
    another plugin already registered and the host may still call. The price is
    explicit and is what the WARN discloses — such a tool runs outside the audit
    trail and outside every policy decision of this round.

    Args:
        request: Host ``ProviderRequest``; only ``func_tool`` is read.
        gateway: Gateway deciding each proxied call. ``None`` delegates every call
            without deciding and exists only for harnesses and tests.

    Returns:
        Count of proxies this call filled back into the toolset (pass-through
        entries are not counted). ``0`` also covers the fail-closed abort, where
        this round's managed candidates are stripped instead of being forwarded
        unguarded.
    """
    func_tool = getattr(request, "func_tool", None)
    if func_tool is None:
        return 0
    entries = list(getattr(func_tool, "tools", None) or [])
    managed: list[tuple[str, ManagedToolProxy]] = []
    stripped: list[str] = []
    passthrough: list[str] = []
    try:
        for tool in entries:
            if isinstance(tool, ManagedToolProxy) or getattr(
                tool, "_guard_proxy", False
            ):
                continue
            kind = _surface_kind(tool)
            name = tool.name
            if kind == "managed":
                managed.append((name, ManagedToolProxy(inner=tool, gateway=gateway)))
            elif strip_unmanaged(gateway):
                stripped.append(name)
            else:
                passthrough.append(name)
    except Exception as exc:  # noqa: BLE001 - fail-closed: strip, never forward.
        stripped_all = strip_untrusted_candidates(
            request, exempt=exempt_tool_names(gateway)
        )
        logger.error(
            "[tooling_guard] 代理安装失败，已剥离 %d 个未豁免工具（本轮受管候选 %d 个）：%s",
            stripped_all,
            len(managed),
            exc,
        )
        return 0
    try:
        for name in stripped:
            _discard(func_tool, name)
        for name, proxy in managed:
            _discard(func_tool, name)
            func_tool.add_tool(proxy)
    except Exception as exc:  # noqa: BLE001 - fail-closed on a broken toolset.
        stripped_all = strip_untrusted_candidates(
            request, exempt=exempt_tool_names(gateway)
        )
        logger.error(
            "[tooling_guard] 代理回填失败，已剥离 %d 个未豁免工具（本轮受管候选 %d 个）：%s",
            stripped_all,
            len(managed),
            exc,
        )
        return 0
    if stripped:
        logger.warning(
            "[tooling_guard] 开关 strip_unmanaged_tools 已开启，剥离 %d 个不可纳管工具"
            "（这些工具本轮不可用，也不留审计行）：%s",
            len(stripped),
            ", ".join(sorted(stripped)),
        )
    if passthrough:
        logger.warning(
            "[tooling_guard] %d 个不可纳管工具原样放行（不进入审计与策略）：%s",
            len(passthrough),
            ", ".join(sorted(passthrough)),
        )
    return len(managed)


def remove_proxies(request: Any) -> None:
    """Remove installed proxies during shutdown. Requirement: Single Wrap Per Call.

    Args:
        request: Host ``ProviderRequest``; only ``func_tool`` is read.
    """
    try:
        func_tool = getattr(request, "func_tool", None)
        if func_tool is None:
            return
        for tool in list(getattr(func_tool, "tools", None) or []):
            if not getattr(tool, "_guard_proxy", False):
                continue
            inner = getattr(tool, "_inner_tool", None)
            if inner is None:
                continue
            name = getattr(tool, "name", "")
            _discard(func_tool, name)
            func_tool.add_tool(inner)
    except Exception as exc:  # noqa: BLE001 - shutdown never raises.
        logger.error("[tooling_guard] 撤销代理失败：%s", exc)
