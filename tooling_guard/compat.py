"""Compatibility fingerprints and brittle public-surface clues.

Requirement: Public Surface Fingerprint. This is the sole module permitted to
name the upstream wrapper, MCP, and handoff clues; every other module must
consume the constants below instead of repeating the raw strings.

Baseline evidence, read from AstrBot 4.29.3 commit 0e997ccd9e8b47930c830e69db6a657dfbf44d9; signatures measured in tests/gate1/compat_probe.py using inspect.signature:

* ToolSet.add_tool duplicate behavior was probed: active wins; equal active state keeps the later tool (tests/gate1/runner_clean.json; upstream tool.py:92-110).

* ``astrbot/core/provider/func_tool_manager.py:240`` sets
  ``self._wrapped = tool``. That outer object is neither ``MCPTool`` nor
  ``HandoffTool`` and carries no ``is_background_task``, so classification
  must unwrap it before reading any other clue.
* ``astrbot/core/agent/mcp_client.py:798`` declares the constructor parameters
  ``mcp_tool, mcp_client, mcp_server_name``; ``:810`` assigns
  ``self.mcp_tool = mcp_tool`` on ``class MCPTool`` at ``:794``.
* ``astrbot/core/agent/handoff.py:8`` declares
  ``class HandoffTool(FunctionTool, ...)``, ``:26`` builds
  ``name=f"transfer_to_{agent.name}"``, ``:36`` sets ``self.agent = agent``.
* ``astrbot/core/agent/tool.py:62`` declares
  ``is_background_task: bool = False``.
* ``astrbot/core/computer/booters/local.py:185`` and ``:313`` raise
  ``PermissionError("Blocked unsafe shell command.")``.
"""

from collections.abc import Collection, Mapping
from typing import Final

GATE_FINGERPRINT: Final[dict[str, str]] = {
    "function_tool_init": "(name: str, description: str, parameters: dict[str, typing.Any], handler: collections.abc.Callable[..., collections.abc.Awaitable[str | None] | collections.abc.AsyncGenerator[astrbot.core.message.message_event_result.MessageEventResult, None]] | None = None, handler_module_path: str | None = None, active: bool = True, is_background_task: bool = False) -> None",
    "function_tool_call": "(self, context: astrbot.core.agent.run_context.ContextWrapper[~TContext], **kwargs) -> str | mcp.types.CallToolResult",
    "toolset_init": "(tools: list[astrbot.core.agent.tool.FunctionTool] = <factory>) -> None",
    "toolset_names": "(self) -> list[str]",
    "toolset_remove_tool": "(self, name: str) -> None",
    "toolset_add_tool": "(self, tool: astrbot.core.agent.tool.FunctionTool) -> None",
    "provider_request_func_tool": "ToolSet | None",
    "filter_on_llm_request": "(**kwargs)",
    "register_on_llm_request": "(**kwargs)",
}

# Attribute in which the host proxy store keeps the real tool it wraps
# (astrbot/core/provider/func_tool_manager.py:240).
UNWRAP_ATTR: Final[str] = "_wrapped"

# MCP provenance markers (astrbot/core/agent/mcp_client.py:798, :810-812).
MCP_TOOL_ATTR: Final[str] = "mcp_tool"
MCP_CLIENT_ATTR: Final[str] = "mcp_client"
MCP_SERVER_NAME_ATTR: Final[str] = "mcp_server_name"
MCP_SOURCE_ATTRS: Final[tuple[str, ...]] = (
    MCP_TOOL_ATTR,
    MCP_CLIENT_ATTR,
    MCP_SERVER_NAME_ATTR,
)

# Handoff marker: name prefix plus the agent payload it carries
# (astrbot/core/agent/handoff.py:26 and :36).
HANDOFF_NAME_PREFIX: Final[str] = "transfer_to_"
HANDOFF_AGENT_ATTR: Final[str] = "agent"

# Background-task self-declaration (astrbot/core/agent/tool.py:62).
BACKGROUND_TASK_ATTR: Final[str] = "is_background_task"

# Verbatim denial text of the native shell guard
# (astrbot/core/computer/booters/local.py:185 and :313).
NATIVE_BLOCK_MESSAGE: Final[str] = "Blocked unsafe shell command."


def unwrap(tool: object) -> object:
    """Return the inner tool a host wrapper proxies, else the tool itself.

    Requirement: Proxy Installation Through Public Surface. Classification under
    that requirement starts from ``inner = getattr(t, "_wrapped", t)``.

    Args:
        tool: One element of ``ProviderRequest.func_tool``.

    Returns:
        ``getattr(tool, UNWRAP_ATTR, tool)``. A missing attribute, or an
        attribute access that raises, yields ``tool`` unchanged so the caller
        keeps fail-closed ownership of the decision.
    """
    try:
        return getattr(tool, UNWRAP_ATTR, tool)
    except Exception:  # noqa: BLE001 - fail-closed; the caller classifies the raw tool.
        return tool


# Deepest _wrapped chain accepted before classification gives up.
MAX_UNWRAP: Final[int] = 4

# Self-declared background tool stripped by default (policy/tools.py:31).
FUTURE_TASK_NAME: Final[str] = "future_task"

# Surface markers returned by classify_wrapper_surface. Stable strings: callers
# (and the unit scripts) compare them instead of re-reading the raw clues.
SURFACE_BUILTIN_STATIC: Final[str] = "builtin_static"
SURFACE_PLUGIN: Final[str] = "plugin"
SURFACE_MCP: Final[str] = "mcp"
SURFACE_HANDOFF: Final[str] = "handoff"
SURFACE_BACKGROUND: Final[str] = "background"
SURFACE_FUTURE_TASK: Final[str] = "future_task"
SURFACE_UNKNOWN: Final[str] = "unknown"

# Every marker classify_wrapper_surface can return, in strip-precedence order.
SURFACE_MARKERS: Final[tuple[str, ...]] = (
    SURFACE_BUILTIN_STATIC,
    SURFACE_PLUGIN,
    SURFACE_MCP,
    SURFACE_HANDOFF,
    SURFACE_BACKGROUND,
    SURFACE_FUTURE_TASK,
    SURFACE_UNKNOWN,
)

# Markers the gateway may proxy; every other marker is stripped (fail-closed).
MANAGED_SURFACES: Final[frozenset[str]] = frozenset(
    {SURFACE_BUILTIN_STATIC, SURFACE_PLUGIN}
)

# Errors a hostile tool may raise while its clues are read. Catching this exact
# tuple keeps classification total under the default ruff rules, which flag a
# blind "except Exception" and forbid the noqa that would silence it.
_HOSTILE_ERRORS: Final[tuple[type[BaseException], ...]] = (
    AttributeError,
    ArithmeticError,
    LookupError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
)

# Sentinel for an attribute read that raised; callers map it to unknown.
_UNREADABLE: Final[object] = object()

# Sentinel for an absent attribute, distinct from a self-referential value.
_ABSENT: Final[object] = object()


def _read(obj: object, attr: str, default: object = None) -> object:
    """Read one clue attribute without letting a hostile tool escape.

    Args:
        obj: Tool or wrapper under inspection.
        attr: Upstream attribute name.
        default: Value used when the attribute is absent.

    Returns:
        The attribute value, default when absent, or _UNREADABLE when the read
        raised.
    """
    try:
        return getattr(obj, attr, default)
    except _HOSTILE_ERRORS:
        return _UNREADABLE


def _type_names(obj: object) -> tuple[str, str]:
    """Return the class name and module name of obj as plain strings.

    Args:
        obj: Object under inspection.

    Returns:
        (class_name, module_name); empty strings when the lookup failed.
    """
    try:
        cls = type(obj)
        name = getattr(cls, "__name__", "")
        module = getattr(cls, "__module__", "")
    except _HOSTILE_ERRORS:
        return "", ""
    return (
        name if isinstance(name, str) else "",
        module if isinstance(module, str) else "",
    )


def unwrap_chain(tool: object, *, limit: int = MAX_UNWRAP) -> tuple[object, bool]:
    """Follow the _wrapped layers up to limit deep.

    Requirement: Managed Tool Scope. A self-referential, cyclic, deeper-than-limit
    or unreadable chain is not a recognised wrapper, so the caller classifies it
    as unknown instead of deciding on a half-unwrapped object.

    Args:
        tool: One raw element of ProviderRequest.func_tool.
        limit: Deepest chain accepted, MAX_UNWRAP by default.

    Returns:
        (innermost, complete). complete is False when an attribute read raised,
        when the chain is cyclic or self-referential, or when another layer
        still exists at limit.
    """
    current = tool
    seen: set[int] = {id(tool)}
    for _ in range(limit):
        inner = _read(current, UNWRAP_ATTR, _ABSENT)
        if inner is _UNREADABLE:
            return current, False
        if inner is _ABSENT:
            return current, True
        if inner is current or id(inner) in seen:
            return current, False
        seen.add(id(inner))
        current = inner
    deeper = _read(current, UNWRAP_ATTR, _ABSENT)
    if deeper is _UNREADABLE:
        return current, False
    if deeper is not _ABSENT and deeper is not current:
        return current, False
    return current, True


def _looks_like_function_tool(obj: object) -> bool:
    """Report whether obj structurally matches astrbot.api.FunctionTool.

    The shape is read by duck typing only: a mapping parameters, a callable call
    and a string description (astrbot/core/agent/tool.py).

    Args:
        obj: Unwrapped tool candidate.

    Returns:
        True when every public shape clue is present and readable.
    """
    parameters = _read(obj, "parameters", None)
    call = _read(obj, "call", None)
    description = _read(obj, "description", None)
    if parameters is _UNREADABLE or call is _UNREADABLE or description is _UNREADABLE:
        return False
    return (
        isinstance(parameters, Mapping)
        and callable(call)
        and isinstance(description, str)
    )


def classify_wrapper_surface(
    tool: object, *, known_tools: Collection[str] | None = None
) -> str:
    """Classify a tool by the brittle clues above, without importing AstrBot.

    Requirement: Managed Tool Scope. The function only classifies: it never
    strips a tool and never decides a call. The clue order mirrors the
    install-time chokepoint (tooling_guard/interface/install.py:27
    _surface_kind), so an excluded source is recognised before any managed
    shape is considered.

    Args:
        tool: One raw element of ProviderRequest.func_tool.
        known_tools: Optional static catalogue. When supplied, a built-in tool
            must also be listed in it (the KNOWN_TOOLS gate at
            tooling_guard/interface/install.py:77); when omitted, source shape
            alone decides and the caller keeps the catalogue check as its own
            concern.

    Returns:
        One of SURFACE_MARKERS. Never raises: a hostile object (raising
        attribute access, self-referential or oversized _wrapped chain,
        unusable class metadata) and every unrecognised form yield
        SURFACE_UNKNOWN, which surface_is_managed reports as unmanaged.
    """
    inner, complete = unwrap_chain(tool)
    if not complete:
        return SURFACE_UNKNOWN
    name = _read(inner, "name", "")
    if name is _UNREADABLE or not isinstance(name, str) or not name:
        return SURFACE_UNKNOWN
    for attr in MCP_SOURCE_ATTRS:
        marker = _read(inner, attr, None)
        if marker is _UNREADABLE:
            return SURFACE_UNKNOWN
        if marker is not None:
            return SURFACE_MCP
    class_name, module_name = _type_names(inner)
    if class_name == "MCPTool" or "mcp_client" in module_name:
        return SURFACE_MCP
    if name.startswith(HANDOFF_NAME_PREFIX):
        return SURFACE_HANDOFF
    agent = _read(inner, HANDOFF_AGENT_ATTR, None)
    if agent is _UNREADABLE:
        return SURFACE_UNKNOWN
    if agent is not None or class_name == "HandoffTool" or "handoff" in module_name:
        return SURFACE_HANDOFF
    background = _read(inner, BACKGROUND_TASK_ATTR, False)
    if background is _UNREADABLE:
        return SURFACE_UNKNOWN
    if background:
        return SURFACE_BACKGROUND
    if name == FUTURE_TASK_NAME:
        return SURFACE_FUTURE_TASK
    if not _looks_like_function_tool(inner):
        return SURFACE_UNKNOWN
    handler = _read(inner, "handler", None)
    module_path = _read(inner, "handler_module_path", None)
    if handler is _UNREADABLE or module_path is _UNREADABLE:
        return SURFACE_UNKNOWN
    if known_tools is not None and name in known_tools:
        return SURFACE_BUILTIN_STATIC
    if handler is not None and module_path:
        return SURFACE_PLUGIN
    if handler is not None and known_tools is None:
        return SURFACE_BUILTIN_STATIC
    return SURFACE_UNKNOWN


def surface_is_managed(kind: str) -> bool:
    """Report whether a surface marker names a tool the gateway may proxy.

    Args:
        kind: Marker returned by classify_wrapper_surface.

    Returns:
        True for the built-in static catalogue and supported plugin tools.
    """
    return kind in MANAGED_SURFACES


def is_manageable(tool: object, *, known_tools: Collection[str] | None = None) -> bool:
    """Report whether one toolset entry can be proxied safely.

    Args:
        tool: One raw element of ProviderRequest.func_tool.
        known_tools: Optional static catalogue, forwarded to the classifier.

    Returns:
        False for every excluded or unknown surface form (fail-closed).
    """
    return surface_is_managed(classify_wrapper_surface(tool, known_tools=known_tools))
