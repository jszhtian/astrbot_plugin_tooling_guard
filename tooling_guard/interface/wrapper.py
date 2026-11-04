"""Managed tool proxy contract. Requirement: Public Tool Delegation Contract."""

from __future__ import annotations

import contextlib
import inspect
import math
import time
from collections.abc import Mapping
from typing import Any

from astrbot.api import FunctionTool, logger
from astrbot.api.event import CommandResult, MessageChain, MessageEventResult

from . import results

# Decision labels start with one of these prefixes; anything else fails closed.
ALLOW_LABELS = ("allow", "permit", "pass")
DENY_LABELS = ("deny", "reject", "block", "forbid")
SUSPEND_LABELS = ("suspend", "pending", "await", "wait")

# The host raises the tool-call timeout only for a raw ShellSessionTool
# (astrbot/core/astr_agent_tool_exec.py:721-731), and that extension is lost
# behind this proxy. A session call is therefore clamped to the budget the
# gateway can still report, keeping this margin for the host's own bookkeeping.
BUDGET_MARGIN_S: float = 5.0
YIELD_TIME_KEY = "yield_time_ms"
# Sentinel for "the gateway could not answer", so a raise and a real value stay
# distinguishable without a blind except.
_UNKNOWN = object()


def _field(source: Any, name: str, default: Any = None) -> Any:
    """Read one field from a mapping or object gateway result.

    Args:
        source: Gateway outcome, either a mapping or an attribute carrier.
        name: Field name to read.
        default: Value returned when the field is absent.

    Returns:
        The field value, or ``default`` when it is missing.
    """
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def _decision(outcome: Any) -> str:
    """Normalize a gateway decision to ``allow``, ``deny`` or ``suspend``.

    Args:
        outcome: Object returned by the gateway, or ``None`` for "no gateway".

    Returns:
        One of ``allow``, ``deny`` or ``suspend``. Unknown labels and missing
        fields return ``deny`` so a broken gateway can never pass a call.
    """
    if outcome is None:
        return "allow"
    raw = _field(outcome, "decision")
    if raw is None:
        raw = _field(outcome, "allowed")
        if isinstance(raw, bool):
            return "allow" if raw else "deny"
        return "deny"
    if isinstance(raw, bool):
        return "allow" if raw else "deny"
    label = str(getattr(raw, "value", raw)).strip().lower()
    if label.startswith(ALLOW_LABELS):
        return "allow"
    if label.startswith(SUSPEND_LABELS):
        return "suspend"
    if label.startswith(DENY_LABELS):
        return "deny"
    return "deny"


def _schema_arguments(tool: Any, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only the arguments the delegated tool declares.

    Args:
        tool: The tool that will receive the call.
        arguments: Arguments supplied by the runner.

    Returns:
        A new dict filtered by ``tool.parameters["properties"]``; when the schema
        carries no properties mapping the arguments are forwarded unchanged.
    """
    parameters = getattr(tool, "parameters", None)
    properties = (
        parameters.get("properties") if isinstance(parameters, Mapping) else None
    )
    if not isinstance(properties, Mapping):
        return dict(arguments)
    return {key: value for key, value in arguments.items() if key in properties}


def _handler_args(
    handler: Any, event: Any, arguments: Mapping[str, Any]
) -> tuple[Any, ...]:
    """Decide whether a handler wants the event as its first positional argument.

    Args:
        handler: Callable stored on ``FunctionTool.handler``.
        event: Message event taken from the runner context.
        arguments: Already filtered keyword arguments.

    Returns:
        ``(event,)`` for the ``handler(event, **kwargs)`` shape, ``()`` for the
        ``handler(**kwargs)`` shape.
    """
    try:
        parameters = list(inspect.signature(handler).parameters.values())
    except (TypeError, ValueError):
        return (event,)
    for parameter in parameters:
        if parameter.kind in (
            parameter.POSITIONAL_ONLY,
            parameter.POSITIONAL_OR_KEYWORD,
        ):
            return () if parameter.name in arguments else (event,)
        if parameter.kind is parameter.VAR_POSITIONAL:
            return (event,)
        if parameter.kind is parameter.VAR_KEYWORD:
            return ()
    return ()


def _overrides_call(tool: Any) -> bool:
    """Detect a subclass that overrides ``FunctionTool.call``.

    Args:
        tool: Candidate tool object.

    Returns:
        ``True`` when the most derived ``call`` in the MRO is not the base one.
    """
    for base in type(tool).__mro__:
        if "call" in base.__dict__:
            return base.__dict__["call"] is not FunctionTool.call
    return False


def _accepts_context(guard_call: Any) -> bool | None:
    """Report whether a gateway callable can take the context keyword.

    Args:
        guard_call: The gateway's ``guard_call`` bound callable.

    Returns:
        ``True`` when the signature declares a ``context`` parameter or
        accepts arbitrary keywords, ``False`` when it can take neither, and
        ``None`` when the signature cannot be read at all (a builtin or C
        callable), where the caller falls back to a ``TypeError`` retry.
    """
    try:
        signature = inspect.signature(guard_call)
    except (TypeError, ValueError):
        return None
    parameter = signature.parameters.get("context")
    if parameter is not None:
        return parameter.kind is not inspect.Parameter.POSITIONAL_ONLY
    for candidate in signature.parameters.values():
        if candidate.kind is inspect.Parameter.VAR_KEYWORD:
            return True
    return False


def _open_call_scope(gateway: Any) -> Any:
    """Open the gateway's deadline scope for this one call, never raising.

    Requirement: Delegation Fidelity (R9-01). The gateway publishes the deadline
    of a call while it decides, but the proxy asks for the budget only after the
    verdict and before delegating; a scope the gateway opens inside `guard_call`
    is gone by then. The proxy therefore owns the scope and closes it after the
    delegation. Duck-typed like `_remaining_seconds`, so a gateway without the
    hook (or a double in a test) keeps working.

    Args:
        gateway: Attached gateway, or `None`.

    Returns:
        The token to hand back to `_close_call_scope`, or `None`.
    """
    opener = getattr(gateway, "begin_call_scope", None)
    if not callable(opener):
        return None
    with contextlib.suppress(Exception):
        return opener()
    return None


def _close_call_scope(gateway: Any, token: Any) -> None:
    """Close the call scope the proxy opened, never raising.

    Args:
        gateway: Attached gateway, or `None`.
        token: Token returned by `_open_call_scope`; `None` is a no-op.
    """
    if token is None:
        return
    closer = getattr(gateway, "end_call_scope", None)
    if not callable(closer):
        return
    with contextlib.suppress(Exception):
        closer(token)


def _remaining_seconds(gateway: Any, context: Any) -> float | None:
    """Read the gateway's remaining budget for this call, never raising.

    The method is duck-typed on purpose: `remaining_seconds(context: Any = None)
    -> float | None` lives on the gateway, and `tooling_guard.main` is never
    imported here. A missing method, a non-numeric answer and an exception all
    mean "unknown", which leaves the call untouched.

    Args:
        gateway: Attached gateway, or `None`.
        context: Runner context wrapper of this invocation.

    Returns:
        Seconds left toward this call's deadline, or `None` when the gateway does
        not expose the method or returns something unusable.
    """
    remaining = getattr(gateway, "remaining_seconds", None)
    if not callable(remaining):
        return None
    value: Any = _UNKNOWN
    with contextlib.suppress(Exception):
        value = remaining(context)
    if value is _UNKNOWN:
        with contextlib.suppress(Exception):
            value = remaining()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _clamp_yield_time(arguments: dict[str, Any], remaining: float | None) -> bool:
    """Clamp `yield_time_ms` to the budget this call still has.

    The host raises the tool-call timeout only when it sees a raw
    `ShellSessionTool` polling or writing (astrbot/core/astr_agent_tool_exec.py:721-731).
    Behind this proxy it sees a plain `FunctionTool`, so that extension is lost
    and a long `yield_time_ms` would hit the shorter generic timeout. The host
    bound is reproduced here before delegating:

        yield_time_ms = max(0, int(min(yield_time_ms, (remaining - 5) * 1000)))

    Args:
        arguments: Filtered call arguments, updated in place.
        remaining: Seconds left before this call's deadline, or `None` when the
            gateway cannot report it, in which case nothing is changed.

    Returns:
        `True` when a value was clamped. `False` covers both a call with no poll
        argument and a call with no budget: an unbounded poll is exactly the
        symptom this clamp exists for, so the missing budget is reported instead
        of vanishing into a silent early return.
    """
    if YIELD_TIME_KEY not in arguments:
        return False
    requested = arguments[YIELD_TIME_KEY]
    if isinstance(requested, bool) or not isinstance(requested, int):
        return False
    if remaining is None:
        logger.info(
            "yield_time_ms=%s left unclamped: this call reports no remaining budget",
            requested,
        )
        return False
    arguments[YIELD_TIME_KEY] = max(
        0, int(min(float(requested), (remaining - BUDGET_MARGIN_S) * 1000))
    )
    return True


def _is_event_result(value: Any) -> bool:
    """Report whether a value is a host event result rather than a tool result.

    Args:
        value: One item produced by a delegated handler.

    Returns:
        `True` for `MessageEventResult` and `CommandResult`.
    """
    return isinstance(value, (MessageEventResult, CommandResult))


async def _emit_result(value: Any, event: Any) -> bool:
    """Forward one event result to the user the way the host does.

    The host stores every event result an async generator yields on the event and
    immediately sends its chain as a `tool_direct_result` message
    (astrbot/core/astr_agent_tool_exec.py:755-773). A proxy returns a single
    value, so each result is forwarded as it arrives instead of being lost
    behind the last one.

    Args:
        value: Yielded `MessageEventResult` or `CommandResult`.
        event: Host message event of this call, or `None` outside a host round.

    Returns:
        `True` when the chain was handed to the event and leaves the proxy
        alone, `False` when the result has to travel back as the return value.
    """
    chain = getattr(value, "chain", None)
    send = getattr(event, "send", None)
    if not chain or not callable(send):
        return False
    sent = False
    with contextlib.suppress(Exception):
        await send(MessageChain(chain=chain, type="tool_direct_result"))
        sent = True
    if not sent:
        logger.error("[tooling_guard] 直接结果转发失败，改为随调用结果返回")
    return sent


async def _forward(value: Any, event: Any) -> Any:
    """Forward a delegated result with the host's own result semantics.

    The host consumes a generator handler item by item
    (astrbot/core/astr_agent_tool_exec.py:860-878): each `MessageEventResult` is
    put on the event and sent, and every other item becomes the tool result. The
    proxy returns one value, so event results are forwarded as they arrive and
    the last plain value is returned. A generator that yields only event results
    returns `None`, which is also what the host sees for it.

    Args:
        value: Raw result of a delegated handler, call or run.
        event: Host message event of this call, or `None`.

    Returns:
        The last non-event item of an async generator, the awaited value, or
        `value` itself when nothing has to be consumed.
    """
    if inspect.isasyncgen(value):
        last: Any = None
        async for item in value:
            if _is_event_result(item):
                if not await _emit_result(item, event):
                    last = item
                continue
            last = item
        return last
    if inspect.isawaitable(value):
        value = await value
    if _is_event_result(value) and await _emit_result(value, event):
        return None
    return value


def _report_result(
    gateway: Any,
    outcome: Any,
    *,
    ok: bool,
    error: str | None,
    elapsed: float,
) -> None:
    """Tell the gateway how the call it released actually ended.

    Requirement: Ticket Lifecycle (a consumed ticket ends in completed or not at
    all). The gateway cannot know this: it writes its decision before the tool
    runs and hands execution over on purpose. Only the proxy sees the return
    value or the exception, so the closing bookkeeping happens here. A gateway
    without the hook (or an older one) is simply not informed, and a failing
    hook never turns a completed tool call into an error.

    Args:
        gateway: Gateway that decided this call.
        outcome: The allow outcome carrying the ticket id, when there is one.
        ok: True when the delegated tool returned without raising.
        error: Exception class name when it raised, else None.
        elapsed: Wall time the delegated tool took, in seconds.
    """
    if gateway is None or outcome is None:
        return
    hook = getattr(gateway, "note_call_result", None)
    if not callable(hook):
        return
    try:
        hook(outcome, ok=ok, error=error, elapsed=elapsed)
    except Exception:  # noqa: BLE001 - bookkeeping must not break the call
        pass


class ManagedToolProxy(FunctionTool):
    """Public FunctionTool adapter; no policy or execution is implemented."""

    def __init__(self, inner: Any, gateway: Any = None) -> None:
        """Initialize the proxy with a tool schema and gateway reference.

        Requirement: Proxy Metadata Preservation.

        Args:
            inner: Toolset entry to manage. When the host already wrapped it, the
                wrapper itself is delegated to, so the native permission check
                still runs before execution.
            gateway: Gateway deciding each call; ``None`` delegates without
                deciding and exists only for harnesses and tests.
        """
        super().__init__(
            name=inner.name,
            description=inner.description,
            parameters=inner.parameters,
            handler=None,
            handler_module_path=getattr(inner, "handler_module_path", None),
            active=getattr(inner, "active", True),
        )
        # Delegation target; deliberately not the host wrapper attribute name.
        self._inner_tool = inner
        self._gateway = gateway
        self._guard_proxy = True

    def __repr__(self) -> str:
        """Identify the proxy for audit output. Requirement: Single Wrap Per Call."""
        return (
            f"ManagedToolProxy(name={self.name!r}, "
            f"inner={type(self._inner_tool).__name__})"
        )

    async def call(self, context: Any, **kwargs: Any) -> Any:
        """Route one invocation to Gateway before delegating.

        Requirement: Delegation Precedes Execution.

        Args:
            context: Runner context wrapper; ``context.context.event`` is passed to
                handlers that take the event positionally.
            **kwargs: Arguments the runner already filtered against this schema.

        Returns:
            A denial result, a non-empty suspension string, or whatever the
            delegated tool returns. No decision path returns ``None``.

        Raises:
            Exception: Whatever the delegated tool raised; the host reports it as
                a tool error (tool_loop_agent_runner.py:1410-1420).
        """
        scope = _open_call_scope(self._gateway)
        try:
            return await self._run_call(context, kwargs)
        finally:
            _close_call_scope(self._gateway, scope)

    async def _run_call(self, context: Any, arguments: dict[str, Any]) -> Any:
        """Decide and delegate one call inside the scope its proxy opened.

        Requirement: Delegation Precedes Execution; Delegation Fidelity.

        Args:
            context: Runner context wrapper of this invocation.
            arguments: Arguments the runner already filtered against this schema.

        Returns:
            The delegation result or the rendered outcome; never `None`.
        """
        kwargs = arguments
        try:
            outcome = await self._decide(context, kwargs)
        except Exception as exc:  # noqa: BLE001 - a broken gateway must not pass.
            return results.denial_result(
                f"网关判定失败，按拦截处理（{type(exc).__name__}: {exc}）"
            )
        decision = _decision(outcome)
        if decision == "allow":
            started = time.monotonic()
            try:
                value = await self._delegate(context, kwargs)
            except BaseException as exc:  # noqa: BLE001 - re-raised unchanged
                _report_result(
                    self._gateway,
                    outcome,
                    ok=False,
                    error=type(exc).__name__,
                    elapsed=time.monotonic() - started,
                )
                raise
            _report_result(
                self._gateway,
                outcome,
                ok=True,
                error=None,
                elapsed=time.monotonic() - started,
            )
            return value
        provided = _field(outcome, "result")
        if provided is not None:
            return provided
        if decision == "suspend":
            text = _field(outcome, "text")
            if isinstance(text, str) and text.strip():
                return text
            ticket_id = str(_field(outcome, "ticket_id", "") or "")
            state = str(_field(outcome, "state", "") or "pending")
            return results.suspension_text(ticket_id, state)
        reason = _field(outcome, "text") or _field(outcome, "reason")
        if not reason:
            reason = f"网关决策 {_field(outcome, 'decision')!r} 未放行"
        return results.denial_result(str(reason))

    async def _decide(self, context: Any, arguments: dict[str, Any]) -> Any:
        """Ask the gateway to decide one call before anything executes.

        The runner context travels with the call, so the gateway derives the
        requester and session from *this* invocation instead of the last
        request it happened to observe; without it two concurrent sessions can
        inherit each other's identity and verdict.

        A gateway written against the older keyword set must never turn the
        tool call into an error, so the context keyword is only sent when the
        gateway can take it: the signature is inspected first, and when that is
        inconclusive (a builtin or C callable) a ``TypeError`` retries the
        call once without the keyword.

        Args:
            context: Runner context wrapper for this invocation.
            arguments: Raw call arguments, before schema filtering.

        Returns:
            The gateway outcome, or ``None`` when no gateway is attached.
        """
        gateway = self._gateway
        if gateway is None:
            return None
        guard_call = getattr(gateway, "guard_call", None)
        if callable(guard_call):
            kwargs: dict[str, Any] = {
                "inner": self._inner_tool,
                "tool_name": self.name,
                "args": arguments,
            }
            if _accepts_context(guard_call) is False:
                return await guard_call(**kwargs)
            try:
                return await guard_call(**kwargs, context=context)
            except TypeError:
                if _accepts_context(guard_call) is True:
                    raise
                return await guard_call(**kwargs)
        return await gateway.handle_call(
            self._inner_tool, dict(arguments), context=context
        )

    async def _delegate(self, context: Any, arguments: dict[str, Any]) -> Any:
        """Run the wrapped tool exactly once through a supported branch.

        Requirement: Public Tool Delegation Contract; Delegation Fidelity.

        The ship-time budget is applied first: a proxied session call is clamped
        to the time this call still has, because the host only extends the timeout
        for a raw `ShellSessionTool`.

        A failure inside the delegated tool is raised, not converted. The host
        turns it into a model-visible `error: ...` tool result and logs the
        traceback (astrbot/core/agent/runners/tool_loop_agent_runner.py:1410-1420);
        a denial result here would report a policy block that never happened.

        Args:
            context: Runner context wrapper.
            arguments: Raw call arguments.

        Returns:
            The delegated result, or a denial result when no branch is available
            or the native permission check refuses the call.

        Raises:
            Exception: Whatever the delegated tool raised.
        """
        inner = self._inner_tool
        filtered = _schema_arguments(inner, arguments)
        _clamp_yield_time(filtered, _remaining_seconds(self._gateway, context))
        event = getattr(getattr(context, "context", None), "event", None)
        try:
            handler = getattr(inner, "handler", None)
            if handler is not None:
                return await _forward(
                    handler(*_handler_args(handler, event, filtered), **filtered), event
                )
            if _overrides_call(inner):
                return await _forward(inner.call(context, **filtered), event)
            run = getattr(inner, "run", None)
            if callable(run):
                return await _forward(run(event, **filtered), event)
        except PermissionError as exc:
            return results.denial_result(f"原生权限检查拒绝本次调用（{exc}）")
        return results.denial_result(
            "该工具没有可用的委派入口（handler、call 覆写与 run 均不可用）"
        )
