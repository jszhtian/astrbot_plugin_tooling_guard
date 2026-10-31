"""AstrBot Tooling Guard plugin entry point.

Requirement: Plugin Skeleton; Hook Delivery and Canary.

This file is the assembly point only: it builds the gateway, injects the
interface-layer capabilities the gateway must not import itself, registers the
request hook and forwards terminate. No decision, path, store or network logic
lives here (ARCHITECTURE.md section 2, duty table).
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, StarTools

from .tooling_guard import __version__, observation, web
from .tooling_guard.interface import hooks, identity
from .tooling_guard.main import Gateway
from .tooling_guard.notify.sender import build_sender, platform_from_admins
from .tooling_guard.store import db as store
from .tooling_guard.ui import commands, reply_approval

#: Directory name under data/plugin_data; renamed with the plugin directory.
PLUGIN_NAME = "astrbot_plugin_tooling_guard"


class ToolingGuard(Star):
    """Register the guard with the host and own the gateway lifecycle."""

    def __init__(self, context: Context, config: dict[str, Any] | None = None) -> None:
        """Assemble the gateway from the validated plugin configuration.

        Args:
            context: Host plugin context.
            config: Raw plugin configuration provided by the host.
        """
        super().__init__(context, config)
        self.gateway = Gateway.from_config(
            config or {},
            data_dir=_data_dir(),
            context=context,
            identity=identity,
            request_hook=self._request_hook,
        )
        for warning in self.gateway.validation.warnings:
            logger.warning(
                "[tooling_guard] gateway disabled: %s (%s)",
                warning.key,
                warning.message,
            )
        config = self.gateway.config
        admins = tuple(getattr(config, "admins", ()) or ())
        self.observer = observation.SideObserver(
            gateway=self.gateway,
            context=context,
            admins=admins,
            # Off suppresses only the private notice: the audit row of a side
            # observation is still written, the call is still not blocked.
            side_notice_enabled=bool(getattr(config, "side_notice_enabled", True)),
            sender=build_sender(
                context,
                platform_id=platform_from_admins(admins),
                inline_reply=bool(getattr(config, "inline_reply", False)),
            ),
        )
        register_api = getattr(context, "register_web_api", None)
        if callable(register_api):
            # The dashboard page is optional: a host without the registration
            # hook, or a rejected route, must not stop the gateway from loading.
            try:
                web.register_web_apis(register_api, PLUGIN_NAME, self.gateway)
            except (AttributeError, TypeError, ValueError) as exc:
                logger.warning("[tooling_guard] web console unavailable: %s", exc)

    def _request_hook(self, event: Any, request: Any) -> Any:
        """Forward one request hook round to the interface layer.

        Requirement: Hook Delivery and Canary. main may not import
        tooling_guard.interface, so this adapter is injected into the gateway.

        Args:
            event: Host message or cron event.
            request: Host ProviderRequest.

        Returns:
            The HookOutcome produced by interface/hooks.on_llm_request.
        """
        return hooks.on_llm_request(event, request, self.gateway)

    @filter.command("toolguard")
    async def toolguard(self, event: AstrMessageEvent) -> AsyncGenerator[Any, None]:
        """Report the gateway state for this session.

        Args:
            event: Host message event.

        Yields:
            One reply describing mode, configuration state and version.
        """
        gateway = self.gateway
        state = "enabled" if gateway.enabled else "disabled"
        yield event.plain_result(
            f"tooling_guard {__version__} · {state} · mode {gateway.mode}"
            f" · judge {gateway.judge_route or 'none'}"
        )

    @filter.command("guard")
    async def guard(self, event: AstrMessageEvent) -> AsyncGenerator[Any, None]:
        """Run one administrative /guard subcommand.

        Requirement: Decision Commands; Operator Introspection.

        Args:
            event: Host message event.

        Yields:
            The single redacted reply produced by the UI layer.
        """
        text = await commands.handle_command(
            event.message_str, self.gateway, event=event
        )
        yield event.plain_result(text)

    @filter.regex(reply_approval.REPLY_APPROVAL_PATTERN)
    async def approve_by_reply(
        self, event: AstrMessageEvent
    ) -> AsyncGenerator[Any, None]:
        """Decide a suspended call when an administrator replies to its notice.

        Requirement: Reply Approval Channel; Approval Channels Are Equivalent. The
        reply is one more way to say what /guard approve and /guard deny say: the
        decision itself runs through the same compare-and-swap, so this handler
        owns no state. A reply that is not a decision for a pending ticket is not
        consumed here at all -- it yields nothing and leaves the event alone, so
        the message still reaches the model.

        Args:
            event: Host message event.

        Yields:
            The single redacted reply produced by the UI layer.
        """
        # handle_reply is synchronous on purpose: it does one sqlite read, one CAS
        # transition and one audit insert, and awaiting a plain string would raise
        # "object str can't be used in 'await' expression".
        text = reply_approval.handle_reply(event.message_str, self.gateway, event=event)
        if text is None:
            return
        yield event.plain_result(text)
        event.stop_event()

    # priority=-1_000_000_000: the host sorts hook handlers by DESCENDING numeric
    # priority (astrbot/core/star/star_handler.py:26, `key=lambda h: -h.extras_configs["priority"]`,
    # default 0 at :21-22), so a SMALLER number runs LATER. The proxy must be
    # installed LAST: `ToolSet.add_tool` (astrbot/core/agent/tool.py:103-108) replaces
    # a same-named active tool in place (`self.tools[i] = tool`), so a plugin
    # running after us at the default priority would silently put its own raw tool
    # back and bypass the gateway. Ties keep registration order (the host sort is
    # stable), which is the only remaining hole and needs this priority to be the
    # smallest one any plugin declares.
    @filter.on_llm_request(priority=-1_000_000_000)
    async def on_llm_request(self, event: AstrMessageEvent, req: Any) -> None:
        """Hand one request round to the gateway, which owns the decision.

        Requirement: Hook Delivery and Canary; Managed Tool Proxy Installation.

        Args:
            event: Host message or cron event.
            req: Host ProviderRequest carrying the toolset to wrap.
        """
        # A disabled gateway is state ② of the pipeline-failure contract: the
        # plugin loaded but its own configuration failed validation. The proxy
        # still has to be installed, because the deny happens per managed call in
        # Gateway._guard (audit row + rate-limited alert); returning early here
        # would leave every managed tool unguarded, which is the silent pass the
        # contract forbids.
        await self.gateway.on_llm_request(event, req)

    @filter.on_agent_done()
    async def on_agent_done(
        self,
        event: AstrMessageEvent,
        run_context: Any = None,
        response: Any = None,
    ) -> None:
        """Void the tickets this finished agent run can no longer approve.

        Requirement: External Cancellation Degradation.

        The host fires OnAgentDoneEvent from
        astrbot/core/astr_agent_hooks.py:23-41 and requires a coroutine handler
        (astrbot/core/pipeline/context_utils.py:115); a sync one would be silently
        skipped. run_context and response belong to the host's call signature
        (astrbot/core/star/register/star_handler.py:507-534) and stay unused: the
        session identity the gateway needs comes from the event alone.

        Args:
            event: Host message event of the run that just ended.
            run_context: Host run context (signature only).
            response: Host LLM response (signature only).
        """
        await self.gateway.on_agent_done(event)

    @filter.on_using_llm_tool()
    async def on_using_llm_tool(
        self,
        event: AstrMessageEvent,
        tool: Any,
        tool_args: dict[str, Any] | None = None,
    ) -> None:
        """Observe one tool call before it executes and file its intent.

        Requirement: Pre-execution Intent Record; Unmanaged Side Sources.

        This hook must be a coroutine function: the host asserts
        `inspect.iscoroutinefunction` on registered handlers
        (astrbot/core/star/context.py) and silently skips a sync one. It must not
        yield either; the observation only audits, alerts, and records intent,
        and never rewrites the arguments or blocks the call.

        Args:
            event: Host message or cron event.
            tool: Host FunctionTool (or managed proxy) about to execute.
            tool_args: Arguments the host will pass to that tool.
        """
        await self.observer.observe(event=event, tool=tool, arguments=tool_args)

    async def terminate(self) -> None:
        """Settle open tickets and close the store on plugin unload.

        Requirement: External Cancellation Degradation.
        """
        await self.gateway.shutdown()


def _data_dir() -> Path | None:
    """Return the plugin data directory, or None when the host refuses one.

    Requirement: Storage Location. Persistent data belongs under the host data
    directory, never inside the plugin directory.  The pre-rename directory is
    moved into place once, so an existing installation keeps its audit store.

    Returns:
        The plugin data directory, or None when it cannot be resolved.
    """
    try:
        path = StarTools.get_data_dir(PLUGIN_NAME)
    except (RuntimeError, ValueError) as exc:
        logger.warning("[tooling_guard] data directory unavailable: %s", exc)
        return None
    note = store.migrate_legacy_data_dir(path)
    if note:
        logger.info("[tooling_guard] %s", note)
    return path
