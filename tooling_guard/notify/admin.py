"""Administrator channel delivery. Requirement: Administrator Channel."""

from __future__ import annotations

import asyncio
import inspect
import math
from collections.abc import Sequence
from typing import Any

#: Default cap of one whole administrator notification, in seconds.
NOTIFY_TIMEOUT_S = 5.0


def notify_timeout_seconds(configured: Any = None) -> float:
    """Return the cap to apply to one whole notification.

    Requirement: Notification Delivery Failure (R9-06). The cap bounds the whole
    fan-out rather than each administrator: a send that hangs hangs the call, and
    the notice must not eat the wait it announces.

    Args:
        configured: Override from the assembly point or a test.

    Returns:
        A positive number of seconds; NOTIFY_TIMEOUT_S for anything unusable.
    """
    if configured is None:
        return NOTIFY_TIMEOUT_S
    try:
        value = float(configured)
    except (TypeError, ValueError):
        return NOTIFY_TIMEOUT_S
    if not math.isfinite(value) or value <= 0:
        return NOTIFY_TIMEOUT_S
    return value


def _logger() -> Any | None:
    """Return the host plugin logger when the public API is importable.

    Returns:
        astrbot.api.logger, the only public AstrBot name this package uses, or
        None when the plugin runs outside the host.
    """
    try:
        from astrbot.api import logger
    except Exception:  # noqa: BLE001 - the module must import without a host
        return None
    return logger


def _targets(admins: Sequence[str]) -> list[str]:
    """Return the usable administrator identifiers, de-duplicated.

    Args:
        admins: Configured administrator identifiers.

    Returns:
        Non-empty, stripped identifiers in configuration order.
    """
    entries = (admins,) if isinstance(admins, str) else tuple(admins or ())
    targets: list[str] = []
    for entry in entries:
        if not isinstance(entry, str):
            continue
        handle = entry.strip()
        if not handle or handle in targets:
            continue
        targets.append(handle)
    return targets


async def notify_admins(
    context: Any,
    admins: Sequence[str],
    message: str,
    *,
    sender: Any = None,
) -> bool:
    """Deliver an already-redacted administrator notification.

    Requirement: Administrator Channel; Notification Delivery Failure.

    AstrBot 4.29.3 public delivery surface, read from source:
        astrbot/api/__init__.py exports only AstrBotConfig,
        BaseFunctionToolExecutor, FunctionTool, ToolSet, agent, html_renderer,
        llm_tool, logger and sp, so no send capability is public there.
        astrbot/api/star/__init__.py:1-7 does export Context, whose
        send_message(session, message_chain) (astrbot/core/star/context.py:655)
        needs a full unified_msg_origin string, matches a platform by
        platform.meta().id == session.platform_name, and returns False when no
        platform matches. The configured administrators are bare
        "platform/admin identifiers" (_conf_schema.json:24), so no session can
        be derived from them.
        astrbot/core/platform/astr_message_event.py:534 defines
        AstrMessageEvent.send(message_chain), which only posts into the live
        event session and needs the event object this helper never owns.
    Conclusion: no reliable public delivery exists for a bare administrator
    identifier, so delivery is injected as sender; without a sender the
    notification is reported as undelivered instead of being dropped silently.

    Args:
        context: Host context, reserved for a future public surface; unused.
        admins: Configured administrator identifiers; blanks, duplicates, and
            non-strings are skipped.
        message: Already-redacted notification body, delivered verbatim.
        sender: Callable[[str, str], Awaitable[bool]] receiving
            (admin_id, message) and returning whether delivery succeeded; a
            plain bool return is tolerated.

    Returns:
        True as soon as one administrator received the message, False when no
        delivery succeeded, including when no sender is injected. A delivery
        failure is never consent and never changes a ticket state.

    Raises:
        asyncio.CancelledError: Propagated unchanged when the caller is
            cancelled, because that is not a delivery failure and the caller
            has to degrade it to canceled_external.
    """
    log = _logger()
    if sender is None:
        if log is not None:
            log.debug(
                "tooling_guard: no administrator sender injected, notification undelivered"
            )
        return False
    targets = _targets(admins)
    if not targets:
        if log is not None:
            log.warning("tooling_guard: no administrator identifier configured")
        return False
    delivered = False
    for handle in targets:
        try:
            outcome = sender(handle, message)
            if inspect.isawaitable(outcome):
                outcome = await outcome
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - one unreachable admin must not block the rest
            outcome = False
        if outcome:
            delivered = True
    if not delivered and log is not None:
        log.warning("tooling_guard: administrator notification could not be delivered")
    return delivered


__all__ = ["notify_admins"]
