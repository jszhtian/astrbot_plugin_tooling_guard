"""Administrator notification delivery over the public AstrBot surface.

Requirement: Administrator Channel; Notification Delivery Failure.

Delivery evidence (AstrBot 4.29.3):
    astrbot/api/star/__init__.py:1-7 re-exports Context, whose
    astrbot/core/star/context.py:655 provides
    "async def send_message(session, message_chain) -> bool"; it delivers to any
    full unified message origin and returns False when no platform matches.
    astrbot/api/event/__init__.py:1-17 exports MessageChain and
    astrbot/api/message_components.py:1 exports Plain.
    astrbot/api/__init__.py:1-83 exposes no platform-level send, and the only
    event-scoped sender is astrbot/core/platform/astr_message_event.py:534
    "async def send(message_chain) -> None", which needs a live event and can
    only reach its own conversation. Therefore a private unified message origin
    is built here and the event path is offered as an inline fallback only.

    AstrBot is imported lazily, exactly like tooling_guard/store/db.py:230 (the
    function-body ``from astrbot.api.star import StarTools`` in
    ``_host_accessor``), so this package stays importable and testable without a
    running host.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable, Iterable, Mapping
from typing import Any

FRIEND_MESSAGE = "FriendMessage"
"""Private chat type. Evidence: astrbot/core/platform/message_type.py:6 defines
MessageType.FRIEND_MESSAGE = "FriendMessage"; the literal is inlined because this
package must never import the private astrbot core namespace."""

GROUP_MESSAGE = "GroupMessage"
"""Group chat type. Evidence: astrbot/core/platform/message_type.py:4-5."""

_KNOWN_MESSAGE_TYPES = frozenset({FRIEND_MESSAGE, GROUP_MESSAGE})
"""Message types recognised inside a configured unified message origin."""

INLINE_COPY_PREFIX = "以下为同一条告警的副本（私信投递失败，改在此会话原地回复）："
"""Header the inline fallback puts in front of the copy it posts in place."""

ATTEMPT_NO_TARGET = "no_platform"
"""No private origin could be built: the id names no platform and none is known."""

ATTEMPT_REJECTED = "rejected"
"""The host answered a private send with a falsy result."""

ATTEMPT_RAISED = "raised"
"""The private send raised before answering."""

ATTEMPT_PRIVATE = "private"
"""The host accepted a private send. It does not prove the account exists."""

ATTEMPT_INLINE = "inline"
"""Delivery fell back to the triggering conversation."""

EPHEMERAL_PLATFORMS: frozenset[str] = frozenset({"webchat"})
"""Platform ids that are panel sessions, not chat accounts.

Requirement: Administrator Channel. AstrBot's built-in web chat addresses a
browser tab ("webchat:FriendMessage:webchat!name!uuid"), so a bare administrator
id prefixed with it names a conversation nobody is signed into. The host still
answers True for it (verified: a fabricated origin came back ok), so treating
that answer as delivery is how a notice disappears without a trace. Reads that
do not go through the panel are chat accounts and are tried normally.
"""

ATTEMPT_EPHEMERAL = "ephemeral"
"""The host accepted a send to a panel channel no chat account is signed into."""


def _logger() -> Any:
    """Return the public host logger, or None outside AstrBot.

    Returns:
        The astrbot.api logger object, or None.
    """
    try:
        from astrbot.api import logger
    except Exception:  # noqa: BLE001 - importing must work without a host
        return None
    return logger


def _debug(log: Any, template: str, *args: Any) -> None:
    """Emit a debug record when a host logger is available.

    Args:
        log: Logger from _logger(), possibly None.
        template: Percent-style message template.
        *args: Template arguments.
    """
    if log is None:
        return
    try:
        log.debug(template, *args)
    except Exception:  # noqa: BLE001 - logging must never break delivery
        return


def _warn(log: Any, template: str, *args: Any) -> None:
    """Emit a warning record when a host logger is available.

    Args:
        log: Logger from _logger(), possibly None.
        template: Percent-style message template.
        *args: Template arguments.
    """
    if log is None:
        return
    try:
        log.warning(template, *args)
    except Exception:  # noqa: BLE001 - logging must never break delivery
        return


def _clean(value: Any) -> str:
    """Return a stripped string form of one session field.

    Args:
        value: Field of a configured identifier, possibly None.

    Returns:
        The stripped text, or "" for a missing value.
    """
    if value is None:
        return ""
    try:
        return str(value).strip()
    except Exception:  # noqa: BLE001 - a hostile __str__ yields no session
        return ""


def _build_chain(message: str) -> Any:
    """Wrap redacted notification text into a single-plain-text message chain.

    Args:
        message: Already-redacted notification body.

    Returns:
        A MessageChain when the public surface is importable, else the raw text.
    """
    try:
        from astrbot.api.event import MessageChain
        from astrbot.api.message_components import Plain
    except Exception:  # noqa: BLE001 - importing must work without a host
        return message
    try:
        return MessageChain([Plain(message)])
    except Exception:  # noqa: BLE001 - an unbuildable chain is not fatal
        return message


async def _resolve(value: Any) -> Any:
    """Await the value when it is awaitable, else return it unchanged.

    Args:
        value: Result of a delivery call, sync or async.

    Returns:
        The resolved value.
    """
    if inspect.isawaitable(value):
        return await value
    return value


def private_session(admin: str, *, platform_id: str = "") -> str:
    """Resolve one configured administrator identifier into a private-chat umo.

    Requirement: Administrator Channel.

    Args:
        admin: One entry of GatewayConfig.admins: a full unified message origin
            ("platform:FriendMessage:123"), a "platform:123" pair, or a bare
            "123" that needs platform_id.
        platform_id: Default platform for entries that carry none.

    Returns:
        A "platform:FriendMessage:sender" origin, or "" when the entry cannot be
        resolved. Never raises.
    """
    try:
        text = "" if admin is None else str(admin).strip()
    except Exception:  # noqa: BLE001 - a hostile __str__ must not break delivery
        return ""
    if not text:
        return ""
    parts = text.split(":")
    if len(parts) == 1:
        platform = _clean(platform_id)
        return f"{platform}:{FRIEND_MESSAGE}:{text}" if platform else ""
    if len(parts) == 2:
        platform, admin_id = _clean(parts[0]), _clean(parts[1])
        if not platform or not admin_id:
            return ""
        return f"{platform}:{FRIEND_MESSAGE}:{admin_id}"
    if _clean(parts[1]) not in _KNOWN_MESSAGE_TYPES:
        return ""
    if any(not _clean(part) for part in parts):
        return ""
    return f"{_clean(parts[0])}:{_clean(parts[1])}:{':'.join(parts[2:])}"


def platform_from_admins(admins: Any) -> str:
    """Return the single platform the configured administrator ids name.

    Requirement: Administrator Channel.  A bare administrator id ("123") has no
    platform of its own, so delivery needs a default.  Only an unambiguous answer
    is usable: zero or several named platforms return "" and the caller must not
    guess, which keeps a multi-platform deployment from delivering to the wrong
    bot.

    Args:
        admins: Configured administrator entries, in any form private_session
            accepts ("platform:FriendMessage:123", "platform:123", "123").

    Returns:
        The one platform id every platform-carrying entry agrees on, or "".
    """
    platforms: set[str] = set()
    entries = admins if isinstance(admins, (list, tuple)) else ()
    for entry in entries:
        if not isinstance(entry, str):
            continue
        parts = entry.strip().split(":")
        platform = _clean(parts[0]) if len(parts) >= 2 else ""
        if platform:
            platforms.add(platform)
    return platforms.pop() if len(platforms) == 1 else ""


def is_ephemeral_platform(platform_id: Any) -> bool:
    """Return whether one platform id names a panel session, not a chat account.

    Requirement: Administrator Channel.

    Args:
        platform_id: Platform id of a unified message origin, possibly None.

    Returns:
        True when the id is in EPHEMERAL_PLATFORMS.
    """
    return _clean(platform_id).lower() in EPHEMERAL_PLATFORMS


def host_platforms(context: Any) -> tuple[str, ...]:
    """Return the platform ids the running host actually has, in host order.

    Requirement: Administrator Channel. A bare administrator id ("123") carries
    no platform, and the platform of the triggering event is only usable when the
    call came from a real chat account -- a call made from the web panel carries
    "webchat", which is a browser tab. The host knows which bots are running, so
    its own list is the fallback: astrbot/core/platform/manager.py keeps the
    instances, and each exposes meta().id. Nothing here imports the private
    astrbot namespace: every step is an attribute probe, so a host that answers
    nothing simply yields no candidates.

    Args:
        context: AstrBot Context, either the host object or a request scope.

    Returns:
        Distinct platform ids, in the order the host lists them; empty when the
        host exposes none.
    """
    manager = getattr(context, "platform_manager", None)
    if manager is None:
        return ()
    found: Any = None
    getter = getattr(manager, "get_insts", None)
    if callable(getter):
        try:
            found = getter()
        except Exception:  # noqa: BLE001 - a probe must not break delivery
            found = None
    if not isinstance(found, (list, tuple)):
        for name in ("platform_insts", "platforms", "instances"):
            value = getattr(manager, name, None)
            if isinstance(value, (list, tuple)):
                found = value
                break
    if not isinstance(found, (list, tuple)):
        return ()
    out: list[str] = []
    for instance in found:
        meta = getattr(instance, "meta", None)
        if callable(meta):
            try:
                meta = meta()
            except Exception:  # noqa: BLE001 - a probe must not break delivery
                meta = None
        platform_id = getattr(meta, "id", None)
        if platform_id is None and isinstance(meta, Mapping):
            platform_id = meta.get("id")
        cleaned = _clean(platform_id)
        if cleaned and cleaned not in out:
            out.append(cleaned)
    return tuple(out)


def delivery_platforms(context: Any, *, platform_id: str = "") -> tuple[str, ...]:
    """Return the platforms to try for an administrator entry that names none.

    Requirement: Administrator Channel. The triggering platform comes first when
    it is a chat account, because that is the bot the administrator was talking to
    minutes ago; the rest of the host's running platforms follow, so a notice
    raised from the web panel still reaches the QQ account. Panel platforms are
    never candidates: the host accepts sends to them, which would report success
    with nobody at the other end.

    Args:
        context: AstrBot Context.
        platform_id: Platform of the triggering event, possibly a panel one.

    Returns:
        Distinct platform ids to attempt, best first; empty when none is usable.
    """
    ordered: list[str] = []
    hint = _clean(platform_id)
    if hint and not is_ephemeral_platform(hint):
        ordered.append(hint)
    for candidate in host_platforms(context):
        if candidate in ordered or is_ephemeral_platform(candidate):
            continue
        ordered.append(candidate)
    return tuple(ordered)


def admin_sessions(
    admin: str, *, context: Any, platform_id: str = ""
) -> tuple[str, ...]:
    """Return the private origins one administrator entry may be reached at.

    Requirement: Administrator Channel. An entry that carries its own platform
    ("platform:FriendMessage:123" or "platform:123") is honoured exactly and never
    guessed at a second time; only a bare id is expanded across the platforms the
    host runs.

    Args:
        admin: Configured administrator entry.
        context: AstrBot Context.
        platform_id: Platform of the triggering event.

    Returns:
        Distinct private origins to attempt, best first; empty when none resolve.
    """
    explicit = private_session(admin, platform_id="")
    if explicit:
        return (explicit,)
    out: list[str] = []
    for candidate in delivery_platforms(context, platform_id=platform_id):
        origin = private_session(admin, platform_id=candidate)
        if origin and origin not in out:
            out.append(origin)
    return tuple(out)


def is_admin_subject(subject: str, entries: Iterable[str]) -> bool:
    """Report whether an identity is named by the configured admins entries.

    Requirement: Approver Authorization; OneBot v11 Compatibility.  This is the
    only copy of the matching rule: ui/commands.py's _listed_admin (the command
    face) and tooling_guard/main.py's suspension eligibility both call it, so a
    configured entry can never be an administrator on one path and a stranger on
    the other.  Two shapes name an administrator, because policy/config.py
    accepts both:

    * a platform-qualified entry, either "platform:123" or the unified origin
      "platform:FriendMessage:123" -- matched by platform_id (first segment) and
      sender_id (last segment), so a middle message-type segment is ignored;
    * a bare "123" -- matched against the sender_id alone, i.e. on every
      platform.  The bare form is therefore wider than the operator may expect:
      the same sender_id on any platform is named.  policy/config.py reports
      every such entry as the non-fatal advisory "bare_admin_entry".

    An entry whose colon-separated form has an empty segment ("platform:" /
    ":123") names nobody and is skipped; an identity without both a platform and
    a sender names nobody either.  Comparison is on stripped lowercase text, so
    case never decides membership.

    Args:
        subject: Identity in "platform_id:sender_id" form (the audit
            subject_key, e.g. "aiocqhttp:123").
        entries: Configured administrator entries, in any of the shapes above.

    Returns:
        True when the identity is explicitly listed.  Never raises: a missing or
        unreadable list names nobody.
    """
    target = _clean(subject).lower()
    platform, _, sender = target.partition(":")
    if not platform or not sender:
        return False
    try:
        candidates = tuple(entries or ())
    except TypeError:  # a non-iterable admins value names nobody
        return False
    for entry in candidates:
        candidate = _clean(entry).lower()
        if not candidate:
            continue
        if candidate == target:
            return True
        segments = candidate.split(":")
        if any(not part for part in segments):
            continue
        if len(segments) == 1:
            if segments[0] == sender:
                return True
            continue
        if segments[0] == platform and segments[-1] == sender:
            return True
    return False


def build_sender(
    context: Any,
    *,
    platform_id: str = "",
    event: Any = None,
    inline_reply: bool = False,
) -> Callable[[str, str], Awaitable[bool]]:
    """Build the sender that notify_admins accepts through its sender argument.

    Requirement: Administrator Channel; Notification Delivery Failure.

    Args:
        context: AstrBot Context providing send_message(session, chain).
        platform_id: Platform of the triggering event, used as the first candidate
            for admins configured without one. It is a candidate, not an answer:
            a call made from the web panel carries the panel platform, which
            reaches no chat account, so the rest of the host's running platforms
            are tried after it and a panel platform is never used for a bare id.
        event: Triggering message event, used only by the inline fallback.
        inline_reply: Whether a failed private delivery may fall back to the
            trigger conversation.  Defaults to False, so a notice only ever goes
            out as a private message unless the administrator opted in; a
            fallback always posts the same redacted text, headed by
            INLINE_COPY_PREFIX so nobody mistakes it for new information.

    Returns:
        An async callable taking the administrator identifier and the
        already-redacted message; it returns True only when a chat account
        accepted it (see EPHEMERAL_PLATFORMS), and the origins it tried are stored
        on send.attempts for delivery_attempts().
    """

    attempts: list[dict[str, Any]] = []
    """One entry per private origin this sender tried, in order.

    Requirement: Notification Delivery Failure (R10-02). AstrBot's
    Context.send_message answers True for a unified message origin nobody is
    listening on -- a fabricated webchat:FriendMessage:123 came back ok -- so the
    boolean is evidence that the host accepted the call, not that an account
    received anything. Recording the origins and the host's answer is what the
    audit row can prove afterwards: the address, and whether the host refused it.
    """

    async def send(admin: str, message: str) -> bool:
        """Deliver one already-redacted notification.

        Args:
            admin: Configured administrator identifier.
            message: Redacted notification body.

        Returns:
            True when a private message or the inline fallback was delivered.
        """
        log = _logger()
        sessions = admin_sessions(admin, context=context, platform_id=platform_id)
        if not sessions:
            _warn(
                log,
                "administrator id %r names no deliverable chat platform (triggering"
                " platform %r is a panel session and the host runs no other); this"
                " notice was not delivered",
                admin,
                _clean(platform_id),
            )
            attempts.append(
                {"admin": _clean(admin), "target": "", "result": ATTEMPT_NO_TARGET}
            )
        for session in sessions:
            try:
                delivered = await _resolve(
                    context.send_message(session, _build_chain(message))
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - delivery failure is not consent
                _debug(log, "private delivery failed for %s: %r", session, exc)
                attempts.append(
                    {
                        "admin": _clean(admin),
                        "target": session,
                        "result": ATTEMPT_RAISED,
                        "error": type(exc).__name__,
                    }
                )
                continue
            if delivered and is_ephemeral_platform(session.split(":", 1)[0]):
                _debug(log, "private origin %s is a panel session", session)
                attempts.append(
                    {
                        "admin": _clean(admin),
                        "target": session,
                        "result": ATTEMPT_EPHEMERAL,
                    }
                )
                continue
            if delivered:
                attempts.append(
                    {
                        "admin": _clean(admin),
                        "target": session,
                        "result": ATTEMPT_PRIVATE,
                    }
                )
                return True
            _debug(log, "private delivery rejected for %s", session)
            attempts.append(
                {
                    "admin": _clean(admin),
                    "target": session,
                    "result": ATTEMPT_REJECTED,
                }
            )
        if inline_reply and event is not None:
            try:
                await _resolve(
                    event.send(_build_chain(f"{INLINE_COPY_PREFIX}\n{message}"))
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - delivery failure is not consent
                _debug(log, "inline delivery failed: %r", exc)
                attempts.append(
                    {
                        "admin": _clean(admin),
                        "target": "",
                        "result": ATTEMPT_RAISED,
                        "error": type(exc).__name__,
                    }
                )
                return False
            attempts.append(
                {"admin": _clean(admin), "target": "", "result": ATTEMPT_INLINE}
            )
            return True
        return False

    send.attempts = attempts  # type: ignore[attr-defined]
    return send


def delivery_attempts(sender: Any) -> tuple[Mapping[str, Any], ...]:
    """Return the private origins one sender tried, in order.

    Requirement: Administrator Channel; Notification Delivery Failure. The audit
    row names the address the notice was actually sent to, so a missing private
    message can be traced to an address instead of being reported as delivered.

    Args:
        sender: The callable build_sender returned, or anything else.

    Returns:
        The attempt records, or an empty tuple when the sender kept none.
    """
    raw = getattr(sender, "attempts", ())
    if not isinstance(raw, (list, tuple)):
        return ()
    out: list[Mapping[str, Any]] = []
    for item in raw:
        if isinstance(item, Mapping):
            out.append(item)
    return tuple(out)
