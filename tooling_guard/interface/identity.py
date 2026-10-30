"""Identity normalization contract. Requirement: Requester Allowlist and Denylist."""

from typing import Any


def _accessor_text(event: Any, accessor: str) -> str:
    """Call one platform-neutral event accessor and normalize it to text.

    Args:
        event: An AstrBot event from any platform adapter.
        accessor: Public accessor name, for example ``get_platform_id``.

    Returns:
        The accessor result when it is a string, else ``""``. A missing accessor or
        an accessor that raises also yields ``""``, so callers stay fail-closed.
    """
    try:
        value = getattr(event, accessor)()
    except Exception:  # noqa: BLE001 - tolerant read across platform adapters.
        return ""
    return value if isinstance(value, str) else ""


def subject_key(event: Any) -> str:
    """Return platform_id:sender_id for an AstrBot event.

    Requirement: Requester Allowlist and Denylist.

    Args:
        event: An AstrBot event from any platform adapter.

    Returns:
        ``"{platform_id}:{sender_id}"``, or ``""`` when either lookup fails: the
        caller then fails closed instead of creating a ticket for an unknown
        subject.
    """
    platform_id = _accessor_text(event, "get_platform_id")
    sender_id = _accessor_text(event, "get_sender_id")
    if not platform_id or not sender_id:
        return ""
    return f"{platform_id}:{sender_id}"


def session_key(event: Any) -> str:
    """Return a minimized stable session key. Requirement: Ticket Persistence.

    Group events must carry the group id, so two senders in one group and the
    same sender in two groups never share a suspension ticket.

    Args:
        event: An AstrBot event from any platform adapter.

    Returns:
        ``event.unified_msg_origin`` when available, else
        ``"{platform_id}:{sender_id}"``, extended with the group id when the
        event belongs to a group. Empty only when nothing is readable.
    """
    try:
        origin = getattr(event, "unified_msg_origin", "")
    except Exception:  # noqa: BLE001 - tolerant read across platform adapters.
        origin = ""
    key = origin if isinstance(origin, str) else ""
    if not key:
        platform_id = _accessor_text(event, "get_platform_id")
        sender_id = _accessor_text(event, "get_sender_id")
        if platform_id and sender_id:
            key = f"{platform_id}:{sender_id}"
    group_id = _accessor_text(event, "get_group_id")
    if group_id and group_id not in key.split(":"):
        key = f"{key}:{group_id}" if key else group_id
    return key


def is_cron_event(event: Any) -> bool:
    """Identify cron-originated events. Requirement: Coverage Boundary Disclosure.

    This is a bypass observation used for coverage disclosure only, never an
    interception gate: cron and background wake-ups cannot be covered by the
    ``OnLLMRequestEvent`` hook, so the gateway reports them instead of blocking
    them. Detection stays name based (module path or class name) to avoid a deep
    AstrBot import from the interface layer.

    Args:
        event: An AstrBot event from any platform adapter.

    Returns:
        ``True`` when the event class looks cron-originated.
    """
    try:
        event_type = type(event)
        module = getattr(event_type, "__module__", "")
        name = getattr(event_type, "__name__", "")
    except Exception:  # noqa: BLE001 - observation only; never block a call.
        return False
    module_text = module if isinstance(module, str) else ""
    name_text = name if isinstance(name, str) else ""
    return "cron" in module_text.lower() or "Cron" in name_text
