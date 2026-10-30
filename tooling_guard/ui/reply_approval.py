"""Approve or deny a suspended call by replying to its notice.

Requirement: Approval Channels Are Equivalent (openspec admin-approval:156-172)
and Reply Approval Channel. A private-chat administrator answers the suspension
notice with 同意 / 批准 / approve, or 拒绝 <reason> / deny <reason>, optionally
followed by the first characters of the ticket id.

The channel owns no state machine of its own. It parses the reply, resolves which
pending ticket the reply names and hands the decision to
commands.decide_ticket, which is the same compare-and-swap, the same
late-decision path and the same audit row shape as /guard approve. Nothing here
writes a ticket, a state column or an audit row by itself.

A reply that names no decision, that arrives in a group chat, from a sender the
administrator gate refuses, or while no ticket is pending is not consumed at all:
handle_reply returns None and the host lets the message reach the model as usual.
The channel can therefore only shorten the way an administrator who is already
entitled to decide gets to decide; it cannot widen who may approve.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass
from typing import Any

from ..store import tickets
from . import commands

__all__ = [
    "REPLY_APPROVAL_PATTERN",
    "REPLY_TOOL",
    "ReplyDecision",
    "handle_reply",
    "parse_reply",
]

#: tool_name recorded on the audit row of a decision made by replying.
REPLY_TOOL = "guard/reply"
#: Chat type that carries the reply channel; group replies are never consumed.
FRIEND_MESSAGE = "FriendMessage"
#: Longest reply treated as a decision; longer text is ordinary conversation.
MAX_REPLY_CHARS = 200
#: Shortest ticket prefix accepted in a reply, in characters.
MIN_PREFIX = 4
#: Pending tickets listed when a reply does not say which one it means.
AMBIGUOUS_VIEW_LIMIT = 5
#: Words that approve. English entries are matched case-insensitively.
APPROVE_WORDS = frozenset(
    {"同意", "批准", "通过", "允许", "approve", "approved", "yes", "allow"}
)
#: Words that deny.
DENY_WORDS = frozenset({"拒绝", "驳回", "不批准", "deny", "denied", "no", "reject"})
#: Handler filter: one decision word, then end of message or a space.
REPLY_APPROVAL_PATTERN = (
    r"^\s*(?:同意|批准|通过|允许|拒绝|驳回|不批准|approve|approved|yes|allow|deny|denied|reject)"
    r"(?=\s|$)"
)
_DECISION_WORDS = tuple(sorted(APPROVE_WORDS | DENY_WORDS, key=len, reverse=True))
#: Separators that end one token of a reply.
_SEPARATORS = re.compile(r"[\s，,。.！!？?；;：:]+")
#: Shape of a ticket reference: at least MIN_PREFIX hex characters with dashes.
_REFERENCE = re.compile(r"^[0-9a-fA-F][0-9a-fA-F-]{2,}$")


@dataclass(frozen=True, slots=True)
class ReplyDecision:
    """One parsed decision reply.

    Attributes:
        approve: True for an approval, False for a denial.
        ref: Ticket prefix the reply named, or "" when it named none.
        reason: Remaining words after the ticket prefix; empty for approvals.
    """

    approve: bool
    ref: str = ""
    reason: str = ""


def parse_reply(text: str) -> ReplyDecision | None:
    """Parse one message as a decision reply.

    Requirement: Reply Approval Channel. Only a message whose first token is a
    decision word is a reply to a notice; everything else, including a /guard
    command, is left to its own channel.

    Args:
        text: Raw message text.

    Returns:
        The parsed decision, or None when the text is not one.
    """
    stripped = (text or "").strip()
    if not stripped or len(stripped) > MAX_REPLY_CHARS:
        return None
    if stripped[0] in "/／":
        return None
    lowered = stripped.lower()
    head = ""
    for word in _DECISION_WORDS:
        if lowered.startswith(word) and (
            len(lowered) == len(word) or not lowered[len(word)].isalnum()
        ):
            head = word
            break
    if not head:
        return None
    approve = head in APPROVE_WORDS
    rest = [token for token in _SEPARATORS.split(stripped[len(head) :]) if token]
    ref = ""
    if rest and _REFERENCE.match(rest[0]):
        ref = rest[0]
        rest = rest[1:]
    reason = "" if approve else " ".join(rest).strip()
    return ReplyDecision(approve=approve, ref=ref, reason=reason)


def handle_reply(
    text: str,
    gateway: Any,
    event: Any,
    *,
    registry: Any = None,
) -> str | None:
    """Turn one administrator reply into a decision, or leave it alone.

    Requirement: Reply Approval Channel; Approval Channels Are Equivalent. The
    decision itself is commands.decide_ticket, so this function never moves a
    ticket state on its own.

    Args:
        text: Raw message text.
        gateway: Gateway owning config, store and registry.
        event: Host message event.
        registry: Approval registry to wake; defaults to gateway.registry.

    Returns:
        The reply text when the message was consumed as a decision, otherwise
        None so the host delivers the message to the model as usual.
    """
    intent = parse_reply(text)
    if intent is None:
        return None
    if commands.chat_type(event) != FRIEND_MESSAGE:
        return None
    actor = commands.admin_actor(gateway, event)
    if actor is None:
        return None
    conn = commands.store_connection(gateway)
    if conn is None:
        return None
    try:
        pending = tickets.list_pending(conn)
    except Exception:  # noqa: BLE001 - an unreadable store is not a decision
        return None
    if not pending:
        return None
    if intent.ref:
        matches = [item for item in pending if item.ticket_id.startswith(intent.ref)]
        if len(matches) > 1:
            return _ambiguous_reply(matches, intent)
        ticket_id = matches[0].ticket_id if matches else intent.ref
    elif len(pending) == 1:
        ticket_id = pending[0].ticket_id
    else:
        return _ambiguous_reply(pending, intent)
    result = commands.decide_ticket(
        gateway,
        ticket_id,
        approve=intent.approve,
        actor=actor,
        reason=intent.reason or None,
        registry=registry,
        tool_name=REPLY_TOOL,
    )
    return commands.finalize_reply(result.message, commands.redactor(gateway))


def _ambiguous_reply(pending: list[Any], intent: ReplyDecision) -> str:
    """Name the pending tickets a reply could have meant.

    Requirement: Reply Approval Channel. An ambiguous reply decides nothing: the
    administrator picks one by its short code, so a single word never settles a
    ticket the operator did not have in mind.

    Args:
        pending: Pending tickets this reply could target.
        intent: The parsed decision.

    Returns:
        The reply text naming the short codes.
    """
    word = "同意" if intent.approve else "拒绝"
    lines = [
        f"待批票据 {len(pending)} 条，未指定是哪一条：请回复「{word} <前 8 位>」"
        + ("" if intent.approve else "（拒绝可再跟原因）")
    ]
    for item in pending[:AMBIGUOUS_VIEW_LIMIT]:
        lines.append(f"  · {_short(item.ticket_id)} {item.tool_name or '?'}")
    hidden = len(pending) - AMBIGUOUS_VIEW_LIMIT
    if hidden > 0:
        lines.append(f"  · 其余 {hidden} 条见 /guard stats")
    return "\n".join(lines)


def _short(ticket_id: str) -> str:
    """Return the short code of one ticket id.

    Args:
        ticket_id: Full ticket identifier.

    Returns:
        The first eight characters.
    """
    return ticket_id[:8]


def short_code(ticket_id: str) -> str:
    """Return the short code the suspension notice shows for a ticket.

    Requirement: Notification Content. The notice prints the short code so the
    administrator can name the ticket in a reply without copying a uuid.

    Args:
        ticket_id: Full ticket identifier.

    Returns:
        The first eight characters, or "" for an empty id.
    """
    with contextlib.suppress(Exception):
        return _short(str(ticket_id or ""))
    return ""
