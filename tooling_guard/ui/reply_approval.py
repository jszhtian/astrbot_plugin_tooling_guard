"""Approve or deny a suspended call by replying to its notice.

Requirement: Approval Channels Are Equivalent (openspec admin-approval:156-172),
Reply Approval Channel and Quoted Reply Resolution. An administrator answers the
suspension notice with 同意 / 批准 / approve, or 拒绝 <reason> / deny <reason>.

Which ticket the reply is about is decided by three sources, in this order:

1. the reply names a short code (「同意 4cd67595」);
2. the reply *quotes* the notice itself -- the host hands the quoted text to
   every handler (aiocqhttp turns the OneBot reply segment into a Reply
   component whose message_str is the notice), and the notice prints the full
   ticket id on its first line and the short code in its last, so the quoted
   text identifies exactly one ticket;
3. the reply names nothing and the administrator has exactly one ticket whose
   notice was delivered to them (see store/notices.py).

A reply that still names no single ticket decides nothing: it is answered with
the candidates and a hint to quote the notice, never applied to "the only
pending ticket" -- a global unique pending ticket is not evidence that this
administrator is answering it, and since 0.7.3 an approval executes the call.

The channel owns no state machine of its own. It parses the reply, resolves which
pending ticket the reply names and hands the decision to
commands.decide_ticket, which is the same compare-and-swap, the same
late-decision path and the same audit row shape as /guard approve. Nothing here
writes a ticket, a state column or an audit row by itself.

A reply that names no decision, or that comes from a sender the administrator
gate refuses while looking nothing like an approval attempt, is not consumed at
all: handle_reply returns None and the host lets the message reach the model as
usual. The gate itself is the same two conditions /guard applies -- the reply
channel can only shorten the way an already-entitled administrator decides; it
can never widen who may approve.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass
from typing import Any

from ..store import notices, tickets
from . import commands

__all__ = [
    "REPLY_APPROVAL_PATTERN",
    "REPLY_TOOL",
    "ReplyDecision",
    "handle_reply",
    "parse_reply",
    "quoted_text",
    "short_code",
]

#: tool_name recorded on the audit row of a decision made by replying.
REPLY_TOOL = "guard/reply"
#: Chat type that may decide without quoting; other chats must quote the notice.
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
_REFERENCE = re.compile(rf"^[0-9a-fA-F]{{{MIN_PREFIX}}}[0-9a-fA-F-]*$")
#: A full ticket id inside quoted text.
_UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


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


@dataclass(frozen=True, slots=True)
class _Target:
    """The ticket one reply was resolved to, or the reason it resolved to none.

    Attributes:
        ticket_id: Ticket to decide, or "" when the reply is answered instead.
        note: Text to send back when nothing was decided.
    """

    ticket_id: str = ""
    note: str = ""


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


def quoted_text(event: Any) -> str:
    """Return the text of the message this event quotes, or "".

    Requirement: Quoted Reply Resolution. AstrBot keeps the quoted message in a
    Reply component of the incoming chain: aiocqhttp fills message_str with the
    original text and leaves text/chain for other adapters. The notice is plain
    text, so reading every plausible carrier of that text is enough to recover
    the ticket id it printed -- no message id lookup is needed (and none exists:
    the host's send path returns no id).

    Args:
        event: Host message event, possibly None.

    Returns:
        The quoted text, or "" when the message quotes nothing.
    """
    reader = getattr(event, "get_messages", None)
    if not callable(reader):
        return ""
    try:
        components = reader()
    except Exception:  # noqa: BLE001 - an unreadable chain quotes nothing
        return ""
    parts: list[str] = []
    for component in list(components or ()):
        if type(component).__name__ != "Reply":
            continue
        parts.extend(_reply_pieces(component))
    return "\n".join(part for part in parts if part).strip()


def _reply_pieces(component: Any) -> list[str]:
    """Return every text field one Reply component carries.

    Args:
        component: The Reply component of an incoming message chain.

    Returns:
        The non-empty text fields, in the order they are read.
    """
    pieces: list[str] = []
    for attribute in ("message_str", "text"):
        value = getattr(component, attribute, None)
        if isinstance(value, str) and value.strip():
            pieces.append(value)
    chain = getattr(component, "chain", None)
    for item in list(chain or ()) if chain is not None else ():
        value = getattr(item, "text", None)
        if isinstance(value, str) and value.strip():
            pieces.append(value)
    return pieces


def handle_reply(
    text: str,
    gateway: Any,
    event: Any,
    *,
    registry: Any = None,
) -> str | None:
    """Turn one administrator reply into a decision, or leave it alone.

    Requirement: Reply Approval Channel; Approval Channels Are Equivalent;
    Quoted Reply Resolution. The decision itself is commands.decide_ticket, so
    this function never moves a ticket state on its own.

    Args:
        text: Raw message text.
        gateway: Gateway owning config, store and registry.
        event: Host message event.
        registry: Approval registry to wake; defaults to gateway.registry.

    Returns:
        The reply text when the message was consumed as a decision (or as a
        refusal the sender has to see), otherwise None so the host delivers the
        message to the model as usual.
    """
    intent = parse_reply(text)
    if intent is None:
        return None
    direct = commands.chat_type(event) == FRIEND_MESSAGE
    quote = quoted_text(event)
    facts = commands.sender_facts(gateway, event)
    conn = commands.store_connection(gateway)
    if conn is None:
        return None
    try:
        pending = tickets.list_pending(conn)
    except Exception:  # noqa: BLE001 - an unreadable store is not a decision
        return None
    if not facts.allowed:
        return _refusal(facts, intent, direct=direct, quote=quote, pending=pending)
    if not pending:
        return None
    target = _resolve(
        conn,
        pending,
        intent,
        quote=quote,
        entries=commands.admin_entries_for(gateway, facts.subject),
        direct=direct,
    )
    if target.note:
        return commands.finalize_reply(target.note, commands.redactor(gateway))
    if not target.ticket_id:
        return None
    result = commands.decide_ticket(
        gateway,
        target.ticket_id,
        approve=intent.approve,
        actor=facts.subject,
        reason=intent.reason or None,
        registry=registry,
        tool_name=REPLY_TOOL,
    )
    return commands.finalize_reply(result.message, commands.redactor(gateway))


def _resolve(
    conn: Any,
    pending: list[Any],
    intent: ReplyDecision,
    *,
    quote: str,
    entries: tuple[str, ...],
    direct: bool,
) -> _Target:
    """Work out which pending ticket one reply is about.

    Requirement: Quoted Reply Resolution. The order matters and is part of the
    contract: a short code the administrator typed outranks a quote, a quote
    outranks "this was delivered to me", and a bare 同意 in a group chat resolves
    to nothing at all -- deciding somebody else's ticket because a chat happened
    to hold one pending ticket is exactly the mis-approval this channel must not
    make.

    Args:
        conn: Open store connection.
        pending: Pending tickets at the time of the reply.
        intent: The parsed decision.
        quote: Quoted text of the reply, or "".
        entries: Configured administrator entries naming this sender.
        direct: True when the reply arrived in a private chat.

    Returns:
        The resolved ticket, or the note to answer with.
    """
    if intent.ref:
        matches = [item for item in pending if item.ticket_id.startswith(intent.ref)]
        if len(matches) > 1:
            return _Target(note=_ambiguous_reply(matches, intent, quoted=False))
        if matches:
            return _Target(ticket_id=matches[0].ticket_id)
        return _Target(note=_unknown_ref(intent))
    if quote:
        resolved = _from_quote(conn, pending, intent, quote=quote)
        if resolved is not None:
            return resolved
    if not direct:
        return _Target()
    delivered = _delivered_candidates(conn, entries)
    own = [item for item in pending if item.ticket_id in delivered]
    if len(own) == 1:
        return _Target(ticket_id=own[0].ticket_id)
    if own:
        return _Target(note=_ambiguous_reply(own, intent, quoted=False))
    return _Target(note=_ambiguous_reply(pending, intent, quoted=True))


def _from_quote(
    conn: Any, pending: list[Any], intent: ReplyDecision, *, quote: str
) -> _Target | None:
    """Resolve a reply by the notice it quotes.

    Requirement: Quoted Reply Resolution. The notice prints the full ticket id
    on its first line and the short code in its instruction line, so either is
    enough. A quote that names a ticket which is no longer pending is answered
    instead of decided: the administrator needs to know the window closed rather
    than watch 同意 do nothing.

    Args:
        conn: Open store connection.
        pending: Pending tickets at the time of the reply.
        intent: The parsed decision.
        quote: Quoted text.

    Returns:
        The resolved target, or None when the quote names no ticket at all.
    """
    haystack = quote.lower()
    matches = [
        item
        for item in pending
        if item.ticket_id.lower() in haystack or _short(item.ticket_id).lower() in haystack
    ]
    if len(matches) > 1:
        return _Target(note=_ambiguous_reply(matches, intent, quoted=False))
    if matches:
        return _Target(ticket_id=matches[0].ticket_id)
    for identifier in dict.fromkeys(_UUID.findall(quote)):
        stale = _fresh_ticket(conn, identifier)
        if stale is None:
            continue
        if stale:
            return _Target(
                note=(
                    f"票据 {_short(identifier)} 不在待批状态（当前 {stale}）："
                    "可能已批准、已拒绝或已过期，本次未做任何操作。"
                )
            )
    return None


def _fresh_ticket(conn: Any, identifier: str) -> str:
    """Return the state of one quoted ticket id, or "" when it is unknown.

    Args:
        conn: Open store connection.
        identifier: Full ticket id found in quoted text.

    Returns:
        The stored state word, or "" when no such ticket exists.
    """
    with contextlib.suppress(Exception):
        found = tickets.get_ticket(conn, identifier)
        if found is not None:
            return str(getattr(found, "state", "") or "")
    return ""


def _delivered_candidates(conn: Any, entries: tuple[str, ...]) -> set[str]:
    """Return the pending tickets whose notice reached this administrator.

    Requirement: Quoted Reply Resolution. Without this relation a bare 同意 has
    no honest answer: the previous fallback matched a globally unique pending
    ticket, which is a statement about the whole system rather than about the
    administrator who typed it.

    Args:
        conn: Open store connection.
        entries: Configured administrator entries naming this sender; the notice
            records the entry it was addressed to, not the sender origin.

    Returns:
        Ticket ids, empty when nothing was recorded.
    """
    found: set[str] = set()
    for entry in entries:
        with contextlib.suppress(Exception):
            found.update(notices.delivered_ticket_ids(conn, entry))
    return found


def _refusal(
    facts: Any,
    intent: ReplyDecision,
    *,
    direct: bool,
    quote: str,
    pending: list[Any],
) -> str | None:
    """Answer a decision reply the administrator gate refused, or stay silent.

    Requirement: Approver Authorization; Sender Self-Identification. The gate
    itself is unchanged -- refusing here is the same two-condition test /guard
    applies -- but a refusal that says nothing is how an administrator concludes
    that their 同意 worked. The note is only produced for a sender that looks
    like an intended approver (one of the two conditions holds) and only when
    there is something to approve, so ordinary conversation in a group chat and
    a stranger's "yes" still reach the model untouched.

    Args:
        facts: Sender facts.
        intent: The parsed decision.
        direct: True when the reply arrived in a private chat.
        quote: Quoted text of the reply, or "".
        pending: Pending tickets at the time of the reply.

    Returns:
        The refusal text, or None to let the message through.
    """
    if not pending:
        return None
    if not (facts.host_admin or facts.listed):
        return None
    if not direct and not (intent.ref or quote):
        return None
    missing: list[str] = []
    if not facts.host_admin:
        missing.append("宿主未把你判为管理员（AstrBot 配置的管理员 ID 里没有你）")
    if not facts.listed:
        missing.append("插件 admins 名单里没有你")
    subject = facts.subject or "未读到"
    lines = [
        "[工具网关] 这条回复没有生效：它看起来是在决定一条待批票据，但你没有审批权限。",
        f"发送者 {subject}（{facts.message_type}）· 未通过：{'；'.join(missing)}",
        "用 /guard whoami 可以看到两处判定的当前取值。",
    ]
    return "\n".join(lines)


def _ambiguous_reply(pending: list[Any], intent: ReplyDecision, *, quoted: bool) -> str:
    """Name the pending tickets a reply could have meant.

    Requirement: Quoted Reply Resolution. An ambiguous reply decides nothing: a
    single word never settles a ticket the operator did not have in mind. Since
    the notice can be quoted, the hint leads with that -- it is the shortest way
    to name a ticket without copying a code.

    Args:
        pending: Pending tickets this reply could target.
        intent: The parsed decision.
        quoted: True when the hint should lead with quoting the notice.

    Returns:
        The reply text naming the short codes.
    """
    word = "同意" if intent.approve else "拒绝"
    tail = "" if intent.approve else "（拒绝可再跟原因）"
    lines = [
        f"这条回复没有指定是哪张票据，本次未做任何操作（待批 {len(pending)} 条）。"
    ]
    if quoted:
        lines.append(f"最快的方式：直接「回复/引用」我发的通知消息，内容只写「{word}」。")
    lines.append(f"也可以回复「{word} <前 8 位>」{tail}")
    for item in pending[:AMBIGUOUS_VIEW_LIMIT]:
        lines.append(f"  · {_short(item.ticket_id)} {item.tool_name or '?'}")
    hidden = len(pending) - AMBIGUOUS_VIEW_LIMIT
    if hidden > 0:
        lines.append(f"  · 其余 {hidden} 条见 /guard stats")
    return "\n".join(lines)


def _unknown_ref(intent: ReplyDecision) -> str:
    """Answer a reply whose short code names no pending ticket.

    Args:
        intent: The parsed decision.

    Returns:
        The reply text.
    """
    word = "同意" if intent.approve else "拒绝"
    return (
        f"没有找到以 {intent.ref} 开头的待批票据，本次未做任何操作。"
        f"请回复「{word} <前 8 位>」，或直接引用通知消息回复。"
    )


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
