"""The structured state object: the one construction source for a judge request.

Requirement: Fast Judge Budget; Sanitized Persistence.

The fast judge is never asked in prose. Both backends are handed this same
mapping -- `prompts.systemone` embeds it in the jev body and
`prompts.single_call` sends it as the user message of a chat completion -- and
`triage.engine.judge_payload` delegates here instead of assembling keys of its
own, so the field set is spelled out exactly once and cannot drift between the
engine and the two request builders.

The state leaves the host, so it is bounded and redacted here rather than
trusted: every free-text field is capped, a secret collapses to its
`<SECRET:...>` placeholder, and an absolute path outside the project roots
collapses to `<EXT>/<basename>`. A state that is still too long is shrunk field
by field, never sent whole.

Nothing here reads a clock: `deadline_monotonic` is the instant the caller
already computed, passed through as a number, never recomputed.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any, Final

from ..anonymize import Anonymizer, PathRedactor

MAX_FIELD_CHARS: Final[int] = 1200
"""Characters one free-text field may carry before it is cut."""

MAX_ITEMS: Final[int] = 12
"""Entries kept per list field; the tail is dropped, never summarised."""

MAX_STATE_CHARS: Final[int] = 6000
"""Serialized length above which the state is shrunk field by field."""

JUDGE_STATE_KEYS: Final[tuple[str, ...]] = (
    "tool",
    "action",
    "verb",
    "targets",
    "tier",
    "labels",
    "text_summary",
    "trajectory_summary",
    "mode",
    "subject",
    "session",
    "deadline_monotonic",
)
"""The keys every judge sees, in this order; caller extras follow them."""

_REDACTOR: Anonymizer | None = None


def _redactor() -> Anonymizer:
    """Return the process-wide redactor, building it on first use.

    Requirement: Sanitized Persistence. Building it eagerly would put the whole
    built-in rule set on the import path of every module that touches triage,
    including the ones that never ask a judge.
    """
    global _REDACTOR
    if _REDACTOR is None:
        _REDACTOR = Anonymizer(paths=PathRedactor())
    return _REDACTOR


def _text(value: Any, limit: int = MAX_FIELD_CHARS) -> str:
    """Return one redacted, truncated text field; never raises."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    return _redactor().redact(text)[:limit]


def _items(value: Any) -> list[Any]:
    """Return the entries of a list-shaped field, or an empty list."""
    if isinstance(value, (str, bytes)):
        return [value]
    if isinstance(value, Iterable):
        return list(value)
    return []


def _listing(value: Any) -> list[str]:
    """Return one bounded list of redacted strings."""
    items = (item for item in _items(value) if isinstance(item, str))
    return [_text(item) for item in items][:MAX_ITEMS]


def _summary(value: Any) -> str:
    """Return one redacted text summary joined from a text sequence."""
    if isinstance(value, str):
        return _text(value)
    joined = "\n".join(_text(item) for item in _items(value) if isinstance(item, str))
    return joined[:MAX_FIELD_CHARS]


def _instant(value: Any) -> float | None:
    """Return a monotonic instant unchanged, or None when it is not a number."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _extra(value: Any) -> Any:
    """Return one caller-supplied extra value, redacted and bounded."""
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, (tuple, list, set, frozenset)):
        return _listing(value)
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return _text(value)


def state_json(state: Mapping[str, Any]) -> str:
    """Serialize one state as the JSON document a judge is asked about."""
    return json.dumps(dict(state), ensure_ascii=False)


def _shrink(state: dict[str, Any]) -> dict[str, Any]:
    """Cut free text until the serialized state fits MAX_STATE_CHARS.

    Requirement: Fast Judge Budget. The bound is on the serialized document
    because that is what the request pays for. Fields are cut in a fixed order
    -- trajectory first, then text, then targets -- so a shrink never drops the
    identity of the call it is asking about.
    """
    for key in ("trajectory_summary", "text_summary", "targets"):
        while len(state_json(state)) > MAX_STATE_CHARS:
            value = state.get(key)
            if isinstance(value, str) and value:
                state[key] = value[: max(0, len(value) - 128)]
            elif isinstance(value, list) and value:
                state[key] = value[:-1]
            else:
                break
    return state


def build_state(
    *,
    tool: Any,
    verb: Any,
    action: Any = None,
    targets: Any = (),
    tier: Any = "",
    labels: Any = (),
    texts: Any = (),
    trajectory_summary: Any = "",
    mode: Any = "",
    subject: Any = "",
    session: Any = "",
    deadline: float | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the structured state a fast judge is asked about.

    Requirement: Fast Judge Budget; Sanitized Persistence.

    Args:
        tool: Tool name as classified.
        verb: Classified verb of the call.
        action: Action word to publish; the verb when the caller has only one
            word for it, so both documented keys always carry a value.
        targets: Target paths or destinations of the call.
        tier: Policy tier of the tool.
        labels: Orthogonal labels the classification attached.
        texts: Free-text excerpts of the arguments.
        trajectory_summary: Summary of the session trajectory window.
        mode: Effective enforcement mode.
        subject: Platform-qualified requester identity.
        session: Session identity the trajectory belongs to.
        deadline: Deadline instant on the caller's monotonic clock, published
            under `deadline_monotonic` and never read as a budget in seconds.
        extra: Additional keys (origin, destinations, rule ids); a canonical key
            always wins, and every extra is redacted and bounded like the rest.

    Returns:
        dict: The state, keyed by JUDGE_STATE_KEYS and then the extras.
    """
    state: dict[str, Any] = {
        "tool": _text(tool),
        "action": _text(verb if action is None else action),
        "verb": _text(verb),
        "targets": _listing(targets),
        "tier": _text(tier),
        "labels": _listing(labels),
        "text_summary": _summary(texts),
        "trajectory_summary": _summary(trajectory_summary),
        "mode": _text(mode),
        "subject": _text(subject),
        "session": _text(session),
        "deadline_monotonic": _instant(deadline),
    }
    for key, value in (extra or {}).items():
        name = str(key)
        if name in state:
            continue
        state[name] = _extra(value)
    return _shrink(state)


__all__ = [
    "JUDGE_STATE_KEYS",
    "MAX_FIELD_CHARS",
    "MAX_ITEMS",
    "MAX_STATE_CHARS",
    "build_state",
    "state_json",
]
