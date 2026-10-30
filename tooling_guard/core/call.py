"""The facts one reviewer is allowed to see. Requirement: Reviewer Contract.

Requirement names owned here: Reviewer Contract (read-only input side).

`GuardCall` is a frozen value: a reviewer may look, never write. It carries only
what a decision can legitimately depend on — which tool, which arguments, which
subject and session, the effective mode, the call id, the argument digest and
the clock reading — so a reviewer never needs a Gateway handle, a store handle
or an AstrBot type to do its job (MR3: read-only boundary).

`build_call` exists because task 11.3 will hand this package objects that
already live inside `tooling_guard.main` (a plan, a summary, a triage outcome).
It reads those by duck typing — attribute names only, no import of
`tooling_guard.main` and no `astrbot.core.*` — so this module stays a contract
with no dependency on the code that will call it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final

from ..triage.decisions import MODE_ENFORCE, effective_mode

#: Attribute names read from a duck-typed source, in priority order.
_TOOL_ATTRS: Final[tuple[str, ...]] = ("tool_name", "tool")
_ARGUMENT_ATTRS: Final[tuple[str, ...]] = ("arguments", "args")
_SUBJECT_ATTRS: Final[tuple[str, ...]] = ("subject_key", "subject", "user")
_SESSION_ATTRS: Final[tuple[str, ...]] = ("session_key", "session")
_CALL_ID_ATTRS: Final[tuple[str, ...]] = ("call_id", "id")
_DIGEST_ATTRS: Final[tuple[str, ...]] = ("args_digest",)
_AT_ATTRS: Final[tuple[str, ...]] = ("at", "ts", "timestamp")
_TIER_ATTRS: Final[tuple[str, ...]] = ("tier",)
_LABEL_ATTRS: Final[tuple[str, ...]] = ("labels",)
_MODE_ATTRS: Final[tuple[str, ...]] = ("mode",)


@dataclass(frozen=True, slots=True)
class GuardCall:
    """Immutable facts of one guarded call, as handed to every reviewer.

    Requirement: Reviewer Contract.

    Attributes:
        tool_name: The tool the model wants to run.
        arguments: Read-only view of the arguments; set on construction, never
            writable afterwards.
        subject_key: Who the call belongs to, in the audit vocabulary.
        session_key: Which session it came from, in the audit vocabulary.
        mode: Effective enforcement mode, normalised to observe or enforce.
        call_id: Stable id of this call.
        args_digest: 32-character lowercase hex digest of the arguments.
        at: Clock reading for the call, in whatever clock the caller used.
        tier: Optional classification tier, kept for reviewers that use it.
        labels: Classification labels, as an immutable set.
    """

    tool_name: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    subject_key: str = ""
    session_key: str = ""
    mode: str = MODE_ENFORCE
    call_id: str = ""
    args_digest: str = ""
    at: float = 0.0
    tier: str | None = None
    labels: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        """Freeze the argument view, the label set and the mode word."""
        object.__setattr__(self, "arguments", MappingProxyType(dict(self.arguments)))
        object.__setattr__(self, "mode", effective_mode(self.mode, self.mode))
        object.__setattr__(self, "labels", frozenset(self.labels))


def build_call(
    source: Any = None,
    *,
    tool_name: str | None = None,
    arguments: Mapping[str, Any] | None = None,
    subject_key: str | None = None,
    session_key: str | None = None,
    mode: str | None = None,
    call_id: str | None = None,
    args_digest: str | None = None,
    at: float | None = None,
    tier: str | None = None,
    labels: Iterable[str] | None = None,
) -> GuardCall:
    """Build a GuardCall from plain values, a duck-typed object, or both.

    Requirement: Reviewer Contract.

    Every keyword overrides the value found on `source`; anything still missing
    falls back to the dataclass default. Nothing about `source` is imported or
    imported from, so a live `_Plan`, a `CallSummary` or a bare `SimpleNamespace`
    all work.

    Args:
        source: Optional live object read by attribute name. Recognised names:
            `tool_name`/`tool`, `arguments`/`args`, `subject_key`/`subject`/
            `user`, `session_key`/`session`, `mode`, `call_id`/`id`,
            `args_digest`, `at`/`ts`/`timestamp`, `tier`, `labels`.
        tool_name: The tool name; required either here or on `source`.
        arguments: The argument mapping, copied into a read-only view.
        subject_key: Who the call belongs to.
        session_key: Which session it came from.
        mode: Requested mode; normalised, and an unknown word becomes enforce.
        call_id: Stable id of this call.
        args_digest: Argument digest carried into the audit row.
        at: Clock reading for the call.
        tier: Optional classification tier.
        labels: Classification labels.

    Returns:
        GuardCall: The frozen value handed to every reviewer.

    Raises:
        ValueError: `tool_name` is neither given nor readable from `source`.
    """
    resolved: dict[str, Any] = {
        "tool_name": _first_text(source, _TOOL_ATTRS),
        "arguments": _first_value(source, _ARGUMENT_ATTRS),
        "subject_key": _first_text(source, _SUBJECT_ATTRS),
        "session_key": _first_text(source, _SESSION_ATTRS),
        "mode": _first_text(source, _MODE_ATTRS),
        "call_id": _first_text(source, _CALL_ID_ATTRS),
        "args_digest": _first_text(source, _DIGEST_ATTRS),
        "at": _first_value(source, _AT_ATTRS),
        "tier": _first_text(source, _TIER_ATTRS),
        "labels": _first_value(source, _LABEL_ATTRS),
    }
    explicit: dict[str, Any] = {
        "tool_name": tool_name,
        "arguments": arguments,
        "subject_key": subject_key,
        "session_key": session_key,
        "mode": mode,
        "call_id": call_id,
        "args_digest": args_digest,
        "at": at,
        "tier": tier,
        "labels": labels,
    }
    for key, value in explicit.items():
        if value is not None:
            resolved[key] = value
    if not resolved["tool_name"]:
        raise ValueError("build_call needs a tool_name, given or on source")
    return GuardCall(
        tool_name=str(resolved["tool_name"]),
        arguments=resolved["arguments"] or {},
        subject_key=str(resolved["subject_key"] or ""),
        session_key=str(resolved["session_key"] or ""),
        mode=str(resolved["mode"] or MODE_ENFORCE),
        call_id=str(resolved["call_id"] or ""),
        args_digest=str(resolved["args_digest"] or ""),
        at=float(resolved["at"] or 0.0),
        tier=resolved["tier"],
        labels=resolved["labels"] or (),
    )


def _first_value(source: Any, names: Iterable[str]) -> Any:
    """Return the first non-None attribute of `source` matching `names`."""
    if source is None:
        return None
    for name in names:
        value = getattr(source, name, None)
        if value is not None:
            return value
    return None


def _first_text(source: Any, names: Iterable[str]) -> str | None:
    """Return the first matching attribute of `source` as text."""
    value = _first_value(source, names)
    return None if value is None else str(value)
