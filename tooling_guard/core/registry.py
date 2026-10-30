"""Reviewer registry: who participates, and in which presentation order.

Requirement: Reviewer Registry.

`(order, name)` is a deterministic *presentation* order and nothing else: it
breaks ties in `PipelineOutcome.verdicts`, in `/guard status` and in the audit
line. It never decides who runs, and it never sequences execution — the pipeline
starts every enabled reviewer concurrently (MR5).

Three behaviours here are contract, not convenience:

- `base_check` cannot be unregistered: `unregister` returns False and leaves the
  entry, its `enabled` flag and its `order` untouched, because a gateway that
  silently lost its path and user black/white-list check must not be reachable by
  accident. It can still be *disabled* by configuration, which is a recorded and
  alerted decision taken elsewhere (MR4).
- `policy` -- the hard-deny half of that same stage (requester blacklist, path
  denials, secret content, private keys, sensitive configuration, the strict write
  whitelist, the T-strong suspend default) -- can be neither unregistered nor
  disabled. Review finding S1: taking it out of the pipeline released exactly the
  calls a deny layer exists for, so `base_check_enabled=false` may now keep its
  whitelist behaviour and lose nothing else.
- re-registering the *same object* under the same name is a no-op, so a plugin
  reload does not explode; a different object under an existing name raises
  `DuplicateReviewer`, which is a `ValueError` as the requirement states.
- `enabled()` is the pipeline's only work list. Disabled reviewers leave the
  concurrent set but stay in `ordered()` and `statuses()`, so a status page can
  report "disabled" instead of "missing".

Where the two sources disagree, the design wins over the spec text: MR4 makes
same-name-same-object a no-op for hot reload, while
`specs/reviewer-pipeline/spec.md` asks for an error on any repeat of a name. A
reload that raised would take the gateway down, so repeat-of-the-same-object
returns quietly and every other repeat raises.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Final

from .reviewer import ReviewerStatus, reviewer_name, reviewer_order, validate_reviewer

#: The whitelist half of the policy stage. Removable never, disable-able by
#: configuration, which is the recorded and alerted decision of MR4.
BASE_CHECK_NAME: Final[str] = "base_check"

#: The hard-deny half of the same stage: the reviewer that `base_check_enabled`
#: is not allowed to remove (review finding S1).
POLICY_NAME: Final[str] = "policy"

#: Reviewers no caller can unregister, whatever the `builtin` argument says, so a
#: mislabelled reload cannot expose the gateway.
_PROTECTED_NAMES: Final[frozenset[str]] = frozenset({BASE_CHECK_NAME, POLICY_NAME})

#: Reviewers no caller can disable either. The deny layer belongs here: a switch
#: that can turn it off is a release path, not a configuration toggle.
_ALWAYS_ON_NAMES: Final[frozenset[str]] = frozenset({POLICY_NAME})


class DuplicateReviewer(ValueError):
    """Raised when an existing reviewer name is registered with another object."""


@dataclass(slots=True)
class _Entry:
    """One registry slot: the reviewer, its protection and its enabled flag."""

    reviewer: Any
    builtin: bool
    enabled: bool = True
    order_hint: int | None = None


class ReviewerRegistry:
    """In-memory set of reviewers, ordered for display and protected by name."""

    def __init__(self) -> None:
        """Create an empty registry."""
        self._entries: dict[str, _Entry] = {}

    def __len__(self) -> int:
        """Return how many reviewers are registered, enabled or not."""
        return len(self._entries)

    def __contains__(self, name: object) -> bool:
        """Return whether a name is registered."""
        return isinstance(name, str) and name in self._entries

    def register(self, reviewer: Any, *, builtin: bool = False) -> None:
        """Add one reviewer.

        Args:
            reviewer: Any object satisfying the `Reviewer` contract.
            builtin: True for a reviewer the registry must protect from
                `unregister`. `base_check` and `policy` are protected by name
                whatever this argument says, so a mislabelled reload cannot
                expose the gateway.

        Raises:
            TypeError: The reviewer does not satisfy the contract surface.
            DuplicateReviewer: A *different* object already holds this name; use
                `replace` to swap the implementation deliberately.
        """
        name = validate_reviewer(reviewer)
        entry = self._entries.get(name)
        if entry is not None:
            if entry.reviewer is not reviewer:
                raise DuplicateReviewer(
                    f"reviewer {name!r} is already registered; use replace()"
                )
            entry.builtin = entry.builtin or builtin or name in _PROTECTED_NAMES
            return
        self._entries[name] = _Entry(
            reviewer=reviewer, builtin=builtin or name in _PROTECTED_NAMES
        )

    def unregister(self, name: str) -> bool:
        """Remove one reviewer.

        Args:
            name: The reviewer to remove.

        Returns:
            bool: False — with the entry, its `enabled` flag and its `order`
            unchanged — for a builtin, a protected name or an unknown name; True
            once a removable reviewer is gone. A load-bearing reviewer is not
            removable by asking, and the name check holds even when a caller
            registered its own object under it without the flag.
        """
        entry = self._entries.get(name)
        if entry is None or entry.builtin or name in _PROTECTED_NAMES:
            return False
        del self._entries[name]
        return True

    def replace(self, reviewer: Any) -> None:
        """Swap the implementation behind an existing name.

        The entry keeps its builtin protection and its enabled flag; when the new
        implementation declares no order of its own it also keeps the order it
        replaces, so a replacement cannot silently jump to the front of the
        presentation order.

        Args:
            reviewer: The new implementation, holding an existing name.

        Raises:
            TypeError: The reviewer does not satisfy the contract surface.
            KeyError: No reviewer is registered under that name.
        """
        name = validate_reviewer(reviewer)
        entry = self._entries.get(name)
        if entry is None:
            raise KeyError(f"reviewer {name!r} is not registered")
        previous = _entry_order(entry)
        entry.reviewer = reviewer
        inherits = reviewer_order(reviewer) == 0 and previous != 0
        entry.order_hint = previous if inherits else None

    def enable(self, name: str) -> bool:
        """Let one reviewer participate again; False when the name is unknown."""
        entry = self._entries.get(name)
        if entry is None:
            return False
        entry.enabled = True
        return True

    def disable(self, name: str) -> bool:
        """Take one reviewer out of the concurrent set; False when refused.

        Disabling is permitted for `base_check` — only removal is refused (MR4).
        The degraded audit row and the rate-limited alert that must accompany it
        belong to the caller that flips the switch, not to this in-memory map.

        `policy` is refused here as well (review finding S1): the configuration
        key that owns `base_check` must not be able to switch the hard denials
        off, so the deny layer reports False and stays in the concurrent set. The
        entry, its `enabled` flag and its order are left untouched.
        """
        entry = self._entries.get(name)
        if entry is None or name in _ALWAYS_ON_NAMES:
            return False
        entry.enabled = False
        return True

    def is_enabled(self, name: str) -> bool:
        """Return whether a registered reviewer currently participates."""
        entry = self._entries.get(name)
        return entry is not None and entry.enabled

    def is_builtin(self, name: str) -> bool:
        """Return whether a registered reviewer is protected from unregister."""
        entry = self._entries.get(name)
        return entry is not None and entry.builtin

    def get(self, name: str) -> Any | None:
        """Return the registered reviewer, or None when the name is unknown."""
        entry = self._entries.get(name)
        return None if entry is None else entry.reviewer

    def ordered(self) -> tuple[Any, ...]:
        """Return every registered reviewer by `(order, name)`, enabled or not."""
        return tuple(entry.reviewer for _, entry in self._sorted())

    def ordered_names(self) -> tuple[str, ...]:
        """Return every registered name by `(order, name)`."""
        return tuple(name for name, _ in self._sorted())

    def enabled(self) -> tuple[Any, ...]:
        """Return the enabled reviewers by `(order, name)`.

        This is the pipeline's only source of work: a reviewer absent here does
        not run and does not take part in the aggregation.
        """
        return tuple(entry.reviewer for _, entry in self._sorted() if entry.enabled)

    def enabled_names(self) -> tuple[str, ...]:
        """Return the enabled names by `(order, name)`."""
        return tuple(name for name, entry in self._sorted() if entry.enabled)

    def statuses(self) -> tuple[ReviewerStatus, ...]:
        """Return one status per registered reviewer, disabled ones included.

        A reviewer's own `status()` supplies busy/in_flight/last_*; the registry
        supplies `name`, `enabled` and `order`, so the truth about participation
        cannot be overridden from inside a reviewer. A status implementation that
        raises is reported as an error status rather than taking the page down.
        """
        return tuple(
            replace(
                _status_of(entry.reviewer),
                name=name,
                enabled=entry.enabled,
                order=_entry_order(entry),
            )
            for name, entry in self._sorted()
        )

    def _sorted(self) -> tuple[tuple[str, _Entry], ...]:
        """Return the entries in deterministic `(order, name)` presentation order."""
        return tuple(
            sorted(
                self._entries.items(),
                key=lambda item: (_entry_order(item[1]), item[0]),
            )
        )


def _entry_order(entry: _Entry) -> int:
    """Return the presentation order of one entry, honouring a replace hint."""
    if entry.order_hint is not None:
        return entry.order_hint
    return reviewer_order(entry.reviewer)


def _status_of(reviewer: Any) -> ReviewerStatus:
    """Return a reviewer's own status, or a fallback carrying its failure."""
    status = getattr(reviewer, "status", None)
    name = reviewer_name(reviewer)
    if callable(status):
        try:
            produced = status()
        except Exception as exc:  # noqa: BLE001 - a status page survives it
            return ReviewerStatus(name=name, last_error=f"{type(exc).__name__}: {exc}")
        if isinstance(produced, ReviewerStatus):
            return produced
    return ReviewerStatus(name=name)
