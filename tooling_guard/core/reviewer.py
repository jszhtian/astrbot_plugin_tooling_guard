"""The reviewer contract: status, busy policy, protocol.

Requirement: Reviewer Contract.

A reviewer answers one question about one `GuardCall` and does nothing else: no
audit row, no notification, no ticket, no sqlite write, no approval consumption.
Everything it returns is a value the pipeline folds, so the only things this
module owns are the shape of that value and the three-state busy policy each
reviewer declares for itself (MR3).

The busy fold belongs to the reviewer, not to the base module: the pipeline
executes the declared policy and records `degraded=reviewer_busy:<name>`, and it
never invents a "busy means allow" default (see `### Requirement: Verdict
Aggregation`).

`ReviewerStatus` is what `/guard status` and `GET /guard/api/status` render. The
registry, not the reviewer, decides `enabled` and the presentation `order`, so a
reviewer's own status cannot promote itself back into the concurrent set.
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Protocol, runtime_checkable

from .call import GuardCall
from .verdict import ReviewOutcome, Verdict


class BusyPolicy(str, Enum):
    """How one busy reviewer folds its own answer. Requirement: Reviewer Contract.

    Three states, chosen by the reviewer and executed — never second-guessed — by
    the pipeline: SKIP contributes a skip plus `degraded=reviewer_busy:<name>`,
    FAIL_CLOSED suspends so an administrator decides, DENY denies outright.
    """

    SKIP = "skip"
    FAIL_CLOSED = "fail_closed"
    DENY = "deny"


#: Fold of one busy policy onto the reviewer vocabulary.
BUSY_OUTCOMES: Final[Mapping[BusyPolicy, ReviewOutcome]] = MappingProxyType(
    {
        BusyPolicy.SKIP: ReviewOutcome.SKIP,
        BusyPolicy.FAIL_CLOSED: ReviewOutcome.SUSPEND,
        BusyPolicy.DENY: ReviewOutcome.DENY,
    }
)


def outcome_for_busy(policy: Any) -> ReviewOutcome:
    """Return the outcome one busy policy folds to.

    Requirement: Reviewer Contract.

    Args:
        policy: A `BusyPolicy` member, its exact lowercase value word, or
            anything else at all.

    Returns:
        ReviewOutcome: The folded outcome; an unrecognised policy denies, because
        a busy reviewer whose policy nobody can read must not release a call.
    """
    if isinstance(policy, BusyPolicy):
        return BUSY_OUTCOMES[policy]
    if isinstance(policy, str):
        for candidate in BusyPolicy:
            if policy == candidate.value:
                return BUSY_OUTCOMES[candidate]
    return ReviewOutcome.DENY


def busy_policy_of(reviewer: Any) -> Any:
    """Return the busy policy a reviewer declares for itself, unjudged.

    Requirement: Verdict Aggregation. The pipeline executes the declared policy
    and nothing else (design.md:240), so this accessor never substitutes one: an
    unreadable declaration comes back as None and `outcome_for_busy` folds it
    into a deny, because a busy reviewer whose policy nobody can read must not
    release a call.

    Args:
        reviewer: Any object claiming to be a reviewer.

    Returns:
        The declared `busy_policy` value, or None when it cannot be read.
    """
    return getattr(reviewer, "busy_policy", None)


def busy_of(reviewer: Any) -> bool:
    """Return whether a reviewer reports itself busy right now.

    Requirement: Verdict Aggregation. The signal is the reviewer's own
    `status().busy`, so the busy fold is a declaration and never a guess: a
    reviewer whose status cannot be read is not reported busy and is simply
    asked, and a status that raises during display must not turn into a
    degradation marker nobody produced.

    Args:
        reviewer: Any object claiming to be a reviewer.

    Returns:
        True only when `status()` answered and reported busy.
    """
    reported = False
    with contextlib.suppress(Exception):
        reported = bool(getattr(reviewer.status(), "busy", False))
    return reported


@dataclass(frozen=True, slots=True)
class ReviewerStatus:
    """One reviewer's observable state. Requirement: Reviewer Contract.

    Attributes:
        name: Stable unique id, the registry key.
        enabled: Whether the registry currently lets this reviewer run. The
            registry overwrites this, so a status page can say "disabled" rather
            than "missing" for a reviewer that is still registered.
        order: Presentation order, from the registry.
        busy: Whether the reviewer reports itself busy right now.
        in_flight: How many calls this reviewer is currently judging.
        last_error: Last failure text, sanitised by the caller before display.
        last_degraded: Last degradation marker this reviewer produced.
        last_elapsed_s: How long its last answer took.
        last_outcome: Its last four-state answer.
    """

    name: str
    enabled: bool = True
    order: int = 0
    busy: bool = False
    in_flight: int = 0
    last_error: str | None = None
    last_degraded: str | None = None
    last_elapsed_s: float = 0.0
    last_outcome: ReviewOutcome | None = None


@runtime_checkable
class Reviewer(Protocol):
    """What the pipeline needs from a reviewer. Requirement: Reviewer Contract.

    `order` is presentation only: it breaks ties in `PipelineOutcome.verdicts`,
    in `/guard status` and in the audit line. Every enabled reviewer is started
    concurrently, so `order` never sequences execution (MR5).

    `review` may return a `Verdict`, one of the four `ReviewOutcome` words, or
    `None`. `None` and every other unreadable value are folded as a deny with
    `degraded=reviewer_error:<name>`: an answer nobody can read is not an answer.
    """

    name: str
    order: int
    enabled: bool
    busy_policy: BusyPolicy

    async def review(self, call: GuardCall) -> Verdict | None:
        """Answer for one call."""
        ...

    def status(self) -> ReviewerStatus:
        """Return this reviewer's own observable state."""
        ...


def reviewer_name(reviewer: Any) -> str:
    """Return a reviewer's stable name.

    Args:
        reviewer: Any object claiming to be a reviewer.

    Returns:
        str: Its non-empty `name`.

    Raises:
        TypeError: `name` is missing or not a non-empty string.
    """
    name = getattr(reviewer, "name", None)
    if not isinstance(name, str) or not name.strip():
        raise TypeError("a reviewer must expose a non-empty str name")
    return name


def reviewer_order(reviewer: Any) -> int:
    """Return a reviewer's presentation order, 0 when it declares none."""
    try:
        return int(getattr(reviewer, "order", 0))
    except (TypeError, ValueError):
        return 0


def validate_reviewer(reviewer: Any) -> str:
    """Check the contract surface of a reviewer before it is registered.

    Args:
        reviewer: Any object claiming to be a reviewer.

    Returns:
        str: Its name, once the surface checks pass.

    Raises:
        TypeError: The name is unusable, `review` is not callable, or no
            `busy_policy` is declared. Failing at registration keeps an
            unusable reviewer out of the concurrent set instead of turning every
            later call into a reviewer error.
    """
    name = reviewer_name(reviewer)
    if not callable(getattr(reviewer, "review", None)):
        raise TypeError(f"reviewer {name!r} must expose a callable review(call)")
    if not hasattr(reviewer, "busy_policy"):
        raise TypeError(f"reviewer {name!r} must declare a busy_policy")
    return name
