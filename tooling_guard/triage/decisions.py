"""Decision taxonomy. Requirement: Decision Taxonomy.

Requirement names owned here: Decision Taxonomy.

The twelve `decision` values and the five `would_be` values are spelled
out exactly once, here, so the audit row, the trajectory entry and the ticket
can never drift apart. Observe mode records the actual allow value in
`decision` and the intended action in `would_be`; a value outside the
enumerations is treated as a denial so no caller can act on an unknown verdict.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Final

from ..policy.layers import (
    LAYER_DENY_REQUESTER,
    PolicyDecision,
    PolicyOutcome,
)

MODE_ENFORCE: Final[str] = "enforce"
MODE_OBSERVE: Final[str] = "observe"

#: Recorded after the call ran untouched, with no judge stage shortening it.
ALLOW_PASSTHROUGH_VALUE: Final[str] = "allow_passthrough"


class Decision(str, Enum):
    """Actual effect of one judged call. Requirement: Decision Taxonomy."""

    ALLOW_PASSTHROUGH = "allow_passthrough"
    ALLOW_FAST = "allow_fast"
    ALLOW_TRAJECTORY = "allow_trajectory"
    ALLOW_APPROVED_RETRY = "allow_approved_retry"
    DENY_RULE = "deny_rule"
    DENY_JUDGE = "deny_judge"
    DENY_POLICY = "deny_policy"
    DENY_REQUESTER = "deny_requester"
    DENIED_NO_WRAPPER = "denied_no_wrapper"
    SUSPENDED = "suspended"
    TIMEOUT_DENY = "timeout_deny"
    CANCELED_EXTERNAL = "canceled_external"


class WouldBe(str, Enum):
    """Expected action, recorded only in observe mode. Requirement: Decision Taxonomy."""

    DENY_RULE = "deny_rule"
    DENY_JUDGE = "deny_judge"
    DENY_POLICY = "deny_policy"
    DENY_REQUESTER = "deny_requester"
    SUSPEND = "suspend"


ALLOW_DECISIONS: Final[frozenset[Decision]] = frozenset(
    {
        Decision.ALLOW_PASSTHROUGH,
        Decision.ALLOW_FAST,
        Decision.ALLOW_TRAJECTORY,
        Decision.ALLOW_APPROVED_RETRY,
    }
)
DENY_DECISIONS: Final[frozenset[Decision]] = frozenset(
    {
        Decision.DENY_RULE,
        Decision.DENY_JUDGE,
        Decision.DENY_POLICY,
        Decision.DENY_REQUESTER,
        Decision.DENIED_NO_WRAPPER,
        Decision.TIMEOUT_DENY,
        Decision.CANCELED_EXTERNAL,
    }
)
SUSPEND_DECISIONS: Final[frozenset[Decision]] = frozenset({Decision.SUSPENDED})

#: Expected action words that map onto WouldBe. "deny" is the generic policy
#: action word; every other entry is an enumerated deny_* value or suspend.
_WOULD_BE_BY_WORD: Final[dict[str, WouldBe]] = {
    "suspend": WouldBe.SUSPEND,
    "suspended": WouldBe.SUSPEND,
    "deny": WouldBe.DENY_POLICY,
    "denied": WouldBe.DENY_POLICY,
    "deny_rule": WouldBe.DENY_RULE,
    "deny_judge": WouldBe.DENY_JUDGE,
    "deny_policy": WouldBe.DENY_POLICY,
    "deny_requester": WouldBe.DENY_REQUESTER,
}


def coerce_decision(value: Any) -> Decision:
    """Read any produced value as an enumerated decision.

    Requirement: Decision Taxonomy; Fail-Closed Triage.

    Args:
        value: A Decision, the exact value word of one, its member name, or
            anything else at all.

    Returns:
        Decision: The matching member, or Decision.DENY_RULE when the value is
        not enumerated. A non-enumerated result is recorded as a denial; the
        caller can tell a downgrade happened because the raw value did not
        already equal the returned value.
    """
    if isinstance(value, Decision):
        return value
    word = value.strip().lower() if isinstance(value, str) else ""
    if word:
        for decision in Decision:
            if word == decision.value or word == decision.name.lower():
                return decision
    return Decision.DENY_RULE


def would_be_for(expected: Any) -> WouldBe | None:
    """Map one expected action onto the observe-mode vocabulary.

    Requirement: Decision Taxonomy.

    Args:
        expected: A Decision, a PolicyDecision, or the action word the layers
            produced ("deny", "suspend", "deny_policy", ...).

    Returns:
        WouldBe: suspend for a suspended call, the matching deny_* for a denial.
        None when the expected action is an allow or is not mappable.
    """
    if isinstance(expected, PolicyDecision):
        if expected is PolicyDecision.SUSPEND:
            return WouldBe.SUSPEND
        if expected is PolicyDecision.DENY:
            return WouldBe.DENY_POLICY
        return None
    word = expected.strip().lower() if isinstance(expected, str) else ""
    if word and word.startswith("allow"):
        return None
    return _WOULD_BE_BY_WORD.get(word)


def decision_from_policy(
    outcome: PolicyOutcome, *, mode: str = MODE_ENFORCE
) -> tuple[Decision, WouldBe | None]:
    """Translate one policy outcome into the decision vocabulary.

    Requirement: Decision Taxonomy; Shadow Observation Mode.

    Enforce maps an expected deny to deny_policy (deny_requester at the
    requester layer), an expected suspend to suspended, and an expected allow to
    allow_passthrough. Observe never yields a deny_* or suspend value: the call
    actually continues, so decision stays an allow value and would_be carries the
    expected action.

    Args:
        outcome: The PolicyOutcome of this call.
        mode: Effective enforcement mode, enforce or observe.

    Returns:
        tuple: The decision and, in observe only, the expected action.

    Raises:
        TypeError: outcome is not a PolicyOutcome.
    """
    if not isinstance(outcome, PolicyOutcome):
        raise TypeError("decision_from_policy 只接受 PolicyOutcome。")
    observe = is_observe_mode(mode) or outcome.would_be is not None
    expected = outcome.expected
    if expected is PolicyDecision.DENY:
        deny = (
            WouldBe.DENY_REQUESTER
            if outcome.layer == LAYER_DENY_REQUESTER
            else WouldBe.DENY_POLICY
        )
        if observe:
            return Decision.ALLOW_PASSTHROUGH, deny
        return _deny_decision_of(deny), None
    if expected is PolicyDecision.SUSPEND:
        if observe:
            return Decision.ALLOW_PASSTHROUGH, WouldBe.SUSPEND
        return Decision.SUSPENDED, None
    return Decision.ALLOW_PASSTHROUGH, None


def is_allow(decision: Any) -> bool:
    """Return whether a value is one of the four allow decisions."""
    return coerce_decision(decision) in ALLOW_DECISIONS


def is_deny(decision: Any) -> bool:
    """Return whether a value ends the call as a denial.

    An unrecognised value coerces to deny_rule, so this predicate is
    fail-closed: only an enumerated allow or suspended value is not a denial.
    """
    return coerce_decision(decision) in DENY_DECISIONS


def is_suspend(decision: Any) -> bool:
    """Return whether a value suspends the call for an administrator."""
    return coerce_decision(decision) in SUSPEND_DECISIONS


def is_observe_mode(mode: Any) -> bool:
    """Return whether a mode string means observe."""
    return isinstance(mode, str) and mode.strip().lower() == MODE_OBSERVE


def effective_mode(mode: Any, snapshot_mode: Any) -> str:
    """Return the mode both the policy layer and this module act in.

    Requirement: Shadow Observation Mode.

    Observe wins whenever either source says observe, because the policy layer
    already turned its own conclusion into decision=allow plus would_be and the
    triage must not re-enforce it. An unknown mode string resolves to enforce,
    which is the fail-closed reading.

    Args:
        mode: Mode requested by the caller.
        snapshot_mode: Mode carried by the policy snapshot.

    Returns:
        str: MODE_OBSERVE or MODE_ENFORCE.
    """
    if is_observe_mode(mode) or is_observe_mode(snapshot_mode):
        return MODE_OBSERVE
    return MODE_ENFORCE


def _deny_decision_of(expectation: WouldBe) -> Decision:
    """Return the enforce-mode deny decision matching one expected deny."""
    if expectation is WouldBe.DENY_REQUESTER:
        return Decision.DENY_REQUESTER
    if expectation is WouldBe.DENY_RULE:
        return Decision.DENY_RULE
    if expectation is WouldBe.DENY_JUDGE:
        return Decision.DENY_JUDGE
    return Decision.DENY_POLICY
