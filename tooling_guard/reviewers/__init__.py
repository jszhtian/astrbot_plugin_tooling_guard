"""The five built-in reviewers: policy, base check, rules, fast judge, slow path.

Requirement: Reviewer Contract; Verdict Aggregation.

Each adapter owns exactly one stage of the triage chain and answers with a
Verdict; the pipeline, not the adapters, folds those answers into one decision.
Nothing here writes an audit row, a notification or a ticket -- degradation and
refusal travel through Verdict and ReviewerStatus and are persisted by the
gateway, which is the only component that owns the store.

`register_builtin_reviewers` is the single wiring point: it registers the five
adapters with `builtin=True`, which is what makes core/registry.py refuse to
unregister them.

`policy` and `base_check` both run the *policy* stage, and that is deliberate
(review finding S1). The hard denials -- requester blacklist, path denials, secret
content, private keys, sensitive configuration, the write whitelist and the
T-strong suspend default -- must survive `base_check_enabled=false`, so they live
in an adapter the configuration cannot disable; `base_check` keeps the half the
switch is allowed to own (promoting a whitelist hit into an explicit allow) and
still carries the disable audit row and alert written by the gateway. One stage,
two adapters, no second mapping: both call `policy_of`/`policy_verdict`.
"""

from __future__ import annotations

from typing import Any, Final

from ..core.registry import ReviewerRegistry
from .base_check import NAME as BASE_CHECK_NAME
from .base_check import BaseCheckReviewer
from .jev_fast import NAME as JEV_FAST_NAME
from .jev_fast import JevFastReviewer
from .llm_deep import NAME as LLM_DEEP_NAME
from .llm_deep import DeepReviewReviewer
from .policy import NAME as POLICY_NAME
from .policy import PolicyReviewer
from .rules import NAME as RULES_NAME
from .rules import RulesReviewer

#: Registration order of the five adapters, the non-disableable deny layer first
#: and the cheapest, most deterministic stages ahead of the model ones. It is
#: also the presentation order they declare.
BUILTIN_NAMES: Final[tuple[str, ...]] = (
    POLICY_NAME,
    BASE_CHECK_NAME,
    RULES_NAME,
    JEV_FAST_NAME,
    LLM_DEEP_NAME,
)


def register_builtin_reviewers(
    registry: ReviewerRegistry,
    *,
    snapshot: Any,
    fast_judge: Any = None,
    deep_judge: Any = None,
    deep_budget_s: float | None = None,
    trajectory_of: Any = None,
    deadline_of: Any = None,
) -> tuple[Any, ...]:
    """Register the five built-in adapters and return them in order.

    Args:
        registry: The registry to populate.
        snapshot: The immutable policy snapshot every adapter judges against.
        fast_judge: Optional judge for the fast adapter.
        deep_judge: Optional judge for the slow adapter.
        deep_budget_s: Optional injected budget for one slow request.
        trajectory_of: Optional reader of the read-only trajectory window.
        deadline_of: Optional reader of the caller budget.

    Returns:
        tuple: The registered adapters, in presentation order.
    """
    reviewers = (
        PolicyReviewer(snapshot=snapshot, trajectory_of=trajectory_of),
        BaseCheckReviewer(snapshot=snapshot, trajectory_of=trajectory_of),
        RulesReviewer(snapshot=snapshot, trajectory_of=trajectory_of),
        JevFastReviewer(
            snapshot=snapshot,
            judge=fast_judge,
            trajectory_of=trajectory_of,
            deadline_of=deadline_of,
        ),
        DeepReviewReviewer(
            snapshot=snapshot,
            deep_judge=deep_judge,
            budget_s=deep_budget_s,
            trajectory_of=trajectory_of,
            deadline_of=deadline_of,
        ),
    )
    for reviewer in reviewers:
        registry.register(reviewer, builtin=True)
    return reviewers


__all__ = [
    "BUILTIN_NAMES",
    "BaseCheckReviewer",
    "DeepReviewReviewer",
    "JevFastReviewer",
    "PolicyReviewer",
    "RulesReviewer",
    "register_builtin_reviewers",
]
