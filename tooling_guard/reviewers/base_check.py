"""The base check adapter: requester lists, paths and content. Order 0.

Requirement: Reviewer Contract; Policy.

This adapter owns the *policy* stage of the triage chain and nothing else: it
calls the same `policy_stage` that `TriageEngine.fold_stages` folds, so a call
reaches the same policy word through the pipeline as through
`TriageEngine.decide`. Review finding S1 made that a shared ownership:
`reviewers/policy.py` runs the very same stage in an adapter the configuration
cannot disable, because `base_check_enabled=false` used to take the whole deny
layer with it. What this adapter keeps behind the switch is the last word below
-- the whitelist promotion -- which is the only *allow* the stage produces. What
that stage decides, in the order it decides it:

- the requester lists (`user_blacklist` blocks; `user_whitelist` only records a
  hint, so a whitelist hit never overrides a blacklist hit -- the existing
  `policy/allowlists.py` precedence, reused rather than re-implemented);
- path denials over normalised targets, then secret content, private keys and
  sensitive configuration files;
- the strict write whitelist, and finally the tier default.

The tier default is part of this stage on purpose: `policy/layers.py` puts it
there, a T-strong tool with no deny layer expects SUSPEND, and no other stage
owns that word. Moving it out would make the adapter chain release calls the
engine suspends -- a silent fail-open, not an accounting difference.

Whitelisted calls become an explicit ALLOW instead of a silent SKIP, so the
audit row can tell "allowed by a whitelist" from "not my call to judge".

This adapter never consults a model: its answer is pure in-memory matching, so
review() awaits nothing inside and declares BusyPolicy.SKIP.

review() also folds the three stages with the engine's own fold_stages and
publishes the result under DETAIL_FOLD. The extra rule pass is the same pure
matching the rules adapter runs, and it never changes this adapter's answer: the
published fold is what lets the caller report the engine's text instead of
writing a second mapping of its own.
"""

from __future__ import annotations

from typing import Final

from ..core.call import GuardCall
from ..core.reviewer import BusyPolicy
from ..core.verdict import Verdict
from ._common import (
    BuiltinReviewer,
    features_of,
    policy_of,
    policy_verdict,
    publish_fold,
    rules_of,
)

#: Registry name. core/registry.py protects BASE_CHECK_NAME from removal by
#: name as well as by the builtin flag; `base_check_enabled=false` may still
#: disable it, which is why the hard denials also run in reviewers/policy.py.
NAME: Final[str] = "base_check"

#: Presentation order: the cheapest, most deterministic stage first.
ORDER_BASE_CHECK: Final[int] = 0


class BaseCheckReviewer(BuiltinReviewer):
    """Judge one call against the allowlists, paths and content of the policy."""

    name = NAME
    order = ORDER_BASE_CHECK
    enabled = True
    busy_policy = BusyPolicy.SKIP

    async def _answer(self, call: GuardCall) -> Verdict:
        """Answer from the policy stage alone, publishing the folded outcome."""
        features = features_of(self.snapshot, call)
        stage = policy_of(self.snapshot, features, call)
        # A hint (reduce_latency / reduce_trajectory_depth) is never an
        # approval: this reviewer reports the whitelist prompt and nothing else,
        # so a hint-only call stays a SKIP and the models still judge it.
        verdict = policy_verdict(stage, reviewer=self.name)
        return publish_fold(
            verdict,
            features=features,
            policy=stage,
            rules=rules_of(features, self.trajectory(call)),
        )


__all__ = ["NAME", "ORDER_BASE_CHECK", "BaseCheckReviewer"]
