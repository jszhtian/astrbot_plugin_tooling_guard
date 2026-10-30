"""The policy stage as its own reviewer: the hard denials no switch can remove.

Requirement: Reviewer Contract; Policy; Built-in Base Checker.

`base_check_enabled=false` used to take this stage out of the gateway entirely
(review finding S1): the user blacklist, `path_deny` over normalised targets,
secret content, private keys, sensitive configuration, the strict write whitelist
and the T-strong suspend default all hung off one removable adapter, so the
configuration switch turned a deny layer into a release path -- `cat
~/.ssh/id_rsa`, a read of a private key, a write inside `path_deny` and a
blacklisted requester were all executed.

This adapter is the fix, and it is the *whole* of it: it runs the same
`policy_stage` / `policy_verdict` pair `reviewers/base_check.py` runs, over the
same `policy_of` / `features_of` helpers and the same published fold, so there is
still exactly one mapping from the policy stage onto a verdict. What differs is
who owns it: this one is registered `builtin=True`, and core/registry.py refuses
both `unregister` and `disable` for its name, so no configuration key can remove
it and no caller can switch it off.

The switch keeps the other half of the stage: a whitelist hit is promoted from a
silent skip into an explicit ALLOW (`policy_verdict` does that for both
reviewers, from the policy outcome itself) so the audit row can tell "allowed by
a whitelist" from "not my call to judge". That promotion is the only *allow* the
stage can produce, and no allow-side hint may produce one: under the consensus
rule one approval approves, so a hint that became an ALLOW would release every
call that merely sits inside a project root.

Order -10 is load-bearing, not decoration: the pipeline folds the strictest
outcome and breaks a tie by the lowest order, so when this stage and another
reviewer both tighten, the audit row carries the policy layer's own reason.

This adapter consults no model -- pure in-memory matching -- so it declares
BusyPolicy.SKIP and never awaits inside review().
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

#: Registry name. core/registry.py protects POLICY_NAME from removal *and* from
#: being disabled, by name as well as by the builtin flag.
NAME: Final[str] = "policy"

#: Presentation order: before base_check (0), because this is the stage that must
#: win the aggregation tie-break once both adapters tighten the same call.
ORDER_POLICY: Final[int] = -10


class PolicyReviewer(BuiltinReviewer):
    """Judge one call against the policy stage, and never promote a whitelist."""

    name = NAME
    order = ORDER_POLICY
    enabled = True
    busy_policy = BusyPolicy.SKIP

    async def _answer(self, call: GuardCall) -> Verdict:
        """Answer from the policy stage alone, publishing the folded outcome."""
        features = features_of(self.snapshot, call)
        stage = policy_of(self.snapshot, features, call)
        verdict = policy_verdict(stage, reviewer=self.name)
        return publish_fold(
            verdict,
            features=features,
            policy=stage,
            rules=rules_of(features, self.trajectory(call)),
        )


__all__ = ["NAME", "ORDER_POLICY", "PolicyReviewer"]
