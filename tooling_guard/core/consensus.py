"""Consensus over the three layers. Requirement: Layered Consensus.

The plugin judges one call in three layers and this module is the only place the
three answers become one:

* the static layer may refuse outright -- a blacklisted requester, a denied
  path, a credential in the arguments, a sensitive configuration read, a
  downloaded or decoded payload handed to a shell. A refusal is final: no model
  can overturn it, and no model is even asked.
* the fast model (jev) reads the same payload and answers allow, deny or nothing
  at all. A deny is not a refusal -- it is a high-risk finding that needs a human
  to say yes explicitly.
* the deep model reads the same payload when jev asked for it, or when jev had no
  opinion. It can only add a second opinion, never remove the first.

The vote is the one the administrator asked for: one refusal refuses, one
approval approves, and a call nobody approved and nobody refused becomes an
approval request ("this looks unusual, confirm it"). An abstention is the
absence of an opinion, so it never refuses and never approves.

Every kind of approval request carries a `ticket_kind`, so the administrator's
card can say why they are being asked instead of looking identical every time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Iterable, Mapping

from .verdict import Decision, ReviewOutcome, Verdict, coerce_decision, coerce_outcome

#: Ticket kinds. One per reason an administrator is asked to approve.
TICKET_MODEL_DENY: Final[str] = "model_deny"
TICKET_MODEL_SUSPEND: Final[str] = "model_suspend"
TICKET_ALL_ABSTAIN: Final[str] = "all_abstain"
TICKET_KINDS: Final[tuple[str, ...]] = (
    TICKET_MODEL_DENY,
    TICKET_MODEL_SUSPEND,
    TICKET_ALL_ABSTAIN,
)

#: Decisions the static layer owns. A hit is final: the call is refused, and the
#: remaining layers are not consulted.
HARD_DENIALS: Final[tuple[Decision, ...]] = (
    Decision.DENY_REQUESTER,
    Decision.DENY_POLICY,
    Decision.DENIED_NO_WRAPPER,
    Decision.DENY_RULE,
)
#: Precedence when several static words arrive together, most specific first.
_HARD_DENIAL_RANK: Final[Mapping[Decision, int]] = {
    Decision.DENY_REQUESTER: 3,
    Decision.DENY_POLICY: 2,
    Decision.DENIED_NO_WRAPPER: 1,
    Decision.DENY_RULE: 0,
}

#: Every decision word that reads as "no". Used only for verdicts a model
#: reviewer produced, where any of them means the model objected.
_DENY_WORDS: Final[frozenset[Decision]] = frozenset(
    {
        Decision.DENY_JUDGE,
        Decision.DENY_REQUESTER,
        Decision.DENY_POLICY,
        Decision.DENIED_NO_WRAPPER,
        Decision.DENY_RULE,
    }
)

#: Reviewer names owned by the model layers. A denial that comes from one of them
#: is a finding that needs a human, never a refusal -- even when the verdict
#: carries a deny word the static vocabulary also uses. The guard is needed
#: because `Verdict` normalises a bare deny outcome onto `DENY_RULE`, so the
#: decision word alone cannot tell a static rule hit from a model objection.
#: The two names are the reviewers' own `NAME` constants; the harness asserts
#: they still match so this copy cannot drift silently.
MODEL_REVIEWERS: Final[frozenset[str]] = frozenset({"jev_fast", "llm_deep"})


@dataclass(frozen=True)
class Consensus:
    """One call's final decision, plus the kind of ticket it asks for."""

    #: The decision the caller acts on.
    decision: Decision
    #: The approval-request kind, or None when no administrator is asked.
    ticket_kind: str | None = None
    #: True when the static layer refused, so the models were not consulted.
    static_denial: bool = False

    @property
    def asks_human(self) -> bool:
        """Return whether this consensus turns into an approval request."""
        return self.ticket_kind is not None


def _split(verdicts: Iterable[Verdict]) -> tuple[list[Decision], list[Decision]]:
    """Split the decision words by the layer that produced them.

    Returns:
        The static words first, then the model words. A verdict with no decision
        word contributes to neither list -- it judged nothing.
    """
    static: list[Decision] = []
    model: list[Decision] = []
    for verdict in verdicts:
        word = coerce_decision(verdict.decision)
        if word is None:
            continue
        target = model if str(verdict.reviewer) in MODEL_REVIEWERS else static
        target.append(word)
    return static, model


def _approvals(verdicts: Iterable[Verdict]) -> int:
    """Return how many verdicts actually voted to let the call through.

    A `skip` is deliberately not an approval: it means "this call is not mine to
    judge", and treating it as a release is exactly the "nobody objected, so run
    it" default this design removes. Only an explicit `allow` votes yes.
    """
    return sum(
        1 for verdict in verdicts if coerce_outcome(verdict.outcome) is ReviewOutcome.ALLOW
    )


def _static_denial(words: Iterable[Decision]) -> Decision | None:
    """Return the static refusal word among the decisions, or None."""
    hits = [word for word in words if word in HARD_DENIALS]
    if not hits:
        return None
    return max(hits, key=lambda word: _HARD_DENIAL_RANK[word])


def consensus(verdicts: Iterable[Verdict]) -> Consensus:
    """Fold every reviewer verdict into the final decision.

    Requirement: Layered Consensus; Verdict Aggregation.

    The fold, in order:

    1. A static refusal wins over everything and consults nobody else.
    2. A model denial or a model suspension asks a human to approve the call. It
       is *not* a refusal: the model found the call risky, not impossible.
    3. Otherwise, one approval approves. "Nobody objected" is not an approval --
       the call needs a verdict that actually released it.
    4. A call with neither denial nor approval was judged by nobody, so a human
       is asked with `all_abstain`.

    Args:
        verdicts: Every verdict that arrived for this call, in any order. An
            empty sequence is a call nobody judged and folds to `all_abstain`.

    Returns:
        Consensus: The decision word, the ticket kind when a human is asked, and
        whether the static layer was the one that refused.
    """
    verdicts = tuple(verdicts)
    static, model = _split(verdicts)
    hard = _static_denial(static)
    if hard is not None:
        return Consensus(decision=hard, ticket_kind=None, static_denial=True)

    if any(word in _DENY_WORDS for word in model):
        return Consensus(decision=Decision.SUSPENDED, ticket_kind=TICKET_MODEL_DENY)
    if any(word is Decision.SUSPENDED for word in model):
        return Consensus(decision=Decision.SUSPENDED, ticket_kind=TICKET_MODEL_SUSPEND)

    if _approvals(verdicts):
        return Consensus(decision=Decision.ALLOW_PASSTHROUGH)

    return Consensus(decision=Decision.SUSPENDED, ticket_kind=TICKET_ALL_ABSTAIN)


__all__ = [
    "Consensus",
    "HARD_DENIALS",
    "MODEL_REVIEWERS",
    "TICKET_ALL_ABSTAIN",
    "TICKET_KINDS",
    "TICKET_MODEL_DENY",
    "TICKET_MODEL_SUSPEND",
    "consensus",
]
