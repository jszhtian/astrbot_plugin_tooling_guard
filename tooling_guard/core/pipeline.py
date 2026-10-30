"""Concurrent reviewer fan-out, deny-only early stop, verdict aggregation.

Requirement: Concurrent Fan-Out and Deny-Only Early Stop; Verdict Aggregation.

Every enabled reviewer gets its own task and they all start before any of them
is awaited, so `order` never sequences anything: it only breaks ties in
`PipelineOutcome.verdicts`, in `/guard status` and in the audit line. An
implementation that walked the registry and awaited each reviewer in turn would
satisfy the same signatures and be wrong — it must not be written.

The three rules the aggregation exists for:

- Only the **first deny** stops the pipeline. It cancels whatever is still
  running, records those reviewer names in `preempted` and sets
  `terminated_early`.
- **Suspend never stops it.** A later deny still wins, and a suspension whose
  peers were still deciding is not a decided call, so the rest keep running
  until they answer or the pipeline deadline passes.
- A **release needs every participant** to answer allow or skip. A preempted
  reviewer counts as neither, which is why a preempted run denies: "nobody
  objected" is not an approval, and a call is never released because reviewers
  were absent, cancelled, broken or late.

Failure folds are all deny plus one marker: `reviewer_timeout:<name>` for a
reviewer over budget (the same fail-closed meaning `Decision.TIMEOUT_DENY` has
in `triage/`), `reviewer_error:<name>` for an exception or an unreadable
outcome. Busy is a fold, not a judgement: a reviewer that reports itself busy is
never asked, and the word comes from the policy the reviewer declared for itself
(`core/reviewer.py` BUSY_OUTCOMES), so this module executes the policy, records
`degraded=reviewer_busy:<name>` and sets `Verdict.busy` instead of inventing a
"busy means allow" default of its own.

`PipelineOutcome` is the single aggregate allowed into the audit row and the
notification (design.md:266): degraded markers are merged in reviewer order, one
per reviewer, deduplicated by text, and a preempted reviewer contributes no
marker at all — it appears in `preempted` instead. The aggregate is a pure
function of the verdict *set*: neither the reported decision word nor the
degraded tuple depends on which task happened to finish first (task 11.3 asserts
exact words), so ties inside one rank are broken by reviewer `order`, then name.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Final

from ..triage.decisions import (
    Decision,
    coerce_decision,
    is_deny,
    is_suspend,
)
from .call import GuardCall
from .registry import ReviewerRegistry
from .reviewer import (
    Reviewer,
    busy_of,
    busy_policy_of,
    outcome_for_busy,
    reviewer_name,
    reviewer_order,
)
from .consensus import consensus
from .verdict import (
    ReviewOutcome,
    Verdict,
    coerce_outcome,
    outcome_rank,
)

#: Per-reviewer budget, in seconds. It matches the fast-judge round-trip cap
#: (`jev/client.py` MAX_TIMEOUT_S = 50.0) so a reviewer that reaches for the judge
#: has room to finish, and it is per reviewer rather than per pipeline: one slow
#: reviewer cannot spend the whole call's budget on behalf of the others.
DEFAULT_REVIEWER_BUDGET_S: Final[float] = 5.0

#: Degradation markers. `{name}` is the reviewer's registered name.
TIMEOUT_MARKER: Final[str] = "reviewer_timeout:{name}"
ERROR_MARKER: Final[str] = "reviewer_error:{name}"
BUSY_MARKER: Final[str] = "reviewer_busy:{name}"

#: Marker for a pipeline that was handed no enabled reviewer at all.
NO_REVIEWERS_MARKER: Final[str] = "no_reviewers"

#: How long a deny may wait for the reviewers it just cancelled to settle. This
#: is a ceiling, not a delay: cancellation is delivered on the next loop tick, so
#: a well-behaved reviewer settles immediately. The ceiling exists so a reviewer
#: that swallows its own cancellation cannot hold a denial open.
PREEMPT_GRACE_S: Final[float] = 0.05


def degraded_marker(template: str, name: str) -> str:
    """Render one degradation marker for one reviewer.

    Args:
        template: One of `TIMEOUT_MARKER`, `ERROR_MARKER`, `BUSY_MARKER`.
        name: The reviewer's registered name.

    Returns:
        str: The marker the audit row and the notification carry.
    """
    return template.format(name=name)


@dataclass(frozen=True, slots=True)
class PipelineOutcome:
    """The one aggregate this package hands to audit and notification.

    Attributes:
        decision: The folded canonical decision: deny > suspend > allow. Both
            decision words come from `triage/decisions.py`; no word is invented
            here.
        verdicts: Every verdict, in completion order. A `Verdict` carries its own
            reviewer name, so the pair the spec asks for is
            `(verdict.reviewer, verdict)`.
        preempted: Names of the reviewers cancelled because an earlier verdict
            denied, in registry presentation order.
        terminated_early: True only when a deny actually cancelled unfinished
            work; a deny that arrived last stopped nothing.
        degraded: Merged, deduplicated degradation markers in reviewer order
            (declared `order`, then name), never in completion order.
        elapsed_s: Wall time of the whole fan-out, for diagnostics only.
        winner: The verdict the decision was taken from, or None when nobody
            answered. Ties inside one rank resolve to the lowest `order`, so this
            is stable run to run and 11.3 can name the denying reviewer.
    """

    decision: Decision
    verdicts: tuple[Verdict, ...] = ()
    preempted: tuple[str, ...] = ()
    terminated_early: bool = False
    degraded: tuple[str, ...] = ()
    elapsed_s: float = 0.0
    winner: Verdict | None = None

    def __post_init__(self) -> None:
        """Freeze the sequences and normalise the decision word."""
        object.__setattr__(self, "decision", coerce_decision(self.decision))
        for field_name in ("verdicts", "preempted", "degraded"):
            object.__setattr__(self, field_name, tuple(getattr(self, field_name)))

    @property
    def denies(self) -> bool:
        """Return whether the folded decision is a denial."""
        return is_deny(self.decision)

    @property
    def suspends(self) -> bool:
        """Return whether the folded decision waits for an administrator."""
        return is_suspend(self.decision)

    @property
    def releases(self) -> bool:
        """Return whether the call may proceed.

        True only when at least one reviewer answered, nothing was preempted and
        every verdict released. The "at least one" is load-bearing: an empty run
        must not read as an approval, because a release never derives from
        "no reviewer objected" (spec.md:75).
        """
        if not self.verdicts or self.preempted:
            return False
        return all(verdict.releases for verdict in self.verdicts)

    @property
    def by_reviewer(self) -> Mapping[str, Verdict]:
        """Return the verdicts keyed by reviewer name, in completion order."""
        return MappingProxyType(
            {verdict.reviewer: verdict for verdict in self.verdicts}
        )

    @property
    def busy_names(self) -> tuple[str, ...]:
        """Return the reviewers folded as busy, in completion order.

        Requirement: Verdict Aggregation. A busy fold carries the word its own
        policy declared, so the verdict alone does not say whether the reviewer
        judged the call; this names the folds so the audit line and the status
        page can tell "skipped because busy" from "answered skip".
        """
        return tuple(verdict.reviewer for verdict in self.verdicts if verdict.busy)


def merge_outcomes(*outcomes: PipelineOutcome | None) -> PipelineOutcome:
    """Fold the outcomes of several rounds into the one aggregate the caller uses.

    Requirement: Layered Consensus. The orchestration layer runs the layers in
    rounds (static + rules + fast judge first, the deep reviewer only when the
    fast judge asked for it), because the deep reviewer must not run when the
    fast one already denied. Each round is a full `ReviewPipeline` over a subset
    of the registry, so the aggregate has to be rebuilt from every round's
    verdicts -- folding the rounds' decision words instead would let one round's
    `no reviewers` answer outvote a real approval.

    Args:
        *outcomes: Round outcomes, in execution order; None entries are ignored so
            a caller can pass the optional second round directly.

    Returns:
        PipelineOutcome: One aggregate over every verdict of every round. The
        decision comes from the same `consensus` the single-round reader uses, so
        two-round and one-round calls agree by construction.
    """
    rounds = tuple(item for item in outcomes if item is not None)
    if not rounds:
        return PipelineOutcome(decision=Decision.DENY_RULE)
    if len(rounds) == 1:
        return rounds[0]
    verdicts = tuple(verdict for item in rounds for verdict in item.verdicts)
    winner: Verdict | None = None
    for verdict in verdicts:
        if winner is None or outcome_rank(verdict.outcome) > outcome_rank(winner.outcome):
            winner = verdict
    return PipelineOutcome(
        decision=consensus(verdicts).decision,
        verdicts=verdicts,
        preempted=tuple(name for item in rounds for name in item.preempted),
        terminated_early=any(item.terminated_early for item in rounds),
        degraded=tuple(dict.fromkeys(m for item in rounds for m in item.degraded)),
        elapsed_s=sum(item.elapsed_s for item in rounds),
        winner=winner,
    )


class ReviewPipeline:
    """Runs every enabled reviewer concurrently and folds their verdicts."""

    def __init__(
        self,
        registry: ReviewerRegistry,
        *,
        budget_s: float = DEFAULT_REVIEWER_BUDGET_S,
        budgets: Mapping[str, float] | None = None,
        deadline_s: float | None = None,
        only: Iterable[str] | None = None,
    ) -> None:
        """Create a pipeline over one registry.

        Args:
            registry: Source of the concurrent set. `registry.enabled()` is read
                once per call, so a reviewer disabled mid-call is not affected.
            budget_s: Default per-reviewer budget in seconds; 0 or less means no
                budget, which only tests and trusted local deployments should do.
            budgets: Per-reviewer budget overrides, keyed by reviewer name.
            deadline_s: Optional whole-fan-out deadline. Reviewers still running
                when it passes are fail-closed as `reviewer_timeout:<name>` and
                are *not* reported as preempted: nobody denied.
            only: Optional subset of reviewer names this round may run. Layered
                Consensus runs the orchestrator in rounds (static+rules+jev, then
                the deep reviewer only when the fast judge asked for it), and a
                round is expressed as one of these subsets. None keeps the whole
                enabled set.
        """
        self._registry = registry
        self._budget_s = float(budget_s)
        self._budgets = dict(budgets or {})
        self._deadline_s = None if deadline_s is None else float(deadline_s)
        self._only = None if only is None else frozenset(str(name) for name in only)

    @property
    def registry(self) -> ReviewerRegistry:
        """Return the registry this pipeline reads its concurrent set from."""
        return self._registry

    def _selected(self, reviewers: tuple[Reviewer, ...]) -> tuple[Reviewer, ...]:
        """Return the reviewers this round is allowed to run.

        Args:
            reviewers: The registry's enabled reviewers, in declared order.

        Returns:
            The same tuple, or only the members named by `only`. The order is
            preserved so `orders` (and therefore tie-breaking) is unchanged.
        """
        if self._only is None:
            return reviewers
        return tuple(item for item in reviewers if reviewer_name(item) in self._only)

    async def run(self, call: GuardCall) -> PipelineOutcome:
        """Judge one call with every enabled reviewer.

        Args:
            call: The immutable facts reviewers may see.

        Returns:
            PipelineOutcome: The aggregate. Never raises because of a reviewer.

        Raises:
            asyncio.CancelledError: When the *caller* cancelled this coroutine.
                Cancellation of the reviewers themselves (a preemption) is
                handled inside and never propagates; the caller's is re-raised
                after the reviewer tasks are cancelled, so a shutdown is not
                mistaken for a verdict.
        """
        started = time.perf_counter()
        reviewers = self._selected(self._registry.enabled())
        if not reviewers:
            return self._no_reviewers(started)

        # One immutable snapshot of the declared order, taken before any
        # reviewer runs: aggregation must not read a registry that may change
        # under it, and its result must not depend on arrival timing.
        orders = self._orders(reviewers)
        queue: asyncio.Queue[tuple[str, Verdict]] = asyncio.Queue()
        tasks: dict[str, asyncio.Task[Verdict]] = {
            reviewer_name(reviewer): asyncio.create_task(
                self._judge(reviewer, call, queue),
                name=f"guard-review:{reviewer_name(reviewer)}",
            )
            for reviewer in reviewers
        }

        verdicts: list[Verdict] = []
        preempted: list[str] = []
        terminated_early = False
        try:
            while tasks:
                entry = await self._next_verdict(queue, started)
                if entry is None:
                    # Whole-call deadline: whatever is still running fails closed
                    # and is *not* preempted, because nobody denied.
                    self._settle(queue, tasks, verdicts)
                    for name, task in tasks.items():
                        task.cancel()
                        verdicts.append(self._timeout_verdict(name, started))
                    await self._await_cancelled(tasks.values())
                    tasks.clear()
                    break
                name, verdict = entry
                tasks.pop(name, None)
                verdicts.append(verdict)
                if verdict.denies and tasks:
                    # A peer may have published in the same tick; count it before
                    # declaring anyone preempted, so only real losers are named.
                    self._settle(queue, tasks, verdicts)
                    if tasks:
                        terminated_early = True
                        preempted.extend(tasks)
                        for task in tasks.values():
                            task.cancel()
                        await self._await_cancelled(tasks.values())
                        tasks.clear()
        except asyncio.CancelledError:
            for task in tasks.values():
                task.cancel()
            # Bounded, exactly like the preemption path: when this coroutine
            # raises, no reviewer may still be running its own bookkeeping, or a
            # cancelled reviewer would give its in-flight slot back after the
            # caller already moved on.
            await self._await_cancelled(tasks.values())
            raise

        winner = self._worst_verdict(verdicts, orders)
        decision, degraded = self._aggregate(verdicts, preempted, orders)
        return PipelineOutcome(
            decision=decision,
            verdicts=tuple(verdicts),
            preempted=tuple(preempted),
            terminated_early=terminated_early,
            degraded=degraded,
            elapsed_s=time.perf_counter() - started,
            winner=winner,
        )

    def _no_reviewers(self, started: float) -> PipelineOutcome:
        """Return the aggregate for a call nobody is registered to judge.

        Absent reviewers cannot release a call (spec.md:75), so an empty
        concurrent set denies and says why in `degraded`.
        """
        return PipelineOutcome(
            decision=Decision.DENY_RULE,
            degraded=(NO_REVIEWERS_MARKER,),
            elapsed_s=time.perf_counter() - started,
        )

    async def _judge(
        self,
        reviewer: Reviewer,
        call: GuardCall,
        queue: asyncio.Queue[tuple[str, Verdict]],
    ) -> Verdict:
        """Judge one call with one reviewer, folding every failure into a verdict.

        Only `asyncio.CancelledError` escapes; a preemption therefore stays
        visible as a cancelled task instead of turning into a denial nobody
        asked for. The verdict is published on the queue *before* this task
        returns, which is what makes `PipelineOutcome.verdicts` a completion
        order rather than a guess.
        """
        name = reviewer_name(reviewer)
        started = time.perf_counter()
        if busy_of(reviewer):
            verdict = self._busy_verdict(reviewer, name, started)
            queue.put_nowait((name, verdict))
            return verdict
        budget = self._budget_for(name)
        try:
            produced = await asyncio.wait_for(reviewer.review(call), budget)
        except TimeoutError:
            # asyncio.wait_for cancels the inner call *and awaits it* before
            # raising, so the reviewer coroutine has already unwound here: the
            # count it took in review() is back to zero and no coroutine of ours
            # survives the timeout to settle a second time.
            verdict = self._timeout_verdict(name, started)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - fail closed; a reviewer may not raise
            verdict = Verdict(
                reviewer=name,
                outcome=ReviewOutcome.DENY,
                reason=f"reviewer raised {type(exc).__name__}: {exc}",
                degraded=degraded_marker(ERROR_MARKER, name),
                elapsed_s=time.perf_counter() - started,
            )
        else:
            verdict = self._fold(name, produced, time.perf_counter() - started)
        queue.put_nowait((name, verdict))
        return verdict

    async def _next_verdict(
        self,
        queue: asyncio.Queue[tuple[str, Verdict]],
        started: float,
    ) -> tuple[str, Verdict] | None:
        """Await the next verdict, or None once the pipeline deadline has passed."""
        while True:
            remaining = self._deadline_remaining(started)
            if remaining is not None and remaining <= 0:
                return None
            try:
                return await asyncio.wait_for(queue.get(), timeout=remaining)
            except TimeoutError:
                return None

    def _settle(
        self,
        queue: asyncio.Queue[tuple[str, Verdict]],
        tasks: dict[str, asyncio.Task[Verdict]],
        verdicts: list[Verdict],
    ) -> None:
        """Collect verdicts published but not yet read.

        A reviewer that published in the same loop tick as a denial finished
        before it was cancelled, so its verdict counts and it is never reported
        as preempted: only a task still running when the denial lands is.
        """
        while True:
            try:
                name, verdict = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            if tasks.pop(name, None) is None:
                continue
            verdicts.append(verdict)

    async def _await_cancelled(self, tasks: Iterable[asyncio.Task[Verdict]]) -> None:
        """Wait, bounded, for cancelled reviewer tasks to settle.

        Bound: `PREEMPT_GRACE_S`. They are cancelled, so their verdicts are gone
        either way — this only stops them outliving the outcome.
        """
        pending = [task for task in tasks if task is not None]
        if pending:
            await asyncio.wait(pending, timeout=PREEMPT_GRACE_S)

    def _fold(self, name: str, produced: Any, elapsed: float) -> Verdict:
        """Turn whatever a reviewer returned into a verdict under its name."""
        if isinstance(produced, Verdict):
            return replace(
                produced,
                reviewer=name,
                elapsed_s=produced.elapsed_s or elapsed,
            )
        outcome = coerce_outcome(produced)
        if outcome is None:
            return Verdict(
                reviewer=name,
                outcome=ReviewOutcome.DENY,
                reason=f"unusable reviewer outcome: {produced!r}",
                degraded=degraded_marker(ERROR_MARKER, name),
                elapsed_s=elapsed,
            )
        return Verdict(reviewer=name, outcome=outcome, elapsed_s=elapsed)

    def _busy_verdict(self, reviewer: Reviewer, name: str, started: float) -> Verdict:
        """Fold one reviewer that declined because it is busy.

        Requirement: Verdict Aggregation. The reviewer is not asked at all, and
        the word is the one its own `busy_policy` declares: this method only
        executes that policy and records `degraded=reviewer_busy:<name>`, so no
        branch here can release a call the reviewer itself would have refused.
        `Verdict.busy` marks the answer as a fold rather than a judgement.
        """
        return Verdict(
            reviewer=name,
            outcome=outcome_for_busy(busy_policy_of(reviewer)),
            reason=f"reviewer {name} folded as busy by its own policy",
            degraded=degraded_marker(BUSY_MARKER, name),
            elapsed_s=time.perf_counter() - started,
            busy=True,
        )

    def _timeout_verdict(self, name: str, started: float) -> Verdict:
        """Return the abstention verdict for a reviewer that ran out of time.

        Requirement: Layered Consensus. A reviewer that ran out of time judged
        nothing, so it abstains instead of denying: only the static layer refuses
        a call on its own, and a slow model is not a refusal. The degraded marker
        still names the timeout, so an audit row can tell "the model said no" from
        "the model never answered" -- the two now lead to different ticket kinds.
        """
        return Verdict(
            reviewer=name,
            outcome=ReviewOutcome.SKIP,
            reason="reviewer exceeded its time budget",
            degraded=degraded_marker(TIMEOUT_MARKER, name),
            elapsed_s=time.perf_counter() - started,
        )

    def _budget_for(self, name: str) -> float | None:
        """Return the budget for one reviewer, or None for no budget."""
        budget = self._budgets.get(name, self._budget_s)
        return budget if budget > 0 else None

    def _deadline_remaining(self, started: float) -> float | None:
        """Return the time left before the pipeline deadline, None when unbounded."""
        if self._deadline_s is None:
            return None
        return self._deadline_s - (time.perf_counter() - started)

    def _aggregate(
        self,
        verdicts: Iterable[Verdict],
        preempted: Iterable[str],
        orders: Mapping[str, int],
    ) -> tuple[Decision, tuple[str, ...]]:
        """Fold verdicts into one decision and the merged degradation list.

        Requirement: Layered Consensus; Verdict Aggregation.

        The fold itself lives in `core.consensus`, because the orchestration layer
        runs the layers in two rounds and must reach the same decision as this
        single-round reader: one static refusal refuses, one model denial asks a
        human, one approval approves, and a call nobody approved becomes an
        approval request. A preempted reviewer never releases anything -- it
        contributed no verdict, and the consensus requires an explicit approval
        rather than the absence of an objection, so preemption cannot turn into a
        release here.
        """
        verdicts = tuple(verdicts)
        decision = consensus(verdicts).decision
        return decision, self._degraded(verdicts, orders)

    def _worst_verdict(
        self,
        verdicts: Iterable[Verdict],
        orders: Mapping[str, int],
    ) -> Verdict | None:
        """Return the verdict the decision is taken from, deterministically.

        Strictest rank wins; inside one rank the lowest declared `order` wins,
        then the lowest name. Completion order is deliberately not an input, so
        the same set of verdicts always yields the same decision word, reason and
        reviewer.
        """
        winner: Verdict | None = None
        for verdict in verdicts:
            if winner is None:
                winner = verdict
                continue
            rank = outcome_rank(verdict.outcome)
            best = outcome_rank(winner.outcome)
            tied = rank == best and self._rank_key(verdict, orders) < self._rank_key(
                winner, orders
            )
            if rank > best or tied:
                winner = verdict
        return winner

    def _rank_key(self, verdict: Verdict, orders: Mapping[str, int]) -> tuple[int, str]:
        """Return the deterministic tie-break key of one verdict."""
        return (orders.get(verdict.reviewer, 0), verdict.reviewer)

    def _degraded(
        self,
        verdicts: Iterable[Verdict],
        orders: Mapping[str, int],
    ) -> tuple[str, ...]:
        """Merge degradation markers in reviewer order, deduplicated by text.

        Ordering is `(declared order, marker)`, never completion order: the same
        verdict set must produce the same tuple run to run.
        """
        lowest: dict[str, int] = {}
        for verdict in verdicts:
            marker = verdict.degraded
            if not marker:
                continue
            order = orders.get(verdict.reviewer, 0)
            if marker not in lowest or order < lowest[marker]:
                lowest[marker] = order
        return tuple(
            marker
            for _, marker in sorted((order, marker) for marker, order in lowest.items())
        )

    def _orders(self, reviewers: Iterable[Reviewer]) -> Mapping[str, int]:
        """Snapshot every reviewer's declared order, keyed by name."""
        return MappingProxyType(
            {
                reviewer_name(reviewer): reviewer_order(reviewer)
                for reviewer in reviewers
            }
        )
