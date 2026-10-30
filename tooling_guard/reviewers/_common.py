"""Shared plumbing for the built-in reviewer adapters.

Requirement: Reviewer Contract; Verdict Aggregation.

Every adapter in this package owns exactly one stage of the triage chain and
calls the same stage function that TriageEngine.fold_stages folds
(tooling_guard/triage/engine.py). Nothing here re-implements a rule, a policy
layer or a read of a judge answer: this module only turns one stage result into
one Verdict, and keeps the per-reviewer bookkeeping ReviewerStatus reports.

Why adapters recompute pure stages: the pipeline starts every enabled reviewer
concurrently and never hands one reviewer's answer to another, so jev_fast and
llm_deep recompute the policy and rule stages for themselves in order to decide
their own preconditions. That duplication is deliberate -- those stages are pure
in-memory matching with no IO, no clock and no store, so the extra cost is
microseconds, and the alternative (a shared mutable cache of stage results)
would make one reviewer's answer depend on another reviewer's timing. No
adapter relies on the pipeline execution order either.

What no adapter does here: write an audit row, send a notification, open a
ticket or take a lock. Degradation travels only through Verdict.degraded and
ReviewerStatus; persisting it belongs to the Gateway slice.

Fail-closed shape: a raise from a stage function is mapped onto the same
verdict the engine's own try/except produces (deny_policy plus the
triage_error:<Type> marker), so one broken snapshot reads the same way through
the pipeline as through TriageEngine.decide. The exception text stays visible in
ReviewerStatus.last_error.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import Any, Final

from ..core.call import GuardCall
from ..core.reviewer import BusyPolicy, ReviewerStatus
from ..core.verdict import ReviewOutcome, Verdict
from ..policy.layers import LAYER_WHITELIST
from ..triage.classify import CallFeatures
from ..triage.decisions import (
    Decision,
    WouldBe,
    coerce_decision,
    decision_from_policy,
    effective_mode,
    is_deny,
    is_observe_mode,
    is_suspend,
)
from ..triage.engine import (
    REASON_TRIAGE_ERROR,
    SKIP_NO_JUDGE,
    Judge,
    JudgeStage,
    PolicyStage,
    RulesStage,
    TriageStages,
    classify_features,
    current_call_base,
    fold_stages,
    policy_stage,
    rule_stage,
)
from ..triage.rules import ACTION_DENY, ACTION_OBSERVE, ACTION_SUSPEND

#: Detail keys every adapter publishes on its Verdict.
DETAIL_ANSWER: Final[str] = "answer"
DETAIL_CONSULTED: Final[str] = "consulted"
DETAIL_DENIED_TARGETS: Final[str] = "denied_targets"
#: The folded triage outcome of this call, published by publish_fold below. Its
#: sub-keys are the DETAIL_* names of this block, so a reader that reports the
#: fold needs no vocabulary of its own.
DETAIL_FOLD: Final[str] = "fold"
#: Taint labels of the classified call, published inside DETAIL_FOLD.
DETAIL_LABELS: Final[str] = "labels"
DETAIL_LAYER: Final[str] = "layer"
#: The folded reason, rule identifiers included, published inside DETAIL_FOLD.
DETAIL_REASON: Final[str] = "reason"
DETAIL_RULE_ID: Final[str] = "rule_id"
DETAIL_RULE_IDS: Final[str] = "rule_ids"
#: What a consulted judge actually said, kept next to the word its banding
#: produced: score in percent, confidence in 0.0-1.0, and the confidence
#: annotation. The approval page shows them so an administrator sees the number
#: behind a suspension instead of a verdict alone.
DETAIL_SCORE: Final[str] = "score"
DETAIL_CONFIDENCE: Final[str] = "confidence"
DETAIL_NOTE: Final[str] = "note"
DETAIL_SEVERITY: Final[str] = "severity"
DETAIL_SKIPPED: Final[str] = "skipped"
DETAIL_WOULD_BE: Final[str] = "would_be"

#: Skip words a stage result can carry in Verdict.detail, so an audit row can
#: say why a reviewer stayed silent instead of pretending it approved. These
#: words are all one family: a reason nobody spent a request on this call.
SKIP_NO_MATCH: Final[str] = "no_match"
SKIP_OBSERVE_ONLY: Final[str] = "observe_only"
SKIP_NOT_SUSPICIOUS: Final[str] = "not_suspicious"
#: The whitelist already released the call, so no model request is spent. It
#: repeats LAYER_WHITELIST on purpose: the skip word and the layer name are the
#: same fact read from the same source, and an audit row can match either.
SKIP_WHITELISTED: Final[str] = "whitelisted"
#: A consulted judge that produced no readable approval or denial. The word is
#: deliberately distinct from every skip word above: those mean "no request was
#: made", this one means "a request was made and it declined to decide".
SKIP_ABSTAINED: Final[str] = "abstained"

#: Marker prefix of a stage failure, matching TriageEngine's fail-closed shape.
TRIAGE_ERROR_PREFIX: Final[str] = "triage_error:"


def features_of(snapshot: Any, call: GuardCall) -> CallFeatures:
    """Classify one guarded call exactly as TriageEngine.decide does."""
    return classify_features(snapshot, call.tool_name, call.arguments)


def policy_of(snapshot: Any, features: CallFeatures, call: GuardCall) -> PolicyStage:
    """Run the policy stage over the call identity and its classified features."""
    return policy_stage(
        snapshot,
        features,
        call.arguments,
        subject_key=call.subject_key,
        mode=call.mode,
        base=current_call_base(),
    )


def rules_of(features: CallFeatures, trajectory: Any = None) -> RulesStage:
    """Run the rule catalogue over the features and the read-only trajectory."""
    return rule_stage(features, trajectory)


def observe_of(snapshot: Any, call: GuardCall) -> bool:
    """Return whether this call is judged in observe mode."""
    mode = effective_mode(call.mode, getattr(snapshot, "mode", call.mode))
    return is_observe_mode(mode)


def outcome_for(decision: Any, would_be: Any = None) -> ReviewOutcome:
    """Fold one decided word onto the four-state reviewer vocabulary.

    A shadow decision keeps its expected outcome in Verdict.detail, so the
    observe fold stays visible instead of being lost as a plain release.
    """
    word = coerce_decision(decision)
    if is_deny(word):
        return ReviewOutcome.DENY
    if is_suspend(word):
        return ReviewOutcome.SUSPEND
    if would_be is not None:
        return ReviewOutcome.ALLOW
    return ReviewOutcome.SKIP


def skip_verdict(
    reviewer: str,
    *,
    skipped: str,
    reason: str = "",
    detail: Mapping[str, Any] | None = None,
) -> Verdict:
    """Build the verdict of a reviewer that is not judging this call."""
    payload: dict[str, Any] = {DETAIL_SKIPPED: skipped}
    if detail:
        payload.update(detail)
    return Verdict(
        reviewer=reviewer,
        outcome=ReviewOutcome.SKIP,
        decision=Decision.ALLOW_PASSTHROUGH,
        reason=reason,
        detail=payload,
    )


def skips_model_review(policy: PolicyStage) -> bool:
    """Return whether the static layer already released this call by itself.

    Requirement: Static Deny Only; Whitelist Shortcut.

    One judgement, read off one fact: the policy stage says the deciding layer
    was LAYER_WHITELIST, i.e. the requester or every target matched the
    configured whitelist (tooling_guard/policy/layers.py). A whitelist hit is
    the one and only static approval in this design -- everything else the static
    layer can say is either a hard denial or PASS, and PASS means "no opinion,
    ask the models". Recomputing the whitelist here would put the same match in
    two places and the copies would drift; the layer name is therefore the only
    input, and it is read from the outcome, never re-derived.

    There is no exec exception any more. The old trust switch needed one because
    project_roots bounds a path but never bounds what a shell or python command
    reaches at run time; a whitelist entry is a different statement -- it names
    the requester or the exact destination the operator has already accepted --
    so a whitelisted shell call is released on purpose, and a non-whitelisted
    one is reviewed like everything else.

    Args:
        policy: The policy stage of this call, already computed by the caller.

    Returns:
        bool: True when the whitelist decided the call, so no model request may
        be spent on it.
    """
    return str(policy.outcome.layer) == LAYER_WHITELIST


def whitelist_skip_verdict(reviewer: str, policy: PolicyStage) -> Verdict:
    """Build the verdict of a reviewer that the whitelist already released.

    Requirement: Whitelist Shortcut.

    The skip word is SKIP_WHITELISTED and DETAIL_LAYER carries the layer of the
    policy outcome, so an audit row says why nothing was asked without any
    reader having to infer it. Nothing is published as a fold: this reviewer
    judged nothing, and a fold invented here would claim an answer it never had.

    Args:
        reviewer: Registry name of the skipping adapter.
        policy: The policy stage whose layer explains the skip.

    Returns:
        Verdict: A SKIP that releases nothing on its own and carries no degraded
        marker, because no request failed -- there was no request.
    """
    return skip_verdict(
        reviewer,
        skipped=SKIP_WHITELISTED,
        reason=policy.outcome.reason,
        detail={DETAIL_LAYER: str(policy.outcome.layer)},
    )


def policy_verdict(stage: PolicyStage, *, reviewer: str) -> Verdict:
    """Map the policy stage onto one verdict.

    Mirrors fold_stages step 1 and 4: the word comes from
    decision_from_policy, so observe rewrites a denial into a release that
    carries WouldBe in the detail.

    Only a whitelist hit becomes an explicit ALLOW here, and nothing else may
    be promoted by hand: an allow-side *hint* (reduce_latency,
    reduce_trajectory_depth) is not an approval, and promoting one would let a
    call that merely sits inside a project root release itself under the
    consensus rule (any allow approves). A static PASS is
    decision_from_policy -> allow_passthrough with no would_be, i.e. a SKIP, and
    that is exactly right: "no opinion" must never be counted as a vote for the
    call.
    """
    decision, would_be = decision_from_policy(stage.outcome, mode=stage.mode)
    outcome = outcome_for(decision, would_be)
    if outcome is ReviewOutcome.SKIP and stage.outcome.passed:
        outcome = ReviewOutcome.ALLOW
    return Verdict(
        reviewer=reviewer,
        outcome=outcome,
        decision=decision,
        reason=stage.outcome.reason,
        detail={
            DETAIL_LAYER: str(stage.outcome.layer),
            DETAIL_RULE_ID: stage.outcome.rule_id,
            DETAIL_DENIED_TARGETS: list(stage.outcome.denied_targets),
            DETAIL_SEVERITY: stage.outcome.severity,
            DETAIL_WOULD_BE: would_be.value if would_be is not None else None,
        },
    )


def rules_verdict(stage: RulesStage, *, reviewer: str, observe: bool) -> Verdict:
    """Map the rule stage onto one verdict.

    Mirrors fold_stages step 2. The engine guards that branch with
    "not is_deny(decision)", which is vacuous here because a policy denial
    short-circuits before the rules are folded; the deny and suspend actions are
    therefore mapped straight through.
    """
    merged = stage.merged
    detail: dict[str, Any] = {
        DETAIL_RULE_IDS: list(stage.rule_ids),
        DETAIL_SEVERITY: stage.severity,
    }
    if merged is None:
        return skip_verdict(reviewer, skipped=SKIP_NO_MATCH, detail=detail)
    if merged.action == ACTION_OBSERVE:
        return skip_verdict(reviewer, skipped=SKIP_OBSERVE_ONLY, detail=detail)
    if merged.action not in (ACTION_DENY, ACTION_SUSPEND):
        return skip_verdict(reviewer, skipped=SKIP_NO_MATCH, detail=detail)
    if merged.action == ACTION_DENY:
        target, word = Decision.DENY_RULE, WouldBe.DENY_RULE
    else:
        target, word = Decision.SUSPENDED, WouldBe.SUSPEND
    if observe:
        decision, expected = Decision.ALLOW_PASSTHROUGH, word
    else:
        decision, expected = target, None
    detail[DETAIL_WOULD_BE] = word.value
    return Verdict(
        reviewer=reviewer,
        outcome=outcome_for(decision, expected),
        decision=decision,
        reason=f"{merged.rule_id}: {merged.reason}",
        detail=detail,
    )


def judge_verdict(
    stage: JudgeStage,
    *,
    reviewer: str,
    observe: bool,
    approve: ReviewOutcome = ReviewOutcome.ALLOW,
) -> Verdict:
    """Map the judge stage onto one verdict.

    Mirrors fold_stages step 3: a denial is deny_judge, a suspension is
    suspended, and an approving answer is a release. observe rewrites both
    tightening words into a release that keeps WouldBe in the detail. The
    degraded marker is carried through unchanged, including in observe mode, so
    an abstention cannot disappear just because the call was not blocked.

    An answer that is None after the judge was actually consulted is an
    ABSTENTION, not an approval: it maps to SKIP with SKIP_ABSTAINED in the
    detail, regardless of the approve word this caller passed. Getting this
    wrong is silent and severe -- the fast judge returns None for every
    unparseable prose answer, so counting None as approve would release exactly
    the calls nobody managed to judge.
    """
    detail: dict[str, Any] = {
        DETAIL_CONSULTED: stage.consulted,
        DETAIL_ANSWER: (
            stage.answer.value if isinstance(stage.answer, Decision) else None
        ),
        DETAIL_SKIPPED: stage.skipped,
    }
    if stage.score is not None:
        detail[DETAIL_SCORE] = int(stage.score)
    if stage.confidence is not None:
        detail[DETAIL_CONFIDENCE] = float(stage.confidence)
    if stage.note:
        detail[DETAIL_NOTE] = stage.note
    if not stage.consulted:
        return skip_verdict(
            reviewer, skipped=stage.skipped or SKIP_NO_MATCH, detail=detail
        )
    answer = stage.answer
    degraded = stage.degraded
    if answer is None:
        detail[DETAIL_SKIPPED] = SKIP_ABSTAINED
        return Verdict(
            reviewer=reviewer,
            outcome=ReviewOutcome.SKIP,
            decision=Decision.ALLOW_PASSTHROUGH,
            reason=stage.reason,
            degraded=degraded,
            detail=detail,
        )
    if is_deny(answer):
        target, word, reason = Decision.DENY_JUDGE, WouldBe.DENY_JUDGE, stage.reason
    elif is_suspend(answer):
        target, word, reason = Decision.SUSPENDED, WouldBe.SUSPEND, stage.reason
    else:
        return Verdict(
            reviewer=reviewer,
            outcome=approve,
            decision=Decision.ALLOW_PASSTHROUGH,
            reason=stage.reason,
            degraded=degraded,
            detail=detail,
        )
    if observe:
        decision, expected = Decision.ALLOW_PASSTHROUGH, word
    else:
        decision, expected = target, None
    detail[DETAIL_WOULD_BE] = word.value
    return Verdict(
        reviewer=reviewer,
        outcome=outcome_for(decision, expected),
        decision=decision,
        reason=reason,
        degraded=degraded,
        detail=detail,
    )


def publish_fold(
    verdict: Verdict,
    *,
    features: CallFeatures,
    policy: PolicyStage,
    rules: RulesStage,
    judge: JudgeStage | None = None,
) -> Verdict:
    """Publish the folded triage outcome of this call on the verdict detail.

    Requirement: Verdict Aggregation; Decision Taxonomy.

    fold_stages is the only place the three stages are combined, so the fold --
    the deciding reason with its rule suffix, the observe word, the severity and
    the taint labels -- is computed here by that same function and published
    under DETAIL_FOLD. A caller then reports the fold instead of re-deriving one,
    which is what keeps a second, parallel mapping from ever being written.

    Publishing is observability and must never change a decision: a fold that
    cannot be computed leaves the verdict exactly as the adapter built it.

    Args:
        verdict: The verdict this adapter is about to return.
        features: The classified call.
        policy: The policy stage of this call.
        rules: The rule stage of this call.
        judge: The judge stage, or None when this adapter consults no model.

    Returns:
        The verdict, carrying DETAIL_FOLD.
    """
    try:
        folded = fold_stages(
            TriageStages(
                features=features,
                policy=policy,
                rules=rules,
                judge=judge if judge is not None else JudgeStage(skipped=SKIP_NO_JUDGE),
            )
        )
    except Exception:  # noqa: BLE001 - publishing never changes a decision
        return verdict
    detail = dict(verdict.detail)
    detail[DETAIL_FOLD] = {
        DETAIL_LABELS: tuple(sorted(str(item) for item in folded.labels)),
        DETAIL_REASON: folded.reason,
        DETAIL_RULE_IDS: list(folded.rule_ids),
        DETAIL_SEVERITY: folded.severity,
        DETAIL_WOULD_BE: (
            folded.would_be.value if folded.would_be is not None else None
        ),
    }
    return replace(verdict, detail=detail)


def fail_closed_fold() -> dict[str, Any]:
    """Publish the fold the engine writes when a triage stage raises.

    Requirement: Fail-Closed Triage.

    A reviewer whose stages cannot run answers with the engine's own fail-closed
    verdict (BuiltinReviewer.review), so it publishes that same fold: the
    triage-error reason, no rule hit, no observe word, no severity, no labels.
    DETAIL_FOLD is therefore present on every verdict, which is what lets the
    caller read the fold instead of testing whether one exists.

    Returns:
        The fold of a failed triage, keyed by the DETAIL_* names.
    """
    return {
        DETAIL_LABELS: (),
        DETAIL_REASON: REASON_TRIAGE_ERROR,
        DETAIL_RULE_IDS: [],
        DETAIL_SEVERITY: None,
        DETAIL_WOULD_BE: None,
    }


def budgeted(judge: Judge | None, budget_s: float | None) -> Judge | None:
    """Wrap one judge so a single answer never outlives the injected budget.

    The budget is a constructor argument of the adapter, never a constant: the
    caller owns the wall clock and this module owns no timeout of its own.
    """
    if judge is None or budget_s is None:
        return judge

    async def _bounded(payload: Mapping[str, Any]) -> Any:
        return await asyncio.wait_for(judge(payload), budget_s)

    return _bounded


class ReviewerSlot:
    """The token one counted call takes and gives back.

    Requirement: Reviewer Contract. A slot owns its own start time and its own
    "already returned" bit, so a per-reviewer counter stays exact even while
    several calls are in flight: nothing here reads shared state, and returning
    the same slot twice cannot move the count twice.
    """

    __slots__ = ("_open", "started")

    def __init__(self, started: float) -> None:
        self.started = started
        self._open = True

    @property
    def open(self) -> bool:
        """Return whether this slot still holds a counted call."""
        return self._open

    def close(self) -> bool:
        """Close this slot; True the first time, False on every replay."""
        was_open = self._open
        self._open = False
        return was_open

    def elapsed(self) -> float:
        """Return how long this call has been running."""
        return max(0.0, time.monotonic() - self.started)


class ReviewerState:
    """The mutable, per-reviewer facts ReviewerStatus reports."""

    def __init__(self) -> None:
        self.in_flight = 0
        self.last_error: str | None = None
        self.last_degraded: str | None = None
        self.last_elapsed_s = 0.0
        self.last_outcome: ReviewOutcome | None = None

    def begin(self) -> ReviewerSlot:
        """Count one call in and hand out the slot that gives it back."""
        slot = ReviewerSlot(time.monotonic())
        self.in_flight += 1
        return slot

    def note_error(self, exc: BaseException) -> None:
        """Record the text of the last failure for the status page."""
        self.last_error = f"{type(exc).__name__}: {exc}"

    def leave(self, slot: ReviewerSlot | None = None) -> float:
        """Give one call's slot back: the counter only, never the statistics.

        Requirement: Reviewer Contract. This is what a `finally` calls, so it
        runs on a normal answer, on a fail-closed answer, on the timeout that
        cancels the reviewer and on the shutdown that cancels its caller alike.
        It is idempotent per slot -- a second call for a slot already returned
        leaves the count alone -- so a path that settles twice cannot decrement
        twice, and a caller that kept no slot still gives its count back.

        Args:
            slot: The slot `begin` handed out for this call, or None.

        Returns:
            float: How long that call ran; 0.0 when no slot was handed in.
        """
        if slot is None:
            self.in_flight = max(0, self.in_flight - 1)
            return 0.0
        if not slot.close():
            return slot.elapsed()
        self.in_flight = max(0, self.in_flight - 1)
        return slot.elapsed()

    def record(self, verdict: Verdict, elapsed_s: float) -> Verdict:
        """Record one real answer and stamp it with its elapsed time.

        Requirement: Reviewer Contract. Statistics are written here and nowhere
        else: only a verdict actually handed to the caller is an answer, so a
        cancelled call -- which has no verdict -- cannot overwrite the last one,
        and the counter above can never be moved by a failure to record.
        """
        self.last_outcome = verdict.outcome
        self.last_degraded = verdict.degraded
        self.last_elapsed_s = elapsed_s
        return replace(verdict, elapsed_s=verdict.elapsed_s or elapsed_s)

    def status(self, *, name: str, order: int, enabled: bool = True) -> ReviewerStatus:
        """Render this state as a ReviewerStatus (the registry overrides three fields)."""
        return ReviewerStatus(
            name=name,
            enabled=enabled,
            order=order,
            busy=self.in_flight > 0,
            in_flight=self.in_flight,
            last_error=self.last_error,
            last_degraded=self.last_degraded,
            last_elapsed_s=self.last_elapsed_s,
            last_outcome=self.last_outcome,
        )


class BuiltinReviewer:
    """The review()/status() shell shared by every built-in adapter."""

    name: str = ""
    order: int = 0
    enabled: bool = True
    busy_policy: BusyPolicy = BusyPolicy.SKIP

    def __init__(
        self,
        *,
        snapshot: Any,
        trajectory_of: Callable[[GuardCall], Any] | None = None,
        deadline_of: Callable[[GuardCall], float | None] | None = None,
    ) -> None:
        """Bind the adapter to one immutable snapshot.

        Args:
            snapshot: The immutable policy snapshot this adapter judges against.
            trajectory_of: Optional reader of the read-only trajectory window of
                one call. GuardCall carries no trajectory, and the rules that
                need one (R7, R9, R11) must see the same window the engine saw,
                so the caller injects the reader instead of the adapter
                guessing at a store it does not own.
            deadline_of: Optional reader of the caller budget for one call.
                GuardCall carries no deadline either, and this package owns no
                clock: the caller hands the budget in, the adapter only forwards
                it to a judge payload.
        """
        self._snapshot = snapshot
        self._trajectory_of = trajectory_of
        self._deadline_of = deadline_of
        self._state = ReviewerState()

    @property
    def snapshot(self) -> Any:
        """Return the snapshot this adapter judges against."""
        return self._snapshot

    def trajectory(self, call: GuardCall) -> Any:
        """Return the trajectory window of one call, or None when unavailable."""
        if self._trajectory_of is None:
            return None
        return self._trajectory_of(call)

    def deadline(self, call: GuardCall) -> float | None:
        """Return the caller budget for one call, or None when unset."""
        if self._deadline_of is None:
            return None
        return self._deadline_of(call)

    async def review(self, call: GuardCall) -> Verdict:
        """Answer for one call; a stage failure denies, as fail-closed requires.

        Requirement: Fail-Closed Triage; Reviewer Contract.

        The in-flight count is given back in `finally`, so it drops on every way
        out: a normal answer, a stage failure, the budget timeout that cancels
        this coroutine and the shutdown that cancels its caller. That bookkeeping
        is the only thing the `finally` does -- the statistics follow the verdict
        below, and a cancelled call has none.

        `asyncio.CancelledError` is a BaseException and is deliberately not
        caught: it leaves unchanged, because a cancelled review has no verdict
        and must never be reported as an ordinary fail-closed denial.
        """
        slot = self._state.begin()
        try:
            try:
                verdict = await self._answer(call)
            except Exception as exc:  # noqa: BLE001 - Fail-Closed Triage
                self._state.note_error(exc)
                verdict = Verdict(
                    reviewer=self.name,
                    outcome=ReviewOutcome.DENY,
                    decision=Decision.DENY_POLICY,
                    reason=REASON_TRIAGE_ERROR,
                    degraded=TRIAGE_ERROR_PREFIX + type(exc).__name__,
                    detail={DETAIL_FOLD: fail_closed_fold()},
                )
        finally:
            elapsed = self._state.leave(slot)
        return self._state.record(verdict, elapsed)

    async def _answer(self, call: GuardCall) -> Verdict:
        """Judge one call; implemented by each adapter."""
        raise NotImplementedError

    def status(self) -> ReviewerStatus:
        """Return this adapter's own observable state."""
        return self._state.status(
            name=self.name, order=self.order, enabled=self.enabled
        )


__all__ = [
    "DETAIL_ANSWER",
    "DETAIL_CONSULTED",
    "DETAIL_DENIED_TARGETS",
    "DETAIL_FOLD",
    "DETAIL_LABELS",
    "DETAIL_LAYER",
    "DETAIL_REASON",
    "DETAIL_RULE_ID",
    "DETAIL_RULE_IDS",
    "DETAIL_CONFIDENCE",
    "DETAIL_NOTE",
    "DETAIL_SCORE",
    "DETAIL_SEVERITY",
    "DETAIL_SKIPPED",
    "DETAIL_WOULD_BE",
    "SKIP_NOT_SUSPICIOUS",
    "SKIP_NO_MATCH",
    "SKIP_ABSTAINED",
    "SKIP_OBSERVE_ONLY",
    "SKIP_WHITELISTED",
    "TRIAGE_ERROR_PREFIX",
    "BuiltinReviewer",
    "ReviewerSlot",
    "ReviewerState",
    "budgeted",
    "fail_closed_fold",
    "features_of",
    "judge_verdict",
    "observe_of",
    "outcome_for",
    "policy_of",
    "policy_verdict",
    "publish_fold",
    "rules_of",
    "rules_verdict",
    "skip_verdict",
    "skips_model_review",
    "whitelist_skip_verdict",
]
