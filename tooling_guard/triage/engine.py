"""Triage orchestration. Requirement: Layered Consensus; Rules Before Models.

Requirement names owned here: Layered Consensus; Rules Before Models;
Decision Taxonomy.

The order is fixed and visible in one place: classify, policy, rules, the
optional injected judge, then the decision vocabulary. What this module does not
do matters as much as what it does:

- no network, no store, no clock, no sleep: the judge is injected by the caller
  and this package ships no HTTP client, prompt or model routing;
- no waiting: the deadline is accepted and handed to the judge payload as given
  under the key `deadline_monotonic` -- an instant on the caller's monotonic
  clock, never a number of seconds -- and it is never enforced here;
- no downgrade: a static denial is final, a deny-class rule refuses on its own,
  every other rule hit only labels the call, and a judge that raises, abstains
  or answers unreadably abstains rather than denying -- the models are an
  opinion, the static layer is the refusal.

The three stages are exposed as values instead of as inline code, so nothing
else has to re-derive them: `TriageEngine.stages` builds a `TriageStages`
and `TriageEngine.decide` is that same record folded. There is one
implementation per stage: `classify_features`, `policy_stage`, `rule_stage` and
`judge_stage` are module level so the reviewer adapters in
`tooling_guard.reviewers` call them instead of growing a second copy.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Final

from ..jev import score as fast_score
from ..policy import paths
from ..policy.layers import (
    PolicyDecision,
    PolicyOutcome,
    PolicyRequest,
    evaluate_policy,
)
from ..prompts.state import build_state
from .classify import (
    ROOT_SCOPED_UNTRUSTED_TOOLS,
    CallFeatures,
    classify_call,
    content_text,
    is_exec_tool,
    is_read_tool,
    mark_read_in_project_roots,
    narrow_untrusted_source,
    read_scope_paths,
)
from .decisions import (
    MODE_ENFORCE,
    Decision,
    WouldBe,
    decision_from_policy,
    effective_mode,
    is_allow,
    is_deny,
    is_observe_mode,
    is_suspend,
)
from .rules import (
    ACTION_DENY,
    RuleHit,
    TrajectoryView,
    evaluate_rules,
    merge_rule_hits,
)

#: A judge is any awaitable callable taking the call payload and returning a
#: verdict. The signature is fixed here so a later slice can inject one.
Judge = Callable[[Mapping[str, Any]], Awaitable[Any]]

REASON_TRIAGE_ERROR: Final[str] = "内部判定错误，按拒绝处理"
REASON_JUDGE_ABSTAINED: Final[str] = "模型没有给出结论，未形成意见"
REASON_JUDGE_UNAVAILABLE: Final[str] = "模型不可用，未形成意见"
REASON_JUDGE_UNREADABLE: Final[str] = "模型回答无法解析，未形成意见"
REASON_JUDGE_DENIED: Final[str] = "模型拒绝"
REASON_JUDGE_SUSPENDED: Final[str] = "模型挂起"

#: Degradation kind recorded when the fast judge answered with nothing usable.
#: An abstention is not a denial: it means neither model formed an opinion, and
#: the consensus turns that into an approval request instead of a refusal. The
#: word keeps its place in the audit vocabulary, so old rows still read alike.
DEGRADED_JUDGE_ABSTAINED: Final[str] = "judge_abstained"

#: Degradation kind recorded when the answer is not a readable score/noul
#: verdict at all. The word predates the score protocol and is kept because it
#: is already in audit rows and operator documentation.
DEGRADED_JUDGE_UNREADABLE: Final[str] = "judge_decision_unrecognized"

#: Degradation kind recorded when an endpoint answered the retired choice
#: protocol: an answer nothing can be banded from, worth naming on its own so an
#: operator sees a protocol mismatch instead of a parse error.
DEGRADED_JUDGE_LEGACY_CHOICE: Final[str] = fast_score.DEGRADED_JUDGE_LEGACY_CHOICE

#: Degradation kind recorded when the confidence floor produced the suspension:
#: the judge was unsure, so a release and a denial alike park for an
#: administrator. The word names the cause, so the row is not read as a plain
#: judge suspension.
DEGRADED_FAST_LOW_CONFIDENCE: Final[str] = fast_score.DEGRADED_FAST_LOW_CONFIDENCE

#: Prefix of the degradation kind recorded when the judge raised; the exception
#: class name is appended, so the audit row says which failure it was.
JUDGE_ERROR_PREFIX: Final[str] = "judge_error:"

#: Why the judge stage did not run. Recorded so that "not asked" can never be
#: read as "asked and abstained": the latter is a vote the consensus counts, the
#: former is only evidence about the judge.
SKIP_NO_JUDGE: Final[str] = "no_judge"
SKIP_POLICY_DECIDED: Final[str] = "policy_decided"


@dataclass(frozen=True, slots=True)
class TriageOutcome:
    """The verdict of one call. Requirement: Decision Taxonomy."""

    decision: Decision
    would_be: WouldBe | None
    rule_hits: tuple[RuleHit, ...]
    reason: str
    severity: str | None
    labels: frozenset[str]
    features: CallFeatures
    policy: PolicyOutcome | None
    degraded: str | None = None

    @property
    def rule_ids(self) -> tuple[str, ...]:
        """Return the ids of every rule that fired, in merge order."""
        return tuple(hit.rule_id for hit in self.rule_hits)

    @property
    def allowed(self) -> bool:
        """Return whether the call may proceed."""
        return is_allow(self.decision)

    @property
    def blocked(self) -> bool:
        """Return whether the call is denied."""
        return is_deny(self.decision)


@dataclass(frozen=True, slots=True)
class PolicyStage:
    """One call as the policy layers judged it.

    Requirement: Policy Layers and Precedence; Shadow Observation Mode.

    Attributes:
        outcome: The `PolicyOutcome` `evaluate_policy` produced, unmodified.
        mode: The effective mode the fold acts in. Observe wins whenever either
            the caller or the snapshot asks for it, so a reader of this record
            never has to recompute that precedence itself.
    """

    outcome: PolicyOutcome
    mode: str

    @property
    def observe(self) -> bool:
        """Return whether this stage acts in shadow mode."""
        return is_observe_mode(self.mode)

    @property
    def expected(self) -> PolicyDecision:
        """Return the action the layers expect before the mode was applied."""
        return self.outcome.expected


@dataclass(frozen=True, slots=True)
class RulesStage:
    """One call as the R1-R11 catalogue judged it. Requirement: Rule Catalog.

    Attributes:
        hits: Every hit, in `evaluate_rules` merge order.
        merged: The hit that decides the call, or None when nothing fired.
    """

    hits: tuple[RuleHit, ...] = ()
    merged: RuleHit | None = None

    @property
    def rule_ids(self) -> tuple[str, ...]:
        """Return the ids of every rule that fired, in merge order."""
        return tuple(hit.rule_id for hit in self.hits)

    @property
    def action(self) -> str | None:
        """Return the action of the deciding hit, or None."""
        return self.merged.action if self.merged is not None else None

    @property
    def severity(self) -> str | None:
        """Return the severity of the deciding hit, or None."""
        return self.merged.severity if self.merged is not None else None


@dataclass(frozen=True, slots=True)
class JudgeStage:
    """One call as the injected fast judge judged it, or did not.

    Requirement: Rules Before Models; Fail-Closed Triage.

    Attributes:
        consulted: Whether the judge was actually asked. False means nobody
            spent a model request, and answer, reason and degraded stay empty.
        answer: The coerced answer, or None when nothing usable came back.
        reason: Administrator-facing text of the answer; empty when the answer
            needs none, as an allow answer changes nothing here.
        degraded: Degradation kind, one of the `judge_*` words or
            `fast_low_confidence`, or None.
        skipped: Why the judge was not consulted, one of the `SKIP_*` words;
            empty when it was consulted. A skipped judge is never an abstention.
        force_deep: Whether this answer asks for the deep analysis.
        score: The answer's score in percent, when one was readable; carried so
            the audit row and the approval page can show what the judge saw
            rather than only the word the banding produced.
        confidence: The answer's confidence in 0.0-1.0, when one was readable.
        note: The confidence annotation, one of the `NOTE_*` words or empty;
            the audit row's evidence for a `fast_low_confidence` degradation.
    """

    consulted: bool = False
    answer: Decision | None = None
    reason: str = ""
    degraded: str | None = None
    skipped: str = ""
    force_deep: bool = False
    score: int | None = None
    confidence: float | None = None
    note: str = ""


@dataclass(frozen=True, slots=True)
class TriageStages:
    """The three stages of one call, as structured values.

    Requirement: Rules Before Models.

    `TriageEngine.decide` is exactly `fold_stages` over this record, and the reviewer
    adapters read the same three fields, so there is one implementation per
    stage rather than one per consumer.

    Attributes:
        features: The classified call.
        policy: The policy layer's conclusion and the mode it was reached in.
        rules: The rule catalogue's hits.
        judge: The optional fast judge's answer.
    """

    features: CallFeatures
    policy: PolicyStage
    rules: RulesStage
    judge: JudgeStage


def _mark_read_in_roots(snapshot: Any, features: CallFeatures) -> CallFeatures:
    """Add the read_in_project_roots label when a read stays inside the roots.

    Requirement: Rule Catalog (R8). The rule layer may not read configuration,
    so the scope fact is decided here, where the snapshot is at hand. The label
    is only added for a read of any shape: no absolute literal, an empty root
    list or a root lookup failure all leave it off, which keeps R8 firing.
    """
    if not (is_exec_tool(features.tool_name) or is_read_tool(features.tool_name)):
        return features
    scope = read_scope_paths(features)
    if not scope:
        return features
    try:
        inside = all(paths.is_in_project_roots(value, snapshot) for value in scope)
    except Exception:  # noqa: BLE001 - a root lookup failure keeps R8 firing
        return features
    return mark_read_in_project_roots(features, inside_project_roots=inside)


def classify_features(
    snapshot: Any,
    tool_name: str,
    arguments: Mapping[str, Any] | None = None,
    *,
    schema: Any = None,
) -> CallFeatures:
    """Classify one call, then narrow and mark its scope-dependent labels.

    Requirement: Taint Label Supply; Rule Catalog R8, R10.

    Args:
        snapshot: The policy snapshot whose project roots scope the labels.
        tool_name: The tool name as the model called it.
        arguments: The call arguments; a non-mapping is treated as empty.
        schema: The tool argument schema, accepted for call-site symmetry.

    Returns:
        CallFeatures: The classified call, carrying read_in_project_roots when
        it reads only and every absolute literal sits inside a project root,
        with untrusted_source dropped only when every target sits inside one.
    """
    features = classify_call(tool_name, arguments, schema=schema)
    features = _mark_read_in_roots(snapshot, features)
    if features.tool_name not in ROOT_SCOPED_UNTRUSTED_TOOLS:
        return features
    if not features.targets:
        return features
    try:
        inside = all(
            paths.is_in_project_roots(target, snapshot) for target in features.targets
        )
    except Exception:  # noqa: BLE001 - a root lookup failure keeps the label
        return features
    return narrow_untrusted_source(features, inside_project_roots=inside)


#: Directory that resolves the relative targets of the call being judged, bound
#: per call by the gateway. A context variable for the same reason
#: `main._REVIEW_DEADLINE` is one: the call identity travels inside a frozen
#: `GuardCall` no stage may widen, and the engine's own fold reaches
#: `policy_stage` too, so one target must resolve alike on both paths or the fold
#: and the pipeline would disagree about the same call.
_CALL_BASE: ContextVar[str | None] = ContextVar("tooling_guard_call_base", default=None)


@contextmanager
def call_base(base: str | None) -> Iterator[None]:
    """Bind the host workspace root that resolves this call's relative targets.

    Requirement: Policy Layers and Precedence. The host resolves a relative tool
    path against the per-session workspace (astrbot/core/tools/computer_tools/
    fs.py:186-205), so the policy stage needs that directory as its `base`;
    without it a relative target stays unresolvable and is denied, which refused
    ordinary workspace files.

    Args:
        base: Absolute workspace root of this call, or `None` to keep the
            fail-closed answer `policy/paths.py` gives every relative target.
    """
    token = _CALL_BASE.set(base)
    try:
        yield
    finally:
        _CALL_BASE.reset(token)


def current_call_base() -> str | None:
    """Return the workspace root bound to this call, `None` when unbound."""
    return _CALL_BASE.get()


def policy_stage(
    snapshot: Any,
    features: CallFeatures,
    arguments: Mapping[str, Any] | None,
    *,
    subject_key: str,
    mode: str = MODE_ENFORCE,
    base: str | None = None,
) -> PolicyStage:
    """Evaluate the policy layers for one classified call.

    Requirement: Policy Layers and Precedence; Policy Snapshot Consistency.

    Args:
        snapshot: The immutable policy snapshot of this judgement.
        features: The classified call, whose targets and texts the layers read.
        arguments: The call arguments, read for inline content only.
        subject_key: Platform-qualified requester identity.
        mode: Mode requested by the caller; observe wins over the snapshot.
        base: Directory that resolves relative targets, by default the one bound
            to this call; `None` leaves them unresolvable, which denies.

    Returns:
        PolicyStage: The conclusion and the effective mode it was reached in.
    """
    effective = effective_mode(mode, getattr(snapshot, "mode", mode))
    workspace = base if base is not None else current_call_base()
    outcome = evaluate_policy(
        PolicyRequest(
            tool_name=features.tool_name,
            subject=subject_key,
            raw_paths=features.targets,
            texts=features.texts,
            destinations=features.destinations,
            content=content_text(arguments) if isinstance(arguments, Mapping) else "",
            writes=bool(features.write_targets),
            base=workspace,
        ),
        snapshot,
    )
    return PolicyStage(outcome=outcome, mode=effective)


def rule_stage(
    features: CallFeatures, trajectory: TrajectoryView | None = None
) -> RulesStage:
    """Judge one classified call against the whole R1-R11 catalogue.

    Requirement: Rule Catalog; Rules Before Models.

    Args:
        features: The classified call.
        trajectory: Optional read-only window of earlier calls.

    Returns:
        RulesStage: Every hit in merge order, and the hit that decides the call.
    """
    hits = evaluate_rules(features, trajectory)
    return RulesStage(hits=hits, merged=merge_rule_hits(hits))


#: How many earlier calls one judge is shown. The window keeps fifty records per
#: session; a model is shown the newest of them, because the question is what this
#: session just did, not what its whole history is.
HISTORY_LIMIT: Final[int] = 8

#: Targets rendered per earlier call: enough to recognise the file, not a transcript.
HISTORY_TARGETS: Final[int] = 2


def trajectory_history(trajectory: Any, *, limit: int = HISTORY_LIMIT) -> str:
    """Render the newest earlier calls of one session as judge-visible history.

    Requirement: Layered Consensus; Trajectory Review. Both model layers are asked
    one question about one document, so history is a field of that document
    (`trajectory_summary`), never a second prompt: the deep layer was shown no
    earlier call at all, which left it unable to see the one thing a single call
    cannot show -- a sequence such as a sensitive read followed by an outbound
    call.

    Args:
        trajectory: The read-only window (`triage.rules.TrajectoryView`), or None.
        limit: Number of newest entries to render.

    Returns:
        str: One line per earlier call, oldest first; empty without a window.
    """
    entries = getattr(trajectory, "entries", None)
    if not entries:
        return ""
    lines: list[str] = []
    for entry in tuple(entries)[-max(1, int(limit)):]:
        tool = _history_text(entry, "tool")
        verb = _history_text(entry, "verb")
        head = " ".join(part for part in (tool, verb) if part)
        targets = _history_targets(entry)
        if targets:
            joined = ", ".join(targets)
            head = f"{head} -> {joined}" if head else joined
        decision = _history_text(entry, "decision")
        if decision:
            head = f"{head} ({decision})" if head else decision
        if head:
            lines.append(head)
    return "\n".join(lines)


def _history_field(entry: Any, name: str) -> Any:
    """Read one field of a trajectory entry from a mapping or an object."""
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


def _history_text(entry: Any, name: str) -> str:
    """Return one text field of an earlier call, or an empty string."""
    value = _history_field(entry, name)
    return value.strip() if isinstance(value, str) else ""


def _history_targets(entry: Any, limit: int = HISTORY_TARGETS) -> list[str]:
    """Return the last few recorded targets of one earlier call."""
    value = _history_field(entry, "targets")
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, (tuple, list, set, frozenset)):
        items = [item for item in value if isinstance(item, str)]
    else:
        items = []
    return [item.strip() for item in items if item.strip()][-limit:]


def judge_payload(
    *,
    features: CallFeatures,
    hits: tuple[RuleHit, ...],
    mode: str,
    subject_key: str,
    session_key: str,
    deadline: float | None,
    trajectory: Any = None,
) -> dict[str, Any]:
    """Build the one state the fast judge is asked about.

    Requirement: Rules Before Models; Fast Judge Budget.

    The keys are not assembled here: prompts.state.build_state owns the field
    set, the bounds and the redaction, and this function only maps a classified
    call onto it. Both request builders (prompts.systemone, prompts.single_call)
    render that same mapping, so the engine and a judge-backed reviewer ask the
    model the same question with the same keys.

    Args:
        features: The classified call.
        hits: Every rule hit of the call.
        mode: Effective enforcement mode.
        subject_key: Platform-qualified requester identity.
        session_key: Session identity the trajectory belongs to.
        deadline: Deadline instant on the caller's monotonic clock, recorded only
            under the payload key `deadline_monotonic`.
        trajectory: Optional read-only window of earlier calls of the session;
            rendered into `trajectory_summary` so both model layers judge the
            call knowing what the session just did.

    Returns:
        dict: The structured state passed to the injected judge.
    """
    return build_state(
        tool=features.tool_name,
        verb=features.verb,
        targets=features.targets,
        tier=features.tier,
        labels=sorted(features.labels),
        texts=features.texts,
        mode=mode,
        subject=subject_key,
        session=session_key,
        # build_state publishes this as deadline_monotonic: an instant on the
        # caller's monotonic clock, never a budget in seconds (R10-07).
        deadline=deadline,
        trajectory_summary=trajectory_history(trajectory),
        extra={
            "origin": features.origin,
            "destinations": list(features.destinations),
            "rule_ids": [hit.rule_id for hit in hits],
        },
    )


async def judge_stage(
    judge: Judge | None,
    *,
    features: CallFeatures,
    policy: PolicyStage,
    rules: RulesStage,
    subject_key: str,
    session_key: str,
    deadline: float | None = None,
    trajectory: Any = None,
) -> JudgeStage:
    """Ask the injected judge, or record why nobody was asked.

    Requirement: Layered Consensus; Rules Before Models.

    The models judge every call. Two preconditions still decide whether a
    request is spent at all: no judge was injected, or the static layer denied
    the call outright -- a denial is final, so asking would only spend a request
    on a verdict nothing can overturn. Nothing else skips this stage, and that is
    the change this design makes: a rule hit, an exec tool, an unknown tool name
    are all labels now, not exits. The call goes to the model with its labels,
    and the answer decides.

    Args:
        judge: The injected judge, or None.
        features: The classified call.
        policy: The policy stage of the same call.
        rules: The rules stage of the same call; its hits travel inside the
            payload, so a rule hit is evidence for the judge rather than a
            substitute for it.
        subject_key: Platform-qualified requester identity.
        session_key: Session identity the trajectory belongs to.
        deadline: Deadline instant on the caller's monotonic clock, recorded only
            as the payload key `deadline_monotonic`.
        trajectory: Optional read-only window of earlier calls; it travels inside
            the payload, so history is the same document for every layer.

    Returns:
        JudgeStage: The consulted flag, the decided answer, the force_deep
        recommendation and the degradation kind. The band is decided once, by
        jev.score.decide. A judge that raises, returns nothing, returns an
        unreadable answer or bands None abstains: `answer` stays None and
        `degraded` names the failure, so the caller can tell "the judge had no
        opinion" from "the judge said stop", and the consensus turns the former
        into an approval request instead of a refusal. An abstention is the
        absence of an opinion, not a denial -- the refusal path belongs to the
        static layer alone. When the confidence floor is what turned the band
        into a suspension, the degradation kind is `fast_low_confidence`, so the
        audit row says the judge was unsure instead of resembling a plain
        suspension.
    """
    if judge is None:
        return JudgeStage(skipped=SKIP_NO_JUDGE)
    if policy.expected is PolicyDecision.DENY:
        return JudgeStage(skipped=SKIP_POLICY_DECIDED)
    payload = judge_payload(
        features=features,
        hits=rules.hits,
        mode=policy.mode,
        subject_key=subject_key,
        session_key=session_key,
        deadline=deadline,
        trajectory=trajectory,
    )
    try:
        answer = await judge(payload)
    except Exception as exc:  # noqa: BLE001 - a judge failure is an abstention
        return JudgeStage(
            consulted=True,
            answer=None,
            reason=REASON_JUDGE_UNAVAILABLE,
            degraded=JUDGE_ERROR_PREFIX + type(exc).__name__,
        )
    if answer is None:
        return JudgeStage(
            consulted=True,
            answer=None,
            reason=REASON_JUDGE_ABSTAINED,
            degraded=DEGRADED_JUDGE_ABSTAINED,
        )
    if not isinstance(answer, fast_score.FastVerdict):
        return JudgeStage(
            consulted=True,
            answer=None,
            reason=REASON_JUDGE_UNREADABLE,
            degraded=DEGRADED_JUDGE_UNREADABLE,
        )
    thresholds = _thresholds_of(judge)
    # The confidence floor is annotated first, and decide reads the confidence
    # itself rather than the note: the note is the evidence the audit row shows,
    # so the two can never disagree about which band the floor rewrote.
    gated = fast_score.annotate_confidence(answer, thresholds)
    banded = fast_score.decide(gated, thresholds)
    if banded is None:
        legacy = gated.note == fast_score.LEGACY_CHOICE_NOTE
        low = gated.note == fast_score.NOTE_LOW_CONFIDENCE
        if legacy:
            degraded = DEGRADED_JUDGE_LEGACY_CHOICE
        elif low:
            # A score under the confidence floor abstains (0.6.2), so the note is
            # the only place that says why: without it the row would read like an
            # unusable answer instead of a nervous one.
            degraded = DEGRADED_FAST_LOW_CONFIDENCE
        else:
            degraded = DEGRADED_JUDGE_ABSTAINED
        return JudgeStage(
            consulted=True,
            answer=None,
            reason=REASON_JUDGE_ABSTAINED,
            degraded=degraded,
            # An abstention is still a request when the answer said so: the
            # middle band votes for nothing, and noul=true is the fast layer
            # asking the deep layer to settle it.
            force_deep=fast_score.forces_deep(gated, thresholds),
            score=gated.score_pct,
            confidence=gated.confidence,
            note=gated.note,
        )
    return JudgeStage(
        consulted=True,
        answer=banded,
        reason=_judge_reason(banded),
        degraded=(
            DEGRADED_FAST_LOW_CONFIDENCE
            if gated.note == fast_score.NOTE_LOW_CONFIDENCE
            else None
        ),
        force_deep=fast_score.forces_deep(gated, thresholds),
        score=gated.score_pct,
        confidence=gated.confidence,
        note=gated.note,
    )


def fold_stages(stages: TriageStages) -> TriageOutcome:
    """Fold one `TriageStages` into the verdict of the call.

    Requirement: Layered Consensus; Shadow Observation Mode.

    This is the only place the three stages are combined, and
    `TriageEngine.decide` calls it directly: a second, parallel mapping would
    drift from this one.

    Only the static stage and a deny-class rule refuse on their own; every other
    rule hit travels as a label and lets the models weigh it. The judge branch is
    classified by `_judge_tightening`: a denial word becomes deny_judge,
    suspended becomes suspended, and an abstention leaves the fold untouched --
    a model with no opinion does not deny, it only fails to approve. That is why
    the published text never announces a release no reviewer voted for.

    Args:
        stages: The policy, rules and judge stages of one call.

    Returns:
        TriageOutcome: The decision, the observe-mode expectation, every rule
        hit and the degradation kind the judge stage recorded.
    """
    features = stages.features
    policy = stages.policy.outcome
    hits = stages.rules.hits
    merged = stages.rules.merged
    observe = stages.policy.observe
    decision, would_be = decision_from_policy(policy, mode=stages.policy.mode)
    reason = policy.reason
    severity = policy.severity

    if policy.expected is PolicyDecision.DENY:
        return TriageOutcome(
            decision=decision,
            would_be=would_be,
            rule_hits=hits,
            reason=_reason_text(reason, hits),
            severity=severity or _severity_of(merged),
            labels=features.labels,
            features=features,
            policy=policy,
            degraded=None,
        )

    if merged is not None:
        reason = _reason_text(f"{merged.rule_id}: {merged.reason}", hits)
        severity = merged.severity or severity
        if merged.action == ACTION_DENY:
            if observe:
                decision, would_be = Decision.ALLOW_PASSTHROUGH, WouldBe.DENY_RULE
            else:
                decision, would_be = Decision.DENY_RULE, None

    judged = stages.judge
    tightening = _judge_tightening(judged)
    if tightening is not None:
        target, word, text = tightening
        # A suspend answer never loosens a denial the fold already holds.
        applies = observe or not (is_suspend(target) and is_deny(decision))
        if applies:
            reason = _reason_text(judged.reason or text, hits)
            if observe:
                decision, would_be = Decision.ALLOW_PASSTHROUGH, word
            else:
                decision, would_be = target, None

    if observe and not is_allow(decision):
        decision, would_be = Decision.ALLOW_PASSTHROUGH, would_be or (WouldBe.SUSPEND)
    return TriageOutcome(
        decision=decision,
        would_be=would_be,
        rule_hits=hits,
        reason=reason,
        severity=severity,
        labels=features.labels,
        features=features,
        policy=policy,
        degraded=judged.degraded,
    )


class TriageEngine:
    """Judge one call at a time. Requirement: Rules Before Models."""

    def __init__(
        self,
        *,
        config: Any,
        snapshot: Any,
        fast_judge: Judge | None = None,
        deep_judge: Judge | None = None,
    ) -> None:
        """Build an engine over one immutable configuration snapshot.

        Requirement: Rules Before Models.

        Args:
            config: The validated gateway configuration.
            snapshot: The immutable policy snapshot of that configuration.
            fast_judge: Optional injected fast judge. Left as None nothing is
                called; the model stage itself belongs to a later slice.
            deep_judge: Optional injected deep judge, accepted for the caller
                that later runs the asynchronous path. It is never called on
                this synchronous path.
        """
        self._config = config
        self._snapshot = snapshot
        self._fast_judge = fast_judge
        self._deep_judge = deep_judge

    @property
    def config(self) -> Any:
        """Return the configuration this engine judges against."""
        return self._config

    @property
    def snapshot(self) -> Any:
        """Return the policy snapshot this engine judges against."""
        return self._snapshot

    async def decide(
        self,
        *,
        tool_name: str,
        arguments: Mapping[str, Any],
        schema: Any = None,
        subject_key: str,
        session_key: str,
        trajectory: TrajectoryView | None = None,
        mode: str = MODE_ENFORCE,
        deadline: float | None = None,
    ) -> TriageOutcome:
        """Judge one call. Requirement: Decision Taxonomy; Shadow Observation Mode.

        This is `fold_stages` over `stages` and nothing else: the policy, rules and
        judge stages are collected once, in `stages`, so this entry point can
        never drift from the reviewer adapters that read the same three values.

        Args:
            tool_name: The tool name as the model called it.
            arguments: The call arguments.
            schema: The tool argument schema, passed to the classifier.
            subject_key: Platform-qualified requester identity.
            session_key: Session identity the trajectory belongs to.
            trajectory: Optional read-only window of earlier calls.
            mode: Effective enforcement mode, enforce or observe.
            deadline: Deadline instant on the caller's monotonic clock; recorded
                as the payload key `deadline_monotonic`, never enforced.

        Returns:
            TriageOutcome: The decision, the expected action in observe mode,
            every rule hit, and the degraded reason when a stage failed.

        Raises:
            Nothing: a judging error denies the call, as Fail-Closed Triage
            requires.
        """
        try:
            stages = await self.stages(
                tool_name=tool_name,
                arguments=arguments,
                schema=schema,
                subject_key=subject_key,
                session_key=session_key,
                trajectory=trajectory,
                mode=mode,
                deadline=deadline,
            )
        except Exception as exc:  # noqa: BLE001 - Fail-Closed Triage
            return _fail_closed(tool_name, exc)
        return fold_stages(stages)

    async def stages(
        self,
        *,
        tool_name: str,
        arguments: Mapping[str, Any],
        schema: Any = None,
        subject_key: str,
        session_key: str,
        trajectory: TrajectoryView | None = None,
        mode: str = MODE_ENFORCE,
        deadline: float | None = None,
    ) -> TriageStages:
        """Collect the three stages of one call without folding them.

        Requirement: Rules Before Models; Policy Layers and Precedence.

        The public stage entry point: a caller that needs the policy conclusion,
        the rule hits or the judge answer as values calls this instead of
        re-running any of the three. It is not fail-closed by design, because
        the caller is the one deciding what an exception means; `decide` is
        the fail-closed wrapper and both share this one implementation.

        Args:
            tool_name: The tool name as the model called it.
            arguments: The call arguments.
            schema: The tool argument schema, passed to the classifier.
            subject_key: Platform-qualified requester identity.
            session_key: Session identity the trajectory belongs to.
            trajectory: Optional read-only window of earlier calls.
            mode: Effective enforcement mode, enforce or observe.
            deadline: Deadline instant on the caller's monotonic clock; recorded
                as the payload key `deadline_monotonic`, never enforced.

        Returns:
            TriageStages: The classified call plus the policy, rules and judge
            stages, in the order they ran.

        Raises:
            Exception: Whatever the classifier, the layers or the rules raise;
            `decide` turns that into a denial.
        """
        features = classify_features(
            self._snapshot, tool_name, arguments, schema=schema
        )
        policy = policy_stage(
            self._snapshot,
            features,
            arguments,
            subject_key=subject_key,
            mode=mode,
        )
        rules = rule_stage(features, trajectory)
        judge = await judge_stage(
            self._fast_judge,
            features=features,
            policy=policy,
            rules=rules,
            subject_key=subject_key,
            session_key=session_key,
            deadline=deadline,
        )
        return TriageStages(features=features, policy=policy, rules=rules, judge=judge)


def _thresholds_of(judge: Judge) -> fast_score.FastThresholds:
    """Return the band thresholds the injected judge was built with.

    Requirement: Fail-Closed Triage. The reviewer is constructed with a judge
    callable and nothing else, so the pair travels on the callable
    (jev.client.FastJudge carries it). A bare callable that carries none is
    banded with the documented factory defaults, which are the shipped 30/75 --
    never with a pair invented here.
    """
    thresholds = getattr(judge, "thresholds", None)
    if isinstance(thresholds, fast_score.FastThresholds):
        return thresholds
    return fast_score.FastThresholds()


def _judge_reason(answer: Decision) -> str:
    """Return the administrator-facing text of one judge answer."""
    if answer is Decision.DENY_JUDGE:
        return REASON_JUDGE_DENIED
    if answer is Decision.SUSPENDED:
        return REASON_JUDGE_SUSPENDED
    return ""


def _judge_tightening(judged: JudgeStage) -> tuple[Decision, WouldBe, str] | None:
    """Return the tightening one consulted judge answer forces on the fold.

    Requirement: Layered Consensus; Decision Taxonomy.

    The band is decided once, by jev.score.decide, and this function only reads
    the decision that produced: suspend suspends, any deny word tightens, and an
    enumerated allow changes nothing. No word is parsed here any more -- the
    retired choice vocabulary is gone, so a second reading of the answer could
    only disagree with the first. Only an enumerated allow word returns None,
    which is what keeps this branch from being a catch-all release.

    An abstention passes through unchanged. A judge that had no opinion must not
    appear in the fold as a denial: the consensus reads "nobody objected" and
    "somebody said stop" differently, and only the second one becomes a refusal
    request. The degradation the stage already recorded keeps the abstention
    visible in the audit row.

    Args:
        judged: The judge stage of the call being folded.

    Returns:
        tuple: The decision the answer forces, the observe-mode word, and the text
        to state when the stage itself carried none; None when the answer changes
        nothing, including when the judge abstained.
    """
    if not judged.consulted:
        return None
    answer = judged.answer
    if answer is None:
        return None
    if is_suspend(answer):
        return Decision.SUSPENDED, WouldBe.SUSPEND, REASON_JUDGE_SUSPENDED
    if not is_deny(answer):
        return None
    return Decision.DENY_JUDGE, WouldBe.DENY_JUDGE, REASON_JUDGE_DENIED


def _severity_of(hit: RuleHit | None) -> str | None:
    """Return the severity of one merged hit, or None."""
    return hit.severity if hit is not None else None


def _reason_text(base: str, hits: tuple[RuleHit, ...]) -> str:
    """Return an administrator-facing reason naming the rules that fired.

    Only rule ids and the already redacted texts of the layers are used, so no
    raw argument content reaches the audit row.
    """
    ids = ",".join(hit.rule_id for hit in hits)
    if not ids:
        return base
    if not base:
        return f"rules={ids}"
    return f"{base} [rules={ids}]"


def _fail_closed(tool_name: str, exc: BaseException) -> TriageOutcome:
    """Return the denial Fail-Closed Triage requires after a judging error."""
    return TriageOutcome(
        decision=Decision.DENY_POLICY,
        would_be=None,
        rule_hits=(),
        reason=REASON_TRIAGE_ERROR,
        severity=None,
        labels=frozenset(),
        features=CallFeatures(tool_name=str(tool_name or "")),
        policy=None,
        degraded=f"triage_error:{type(exc).__name__}",
    )
