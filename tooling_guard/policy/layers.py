"""Static layer of the review chain. Requirement: Policy Layers and Precedence.

Requirement names owned here: Policy Layers and Precedence.

The static layer answers exactly one question: is this call one of the named
high-risk shapes that must be refused without asking anybody? Those shapes are
the requester blacklist, the path denylist, credentials and private keys
(including secrets found in the text), a sensitive configuration read, and a
strict-whitelist write outside every root. Everything else is `PASS`: the call
carries no static objection and goes on to the model reviewers, which own every
other conclusion. A whitelist hit is the only static approval and it is recorded
as `ALLOW` so the reviewers can be skipped.

Every evaluation reads one immutable PolicySnapshot: configuration is never
re-read inside a judgement.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Final

from . import allowlists, paths
from .snapshot import PolicySnapshot
from .tools import KNOWN_TOOLS


class PolicyDecision(str, Enum):
    """The only four static-layer conclusions.

    Requirement: Policy Layers and Precedence.

    PASS is the neutral answer: the static layer raised no objection and the
    models decide. It is not an approval, so it can never release a call on its
    own.
    """

    ALLOW = "allow"
    DENY = "deny"
    PASS = "pass"
    SUSPEND = "suspend"


SOURCE_DENY: Final[str] = "policy_deny"
SOURCE_SUSPEND: Final[str] = "policy_suspend"
SOURCE_STATIC_PASS: Final[str] = "static_pass"
SOURCE_WHITELIST: Final[str] = "whitelist"

LAYER_DENY_REQUESTER: Final[str] = "deny_requester"
LAYER_DENY_TOOL: Final[str] = "deny_tool"
LAYER_DENY_PATH: Final[str] = "deny_path"
LAYER_DENY_SECRET: Final[str] = "deny_secret"
LAYER_SENSITIVE_CONFIG: Final[str] = "sensitive_config"
LAYER_STRICT_WHITELIST: Final[str] = "strict_path_whitelist"
LAYER_UNKNOWN_TOOL: Final[str] = "unknown_tool"
#: The allow side: every target or the requester itself is whitelisted.
LAYER_WHITELIST: Final[str] = "whitelist"
#: The neutral default: nothing static objected, the models decide.
LAYER_STATIC_PASS: Final[str] = "static_pass"

WOULD_BE_DENY_REQUESTER: Final[str] = "deny_requester"
WOULD_BE_DENY_POLICY: Final[str] = "deny_policy"
WOULD_BE_SUSPEND: Final[str] = "suspend"

RULE_SENSITIVE_CONFIG: Final[str] = "R6"
SEVERITY_MEDIUM: Final[str] = "medium"
SEVERITY_HIGH: Final[str] = "high"


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    """One managed call as the policy layers see it.

    Requirement: Policy Layers and Precedence.

    Attributes:
        tool_name: Managed tool name after unwrapping.
        subject: Request subject key, platform_id:sender_id.
        raw_paths: Path-like arguments of the call.
        texts: Shell command or python source text of the call.
        destinations: Outbound destinations of the call.
        content: Content about to be written or delivered.
        writes: The call has a write side effect.
        base: Directory used to resolve relative targets.
    """

    tool_name: str
    subject: str
    raw_paths: tuple[str, ...] = ()
    texts: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()
    content: str = ""
    writes: bool = False
    base: str | None = None


@dataclass(frozen=True, slots=True)
class PolicyOutcome:
    """One policy conclusion with the layer and reason that produced it.

    Requirement: Policy Layers and Precedence.

    Attributes:
        decision: Actual conclusion in the configured mode: allow, deny, suspend.
        expected: What the layers concluded before the mode was applied.
        layer: The layer that decided, for example deny_path.
        source: Audit source label, for example policy_deny or tier_default.
        reason: Administrator-facing explanation with no secret content.
        policy_version: Version of the snapshot that produced this outcome.
        would_be: Shadow action recorded in observe mode, else None.
        hints: Allow-side hints that may only reduce latency or depth.
        exempt: The tool is exempt from deeper analysis, never from this check.
        rule_id: Rule identifier aligned with the call-triage catalogue.
        severity: Risk of the conclusion, or None.
        denied_targets: Normalized targets that triggered the deny side.
    """

    decision: PolicyDecision
    expected: PolicyDecision
    layer: str
    source: str
    reason: str
    policy_version: str
    would_be: str | None = None
    hints: tuple[str, ...] = ()
    exempt: bool = False
    rule_id: str | None = None
    severity: str | None = None
    denied_targets: tuple[paths.PathKey, ...] = ()

    @property
    def passed(self) -> bool:
        """Whether a whitelist approved the call outright."""
        return self.expected is PolicyDecision.ALLOW

    @property
    def blocked(self) -> bool:
        """Whether the layers expect the call to be denied."""
        return self.expected is PolicyDecision.DENY

    @property
    def neutral(self) -> bool:
        """Whether the static layer raised no objection at all."""
        return self.expected is PolicyDecision.PASS

    @property
    def suspended(self) -> bool:
        """Whether the layers expect the call to be suspended for approval."""
        return self.expected is PolicyDecision.SUSPEND


def evaluate_policy(
    request: PolicyRequest | object, snapshot: PolicySnapshot
) -> PolicyOutcome:
    """Evaluate one call against a single immutable policy snapshot.

    Requirement: Policy Layers and Precedence; Policy Snapshot Consistency.

    The deny side (requester blacklist, path denylist over normalized targets and
    over absolute literals inside command text, private keys, secret patterns, a
    sensitive configuration read, the strict whitelist write check) is the only
    part of this layer that concludes anything on its own: it answers DENY. The
    allow side only annotates hints, and one call whose requester or every target
    is whitelisted answers ALLOW so the model reviewers can be skipped. Every
    other call answers PASS, the neutral word that says "nothing static objected,
    let the models decide"; there is no per-tier default any more. In observe
    mode a deny or suspend conclusion is reported as decision=allow with the
    intended action in would_be; PASS has no shadow action.

    Args:
        request: A PolicyRequest, or any object or mapping exposing the same
            field names; unreadable fields fail closed.
        snapshot: The PolicySnapshot for this judgement.

    Returns:
        A PolicyOutcome with the conclusion, the deciding layer and the reason.

    Raises:
        TypeError: snapshot is not a PolicySnapshot, so configuration would have
            to be re-read inside the judgement.
    """
    if not isinstance(snapshot, PolicySnapshot):
        raise TypeError(
            "evaluate_policy 只接受不可变 PolicySnapshot；判定中禁止重读配置。"
        )
    req = _coerce_request(request)
    config = snapshot.config
    requester = allowlists.check_requester(req.subject, config)
    exempt = bool(req.tool_name) and req.tool_name in snapshot.exempt_tools
    if requester.blocked:
        return _conclude(
            snapshot,
            PolicyDecision.DENY,
            LAYER_DENY_REQUESTER,
            SOURCE_DENY,
            requester.reason,
            hints=requester.hints,
            exempt=exempt,
            severity=SEVERITY_HIGH,
        )
    if not req.tool_name or req.tool_name not in KNOWN_TOOLS:
        # The static layer only refuses the named high-risk shapes. An unknown
        # tool is not one of them: it is handed to the models with the label
        # that says so, and they own the conclusion.
        return _conclude(
            snapshot,
            PolicyDecision.PASS,
            LAYER_UNKNOWN_TOOL,
            SOURCE_STATIC_PASS,
            f"工具 {req.tool_name!r} 不在受管静态表内；静态层不下结论，交由模型审查。",
            hints=requester.hints,
            exempt=exempt,
            severity=None,
        )
    targets = _normalized_targets(req)
    denied = tuple(key for key in targets if paths.is_path_denied(key, snapshot))
    if denied:
        return _conclude(
            snapshot,
            PolicyDecision.DENY,
            LAYER_DENY_PATH,
            SOURCE_DENY,
            "目标落在 path_deny 内或不可解析："
            + ", ".join(_describe(key) for key in denied),
            hints=requester.hints,
            exempt=exempt,
            severity=SEVERITY_HIGH,
            denied_targets=denied,
        )
    private_key = _private_key_reason(targets, req.content, req.texts)
    if private_key:
        return _conclude(
            snapshot,
            PolicyDecision.DENY,
            LAYER_DENY_SECRET,
            SOURCE_DENY,
            private_key,
            hints=requester.hints,
            exempt=exempt,
            severity=SEVERITY_HIGH,
            denied_targets=targets,
        )
    scan = allowlists.scan_secret_patterns(
        "\n".join((req.content, *req.texts)), snapshot.secret_patterns
    )
    if scan.pattern is not None:
        reason = f"内容命中秘密模式 {scan.pattern!r}；按 deny 侧最高优先级拒绝。"
        if scan.marker:
            reason = f"{reason}（{scan.marker}）"
        return _conclude(
            snapshot,
            PolicyDecision.DENY,
            LAYER_DENY_SECRET,
            SOURCE_DENY,
            reason,
            hints=requester.hints,
            exempt=exempt,
            severity=SEVERITY_HIGH,
            denied_targets=targets,
        )
    if scan.incomplete:
        # Requirement: Content Whitelist and Secret Blocking. A scan that
        # stopped at its window did not answer "no secret"; it answered nothing
        # about the text past MAX_SECRET_SCAN, so it denies on its own instead
        # of falling through to the sensitive-config suspension. A suspension is
        # approvable, and no approval may exempt content the deny side never
        # read.
        return _conclude(
            snapshot,
            PolicyDecision.DENY,
            LAYER_DENY_SECRET,
            SOURCE_DENY,
            "秘密扫描在窗口边界截断，窗口内未命中不能判定为无秘密；按 fail-closed 拒绝"
            f"（{scan.incomplete_marker}）。",
            hints=requester.hints,
            exempt=exempt,
            severity=SEVERITY_HIGH,
            denied_targets=targets,
        )
    allow = allowlists.allow_hints(
        req.subject,
        config,
        targets=targets,
        destinations=req.destinations,
    )
    hints = allow.labels()
    sensitive = _sensitive_targets(targets)
    if sensitive:
        return _conclude(
            snapshot,
            PolicyDecision.DENY,
            LAYER_SENSITIVE_CONFIG,
            SOURCE_DENY,
            "读取敏感配置文件属于静态拒绝项："
            + ", ".join(item.filename for item in sensitive),
            hints=hints,
            exempt=exempt,
            rule_id=RULE_SENSITIVE_CONFIG,
            severity=SEVERITY_HIGH,
            denied_targets=targets,
        )
    if snapshot.strict_path_whitelist and req.writes:
        outside = tuple(
            key
            for key in targets
            if not paths.is_path_whitelisted(key, snapshot, include_project_roots=True)
        )
        if outside:
            return _conclude(
                snapshot,
                PolicyDecision.DENY,
                LAYER_STRICT_WHITELIST,
                SOURCE_DENY,
                "strict_path_whitelist 已启用且写目标不在任何白名单根内："
                + ", ".join(_describe(key) for key in outside),
                hints=hints,
                exempt=exempt,
                severity=SEVERITY_HIGH,
                denied_targets=outside,
            )
    if allow.requester_whitelisted or allow.path_whitelisted:
        # The only static approval: a whitelist already covers this call, so the
        # model reviewers are skipped entirely.
        return _conclude(
            snapshot,
            PolicyDecision.ALLOW,
            LAYER_WHITELIST,
            SOURCE_WHITELIST,
            "请求者或全部目标命中白名单：静态通过，跳过模型审查。",
            hints=hints,
            exempt=exempt,
            severity=None,
        )
    return _conclude(
        snapshot,
        PolicyDecision.PASS,
        LAYER_STATIC_PASS,
        SOURCE_STATIC_PASS,
        f"静态检查通过（工具 {req.tool_name}），由 jev 与 deep 审查决定。",
        hints=hints,
        exempt=exempt,
        severity=None,
    )


def _conclude(
    snapshot: PolicySnapshot,
    expected: PolicyDecision,
    layer: str,
    source: str,
    reason: str,
    *,
    hints: tuple[str, ...] = (),
    exempt: bool = False,
    rule_id: str | None = None,
    severity: str | None = None,
    denied_targets: tuple[paths.PathKey, ...] = (),
) -> PolicyOutcome:
    """Apply the enforcement mode to one expected conclusion."""
    decision = expected
    would_be: str | None = None
    if (
        expected is PolicyDecision.DENY or expected is PolicyDecision.SUSPEND
    ) and snapshot.mode == "observe":
        would_be = _would_be_label(expected, layer)
        decision = PolicyDecision.ALLOW
    return PolicyOutcome(
        decision=decision,
        expected=expected,
        layer=layer,
        source=source,
        reason=reason,
        policy_version=snapshot.policy_version,
        would_be=would_be,
        hints=hints,
        exempt=exempt,
        rule_id=rule_id,
        severity=severity,
        denied_targets=denied_targets,
    )


def _would_be_label(expected: PolicyDecision, layer: str) -> str:
    """Map an expected conclusion to the shadow action recorded in observe."""
    if expected is PolicyDecision.SUSPEND:
        return WOULD_BE_SUSPEND
    if layer == LAYER_DENY_REQUESTER:
        return WOULD_BE_DENY_REQUESTER
    return WOULD_BE_DENY_POLICY


def _coerce_request(request: object) -> PolicyRequest:
    """Read one request into a PolicyRequest, failing closed on bad input."""
    if isinstance(request, PolicyRequest):
        return request
    source: object = request
    if isinstance(request, Mapping):
        source = dict(request)

    def read(name: str, default: object) -> object:
        if isinstance(source, Mapping):
            return source.get(name, default)
        return getattr(source, name, default)

    base = read("base", None)
    return PolicyRequest(
        tool_name=_text(read("tool_name", "")),
        subject=_text(read("subject", "")),
        raw_paths=_texts(read("raw_paths", ())),
        texts=_texts(read("texts", ())),
        destinations=_texts(read("destinations", ())),
        content=_text(read("content", "")),
        writes=bool(read("writes", False)),
        base=base if isinstance(base, str) and base else None,
    )


def _text(value: object) -> str:
    """Read one value as text, turning anything unusable into an empty string."""
    return value.strip() if isinstance(value, str) else ""


def _texts(value: object) -> tuple[str, ...]:
    """Read one value as a tuple of non-empty strings."""
    if isinstance(value, str):
        return (value,) if value.strip() else ()
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(str(item) for item in value if isinstance(item, str) and item)
    return ()


def _normalized_targets(request: PolicyRequest) -> tuple[paths.PathKey, ...]:
    """Normalize path arguments and absolute literals inside command text."""
    targets: list[paths.PathKey] = [
        paths.normalize_path(raw, base=request.base) for raw in request.raw_paths
    ]
    for text in request.texts:
        for literal in paths.extract_absolute_paths(text):
            targets.append(paths.normalize_path(literal, base=request.base))
    return tuple(targets)


def _private_key_reason(
    targets: tuple[paths.PathKey, ...],
    content: str,
    texts: Sequence[str] = (),
) -> str | None:
    """Return the deny reason for a private key target, text reference or block."""
    for key in targets:
        verdict = allowlists.classify_sensitive_target(key)
        if verdict.private_key:
            return verdict.reason
    for text in texts:
        reference = allowlists.private_key_reference(text)
        if reference:
            return reference
    if allowlists.contains_private_key_block(content):
        return "写入内容包含 PEM 或 OpenSSH 私钥块；按最高优先级 policy deny 拒绝。"
    return None


def _sensitive_targets(
    targets: tuple[paths.PathKey, ...],
) -> tuple[allowlists.SensitiveVerdict, ...]:
    """Return the non-private-key sensitive targets that need approval."""
    found: list[allowlists.SensitiveVerdict] = []
    for key in targets:
        verdict = allowlists.classify_sensitive_target(key)
        if verdict.suspend:
            found.append(verdict)
    return tuple(found)


def _describe(key: paths.PathKey) -> str:
    """Render one target for the audit trail without leaking content."""
    if not key.hazards:
        return key.display or key.raw
    return f"{key.display or key.raw}（{'/'.join(key.hazards)}）"
