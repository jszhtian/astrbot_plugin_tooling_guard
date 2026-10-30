"""Immutable policy snapshot. Requirement: Policy Snapshot Consistency.

Requirement names owned here: Policy Snapshot Consistency.

A snapshot resolves every configured path once, compiles every secret pattern
once and freezes the requester lists, so one judgement never re-reads
configuration. Changes reach the gateway only through a new snapshot with a
monotonic policy version, and every field difference between two snapshots is
available as an audit summary with secret fields redacted.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, fields
from typing import Final

from ..anonymize import validate_secret_pattern
from . import paths
from .config import GatewayConfig

_SENSITIVE_FIELD_RE: Final[re.Pattern[str]] = re.compile(
    r"(api_key|secret|token|password)",
    re.IGNORECASE,
)
_MAX_RENDERED_CHARS: Final[int] = 200
_REDACTED: Final[str] = "<redacted>"


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    """One immutable policy version used for an entire judgement.

    Requirement: Policy Snapshot Consistency.

    Attributes:
        version: Positive, strictly increasing policy version.
        config: The validated configuration this snapshot was built from.
        mode: Effective enforcement mode ("observe" or "enforce").
        strict_path_whitelist: Writes outside every whitelisted root are denied.
        trust_project_roots: An all-in-root call skips the tier_default layer.
        exempt_tools: Tools allowed to skip deeper analysis only.
        user_whitelist: Request subject keys that only get latency/depth hints.
        user_blacklist: Request subject keys that are denied first.
        destination_allowlist: Outbound destinations that only get hints.
        path_whitelist: Resolved location whitelist roots.
        path_deny: Resolved location denylist roots.
        project_roots: Resolved project roots, hints only.
        secret_patterns: Compiled secret detection patterns.
        warnings: Load-time notes for entries that are not resolvable.
        digest: SHA-256 over the configuration values behind this version.
    """

    version: int
    config: GatewayConfig
    mode: str
    strict_path_whitelist: bool
    trust_project_roots: bool
    exempt_tools: frozenset[str]
    user_whitelist: frozenset[str]
    user_blacklist: frozenset[str]
    destination_allowlist: frozenset[str]
    path_whitelist: tuple[paths.PathKey, ...]
    path_deny: tuple[paths.PathKey, ...]
    project_roots: tuple[paths.PathKey, ...]
    secret_patterns: tuple[re.Pattern[str], ...]
    warnings: tuple[str, ...]
    digest: str

    @property
    def policy_version(self) -> str:
        """Return the version recorded with every decision this snapshot made."""
        return f"policy-v{self.version}"


@dataclass(frozen=True, slots=True)
class SnapshotFieldChange:
    """One audited field difference between two policy versions.

    Requirement: Policy Snapshot Consistency.

    Attributes:
        field: Configuration field name.
        old: Rendered previous value, or a redaction placeholder.
        new: Rendered new value, or a redaction placeholder.
        redacted: The field holds a credential and its value is not shown.
    """

    field: str
    old: str
    new: str
    redacted: bool = False


@dataclass(frozen=True, slots=True)
class SnapshotDiff:
    """Audit summary of what changed between two policy versions.

    Requirement: Policy Snapshot Consistency.

    Attributes:
        old_version: Version of the previous snapshot.
        new_version: Version of the current snapshot.
        changes: One entry per changed field.
    """

    old_version: int
    new_version: int
    changes: tuple[SnapshotFieldChange, ...]

    @property
    def changed_fields(self) -> tuple[str, ...]:
        """Return the changed field names in configuration order."""
        return tuple(change.field for change in self.changes)

    @property
    def is_empty(self) -> bool:
        """Return whether the two snapshots carry the same policy values."""
        return not self.changes

    @property
    def requester_lists_changed(self) -> bool:
        """Return whether a requester list changed; it applies only afterwards."""
        return any(
            change.field in {"user_whitelist", "user_blacklist"}
            for change in self.changes
        )

    def to_summary(self) -> str:
        """Render the diff as one audit line without any secret value."""
        if self.is_empty:
            return f"{self.old_version}->{self.new_version}: 策略无变更"
        rendered = "; ".join(
            f"{change.field}={change.old}->{change.new}" for change in self.changes
        )
        return f"{self.old_version}->{self.new_version}: {rendered}"


def build_snapshot(
    config: GatewayConfig,
    *,
    previous: PolicySnapshot | None = None,
    version: int | None = None,
) -> PolicySnapshot:
    """Build one immutable policy snapshot from a validated configuration.

    Requirement: Policy Snapshot Consistency.

    Args:
        config: A configuration returned by validate_config.
        previous: The snapshot being replaced; the new version follows it.
        version: Explicit positive version, used instead of the derived one.

    Returns:
        A PolicySnapshot with resolved path roots, compiled secret patterns and
        frozen requester lists.

    Raises:
        TypeError: config is not a validated GatewayConfig.
        ValueError: the version is not positive and increasing, or a secret
            pattern cannot be compiled.
    """
    if not isinstance(config, GatewayConfig):
        raise TypeError(
            "build_snapshot 只接受已校验的 GatewayConfig；原始映射会绕过配置校验。"
        )
    resolved_version = _resolve_version(previous, version)
    warnings: list[str] = []
    deny = tuple(paths.normalize_path(item) for item in config.path_deny)
    whitelist = tuple(paths.normalize_path(item) for item in config.path_whitelist)
    roots = tuple(paths.normalize_path(str(item)) for item in config.project_roots)
    for name, entries in (
        ("path_deny", deny),
        ("path_whitelist", whitelist),
        ("project_roots", roots),
    ):
        for entry in entries:
            if entry.deny_side:
                warnings.append(
                    f"{name} 条目 {entry.raw!r} 不可解析"
                    f"（{'/'.join(entry.hazards)}）；按 deny 侧语义处理。"
                )
    return PolicySnapshot(
        version=resolved_version,
        config=config,
        mode=config.mode,
        strict_path_whitelist=bool(config.strict_path_whitelist),
        trust_project_roots=bool(config.trust_project_roots),
        exempt_tools=frozenset(config.exempt_tools),
        user_whitelist=frozenset(config.user_whitelist),
        user_blacklist=frozenset(config.user_blacklist),
        destination_allowlist=frozenset(config.destination_allowlist),
        path_whitelist=whitelist,
        path_deny=deny,
        project_roots=roots,
        secret_patterns=_compile_patterns(config, warnings),
        warnings=tuple(warnings),
        digest=_digest(config),
    )


def diff_snapshot(old: PolicySnapshot, new: PolicySnapshot) -> SnapshotDiff:
    """Summarize the audited differences between two policy versions.

    Requirement: Policy Snapshot Consistency.

    Args:
        old: The snapshot that was in force.
        new: The snapshot that is about to take effect.

    Returns:
        A SnapshotDiff whose rendered values never expose a credential.

    Raises:
        TypeError: either argument is not a PolicySnapshot.
    """
    if not isinstance(old, PolicySnapshot) or not isinstance(new, PolicySnapshot):
        raise TypeError("diff_snapshot 只接受 PolicySnapshot。")
    changes: list[SnapshotFieldChange] = []
    for field in fields(GatewayConfig):
        before = getattr(old.config, field.name)
        after = getattr(new.config, field.name)
        if before == after:
            continue
        redacted = bool(_SENSITIVE_FIELD_RE.search(field.name))
        changes.append(
            SnapshotFieldChange(
                field=field.name,
                old=_render(before, redacted=redacted),
                new=_render(after, redacted=redacted),
                redacted=redacted,
            )
        )
    return SnapshotDiff(
        old_version=old.version,
        new_version=new.version,
        changes=tuple(changes),
    )


def _resolve_version(previous: PolicySnapshot | None, version: int | None) -> int:
    """Return the next policy version and enforce monotonic growth."""
    if version is None:
        version = 1 if previous is None else previous.version + 1
    if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
        raise ValueError("policy_version 必须是正整数。")
    if previous is not None and not isinstance(previous, PolicySnapshot):
        raise TypeError("previous 必须是 PolicySnapshot。")
    if previous is not None and version <= previous.version:
        raise ValueError("policy_version 必须单调递增。")
    return version


def _compile_patterns(
    config: GatewayConfig, warnings: list[str]
) -> tuple[re.Pattern[str], ...]:
    """Compile the secret patterns once, dropping any outside the safe subset.

    The subset check is the one the configuration slice already runs, so a pattern
    is accepted or refused in both places. A refused pattern never reaches the
    effective set: it scans untrusted text inside the deny check, and a
    synchronous match cannot be interrupted by a timeout, so an expression that
    backtracks exponentially would freeze the event loop of every judgement. The
    pattern is dropped with a warning rather than raising, because one bad
    operator expression must not take the whole snapshot down.
    """
    if not config.secret_patterns:
        raise ValueError("secret_patterns 为空；拒绝构建策略快照。")
    compiled: list[re.Pattern[str]] = []
    for index, pattern in enumerate(config.secret_patterns):
        code = validate_secret_pattern(pattern)
        if code is not None:
            warnings.append(
                f"secret_patterns[{index}] 未启用（{code}）；"
                "该正则不进入生效集合，网关仍会启用。"
            )
            continue
        try:
            compiled.append(re.compile(pattern))
        except re.error as exc:
            raise ValueError(
                f"secret_patterns[{index}] 无法编译（{exc}）；拒绝构建策略快照。"
            ) from exc
    if not compiled:
        warnings.append(
            "secret_patterns 全部未启用；本次快照没有生效的脱敏扫描正则，网关仍会启用。"
        )
    return tuple(compiled)


def _digest(config: GatewayConfig) -> str:
    """Return a stable digest over the configuration values of this version."""
    parts: list[str] = []
    for field in fields(GatewayConfig):
        value = getattr(config, field.name)
        if isinstance(value, (list, tuple)):
            rendered = ",".join(str(item) for item in value)
        else:
            rendered = str(value)
        parts.append(f"{field.name}={rendered}")
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def _render(value: object, *, redacted: bool) -> str:
    """Render one configuration value for the audit trail, bounded in length."""
    if redacted:
        return _REDACTED
    if isinstance(value, (list, tuple)):
        rendered = ",".join(str(item) for item in value)
    else:
        rendered = str(value)
    if len(rendered) <= _MAX_RENDERED_CHARS:
        return rendered
    return rendered[: _MAX_RENDERED_CHARS - 3] + "..."
