"""Allow-side hints, requester lists and secret classification.

Requirement: Requester Allowlist and Denylist; Content Whitelist and Secret
Blocking; Path Whitelist Semantics.

This file owns the sensitive-target and requester verdicts instead of layers.py
because both are list semantics (who may call, which content is sensitive),
while layers.py only fixes the evaluation order. Nothing here can grant a
pass-through: a whitelist match never skips per-call rules, policy, audit or
redaction, and the private-key class always lands on the deny side.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

from ..anonymize import MAX_REDACT_SCAN
from . import paths

_LOGGER = logging.getLogger(__name__)

MAX_SECRET_SCAN: Final[int] = MAX_REDACT_SCAN
"""Characters one deny-side secret scan reads; longer text is cut first.

Requirement: Content Whitelist and Secret Blocking. A call argument is
attacker-controlled, and every configured pattern is a regular expression whose
cost grows with the text it is given, so the deny side carries the same bound the
redaction side already applies. Truncation can only hide a match that starts past
the bound, so it never turns a found secret into a safe one; the loss is reported
through SECRET_SCAN_TRUNCATED instead of staying silent.
"""

SECRET_SCAN_TRUNCATED: Final[str] = "secret_scan_truncated"
"""Degradation marker: a secret scan only read MAX_SECRET_SCAN characters."""

SECRET_SCAN_INCOMPLETE: Final[str] = "secret_scan_incomplete"
"""Deny word and degradation marker: the scan never read past its window.

Requirement: Content Whitelist and Secret Blocking. A capped scan is not a
clean "no secret": the deny side cannot claim the absence of a secret in text it
never read, so an incomplete scan denies on its own instead of falling through
to the approvable sensitive-config suspension. A stable literal, so one stored
row can be searched for it.
"""

HINT_REDUCE_LATENCY: Final[str] = "reduce_latency"
HINT_REDUCE_TRAJECTORY_DEPTH: Final[str] = "reduce_trajectory_depth"

PRIVATE_KEY_NAMES: Final[frozenset[str]] = frozenset(
    {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ed448"}
)
PRIVATE_KEY_SUFFIXES: Final[tuple[str, ...]] = (
    ".pem",
    ".key",
    ".ppk",
    ".p12",
    ".pfx",
)
PUBLIC_KEY_SUFFIXES: Final[tuple[str, ...]] = (".pub", ".crt", ".cer", ".p7b")
SENSITIVE_NAMES: Final[frozenset[str]] = frozenset(
    {".env", ".npmrc", ".pypirc", ".netrc", ".git-credentials"}
)
SENSITIVE_PREFIXES: Final[tuple[str, ...]] = (".env.",)
SENSITIVE_MARKERS: Final[tuple[str, ...]] = (
    "secret",
    "credential",
    "passwd",
    "password",
    "apikey",
    "api_key",
)
SENSITIVE_DIRS: Final[frozenset[str]] = frozenset(
    {".ssh", ".gnupg", ".aws", ".azure", ".docker", ".kube"}
)
CREDENTIAL_DIR_NON_SECRET_NAMES: Final[frozenset[str]] = frozenset(
    {"known_hosts", "known_hosts.old", "config", "authorized_keys"}
)
CREDENTIAL_DIR_PUBLIC_SUFFIXES: Final[tuple[str, ...]] = (".pub",)
PRIVATE_KEY_NAME_PREFIXES: Final[tuple[str, ...]] = tuple(
    sorted(name + "_" for name in PRIVATE_KEY_NAMES)
)
PRIVATE_KEY_BACKUP_SUFFIXES: Final[tuple[str, ...]] = (
    "~",
    ".bak",
    ".old",
    ".orig",
    ".backup",
    ".save",
    ".copy",
    ".txt",
    ".tmp",
    ".swp",
    ".1",
    ".2",
    ".3",
    ".4",
    ".5",
    ".6",
    ".7",
    ".8",
    ".9",
)
_PRIVATE_KEY_MARKERS: Final[tuple[str, ...]] = ("private key", "private_key")
_REFERENCE_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[\s\"'\x60|&;<>()\[\]{},=]+")
_HOME_REFERENCE_RE: Final[re.Pattern[str]] = re.compile(
    r"%(?:homedrive%%homepath%|userprofile%|homepath%|homedrive%)"
    r"|\$(?:\{home\}|home(?![a-z0-9_]))|~",
    re.IGNORECASE,
)

_PRIVATE_KEY_BLOCK_RE: Final[re.Pattern[str]] = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY(?: BLOCK)?-----"
)


@dataclass(frozen=True, slots=True)
class RequesterVerdict:
    """Membership and hint outcome for one request subject.

    Requirement: Requester Allowlist and Denylist.

    Attributes:
        subject: The key that was matched, exactly as supplied.
        blacklisted: The key is listed in user_blacklist.
        whitelisted: The key is listed in user_whitelist.
        blocked: The requester must be denied (blacklist or an unusable key).
        strictest: The key was empty or not platform_id:sender_id.
        hints: Allow-side hints; a whitelist may only reduce latency or depth.
        reason: Administrator-facing explanation with no secret content.
    """

    subject: str
    blacklisted: bool = False
    whitelisted: bool = False
    blocked: bool = False
    strictest: bool = False
    hints: tuple[str, ...] = ()
    reason: str = ""


@dataclass(frozen=True, slots=True)
class SensitiveVerdict:
    """Policy class of one file target.

    Requirement: Content Whitelist and Secret Blocking.

    Attributes:
        kind: "private_key", "sensitive_config" or an empty string.
        filename: Base name only; the audit never stores file content.
        private_key: The target is a private key and must be denied.
        suspend: The target is another sensitive config and must be suspended.
        rule_id: Rule identifier aligned with the call-triage catalogue.
        severity: Risk of the conclusion, or None.
        reason: Explanation with no secret content.
    """

    kind: str = ""
    filename: str = ""
    private_key: bool = False
    suspend: bool = False
    rule_id: str | None = None
    severity: str | None = None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class AllowHints:
    """Allow-side hints for one judged call.

    Requirement: Policy Layers and Precedence; Path Whitelist Semantics.

    Attributes:
        requester_whitelisted: The subject is in user_whitelist.
        path_whitelisted: A target sits inside path_whitelist.
        in_project_root: A target sits inside project_roots.
        destination_allowed: Every destination is in destination_allowlist.
    """

    requester_whitelisted: bool = False
    path_whitelisted: bool = False
    in_project_root: bool = False
    destination_allowed: bool = False

    def labels(self) -> tuple[str, ...]:
        """Return the hint labels this verdict justifies.

        Requirement: Policy Layers and Precedence.

        Returns:
            Hint labels only; never an allow decision.
        """
        hints: list[str] = []
        if (
            self.requester_whitelisted
            or self.path_whitelisted
            or self.in_project_root
            or self.destination_allowed
        ):
            hints.append(HINT_REDUCE_LATENCY)
        if self.requester_whitelisted or self.path_whitelisted or self.in_project_root:
            hints.append(HINT_REDUCE_TRAJECTORY_DEPTH)
        return tuple(hints)


def check_requester(subject_key: str, config: object) -> RequesterVerdict:
    """Match one request subject against the requester lists.

    Requirement: Requester Allowlist and Denylist.

    The subject key is fixed as platform_id:sender_id. The blacklist is decided
    first and rejects. The whitelist can only lower judgement latency or
    trajectory-analysis depth: it never passes a call through, never skips rules,
    policy, audit or redaction, and never overrides a deny rule. A bare sender id
    and an empty key are not equivalent to a subject key and are denied.

    Args:
        subject_key: Expected "platform_id:sender_id".
        config: A GatewayConfig or PolicySnapshot.

    Returns:
        A RequesterVerdict; blocked=True means the call must be denied.
    """
    subject = subject_key.strip() if isinstance(subject_key, str) else ""
    platform_id, separator, sender_id = subject.partition(":")
    blacklist = _listed(config, "user_blacklist")
    whitelist = _listed(config, "user_whitelist")
    if not separator or not platform_id.strip() or not sender_id.strip():
        return RequesterVerdict(
            subject=subject,
            blocked=True,
            strictest=True,
            reason=(
                "主体键缺失或不是 platform_id:sender_id；按最严格策略拒绝，不创建票据。"
            ),
        )
    if subject in blacklist:
        return RequesterVerdict(
            subject=subject,
            blacklisted=True,
            whitelisted=subject in whitelist,
            blocked=True,
            reason="命中 user_blacklist；黑名单先判并拒绝。",
        )
    if subject in whitelist:
        return RequesterVerdict(
            subject=subject,
            whitelisted=True,
            hints=(HINT_REDUCE_LATENCY, HINT_REDUCE_TRAJECTORY_DEPTH),
            reason=(
                "命中 user_whitelist；仅降低判定延迟或轨迹分析深度，"
                "仍执行逐次判定、审计与脱敏。"
            ),
        )
    return RequesterVerdict(
        subject=subject,
        reason="未命中请求方名单；按常规逐次判定处理。",
    )


def classify_sensitive_target(target: str | paths.PathKey) -> SensitiveVerdict:
    """Classify one file target as private key, sensitive config or neither.

    Requirement: Content Whitelist and Secret Blocking.

    Private key names (id_rsa, id_ed25519, private .pem/.key files) are deny-side
    at the highest priority. The classification runs on the base name of the
    resolved path, folded to lower case with back slashes reduced to "/" and
    with trailing dots, trailing white space and backup suffixes (.bak, .old,
    .txt, ~, .1 … .9) removed, so that names Windows silently truncates and
    editor backups cannot slip through. An unknown file inside a credential
    directory (.ssh, .gnupg, .aws, .azure, .docker, .kube) is treated as a
    private key as well: a wrong deny costs one suspension-free refusal, a wrong
    allow leaks a key. The known non-secret names of those directories
    (CREDENTIAL_DIR_NON_SECRET_NAMES, CREDENTIAL_DIR_PUBLIC_SUFFIXES) are not
    denied for their directory alone: they fall through to the content-level
    judgement. Other sensitive configs (.env, names containing "secret",
    .npmrc) are suspension candidates matching rule R6 at medium risk.
    Public-key suffixes are not treated as private keys.

    Args:
        target: Path text or an already normalized PathKey.

    Returns:
        A SensitiveVerdict; kind is empty when the target is not sensitive.
    """
    key = (
        target
        if isinstance(target, paths.PathKey)
        else paths.normalize_path(str(target))
    )
    source = key.resolved or key.display or key.raw
    filename = _filename(source) or _filename(key.display or key.raw)
    if _is_private_key(filename):
        return SensitiveVerdict(
            kind="private_key",
            filename=filename,
            private_key=True,
            severity="high",
            reason=(
                f"私钥文件 {filename} 由最高优先级 policy deny 拒绝；"
                "审计只记录占位与长度，不记录内容。"
            ),
        )
    directory = _sensitive_directory(source) or _sensitive_directory(
        key.display or key.raw
    )
    if directory and not _is_credential_dir_non_secret(filename):
        return SensitiveVerdict(
            kind="private_key",
            filename=filename,
            private_key=True,
            severity="high",
            reason=(
                f"凭据目录 {directory} 下的文件 {filename} 按私钥类 deny 拒绝；"
                "审计只记录占位与长度，不记录内容。"
            ),
        )
    if _is_sensitive_config(filename):
        return SensitiveVerdict(
            kind="sensitive_config",
            filename=filename,
            suspend=True,
            rule_id="R6",
            severity="medium",
            reason=f"敏感配置文件 {filename} 命中 R6（medium），转挂起审批。",
        )
    return SensitiveVerdict(filename=filename)


def contains_private_key_block(text: str) -> bool:
    """Detect a PEM or OpenSSH private key block inside text.

    Requirement: Content Whitelist and Secret Blocking.

    Args:
        text: Content about to be written or delivered.

    Returns:
        True when the text holds a private key block header.
    """
    if not isinstance(text, str) or not text:
        return False
    return _PRIVATE_KEY_BLOCK_RE.search(text) is not None


def private_key_reference(text: str) -> str:
    """Return a reason when a command text names a private key path, else "".

    Requirement: Content Whitelist and Secret Blocking.

    Shell commands reach the key through a home reference (cat ~/.ssh/id_rsa,
    type %USERPROFILE%\\.ssh\\id_rsa) instead of an absolute path literal, so the
    policy layer cannot see a path target. Every shell word is expanded and
    matched against the private key catalogue, and a credential directory hit is
    treated the same way unless the word names a known non-secret file of those
    directories (CREDENTIAL_DIR_NON_SECRET_NAMES, CREDENTIAL_DIR_PUBLIC_SUFFIXES):
    reading .ssh/config or .ssh/known_hosts is not a key access and stays a
    content-level decision.

    Args:
        text: Shell command or any free text that may embed a path.

    Returns:
        An administrator-facing reason naming the matched base name, or "".
    """
    if not isinstance(text, str) or not text:
        return ""
    expanded = _HOME_REFERENCE_RE.sub("~", text.casefold())
    for token in _REFERENCE_TOKEN_RE.split(expanded):
        candidate = token.strip(" .\t\r\n'\"")
        if len(candidate) < 3:
            continue
        name = candidate.rsplit("/", 1)[-1]
        if _is_private_key(candidate):
            return f"命令文本中出现私钥文件 {name}；按最高优先级 policy deny 拒绝。"
        if _sensitive_directory(candidate) and not _is_credential_dir_non_secret(
            candidate
        ):
            return f"命令文本中出现凭据目录 {name}；按私钥类 deny 拒绝。"
    return ""


@dataclass(frozen=True, slots=True)
class SecretScan:
    """Outcome of one deny-side secret scan.

    Requirement: Content Whitelist and Secret Blocking.

    Attributes:
        pattern: The first matching pattern source, or None when nothing matched.
        length: Characters the caller asked to scan.
        scanned: Characters actually scanned; at most MAX_SECRET_SCAN.
    """

    pattern: str | None = None
    length: int = 0
    scanned: int = 0

    @property
    def truncated(self) -> bool:
        """Report whether the scan stopped short of the whole text."""
        return self.scanned < self.length

    @property
    def marker(self) -> str:
        """Return the degradation marker of this scan, empty when it read it all."""
        if not self.truncated:
            return ""
        return (
            f"{SECRET_SCAN_TRUNCATED} length={self.length} scanned={self.scanned}"
            f" limit={MAX_SECRET_SCAN}"
        )

    @property
    def incomplete(self) -> bool:
        """Report a scan that read its whole window and still found no hit."""
        return self.pattern is None and self.truncated

    @property
    def incomplete_marker(self) -> str:
        """Return the marker of an incomplete scan, empty when it is not one."""
        if not self.incomplete:
            return ""
        return f"{SECRET_SCAN_INCOMPLETE} {self.marker}"


def scan_secret_patterns(text: str, patterns: Sequence[re.Pattern[str]]) -> SecretScan:
    """Return the first configured secret pattern that matches text, and the cost.

    Requirement: Content Whitelist and Secret Blocking. The scan is bounded by
    MAX_SECRET_SCAN, which is what keeps one megabyte argument from turning every
    configured expression into a full-text pass on the event loop. The marker is
    logged here rather than by a caller, so no call site can truncate silently,
    including callers that only want the hit and drop this report.

    Args:
        text: Redacted-free text to scan; the caller keeps it out of the audit.
        patterns: Compiled patterns from the policy snapshot.

    Returns:
        The hit, the scanned length, and the length of the whole text.
    """
    if not isinstance(text, str) or not text:
        return SecretScan()
    length = len(text)
    window = text[:MAX_SECRET_SCAN]
    scan = SecretScan(length=length, scanned=len(window))
    for pattern in patterns:
        if pattern.search(window):
            scan = SecretScan(
                pattern=pattern.pattern, length=length, scanned=len(window)
            )
            break
    if scan.truncated:
        _LOGGER.warning(
            "%s length=%d scanned=%d limit=%d",
            SECRET_SCAN_TRUNCATED,
            length,
            len(window),
            MAX_SECRET_SCAN,
        )
    return scan


def secret_pattern_hit(text: str, patterns: Sequence[re.Pattern[str]]) -> str | None:
    """Return the first configured secret pattern that matches text.

    Requirement: Content Whitelist and Secret Blocking. This is the bare hit of
    scan_secret_patterns; a caller that reports degradation asks that function
    for the whole SecretScan instead.

    Args:
        text: Redacted-free text to scan; the caller keeps it out of the audit.
        patterns: Compiled patterns from the policy snapshot.

    Returns:
        The matching pattern source for the audit trail, or None.
    """
    return scan_secret_patterns(text, patterns).pattern


def allow_hints(
    subject: str,
    config: object,
    *,
    targets: Sequence[paths.PathKey] = (),
    destinations: Sequence[str] = (),
) -> AllowHints:
    """Collect the allow-side hints for one call.

    Requirement: Policy Layers and Precedence; Path Whitelist Semantics.

    Args:
        subject: Request subject key.
        config: A GatewayConfig or PolicySnapshot.
        targets: Normalized path targets of the call.
        destinations: Outbound destinations of the call.

    Returns:
        AllowHints; the caller must still run the deny side and the tier default.
    """
    requester = check_requester(subject, config)
    return AllowHints(
        requester_whitelisted=requester.whitelisted,
        path_whitelisted=any(
            paths.is_path_whitelisted(key, config, include_project_roots=False)
            for key in targets
        ),
        in_project_root=any(paths.is_in_project_roots(key, config) for key in targets),
        destination_allowed=bool(destinations)
        and all(_destination_listed(item, config) for item in destinations),
    )


def trusted_in_project_roots(
    targets: Iterable[str | paths.PathKey], config: object
) -> bool:
    """Return whether every target of one call sits inside a project root.

    Requirement: Path Whitelist Semantics; Policy Layers and Precedence.

    Answers one question only: do all targets of this call lie inside a
    configured project root? An empty call is never trusted -- "no target" says
    nothing about where the call will act -- and one target outside the roots, or
    one the normalizer refused to resolve, untrusts the whole call, so a single
    target decides for the call and never for the part of it that is in-root.
    ``paths.is_in_project_roots`` is the only membership test used, and it
    already refuses a deny-side key (relative with no base, ADS stream, broken 8.3
    name, un-expandable "~" or environment reference, ...) as well as a key with
    no resolved form, which is why those two conditions need no second check here.

    The ``trust_project_roots`` switch is deliberately not read here: the
    predicate must stay usable by any caller that only needs the fact "all targets
    are in the roots", so the caller reads ``config.trust_project_roots`` and
    decides whether that fact changes its conclusion.

    Args:
        targets: Path texts or already normalized PathKeys of the call.
        config: A GatewayConfig or PolicySnapshot.

    Returns:
        True only when targets is non-empty and every target is inside a
        project root.
    """
    keys = tuple(targets)
    if not keys:
        return False
    return all(paths.is_in_project_roots(key, config) for key in keys)


def _listed(config: object, name: str) -> frozenset[str]:
    """Read one string list from a config or snapshot as an immutable set."""
    value = getattr(config, name, None)
    if value is None:
        holder = getattr(config, "config", config)
        value = getattr(holder, name, ())
    if not isinstance(value, (list, tuple, set, frozenset)):
        return frozenset()
    return frozenset(item for item in value if isinstance(item, str) and item)


def _filename(text: str) -> str:
    """Return the base name of a path text with any trailing separator removed."""
    cleaned = text.rstrip("\\/")
    if not cleaned:
        return ""
    return cleaned.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]


def _clean_text(text: str) -> str:
    """Fold a raw path or name text into a comparable form.

    Trailing dots and white space are dropped first because Windows strips them
    when it opens a path, then the text is lower-cased and every back slash is
    reduced to "/" so that one comparison covers both separators.
    """
    value = str(text).casefold().replace("\\", "/")
    return value.rstrip(" .\t\r\n/")


def _name_variants(text: str) -> tuple[str, ...]:
    """Return the comparable base names of one raw path or file-name text."""
    cleaned = _clean_text(text)
    if not cleaned:
        return ()
    name = cleaned.rsplit("/", 1)[-1].strip("*?")
    if not name:
        return ()
    stripped = _strip_backup_suffixes(name)
    if stripped and stripped != name:
        return (name, stripped)
    return (name,)


def _strip_backup_suffixes(name: str) -> str:
    """Remove every trailing backup suffix and trailing dot from a base name."""
    value = name
    for _ in range(4):
        trimmed = value.rstrip(" .\t")
        hit = next(
            (
                suffix
                for suffix in PRIVATE_KEY_BACKUP_SUFFIXES
                if trimmed.endswith(suffix) and len(trimmed) > len(suffix)
            ),
            "",
        )
        if not hit:
            return trimmed
        value = trimmed[: -len(hit)]
    return value.rstrip(" .\t")


def _sensitive_directory(text: str) -> str:
    """Return the credential directory component of a path text, or ""."""
    cleaned = _clean_text(text)
    if not cleaned:
        return ""
    for part in cleaned.split("/"):
        if part in SENSITIVE_DIRS:
            return part
    return ""


def _is_private_key(text: str) -> bool:
    """Return whether a raw path or base name denotes a private key."""
    for name in _name_variants(text):
        if name.endswith(PUBLIC_KEY_SUFFIXES):
            continue
        if name in PRIVATE_KEY_NAMES or name.startswith(PRIVATE_KEY_NAME_PREFIXES):
            return True
        if any(marker in name for marker in _PRIVATE_KEY_MARKERS):
            return True
        if name.endswith(PRIVATE_KEY_SUFFIXES):
            return True
    return False


def _is_credential_dir_non_secret(text: str) -> bool:
    """Return whether a base name is a known non-secret file of those directories."""
    cleaned = _clean_text(text)
    if not cleaned:
        return False
    name = cleaned.rsplit("/", 1)[-1].strip("*?")
    if not name:
        return False
    return name in CREDENTIAL_DIR_NON_SECRET_NAMES or name.endswith(
        CREDENTIAL_DIR_PUBLIC_SUFFIXES
    )


def _is_sensitive_config(text: str) -> bool:
    """Return whether a raw path or base name denotes another sensitive config."""
    for name in _name_variants(text):
        if name in SENSITIVE_NAMES or name.startswith(SENSITIVE_PREFIXES):
            return True
        if any(marker in name for marker in SENSITIVE_MARKERS):
            return True
    return False


def _destination_listed(destination: str, config: object) -> bool:
    """Return whether one destination matches destination_allowlist."""
    allowed = _listed(config, "destination_allowlist")
    if not allowed or not isinstance(destination, str) or not destination.strip():
        return False
    lowered = destination.strip().lower()
    if lowered in allowed:
        return True
    host = _host_of(lowered)
    return bool(host) and host in allowed


def _host_of(value: str) -> str:
    """Return the lower-cased host of an absolute URL, or an empty string."""
    if "://" not in value:
        return ""
    try:
        return (urlsplit(value).hostname or "").lower()
    except ValueError:
        return ""
