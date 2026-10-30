"""Windows target normalization. Requirement: Windows Path Normalization.

Requirement names owned here: Windows Path Normalization, Path Denylist and
Target Extraction for All Tools. Every helper is a pure function over text and
read-only filesystem metadata: no configuration reload, no network access, no
writes. A target that cannot be resolved is always deny-side; nothing in this
module grants a pass-through.

Expansion follows the host before any normalization: a leading "~" expands like
the host's `Path(path).expanduser()`, and %VAR%, $VAR and ${VAR} expand from
the environment. A name that does not expand leaves a deny-side hazard instead
of being read literally, and a relative target with no known base is deny-side
as well: resolving it against the plugin process working directory would judge a
different object than the per-session host workspace the tool actually touches.
"""

from __future__ import annotations

import ntpath
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

HAZARD_ADS: Final[str] = "ads"
HAZARD_SHORT_NAME: Final[str] = "short_name"
HAZARD_DEVICE: Final[str] = "device_namespace"
HAZARD_DRIVE_RELATIVE: Final[str] = "drive_relative"
HAZARD_UNRESOLVED: Final[str] = "unresolved"
HAZARD_EMPTY: Final[str] = "empty"
HAZARD_RELATIVE: Final[str] = "relative"
HAZARD_LOOPBACK: Final[str] = "loopback_share"
HAZARD_ENV_UNRESOLVED: Final[str] = "env_unresolved"
HAZARD_HOME_UNRESOLVED: Final[str] = "home_unresolved"
HAZARD_RELATIVE_UNKNOWN_BASE: Final[str] = "relative_unknown_base"

DENY_SIDE_HAZARDS: Final[frozenset[str]] = frozenset(
    {
        HAZARD_ADS,
        HAZARD_LOOPBACK,
        HAZARD_SHORT_NAME,
        HAZARD_DEVICE,
        HAZARD_DRIVE_RELATIVE,
        HAZARD_UNRESOLVED,
        HAZARD_EMPTY,
        HAZARD_ENV_UNRESOLVED,
        HAZARD_HOME_UNRESOLVED,
        HAZARD_RELATIVE_UNKNOWN_BASE,
    }
)

_NAMESPACE_PREFIX: Final[str] = "\\\\?\\"
_NAMESPACE_UNC: Final[str] = "\\\\?\\unc\\"
_DEVICE_PREFIX: Final[str] = "\\\\.\\"
_DEVICE_TARGETS: Final[tuple[str, ...]] = (
    "volume{",
    "globalroot",
    "pipe\\",
    "device\\",
)

_SHORT_NAME_RE: Final[re.Pattern[str]] = re.compile(r"~\d")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"[\\/]+")
_MSYS_DRIVE_RE: Final[re.Pattern[str]] = re.compile(r"^/([A-Za-z])(?=[\\/])")
_ABSOLUTE_START_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:[A-Za-z]:[\\/]|\\\\|/[A-Za-z]/)"
)
_PATH_RUN: Final[str] = r"[^\s\"'\x60<>|&;]*"
_ABSOLUTE_LITERAL_RE: Final[re.Pattern[str]] = re.compile(
    "(?<![0-9A-Za-z_])("
    + r"\\\\\?\\"
    + _PATH_RUN
    + r"|\\\\.\\"
    + _PATH_RUN
    + r"|\\\\[^\\/\s\"']+(?:\\"
    + _PATH_RUN
    + r")?"
    + r"|[A-Za-z]:[\\/]"
    + _PATH_RUN
    + r"|/(?:[A-Za-z])/"
    + _PATH_RUN
    + r")"
)
_QUOTE_CHARS: Final[tuple[str, ...]] = ('"', "'", "\x60")
_LOOPBACK_UNC_RE: Final[re.Pattern[str]] = re.compile(
    r"^\\\\(?P<host>localhost|127\.0\.0\.1|\[::1\]|::1)\\(?P<share>[^\\/]+)",
    re.IGNORECASE,
)
_ADMIN_SHARE_RE: Final[re.Pattern[str]] = re.compile(r"^(?P<drive>[A-Za-z])\$")
_PERCENT_VAR_RE: Final[re.Pattern[str]] = re.compile(r"%([^%\\/]+)%")
_DOLLAR_VAR_RE: Final[re.Pattern[str]] = re.compile(
    r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)


@dataclass(frozen=True, slots=True)
class PathKey:
    """One normalized Windows path identity with its deny-side hazards.

    Requirement: Windows Path Normalization.

    Attributes:
        raw: The argument text exactly as received.
        display: Lexically normalized path keeping the original letter case.
        resolved: Real path after reparse-point resolution, or None.
        anchor: Drive root or UNC share part of the path.
        stream: NTFS alternate data stream name when the target carries one.
        hazards: Normalization hazards; see DENY_SIDE_HAZARDS.
    """

    raw: str
    display: str
    resolved: str | None = None
    anchor: str = ""
    stream: str | None = None
    hazards: tuple[str, ...] = ()

    @property
    def folded(self) -> str:
        """Case-folded text of display, used for containment comparison."""
        return fold_path(self.display)

    @property
    def resolved_folded(self) -> str:
        """Case-folded text of the resolved real path, or an empty string."""
        return fold_path(self.resolved) if self.resolved else ""

    @property
    def comparison(self) -> str:
        """Best available path text for a containment comparison."""
        return self.resolved_folded or self.folded

    @property
    def deny_side(self) -> bool:
        """Whether the target must be treated as deny-side (unresolvable)."""
        return bool(set(self.hazards) & DENY_SIDE_HAZARDS)

    @property
    def has_ads(self) -> bool:
        """Whether the target carries an NTFS alternate data stream."""
        return self.stream is not None


def fold_path(value: str) -> str:
    """Fold one path text into a Windows comparison key.

    Requirement: Windows Path Normalization.

    Args:
        value: Any path text using either separator style.

    Returns:
        Separator-normalized, case-folded text; an empty string for empty input.
    """
    if not isinstance(value, str) or not value:
        return ""
    return ntpath.normpath(value.replace("/", "\\")).lower()


def normalize_path(raw: str, *, base: str | os.PathLike[str] | None = None) -> PathKey:
    """Normalize one Windows target and fail closed when it is unresolvable.

    Requirement: Windows Path Normalization; Target Extraction for All Tools.

    Handles home and environment expansion, case folding (the original case
    stays visible in display), dot-dot resolution, symbolic links / junctions /
    reparse points, the long-path prefix, UNC paths (backslash and forward-slash
    spellings alike), NTFS alternate data streams and 8.3 short names. UNC
    targets are normalized lexically only, so no network round trip happens.

    Args:
        raw: Path text as it arrived in the tool arguments or command text.
        base: Directory used for relative input, normally the host per-session
            workspace of the call. When it is None a relative target is
            deny-side instead of being resolved against the plugin process CWD,
            because the host would resolve it somewhere else entirely.

    Returns:
        A PathKey. PathKey.deny_side is True whenever the target is empty,
        device-namespaced, drive-relative, carries an ADS stream, keeps an
        unresolvable 8.3 short name, cannot be resolved at all, carries a "~" or
        environment reference that does not expand, or is relative with no
        known base.
    """
    original = raw if isinstance(raw, str) else str(raw)
    text = original.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1].strip()
    if not text:
        return PathKey(raw=original, display="", hazards=(HAZARD_EMPTY,))

    hazards: list[str] = []
    text = _expand_target(text, hazards)
    text = _msys_drive(text)
    text = _strip_namespace_prefix(text, hazards)
    text = _loopback_share(text, hazards)
    path_text, stream = _split_stream(text, hazards)
    joined = _absolute_path(path_text, base, hazards)
    if joined is None:
        return PathKey(
            raw=original,
            display=ntpath.normpath(path_text),
            stream=stream,
            hazards=tuple(dict.fromkeys(hazards)),
        )
    lexical = _expand_short_name(ntpath.normpath(joined), hazards)
    anchor = ntpath.splitdrive(lexical)[0]
    resolved = _resolve(lexical, hazards)
    return PathKey(
        raw=original,
        display=lexical,
        resolved=resolved,
        anchor=anchor,
        stream=stream,
        hazards=tuple(dict.fromkeys(hazards)),
    )


def is_within(root: str | PathKey, target: str | PathKey) -> bool:
    """Return whether a target sits inside a root, component by component.

    Requirement: Path Denylist; Path Whitelist Semantics.

    Components are compared rather than raw characters, so "C:/a/bc" is not
    inside "C:/a/b".

    Args:
        root: Root directory text or key.
        target: Target path text or key.

    Returns:
        True only when the whole root component list prefixes the target.
    """
    root_text = fold_path(root if isinstance(root, str) else root.comparison)
    target_text = fold_path(target if isinstance(target, str) else target.comparison)
    if not root_text or not target_text:
        return False
    root_parts = _parts(root_text)
    target_parts = _parts(target_text)
    if not root_parts or len(target_parts) < len(root_parts):
        return False
    return target_parts[: len(root_parts)] == root_parts


def is_path_denied(
    target: str | PathKey,
    config: object,
    *,
    base: str | os.PathLike[str] | None = None,
) -> bool:
    """Return whether a target falls on the deny side of policy.

    Requirement: Path Denylist; Policy Layers and Precedence.

    A path inside a path_deny root is denied before any allow-side hint is
    consulted, and an unresolvable target is deny-side by construction. An
    unresolvable deny root still matches lexically, so a mistyped root never
    silently stops denying.

    Args:
        target: Path text or an already normalized PathKey.
        config: A GatewayConfig or PolicySnapshot.
        base: Directory used for relative input.

    Returns:
        True when the target must be denied.
    """
    key = (
        target
        if isinstance(target, PathKey)
        else normalize_path(str(target), base=base)
    )
    if key.deny_side:
        return True
    entries = _listed_paths(config, "path_deny")
    return any(_entry_matches(entry, key) for entry in entries)


def is_path_whitelisted(
    target: str | PathKey,
    config: object,
    *,
    base: str | os.PathLike[str] | None = None,
    include_project_roots: bool = False,
) -> bool:
    """Return whether a target sits inside a configured location whitelist.

    Requirement: Path Whitelist Semantics.

    Both sides are compared as resolved paths, so a junction or symlink that
    leaves the whitelisted directory does not inherit the whitelist. A
    whitelisted location is a latency or depth hint only: the caller must still
    run per-call judgement, audit and redaction.

    Args:
        target: Path text or an already normalized PathKey.
        config: A GatewayConfig or PolicySnapshot.
        base: Directory used for relative input.
        include_project_roots: Also accept project_roots as whitelist roots.

    Returns:
        True when the resolved target is inside a resolved whitelist root.
    """
    key = (
        target
        if isinstance(target, PathKey)
        else normalize_path(str(target), base=base)
    )
    if key.deny_side or not key.resolved_folded:
        return False
    names = ["path_whitelist"]
    if include_project_roots:
        names.append("project_roots")
    for name in names:
        for entry in _listed_paths(config, name):
            if entry.resolved_folded and is_within(
                entry.resolved_folded, key.resolved_folded
            ):
                return True
    return False


def is_in_project_roots(
    target: str | PathKey,
    config: object,
    *,
    base: str | os.PathLike[str] | None = None,
) -> bool:
    """Return whether a target sits inside a configured project root.

    Requirement: Path Whitelist Semantics.

    A project root is an allow-side hint only: it may reduce latency or
    trajectory-analysis depth and never replaces per-call judgement.

    Args:
        target: Path text or an already normalized PathKey.
        config: A GatewayConfig or PolicySnapshot.
        base: Directory used for relative input.

    Returns:
        True when the resolved target is inside a resolved project root.
    """
    key = (
        target
        if isinstance(target, PathKey)
        else normalize_path(str(target), base=base)
    )
    if key.deny_side or not key.resolved_folded:
        return False
    for entry in _listed_paths(config, "project_roots"):
        if entry.resolved_folded and is_within(
            entry.resolved_folded, key.resolved_folded
        ):
            return True
    return False


def extract_absolute_paths(text: str) -> tuple[str, ...]:
    """Extract absolute path literals from shell command or python code text.

    Requirement: Path Denylist; Target Extraction for All Tools.

    Handles quoted and unquoted forms, double-escaped literals such as
    "C:\\x\\y", "C:/x/y", the MSYS "/d/x/y" form, long-path and UNC forms.

    Args:
        text: Shell command or python code text.

    Returns:
        Absolute path literals in first-seen order, de-duplicated case
        insensitively; an empty tuple when the text holds no absolute literal.
    """
    if not isinstance(text, str) or not text:
        return ()
    found: list[str] = []
    seen: set[str] = set()
    for segment in _quoted_segments(text):
        _remember_forms(found, seen, segment.strip())
    for match in _ABSOLUTE_LITERAL_RE.finditer(text):
        _remember_forms(found, seen, match.group(1).strip())
    return tuple(found)


def _quoted_segments(text: str) -> tuple[str, ...]:
    """Split text into the inner bodies of single, double and back quotes."""
    segments: list[str] = []
    for quote in _QUOTE_CHARS:
        if quote in text:
            segments.extend(text.split(quote)[1::2])
    return tuple(segments)


def _remember_forms(found: list[str], seen: set[str], candidate: str) -> None:
    """Record a literal as written and, when it differs, unescaped.

    A python source literal ("C:\\\\x") and a shell literal ("\\\\srv\\share")
    cannot be told apart lexically, so both readings are kept; normalization
    collapses the difference for deny matching.
    """
    _remember(found, seen, candidate)
    unescaped = _unescape_literal(candidate)
    if unescaped != candidate:
        _remember(found, seen, unescaped)


def _remember(found: list[str], seen: set[str], candidate: str) -> None:
    """Record one candidate literal when it is absolute and still unseen."""
    if not candidate or not _ABSOLUTE_START_RE.match(candidate):
        return
    marker = fold_path(candidate)
    if not marker or marker in seen:
        return
    seen.add(marker)
    found.append(candidate)


def _unescape_literal(text: str) -> str:
    """Collapse doubled backslashes that appear in python or shell literals."""
    if "\\\\" not in text:
        return text
    return text.replace("\\\\", "\\")


def _expand_target(text: str, hazards: list[str]) -> str:
    """Expand a leading "~" and every environment reference in one target.

    Requirement: Windows Path Normalization.

    The host resolves a file argument with Path(path).expanduser() before it
    opens anything, and shell text reaches the operating system through a shell
    that expands the percent, dollar and braced dollar forms of an environment
    reference. Judging the literal text would judge a different object than the
    tool touches. A reference that does not expand is never read literally: it
    keeps a deny-side hazard, because an unknown name makes the real target
    unknowable.

    Args:
        text: Stripped path text of one target.
        hazards: Hazard list of the running normalization, appended in place.

    Returns:
        The expanded text, or the input when it holds nothing to expand.
    """
    return _expand_vars(_expand_home(text, hazards), hazards)


def _expand_home(text: str, hazards: list[str]) -> str:
    """Expand a leading "~" exactly like the host's Path.expanduser().

    Args:
        text: Stripped path text of one target.
        hazards: Hazard list of the running normalization, appended in place.

    Returns:
        The expanded text, or the input when the home directory is unknown.
    """
    if not text.startswith("~"):
        return text
    expanded = ntpath.expanduser(text)
    if expanded != text and ntpath.isabs(expanded):
        return expanded
    hazards.append(HAZARD_HOME_UNRESOLVED)
    return text


def _expand_vars(text: str, hazards: list[str]) -> str:
    """Expand the percent, dollar and braced dollar variable forms.

    Args:
        text: Path text of one target, already home-expanded.
        hazards: Hazard list of the running normalization, appended in place.

    Returns:
        The text with every known reference replaced; an unknown reference is
        kept verbatim and flagged HAZARD_ENV_UNRESOLVED.
    """
    if "%" not in text and "$" not in text:
        return text

    def from_percent(match: re.Match[str]) -> str:
        return _substitute(match.group(1), match.group(0), hazards)

    def from_dollar(match: re.Match[str]) -> str:
        name = match.group("braced") or match.group("plain")
        return _substitute(name, match.group(0), hazards)

    return _DOLLAR_VAR_RE.sub(from_dollar, _PERCENT_VAR_RE.sub(from_percent, text))


def _substitute(name: str, reference: str, hazards: list[str]) -> str:
    """Return one environment value, or keep the reference and flag it.

    Args:
        name: Variable name as written in the target.
        reference: The full reference text, used when the name is unknown.
        hazards: Hazard list of the running normalization, appended in place.

    Returns:
        The variable value, or the reference text unchanged when unknown.
    """
    value = _env_value(name)
    if value is None:
        hazards.append(HAZARD_ENV_UNRESOLVED)
        return reference
    return value


def _env_value(name: str) -> str | None:
    """Look an environment variable up case-insensitively.

    Args:
        name: Variable name as written in the target.

    Returns:
        The value, or None when this process does not define the name.
    """
    value = os.environ.get(name)
    if value is not None:
        return value
    folded = name.casefold()
    for key, candidate in os.environ.items():
        if key.casefold() == folded:
            return candidate
    return None


def _msys_drive(text: str) -> str:
    """Rewrite a Git-Bash style "/d/x/y" drive path into "D:/x/y"."""
    match = _MSYS_DRIVE_RE.match(text)
    if not match:
        return text
    return f"{match.group(1).upper()}:{text[2:]}"


def _strip_namespace_prefix(text: str, hazards: list[str]) -> str:
    """Remove a long-path or UNC namespace prefix and flag device names.

    The fold to backslashes happens only when the text carries no recognised
    backslash prefix, so backslash behaviour is unchanged. It matters because the
    operating system folds "/" before it opens anything: "//?/C:/Windows/x.txt"
    reaches the very file "\\\\?\\C:\\Windows\\x.txt" does, and the deny side has to
    judge both spellings alike instead of letting the forward-slash one through.
    """
    lowered = text.lower()
    if "/" in text and not lowered.startswith((_NAMESPACE_PREFIX, _DEVICE_PREFIX)):
        folded = text.replace("/", "\\")
        if folded.lower().startswith((_NAMESPACE_PREFIX, _DEVICE_PREFIX)):
            text = folded
            lowered = folded.lower()
    if lowered.startswith(_NAMESPACE_UNC):
        return "\\\\" + text[len(_NAMESPACE_UNC) :]
    if lowered.startswith(_NAMESPACE_PREFIX):
        rest = text[len(_NAMESPACE_PREFIX) :]
        if rest.lower().startswith(_DEVICE_TARGETS):
            hazards.append(HAZARD_DEVICE)
        return rest
    if lowered.startswith(_DEVICE_PREFIX):
        hazards.append(HAZARD_DEVICE)
        return text
    return text


def _loopback_share(text: str, hazards: list[str]) -> str:
    """Rewrite a loopback administrative share onto its local drive path.

    A path such as \\\\localhost\\C$\\Users\\me\\x.txt reaches the very file
    C:\\Users\\me\\x.txt through the local server service, so the deny side has to
    judge the same target instead of an unreachable share. A loopback UNC path
    whose share is not administrative cannot be rewritten and is flagged
    deny-side rather than being taken as harmless outside every root. Forward
    slashes are folded to backslashes before matching, so "//127.0.0.1/D$/x"
    reaches the same conclusion as the backslash spelling: the operating system
    opens both forms.
    """
    match = _LOOPBACK_UNC_RE.match(text)
    if match is None and "/" in text:
        folded = text.replace("/", "\\")
        match = _LOOPBACK_UNC_RE.match(folded)
        if match is not None:
            text = folded
    if match is None:
        return text
    admin = _ADMIN_SHARE_RE.match(match.group("share"))
    if admin is None:
        hazards.append(HAZARD_LOOPBACK)
        return text
    remainder = text[match.end() :]
    if not remainder.startswith(("\\", "/")):
        remainder = "\\" + remainder
    return admin.group("drive").upper() + ":" + remainder


def _split_stream(text: str, hazards: list[str]) -> tuple[str, str | None]:
    """Split an NTFS alternate data stream off a path and flag drive-relative."""
    drive, rest = ntpath.splitdrive(text)
    stream: str | None = None
    if ":" in rest:
        path_part, _, tail = rest.partition(":")
        if tail:
            stream = tail
            hazards.append(HAZARD_ADS)
        rest = path_part
    if drive and not drive.startswith("\\\\") and not rest.startswith(("\\", "/")):
        hazards.append(HAZARD_DRIVE_RELATIVE)
    return drive + rest, stream


def _absolute_path(
    path_text: str,
    base: str | os.PathLike[str] | None,
    hazards: list[str],
) -> str | None:
    """Resolve a relative path against base, or fail closed without a base.

    Requirement: Windows Path Normalization.

    The host resolves a relative tool argument against the per-session workspace
    of the call, which the plugin process CWD does not reproduce. Without a base
    the target therefore stays deny-side (HAZARD_RELATIVE_UNKNOWN_BASE) instead
    of borrowing the plugin CWD and judging a different file than the one the
    tool opens.

    Args:
        path_text: Target text that is not absolute.
        base: Known base directory of the call, or None when unknown.
        hazards: Hazard list of the running normalization.

    Returns:
        The absolute target text, or None when the base is unknown.
    """
    if ntpath.isabs(path_text):
        return path_text
    hazards.append(HAZARD_RELATIVE)
    if base is None:
        hazards.append(HAZARD_RELATIVE_UNKNOWN_BASE)
        return None
    return ntpath.join(str(base), path_text)


def _expand_short_name(path: str, hazards: list[str]) -> str:
    """Expand an 8.3 short name, or flag it as unresolvable deny-side."""
    if not _SHORT_NAME_RE.search(path):
        return path
    expanded = _long_path_name(path)
    if expanded and fold_path(expanded) != fold_path(path):
        return expanded
    if os.path.exists(path):
        return path
    hazards.append(HAZARD_SHORT_NAME)
    return path


def _long_path_name(path: str) -> str | None:
    """Return the long form of path when the platform exposes one."""
    getter = getattr(os.path, "getlongpathname", None)
    if callable(getter):
        try:
            value = getter(path)
        except (OSError, ValueError):
            value = None
        if isinstance(value, str) and value:
            return value
    return _windows_long_path_name(path)


def _windows_long_path_name(path: str) -> str | None:
    """Ask the Windows kernel for the long form of an 8.3 short path."""
    if os.name != "nt":
        return None
    try:
        import ctypes
    except ImportError:
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        buffer = ctypes.create_unicode_buffer(32768)
        length = kernel32.GetLongPathNameW(path, buffer, 32768)
    except (AttributeError, OSError, ValueError):
        return None
    if not length:
        return None
    return buffer.value or None


def _resolve(lexical: str, hazards: list[str]) -> str | None:
    """Resolve reparse points without failing on missing targets.

    Requirement: Windows Path Normalization.
    """
    if os.name != "nt" or lexical.startswith("\\\\"):
        return ntpath.normpath(lexical)
    resolved = ""
    try:
        resolved = os.path.realpath(lexical)
    except (OSError, RuntimeError, ValueError):
        resolved = ""
    if not resolved:
        try:
            resolved = str(Path(lexical).resolve(strict=False))
        except (OSError, RuntimeError, ValueError):
            resolved = ""
    if not resolved:
        hazards.append(HAZARD_UNRESOLVED)
        return None
    return ntpath.normpath(resolved)


def _parts(folded: str) -> tuple[str, ...]:
    """Split folded path text into comparison components."""
    return tuple(part for part in _SEPARATOR_RE.split(folded) if part)


def _entry_matches(entry: PathKey, key: PathKey) -> bool:
    """Match a configured root against a target using every available form."""
    pairs = (
        (entry.resolved_folded, key.resolved_folded),
        (entry.folded, key.folded),
        (entry.folded, key.resolved_folded),
        (entry.resolved_folded, key.folded),
    )
    return any(root and target and is_within(root, target) for root, target in pairs)


def _listed_paths(config: object, name: str) -> tuple[PathKey, ...]:
    """Read one path list from a config or snapshot and normalize its entries.

    Review finding R9-07: an entry is normalized with no base, so it must already
    be absolute. validate_config refuses a section-relative entry with the
    path_not_absolute issue instead of accepting one here, because a base guess
    (the plugin working directory) would describe a different object than the
    absolute target the host tool opens, and the deny root would silently never
    match. A relative entry that still arrives here (a hand-built config) simply
    matches nothing; it cannot be widened into a deny-everything rule.
    """
    value = getattr(config, name, None)
    if value is None:
        holder = getattr(config, "config", config)
        value = getattr(holder, name, ())
    if not isinstance(value, (list, tuple)):
        return ()
    entries: list[PathKey] = []
    for item in value:
        if isinstance(item, PathKey):
            entries.append(item)
        elif isinstance(item, (str, os.PathLike)):
            entries.append(normalize_path(str(item)))
    return tuple(entries)
