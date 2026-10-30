"""Deterministic rule catalog. Requirement: Rule Catalog.

Requirement names owned here: Rule Catalog; Rules Before Models.

Rules judge, they do not act: no configuration read, no disk, no store, no
network, no clock of their own. Each rule turns one call (plus, for the window
rules, the read-only trajectory view) into zero or more RuleHit values. The
engine merges them, and only a deny hit concludes anything by itself: every
observe hit is an annotation that travels to the model reviewers with the call.

Rule ownership is by rule text:
R1 same-turn write then execute, R2 inline interpreter, R3 encoded powershell,
R4 download piped into a shell, R5 downloaded file executed, R6 sensitive
configuration read, R7 sensitive read then outbound inside the window, R8 host
absolute path (observation only), R9 trajectory write then execute, R10 python
source that spawns, R11 shell-session write then execute.

Taint escalation is not judged here. It is cross-call and tainted-session state
owned by tooling_guard.trace.escalation.evaluate, which consumes the labels this
package classifies.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Final

from ..policy import paths
from ..policy.allowlists import classify_sensitive_target
from .classify import (
    LABEL_READ_IN_ROOTS,
    LABEL_SINK_DELIVER,
    LABEL_SINK_READ,
    CallFeatures,
    basename,
    is_exec_tool,
    is_read_tool,
    shell_write_targets,
)

ACTION_DENY: Final[str] = "deny"
ACTION_SUSPEND: Final[str] = "suspend"
ACTION_OBSERVE: Final[str] = "observe"
ACTION_ALLOW: Final[str] = "allow"

SEVERITY_HIGH: Final[str] = "high"
SEVERITY_MEDIUM: Final[str] = "medium"

RULE_R1: Final[str] = "R1"
RULE_R2: Final[str] = "R2"
RULE_R3: Final[str] = "R3"
RULE_R4: Final[str] = "R4"
RULE_R5: Final[str] = "R5"
RULE_R6: Final[str] = "R6"
RULE_R7: Final[str] = "R7"
RULE_R8: Final[str] = "R8"
RULE_R9: Final[str] = "R9"
RULE_R10: Final[str] = "R10"
RULE_R11: Final[str] = "R11"

#: The rules judged in this package, in catalog order.
RULES: Final[tuple[str, ...]] = (
    RULE_R1,
    RULE_R2,
    RULE_R3,
    RULE_R4,
    RULE_R5,
    RULE_R6,
    RULE_R7,
    RULE_R8,
    RULE_R9,
    RULE_R10,
    RULE_R11,
)
#: Catalog action per rule. Only the shapes that must never reach a model deny:
#: encoded powershell (R3), a downloaded payload handed to an interpreter (R4)
#: and a sensitive configuration read (R6). Everything else observes: it labels
#: the call so jev and deep see the suspicion, and those two own the conclusion.
RULE_ACTIONS: Final[dict[str, str]] = {
    RULE_R1: ACTION_OBSERVE,
    RULE_R2: ACTION_OBSERVE,
    RULE_R3: ACTION_DENY,
    RULE_R4: ACTION_DENY,
    RULE_R5: ACTION_OBSERVE,
    RULE_R6: ACTION_DENY,
    RULE_R7: ACTION_OBSERVE,
    RULE_R8: ACTION_OBSERVE,
    RULE_R9: ACTION_OBSERVE,
    RULE_R10: ACTION_OBSERVE,
    RULE_R11: ACTION_OBSERVE,
}
#: Catalog severity per rule.
RULE_SEVERITIES: Final[dict[str, str]] = {
    RULE_R1: SEVERITY_HIGH,
    RULE_R2: SEVERITY_HIGH,
    RULE_R3: SEVERITY_HIGH,
    RULE_R4: SEVERITY_HIGH,
    RULE_R5: SEVERITY_HIGH,
    RULE_R6: SEVERITY_HIGH,
    RULE_R7: SEVERITY_HIGH,
    RULE_R8: SEVERITY_MEDIUM,
    RULE_R9: SEVERITY_HIGH,
    RULE_R10: SEVERITY_HIGH,
    RULE_R11: SEVERITY_HIGH,
}

#: R7 window: a sensitive read followed by an outbound call within 30 seconds.
R7_WINDOW_SECONDS: Final[float] = 30.0

#: Catalog version stamped on every audit row this build judges with.
#:
#: Requirement: Rule Set Versioning.  A stored verdict is only meaningful
#: together with the rule catalog that produced it, so the gateway and the
#: /guard command write this value on every row; changing a rule's action,
#: severity or identity means a new value here.  It describes the R1-R11 catalog
#: only and never the policy snapshot, which carries its own policy_version.
RULE_SET_VERSION: Final[str] = "r1-r11/2"

_ACTION_PRIORITY: Final[dict[str, int]] = {
    ACTION_DENY: 3,
    ACTION_SUSPEND: 2,
    ACTION_OBSERVE: 1,
    ACTION_ALLOW: 0,
}
_SEVERITY_PRIORITY: Final[dict[str, int]] = {
    SEVERITY_HIGH: 2,
    SEVERITY_MEDIUM: 1,
}

_PS_FAMILY_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(?:pwsh|powershell)(?:\.exe)?\b"
)
_ENCODED_COMMAND_LADDER: Final[str] = "|".join(
    "encodedcommand"[:length] for length in range(len("encodedcommand"), 1, -1)
)
_R3_ENCODED_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:^|[\s;|&(\x60])[-/\u2013\u2014](?:" + _ENCODED_COMMAND_LADDER + r")\b"
)
_E_FLAG_LADDER: Final[str] = (
    "|".join(
        "encodedcommand"[:length] for length in range(len("encodedcommand"), 0, -1)
    )
    + "|ec"
)
_R3_E_FLAG_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:^|[\s;|&(\x60])[-/\u2013\u2014](?:" + _E_FLAG_LADDER + r")\b"
    r"\s+(?P<argument>[^\s;&|)\]]+)"
)
_COMMAND_PAYLOAD_LADDER: Final[str] = "|".join(
    "command"[:length] for length in range(1, len("command") + 1)
)
_PS_COMMAND_FLAG_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:^|[\s;|&(\x60])[-/\u2013\u2014](?:" + _COMMAND_PAYLOAD_LADDER + r")\b"
)
_R2_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:^|[;|&(\x60\n\s])(?:[A-Za-z0-9_.\\/:-]*[\\/])?(?:"
    r"(?:python3(?:\.\d+)?|python|py|ipython3?(?:\.\d+)?)(?:\.exe)?\s+"
    r"(?:-{1,2}[\w.-]+\s+)*-c\b"
    r"|(?:node|nodejs|bun)(?:\.exe)?\s+(?:-{1,2}[\w.-]+\s+)*"
    r"(?:-e|--eval|-p|--print)\b"
    r"|deno(?:\.exe)?\s+(?:-{1,2}[\w.-]+\s+)*eval\b"
    r"|php(?:\.exe)?\s+(?:-{1,2}[\w.-]+\s+)*(?:-e|-r)\b"
    r"|(?:perl|ruby|lua)(?:\.exe)?\s+(?:-{1,2}[\w.-]+\s+)*-e\b"
    r"|(?:bash|sh|zsh|dash|pwsh|powershell|cmd)(?:\.exe)?\s+"
    r"(?:-{1,2}[\w.-]+\s+)*(?:-c|-command|/c|/k)\b"
    r")"
)
_R4_PIPE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|aria2c"
    r"|base64)(?:\.exe)?\b[^\n]{0,300}\|\s*"
    r"(?:[A-Za-z0-9_.\\/:-]*[\\/])?"
    r"(?:(?:sudo|doas|exec|env|call|start|nohup)(?:\s+[A-Za-z_]\w*=\S*)*\s+)*"
    r"(?:iex|invoke-expression|sh|bash|zsh|dash|python3?|py|pwsh|powershell"
    r"|cmd|node|perl|ruby|php)\b"
)
_R4_SUBST_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(?:iex|invoke-expression|source|sh|bash|zsh|dash|python3?|py"
    r"|pwsh|powershell|cmd|node|perl|ruby|php)(?:\.exe)?\b[^\n]{0,80}?"
    r"(?:<\s*\(|\$\(|\x60)\s*"
    r"(?:[A-Za-z0-9_.\\/:-]*[\\/])?"
    r"(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|aria2c)\b"
)
_R4_IEX_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(?:iex|invoke-expression)\b[^\n]{0,200}?"
    r"(?:downloadstring|downloadfile|downloaddata)\b"
    r"|(?:downloadstring|downloadfile|downloaddata)\b[^\n]{0,200}?"
    r"\b(?:iex|invoke-expression)\b"
)
_R4_DECODE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\bcertutil(?:\.exe)?\b[^\n;|&]{0,200}?"
    r"(?:-decode|-decodehex|-urlcache)\b[^\n]{0,200}?"
    r"(?:&&|;|\|)\s*(?:[A-Za-z0-9_.\\/:-]*[\\/])?"
    r"[A-Za-z0-9_$.-]+\.(?:exe|bat|cmd|ps1|scr|vbs|js|dll)\b"
)
_R4_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("pipe-to-shell", _R4_PIPE_RE),
    ("substitution", _R4_SUBST_RE),
    ("iex-download", _R4_IEX_RE),
    ("certutil-decode-exec", _R4_DECODE_RE),
)
_R5_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(?:curl|wget|iwr|invoke-webrequest)(?:\.exe)?\b[^\n|;]{0,300}?"
    r"(?:\s-o\s+|--output[= ]|--output-document[= ]|-outfile\s+)"
    r"(?P<target>[^\s;&|\"']+)"
)
_R10_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:\bsubprocess\b"
    r"|\bos\s*\.\s*(?:system|popen|exec\w*|spawn\w*|fork|kill\w*)\b"
    r"|\bpty\s*\.\s*spawn\w*\b|\brunpy\b|\b__import__\s*\(|\bcompile\s*\("
    r"|\bimportlib\b|\bexec\b|\beval\b|\bctypes\b)"
)
_IPYTHON_MAGIC_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:^|[\n;])\s*(?:!!?\S"
    r"|%%(?:bash|sh|system|script|perl|ruby|python|python3|pypy|cmd|powershell)\b)"
    r"|\bget_ipython\s*\(\s*\)\s*\.\s*(?:system|getoutput|run_line_magic)\b"
)
_PYTHON_TOOLS: Final[frozenset[str]] = frozenset(
    {"astrbot_execute_python", "astrbot_execute_ipython"}
)
_EXEC_PATH_TOKEN: Final[str] = r"[^\s;&|()<>\"'\x60]*[\\/]"
_EXEC_PATH_TAIL: Final[str] = r"(?:" + _EXEC_PATH_TOKEN + r")?"
_EXEC_ABSOLUTE: Final[str] = r"(?:[A-Za-z]:)?[\\/]" + _EXEC_PATH_TAIL
_EXEC_RELATIVE: Final[str] = r"\.{1,2}[\\/]" + _EXEC_PATH_TAIL
_EXEC_HEAD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:^|[;|&(\x60\n])\s*(?:&\s*)?(?:"
    r"(?:[\w.\\/:-]*[\\/])?"
    r"(?:sh|bash|zsh|dash|python3?|py|node|nodejs|perl|ruby|php|pwsh"
    r"|powershell|cmd)(?:\.exe)?"
    r"|" + _EXEC_ABSOLUTE + r"|" + _EXEC_RELATIVE + r"|start\b|source\b|invoke-item\b"
    r")(?:\s+-{1,2}[\w.-]+(?:[= ]\S+)?)*(?:\s*" + _EXEC_PATH_TOKEN + r")?\s*$"
)
_EXEC_HEAD_LIMIT: Final[int] = 160


@dataclass(frozen=True, slots=True)
class RuleHit:
    """One rule firing on one call. Requirement: Rule Catalog."""

    rule_id: str
    action: str
    severity: str | None = None
    reason: str = ""
    detail: str = ""

    @property
    def priority(self) -> int:
        """Return the merge priority of this hit: deny > suspend > observe."""
        return _ACTION_PRIORITY.get(self.action, 0)

    @property
    def severity_priority(self) -> int:
        """Return the merge priority of the severity: high > medium > none."""
        return _SEVERITY_PRIORITY.get(self.severity or "", 0)

    def as_dict(self) -> dict[str, Any]:
        """Return the audit shape of this hit."""
        return {
            "rule_id": self.rule_id,
            "action": self.action,
            "severity": self.severity,
            "reason": self.reason,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class TrajectoryView:
    """Read-only window of earlier calls of the same subject.

    Requirement: Rule Catalog R7, R9, R11.

    Each entry only has to expose tool, targets, verb and a timestamp through
    an attribute or a mapping key; anything else is ignored.
    """

    entries: tuple[object, ...] = ()
    session_key: str = ""
    now: float = 0.0


def evaluate_rules(
    features: CallFeatures, trajectory: TrajectoryView | None = None
) -> tuple[RuleHit, ...]:
    """Judge one call against the whole catalog.

    Requirement: Rule Catalog; Rules Before Models.

    Args:
        features: The classified call.
        trajectory: Optional read-only window of earlier calls; without it the
            window rules (R7, R9, R11) cannot fire.

    Returns:
        tuple: Every hit, ordered deny before suspend before observe and, at
        equal action, higher severity first. Empty when nothing fired.
    """
    hits: list[RuleHit] = []
    for judge in (
        _rule_r1,
        _rule_r2,
        _rule_r3,
        _rule_r4,
        _rule_r5,
        _rule_r6,
        _rule_r10,
    ):
        hit = judge(features)
        if hit is not None:
            hits.append(hit)
    if trajectory is not None:
        for judge in (_rule_r7, _rule_r9, _rule_r11):
            hit = judge(features, trajectory)
            if hit is not None:
                hits.append(hit)
    hit = _rule_r8(features)
    if hit is not None:
        hits.append(hit)
    hits.sort(key=lambda item: (-item.priority, -item.severity_priority, item.rule_id))
    return tuple(hits)


def merge_rule_hits(hits: tuple[RuleHit, ...]) -> RuleHit | None:
    """Return the hit that decides the call, or None when nothing fired.

    Requirement: Rule Catalog.

    Args:
        hits: Every hit of the call.

    Returns:
        RuleHit | None: The strongest hit by deny > suspend > observe and, at
        equal action, by high > medium severity.
    """
    best: RuleHit | None = None
    for hit in hits:
        if best is None:
            best = hit
            continue
        if (hit.priority, hit.severity_priority) > (
            best.priority,
            best.severity_priority,
        ):
            best = hit
    return best


def _command_text(features: CallFeatures) -> str:
    """Return the command text of a call, joined."""
    return "\n".join(features.texts)


def _hit(rule_id: str, reason: str, detail: str = "") -> RuleHit:
    """Build a hit with the catalog action and severity of one rule."""
    return RuleHit(
        rule_id=rule_id,
        action=RULE_ACTIONS[rule_id],
        severity=RULE_SEVERITIES[rule_id],
        reason=reason,
        detail=detail,
    )


def _executes(text: str, name: str, *, after: int = 0) -> bool:
    """Return whether a text executes the named file after a position.

    Requirement: Rule Catalog R1, R5, R9, R11.

    Args:
        text: The command text.
        name: The bare file name to look for.
        after: Start offset; the write that produced the name is skipped.

    Returns:
        bool: True when the name appears as a command or a command argument
        introduced by an interpreter or a script path.
    """
    needle = name.strip().strip("\"'")
    if not needle:
        return False
    lowered = text.lower()
    wanted = needle.lower()
    target = lowered.find(wanted, after)
    while target != -1:
        before = lowered[target - 1] if target else " "
        if not (before.isalnum() or before in "_.-"):
            head = lowered[max(0, target - _EXEC_HEAD_LIMIT) : target]
            if _EXEC_HEAD_RE.search(head):
                return True
        target = lowered.find(wanted, target + 1)
    return False


def _rule_r1(features: CallFeatures) -> RuleHit | None:
    """R1: one command writes a script and then executes it."""
    if not is_exec_tool(features.tool_name):
        return None
    text = _command_text(features)
    if not text:
        return None
    for target in shell_write_targets(text):
        name = basename(target)
        if name and _executes(text, name):
            return _hit(RULE_R1, "同轮写入脚本后立即执行", f"target={name}")
    return None


def _rule_r2(features: CallFeatures) -> RuleHit | None:
    """R2: an inline interpreter payload (python -c, node -e, bash -c)."""
    if not is_exec_tool(features.tool_name):
        return None
    text = _command_text(features)
    if not text:
        return None
    match = _R2_RE.search(text)
    if match is None:
        return None
    return _hit(RULE_R2, "内联解释器执行载荷", f"form={match.group(0).strip()[:40]}")


def _encoded_e_argument(text: str) -> str:
    """Return the payload of a powershell -e flag, or an empty string.

    Requirement: Rule Catalog R3.

    -e is the shortest abbreviation of -EncodedCommand, so any non-empty
    argument handed to it is an encoded command. The flag must belong to a
    powershell invocation of the same command segment, and its argument must
    not itself be a flag or a path.
    """
    for match in _R3_E_FLAG_RE.finditer(text):
        argument = match.group("argument")
        if not argument or argument[0] in "-/":
            continue
        if _same_powershell_segment(text, match.start()):
            return argument
    return ""


def _same_powershell_segment(text: str, stop: int) -> bool:
    """Return whether a powershell invocation owns the flag before stop.

    A -Command flag opens a script payload, so a flag after it belongs to the
    inner command rather than to powershell itself and is not owned here.
    """
    family = None
    for found in _PS_FAMILY_RE.finditer(text, 0, stop):
        family = found
    if family is None:
        return False
    segment = text[family.end() : stop]
    if any(char in segment for char in ";|&\n"):
        return False
    return _PS_COMMAND_FLAG_RE.search(segment) is None


def _rule_r3(features: CallFeatures) -> RuleHit | None:
    """R3: encoded powershell (encodedcommand or base64 -e payload)."""
    if not is_exec_tool(features.tool_name):
        return None
    text = _command_text(features)
    if not text:
        return None
    encoded = bool(_PS_FAMILY_RE.search(text)) and bool(_R3_ENCODED_RE.search(text))
    base64_e = bool(_encoded_e_argument(text))
    if not encoded and not base64_e:
        return None
    form = "encodedcommand" if encoded else "base64-e"
    return _hit(RULE_R3, "编码后的 powershell 命令", f"form={form}")


def _rule_r4(features: CallFeatures) -> RuleHit | None:
    """R4: a downloaded payload handed straight to an interpreter."""
    if not is_exec_tool(features.tool_name):
        return None
    text = _command_text(features)
    if not text:
        return None
    for form, pattern in _R4_PATTERNS:
        if pattern.search(text) is not None:
            return _hit(RULE_R4, "下载内容直接送入解释器管道", f"form={form}")
    return None


def _rule_r5(features: CallFeatures) -> RuleHit | None:
    """R5: one command downloads to a file and then executes that file."""
    if not is_exec_tool(features.tool_name):
        return None
    text = _command_text(features)
    if not text:
        return None
    for match in _R5_RE.finditer(text):
        name = basename(match.group("target"))
        if name and _executes(text, name, after=match.end()):
            return _hit(RULE_R5, "下载落盘后执行该文件", f"target={name}")
    return None


def _rule_r6(features: CallFeatures) -> RuleHit | None:
    """R6: a read or grep of a sensitive configuration file.

    Requirement: Rule Catalog R6.

    Only the non-private-key sensitive configuration shape suspends here; a
    private key file name is a policy denial, judged by the policy layer before
    this catalog runs.
    """
    if not is_read_tool(features.tool_name):
        return None
    for target in features.targets:
        verdict = classify_sensitive_target(target)
        if verdict.private_key or not verdict.suspend:
            continue
        return _hit(RULE_R6, "读取敏感配置文件", f"target={basename(target)}")
    return None


def _rule_r7(features: CallFeatures, trajectory: TrajectoryView) -> RuleHit | None:
    """R7: a sensitive read shortly before an outbound call."""
    if not (
        LABEL_SINK_READ in features.labels or LABEL_SINK_DELIVER in features.labels
    ):
        return None
    for entry in trajectory.entries:
        if not _in_window(entry, trajectory.now):
            continue
        name = _sensitive_read_name(entry)
        if not name:
            continue
        return _hit(
            RULE_R7,
            "非私钥敏感配置读取后短时内向外发送",
            f"after={name}",
        )
    return None


def _rule_r8(features: CallFeatures) -> RuleHit | None:
    """R8: an absolute path handed to a command (host sandbox blind spot).

    Requirement: Rule Catalog (R8). A read-only call whose every absolute
    literal sits inside the project roots does not fire: the sandbox blind spot
    has no effect a read could produce. The label is the whole test, and only
    the classification stage can set it, so a write, a delete or an execute
    never carries it and every other shape keeps firing with the same rule id,
    the same observe action and the same absolute_paths count.
    """
    if LABEL_READ_IN_ROOTS in features.labels:
        return None
    if not is_exec_tool(features.tool_name):
        return None
    literals: list[str] = []
    for text in features.texts:
        literals.extend(paths.extract_absolute_paths(text))
    if not literals:
        return None
    return _hit(
        RULE_R8,
        "命令携带绝对路径，原生沙箱不覆盖该路径",
        f"absolute_paths={len(literals)}",
    )


def _rule_r9(features: CallFeatures, trajectory: TrajectoryView) -> RuleHit | None:
    """R9: an earlier write of a target, then this call executes it."""
    if not is_exec_tool(features.tool_name):
        return None
    if features.tool_name == "astrbot_shell_session":
        return None
    text = _command_text(features)
    if not text:
        return None
    for entry in trajectory.entries:
        if not _entry_wrote(entry):
            continue
        for target in _entry_targets(entry):
            name = basename(target)
            if name and _executes(text, name):
                return _hit(RULE_R9, "轨迹内写入的文件随后被执行", f"target={name}")
    return None


def _rule_r10(features: CallFeatures) -> RuleHit | None:
    """R10: python or ipython source that spawns a process or evals."""
    if features.tool_name not in _PYTHON_TOOLS:
        return None
    text = _command_text(features)
    if not text:
        return None
    magic = _IPYTHON_MAGIC_RE.search(text)
    if magic is not None:
        return _hit(
            RULE_R10,
            "python 源码中的 shell 逃逸或魔法命令",
            f"symbol={magic.group(0).strip()[:40]}",
        )
    match = _R10_RE.search(text)
    if match is None:
        return None
    return _hit(
        RULE_R10, "python 源码含进程派生或动态求值调用", f"symbol={match.group(0)}"
    )


def _rule_r11(features: CallFeatures, trajectory: TrajectoryView) -> RuleHit | None:
    """R11: a shell session writes a file, later executes it in the session."""
    if features.tool_name != "astrbot_shell_session":
        return None
    text = _command_text(features)
    if not text:
        return None
    for entry in trajectory.entries:
        if not _entry_wrote(entry):
            continue
        for target in _entry_targets(entry):
            name = basename(target)
            if name and _executes(text, name):
                return _hit(
                    RULE_R11,
                    "会话内写入的文件随后在会话中执行",
                    f"target={name}",
                )
    return None


def _field(entry: object, name: str, default: Any = None) -> Any:
    """Read one field of a trajectory entry from a mapping or an object."""
    if isinstance(entry, Mapping):
        return entry.get(name, default)
    return getattr(entry, name, default)


def _entry_targets(entry: object) -> tuple[str, ...]:
    """Return the normalized targets recorded for one trajectory entry."""
    value = _field(entry, "targets", ())
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(str(item) for item in value if str(item).strip())
    return ()


def _entry_verb(entry: object) -> str:
    """Return the verb recorded for one trajectory entry."""
    value = _field(entry, "verb", "")
    return value.strip().lower() if isinstance(value, str) else ""


def _entry_tool(entry: object) -> str:
    """Return the tool name recorded for one trajectory entry."""
    value = _field(entry, "tool", "")
    return value if isinstance(value, str) else ""


def _entry_wrote(entry: object) -> bool:
    """Return whether one trajectory entry wrote a file."""
    if _entry_verb(entry) in {"write", "edit"}:
        return True
    return _entry_tool(entry) in {
        "astrbot_file_write_tool",
        "astrbot_file_edit_tool",
    }


def _sensitive_read_name(entry: object) -> str:
    """Return the sensitive configuration file name an entry read, if any."""
    tool = _entry_tool(entry)
    if _entry_verb(entry) != "read" and tool not in {
        "astrbot_file_read_tool",
        "astrbot_grep_tool",
    }:
        return ""
    for target in _entry_targets(entry):
        verdict = classify_sensitive_target(target)
        if verdict.suspend and not verdict.private_key:
            return basename(target)
    return ""


def _entry_at(entry: object) -> float | None:
    """Return the timestamp recorded for one trajectory entry, in epoch seconds.

    Requirement: Rule Catalog (R7). A stored record keeps `at` as ISO-8601 text
    (`trace.summary.utc_now_text`), so a text instant is parsed here: a window
    rule that could only read numbers placed every record outside the clock and
    treated the whole history as recent.
    """
    for name in ("at", "ts", "time", "timestamp"):
        value = _field(entry, name)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        if isinstance(value, str):
            instant = _instant_of(value)
            if instant is not None:
                return instant
    return None


def _instant_of(text: str) -> float | None:
    """Return one ISO-8601 text as epoch seconds, or None when unreadable."""
    raw = text.strip()
    if not raw:
        return None
    candidate = raw[:-1] + "+00:00" if raw[-1:] in {"Z", "z"} else raw
    try:
        instant = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant.timestamp()


def _in_window(entry: object, now: float) -> bool:
    """Return whether one trajectory entry falls inside the R7 window."""
    stamp = _entry_at(entry)
    if stamp is None:
        return True
    delta = now - stamp
    return 0.0 <= delta <= R7_WINDOW_SECONDS
