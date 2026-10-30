"""Call and target classification. Requirement: Triage Inputs.

Requirement names owned here: Triage Inputs.

Pure functions only: one call in, one CallFeatures out. Nothing here reads the
configuration, touches the disk or opens a socket, so the same arguments always
produce the same features.

The label families are orthogonal, exactly as the spec requires:

- untrusted_source marks the producing side: a tool whose *result* enters the
  context and may therefore carry outside instructions.
- sink_read marks a receiving side that sends a query or an address outward.
- sink_deliver marks a receiving side that lets data leave the context.
- read_in_project_roots marks a read-only call whose every absolute path
  literal resolves inside a configured project root. It is a scope fact, not a
  permission: the caller that holds the snapshot computes it, and the only use
  a rule may make of it is to stop an observation from firing.

A single call may carry both sides at once. That is recorded and never
escalates: escalation is judged across calls by
tooling_guard.trace.escalation.evaluate.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, replace
from typing import Any, Final

from ..policy import paths
from ..policy.allowlists import (
    PRIVATE_KEY_NAMES,
    PRIVATE_KEY_SUFFIXES,
    SENSITIVE_DIRS,
    SENSITIVE_MARKERS,
    SENSITIVE_NAMES,
    classify_sensitive_target,
    private_key_reference,
)
from ..policy.tools import T_STRONG_TOOLS, T_WEAK_TOOLS

TIER_STRONG: Final[str] = "T-strong"
TIER_WEAK: Final[str] = "T-weak"
TIER_UNKNOWN: Final[str] = "unknown"

ORIGIN_USER: Final[str] = "user"
ORIGIN_MODEL: Final[str] = "model"
ORIGIN_SYSTEM: Final[str] = "system"

LABEL_UNTRUSTED_SOURCE: Final[str] = "untrusted_source"
LABEL_SINK_READ: Final[str] = "sink_read"
LABEL_SINK_DELIVER: Final[str] = "sink_deliver"
LABEL_READ_IN_ROOTS: Final[str] = "read_in_project_roots"
LABELS: Final[frozenset[str]] = frozenset(
    {
        LABEL_UNTRUSTED_SOURCE,
        LABEL_SINK_READ,
        LABEL_SINK_DELIVER,
        LABEL_READ_IN_ROOTS,
    }
)

VERB_READ: Final[str] = "read"
VERB_WRITE: Final[str] = "write"
VERB_EDIT: Final[str] = "edit"
VERB_EXEC: Final[str] = "exec"
VERB_DELIVER: Final[str] = "deliver"
VERB_FETCH: Final[str] = "fetch"
VERB_QUERY: Final[str] = "query"
VERB_DELEGATE: Final[str] = "delegate"
VERB_CALL: Final[str] = "call"

_WEB_TOOLS: Final[tuple[str, ...]] = (
    "web_search_serpapi",
    "image_search_serpapi",
    "finance_search_serpapi",
    "scholar_search_serpapi",
    "web_search_tavily",
    "tavily_extract_web_page",
    "web_search_bocha",
    "web_search_brave",
    "web_search_firecrawl",
    "firecrawl_extract_web_page",
    "web_search_baidu",
    "web_search_exa",
    "exa_get_contents",
    "web_search_anysearch",
    "web_search_deepseek",
    "deepseek_fetch_web_page",
)
_BROWSER_TOOLS: Final[tuple[str, ...]] = (
    "astrbot_execute_browser",
    "astrbot_execute_browser_batch",
    "astrbot_run_browser_skill",
)
_UNTRUSTED_EXTRA: Final[tuple[str, ...]] = (
    "astrbot_download_file",
    "get_group_message_history",
    "astr_kb_search",
    "astrbot_file_read_tool",
)
_DELIVER_TOOLS: Final[tuple[str, ...]] = (
    "astrbot_execute_shell",
    "astrbot_execute_python",
    "astrbot_execute_ipython",
    "astrbot_shell_session",
    "astrbot_upload_file",
    "send_message_to_user",
    "astrbot_cua_screenshot",
    "astrbot_cua_mouse_click",
    "astrbot_cua_keyboard_type",
)

#: Tools whose produced content becomes context and may carry outside text.
UNTRUSTED_SOURCE_TOOLS: Final[frozenset[str]] = frozenset(
    _WEB_TOOLS + _BROWSER_TOOLS + _UNTRUSTED_EXTRA
)
#: Tools that send a query or an address outward (receiving side, read shape).
SINK_READ_TOOLS: Final[frozenset[str]] = frozenset(
    _WEB_TOOLS + _BROWSER_TOOLS + ("astrbot_download_file",)
)
#: Tools that let data leave the context (receiving side, deliver shape).
SINK_DELIVER_TOOLS: Final[frozenset[str]] = frozenset(_DELIVER_TOOLS + _BROWSER_TOOLS)
#: Tools that read a file or scan file contents for the caller.
FILE_READ_TOOLS: Final[frozenset[str]] = frozenset(
    {"astrbot_file_read_tool", "astrbot_grep_tool"}
)
#: Tools that write or edit a file.
WRITE_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "astrbot_file_write_tool",
        "astrbot_file_edit_tool",
        "astrbot_cua_screenshot",
    }
)
#: Tools that run a command or a script.
EXEC_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "astrbot_execute_shell",
        "astrbot_execute_python",
        "astrbot_execute_ipython",
        "astrbot_shell_session",
    }
)
#: Tools whose untrusted_source label depends on where the target lives.
ROOT_SCOPED_UNTRUSTED_TOOLS: Final[frozenset[str]] = frozenset(
    {"astrbot_file_read_tool"}
)
#: Tools whose text is one command line, so its first word can be read as the
#: program. A stateful shell session is deliberately absent: it carries state
#: from earlier commands, so its next line is not provably one read-only
#: command.
SHELL_TOOLS: Final[frozenset[str]] = frozenset({"astrbot_execute_shell"})

PATH_KEYS: Final[frozenset[str]] = frozenset(
    {
        "path",
        "paths",
        "file",
        "files",
        "file_path",
        "filepath",
        "filename",
        "dir",
        "directory",
        "cwd",
        "workdir",
        "working_directory",
        "target",
        "targets",
        "target_path",
        "src",
        "source_path",
        "dest",
        "destination_path",
        "input",
        "in_path",
        "out",
        "output",
        "out_path",
    }
)
TEXT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "command",
        "cmd",
        "cmdline",
        "command_line",
        "script",
        "code",
        "source",
        "shell",
        "stdin",
    }
)
CONTENT_KEYS: Final[frozenset[str]] = frozenset({"content", "text", "data", "body"})
PATTERN_KEYS: Final[frozenset[str]] = frozenset(
    {
        "glob",
        "globs",
        "pattern",
        "patterns",
        "name_pattern",
        "name_patterns",
        "filename_pattern",
        "include",
        "include_glob",
    }
)
_PRIVATE_KEY_TEXT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:-----)?begin[^\n]{0,40}private key|private[_ ]key"
)
_GLOB_WILDCARDS: Final[frozenset[str]] = frozenset("*?[]{}")
_GLOB_BRACES: Final[re.Pattern[str]] = re.compile(r"\{([^{}]*)\}")
_GLOB_SEPARATORS: Final[re.Pattern[str]] = re.compile(r"/{2,}")
_PATTERN_KEY_NAME_MIN_LENGTH: Final[int] = 3
_PRIVATE_KEY_NAME_ORDER: Final[tuple[str, ...]] = tuple(
    sorted(PRIVATE_KEY_NAMES, key=lambda name: (name != "id_rsa", name))
)
#: Credential file names a glob is matched against (review finding R9-04). A glob
#: is a file-name filter, so it reaches a key exactly when it matches that name;
#: stripping the wildcards instead ("id_?sa" -> "id_sa") names no file, which is
#: what let the bypass through. Every entry is a concrete name, so an extension
#: filter such as "*.py" or "*.json" reaches none of them.
_GLOB_KEY_CANDIDATES: Final[tuple[str, ...]] = (
    *_PRIVATE_KEY_NAME_ORDER,
    *("private" + suffix for suffix in PRIVATE_KEY_SUFFIXES),
    *(f"{directory}/id_rsa" for directory in sorted(SENSITIVE_DIRS)),
)
#: Credential config names a glob is matched against. They are classified as a
#: sensitive surface, not as a private key, so a hit suspends the call.
_GLOB_CONFIG_CANDIDATES: Final[tuple[str, ...]] = (
    *sorted(SENSITIVE_NAMES),
    ".env.local",
    *SENSITIVE_MARKERS,
)
#: Answer for a pattern naming no character of any file name ("*", "*.*", "**/*"):
#: no candidate set can prove it harmless, so it is reported as this
#: sensitive-config witness. The call then suspends instead of being denied,
#: because a grep without any glob reads exactly the same files and the tier
#: default allows it; denying the wildcard alone would be an asymmetry, while the
#: suspension keeps the call fail-closed for a human.
_GLOB_TOTAL_WILDCARD_WITNESS: Final[str] = ".env"
_GLOB_NAME_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[0-9A-Za-z_]")
DESTINATION_KEYS: Final[frozenset[str]] = frozenset(
    {
        "to",
        "recipient",
        "recipients",
        "user",
        "user_id",
        "session",
        "session_id",
        "chat",
        "chat_id",
        "group_id",
        "channel",
        "conversation_id",
        "peer",
        "email",
        "phone",
        "destination",
        "destinations",
        "url",
        "urls",
        "href",
        "link",
        "links",
        "address",
        "endpoint",
        "webhook",
        "target",
        "targets",
    }
)

_VERB_MARKERS: Final[tuple[tuple[str, str], ...]] = (
    ("send_message_to_user", VERB_DELIVER),
    ("_file_read", VERB_READ),
    ("_file_write", VERB_WRITE),
    ("_file_edit", VERB_EDIT),
    ("_grep", VERB_READ),
    ("_execution_history", VERB_READ),
    ("_execute_shell", VERB_EXEC),
    ("_execute_python", VERB_EXEC),
    ("_execute_ipython", VERB_EXEC),
    ("_shell_session", VERB_EXEC),
    ("_upload", VERB_DELIVER),
    ("_cua_", VERB_DELIVER),
    ("_browser", VERB_DELIVER),
    ("_download", VERB_FETCH),
    ("_web_search", VERB_FETCH),
    ("_search_", VERB_FETCH),
    ("_extract", VERB_FETCH),
    ("_fetch_", VERB_FETCH),
    ("_get_contents", VERB_FETCH),
    ("_kb_search", VERB_QUERY),
    ("_message_history", VERB_QUERY),
    ("_skill", VERB_QUERY),
    ("future_task", VERB_DELEGATE),
)

_REDIRECT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:\d?)>{1,2}\s*(?P<target>\"[^\"]+\"|'[^']+'|[^\s;&|<>()]+)"
)
_OUTFILE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:-outfile|--output|-output|set-content\s+-path|tee)\s+"
    r"(?P<target>\"[^\"]+\"|'[^']+'|[^\s;&|<>()]+)"
)
_URL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(?:https?|wss?)://([^/\s?#\"'<>]+)"
)
_TOKEN_SPLIT_RE: Final[re.Pattern[str]] = re.compile(r"[^\s;&|()<>\"']+")
_NAME_SPLIT_RE: Final[re.Pattern[str]] = re.compile(r"[\\/]+")
_QUOTES_RE: Final[re.Pattern[str]] = re.compile(r"^[\"']+|[\"']+$")
_MAX_DEPTH: Final[int] = 4
_QUOTED_SPAN_RE: Final[re.Pattern[str]] = re.compile(r"\"[^\"]*\"|'[^']*'")
_SEGMENT_SPLIT_RE: Final[re.Pattern[str]] = re.compile(r"[;&|\r\n]+")
_UNQUOTED_RISK_RE: Final[re.Pattern[str]] = re.compile(r"[>{}]|\$\(")

#: Program words that only read. A command line is read-only only when every
#: segment of it starts with one of these: a whitelist, so every word it does
#: not name keeps R8 firing. That is the safe direction, because a missing word
#: costs an unsuppressed observation, never a missed write.
READ_ONLY_COMMANDS: Final[frozenset[str]] = frozenset(
    {
        "get-childitem",
        "gci",
        "dir",
        "ls",
        "get-content",
        "gc",
        "cat",
        "type",
        "select-string",
        "sls",
        "get-item",
        "gi",
        "test-path",
        "resolve-path",
        "get-location",
        "pwd",
        "get-filehash",
        "measure-object",
        "get-itemproperty",
        "tree",
        "echo",
        "write-output",
        "write-host",
        "select-object",
        "where-object",
        "sort-object",
        "format-table",
        "format-list",
        "out-string",
        "compare-object",
        "group-object",
        "head",
        "tail",
        "wc",
        "nl",
        "od",
        "xxd",
        "hexdump",
        "strings",
        "file",
        "stat",
        "realpath",
        "readlink",
        "basename",
        "dirname",
        "du",
        "df",
        "diff",
        "cmp",
        "cut",
        "tr",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "find",
    }
)

#: Words and flags that write, delete or execute. One of them anywhere in the
#: command keeps R8 firing, so the list is deliberately broader than the
#: read-only vocabulary it guards.
WRITE_EXEC_WORDS: Final[frozenset[str]] = frozenset(
    {
        "remove-item",
        "ri",
        "rm",
        "del",
        "erase",
        "rd",
        "rmdir",
        "clear-content",
        "clc",
        "set-content",
        "sc",
        "add-content",
        "ac",
        "new-item",
        "ni",
        "mkdir",
        "md",
        "copy-item",
        "cpi",
        "cp",
        "copy",
        "xcopy",
        "robocopy",
        "move-item",
        "mi",
        "mv",
        "move",
        "rename-item",
        "rni",
        "ren",
        "out-file",
        "tee-object",
        "tee",
        "export-csv",
        "export-clixml",
        "set-item",
        "si",
        "set-itemproperty",
        "sp",
        "set-acl",
        "icacls",
        "takeown",
        "attrib",
        "new-psdrive",
        "remove-psdrive",
        "clear-recyclebin",
        "invoke-expression",
        "iex",
        "invoke-command",
        "icm",
        "invoke-item",
        "ii",
        "start-process",
        "saps",
        "start",
        "start-job",
        "sajb",
        "start-threadjob",
        "stop-process",
        "spps",
        "kill",
        "taskkill",
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "fish",
        "pwsh",
        "powershell",
        "cmd",
        "python",
        "python3",
        "py",
        "ipython",
        "node",
        "nodejs",
        "perl",
        "ruby",
        "php",
        "lua",
        "rscript",
        "java",
        "dotnet",
        "npm",
        "pnpm",
        "yarn",
        "pip",
        "pip3",
        "uv",
        "conda",
        "gem",
        "cargo",
        "make",
        "source",
        "eval",
        "exec",
        "sudo",
        "doas",
        "nohup",
        "xargs",
        "timeout",
        "watch",
        "curl",
        "wget",
        "iwr",
        "invoke-webrequest",
        "irm",
        "invoke-restmethod",
        "ssh",
        "scp",
        "sftp",
        "nc",
        "ncat",
        "reg",
        "schtasks",
        "wmic",
        "ln",
        "chmod",
        "chown",
        "chgrp",
        "touch",
        "truncate",
        "dd",
        "shred",
        "install",
        "add-type",
        "set-executionpolicy",
        "new-variable",
        "set-variable",
        "clear-variable",
        "-exec",
        "-execdir",
        "-ok",
        "-okdir",
        "-delete",
        "-fprint",
        "-fprint0",
        "-fprintf",
        "-fls",
        "--pre",
        "-outfile",
        "--output",
        "--output-file",
        "-destination",
    }
)


@dataclass(frozen=True, slots=True)
class CallFeatures:
    """Everything the rules and the audit row need about one call.

    Requirement: Triage Inputs.
    """

    tool_name: str
    tier: str = TIER_UNKNOWN
    origin: str = ORIGIN_MODEL
    verb: str = VERB_CALL
    targets: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()
    texts: tuple[str, ...] = ()
    labels: frozenset[str] = frozenset()
    tokens: tuple[str, ...] = ()
    write_targets: tuple[str, ...] = ()


def tier_of(tool_name: str) -> str:
    """Return the read tier of one tool name.

    Requirement: Read-Tier On Demand; Unknown Call Classification.

    Args:
        tool_name: The tool name as the model called it.

    Returns:
        str: T-weak, T-strong, or unknown. An unknown name is not upgraded
        here; the policy layer denies a tool it does not know.
    """
    if tool_name in T_WEAK_TOOLS:
        return TIER_WEAK
    if tool_name in T_STRONG_TOOLS:
        return TIER_STRONG
    return TIER_UNKNOWN


def verb_of(tool_name: str) -> str:
    """Return the coarse verb of one tool name (read, write, exec, ...)."""
    for marker, verb in _VERB_MARKERS:
        if marker in tool_name:
            return verb
    return VERB_CALL


def labels_of(tool_name: str) -> frozenset[str]:
    """Return the taint labels of one tool name.

    Requirement: Triage Inputs.

    Args:
        tool_name: The tool name as the model called it.

    Returns:
        frozenset: A subset of untrusted_source, sink_read, sink_deliver.
    """
    labels: set[str] = set()
    if tool_name in UNTRUSTED_SOURCE_TOOLS:
        labels.add(LABEL_UNTRUSTED_SOURCE)
    if tool_name in SINK_READ_TOOLS:
        labels.add(LABEL_SINK_READ)
    if tool_name in SINK_DELIVER_TOOLS:
        labels.add(LABEL_SINK_DELIVER)
    return frozenset(labels)


def basename(value: str) -> str:
    """Return the last path component of a target, quotes stripped."""
    text = _QUOTES_RE.sub("", value.strip())
    parts = [part for part in _NAME_SPLIT_RE.split(text) if part]
    return parts[-1] if parts else ""


def shell_write_targets(text: str) -> tuple[str, ...]:
    """Return the files a command text writes through redirection or -OutFile.

    Requirement: Triage Inputs; Rule Catalog R1, R5, R9.

    Args:
        text: A shell, powershell or python command text.

    Returns:
        tuple: The written targets in first-seen order, quotes stripped.
    """
    found: list[str] = []
    for match in _REDIRECT_RE.finditer(text):
        found.append(match.group("target"))
    for match in _OUTFILE_RE.finditer(text):
        found.append(match.group("target"))
    return _dedupe(_QUOTES_RE.sub("", value) for value in found)


def content_text(arguments: Mapping[str, Any]) -> str:
    """Return the inline content an arguments mapping carries, joined."""
    pairs = tuple(_walk(arguments))
    return "\n".join(_values(pairs, CONTENT_KEYS))


def classify_call(
    tool_name: str,
    arguments: Mapping[str, Any],
    *,
    schema: Any = None,
    origin: str = ORIGIN_MODEL,
) -> CallFeatures:
    """Classify one call into its features.

    Requirement: Triage Inputs.

    Args:
        tool_name: The tool name as the model called it.
        arguments: The call arguments; a non-mapping is treated as empty.
        schema: The tool argument schema, accepted for call-site symmetry. The
            features are derived from the arguments themselves, so the schema
            does not change the result.
        origin: Who produced the call: user, model, or system.

    Returns:
        CallFeatures: Tier, verb, targets, destinations, texts, labels, tokens
        and write targets of this call.
    """
    tool = str(tool_name or "")
    mapping = arguments if isinstance(arguments, Mapping) else {}
    pairs = tuple(_walk(mapping))
    path_values = _values(pairs, PATH_KEYS)
    text_values = _values(pairs, TEXT_KEYS)
    texts = _dedupe(text_values)
    targets = _dedupe(
        _target_values(path_values, texts)
        + list(_sensitive_pattern_targets(pairs, tool))
    )
    destinations = _dedupe(_destination_values(pairs, path_values))
    return CallFeatures(
        tool_name=tool,
        tier=tier_of(tool),
        origin=origin,
        verb=verb_of(tool),
        targets=targets,
        destinations=destinations,
        texts=texts,
        labels=labels_of(tool),
        tokens=_tokens(texts),
        write_targets=_write_targets(tool, path_values, texts),
    )


def narrow_untrusted_source(
    features: CallFeatures, *, inside_project_roots: bool
) -> CallFeatures:
    """Drop the untrusted_source label of a read that stays in the project roots.

    Requirement: Triage Inputs (untrusted_source marks the producing side).

    A file read inside the project roots returns content the owner already
    wrote; outside it, the file may carry outside instructions.

    Args:
        features: The features of the call.
        inside_project_roots: Whether every target sits inside a project root.

    Returns:
        CallFeatures: The same features, with the label removed when the call
        is root-scoped and stayed inside the roots.
    """
    if not inside_project_roots:
        return features
    if features.tool_name not in ROOT_SCOPED_UNTRUSTED_TOOLS:
        return features
    if LABEL_UNTRUSTED_SOURCE not in features.labels:
        return features
    return replace(features, labels=features.labels - {LABEL_UNTRUSTED_SOURCE})


def is_exec_tool(tool_name: str) -> bool:
    """Return whether a tool name runs a command or a script."""
    return tool_name in EXEC_TOOLS


def is_write_tool(tool_name: str) -> bool:
    """Return whether a tool name writes or edits a file."""
    return tool_name in WRITE_TOOLS


def is_read_tool(tool_name: str) -> bool:
    """Return whether a tool name reads a file or scans file contents."""
    return tool_name in FILE_READ_TOOLS


def is_read_only_call(features: CallFeatures) -> bool:
    """Return whether the call reads and changes nothing.

    Requirement: Rule Catalog (R8).

    A file or grep tool reads by its shape. A shell tool reads only when the
    line it carries is provably one read-only command. Every other tool is not
    read-only here, so R8 keeps firing for it.

    Args:
        features: The features of the call.

    Returns:
        bool: True when the call is read-only at command level.
    """
    if is_read_tool(features.tool_name):
        return True
    if features.tool_name not in SHELL_TOOLS:
        return False
    return is_read_only_command(features.texts)


def read_scope_paths(features: CallFeatures) -> tuple[str, ...]:
    """Return the absolute literals whose location decides the scope fact.

    Requirement: Rule Catalog (R8).

    A file or grep tool names its targets in path arguments, so only the
    absolute values of those targets count. A shell command names them in its
    text, so the same extractor R8 uses decides. A relative path is excluded on
    purpose: it neither proves inside nor outside, and its absence must not be
    read as either.

    Args:
        features: The features of the call.

    Returns:
        tuple: The absolute literals, in first-seen order and deduped.
    """
    found: list[str] = []
    if is_read_tool(features.tool_name):
        for target in features.targets:
            found.extend(paths.extract_absolute_paths(target))
        return _dedupe(found)
    for text in features.texts:
        found.extend(paths.extract_absolute_paths(text))
    return _dedupe(found)


def mark_read_in_project_roots(
    features: CallFeatures, *, inside_project_roots: bool
) -> CallFeatures:
    """Add the read_in_project_roots label when the scope fact holds.

    Requirement: Rule Catalog (R8).

    The caller decides whether every absolute literal of a read-only call
    resolves inside a project root; this function only records that answer. It
    never removes a label and never fires a rule: the label lets R8 tell a read
    inside the roots from a write, a delete or an execute, which keep firing.

    Args:
        features: The features of the call.
        inside_project_roots: Whether every literal resolved inside a root.

    Returns:
        CallFeatures: The same features, with the label added when the call is
        read-only and the scope fact holds.
    """
    if not inside_project_roots:
        return features
    if not is_read_only_call(features):
        return features
    if LABEL_READ_IN_ROOTS in features.labels:
        return features
    return replace(features, labels=features.labels | {LABEL_READ_IN_ROOTS})


def is_read_only_command(texts: tuple[str, ...]) -> bool:
    """Return whether every text is one provably read-only command line.

    Requirement: Rule Catalog (R8).

    A line qualifies when each of its segments starts with a word of
    READ_ONLY_COMMANDS, no segment carries a word or flag of WRITE_EXEC_WORDS,
    and it has no redirect, script block or subexpression outside a quoted
    string. Everything this cannot prove counts as not read-only: a false
    positive would be an R8 that stops firing, so every doubt keeps it loud.

    Args:
        texts: The command texts of one call.

    Returns:
        bool: True when at least one text is present and all of them qualify.
    """
    seen = False
    for text in texts:
        if not text.strip():
            continue
        seen = True
        if not _read_only_line(text):
            return False
    return seen


def _walk(value: Any, *, depth: int = 0) -> Iterator[tuple[str, str]]:
    """Yield (lowercase key, string value) pairs of an arguments structure.

    A list of strings is yielded once per element under the key that holds it,
    because a tool that takes paths or patterns takes a list of them.
    """
    if depth > _MAX_DEPTH:
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key).strip().lower()
            if isinstance(item, str):
                yield name, item
            elif isinstance(item, (list, tuple)):
                for element in item:
                    if isinstance(element, str):
                        yield name, element
                    else:
                        yield from _walk(element, depth=depth + 1)
            else:
                yield from _walk(item, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk(item, depth=depth + 1)


def _values(pairs: tuple[tuple[str, str], ...], keys: frozenset[str]) -> list[str]:
    """Return the non-empty values whose key belongs to keys."""
    return [value for key, value in pairs if key in keys and value.strip()]


def _target_values(path_values: list[str], texts: tuple[str, ...]) -> list[str]:
    """Return the path targets of a call, from path keys and command literals."""
    found = [value.strip() for value in path_values]
    for text in texts:
        found.extend(paths.extract_absolute_paths(text))
    for text in texts:
        found.extend(shell_write_targets(text))
    return [value for value in found if value]


def _sensitive_pattern_targets(
    pairs: tuple[tuple[str, str], ...], tool_name: str
) -> tuple[str, ...]:
    """Return read-tool glob or name patterns that aim at a credential surface.

    Requirement: Triage Inputs.

    A search tool names its target surface twice: in the path argument and in
    the pattern. A grep over the home directory with the pattern id_rsa, or a
    glob of *.pem, reaches the keys even though every path argument stays
    harmless, so those patterns join the path targets of the call. Only values
    that point at a private key, a PEM header or a credential directory are
    added, so an ordinary search pattern is left alone.
    """
    if not is_read_tool(tool_name):
        return ()
    found: list[str] = []
    for key, value in pairs:
        if key not in PATTERN_KEYS:
            continue
        stripped = value.strip()
        if not stripped:
            continue
        reached = _glob_credential(stripped)
        if reached:
            found.append(reached)
            continue
        reached = _pattern_credential(stripped)
        if reached:
            found.append(reached)
            continue
        if _PRIVATE_KEY_TEXT_RE.search(stripped) or private_key_reference(stripped):
            found.append(stripped)
    return tuple(found)


def _glob_alternatives(pattern: str) -> tuple[str, ...]:
    """Expand every brace group of one glob into one pattern per alternative."""
    match = _GLOB_BRACES.search(pattern)
    if match is None:
        return (pattern,)
    head, tail = pattern[: match.start()], pattern[match.end() :]
    expanded: list[str] = []
    for option in match.group(1).split(","):
        expanded.extend(_glob_alternatives(head + option + tail))
    return tuple(expanded)


def _glob_regex(pattern: str) -> re.Pattern[str] | None:
    """Compile one glob into the expression that matches a whole path.

    The host hands its glob to ripgrep (-g), so the semantics are globset's
    rather than fnmatch's: a star or a question mark never crosses a separator, a
    doubled star does and a doubled star segment also matches no directory at all,
    a bracket group is a character class with an exclamation mark as its negation,
    and a back slash is a separator, which leaves the glob no escape character.

    Args:
        pattern: One brace-free glob, with separators already normalized to "/".

    Returns:
        The compiled expression, or None when the pattern is not a valid glob.
    """
    body: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                index += 2
                if index < len(pattern) and pattern[index] == "/":
                    index += 1
                    body.append(r"(?:[^/]+/)*")
                else:
                    body.append(r".*")
                continue
            index += 1
            body.append(r"[^/]*")
            continue
        if char == "?":
            index += 1
            body.append(r"[^/]")
            continue
        if char == "[":
            close = pattern.find("]", index + 2)
            if close > 0:
                content = pattern[index + 1 : close]
                if content.startswith("!"):
                    content = "^" + content[1:]
                body.append("[" + content + "]")
                index = close + 1
                continue
            body.append(r"\[")
            index += 1
            continue
        body.append(re.escape(char))
        index += 1
    try:
        return re.compile("".join(body))
    except re.error:
        return None


def _glob_credential(pattern: str) -> str:
    """Return the credential file name one glob matches.

    Requirement: Triage Inputs.

    A grep glob filters file names, so whether it reaches a key is decided by
    matching it against the catalogued credential names, not by reading the text
    left once the wildcards are gone: "id_?sa", "id_*sa" and "*_rsa" name no file
    themselves yet all match id_rsa. A pattern without a separator is matched
    against the base name, which is how the host applies it (at any depth); a
    pattern with one is matched against the whole relative name.

    Args:
        pattern: The glob or name pattern of one call argument.

    Returns:
        The matched candidate name, or an empty string when no credential file
        name is reachable.
    """
    text = pattern.strip().strip("\"'").replace("\\", "/")
    if not text:
        return ""
    if not _GLOB_NAME_CHAR_RE.search(text):
        return _GLOB_TOTAL_WILDCARD_WITNESS
    matchers: list[tuple[re.Pattern[str], bool]] = []
    for alternative in _glob_alternatives(text):
        compiled = _glob_regex(alternative.lstrip("/"))
        if compiled is not None:
            matchers.append((compiled, "/" in alternative))
    for candidate in (*_GLOB_KEY_CANDIDATES, *_GLOB_CONFIG_CANDIDATES):
        name = candidate.rsplit("/", 1)[-1]
        for compiled, anchored in matchers:
            if compiled.fullmatch(candidate if anchored else name):
                return candidate
    return ""


def _pattern_credential(pattern: str) -> str:
    """Return the credential file one glob or name pattern reaches.

    Requirement: Triage Inputs.

    This is the second detector: the glob matcher in _glob_credential decides the
    file names a pattern matches, and this residue pass covers the entry shapes
    no plain file name can witness, such as a home reference
    ("%USERPROFILE%/.ssh/id_*") or a directory the wildcard names
    ("secrets/**", "credentials*"). A pattern is judged with its wildcards
    removed and its brace alternatives split apart, because id_*, .env* and
    {id_rsa,id_ed25519} reach the same files as id_rsa and .env while naming
    neither of them. The residue is classified like a path target; when it only
    names the stem of a catalogued key (id_), the key name it reaches (id_rsa) is
    returned, because that is the shape the policy layer classifies. A pattern
    that resolves to nothing sensitive returns an empty string, so an ordinary
    search pattern is left alone.
    """
    expanded = _GLOB_BRACES.sub(
        lambda match: "," + match.group(1) + ",", pattern.strip().strip("\"'")
    )
    literal = "".join(
        char for char in expanded.replace("\\", "/") if char not in _GLOB_WILDCARDS
    )
    for piece in _GLOB_SEPARATORS.sub("/", literal).split(","):
        candidate = piece.strip()
        if not candidate:
            continue
        verdict = classify_sensitive_target(candidate)
        if verdict.private_key or verdict.suspend:
            return candidate
        reached = _pattern_key_name(candidate)
        if reached:
            return reached
    return ""


def _pattern_key_name(literal: str) -> str:
    """Return the catalogued private key name a wildcard-free pattern reaches."""
    name = literal.rsplit("/", 1)[-1].strip()
    if len(name) < _PATTERN_KEY_NAME_MIN_LENGTH:
        return ""
    for candidate in _PRIVATE_KEY_NAME_ORDER:
        if candidate.startswith(name) or name.startswith(candidate + "_"):
            return candidate
    return ""


def _destination_values(
    pairs: tuple[tuple[str, str], ...], path_values: list[str]
) -> list[str]:
    """Return the destinations of a call: URL hosts plus named recipients."""
    path_set = {value.strip() for value in path_values}
    found: list[str] = []
    for key, value in pairs:
        stripped = value.strip()
        if not stripped:
            continue
        hosts = _url_hosts(stripped)
        found.extend(hosts)
        if hosts or stripped in path_set or _looks_like_path(stripped):
            continue
        if key in DESTINATION_KEYS:
            found.append(stripped)
    return [value for value in found if value]


def _url_hosts(text: str) -> list[str]:
    """Return the lower-case URL hosts mentioned in a text."""
    hosts: list[str] = []
    for match in _URL_RE.finditer(text):
        host = match.group(1)
        host = host.rsplit("@", 1)[-1]
        hosts.append(host.split(":", 1)[0].strip().lower())
    return [host for host in hosts if host]


def _looks_like_path(value: str) -> bool:
    """Return whether a value looks like a filesystem path, not a destination."""
    return bool(_NAME_SPLIT_RE.search(value)) or value.startswith("~")


def _tokens(texts: tuple[str, ...]) -> tuple[str, ...]:
    """Return the command fragments of a call, in first-seen order."""
    found: list[str] = []
    for text in texts:
        found.extend(_TOKEN_SPLIT_RE.findall(text))
    return _dedupe(found)


def _write_targets(
    tool_name: str, path_values: list[str], texts: tuple[str, ...]
) -> tuple[str, ...]:
    """Return the files this call writes, by tool shape or by redirection."""
    if tool_name in WRITE_TOOLS:
        return _dedupe(value.strip() for value in path_values)
    found: list[str] = []
    for text in texts:
        found.extend(shell_write_targets(text))
    return _dedupe(found)


def _dedupe(values: Any) -> tuple[str, ...]:
    """Return the values with case-folded duplicates removed, order kept."""
    seen: set[str] = set()
    kept: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        folded = text.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        kept.append(text)
    return tuple(kept)


def _read_only_line(text: str) -> bool:
    """Return whether one command line only reads."""
    if _UNQUOTED_RISK_RE.search(_QUOTED_SPAN_RE.sub(" ", text)):
        return False
    for segment in _SEGMENT_SPLIT_RE.split(text):
        tokens = [token for token in _TOKEN_SPLIT_RE.findall(segment) if token]
        if not tokens:
            continue
        if _command_word(tokens[0]) not in READ_ONLY_COMMANDS:
            return False
        for token in tokens:
            if token.lower() in WRITE_EXEC_WORDS:
                return False
            if _command_word(token) in WRITE_EXEC_WORDS:
                return False
    return True


def _command_word(token: str) -> str:
    """Return the program word a token names, or a value nothing matches.

    The word is the last path component, lowercased and without an executable
    suffix, so C:/Windows/System32/cmd.exe names cmd. A token that names no
    program word returns a value no vocabulary holds.
    """
    text = token.strip("\"'")
    text = text.replace("\\", "/").rsplit("/", 1)[-1]
    if text.lower().endswith(".exe"):
        text = text[:-4]
    return text.lower()
