"""Strict config validation. Requirement: Config Validation Fail-Closed.

Every rejection carries a stable ``ConfigWarning.code`` next to the human message,
so ``/guard status`` and the unit scripts can assert one rule without matching
Chinese prose. A code is part of the observable contract and is never renamed.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ..anonymize import (
    PATTERN_UNCOMPILABLE,
    validate_secret_pattern,
)
from .tools import KNOWN_TOOLS, T_STRONG_TOOLS

#: Accepted ``mode`` values (Gateway.set_mode enforces the same pair).
MODE_VALUES: Final[frozenset[str]] = frozenset({"observe", "enforce"})

#: Accepted ``llm_mode`` values.
LLM_MODE_VALUES: Final[frozenset[str]] = frozenset({"endpoint", "astrbot_provider"})

#: Default ``fast_judge_backend``: the native jev protocol. Both backends eat
#: the same structured state; they differ only in the wire shape and in how
#: the answer is read back (jev answers vs chat completion JSON).
#:
#: The four fast-judge defaults below are literals rather than imports of
#: jev.score: that module imports triage.decisions, which reaches
#: policy.layers -> policy.snapshot -> this module, so a module-scope import
#: here is a circular import. jev.score stays the single source of the banding
#: and of the legal backend set; validate_config imports it lazily and reads
#: its values, so only these dataclass defaults repeat the three numbers.
FAST_JUDGE_BACKEND_DEFAULT: Final[str] = "jev"

#: Mirrors jev.score.DEFAULT_FAST_ALLOW_SCORE.
FAST_ALLOW_SCORE_DEFAULT: Final[int] = 30

#: Mirrors jev.score.DEFAULT_FAST_BLOCK_SCORE.
FAST_BLOCK_SCORE_DEFAULT: Final[int] = 75

#: Mirrors jev.score.DEFAULT_FAST_MIN_CONFIDENCE: a judged confidence strictly
#: below it turns both outer bands -- the release and the denial -- into a wait
#: for an administrator. 0.6 is deliberately above a coin flip: a judge that is
#: not sure enough to back its own band should let a human settle it.
FAST_MIN_CONFIDENCE_DEFAULT: Final[float] = 0.6

#: Mirrors jev.client.DEFAULT_TIMEOUT_S: one fast-judge round trip, in seconds.
#: A local judge needs room to cold start (about 15 s for an Ollama-hosted model)
#: plus ~0.6 s per KB of state, so the old hard five second cap degraded every
#: judgement; the key lets the operator fit the endpoint instead.
DEFAULT_JEV_TIMEOUT_S: Final[int] = 10
"""Default budget of one fast-judge round trip, in seconds."""

MAX_JEV_TIMEOUT_S: Final[int] = 50
"""Ceiling of one fast-judge round trip, in seconds.

A local judge cold starts slowly -- an Ollama-hosted model needs ~15 s to load a
9B Q8_0 before it answers anything -- so a 30 s ceiling was a timeout generator
on the first call of every session. The ceiling stays under the 120 s tool-call
cap with room for the deep round and the approval reserve.
"""

DEFAULT_DEEP_ANALYSIS_TIMEOUT_S: Final[int] = 60
"""Default budget of one deep-review request, in seconds."""

MAX_DEEP_ANALYSIS_TIMEOUT_S: Final[int] = 60
"""Ceiling of one deep-review request, in seconds."""

DEFAULT_DECISION_BUDGET_S: Final[int] = 120
"""Default budget of one whole synchronous decision, in seconds.

Requirement: Layered Consensus. The three layers share one budget: the static
layer and the two model layers answer inside this window, and whatever is left
goes to the approval wait. It is a configuration key rather than a constant so
an operator can buy time for slow models without touching the code.
"""

MAX_DECISION_BUDGET_S: Final[int] = 120
"""Ceiling of one synchronous decision, in seconds (the tool-call cap)."""

#: Stable issue codes this validator emits.
ISSUE_CODES: Final[frozenset[str]] = frozenset(
    {
        "bad_mode",
        "blank_item",
        # Advisory-only: both reviewers switched off is reported, never fatal.
        "deep_reviewers_disabled",
        "endpoint_field_required",
        "enforce_without_admins",
        "exempt_overrides_strong",
        "field_not_list",
        "field_not_string",
        # Fatal: an unknown backend would make every judgement an abstention.
        "fast_judge_backend_unknown",
        # Fatal: a non-numeric or out-of-range confidence floor would either be
        # read as the default (hiding the mistake) or switch the floor off; the
        # gateway does not run on a floor nobody can compute.
        "fast_min_confidence_invalid",
        # Fatal: allow >= block leaves no middle band and inverts the two
        # extremes; the scoring module refuses to band such a pair at all.
        "fast_thresholds_inverted",
        "llm_mode_unknown",
        "not_bool",
        "not_int",
        "path_not_absolute",
        "path_overlap",
        "provider_id_required",
        "regex_uncompilable",
        "requester_overlap",
        "required_missing",
        "root_missing",
        "secret_patterns_empty",
        # Advisory-only: stripping removes tools from the request, and the tools
        # it removes then leave no audit row and no judgement.
        "strip_unmanaged_tools_enabled",
        # Advisory-only: the trust switch removes one suspension, never a denial.
        "trust_project_roots_enabled",
        "unknown_tool",
        "value_out_of_range",
    }
)

#: Shapes accepted as an absolute configured path: a drive with a separator, a
#: UNC or device prefix, or a POSIX root. Review finding R9-07: an entry like
#: "tg_secret", "~/x" or "%USERPROFILE%\x" carries a base the validator would
#: have to guess, and a guess cannot be compared with the absolute targets the
#: host tool actually opens, so the deny root silently never matched.
_ABSOLUTE_ENTRY_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:[A-Za-z]:[\\/]|[\\/]{2}|/)"
)

#: Inclusive bounds for the budget and shingle/taint settings. Keys absent here
#: only require ``>= 1``. An out-of-range value disables the gateway; it is never
#: silently clamped, because a clamped budget would hide the operator's mistake.
INT_BOUNDS: Final[dict[str, tuple[int, int | None]]] = {
    # Design caps a suspension wait at 110 s (design.md "动态挂起预算").
    "suspend_timeout_s": (1, 110),
    # One deep-review request. A longer budget outlives any tool-call horizon.
    "deep_analysis_timeout_s": (1, MAX_DEEP_ANALYSIS_TIMEOUT_S),
    "shingle_k": (1, 32),
    "shingle_min_chars": (1, 4096),
    "shingle_min_matches": (1, 32),
    "shingle_min_covered_chars": (1, 65536),
    # One day: the taint window is a per-session cache, not a retention policy.
    "taint_ttl_s": (1, 86_400),
    "shingle_capacity": (1, 1_000_000),
    # The fast judge bands are percentages; 0..100 is the whole scale.
    "fast_allow_score": (0, 100),
    "fast_block_score": (0, 100),
    # One fast-judge round trip. The upper bound is the same ceiling
    # jev/client.py clamps to; a local judge cold starts in ~15 s, so 30 s
    # generated timeouts on the first call of every session.
    "jev_timeout_s": (1, MAX_JEV_TIMEOUT_S),
    # One whole synchronous decision, shared by all three layers.
    "decision_budget_s": (1, MAX_DECISION_BUDGET_S),
}

#: Inclusive bounds for the probability settings, on the 0..1 scale the judge
#: answers confidence on. Out of range or non-numeric is fatal, exactly like the
#: integer bounds: a clamped floor would hide the operator's mistake.
FLOAT_BOUNDS: Final[dict[str, tuple[float, float]]] = {
    "fast_min_confidence": (0.0, 1.0),
}


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    """Validated immutable configuration used by gateway components."""

    mode: str
    #: Effective suspension cap: wait = min(suspend_timeout_s, 110, deadline - now).
    #: Below 30 is equivalent to no wait -- no ticket, immediate timeout_deny --
    #: because a suspension needs 30 s of reserve to be answerable.
    suspend_timeout_s: int
    #: Sessions that may not wait for an approval: an entry must equal the whole
    #: session key -- the value stored as audit_events.session_key -- exactly, so
    #: a matching call is denied instead of suspended.  Group sessions never wait
    #: even when unlisted, and this setting only ever removes the wait, never the
    #: denial.
    suspend_disabled_sessions: tuple[str, ...]
    user_whitelist: tuple[str, ...]
    user_blacklist: tuple[str, ...]
    path_whitelist: tuple[str, ...]
    path_deny: tuple[str, ...]
    project_roots: tuple[Path, ...]
    destination_allowlist: tuple[str, ...]
    exempt_tools: tuple[str, ...]
    jev_base_url: str
    jev_model: str
    jev_api_key: str
    llm_mode: str
    llm_base_url: str
    llm_model: str
    llm_api_key: str
    llm_provider_id: str
    admins: tuple[str, ...]
    inline_reply: bool
    secret_patterns: tuple[str, ...]
    deep_analysis_timeout_s: int
    shingle_k: int
    shingle_min_chars: int
    shingle_min_matches: int
    shingle_min_covered_chars: int
    taint_ttl_s: int
    shingle_capacity: int
    audit_retention_days: int
    trajectory_retention_per_user: int
    strict_path_whitelist: bool
    #: Whether the built-in base checker takes part. Disabling it is allowed but
    #: never silent: the caller that flips the switch (tooling_guard/main.py)
    #: writes one degraded audit row and sends one rate-limited administrator
    #: alert, and /guard status keeps listing the reviewer as disabled. The other
    #: reviewers still run, and every call is still folded by core.consensus --
    #: one model allow releases, a model deny or a full abstention opens a ticket
    #: -- so a missing base checker never widens the gateway.
    base_check_enabled: bool = True
    #: Whether in-root targets are labelled as trusted (AllowHints.
    #: in_project_root) instead of reading as suspicious. Since 0.6.0 this is a
    #: label only: the static layer no longer releases an in-root call and no
    #: reviewer skips the models because of it, so turning it on buys no fewer
    #: model calls and turning it off cannot block anything by itself.
    trust_project_roots: bool = False
    #: Whether the five unmanaged kinds -- MCP tools, HandoffTool, background
    #: task tools, future_task and shapes that cannot be recognised -- are
    #: removed from the request toolset instead of being passed through.  Off by
    #: default: every unmanaged entry keeps working as the host built it and
    #: install.py discloses it with one WARN.  Turning it on costs what the switch
    #: says -- a stripped tool is gone for that request, leaves no audit row and
    #: gets no judgement at all.
    strip_unmanaged_tools: bool = False
    #: Dashboard usernames allowed to approve or deny on the web card.  Empty
    #: means nobody may approve there -- never "everybody", and never a widening
    #: of the command plane's own admins.
    web_admin_usernames: tuple[str, ...] = ()
    #: Pairs of (dashboard username, audit subject_key) that bind a dashboard
    #: login to the platform_id:sender_id form used by admins.  A username that
    #: is absent here can read nothing, so the default fails closed.
    web_subject_map: tuple[tuple[str, str], ...] = ()
    #: Whether the JEV fast reviewer takes part.  A reviewer that is switched
    #: off never asks for the credentials it would not use, so a fresh install
    #: validates with the shipped defaults (off, no endpoint key required).
    jev_enabled: bool = False
    #: Whether the LLM deep reviewer takes part.  Under
    #: llm_mode=astrbot_provider an empty llm_provider_id means "use the model
    #: the host currently has as its default", which needs no endpoint.
    llm_enabled: bool = True
    #: How the fast judge speaks to jev_base_url. jev posts the structured
    #: state to the endpoint and reads the score/noul answer; llm posts an
    #: OpenAI-compatible chat completion to the same endpoint and reads the
    #: same two fields out of the JSON message content. The default sits here
    #: rather than beside the other jev_* fields so an old config file, which
    #: carries no such key, keeps the shipped protocol.
    fast_judge_backend: str = FAST_JUDGE_BACKEND_DEFAULT
    #: Score bands in percent (see jev/score.py for the one banding decision).
    #: Below allow releases as allow_fast; at or above block denies as
    #: deny_judge; the middle band releases only when the judge also said noul
    #: is true, and suspends when it said false. allow >= block is fatal: the
    #: two bands would overlap or invert, and the scoring module then refuses to
    #: band the answer at all, so every judgement would abstain.
    fast_allow_score: int = FAST_ALLOW_SCORE_DEFAULT
    fast_block_score: int = FAST_BLOCK_SCORE_DEFAULT
    #: The confidence floor, on the same 0..1 scale as the judge's own
    #: confidence answer. A judged confidence strictly below it turns the two
    #: outer bands into a suspension -- a release waits for approval, a denial
    #: waits for an administrator -- while the middle band is untouched (noul
    #: already decides it). A missing or unusable confidence never trips it, and
    #: a value outside 0..1 is fatal rather than clamped.
    fast_min_confidence: float = FAST_MIN_CONFIDENCE_DEFAULT
    #: One fast-judge round trip, in seconds. Local endpoints cold start slower
    #: than the old five second constant, so this is a key rather than a constant.
    jev_timeout_s: int = DEFAULT_JEV_TIMEOUT_S
    #: Budget of one whole synchronous decision, in seconds, shared by the
    #: static layer, the fast judge and the deep reviewer. What is left after
    #: the three layers is the approval reserve, so this number is the ceiling
    #: on how long a call may spend being judged before it is either answered
    #: or handed to an administrator.
    decision_budget_s: int = DEFAULT_DECISION_BUDGET_S


@dataclass(frozen=True, slots=True)
class ConfigWarning:
    """An administrator-facing issue: offending key path, text and stable code.

    ``code`` is the only field added over the original two-field shape; it
    defaults to an empty string so every existing constructor call and the
    ``key``/``message`` consumers in ``tooling_guard/main.py`` and
    ``tooling_guard/ui/commands.py:254-257`` keep working unchanged.
    """

    key: str
    message: str
    code: str = ""

    def __str__(self) -> str:
        """Render a clear key-specific fail-closed warning."""
        return f"{self.key}: {self.message}"


@dataclass(frozen=True, slots=True)
class ConfigValidationResult:
    """Validated config or explicit fail-closed startup issues.

    Shape is unchanged: ``enabled``, ``config`` and ``warnings``; each warning now
    also carries a stable code. ``advisories`` is appended last with an empty
    default: it carries non-fatal advisories that never disable the gateway, so
    the existing invariant (enabled implies an empty ``warnings`` tuple) holds.
    """

    enabled: bool
    config: GatewayConfig | None
    warnings: tuple[ConfigWarning, ...]
    advisories: tuple[ConfigWarning, ...] = ()


#: Legacy two-argument emitter type, kept for callers that build warnings.
ConfigWarningCallback = Callable[[str, str], None]

#: Three-argument emitter used inside this module: key, message, stable code.
ConfigIssueCallback = Callable[[str, str, str], None]


def validate_config(raw: Mapping[str, object]) -> ConfigValidationResult:
    """Validate settings; malformed or unsafe values disable the gateway.

    Requirements: Config Validation Fail-Closed; Exempt List Guardrails.

    The validator is a pure function. It may stat a declared project root
    (``resolve(strict=True)`` / ``is_dir()``) but never creates a directory, touches
    the network, or writes configuration back.

    Args:
        raw: Raw plugin configuration mapping.

    Returns:
        A disabled result carrying every issue when any rule fails, else the
        validated immutable config.
    """
    warnings: list[ConfigWarning] = []
    advisories: list[ConfigWarning] = []

    def issue(key: str, message: str, code: str) -> None:
        warnings.append(ConfigWarning(key=key, message=message, code=code))

    def advisory(key: str, message: str, code: str) -> None:
        advisories.append(ConfigWarning(key=key, message=message, code=code))

    def text(key: str) -> str:
        value = raw.get(key, "")
        if not isinstance(value, str):
            issue(key, "必须是字符串。", "field_not_string")
            return ""
        return value.strip()

    def string_list(key: str) -> list[str]:
        value = raw.get(key, [])
        if not isinstance(value, (list, tuple)):
            issue(key, "必须是字符串列表。", "field_not_list")
            return []
        output: list[str] = []
        for index, item in enumerate(value):
            if not isinstance(item, str) or not item.strip():
                issue(f"{key}[{index}]", "必须是非空字符串。", "blank_item")
            else:
                output.append(item.strip())
        return output

    def web_list(key: str) -> list[str]:
        # Requirement: Visibility Scope. A web identity declaration is never
        # allowed to break the gateway, so a malformed value is advisory and the
        # whole key reads as empty: no guessed administrator, no guessed subject.
        value = raw.get(key, [])
        if not isinstance(value, (list, tuple)):
            advisory(
                key,
                "必须是字符串列表；该键按空处理，Web 面不放宽任何可见范围。",
                "web_not_list",
            )
            return []
        items: list[str] = []
        for index, item in enumerate(value):
            if not isinstance(item, str) or not item.strip():
                advisory(
                    f"{key}[{index}]",
                    "必须是非空字符串；该键按空处理，Web 面不放宽任何可见范围。",
                    "web_bad_item",
                )
                return []
            items.append(item.strip())
        return items

    def web_subject_pairs(key: str) -> list[tuple[str, str]]:
        # Requirement: Visibility Scope. Element shape is
        # <dashboard_username>=<platform_id>:<user_id>; anything else voids the
        # whole key instead of silently binding a wrong subject.
        entries = web_list(key)
        if not entries:
            return []
        pairs: list[tuple[str, str]] = []
        for entry in entries:
            name, separator, subject = entry.partition("=")
            platform, colon, user_id = subject.partition(":")
            if not (
                separator
                and colon
                and name.strip()
                and platform.strip()
                and user_id.strip()
            ):
                advisory(
                    key,
                    "元素必须是 <dashboard_username>=<platform_id>:<user_id>；"
                    "该键按空处理，不猜测默认主体。",
                    "web_bad_subject_entry",
                )
                return []
            pairs.append((name.strip(), f"{platform.strip()}:{user_id.strip()}"))
        return pairs

    def required(key: str) -> str:
        value = text(key)
        if not value:
            issue(key, "缺少必需配置；网关不会启用。", "required_missing")
        return value

    def boolean(key: str, *, default: bool = False) -> bool:
        value = raw.get(key, default)
        if not isinstance(value, bool):
            issue(key, "必须是布尔值。", "not_bool")
            return False
        return value

    mode = text("mode") or "observe"
    if mode not in MODE_VALUES:
        issue("mode", "仅支持 observe 或 enforce。", "bad_mode")
    suspend_timeout_s = _bounded_int(raw, "suspend_timeout_s", 110, issue)
    suspend_disabled_sessions = string_list("suspend_disabled_sessions")
    user_whitelist = string_list("user_whitelist")
    user_blacklist = string_list("user_blacklist")
    path_whitelist = string_list("path_whitelist")
    path_deny = string_list("path_deny")

    # Review finding R9-07: a section-relative deny root used to be accepted and
    # then normalized with no base, so it could never equal an absolute target and
    # the deny silently did nothing. Refusing the entry keeps the gateway off
    # instead of running with a rule that never fires.
    for entry_key, entry_list in (
        ("path_whitelist", path_whitelist),
        ("path_deny", path_deny),
    ):
        for entry_index, entry in enumerate(entry_list):
            if _ABSOLUTE_ENTRY_RE.match(entry):
                continue
            issue(
                f"{entry_key}[{entry_index}]",
                f"路径必须是绝对路径（盘符绝对、UNC 或 POSIX 绝对）：{entry!r} 无法与任何"
                "绝对目标匹配，相对条目不再被接受；网关不会启用。",
                "path_not_absolute",
            )
    destination_allowlist = string_list("destination_allowlist")
    exempt_tools = string_list("exempt_tools")
    admins = string_list("admins")
    secret_patterns = string_list("secret_patterns")
    project_root_values = string_list("project_roots")

    for name in sorted(set(exempt_tools) - KNOWN_TOOLS):
        issue("exempt_tools", f"未知工具名 {name!r}。", "unknown_tool")
    for name in sorted(set(exempt_tools) & T_STRONG_TOOLS):
        issue(
            "exempt_tools",
            f"T-strong 工具 {name!r} 不得豁免。",
            "exempt_overrides_strong",
        )

    # Review finding S2: an overlap is a configuration smell, never a reason to
    # shut the gateway down — adding one whitelist entry used to refuse every
    # managed call. Blacklist wins on the overlap (specs/policy/spec.md), so the
    # operator sees an advisory and the deny side stays in force.
    for path in sorted(set(path_whitelist) & set(path_deny)):
        advisory(
            "path_whitelist",
            f"与 path_deny 中的路径 {path!r} 重叠；黑名单优先，该路径仍按拒绝处理。",
            "path_overlap",
        )
        advisory(
            "path_deny",
            f"与 path_whitelist 中的路径 {path!r} 重叠；黑名单优先，该路径仍按拒绝处理。",
            "path_overlap",
        )
    for subject in sorted(set(user_whitelist) & set(user_blacklist)):
        advisory(
            "user_whitelist",
            f"与 user_blacklist 中的主体 {subject!r} 重叠；黑名单优先，该主体仍按拒绝处理。",
            "requester_overlap",
        )
        advisory(
            "user_blacklist",
            f"与 user_whitelist 中的主体 {subject!r} 重叠；黑名单优先，该主体仍按拒绝处理。",
            "requester_overlap",
        )

    resolved_roots: list[Path] = []
    if not project_root_values:
        # Advisory, never fatal: an empty list is the fresh-install default, and
        # a gateway that refuses to start on it leaves every managed tool denied
        # with nothing recorded. It stays enabled and judges in mode=observe.
        advisory(
            "project_roots",
            "未配置项目根目录：网关仍会启用并以 mode=observe 运行，但全部目标都不在"
            "任何项目根内——trust_project_roots 因此永不生效，轨迹污点"
            "（outside_project_roots）也不覆盖任何路径。",
            "root_missing",
        )
    for index, root_value in enumerate(project_root_values):
        key = f"project_roots[{index}]"
        try:
            root = Path(root_value).expanduser().resolve(strict=True)
            if not root.is_dir():
                raise OSError("不是目录")
        except (OSError, RuntimeError, ValueError):
            issue(
                key,
                f"项目根目录 {root_value!r} 不存在或不是目录。",
                "root_missing",
            )
        else:
            resolved_roots.append(root)

    for index, pattern in enumerate(secret_patterns):
        # anonymize.py owns the redaction rule set and silently drops a pattern it
        # cannot use (MAX_SECRET_PATTERN_LENGTH, nested quantifiers), so the ones it
        # would drop are reported here verbatim as advisories instead of vanishing
        # from the operator's view. The tuple keeps the operator's own wording: the
        # expression enters no effective set because every compiling consumer
        # (snapshot.py, anonymize.py, taint.py) runs this same check and refuses it.
        # An uncompilable expression stays fatal below: a pattern that never
        # reaches the scanner leaves secrets unredacted.
        shape = validate_secret_pattern(pattern)
        if shape is not None and shape != PATTERN_UNCOMPILABLE:
            advisory(
                f"secret_patterns[{index}]",
                f"脱敏扫描会忽略该正则（{shape}）；该表达式不进入生效集合，"
                "请缩短或改写，网关仍会启用。",
                shape,
            )
            continue
        try:
            re.compile(pattern)
        except re.error as exc:
            issue(
                f"secret_patterns[{index}]",
                f"正则无法编译：{exc}；网关不会启用。",
                "regex_uncompilable",
            )
    if not secret_patterns:
        issue(
            "secret_patterns",
            "不得清空；至少需要一个秘密检测正则。",
            "secret_patterns_empty",
        )

    # Two independent reviewer switches.  A switched-off reviewer is never
    # asked for the credentials it would not use: the shipped defaults leave
    # JEV off with no endpoint, so a fresh install validates instead of
    # refusing to start over three keys nothing would read.
    jev_enabled = boolean("jev_enabled")
    llm_enabled = boolean("llm_enabled", default=True)
    if jev_enabled:
        jev_base_url = required("jev_base_url")
        jev_model = required("jev_model")
        jev_api_key = required("jev_api_key")
    else:
        # Read without the requirement so a wrong type is still reported and
        # the operator keeps whatever was typed for later inspection.
        jev_base_url = text("jev_base_url")
        jev_model = text("jev_model")
        jev_api_key = text("jev_api_key")
    llm_mode = text("llm_mode") or "astrbot_provider"
    if llm_mode not in LLM_MODE_VALUES:
        issue("llm_mode", "仅支持 endpoint 或 astrbot_provider。", "llm_mode_unknown")
    # No config file written before this key existed carries it, so an empty
    # value keeps the shipped jev protocol. An unknown value is fatal rather
    # than silently defaulted: a typo would otherwise point the fast judge at a
    # protocol it cannot speak, and every judgement would then look like a
    # healthy abstention.
    #
    # Imported inside the function: jev.score reaches triage.decisions ->
    # policy.layers -> policy.snapshot -> this module, so a module-scope import
    # is a circular import. By the time validate_config runs, this module is
    # fully initialised and the import is free.
    from ..jev.score import (
        DEFAULT_FAST_ALLOW_SCORE,
        DEFAULT_FAST_BLOCK_SCORE,
        DEFAULT_FAST_MIN_CONFIDENCE,
        FAST_JUDGE_BACKENDS,
    )

    fast_judge_backend = text("fast_judge_backend") or FAST_JUDGE_BACKEND_DEFAULT
    if fast_judge_backend not in FAST_JUDGE_BACKENDS:
        issue(
            "fast_judge_backend",
            "仅支持 jev 或 llm。",
            "fast_judge_backend_unknown",
        )
    # Bands are read strictly and never clamped (a clamped band would hide the
    # operator mistake), and an inverted pair is fatal on top of the range
    # check: the scoring module refuses to band an inverted pair, so every
    # judgement would abstain -- safe, but at runtime indistinguishable from a
    # dead endpoint, which is exactly what a validation error prevents.
    fast_allow_score = _bounded_int(
        raw, "fast_allow_score", DEFAULT_FAST_ALLOW_SCORE, issue
    )
    fast_block_score = _bounded_int(
        raw, "fast_block_score", DEFAULT_FAST_BLOCK_SCORE, issue
    )
    if fast_allow_score >= fast_block_score:
        issue(
            "fast_block_score",
            f"必须大于 fast_allow_score（当前 allow={fast_allow_score}、"
            f"block={fast_block_score}）；两档倒置或重叠时快审无法分档，网关不会启用。",
            "fast_thresholds_inverted",
        )
    # The confidence floor is a probability, so it is read strictly too and it
    # gets one code for both failure shapes ("not a number" and "out of range"
    # differ only in the message). Fatal on purpose: a floor read as the default
    # would hide the mistake, and a floor silently clamped would suspend
    # nothing -- two ways of quietly losing the safety feature the operator
    # asked for.
    fast_min_confidence = _bounded_float(
        raw,
        "fast_min_confidence",
        DEFAULT_FAST_MIN_CONFIDENCE,
        issue,
        code="fast_min_confidence_invalid",
    )
    # One fast-judge round trip. Strict like the rest of the judge settings: a
    # clamped timeout would look configured while actually being another number,
    # and too small a timeout degrades every judgement, which is invisible at
    # config time but very visible in the audit trail.
    jev_timeout_s = _bounded_int(raw, "jev_timeout_s", DEFAULT_JEV_TIMEOUT_S, issue)
    # One whole synchronous decision. Strict like the budgets above: a clamped
    # value would look configured while being another number, and a decision
    # budget below the two model budgets can only ever produce abstentions.
    decision_budget_s = _bounded_int(
        raw, "decision_budget_s", DEFAULT_DECISION_BUDGET_S, issue
    )
    llm_base_url = text("llm_base_url")
    llm_model = text("llm_model")
    llm_api_key = text("llm_api_key")
    llm_provider_id = text("llm_provider_id")
    if llm_enabled and llm_mode == "endpoint":
        for key, value in (
            ("llm_base_url", llm_base_url),
            ("llm_model", llm_model),
            ("llm_api_key", llm_api_key),
        ):
            if not value:
                issue(
                    key,
                    "llm_mode=endpoint 时此项必填；网关不会启用。",
                    "endpoint_field_required",
                )
    # Under astrbot_provider an empty llm_provider_id is a valid choice: it
    # means "use the model the host currently serves as its default"
    # (astrbot/core/star/context.py llm_generate resolves it), so the old
    # provider_id_required issue is gone.  The code stays in ISSUE_CODES: a
    # code is part of the observable contract and is never renamed or reused.
    if not jev_enabled and not llm_enabled:
        # Advisory, never fatal: the base checker (path and credential
        # rules) is unaffected by these switches, so the pipeline still
        # intercepts and suspends -- it only stops doing the deep review.
        advisory(
            "jev_enabled",
            "JEV 与 LLM 两个深度审查器都被关闭：仅基础检查器（路径与凭据）生效，网关仍会拦截与挂起，但不再做深度复核；如需深度复核请至少启用其中一个。",
            "deep_reviewers_disabled",
        )
    # Same semantic as Gateway.set_mode (tooling_guard/main.py:964-968): enforce
    # without an administrator is refused, never silently downgraded.
    if mode == "enforce" and not admins:
        issue(
            "admins",
            "enforce 模式必须配置至少一个管理员；网关不会启用。",
            "enforce_without_admins",
        )

    inline_reply = boolean("inline_reply")
    deep_analysis_timeout_s = _bounded_int(raw, "deep_analysis_timeout_s", 60, issue)
    shingle_k = _bounded_int(raw, "shingle_k", 5, issue)
    shingle_min_chars = _bounded_int(raw, "shingle_min_chars", 24, issue)
    shingle_min_matches = _bounded_int(raw, "shingle_min_matches", 2, issue)
    shingle_min_covered_chars = _bounded_int(
        raw, "shingle_min_covered_chars", 48, issue
    )
    taint_ttl_s = _bounded_int(raw, "taint_ttl_s", 1800, issue)
    shingle_capacity = _bounded_int(raw, "shingle_capacity", 4096, issue)
    audit_retention_days = _bounded_int(raw, "audit_retention_days", 7, issue)
    trajectory_retention_per_user = _bounded_int(
        raw, "trajectory_retention_per_user", 50, issue
    )
    strict_path_whitelist = boolean("strict_path_whitelist")
    base_check_enabled = boolean("base_check_enabled", default=True)
    strip_unmanaged_tools = boolean("strip_unmanaged_tools")
    if strip_unmanaged_tools:
        # Advisory, never fatal: it only deletes tools the gateway cannot manage.
        advisory(
            "strip_unmanaged_tools",
            "strip_unmanaged_tools 已启用：MCP 工具、交接工具、后台任务工具、"
            "future_task 与形态未识别的工具都会从本次请求的工具集中删除，"
            "这些工具既不可用、也不再留下审计行与策略判定；"
            "关闭时它们原样放行并逐名披露。",
            "strip_unmanaged_tools_enabled",
        )
    web_admin_usernames = web_list("web_admin_usernames")
    web_subject_map = web_subject_pairs("web_subject_map")
    trust_project_roots = boolean("trust_project_roots")
    if trust_project_roots:
        # Advisory, never fatal: the switch only drops the tier_default layer,
        # so every hard denial and the R6 suspension still decide first.
        advisory(
            "trust_project_roots",
            "trust_project_roots 已启用：全部目标位于 project_roots 内的调用不再因分级默认"
            "（tier_default）而挂起，深度分析亦不执行；私钥/凭据/路径黑名单/敏感配置仍然拦截。",
            "trust_project_roots_enabled",
        )

    # An entry without a platform still names one administrator: ui/commands.py
    # _listed_admin matches it against the event sender_id on any platform, so
    # the narrowest identity it can grant is wider than the platform-qualified
    # form. Advisory only -- the configuration stays usable.
    for entry in admins:
        if ":" not in entry:
            advisory(
                "admins",
                f"裸 admin id {entry!r} 会在任意平台上匹配同一 sender_id；"
                "建议写成 platform_id:sender_id。",
                "bare_admin_entry",
            )

    if warnings:
        return ConfigValidationResult(
            enabled=False, config=None, warnings=tuple(warnings)
        )
    config = GatewayConfig(
        mode=mode,
        suspend_timeout_s=suspend_timeout_s,
        suspend_disabled_sessions=tuple(suspend_disabled_sessions),
        user_whitelist=tuple(user_whitelist),
        user_blacklist=tuple(user_blacklist),
        path_whitelist=tuple(path_whitelist),
        path_deny=tuple(path_deny),
        project_roots=tuple(resolved_roots),
        destination_allowlist=tuple(destination_allowlist),
        exempt_tools=tuple(exempt_tools),
        jev_base_url=jev_base_url,
        jev_model=jev_model,
        jev_api_key=jev_api_key,
        fast_judge_backend=fast_judge_backend,
        fast_allow_score=fast_allow_score,
        fast_block_score=fast_block_score,
        fast_min_confidence=fast_min_confidence,
        jev_timeout_s=jev_timeout_s,
        decision_budget_s=decision_budget_s,
        llm_mode=llm_mode,
        llm_base_url=llm_base_url,
        llm_model=llm_model,
        llm_api_key=llm_api_key,
        llm_provider_id=llm_provider_id,
        admins=tuple(admins),
        inline_reply=inline_reply,
        secret_patterns=tuple(secret_patterns),
        deep_analysis_timeout_s=deep_analysis_timeout_s,
        shingle_k=shingle_k,
        shingle_min_chars=shingle_min_chars,
        shingle_min_matches=shingle_min_matches,
        shingle_min_covered_chars=shingle_min_covered_chars,
        taint_ttl_s=taint_ttl_s,
        shingle_capacity=shingle_capacity,
        audit_retention_days=audit_retention_days,
        trajectory_retention_per_user=trajectory_retention_per_user,
        strict_path_whitelist=strict_path_whitelist,
        base_check_enabled=base_check_enabled,
        trust_project_roots=trust_project_roots,
        strip_unmanaged_tools=strip_unmanaged_tools,
        web_admin_usernames=tuple(web_admin_usernames),
        web_subject_map=tuple(web_subject_map),
        jev_enabled=jev_enabled,
        llm_enabled=llm_enabled,
    )
    return ConfigValidationResult(
        enabled=True, config=config, warnings=(), advisories=tuple(advisories)
    )


def _bounded_int(
    raw: Mapping[str, object],
    key: str,
    default: int,
    issue: ConfigIssueCallback,
) -> int:
    """Read one integer setting strictly inside its declared bounds.

    Args:
        raw: Raw configuration mapping.
        key: Setting name, also used as the issue key path.
        default: Value used when the setting is missing or rejected.
        issue: Emitter reporting key, message and stable code.

    Returns:
        The configured integer when it is an int inside ``INT_BOUNDS[key]``,
        otherwise ``default`` after one issue was reported.
    """
    minimum, maximum = INT_BOUNDS.get(key, (1, None))
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        issue(key, "必须是整数。", "not_int")
        return default
    span = f">= {minimum}" if maximum is None else f"{minimum}..{maximum}"
    if value < minimum or (maximum is not None and value > maximum):
        issue(
            key,
            f"必须在 {span} 范围内（当前 {value}）；网关不会启用。",
            "value_out_of_range",
        )
        return default
    return value


def _bounded_float(
    raw: Mapping[str, object],
    key: str,
    default: float,
    issue: ConfigIssueCallback,
    *,
    code: str,
) -> float:
    """Read one probability setting strictly inside its declared bounds.

    Requirement: Fast Judge Configuration Validation. A confidence floor is a
    probability, so it is read with the same discipline as the integer bounds:
    neither a non-number nor an out-of-range number is clamped, because a
    clamped floor hides the operator's mistake -- a floor written as 6.0 would
    silently become 1.0 and stop suspending anything.

    Args:
        raw: Raw configuration mapping.
        key: Setting name, also used as the issue key path.
        default: Value used when the setting is missing or rejected.
        issue: Emitter reporting key, message and stable code.
        code: The stable issue code to report. This setting has one code for
            both failure shapes ("not a number" and "out of range"), so the
            message carries the distinction.

    Returns:
        The configured number when it is an int or float inside
        ``FLOAT_BOUNDS[key]``, otherwise ``default`` after one issue.
    """
    minimum, maximum = FLOAT_BOUNDS.get(key, (0.0, 1.0))
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        issue(key, "必须是数字。", code)
        return default
    number = float(value)
    if not minimum <= number <= maximum:
        issue(
            key,
            f"必须在 {minimum}..{maximum} 范围内（当前 {value}）；网关不会启用。",
            code,
        )
        return default
    return number
