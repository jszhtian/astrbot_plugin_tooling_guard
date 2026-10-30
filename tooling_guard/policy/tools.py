"""Static AstrBot core tool classification from TOOL-MATRIX.md.

Requirement: Exempt List Guardrails; Danger Tiering.
"""

from typing import Final

T_STRONG_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "astrbot_execute_shell",
        "astrbot_execute_ipython",
        "astrbot_upload_file",
        "astrbot_download_file",
        "astrbot_file_write_tool",
        "astrbot_file_edit_tool",
        "astrbot_execute_python",
        "astrbot_shell_session",
        "astrbot_execute_browser",
        "astrbot_execute_browser_batch",
        "astrbot_run_browser_skill",
        "astrbot_annotate_execution",
        "astrbot_create_skill_payload",
        "astrbot_create_skill_candidate",
        "astrbot_evaluate_skill_candidate",
        "astrbot_promote_skill_candidate",
        "astrbot_rollback_skill_release",
        "astrbot_sync_skill_release",
        "astrbot_cua_screenshot",
        "astrbot_cua_mouse_click",
        "astrbot_cua_keyboard_type",
        "future_task",
        "send_message_to_user",
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
    }
)
T_WEAK_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "astrbot_file_read_tool",
        "astrbot_grep_tool",
        "astrbot_get_execution_history",
        "astrbot_get_skill_payload",
        "astrbot_list_skill_candidates",
        "astrbot_list_skill_releases",
        "astr_kb_search",
        "get_group_message_history",
    }
)
KNOWN_TOOLS: Final[frozenset[str]] = T_STRONG_TOOLS | T_WEAK_TOOLS
#: Tools whose name alone proves the call can run arbitrary commands or code.
#: The trust switch (config.trust_project_roots) never exempts these from deep
#: review: an in-root shell call can still reach anything the process can reach.
EXEC_TOOL_NAMES: Final[frozenset[str]] = frozenset(
    {
        "astrbot_execute_shell",
        "astrbot_execute_python",
        "astrbot_execute_ipython",
        "astrbot_shell_session",
    }
)
#: Name suffixes that mark the same capability for tools this catalogue has
#: never seen, such as a plugin or MCP tool that shells out. Matching is on the
#: lowercased name only; a miss costs one extra review, never a skipped one.
EXEC_NAME_SUFFIXES: Final[tuple[str, ...]] = (
    "_execute_shell",
    "_execute_python",
    "_execute_ipython",
    "_execute_bash",
    "_exec_shell",
    "_run_shell",
    "_shell_session",
)


def is_exec_tool(tool_name: str) -> bool:
    """Return whether the tool name proves an arbitrary command/code surface.

    The judgement reads the name and nothing else: it never inspects the
    arguments, so a tool that carries a command in a differently named
    parameter is still recognised by its name. Being wrong in the strict
    direction costs one review; being wrong in the lax direction would skip
    the only reviewer able to see what the command does.
    """
    name = tool_name.strip().lower() if isinstance(tool_name, str) else ""
    if not name:
        return False
    if name in EXEC_TOOL_NAMES:
        return True
    return name.endswith(EXEC_NAME_SUFFIXES)
