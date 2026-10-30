"""Result adapter contracts. Requirement: Denial Result Contract."""

from typing import Any

from mcp.types import CallToolResult, TextContent

# Longest single in-call approval wait; design D8 clamps the wait to this cap.
PENDING_WAIT_SECONDS = 110


def denial_result(reason: str) -> Any:
    """Construct a host-compatible denial result. Requirement: Denial Result Contract.

    Args:
        reason: Rule or policy statement, including its rule identifier. It must
            not repeat the raw arguments or secret values of the refused call.

    Returns:
        A ``mcp.types.CallToolResult`` marked ``isError=True`` whose single text
        block names the reason and states that the same call must not be retried.
    """
    detail = " ".join(str(reason or "").split())
    if not detail:
        detail = "策略拒绝了本次调用，且未提供原因"
    return CallToolResult(
        isError=True,
        content=[
            TextContent(
                type="text",
                text=(
                    f"工具调用已被拦截：{detail}。"
                    "请勿重试同一调用；如确需继续，请修改请求后重试或联系管理员。"
                ),
            )
        ],
    )


def suspension_text(ticket_id: str, state: str) -> str:
    """Build a real, non-empty suspension result.

    Requirement: Synchronous Suspension Result Contract.

    Args:
        ticket_id: Identifier of the approval ticket backing this suspension.
        state: Decided ticket state: ``approved``, ``pending``, ``denied`` or
            ``timeout``; matching is case-insensitive.

    Returns:
        Non-empty text for every state. A ``None`` return from the proxy would end
        the tool loop instead of suspending it
        (astrbot/core/agent/runners/tool_loop_agent_runner.py:1372-1387).
    """
    ticket = " ".join(str(ticket_id or "").split()) or "未知票据"
    normalized = " ".join(str(state or "").split()).lower()
    if normalized in {"approved", "approve", "allow", "allowed", "allow_passthrough"}:
        return (
            f"已批准（票据 {ticket}）：可用相同工具名与相同参数重试一次；不会自动重放。"
        )
    if normalized in {"pending", "suspended", "suspend", "waiting", "awaiting"}:
        return (
            f"已挂起（票据 {ticket}）：已通知管理员审批，"
            f"{PENDING_WAIT_SECONDS} 秒内无响应按超时拒绝；请勿重复调用。"
        )
    if normalized in {
        "denied",
        "deny",
        "deny_policy",
        "deny_requester",
        "deny_rule",
        "deny_judge",
        "reject",
        "rejected",
    }:
        return (
            f"已拒绝（票据 {ticket}）：管理员未批准。"
            "请勿重试同一调用；如需继续请改请求或联系管理员。"
        )
    if normalized in {"timeout", "timed_out", "expired"}:
        return f"审批超时（票据 {ticket}）：按拦截处理并已记审计；请勿重试同一调用。"
    return (
        f"审批未决（票据 {ticket}，状态 {normalized or '未知'}）："
        "按拦截处理并已记审计；请勿重试同一调用。"
    )
