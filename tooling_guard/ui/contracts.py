"""View-only data contracts. Requirement: Operator Introspection."""

from dataclasses import dataclass

from ..jev.score import (
    DEFAULT_FAST_ALLOW_SCORE,
    DEFAULT_FAST_BLOCK_SCORE,
    DEFAULT_FAST_MIN_CONFIDENCE,
)


@dataclass(frozen=True, slots=True)
class StartupSweepView:
    """Read-only view of the last startup ticket sweep of one connection.

    Requirement: Operator Introspection. A failed startup sweep closes the
    approval side, and that fact used to be invisible on every surface an
    operator can reach; these four fields are the whole disclosure: whether the
    sweep settled, how many attempts the connection has made, the failure text
    (already redacted downstream) and whether approvals are currently refused.
    """

    ok: bool
    attempts: int
    error: str = ""
    approvals_closed: bool = False

    def as_dict(self) -> dict[str, object]:
        """Return the field set as a plain mapping for the web payload."""
        return {
            "ok": self.ok,
            "attempts": self.attempts,
            "error": self.error,
            "approvals_closed": self.approvals_closed,
        }


@dataclass(frozen=True, slots=True)
class GatewayStatus:
    """Read-only gateway status view."""

    enabled: bool
    mode: str
    warning_count: int
    judge_route: str | None = None
    hook_degraded: str | None = None
    startup_sweep: StartupSweepView | None = None


@dataclass(frozen=True, slots=True)
class TicketView:
    """Read-only ticket summary view."""

    ticket_id: str
    state: str
    tool_name: str = ""
    created_at: str = ""


@dataclass(frozen=True, slots=True)
class TaintView:
    """Read-only taint status view."""

    active: bool
    session_hint: str


@dataclass(frozen=True, slots=True)
class FastJudgeStatus:
    """Read-only view of the fast judge exactly as the gateway assembled it.

    Requirement: Fast Judge Observability. A switched-off fast judge still has a
    backend, two score bands and a confidence floor -- the configured values are
    what tell an operator which client would have spoken -- so refusal and
    configuration travel together instead of one hiding the other. Every
    consumer reads this one object, so the text face and the web face cannot
    drift apart on a number and neither one re-derives a default. The defaults
    below are the shipped ones owned by `jev/score.py`, never a second copy of
    them; they are also the shape an unreadable gateway reports
    (`enabled=False`, empty backend), so a missing reader still fills every key
    rather than erasing it.
    """

    enabled: bool = False
    backend: str = ""
    allow_score: int = DEFAULT_FAST_ALLOW_SCORE
    block_score: int = DEFAULT_FAST_BLOCK_SCORE
    min_confidence: float = DEFAULT_FAST_MIN_CONFIDENCE
