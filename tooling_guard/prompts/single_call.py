"""The llm request body: an OpenAI-compatible chat completion over the state.

Requirement: Fast Judge Budget; Fail-Closed Triage.

The llm backend is any OpenAI-compatible chat endpoint, so the request is the
plainest one that can be parsed deterministically: temperature 0, a JSON object
as the only response shape, and the structured state as the user message. The
system message states the answer schema once --
`{"score": int, "noul": bool, "confidence": number}` -- because
`jev.schema.parse_llm_answer` rejects everything else, and a model that answers
a decision word instead of a score is an abstention, not a release. `confidence`
is the one optional field: a missing or unusable value changes no band, it only
leaves the confidence floor unarmed and records that it did.

The state is sent as JSON, not as prose: the same document the jev backend gets,
so both backends can be compared on identical input.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from .state import state_json

SYSTEM_PROMPT: Final[str] = (
    "You are a tool-call risk reviewer. Output one JSON object and no other text, "
    'shaped exactly like {"score": <integer 0-100>, "noul": <true or false>, '
    '"confidence": <number from 0 to 1>}. '
    "A higher score means more dangerous: 0 is completely harmless, 100 is "
    "critical; judge the effect of this call, not the capability of the tool. "
    "When trajectory_summary is present it lists earlier calls of the same "
    "session (oldest first, with their outcome), and a sensitive read followed by "
    "an outbound call is riskier than either call alone. Set noul to true only "
    "when this call still needs one synchronous deep analysis before it is "
    "allowed. confidence is how certain you are of this judgement: 0 is a pure "
    "guess, 1 is certain; answer 0.8 or more when the call plainly matches one "
    "band. Below the operator's floor your answer is recorded as no opinion at "
    "all: the deep layer decides, and if it also has no opinion an administrator "
    "is asked."
)
"""The system message: the answer schema, stated once, with no prose allowed."""

RESPONSE_FORMAT: Final[dict[str, str]] = {"type": "json_object"}
"""The only response shape this backend is asked for."""


def build_single_call_body(*, model: str, state: Mapping[str, Any]) -> dict[str, Any]:
    """Build the complete chat-completions body for one state.

    Requirement: Fast Judge Budget. One request, one answer: the user message is
    the serialized state and the system message fixes the output schema, so no
    multi-turn exchange can spend a second request.

    Args:
        model: Model id the endpoint should answer with.
        state: The structured state, as `prompts.state.build_state` builds it.

    Returns:
        dict: The body posted verbatim to the configured chat endpoint.
    """
    return {
        "model": model,
        "temperature": 0,
        "response_format": dict(RESPONSE_FORMAT),
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": state_json(state)},
        ],
    }


__all__ = [
    "RESPONSE_FORMAT",
    "SYSTEM_PROMPT",
    "build_single_call_body",
]
