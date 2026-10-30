"""The fast judge client: one request, one answer, one hard five-second cap.

Requirement: Fast Judge Budget.

The budget rule is the whole design. One call spends exactly one request, never
retries, and never waits longer than `MAX_TIMEOUT_S` -- a retry would make the
worst case unbounded, and an unbounded fast judge inside the synchronous half of
the budget is what the cap exists to prevent. The caller may ask for less (the
pipeline hands down the remainder of the call budget) but never for more.

Two backends, one state:

- `fast_judge_backend = "jev"` posts the native systemone body from
  `prompts.systemone`: one state, a risk score question and a yes/no deep
  question, answered in one round trip.
- `fast_judge_backend = "llm"` posts an OpenAI-compatible chat completion from
  `prompts.single_call` and reads the JSON object out of the message content.

`jev_base_url` is the complete endpoint, verbatim. Nothing is appended to it,
because the two backends do not share a path suffix and a urljoin would silently
mangle a base that already carries one. Endpoint, model and key are the same
three configuration keys for both backends; only the body and the parser differ.

Errors are sanitized before they escape: the message carries the exception class
name and nothing else, so an operator can tell a timeout from a bad response
without the audit row quoting a URL, a header or a body.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any, Final

from ..prompts.single_call import build_single_call_body
from ..prompts.systemone import build_systemone_body
from .schema import parse_jev_answer, parse_llm_answer
from .score import BACKEND_JEV, FAST_JUDGE_BACKENDS, FastThresholds, FastVerdict

MAX_TIMEOUT_S: Final[float] = 50.0
"""Absolute ceiling on one fast judge request, in seconds.

The configured `jev_timeout_s` (validated to 1-50) is clamped into
`0..MAX_TIMEOUT_S`; this constant is the outer bound the configuration can
never pass, so a mistyped number cannot turn one judgement into a stall. The
raise from 30 s is not cosmetic: a 9B judge cold loaded by Ollama needs about
15 s before its first token, and the old ceiling turned the first call of a
session into a timeout that then denied the call.
"""

DEFAULT_TIMEOUT_S: Final[float] = 10.0
"""Timeout used when `jev_timeout_s` is absent.

Five seconds was the old hard cap, and it is below the cold start of a local
judge (an Ollama-hosted model needs about 15 seconds to load before it answers
anything). Ten seconds keeps a warm judge bounded while leaving room for the
state itself: a 6 KB state costs roughly 0.6 s/KB, so ~3.6 seconds of inference
on top of a fast load. Endpoints that cold start slower raise the key.
"""

_SANITIZED_ERRORS: Final[tuple[type[BaseException], ...]] = (
    OSError,
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    AttributeError,
    RuntimeError,
)
"""Failures reported by class name only; `httpx.HTTPError` joins them at call time."""


def _setting(config: Any, name: str) -> Any:
    """Read one configuration value off a mapping or an object."""
    if isinstance(config, Mapping):
        return config.get(name)
    return getattr(config, name, None)


def _text(value: Any) -> str:
    """Return one trimmed configuration string, or an empty string."""
    return value.strip() if isinstance(value, str) else ""


def configured_timeout(value: Any) -> float:
    """Return the configured fast-judge timeout, clamped into the legal range.

    Requirement: Fast Judge Budget. The configuration layer already rejects an
    out-of-range `jev_timeout_s` as a fatal issue; this clamp only keeps a
    hand-built config or a fake from producing a nonsense budget, and it never
    widens above `MAX_TIMEOUT_S`.
    """
    if isinstance(value, bool) or value is None:
        return DEFAULT_TIMEOUT_S
    try:
        number = float(value)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_S
    if not math.isfinite(number) or number <= 0:
        return DEFAULT_TIMEOUT_S
    return min(number, MAX_TIMEOUT_S)


class JevClient:
    """One configured fast judge endpoint, asked one state at a time."""

    def __init__(
        self, config: Any, *, transport: Any = None, client: Any = None
    ) -> None:
        """Read the endpoint, the route and the timeout policy off a config.

        Args:
            config: A resolved gateway config or any mapping with the same keys.
            transport: Optional `httpx` transport, injected by tests.
            client: Optional prepared `httpx.AsyncClient`; when given it is used
                as-is and never closed here.

        Raises:
            ValueError: The backend is outside `jev`/`llm`, or the endpoint,
                model and key are not all non-empty. No default is invented: a
                fast judge that cannot be configured must fail loudly at build
                time, where the assembly already degrades the gateway.
        """
        backend = _text(_setting(config, "fast_judge_backend")) or BACKEND_JEV
        endpoint = _text(_setting(config, "jev_base_url"))
        model = _text(_setting(config, "jev_model"))
        api_key = _text(_setting(config, "jev_api_key"))
        if backend not in FAST_JUDGE_BACKENDS:
            raise ValueError(f"unknown fast judge backend: {backend}")
        if not endpoint or not model or not api_key:
            raise ValueError("Jev endpoint configuration is incomplete")
        self._backend = backend
        self._endpoint = endpoint
        self._model = model
        self._api_key = api_key
        self._transport = transport
        self._client = client
        self._timeout_s = configured_timeout(_setting(config, "jev_timeout_s"))

    @property
    def timeout_s(self) -> float:
        """Return the configured per-request ceiling in seconds."""
        return self._timeout_s

    @property
    def backend(self) -> str:
        """Return the configured backend word, `jev` or `llm`."""
        return self._backend

    @property
    def endpoint(self) -> str:
        """Return the configured endpoint exactly as it will be posted to."""
        return self._endpoint

    @property
    def model(self) -> str:
        """Return the configured model id."""
        return self._model

    def body(self, state: Mapping[str, Any]) -> dict[str, Any]:
        """Build the request body of this backend for one state."""
        if self._backend == BACKEND_JEV:
            return build_systemone_body(model=self._model, state=state)
        return build_single_call_body(model=self._model, state=state)

    def parse(self, payload: Any) -> FastVerdict:
        """Read the decoded answer of this backend as a verdict."""
        if self._backend == BACKEND_JEV:
            return parse_jev_answer(payload)
        return parse_llm_answer(payload)

    async def ask(
        self, state: Mapping[str, Any], *, timeout_s: float = MAX_TIMEOUT_S
    ) -> FastVerdict:
        """Ask the endpoint about one state, once.

        Requirement: Fast Judge Budget; Fail-Closed Triage.

        Args:
            state: The structured state built by `prompts.state.build_state`.
            timeout_s: The caller's remaining budget in seconds; clamped into
                `0..MAX_TIMEOUT_S`, so a large budget cannot extend the cap.

        Returns:
            FastVerdict: The parsed answer. An unreadable answer carries
            `score_pct=None`, which the decision step treats as an abstention.

        Raises:
            RuntimeError: The request failed. The message names the exception
                class only, and the engine folds it into a deny.
        """
        import httpx

        timeout = min(max(float(timeout_s), 0.0), self._timeout_s)
        headers = {"Authorization": f"Bearer {self._api_key}"}
        body = self.body(state)
        try:
            response = await self._post(
                httpx, body=body, headers=headers, timeout=timeout
            )
            return self.parse(response.json())
        except _SANITIZED_ERRORS + (httpx.HTTPError,) as exc:
            raise RuntimeError(f"Jev request failed ({type(exc).__name__})") from None

    async def _post(
        self,
        httpx: Any,
        *,
        body: dict[str, Any],
        headers: dict[str, str],
        timeout: float,
    ) -> Any:
        """Post one body and return the response, raising for a bad status."""
        if self._client is not None:
            response = await self._client.post(
                self._endpoint, json=body, headers=headers, timeout=timeout
            )
        else:
            async with httpx.AsyncClient(transport=self._transport) as client:
                response = await client.post(
                    self._endpoint, json=body, headers=headers, timeout=timeout
                )
        response.raise_for_status()
        return response


class FastJudge:
    """The injected judge callable: one client, one cap, one threshold pair.

    Requirement: Fail-Closed Triage. The reviewer is built without thresholds --
    `reviewers.register_builtin_reviewers` binds the callable and nothing else --
    so the pair travels with the judge and the engine reads it back off this
    object. A bare callable without `thresholds` falls back to the factory
    defaults in `jev.score`, never to a release.
    """

    def __init__(
        self,
        client: JevClient,
        *,
        timeout_s: float | None = None,
        thresholds: FastThresholds | None = None,
    ) -> None:
        """Bind one client to one cap and one threshold pair.

        Args:
            client: The configured endpoint client.
            timeout_s: Per-call cap in seconds, clamped into `0..MAX_TIMEOUT_S`.
            thresholds: The band factory; the documented defaults when omitted.
        """
        self._client = client
        # A client stand-in need not publish the attribute; the documented default
        # is the fallback, and an explicit timeout_s can still only narrow it.
        ceiling = configured_timeout(getattr(client, "timeout_s", None))
        if timeout_s is None:
            self._timeout_s = ceiling
        else:
            self._timeout_s = min(max(float(timeout_s), 0.0), ceiling)
        self._thresholds = FastThresholds() if thresholds is None else thresholds

    @property
    def client(self) -> JevClient:
        """Return the bound client."""
        return self._client

    @property
    def thresholds(self) -> FastThresholds:
        """Return the band thresholds this judge is banded with."""
        return self._thresholds

    @property
    def timeout_s(self) -> float:
        """Return the per-call cap this judge enforces."""
        return self._timeout_s

    async def __call__(
        self, state: Mapping[str, Any], *, timeout_s: float | None = None
    ) -> FastVerdict:
        """Ask the bound client about one state.

        Args:
            state: The structured state the engine built.
            timeout_s: Optional override for this one call, clamped by the client.

        Returns:
            FastVerdict: The parsed answer.
        """
        cap = self._timeout_s if timeout_s is None else timeout_s
        return await self._client.ask(state, timeout_s=cap)


__all__ = [
    "DEFAULT_TIMEOUT_S",
    "MAX_TIMEOUT_S",
    "FastJudge",
    "JevClient",
    "configured_timeout",
]
