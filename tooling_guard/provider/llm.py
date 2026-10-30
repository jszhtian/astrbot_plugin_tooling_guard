"""Deep-analysis client for OpenAI-compatible and AstrBot chat providers.

Requirement: Deep Analysis Client. Inputs are anonymized before either route;
no route retries a request.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any, Final

from ..anonymize import Anonymizer, PathRedactor

#: Defaults of the exact plugin schema keys, used when a key is absent.
_DEFAULTS: Final[Mapping[str, str]] = {
    "llm_mode": "astrbot_provider",
    "llm_base_url": "",
    "llm_model": "",
    "llm_api_key": "",
    "llm_provider_id": "",
}


def _setting(config: Any, name: str) -> Any:
    """Read one plugin schema key from a mapping or a config object.

    Requirement: Deep Analysis Client. The assembly point hands over the
    validated ``policy.config.GatewayConfig`` (a frozen slots dataclass), while
    tests and older callers pass a plain mapping; both must resolve. This
    mirrors ``jev/client.py:_setting`` so the two clients cannot disagree about
    how configuration is read.
    """
    if isinstance(config, Mapping):
        return config.get(name, _DEFAULTS.get(name))
    return getattr(config, name, _DEFAULTS.get(name))


class DeepReviewClient:
    """Unify endpoint and AstrBot-provider model access without retries."""

    def __init__(
        self,
        config: Any = None,
        *,
        context: Any = None,
        client: Any = None,
        transport: Any = None,
        anonymizer: Anonymizer | None = None,
    ) -> None:
        """Configure from the exact plugin schema keys and optional fakes."""
        self.mode = _setting(config, "llm_mode")
        self.base_url = _setting(config, "llm_base_url")
        self.model = _setting(config, "llm_model")
        self.api_key = _setting(config, "llm_api_key")
        self.provider_id = _setting(config, "llm_provider_id")
        self.context = context
        self._client = client
        self._transport = transport
        self._anonymizer = anonymizer or Anonymizer(paths=PathRedactor())

    async def review(
        self,
        prompt: str,
        *,
        timeout_s: float,
        system_prompt: str | None = None,
        response_format: Mapping[str, Any] | None = None,
    ) -> Any:
        """Run one anonymized review; timeout is supplied by the caller.

        Requirement: Deep Analysis Client; Layered Consensus. Background reviews
        pass deep_analysis_timeout_s (default 60); a synchronous review passes the
        budget left in the current request. No route retries, and the input is
        anonymized before either route is entered.

        The two optional arguments exist because the deep reviewer answers the
        same question the fast judge answers: same state document, same output
        schema. They carry the schema, not more input -- the user message stays
        the anonymized state, which is what keeps the two layers comparable.

        Args:
            prompt: The anonymized user message.
            timeout_s: Budget of this single request.
            system_prompt: Optional system message stating the answer schema.
            response_format: Optional OpenAI-compatible response_format mapping,
                forwarded only by the endpoint route (the host provider route has
                no equivalent argument).

        Returns:
            The completion text of the configured route.
        """
        redacted_prompt = self._anonymizer.redact(prompt)
        if self.mode == "endpoint":
            return await self._review_endpoint(
                redacted_prompt,
                timeout_s,
                system_prompt=system_prompt,
                response_format=response_format,
            )
        if self.mode == "astrbot_provider":
            return await self._review_provider(
                redacted_prompt, timeout_s, system_prompt=system_prompt
            )
        raise ValueError(f"unsupported llm_mode: {self.mode!r}")

    async def _review_endpoint(
        self,
        prompt: str,
        timeout_s: float,
        *,
        system_prompt: str | None = None,
        response_format: Mapping[str, Any] | None = None,
    ) -> str:
        """POST one OpenAI-compatible chat completion request."""
        if not self.base_url or not self.model:
            raise ValueError(
                "llm_base_url and llm_model are required for endpoint mode"
            )
        url = self.base_url.rstrip("/")
        if not url.endswith("/chat/completions"):
            url += "/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        payload: dict[str, Any] = {
            "model": self.model,
            "temperature": 0,
            "messages": messages,
        }
        if response_format is not None:
            payload["response_format"] = dict(response_format)
        if self._client is not None:
            response = await self._client.post(
                url, json=payload, headers=headers, timeout=timeout_s
            )
        else:
            try:
                import httpx
            except ImportError as exc:
                raise RuntimeError("httpx is required for endpoint mode") from exc
            async with httpx.AsyncClient(
                transport=self._transport, timeout=timeout_s
            ) as client:
                response = await client.post(
                    url, json=payload, headers=headers, timeout=timeout_s
                )
        response.raise_for_status()
        data = response.json()
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("endpoint returned an invalid chat completion") from exc
        if not isinstance(content, str):
            raise TypeError("endpoint returned non-text completion content")
        return content

    async def _review_provider(
        self, prompt: str, timeout_s: float, *, system_prompt: str | None = None
    ) -> str:
        """Invoke the public Context.llm_generate without importing astrbot.core.

        Host evidence (AstrBot 4.29.3): the public surface re-exports Context,
        Star and StarTools at astrbot/api/star/__init__.py:1 and lists them in
        __all__ at astrbot/api/star/__init__.py:7, so the Context handed to a
        plugin is the class defined at astrbot/core/star/context.py, whose
        verified method signature at astrbot/core/star/context.py:180-191 is

            async def llm_generate(
                self, *, chat_provider_id: str, prompt: str | None = None,
                image_urls: list[str] | None = None,
                audio_urls: list[str] | None = None, tools: ToolSet | None = None,
                system_prompt: str | None = None,
                contexts: list[Message] | None = None, **kwargs: Any,
            ) -> LLMResponse

        Both arguments are keyword-only, which matches the call below. The
        return type is astrbot/core/provider/entities.py:355 LLMResponse, whose
        text is the completion_text property at
        astrbot/core/provider/entities.py:447 (backed by _completion_text at
        astrbot/core/provider/entities.py:378). A context without the method
        raises TypeError instead of faking provider support.
        """
        generate = getattr(self.context, "llm_generate", None)
        if not callable(generate):
            raise TypeError(
                "astrbot_provider unavailable: the Context passed to the plugin "
                "does not expose the public llm_generate method"
            )
        response = await asyncio.wait_for(
            self._generate(generate, prompt, system_prompt),
            timeout=timeout_s,
        )
        text = getattr(response, "completion_text", None)
        if not isinstance(text, str):
            raise TypeError(
                f"{type(response).__name__} returned no text completion_text"
            )
        return text

    async def _generate(
        self, generate: Any, prompt: str, system_prompt: str | None = None
    ) -> Any:
        """Call llm_generate with the configured or host-default provider id.

        Requirement: Deep Analysis Client. An empty llm_provider_id means "use
        the model the host currently serves as its default", so resolving that
        default and generating share the caller's single
        ``asyncio.wait_for(timeout_s)`` budget: the timeout is never
        doubled and no route gains a retry.
        """
        provider_id = self.provider_id
        if not provider_id:
            provider_id = await self._default_provider_id()
        # system_prompt is a keyword-only argument of the same host method
        # (astrbot/core/star/context.py:180-191, quoted above), so the schema
        # reaches the provider route without a second request or a second call.
        return await generate(
            chat_provider_id=provider_id,
            prompt=prompt,
            system_prompt=system_prompt,
        )

    async def _default_provider_id(self) -> str:
        """Resolve the chat provider the host currently serves by default.

        Host evidence (AstrBot 4.29.3): the Context carries the provider manager
        as ``provider_manager`` (astrbot/core/star/context.py:162) and the
        public asynchronous default lookup is
        ``get_using_provider_async(provider_type, umo=None)``
        (astrbot/core/provider/manager.py:317), which returns None when that
        provider type is switched off or nothing is configured (:239-240) and
        otherwise falls back to ``provider_insts[0]`` for CHAT_COMPLETION
        (:249-258). The enum member is astrbot/core/provider/entities.py:33-34,
        re-exported at astrbot/api/provider/__init__.py:7; it is imported at call
        time, and its string value is never passed as a stand-in member. The id
        itself comes from ``meta()``
        (astrbot/core/provider/provider.py:47-59), which reads
        ``provider_config["id"]``.

        Raises:
            TypeError: the Context exposes no provider_manager, or the manager
                has no callable get_using_provider_async.
            RuntimeError: ProviderType cannot be imported, the host serves no
                default chat provider, or that provider reports no id.

        Returns:
            The provider id to hand to Context.llm_generate.
        """
        manager = getattr(self.context, "provider_manager", None)
        if manager is None:
            raise TypeError(
                "astrbot_provider unavailable: the Context passed to the plugin "
                "does not expose provider_manager, so an empty llm_provider_id "
                "cannot resolve to the host default chat provider"
            )
        getter = getattr(manager, "get_using_provider_async", None)
        if not callable(getter):
            raise TypeError(
                "astrbot_provider unavailable: Context.provider_manager has no "
                "callable get_using_provider_async, so an empty llm_provider_id "
                "cannot resolve to the host default chat provider"
            )
        try:
            from astrbot.api.provider import ProviderType
        except ImportError as exc:
            raise RuntimeError(
                "astrbot_provider unavailable: astrbot.api.provider exports no "
                "ProviderType, so an empty llm_provider_id cannot resolve"
            ) from exc
        provider = await getter(ProviderType.CHAT_COMPLETION)
        if provider is None:
            raise RuntimeError(
                "astrbot_provider unavailable: the host currently serves no "
                "default chat provider; set llm_provider_id in the plugin "
                "configuration"
            )
        try:
            meta_id = getattr(provider.meta(), "id", None)
        except Exception:  # noqa: BLE001 - any meta() failure falls back
            meta_id = None
        provider_config = getattr(provider, "provider_config", None)
        configured_id = None
        if isinstance(provider_config, Mapping):
            configured_id = provider_config.get("id")
        candidates = (meta_id, configured_id, getattr(provider, "provider_id", None))
        for candidate in candidates:
            if isinstance(candidate, str) and candidate:
                return candidate
        raise RuntimeError(
            "astrbot_provider unavailable: the host default chat provider reports "
            "no id; set llm_provider_id in the plugin configuration"
        )
