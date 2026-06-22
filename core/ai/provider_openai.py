"""OpenAI provider adapter — used for the independent *judge* model (§2).

Independent review should use a different provider/model family from the producer, so a
conclusion is not accepted merely because copies of the same model agree. This adapter
lazily imports the ``openai`` SDK and reads ``OPENAI_API_KEY``; absent either, it
reports ``available() == False`` and the gateway fails closed.
"""

from __future__ import annotations

import os

from .provider_base import ProviderResult


class OpenAIProvider:
    """Calls OpenAI's Responses/Chat API for a pinned judge model id."""

    name = "openai"

    def __init__(self, *, api_key_env: str = "OPENAI_API_KEY") -> None:
        self._api_key_env = api_key_env

    def _client(self):
        try:
            import openai  # type: ignore
        except Exception:  # pragma: no cover - SDK is optional
            return None
        api_key = os.environ.get(self._api_key_env)
        if not api_key:
            return None
        return openai.OpenAI(api_key=api_key)

    def available(self) -> bool:
        return self._client() is not None

    def complete(
        self,
        *,
        model_id: str,
        system: str,
        user: str,
        max_output_tokens: int,
        timeout_s: float,
    ) -> ProviderResult:  # pragma: no cover - requires SDK + network
        client = self._client()
        if client is None:
            raise RuntimeError("openai provider unavailable (SDK or API key missing)")
        resp = client.chat.completions.create(
            model=model_id,
            max_tokens=max_output_tokens,
            timeout=timeout_s,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        text = resp.choices[0].message.content or ""
        usage = getattr(resp, "usage", None)
        return ProviderResult(
            text=text,
            input_tokens=getattr(usage, "prompt_tokens", 0) if usage else 0,
            output_tokens=getattr(usage, "completion_tokens", 0) if usage else 0,
            model_id=model_id,
        )


__all__ = ["OpenAIProvider"]
