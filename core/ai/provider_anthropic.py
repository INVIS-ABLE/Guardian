"""Anthropic provider adapter (§2).

Lazily imports the ``anthropic`` SDK and reads ``ANTHROPIC_API_KEY``. If either is
absent the provider reports ``available() == False`` and the gateway fails closed —
it never silently substitutes a different model. The SDK is an *optional* dependency
(see pyproject ``[project.optional-dependencies].brain``); Guardian runs offline
without it via the local provider.
"""

from __future__ import annotations

import os

from .provider_base import ProviderResult


class AnthropicProvider:
    """Calls Anthropic's Messages API for pinned Claude model ids."""

    name = "anthropic"

    def __init__(self, *, api_key_env: str = "ANTHROPIC_API_KEY") -> None:
        self._api_key_env = api_key_env

    def _client(self):
        try:
            import anthropic  # type: ignore
        except Exception:  # pragma: no cover - SDK is optional
            return None
        api_key = os.environ.get(self._api_key_env)
        if not api_key:
            return None
        return anthropic.Anthropic(api_key=api_key)

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
            raise RuntimeError("anthropic provider unavailable (SDK or API key missing)")
        msg = client.messages.create(
            model=model_id,
            max_tokens=max_output_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            timeout=timeout_s,
        )
        text = "".join(
            block.text for block in msg.content if getattr(block, "type", None) == "text"
        )
        usage = getattr(msg, "usage", None)
        return ProviderResult(
            text=text,
            input_tokens=getattr(usage, "input_tokens", 0) if usage else 0,
            output_tokens=getattr(usage, "output_tokens", 0) if usage else 0,
            model_id=model_id,
        )


__all__ = ["AnthropicProvider"]
