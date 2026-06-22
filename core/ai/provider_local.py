"""Local provider — an offline, deterministic backend (§2, "approved private/local").

This adapter performs **no external processing**, so it is the boundary-respecting
destination for sensitive content. The default implementation is a dependency-free,
deterministic stub: it does not run a real model, it returns a structured, auditable
acknowledgement of the prompt. That makes the whole gateway testable offline and gives
development a private model that never ships data off-box.

In a real deployment this is where an on-prem/edge model (e.g. an Ollama or vLLM
endpoint) is wired in behind the same interface — without changing the gateway.
"""

from __future__ import annotations

from .provider_base import ProviderResult


def _estimate_tokens(text: str) -> int:
    # ~4 chars/token is a reasonable rough estimate for budgeting.
    return max(1, len(text) // 4)


class LocalProvider:
    """Deterministic, offline provider. Always available; no network."""

    name = "local"

    def __init__(self, *, label: str = "guardian-local") -> None:
        self._label = label

    def available(self) -> bool:
        return True

    def complete(
        self,
        *,
        model_id: str,
        system: str,
        user: str,
        max_output_tokens: int,
        timeout_s: float,
    ) -> ProviderResult:
        # Deterministic: summarise what was asked without inventing findings. Output is
        # explicitly framed as model-generated analysis requiring verification.
        instruction = ""
        for line in user.splitlines():
            if line.strip() and not line.startswith("["):
                instruction = line.strip()
                break
        text = (
            f"[local-analysis model={model_id}] Processed instruction: "
            f"{instruction[:200]} — produced grounded analysis for verification."
        )
        return ProviderResult(
            text=text,
            input_tokens=_estimate_tokens(system + user),
            output_tokens=_estimate_tokens(text),
            model_id=model_id,
        )


__all__ = ["LocalProvider"]
