"""Model registry — the allow-list of pinned models the gateway may call (§2).

A model is callable only if it is registered here. The registry maps capability
*classes* (fast, strong-reasoning, judge, …) to concrete pinned :class:`ModelSpec`s,
so routing can ask for "a strong reasoning model" and get a specific, pinned id.

Prices on the default specs are estimates for budget accounting, overridable via
configuration; they are not authoritative billing figures.
"""

from __future__ import annotations

from .schemas import ModelClass, ModelSpec

# The current pinned reasoning model. Anthropic publishes pinned snapshot IDs rather
# than moving aliases; this matches guardian.config.yaml.
CLAUDE_OPUS = "claude-opus-4-8"
CLAUDE_HAIKU = "claude-haiku-4-5-20251001"


class ModelRegistry:
    """An allow-list of registered models, indexed by id and by capability class."""

    def __init__(self, specs: list[ModelSpec] | None = None) -> None:
        self._by_id: dict[str, ModelSpec] = {}
        self._by_class: dict[ModelClass, list[ModelSpec]] = {}
        for spec in specs or []:
            self.register(spec)

    def register(self, spec: ModelSpec) -> None:
        self._by_id[spec.model_id] = spec
        self._by_class.setdefault(spec.model_class, []).append(spec)

    def get(self, model_id: str) -> ModelSpec | None:
        return self._by_id.get(model_id)

    def for_class(self, model_class: ModelClass) -> list[ModelSpec]:
        """Registered specs for a capability class (in registration order)."""
        return list(self._by_class.get(model_class, []))

    def resolve(self, model_class: ModelClass) -> ModelSpec | None:
        """The preferred (first registered) spec for a capability class, if any."""
        specs = self._by_class.get(model_class)
        return specs[0] if specs else None


def default_registry() -> ModelRegistry:
    """The default production allow-list of pinned models.

    The local provider (``guardian-local``) is the only one guaranteed to be available
    offline; the Anthropic/OpenAI specs require their SDK + credentials and otherwise
    resolve to "unavailable" at call time, so the gateway fails closed rather than
    silently downgrading.
    """
    return ModelRegistry(
        [
            ModelSpec(
                model_id=CLAUDE_OPUS,
                provider="anthropic",
                model_class=ModelClass.STRONG_REASONING,
                family="claude",
                performs_external_processing=True,
                max_output_tokens=8192,
                input_price_per_mtok=15.0,
                output_price_per_mtok=75.0,
            ),
            ModelSpec(
                model_id=CLAUDE_OPUS,
                provider="anthropic",
                model_class=ModelClass.STRONG_CODING,
                family="claude",
                performs_external_processing=True,
                max_output_tokens=8192,
                input_price_per_mtok=15.0,
                output_price_per_mtok=75.0,
            ),
            ModelSpec(
                model_id=CLAUDE_HAIKU,
                provider="anthropic",
                model_class=ModelClass.FAST,
                family="claude",
                performs_external_processing=True,
                max_output_tokens=4096,
                input_price_per_mtok=1.0,
                output_price_per_mtok=5.0,
            ),
            # Independent reviewer: a deliberately different family so a conclusion is
            # not accepted merely because copies of the same model agree (§2).
            ModelSpec(
                model_id="gpt-judge-pinned",
                provider="openai",
                model_class=ModelClass.JUDGE,
                family="openai",
                performs_external_processing=True,
                max_output_tokens=4096,
                input_price_per_mtok=10.0,
                output_price_per_mtok=30.0,
            ),
            # Approved private/local model for sensitive content — no external processing.
            ModelSpec(
                model_id="guardian-local",
                provider="local",
                model_class=ModelClass.LOCAL,
                family="local",
                performs_external_processing=False,
                max_output_tokens=4096,
                input_price_per_mtok=0.0,
                output_price_per_mtok=0.0,
            ),
        ]
    )


__all__ = ["ModelRegistry", "default_registry", "CLAUDE_OPUS", "CLAUDE_HAIKU"]
