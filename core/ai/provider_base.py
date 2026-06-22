"""Provider abstraction — the thin seam between the gateway and a model backend.

A provider knows how to turn a (system, user) prompt into text for one or more pinned
models, and whether it is currently usable (SDK present, credentials configured). The
gateway never imports a provider SDK directly; it talks to this interface, so a missing
or unconfigured backend simply reports ``available() == False`` and the gateway fails
closed instead of crashing.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class ProviderResult(BaseModel):
    """The raw result of a provider call, before firewalling/provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str
    input_tokens: int = Field(ge=0, default=0)
    output_tokens: int = Field(ge=0, default=0)
    model_id: str


@runtime_checkable
class ModelProvider(Protocol):
    """A backend the gateway can call. Implementations live in ``provider_*.py``."""

    name: str

    def available(self) -> bool:
        """Whether this provider can currently serve a call (SDK + credentials)."""

    def complete(
        self,
        *,
        model_id: str,
        system: str,
        user: str,
        max_output_tokens: int,
        timeout_s: float,
    ) -> ProviderResult:
        """Run a single completion. Raise on any failure — the gateway fails closed."""


__all__ = ["ProviderResult", "ModelProvider"]
