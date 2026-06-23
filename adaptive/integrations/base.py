"""Integration-adapter contracts for the Level 6 control plane (directive §4, §11, §37).

The directive integrates many external systems — Argo CD/Rollouts, Keptn, Flink, Karmada,
Crossplane, MLflow, KServe and so on — but every one of them sits *behind* Guardian's
existing authorities. The rule is invariant: **an integration never grants authority; it
produces evidence and signals.** This module defines the shared adapter contract and the
guard that enforces that rule, so the actual network-talking adapters (which are deployment-
specific) can only ever be wired in as evidence sources.

Nothing here talks to a network. These are the *contracts*; a real adapter implements the
``IntegrationAdapter`` protocol in the deployment, and registration refuses anything that
claims authority.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AdapterHealth(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    available: bool
    detail: str = ""


class Signal(BaseModel):
    """A typed evidence/signal an adapter emits. Never an instruction, never authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    summary: str = ""
    tenant_id: str = ""
    classification: str = "internal"
    payload_ref: str = ""  # content-addressed reference; never inline secrets
    at: datetime = Field(default_factory=_utcnow)


@runtime_checkable
class IntegrationAdapter(Protocol):
    """An external system Guardian reads from. It reports health and emits signals only."""

    name: str
    grants_authority: bool  # MUST be False — enforced by assert_no_authority

    def health(self) -> AdapterHealth: ...


class AuthorityViolation(RuntimeError):
    """Raised when an integration claims to grant authority. Fail closed."""


def assert_no_authority(adapter: IntegrationAdapter) -> None:
    """Refuse any adapter that claims to grant authority (§11, §37). Fail closed."""
    if getattr(adapter, "grants_authority", True):
        raise AuthorityViolation(
            f"integration {getattr(adapter, 'name', adapter)!r} must not grant authority — "
            "integrations produce evidence and signals only"
        )


__all__ = [
    "AdapterHealth",
    "Signal",
    "IntegrationAdapter",
    "AuthorityViolation",
    "assert_no_authority",
]
