"""Typed models for the digital-twin chaos & recovery simulator (Sovereign plane, Wave 3, #17).

Failure simulations run against a **clone** of the digital twin (#1), never production: kill a
region, an IdP, OPA, the secrets store, a CA, a key rotation, a queue, a DB, the audit log, or a
network partition — then compare the **predicted** blast radius (what the twin model said would
break) against the **actual** observed impact. Every mismatch is a *surprise* the model can learn
from: a control that worked better than predicted, or a dependency the map missed
(docs/sovereign_ops_plane.md).

Shapes only: the `FailureScenario`, the `ChaosResult` (predicted vs actual impact + recovery
timing), the `Surprise` (where the model and reality diverged), and the `ChaosReport`. The
simulator engine — which enforces *clone-only* — lives in ``simulator.py``.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator

SCHEMA_VERSION = 1


class FailureMode(str, Enum):
    """The kinds of failure the simulator injects against the cloned twin."""

    REGION_OUTAGE = "region_outage"
    IDP_OUTAGE = "idp_outage"
    POLICY_ENGINE_DOWN = "policy_engine_down"   # OPA unavailable
    SECRETS_STORE_DOWN = "secrets_store_down"   # OpenBao/Vault unavailable
    CA_OUTAGE = "ca_outage"
    KEY_ROTATION = "key_rotation"
    QUEUE_BACKLOG = "queue_backlog"
    DATABASE_FAILOVER = "database_failover"
    AUDIT_LOG_DOWN = "audit_log_down"
    NETWORK_PARTITION = "network_partition"


class SurpriseKind(str, Enum):
    """How the model diverged from reality (the learning signal)."""

    UNPREDICTED_IMPACT = "unpredicted_impact"   # actually broke, model didn't foresee it (bad — map gap)
    OVERPREDICTED_IMPACT = "overpredicted_impact"  # model feared it, control held (good — resilience)


class FailureScenario(BaseModel):
    """One failure to inject against the cloned twin, with the model's predicted impact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    id: str
    mode: FailureMode
    target: str                   # the twin asset id the failure hits, e.g. "svc:messaging-relay"
    predicted_impact: tuple[str, ...] = ()  # asset ids the twin model expects to be affected

    @field_validator("id", "target")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("scenario id/target must be non-empty")
        return v


class Surprise(BaseModel):
    """One asset where predicted and actual impact disagreed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    asset: str
    kind: SurpriseKind


class ChaosResult(BaseModel):
    """The outcome of one scenario: predicted vs actual impact and recovery timing."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario: FailureScenario
    actual_impact: tuple[str, ...]      # asset ids actually affected in the clone
    recovered: bool                     # did the system recover within objective?
    rto_seconds: int | None = None      # observed time to recover
    rto_objective_seconds: int | None = None  # the objective it was measured against

    @property
    def surprises(self) -> tuple[Surprise, ...]:
        predicted = set(self.scenario.predicted_impact)
        actual = set(self.actual_impact)
        out = [Surprise(asset=a, kind=SurpriseKind.UNPREDICTED_IMPACT) for a in sorted(actual - predicted)]
        out += [Surprise(asset=a, kind=SurpriseKind.OVERPREDICTED_IMPACT) for a in sorted(predicted - actual)]
        return tuple(out)

    @property
    def model_accurate(self) -> bool:
        """True when predicted impact exactly matched reality (no surprises)."""
        return set(self.scenario.predicted_impact) == set(self.actual_impact)

    @property
    def rto_breached(self) -> bool:
        if self.rto_seconds is None or self.rto_objective_seconds is None:
            return not self.recovered
        return (not self.recovered) or self.rto_seconds > self.rto_objective_seconds


class ChaosReport(BaseModel):
    """The outcome of a chaos run over a cloned twin."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run: str
    clone_of: str                 # the twin the clone was taken from (provenance)
    results: tuple[ChaosResult, ...]

    @property
    def unpredicted(self) -> tuple[Surprise, ...]:
        """Map gaps: assets that broke but the model didn't foresee (the dangerous surprises)."""
        return tuple(s for r in self.results for s in r.surprises
                     if s.kind is SurpriseKind.UNPREDICTED_IMPACT)

    @property
    def rto_breaches(self) -> tuple[ChaosResult, ...]:
        return tuple(r for r in self.results if r.rto_breached)

    @property
    def has_gap(self) -> bool:
        """A map gap or an RTO breach is a finding — callers gate on this."""
        return bool(self.unpredicted) or bool(self.rto_breaches)

    def model_accuracy(self) -> float:
        """Fraction of scenarios whose predicted impact exactly matched reality."""
        if not self.results:
            return 1.0
        return sum(1 for r in self.results if r.model_accurate) / len(self.results)
