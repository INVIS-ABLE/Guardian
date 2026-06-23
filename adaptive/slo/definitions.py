"""Service-level objectives, including the privacy/safeguarding ones (directive §9).

Guardian must not optimise only for technical uptime. Every critical service carries the
usual reliability SLOs (availability, latency, error rate, replication, backup freshness,
…) *and* the INVISABLE-specific invariant SLOs (privacy, safeguarding, notification
confidentiality, cross-tenant access, encryption-downgrade, key-directory consistency,
account recovery). The latter are marked ``privacy_critical`` so the safety gate
(``safety_gates.py``) can refuse any repair that would trade them for availability.

Strict Pydantic v2; objectives are expressed uniformly as a target *good fraction* in
(0, 1] over a rolling window.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class SLOKind(str, Enum):
    # reliability objectives
    AVAILABILITY = "availability"
    LATENCY = "latency"
    ERROR_RATE = "error_rate"
    QUEUE_DELAY = "queue_delay"
    REPLICATION_HEALTH = "replication_health"
    MESSAGE_DELIVERY_HEALTH = "message_delivery_health"
    AUTHENTICATION_HEALTH = "authentication_health"
    KEY_TRANSPARENCY_HEALTH = "key_transparency_health"
    EVIDENCE_WRITE_HEALTH = "evidence_write_health"
    POLICY_DECISION_HEALTH = "policy_decision_health"
    BACKUP_FRESHNESS = "backup_freshness"
    RECOVERY_READINESS = "recovery_readiness"
    # INVISABLE invariant objectives (privacy / safeguarding / security)
    PRIVACY_INVARIANT = "privacy_invariant"
    SAFEGUARDING_WORKFLOW = "safeguarding_workflow"
    NOTIFICATION_CONFIDENTIALITY = "notification_confidentiality"
    CROSS_TENANT_ACCESS = "cross_tenant_access"
    ENCRYPTION_DOWNGRADE = "encryption_downgrade"
    KEY_DIRECTORY_CONSISTENCY = "key_directory_consistency"
    ACCOUNT_RECOVERY = "account_recovery"


# Invariant SLOs that must never be regressed for an availability gain (§9). A repair that
# weakens any of these is rejected regardless of its reliability benefit.
PRIVACY_CRITICAL_KINDS: frozenset[SLOKind] = frozenset(
    {
        SLOKind.PRIVACY_INVARIANT,
        SLOKind.SAFEGUARDING_WORKFLOW,
        SLOKind.NOTIFICATION_CONFIDENTIALITY,
        SLOKind.CROSS_TENANT_ACCESS,
        SLOKind.ENCRYPTION_DOWNGRADE,
        SLOKind.KEY_DIRECTORY_CONSISTENCY,
    }
)


class SLO(BaseModel):
    """One service-level objective: a target good-fraction over a rolling window."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    service: str = Field(min_length=1)
    kind: SLOKind
    objective: float = Field(gt=0.0, le=1.0)  # e.g. 0.999
    window_seconds: int = Field(ge=1)
    description: str = ""

    @property
    def is_privacy_critical(self) -> bool:
        return self.kind in PRIVACY_CRITICAL_KINDS

    @property
    def error_budget(self) -> float:
        """The allowed bad fraction (1 - objective)."""
        return 1.0 - self.objective


class SLORegistry:
    """The set of SLOs Guardian tracks, indexed by service."""

    def __init__(self, slos: list[SLO] | None = None) -> None:
        self._by_service: dict[str, list[SLO]] = {}
        for slo in slos or []:
            self.register(slo)

    def register(self, slo: SLO) -> None:
        self._by_service.setdefault(slo.service, []).append(slo)

    def for_service(self, service: str) -> list[SLO]:
        return list(self._by_service.get(service, []))

    def services_without_slo(self, critical_services: list[str]) -> list[str]:
        """Critical services that have no SLO at all (acceptance #12 helper)."""
        return [s for s in critical_services if not self._by_service.get(s)]


__all__ = ["SLOKind", "PRIVACY_CRITICAL_KINDS", "SLO", "SLORegistry"]
