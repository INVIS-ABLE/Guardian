"""Cryptographic-agility verifier (Citadel System 23).

Ties the fabric together for a single, fail-closed verdict the CI gate consumes:

  * the inventory has no blocking findings (no unknown / forbidden / under-strength crypto),
  * no migration plan cut over to a new primary without first reaching dual-read,
  * no observed negotiation was a downgrade.

The authoritative owner is ``inventory.py``; downgrade detection (``downgrade.py``) is the named
independent verifier. This module composes them so a release can be gated on crypto agility.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .algorithms import AlgorithmPolicy
from .downgrade import detect_downgrade
from .inventory import CryptoFinding, CryptoInventory, blocking_findings
from .migration import MigrationPlan, MigrationState


@dataclass(frozen=True)
class CryptoAgilityReport:
    ok: bool
    blocking_findings: tuple[CryptoFinding, ...]
    migration_violations: tuple[str, ...]
    downgrade_violations: tuple[str, ...]


@dataclass
class CryptoAgilityVerifier:
    policy: AlgorithmPolicy = field(default_factory=AlgorithmPolicy.default)

    def verify(
        self,
        inventory: CryptoInventory,
        *,
        plans: list[MigrationPlan] | None = None,
        negotiations: list[tuple[list[str], str]] | None = None,
    ) -> CryptoAgilityReport:
        blocking = tuple(blocking_findings(inventory.scan(self.policy)))

        migration_violations: list[str] = []
        for plan in plans or []:
            if plan.cutover_done and not plan.dual_read_reached:
                migration_violations.append(
                    f"{plan.asset_id}: cut over to new-primary without dual-read"
                )

        downgrade_violations: list[str] = []
        for offered, negotiated in negotiations or []:
            verdict = detect_downgrade(offered, negotiated, self.policy)
            if not verdict.ok:
                downgrade_violations.extend(f"{negotiated}: {r}" for r in verdict.reasons)

        return CryptoAgilityReport(
            ok=not (blocking or migration_violations or downgrade_violations),
            blocking_findings=blocking,
            migration_violations=tuple(migration_violations),
            downgrade_violations=tuple(downgrade_violations),
        )


# Exposed for the migration-state guard used in tests / docs.
DUAL_READ = MigrationState.DUAL_READ

__all__ = ["CryptoAgilityReport", "CryptoAgilityVerifier", "DUAL_READ"]
