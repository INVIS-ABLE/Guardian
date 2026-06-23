"""Cryptographic inventory — the authoritative owner of System 23.

Every cryptographic use Guardian makes (algorithm + purpose + library + key size + protocol + where
the data lives + who owns it + migration state) is registered here. Scanning the inventory against
the algorithm policy produces findings: *unknown* crypto (fail CI), *deprecated* crypto (blocking
finding), or *forbidden* crypto (critical). This is what keeps cryptography from drifting silently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .algorithms import AlgorithmPolicy, AlgorithmStatus
from .migration import MigrationState


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def blocking(self) -> bool:
        return self in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)


@dataclass(frozen=True)
class CryptoAsset:
    """One registered cryptographic use. Mirrors the registry_fields in crypto-agility.yaml."""

    asset_id: str
    algorithm: str
    purpose: str
    library: str
    version: str
    key_size: int = 0
    protocol: str = ""
    data_locations: tuple[str, ...] = ()
    owners: tuple[str, ...] = ()
    rotation_period_days: int = 0
    migration_state: MigrationState = MigrationState.DISCOVERED
    approved_alternatives: tuple[str, ...] = ()
    deprecation_date: str = ""


@dataclass(frozen=True)
class CryptoFinding:
    asset_id: str
    algorithm: str
    severity: FindingSeverity
    reason: str


@dataclass
class CryptoInventory:
    assets: dict[str, CryptoAsset] = field(default_factory=dict)

    def register(self, asset: CryptoAsset) -> None:
        self.assets[asset.asset_id] = asset

    def all(self) -> list[CryptoAsset]:
        return list(self.assets.values())

    def scan(self, policy: AlgorithmPolicy | None = None) -> list[CryptoFinding]:
        """Classify every registered use. Unknown -> fail CI; deprecated/forbidden -> blocking."""
        pol = policy or AlgorithmPolicy.default()
        findings: list[CryptoFinding] = []
        for asset in self.assets.values():
            status = pol.classify(asset.algorithm)
            if status is None:
                findings.append(CryptoFinding(
                    asset.asset_id, asset.algorithm, FindingSeverity.HIGH,
                    "unknown algorithm: not on the approved allow-list (fail closed)",
                ))
                continue
            if status is AlgorithmStatus.FORBIDDEN:
                findings.append(CryptoFinding(
                    asset.asset_id, asset.algorithm, FindingSeverity.CRITICAL,
                    "forbidden algorithm in use",
                ))
            elif status is AlgorithmStatus.DEPRECATED:
                findings.append(CryptoFinding(
                    asset.asset_id, asset.algorithm, FindingSeverity.HIGH,
                    "deprecated algorithm: migrate before its deprecation date",
                ))
            algo = pol.get(asset.algorithm)
            if algo and algo.min_key_size and asset.key_size and asset.key_size < algo.min_key_size:
                findings.append(CryptoFinding(
                    asset.asset_id, asset.algorithm, FindingSeverity.HIGH,
                    f"key size {asset.key_size} below minimum {algo.min_key_size}",
                ))
        return findings


def blocking_findings(findings: list[CryptoFinding]) -> list[CryptoFinding]:
    return [f for f in findings if f.severity.blocking]


__all__ = [
    "FindingSeverity", "CryptoAsset", "CryptoFinding", "CryptoInventory", "blocking_findings",
]
