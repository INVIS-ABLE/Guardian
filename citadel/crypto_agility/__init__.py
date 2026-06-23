"""Citadel System 23 — Cryptographic Agility Fabric (Wave 23).

Inventory every algorithm / certificate / protocol / key use; classify against an allow-list
(unknown == fail closed); migrate under control (dual-read before cutover); detect downgrades; plan
hybrid post-quantum migration without weakening classical security.

Owner: ``inventory.py``. Independent verifier: ``downgrade.py``. Composed by ``verifier.py``.
"""

from __future__ import annotations

from .algorithms import (
    DEFAULT_ALGORITHMS,
    Algorithm,
    AlgorithmPolicy,
    AlgorithmStatus,
    CryptoPurpose,
)
from .certificates import Certificate, CertificateInventory
from .downgrade import DowngradeVerdict, detect_downgrade
from .hybrid import HybridScheme, HybridVerdict, hybrid_not_weaker_than_classical
from .inventory import (
    CryptoAsset,
    CryptoFinding,
    CryptoInventory,
    FindingSeverity,
    blocking_findings,
)
from .migration import MigrationError, MigrationPlan, MigrationState
from .protocols import ProtocolInventory, ProtocolUse
from .rotation import due_for_rotation, is_due
from .verifier import CryptoAgilityReport, CryptoAgilityVerifier

__all__ = [
    "Algorithm", "AlgorithmPolicy", "AlgorithmStatus", "CryptoPurpose", "DEFAULT_ALGORITHMS",
    "Certificate", "CertificateInventory", "DowngradeVerdict", "detect_downgrade",
    "HybridScheme", "HybridVerdict", "hybrid_not_weaker_than_classical",
    "CryptoAsset", "CryptoFinding", "CryptoInventory", "FindingSeverity", "blocking_findings",
    "MigrationError", "MigrationPlan", "MigrationState", "ProtocolInventory", "ProtocolUse",
    "due_for_rotation", "is_due", "CryptoAgilityReport", "CryptoAgilityVerifier",
]
