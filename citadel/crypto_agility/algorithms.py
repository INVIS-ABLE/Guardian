"""Algorithm policy + classification (Citadel System 23, Wave 23).

The authoritative allow-list of cryptographic algorithms and their lifecycle. Anything not on the
list is *unknown* (and must fail closed); anything deprecated/forbidden is a finding. Post-quantum
readiness is tracked per algorithm so migration can be planned, never silent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class AlgorithmStatus(str, Enum):
    APPROVED = "approved"
    DEPRECATED = "deprecated"     # still readable during migration; a blocking finding for new use
    FORBIDDEN = "forbidden"       # never permitted


class CryptoPurpose(str, Enum):
    SIGNATURE = "signature"
    KEY_EXCHANGE = "key_exchange"
    ENCRYPTION = "encryption"
    HASH = "hash"
    KDF = "kdf"
    MAC = "mac"


@dataclass(frozen=True)
class Algorithm:
    name: str
    purpose: CryptoPurpose
    status: AlgorithmStatus
    min_key_size: int = 0          # 0 = not key-sized (e.g. a hash)
    post_quantum: bool = False     # PQ or PQ-hybrid safe
    classical_strength_bits: int = 0   # equivalent classical security (for hybrid checks)


# A small, opinionated baseline. Real deployments load this from configs/citadel/crypto-agility.yaml.
DEFAULT_ALGORITHMS: tuple[Algorithm, ...] = (
    Algorithm("ed25519", CryptoPurpose.SIGNATURE, AlgorithmStatus.APPROVED, 256, False, 128),
    Algorithm("ecdsa-p256", CryptoPurpose.SIGNATURE, AlgorithmStatus.APPROVED, 256, False, 128),
    Algorithm("rsa-2048", CryptoPurpose.SIGNATURE, AlgorithmStatus.DEPRECATED, 2048, False, 112),
    Algorithm("rsa-1024", CryptoPurpose.SIGNATURE, AlgorithmStatus.FORBIDDEN, 1024, False, 80),
    Algorithm("ml-dsa-65", CryptoPurpose.SIGNATURE, AlgorithmStatus.APPROVED, 0, True, 192),
    Algorithm("x25519", CryptoPurpose.KEY_EXCHANGE, AlgorithmStatus.APPROVED, 256, False, 128),
    Algorithm("ml-kem-768", CryptoPurpose.KEY_EXCHANGE, AlgorithmStatus.APPROVED, 0, True, 192),
    Algorithm("aes-256-gcm", CryptoPurpose.ENCRYPTION, AlgorithmStatus.APPROVED, 256, True, 256),
    Algorithm("aes-128-gcm", CryptoPurpose.ENCRYPTION, AlgorithmStatus.APPROVED, 128, False, 128),
    Algorithm("3des", CryptoPurpose.ENCRYPTION, AlgorithmStatus.FORBIDDEN, 112, False, 112),
    Algorithm("sha256", CryptoPurpose.HASH, AlgorithmStatus.APPROVED, 0, True, 128),
    Algorithm("sha1", CryptoPurpose.HASH, AlgorithmStatus.FORBIDDEN, 0, False, 80),
    Algorithm("md5", CryptoPurpose.HASH, AlgorithmStatus.FORBIDDEN, 0, False, 0),
)


@dataclass
class AlgorithmPolicy:
    """Classifies algorithm usage against the allow-list. Unknown == fail closed."""

    algorithms: dict[str, Algorithm] = field(default_factory=dict)

    @classmethod
    def default(cls) -> AlgorithmPolicy:
        return cls(algorithms={a.name: a for a in DEFAULT_ALGORITHMS})

    def classify(self, name: str) -> AlgorithmStatus | None:
        """Return the algorithm's status, or None if it is unknown (not on the allow-list)."""
        algo = self.algorithms.get(name.lower())
        return algo.status if algo else None

    def get(self, name: str) -> Algorithm | None:
        return self.algorithms.get(name.lower())

    def is_known(self, name: str) -> bool:
        return name.lower() in self.algorithms


__all__ = [
    "AlgorithmStatus", "CryptoPurpose", "Algorithm", "DEFAULT_ALGORITHMS", "AlgorithmPolicy",
]
