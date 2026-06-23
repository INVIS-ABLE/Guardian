"""Typed contracts for the Root-of-Trust Fabric (Citadel System 21, Wave 21).

These are public, non-secret records (no private keys, no plaintext). They model a platform's
enrolled identity, its boot/runtime measurements, and the attestation verdict that gates whether
the platform may receive a production capability. Frozen dataclasses, matching the house style of
``core.machine_attestation`` (this is the same domain — the machine root).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum


class PlatformStatus(str, Enum):
    """Lifecycle of an enrolled platform. A platform is untrusted unless ENROLLED."""

    ENROLLED = "enrolled"
    QUARANTINED = "quarantined"   # drift detected; denied until re-attested + cleared
    REVOKED = "revoked"           # permanently removed from approved inventory


@dataclass(frozen=True)
class PlatformIdentity:
    """A platform bound to approved inventory: its AK key + golden measurements + allow-lists."""

    node_id: str
    ak_public_key: str                                  # hex; enrolled out of band
    golden_pcrs: dict[str, str]                          # PCR index -> approved sha256 digest
    approved_firmware: frozenset[str] = frozenset()
    approved_kernels: frozenset[str] = frozenset()
    enrolled_at: float = 0.0
    status: PlatformStatus = PlatformStatus.ENROLLED
    attestation_max_age_seconds: int = 900               # 15 min default (configs/citadel/root-of-trust.yaml)

    @property
    def active(self) -> bool:
        return self.status is PlatformStatus.ENROLLED


@dataclass(frozen=True)
class BootMeasurement:
    """Measured-boot / Secure Boot state collected from a platform (TPM PCRs + firmware/kernel)."""

    node_id: str
    pcrs: dict[str, str]
    firmware: str
    kernel: str
    secure_boot: bool = False


@dataclass(frozen=True)
class RuntimeMeasurement:
    """Linux IMA/EVM runtime-integrity state."""

    node_id: str
    ima_ok: bool = False
    ima_log_hash: str = ""


@dataclass(frozen=True)
class AttestationPolicy:
    """How fresh + complete an attestation must be to gate a production capability."""

    max_age_seconds: int = 900
    require_secure_boot: bool = True
    require_ima: bool = True


@dataclass(frozen=True)
class PlatformAttestation:
    """The attestation verdict for one platform at one moment. Attaches to execution as evidence."""

    node_id: str
    ok: bool
    reasons: tuple[str, ...]
    attested_at: float
    expires_at: float

    def is_expired(self, now: float) -> bool:
        return now >= self.expires_at

    def canonical(self) -> bytes:
        return json.dumps(
            {
                "node_id": self.node_id, "ok": self.ok, "reasons": list(self.reasons),
                "attested_at": self.attested_at, "expires_at": self.expires_at,
            },
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")

    @property
    def evidence_digest(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()


@dataclass(frozen=True)
class AttestationResult:
    """The gate decision: may this platform receive a production capability right now?"""

    allow: bool
    node_id: str
    reasons: tuple[str, ...]
    attestation: PlatformAttestation


@dataclass(frozen=True)
class DriftEvent:
    """A durable record that a platform's measurements drifted from its golden baseline."""

    event_type: str            # guardian.boot.* / guardian.attestation.* / guardian.integrity.*
    node_id: str
    reasons: tuple[str, ...]
    at: float
    detail: str = ""

    def canonical(self) -> bytes:
        return json.dumps(
            {"event_type": self.event_type, "node_id": self.node_id,
             "reasons": list(self.reasons), "at": self.at, "detail": self.detail},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")


@dataclass(frozen=True)
class PlatformCase:
    """A case opened when a platform fails attestation / drifts — for human follow-up."""

    case_id: str
    node_id: str
    title: str
    reasons: tuple[str, ...]
    opened_at: float
    severity: str = "high"


__all__ = [
    "PlatformStatus", "PlatformIdentity", "BootMeasurement", "RuntimeMeasurement",
    "AttestationPolicy", "PlatformAttestation", "AttestationResult", "DriftEvent", "PlatformCase",
]
