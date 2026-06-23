"""Key ceremonies + key classes (Citadel System 24).

A key ceremony performs a high-value key operation (rotation, recovery, CA issuance) under quorum,
and produces signed ceremony evidence. Key classes mirror configs/citadel/quorum.yaml: recovery and
attestation roots are deliberately separated from release/evidence signing.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum

from .proposals import Proposal
from .threshold import ThresholdDecision


class KeyClass(str, Enum):
    ROOT_SIGNING = "root_signing"
    RELEASE_SIGNING = "release_signing"
    ATTESTATION_ROOT = "attestation_root"
    EVIDENCE_SIGNING = "evidence_signing"
    RECOVERY_ROOT = "recovery_root"
    CERTIFICATE_AUTHORITY = "certificate_authority"
    BACKUP_ENCRYPTION = "backup_encryption"
    TRANSPARENCY_LOG = "transparency_log"
    SERVICE_IDENTITY = "service_identity"
    USER_EXPORT = "user_export"


@dataclass(frozen=True)
class KeyCeremony:
    """Immutable, verifiable record of a quorum-approved key operation."""

    ceremony_id: str
    key_class: KeyClass
    proposal: Proposal
    decision: ThresholdDecision
    participant_ids: tuple[str, ...]
    performed_at: float

    @property
    def ok(self) -> bool:
        return self.decision.satisfied

    def canonical(self) -> bytes:
        return json.dumps(
            {
                "ceremony_id": self.ceremony_id, "key_class": self.key_class.value,
                "operation": self.proposal.operation.value,
                "target_digest": self.proposal.target_digest,
                "policy_digest": self.proposal.policy_digest,
                "participant_ids": sorted(self.participant_ids),
                "threshold": self.decision.threshold,
                "distinct_approvers": self.decision.distinct_approvers,
                "satisfied": self.decision.satisfied, "performed_at": self.performed_at,
            },
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")

    @property
    def evidence_digest(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()


__all__ = ["KeyClass", "KeyCeremony"]
