"""Root-operation proposals + their required thresholds (Citadel Systems 24 + 38).

The thresholds mirror configs/citadel/quorum.yaml. Each operation names what is being changed
(target_digest) under which policy (policy_digest); a proposal is satisfied only when enough
DISTINCT participants approve before it expires.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RootOperation(str, Enum):
    ROOT_KEY_ROTATION = "root_key_rotation"
    ATTESTATION_ROOT_ROTATION = "attestation_root_rotation"
    RECOVERY_ACTIVATION = "recovery_activation"
    EVIDENCE_ROOT_MIGRATION = "evidence_root_migration"
    TRANSPARENCY_LOG_MIGRATION = "transparency_log_migration"
    EMERGENCY_POLICY_REPLACEMENT = "emergency_policy_replacement"
    GUARDIAN_WIDE_FREEZE = "guardian_wide_freeze"
    RE_ENROLMENT_AFTER_COMPROMISE = "re_enrolment_after_catastrophic_compromise"


# configs/citadel/quorum.yaml — minimum distinct participants per operation.
REQUIRED_THRESHOLD: dict[RootOperation, int] = {
    RootOperation.ROOT_KEY_ROTATION: 3,
    RootOperation.ATTESTATION_ROOT_ROTATION: 3,
    RootOperation.RECOVERY_ACTIVATION: 3,
    RootOperation.EVIDENCE_ROOT_MIGRATION: 3,
    RootOperation.TRANSPARENCY_LOG_MIGRATION: 3,
    RootOperation.EMERGENCY_POLICY_REPLACEMENT: 4,
    RootOperation.GUARDIAN_WIDE_FREEZE: 2,
    RootOperation.RE_ENROLMENT_AFTER_COMPROMISE: 4,
}

# Operations that may only be activated with offline recovery custodians in the quorum.
_RECOVERY_OPERATIONS = frozenset(
    {RootOperation.RECOVERY_ACTIVATION, RootOperation.RE_ENROLMENT_AFTER_COMPROMISE}
)


@dataclass(frozen=True)
class Proposal:
    proposal_id: str
    operation: RootOperation
    target_digest: str
    policy_digest: str
    created_at: float
    expires_at: float

    @property
    def threshold(self) -> int:
        return REQUIRED_THRESHOLD[self.operation]

    @property
    def requires_recovery_custodian(self) -> bool:
        return self.operation in _RECOVERY_OPERATIONS

    def is_expired(self, now: float) -> bool:
        return now >= self.expires_at

    def canonical(self) -> bytes:
        import json
        return json.dumps(
            {"proposal_id": self.proposal_id, "operation": self.operation.value,
             "target_digest": self.target_digest, "policy_digest": self.policy_digest},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")


__all__ = ["RootOperation", "REQUIRED_THRESHOLD", "Proposal"]
