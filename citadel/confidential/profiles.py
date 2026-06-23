"""Confidential-worker profiles (Citadel System 22, Wave 22).

Each worker class maps to the strict sandbox posture owned by ``isolation.sandbox`` (reused, not
duplicated) PLUS the confidential-compute requirements: remote attestation, a measured + signed
workload image, attestation-bound secret release, ephemeral identity/storage, and evidence
generated outside the worker's sole control. Ordinary sandbox classes do NOT require attestation;
confidential classes do. Mirrors configs/citadel/confidential-compute.yaml.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from isolation.sandbox import SandboxProfile


class WorkerClass(str, Enum):
    STANDARD_SANDBOX = "standard_sandbox"
    HIGH_ISOLATION_SANDBOX = "high_isolation_sandbox"
    CONFIDENTIAL_WORKER = "confidential_worker"
    FORENSIC_CONFIDENTIAL_WORKER = "forensic_confidential_worker"
    RECOVERY_CONFIDENTIAL_WORKER = "recovery_confidential_worker"
    SHADOW_VERIFICATION_WORKER = "shadow_verification_worker"


_CONFIDENTIAL_CLASSES = frozenset(
    {
        WorkerClass.CONFIDENTIAL_WORKER,
        WorkerClass.FORENSIC_CONFIDENTIAL_WORKER,
        WorkerClass.RECOVERY_CONFIDENTIAL_WORKER,
        WorkerClass.SHADOW_VERIFICATION_WORKER,
    }
)


@dataclass(frozen=True)
class ConfidentialProfile:
    """The full posture a worker class must satisfy before it may run / receive secrets."""

    worker_class: WorkerClass
    sandbox: SandboxProfile
    requires_attestation: bool
    encrypted_memory: bool
    signed_image: bool
    measured_workload: bool
    ephemeral_identity: bool
    ephemeral_storage: bool
    evidence_outside_worker: bool

    @property
    def is_confidential(self) -> bool:
        return self.worker_class in _CONFIDENTIAL_CLASSES


def profile_for(worker_class: WorkerClass) -> ConfidentialProfile:
    """Return the required profile for a worker class. Confidential classes demand attestation +
    measured/signed image + ephemerality + externally-committed evidence; sandbox classes do not."""
    confidential = worker_class in _CONFIDENTIAL_CLASSES
    high_isolation = confidential or worker_class is WorkerClass.HIGH_ISOLATION_SANDBOX
    return ConfidentialProfile(
        worker_class=worker_class,
        sandbox=SandboxProfile(require_gvisor=high_isolation),
        requires_attestation=confidential,
        encrypted_memory=confidential,
        signed_image=True,                       # every worker image is signed
        measured_workload=confidential,
        ephemeral_identity=confidential,
        ephemeral_storage=confidential,
        evidence_outside_worker=confidential,
    )


__all__ = ["WorkerClass", "ConfidentialProfile", "profile_for"]
