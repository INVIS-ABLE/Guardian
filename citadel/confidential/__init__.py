"""Citadel System 22 — Confidential Execution Fabric (Wave 22).

Confidential-worker profiles, remote (platform+workload) attestation, attestation-bound secret
release, the Confidential Containers / Kata runtime (+ Gramine/Enarx specialist adapters), worker
evidence, and worker-destruction verification.

Owner of worker isolation: ``isolation.sandbox`` (reused, not duplicated). This package is the
confidential-compute fabric + the independent verifier around it (docs/citadel_plane.md). It builds
on Wave 21 (``citadel.root_of_trust``) for the platform attestation it binds workloads to.
"""

from __future__ import annotations

from .attestation import WorkloadAttestation, attest_workload, workload_measurement
from .confidential_containers import (
    ConfidentialRuntime,
    DestructionReceipt,
    KataConfidentialContainers,
    WorkerHandle,
)
from .enarx import EnarxKeep
from .gramine import GramineEnclave
from .profiles import ConfidentialProfile, WorkerClass, profile_for
from .secret_release import (
    SealedSecret,
    SecretBroker,
    SecretReleaseDenied,
    SecretReleaseResult,
)
from .verifier import ConfidentialVerifier, WorkerEvidence

__all__ = [
    "ConfidentialProfile", "ConfidentialRuntime", "ConfidentialVerifier", "DestructionReceipt",
    "EnarxKeep", "GramineEnclave", "KataConfidentialContainers", "SealedSecret", "SecretBroker",
    "SecretReleaseDenied", "SecretReleaseResult", "WorkerClass", "WorkerEvidence", "WorkerHandle",
    "WorkloadAttestation", "attest_workload", "profile_for", "workload_measurement",
]
