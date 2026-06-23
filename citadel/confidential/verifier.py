"""Confidential-execution verifier (independent verifier for Citadel System 22).

The authoritative owner of worker isolation is ``isolation.sandbox``. This is the independent
verifier that ties the confidential-execution invariants together:

  * attestation-bound secret release — a secret is released only against a passing workload
    attestation whose measurement matches what the secret was sealed to,
  * worker evidence is committed OUTSIDE the worker's sole control (an independent sink),
  * worker destruction is verified — a confidential worker must not outlive its job (ephemeral).

It does not grant authority; it proves the worker ran where, as, and only as long as it should.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass

from .attestation import WorkloadAttestation
from .confidential_containers import ConfidentialRuntime, DestructionReceipt
from .profiles import WorkerClass
from .secret_release import SecretBroker, SecretReleaseResult


@dataclass(frozen=True)
class WorkerEvidence:
    """Immutable evidence that a confidential worker attested, what it measured, and the outcome."""

    worker_id: str
    worker_class: WorkerClass
    measurement: str
    attestation_ok: bool
    secret_released: bool
    committed_at: float

    def canonical(self) -> bytes:
        return json.dumps(
            {
                "worker_id": self.worker_id, "worker_class": self.worker_class.value,
                "measurement": self.measurement, "attestation_ok": self.attestation_ok,
                "secret_released": self.secret_released, "committed_at": self.committed_at,
            },
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")

    @property
    def evidence_digest(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()


@dataclass
class ConfidentialVerifier:
    """Independent verifier + orchestrator for confidential-worker secret release and teardown."""

    broker: SecretBroker
    evidence_sink: Callable[[WorkerEvidence], None]   # independent committer (NOT the worker)

    def release_secret(
        self, secret_id: str, attestation: WorkloadAttestation, *, at: float
    ) -> SecretReleaseResult:
        """Evaluate secret release and independently commit worker evidence either way.

        Evidence is committed by the verifier (outside the worker's control) regardless of outcome,
        so a denied release is just as auditable as a granted one.
        """
        result = self.broker.evaluate(secret_id, attestation)
        self.commit_evidence(attestation, secret_released=result.allowed, at=at)
        return result

    def commit_evidence(
        self, attestation: WorkloadAttestation, *, secret_released: bool, at: float
    ) -> WorkerEvidence:
        evidence = WorkerEvidence(
            worker_id=attestation.worker_id, worker_class=attestation.worker_class,
            measurement=attestation.measurement, attestation_ok=attestation.ok,
            secret_released=secret_released, committed_at=at,
        )
        self.evidence_sink(evidence)   # committed outside the worker's sole control
        return evidence

    @staticmethod
    def verify_destroyed(runtime: ConfidentialRuntime, receipt: DestructionReceipt) -> bool:
        """A confidential worker must not outlive its job: the receipt is complete AND the runtime
        no longer reports the worker as live (ephemeral identity + storage are gone)."""
        return receipt.complete and not runtime.is_live(receipt.worker_id)


__all__ = ["WorkerEvidence", "ConfidentialVerifier"]
