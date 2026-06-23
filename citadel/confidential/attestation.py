"""Workload attestation for confidential workers (Citadel System 22).

Builds on the platform attestation from Wave 21 (``citadel.root_of_trust``): a confidential worker
is trustworthy only when BOTH the platform is attested AND the exact workload (signed image +
profile + config) measures to the value bound to the secrets it will receive. This module computes
the canonical workload measurement and the combined attestation verdict.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from citadel.root_of_trust import PlatformAttestation

from .profiles import ConfidentialProfile, WorkerClass


def workload_measurement(image_digest: str, worker_class: WorkerClass, config_digest: str = "") -> str:
    """Canonical, content-addressable measurement of a workload (what the secret is sealed to)."""
    canonical = json.dumps(
        {"image_digest": image_digest, "worker_class": worker_class.value, "config_digest": config_digest},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True)
class WorkloadAttestation:
    """The combined platform + workload attestation verdict for one confidential worker."""

    worker_id: str
    worker_class: WorkerClass
    measurement: str
    ok: bool
    reasons: tuple[str, ...]


def attest_workload(
    *,
    worker_id: str,
    profile: ConfidentialProfile,
    platform: PlatformAttestation,
    image_digest: str,
    image_signed: bool,
    config_digest: str = "",
) -> WorkloadAttestation:
    """Verify a confidential worker: platform attested + image signed + measured workload computed.

    Fail closed: a failed platform attestation, an unsigned image, or a profile that demands
    attestation it cannot show, all deny.
    """
    measurement = workload_measurement(image_digest, profile.worker_class, config_digest)
    reasons: list[str] = []

    if profile.requires_attestation and not platform.ok:
        reasons.append("platform_attestation_failed")
    if profile.signed_image and not image_signed:
        reasons.append("image_not_signed")
    if profile.measured_workload and not measurement:
        reasons.append("workload_not_measured")

    return WorkloadAttestation(
        worker_id=worker_id, worker_class=profile.worker_class, measurement=measurement,
        ok=not reasons, reasons=tuple(reasons),
    )


__all__ = ["workload_measurement", "WorkloadAttestation", "attest_workload"]
