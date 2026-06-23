"""Platform enrolment — binding a platform to approved inventory.

Enrolment is a deliberate act with preconditions: a genuine AK public key and a non-empty golden
PCR baseline (you cannot attest against nothing). Enrolling a new attestation root is a quorum
operation (configs/citadel/quorum.yaml: attestation_root_rotation >= 3) — this function performs
the *binding*; it does not itself grant that authority. No model can enrol a platform (invariant 5).
"""

from __future__ import annotations

from .inventory import PlatformInventory
from .schemas import PlatformIdentity, PlatformStatus


class EnrolmentError(ValueError):
    """Raised when a platform cannot be enrolled (missing key or golden baseline)."""


def enrol_platform(
    inventory: PlatformInventory,
    *,
    node_id: str,
    ak_public_key: str,
    golden_pcrs: dict[str, str],
    approved_firmware: frozenset[str] | set[str] = frozenset(),
    approved_kernels: frozenset[str] | set[str] = frozenset(),
    enrolled_at: float,
    attestation_max_age_seconds: int = 900,
) -> PlatformIdentity:
    """Enrol a platform into the approved inventory. Fail closed on incomplete identity."""
    if not ak_public_key:
        raise EnrolmentError(f"{node_id}: cannot enrol without an AK public key")
    if not golden_pcrs:
        raise EnrolmentError(f"{node_id}: cannot enrol without a golden PCR baseline")
    if attestation_max_age_seconds <= 0:
        raise EnrolmentError(f"{node_id}: attestation_max_age_seconds must be positive")

    identity = PlatformIdentity(
        node_id=node_id,
        ak_public_key=ak_public_key,
        golden_pcrs=dict(golden_pcrs),
        approved_firmware=frozenset(approved_firmware),
        approved_kernels=frozenset(approved_kernels),
        enrolled_at=enrolled_at,
        status=PlatformStatus.ENROLLED,
        attestation_max_age_seconds=attestation_max_age_seconds,
    )
    inventory.add(identity)
    return identity


__all__ = ["EnrolmentError", "enrol_platform"]
