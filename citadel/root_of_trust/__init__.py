"""Citadel System 21 — Root-of-Trust Fabric (Wave 21).

Hardware-rooted platform identity, measured/secure boot + IMA/EVM collection, remote attestation,
inventory, enrolment, revocation, and an independent verifier that gates capability issuance.

Owner of the authoritative attestation check: ``core.machine_attestation`` (reused, not duplicated).
This package is the fabric + the independent verifier around it (docs/citadel_plane.md).
"""

from __future__ import annotations

from core.machine_attestation import AttestationReport
from core.roots_of_trust import MachineTrust

from .enrolment import EnrolmentError, enrol_platform
from .integrity_view import platform_integrity_summary
from .inventory import PlatformInventory
from .keylime import KeylimeClient, StaticKeylimeClient
from .revocation import clear_quarantine, quarantine, revoke
from .schemas import (
    AttestationPolicy,
    AttestationResult,
    BootMeasurement,
    DriftEvent,
    PlatformAttestation,
    PlatformCase,
    PlatformIdentity,
    PlatformStatus,
    RuntimeMeasurement,
)
from .tpm import SoftwareTpm, build_report
from .verifier import RootOfTrustVerifier


def attest_via_keylime(
    verifier: RootOfTrustVerifier, client: KeylimeClient, node_id: str, *, now: float
) -> PlatformAttestation:
    """End-to-end: issue a nonce, fetch a fresh nonce-bound quote from Keylime, and verify it."""
    nonce = verifier.issue_nonce(node_id)
    report, signature = client.get_quote(node_id, nonce)
    return verifier.attest(report, signature, now=now)


__all__ = [
    "AttestationPolicy", "AttestationReport", "AttestationResult", "BootMeasurement", "DriftEvent",
    "EnrolmentError", "KeylimeClient", "MachineTrust", "PlatformAttestation", "PlatformCase",
    "PlatformIdentity", "PlatformInventory", "PlatformStatus", "RootOfTrustVerifier",
    "RuntimeMeasurement", "SoftwareTpm", "StaticKeylimeClient", "attest_via_keylime",
    "build_report", "clear_quarantine", "enrol_platform", "platform_integrity_summary",
    "quarantine", "revoke",
]
