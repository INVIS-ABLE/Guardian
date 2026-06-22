"""Guardian attestation & evidence-of-record (Phase 2 / blueprint areas 5, 9).

Signed, hash-chained evidence stored in a system of record separate from the local cache, so
deleting local logs cannot destroy the authoritative evidence. Ed25519 by default (HMAC
fallback); cosign/witness perform artifact + pipeline attestation in deployment.
"""

from __future__ import annotations

from .evidence_store import (
    Attestation,
    EvidenceStore,
    ImmudbEvidenceStore,
    InMemoryEvidenceStore,
    SystemOfRecord,
)
from .signing import Ed25519Signer, HmacSigner, Signer, default_signer, ed25519_available

__all__ = [
    "Attestation",
    "EvidenceStore",
    "InMemoryEvidenceStore",
    "ImmudbEvidenceStore",
    "SystemOfRecord",
    "Signer",
    "Ed25519Signer",
    "HmacSigner",
    "default_signer",
    "ed25519_available",
]
