"""Citadel Systems 28 + 29 — Reproducible Build Foundry + Transparency Fabric (Wave 29).

Append-only Merkle transparency log with inclusion + consistency proofs, and a promotion gate that
requires the full provenance chain plus a verifiable inclusion proof. Owner of build provenance:
``supplychain/provenance.py`` (reused); transparency + promotion are the new fabric here.
"""

from __future__ import annotations

from .promotion import PromotionDecision, ReleaseCandidate, evaluate_promotion
from .transparency import (
    Checkpoint,
    InclusionProof,
    TransparencyLog,
    consistent,
    verify_inclusion,
)

__all__ = [
    "PromotionDecision", "ReleaseCandidate", "evaluate_promotion",
    "Checkpoint", "InclusionProof", "TransparencyLog", "consistent", "verify_inclusion",
]
