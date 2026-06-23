"""Release promotion gate (Citadel Systems 28 + 29).

A release candidate is promotable only when its full provenance chain is present AND it has a
verifiable inclusion proof in the transparency log (Wave-20 invariants 9, 10, 28, 29):

    source identity + lockfile + hermetic build + independent rebuild + matching digest
    + SBOM + provenance + signature + transparency inclusion

A signature alone is insufficient; a non-reproducible critical build cannot promote; a missing
inclusion proof denies promotion. Fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass

from .transparency import InclusionProof, verify_inclusion


@dataclass(frozen=True)
class ReleaseCandidate:
    artefact_id: str
    source_identity: bool
    lockfile: bool
    hermetic_build: bool
    independent_rebuild_matches: bool   # independent rebuild produced the same digest
    sbom: bool
    provenance: bool
    signature: bool


@dataclass(frozen=True)
class PromotionDecision:
    promotable: bool
    artefact_id: str
    reasons: tuple[str, ...]


_REQUIRED = {
    "source_identity": "source_identity",
    "lockfile": "lockfile",
    "hermetic_build": "hermetic_build_definition",
    "independent_rebuild_matches": "independent_rebuild_matching_digest",
    "sbom": "sbom",
    "provenance": "provenance",
    "signature": "signature",
}


def evaluate_promotion(
    candidate: ReleaseCandidate, inclusion: InclusionProof | None, log_root: str | None
) -> PromotionDecision:
    reasons: list[str] = []
    for attr, label in _REQUIRED.items():
        if not getattr(candidate, attr):
            reasons.append(f"missing_{label}")

    # Transparency inclusion proof is mandatory and must verify against the log root.
    if inclusion is None or log_root is None:
        reasons.append("missing_transparency_inclusion_proof")
    elif not verify_inclusion(inclusion, log_root):
        reasons.append("invalid_transparency_inclusion_proof")

    return PromotionDecision(promotable=not reasons, artefact_id=candidate.artefact_id,
                             reasons=tuple(reasons))


__all__ = ["ReleaseCandidate", "PromotionDecision", "evaluate_promotion"]
