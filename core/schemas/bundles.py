"""Evidence bundle schema (Final Power-Up §23).

An ``EvidenceBundle`` is the signable unit of chain-of-custody: a set of evidence
artifact ids reduced to a single ``merkle_root`` so the whole bundle can be signed and
attested once, and later verified without re-reading every artifact.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = 1


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def merkle_root(evidence_sha256: list[str]) -> str:
    """Deterministic root over a list of ``sha256:`` evidence hashes (sorted, paired)."""
    layer = sorted(evidence_sha256)
    if not layer:
        return "sha256:" + hashlib.sha256(b"").hexdigest()
    while len(layer) > 1:
        nxt: list[str] = []
        for i in range(0, len(layer), 2):
            pair = layer[i] + (layer[i + 1] if i + 1 < len(layer) else layer[i])
            nxt.append("sha256:" + hashlib.sha256(pair.encode("utf-8")).hexdigest())
        layer = nxt
    return layer[0]


class EvidenceBundle(BaseModel):
    """A signable, verifiable collection of evidence artifacts (master map §23)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    bundle_id: UUID = Field(default_factory=uuid4)
    case_id: UUID
    evidence_ids: tuple[str, ...] = ()
    evidence_sha256: tuple[str, ...] = ()
    merkle_root: str = ""
    classification: str = "internal"
    created_at: datetime = Field(default_factory=_utcnow)
    signature: str | None = None
    attestation_uri: str | None = None

    @classmethod
    def create(
        cls,
        *,
        case_id: UUID,
        evidence_ids: tuple[str, ...],
        evidence_sha256: tuple[str, ...],
        classification: str = "internal",
    ) -> EvidenceBundle:
        """Build a bundle with its ``merkle_root`` computed from the artifact hashes."""
        return cls(
            case_id=case_id,
            evidence_ids=evidence_ids,
            evidence_sha256=evidence_sha256,
            merkle_root=merkle_root(list(evidence_sha256)),
            classification=classification,
        )

    def root_intact(self) -> bool:
        """True when the recorded root matches a fresh root over the artifact hashes."""
        return self.merkle_root == merkle_root(list(self.evidence_sha256))

    def signed(self, signature: str, *, attestation_uri: str | None = None) -> EvidenceBundle:
        """Return a copy carrying a signature (and optional attestation), root unchanged."""
        return self.model_copy(update={"signature": signature, "attestation_uri": attestation_uri})


__all__ = ["EvidenceBundle", "merkle_root", "SCHEMA_VERSION"]
