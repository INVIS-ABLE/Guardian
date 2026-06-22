"""Admission verification (Phase 4 / blueprint areas 8, 9).

Before an image may run / a release may deploy, it must be:
  - **pinned by digest** (sha256), never a movable tag;
  - **signed** by an allowed identity (cosign cert identity / OIDC subject);
  - accompanied by valid **provenance** whose subject digest matches the image;
  - accompanied by an **SBOM**;
  - **not expired**.

Verification **fails closed**: if signature/provenance/SBOM material is missing, the artifact
is refused. This models cosign + sigstore/policy-controller (admission) + in-toto/witness.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from time import time

from attestation.signing import Signer, default_signer

from .provenance import SignedProvenance, verify_provenance

_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")


@dataclass
class AdmissionPolicy:
    require_digest: bool = True
    require_signature: bool = True
    require_provenance: bool = True
    require_sbom: bool = True
    allowed_identities: set[str] = field(default_factory=set)  # OIDC subjects / cosign ids
    fail_closed: bool = True


@dataclass
class ArtifactBundle:
    image_ref: str  # e.g. "registry.invisable/app@sha256:<64hex>"
    signed_provenance: SignedProvenance | None = None
    sbom: dict | None = None
    expires_at: float | None = None


@dataclass
class AdmissionDecision:
    allow: bool
    reasons: list[str] = field(default_factory=list)

    def reason(self) -> str:
        return "; ".join(self.reasons) if self.reasons else "admitted"


def _image_digest(image_ref: str) -> str | None:
    m = _DIGEST_RE.search(image_ref)
    return image_ref.split("@", 1)[1] if m else None


def verify_artifact(
    bundle: ArtifactBundle,
    policy: AdmissionPolicy,
    signer: Signer | None = None,
    *,
    now: float | None = None,
) -> AdmissionDecision:
    """Return an admission decision. Default deny; fail closed on missing material."""
    now = time() if now is None else now
    s = signer or default_signer()
    reasons: list[str] = []

    digest = _image_digest(bundle.image_ref)
    if policy.require_digest and digest is None:
        reasons.append("image is not pinned by sha256 digest (movable tag refused)")

    if policy.require_signature or policy.require_provenance:
        if bundle.signed_provenance is None:
            if policy.fail_closed:
                reasons.append("no signed provenance present (fail closed)")
        else:
            sp = bundle.signed_provenance
            if not verify_provenance(sp, s):
                reasons.append("provenance signature is invalid")
            if policy.allowed_identities and sp.identity not in policy.allowed_identities:
                reasons.append(f"signer identity '{sp.identity}' is not allowed")
            # Provenance must attest THIS artifact.
            subj = sp.statement.get("subject_digest")
            if digest is not None and subj != digest:
                reasons.append("provenance subject digest does not match the image")

    if policy.require_sbom and not bundle.sbom:
        reasons.append("no SBOM present")

    if bundle.expires_at is not None and now >= bundle.expires_at:
        reasons.append("artifact attestation has expired")

    return AdmissionDecision(allow=not reasons, reasons=reasons)
