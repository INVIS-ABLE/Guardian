"""Guardian supply-chain trust & verification (Phase 4 / blueprint areas 8, 9, 17).

Admission verification (digest-pinned + signed + provenance + SBOM, fail closed), build
provenance signing, and risk-based vulnerability prioritisation (KEV/EPSS/exposure/reachability
+ OpenVEX exploitability). Harbor, Dependency-Track, cosign, sigstore/policy-controller, and
in-toto/witness are the deployment systems; these are the in-process decisions.
"""

from __future__ import annotations

from .admission import (
    AdmissionDecision,
    AdmissionPolicy,
    ArtifactBundle,
    verify_artifact,
)
from .provenance import (
    Provenance,
    SignedProvenance,
    sign_provenance,
    verify_provenance,
)
from .sbom import (
    Prioritisation,
    RiskContext,
    VexStatement,
    VexStatus,
    Vulnerability,
    is_exploitable,
    prioritise,
)

__all__ = [
    "AdmissionPolicy",
    "ArtifactBundle",
    "AdmissionDecision",
    "verify_artifact",
    "Provenance",
    "SignedProvenance",
    "sign_provenance",
    "verify_provenance",
    "Vulnerability",
    "VexStatement",
    "VexStatus",
    "RiskContext",
    "Prioritisation",
    "is_exploitable",
    "prioritise",
]
