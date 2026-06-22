"""Build provenance (Phase 4 / blueprint area 9).

A minimal, SLSA-style provenance statement binding an artifact (by digest) to the source repo,
commit, builder, and materials. Signed/verified with the attestation signer (Ed25519/HMAC);
in deployment, cosign signs and in-toto/witness attest each pipeline stage.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from attestation.signing import Signer, default_signer


@dataclass
class Provenance:
    """SLSA-ish provenance: what was built, from where, by whom, with which inputs."""

    subject_digest: str  # sha256:... of the artifact this attests
    source_repo: str
    commit: str
    builder_id: str
    build_workflow: str
    materials: list[str] = field(default_factory=list)  # input digests/refs
    built_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SignedProvenance:
    statement: dict[str, Any]
    signature: str
    algorithm: str
    identity: str  # signer identity (issuer/subject), e.g. the OIDC workflow identity


def sign_provenance(prov: Provenance, identity: str, signer: Signer | None = None) -> SignedProvenance:
    s = signer or default_signer()
    statement = prov.to_dict()
    return SignedProvenance(
        statement=statement,
        signature=s.sign(statement),
        algorithm=s.algorithm,
        identity=identity,
    )


def verify_provenance(signed: SignedProvenance, signer: Signer | None = None) -> bool:
    s = signer or default_signer()
    return s.verify(signed.statement, signed.signature)
