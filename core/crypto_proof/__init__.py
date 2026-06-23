"""Guardian cryptographic protocol proof lab (Sovereign plane, Wave 3, system #15).

Symbolic verification of the protocols that protect INVISABLE — device enrolment, key agreement,
group membership, forward secrecy, account recovery — surfacing any flow whose security property
an active attacker can break (docs/sovereign_ops_plane.md; upstream: Tamarin / Verifpal / ProVerif).

The cardinal rule: it reviews the crypto **system**, never plaintext or key material. The models
refuse any artefact that names real content/keys, so proof traces are symbolic by construction.
"""

from __future__ import annotations

from .ingest import (
    build_from_spec,
    from_provers,
    load_proofs,
    production_source_required,
)
from .lab import CryptoProofError, CryptoProofLab
from .models import (
    ProofReport,
    ProofResult,
    ProofStatus,
    PropertyKind,
    Protocol,
    SecurityProperty,
)

__all__ = [
    "CryptoProofLab",
    "CryptoProofError",
    "PropertyKind",
    "ProofStatus",
    "Protocol",
    "SecurityProperty",
    "ProofResult",
    "ProofReport",
    "build_from_spec",
    "load_proofs",
    "from_provers",
    "production_source_required",
]
