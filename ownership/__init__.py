"""Guardian ownership verification — live, expiring, fail-closed proof (blueprint area 2).

Provides an :class:`OwnershipVerifier` that drops into ``Guardrails.ownership_verifier`` and
re-proves domain/repo ownership against injected DNS / GitHub resolvers. Scope-file membership
is intent; this is proof — and proof expires.
"""

from __future__ import annotations

from .evidence import OwnershipEvidence, ProofMethod
from .verifier import (
    DNS_PREFIX,
    DnsResolver,
    GithubResolver,
    OwnershipVerifier,
    dns_challenge_record,
)

__all__ = [
    "OwnershipEvidence",
    "ProofMethod",
    "OwnershipVerifier",
    "DnsResolver",
    "GithubResolver",
    "DNS_PREFIX",
    "dns_challenge_record",
]
