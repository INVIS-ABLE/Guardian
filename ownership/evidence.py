"""Ownership evidence with expiry (blueprint area 2).

Owning an asset is not a permanent fact you assert once — it is evidence you must be able to
re-prove. Each successful proof produces an :class:`OwnershipEvidence` record that *expires*, so
stale proof is never trusted indefinitely. Two proof methods are modelled:

  - DNS-TXT  — the owner publishes a ``guardian-verification=<token>`` TXT record on the domain.
  - GitHub-App — the Guardian App installation reports the repo's owning login.

The evidence object is deliberately small and serialisable; the live re-proving lives in
:mod:`ownership.verifier`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ProofMethod(str, Enum):
    DNS_TXT = "dns_txt"
    GITHUB_APP = "github_app"


@dataclass
class OwnershipEvidence:
    kind: str  # "domain" | "repo"
    target: str
    method: ProofMethod
    proof: str  # the token matched / owning login observed
    verified_at: float  # epoch seconds the proof was last confirmed
    expires_at: float | None  # epoch seconds; None = never (discouraged)

    def fresh(self, now: float) -> bool:
        """True only while the evidence is still within its validity window."""
        return self.expires_at is not None and now < self.expires_at
