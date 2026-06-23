"""The crypto-proof lab engine (Sovereign plane, Wave 3, system #15).

``CryptoProofLab`` assembles a :class:`ProofReport` from the symbolic prover's results and
adjudicates them: it surfaces every **break** (a falsified *critical* property — a real attack on
the protocol), separates merely-``unknown`` results (the prover did not conclude) from genuine
failures, and gates on any break.

It proves nothing itself — it adjudicates a prover's output — and asserts no authority. The
models already refuse any artefact that smells of real content/keys, so the lab is structurally
about the crypto *system*, never secrets.
"""

from __future__ import annotations

from typing import Iterable

from .models import ProofReport, ProofResult, Protocol


class CryptoProofError(ValueError):
    """Raised on structural errors (result references an unknown protocol, duplicate protocol)."""


class CryptoProofLab:
    """Adjudicates symbolic proof results over the registered protocols."""

    def __init__(self, protocols: Iterable[Protocol]) -> None:
        self._protocols: dict[str, Protocol] = {}
        for p in protocols:
            if p.id in self._protocols:
                raise CryptoProofError(f"duplicate protocol: {p.id}")
            self._protocols[p.id] = p

    def report(self, results: Iterable[ProofResult]) -> ProofReport:
        """Validate that results reference known protocols and assemble the adjudicated report."""
        materialised = tuple(results)
        for r in materialised:
            if r.protocol_id not in self._protocols:
                raise CryptoProofError(f"result references unknown protocol: {r.protocol_id}")
        return ProofReport(
            protocols=tuple(self._protocols.values()), results=materialised,
        )
