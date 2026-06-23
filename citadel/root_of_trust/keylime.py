"""Keylime integration seam.

Keylime is the authoritative production source of remote-attestation quotes (TPM AK quotes over
boot/runtime PCRs). This module is the thin client boundary Guardian talks to; ``StaticKeylimeClient``
is a deterministic stand-in (wrapping ``SoftwareTpm`` agents) so the verifier path is testable
without a live Keylime verifier. Swap in the real client in production — the contract is the same.
"""

from __future__ import annotations

from typing import Protocol

from core.machine_attestation import AttestationReport

from .tpm import TpmQuoteSource


class KeylimeClient(Protocol):
    """Request a fresh, nonce-bound attestation quote for an agent (node)."""

    def get_quote(self, node_id: str, nonce: str) -> tuple[AttestationReport, str]:
        """Request a fresh, nonce-bound attestation quote for an agent (node)."""


class StaticKeylimeClient:
    """Test/local Keylime stand-in backed by per-node quote sources (e.g. ``SoftwareTpm``)."""

    def __init__(self, agents: dict[str, TpmQuoteSource]) -> None:
        self._agents = agents

    def register(self, node_id: str, source: TpmQuoteSource) -> None:
        self._agents[node_id] = source

    def get_quote(self, node_id: str, nonce: str) -> tuple[AttestationReport, str]:
        agent = self._agents.get(node_id)
        if agent is None:
            raise KeyError(f"no Keylime agent registered for {node_id}")
        return agent.quote(node_id, nonce)


__all__ = ["KeylimeClient", "StaticKeylimeClient"]
