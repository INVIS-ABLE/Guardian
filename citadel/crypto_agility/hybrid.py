"""Hybrid post-quantum migration (Citadel System 23, Wave-20 invariant 26).

A hybrid scheme combines a classical algorithm with a post-quantum one so security holds if *either*
remains unbroken. The rule: a PQ migration must **not silently reduce** current classical security —
the hybrid's classical component must be at least as strong as what it replaces.
"""

from __future__ import annotations

from dataclasses import dataclass

from .algorithms import Algorithm, AlgorithmPolicy


@dataclass(frozen=True)
class HybridScheme:
    name: str
    classical: str        # e.g. "x25519"
    post_quantum: str     # e.g. "ml-kem-768"


@dataclass(frozen=True)
class HybridVerdict:
    ok: bool
    reasons: tuple[str, ...]


def hybrid_not_weaker_than_classical(
    scheme: HybridScheme, replacing: str, policy: AlgorithmPolicy | None = None
) -> HybridVerdict:
    """Verify a hybrid scheme keeps a PQ component AND classical strength >= the algorithm it
    replaces (no silent downgrade of current classical security)."""
    pol = policy or AlgorithmPolicy.default()
    reasons: list[str] = []

    classical: Algorithm | None = pol.get(scheme.classical)
    pq: Algorithm | None = pol.get(scheme.post_quantum)
    old: Algorithm | None = pol.get(replacing)

    if classical is None:
        reasons.append("classical_component_unknown")
    if pq is None or not pq.post_quantum:
        reasons.append("missing_post_quantum_component")
    if classical and old and classical.classical_strength_bits < old.classical_strength_bits:
        reasons.append(
            f"hybrid weakens classical security: {classical.classical_strength_bits} < "
            f"{old.classical_strength_bits} bits"
        )
    return HybridVerdict(not reasons, tuple(reasons))


__all__ = ["HybridScheme", "HybridVerdict", "hybrid_not_weaker_than_classical"]
