"""Downgrade detection — the independent verifier for System 23 (Wave-20 invariant: no silent
downgrade).

Given what a peer *offered* and what was *negotiated*, this catches a negotiated algorithm that is
weaker than an approved, mutually-available option — the classic downgrade attack — and any
negotiation that lands on a deprecated/forbidden/unknown algorithm. It is independent of the
inventory owner: it reasons about a single negotiation event, fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass

from .algorithms import AlgorithmPolicy, AlgorithmStatus


@dataclass(frozen=True)
class DowngradeVerdict:
    ok: bool
    negotiated: str
    reasons: tuple[str, ...]


def detect_downgrade(
    offered: list[str], negotiated: str, policy: AlgorithmPolicy | None = None
) -> DowngradeVerdict:
    """Flag a downgrade: a negotiated algorithm weaker than an available approved one, or one that
    is not approved at all."""
    pol = policy or AlgorithmPolicy.default()
    reasons: list[str] = []

    neg = pol.get(negotiated)
    if neg is None:
        reasons.append("negotiated_unknown_algorithm")
        return DowngradeVerdict(False, negotiated, tuple(reasons))
    if neg.status is AlgorithmStatus.FORBIDDEN:
        reasons.append("negotiated_forbidden_algorithm")
    elif neg.status is AlgorithmStatus.DEPRECATED:
        reasons.append("negotiated_deprecated_algorithm")

    # Was a stronger, approved, same-purpose algorithm available but not chosen?
    best_available = 0
    for name in offered:
        algo = pol.get(name)
        if algo and algo.status is AlgorithmStatus.APPROVED and algo.purpose == neg.purpose:
            best_available = max(best_available, algo.classical_strength_bits)
    if best_available > neg.classical_strength_bits:
        reasons.append(
            f"downgrade: negotiated {neg.classical_strength_bits}-bit when "
            f"{best_available}-bit approved option was offered"
        )

    return DowngradeVerdict(not reasons, negotiated, tuple(reasons))


__all__ = ["DowngradeVerdict", "detect_downgrade"]
