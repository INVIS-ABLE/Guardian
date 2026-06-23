"""Continuous control-proof engine (Citadel System 39, Wave 39).

Continuously tests claims about Guardian's own controls ("all production images are signed", "no
capability was replayed", ...). Each claim has an evaluator over data sources, and each proof
carries a result, evidence, freshness and a remediation deadline. A claim whose evidence is stale,
or that fails, is a control finding — and gates high-impact promotion.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class ControlClaim:
    claim_id: str
    statement: str
    owner: str
    max_evidence_age_seconds: int
    evaluator: Callable[[], "ClaimObservation"]


@dataclass(frozen=True)
class ClaimObservation:
    holds: bool
    evidence: str            # content-addressable digest / reference
    observed_at: float
    detail: str = ""


@dataclass(frozen=True)
class ControlProof:
    claim_id: str
    statement: str
    owner: str
    ok: bool
    fresh: bool
    evidence: str
    observed_at: float
    remediation_deadline: float | None
    reasons: tuple[str, ...]


class ControlProofEngine:
    def __init__(self) -> None:
        self._claims: dict[str, ControlClaim] = {}

    def register(self, claim: ControlClaim) -> None:
        self._claims[claim.claim_id] = claim

    def evaluate(self, claim_id: str, *, now: float) -> ControlProof:
        claim = self._claims[claim_id]
        obs = claim.evaluator()
        fresh = (now - obs.observed_at) <= claim.max_evidence_age_seconds
        reasons: list[str] = []
        if not obs.holds:
            reasons.append("claim_failed")
        if not fresh:
            reasons.append("evidence_stale")
        deadline = None if obs.holds and fresh else now + 86400
        return ControlProof(
            claim_id=claim.claim_id, statement=claim.statement, owner=claim.owner,
            ok=obs.holds, fresh=fresh, evidence=obs.evidence, observed_at=obs.observed_at,
            remediation_deadline=deadline, reasons=tuple(reasons),
        )

    def evaluate_all(self, *, now: float) -> list[ControlProof]:
        return [self.evaluate(cid, now=now) for cid in self._claims]

    def gate(self, *, now: float) -> bool:
        """High-impact promotion is allowed only if every control proof is OK and fresh."""
        return all(p.ok and p.fresh for p in self.evaluate_all(now=now))


__all__ = ["ControlClaim", "ClaimObservation", "ControlProof", "ControlProofEngine"]
