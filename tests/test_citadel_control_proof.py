"""Wave 39 acceptance — Citadel Continuous Control Proof Engine (System 39)."""

from __future__ import annotations

from citadel.control_proof import ClaimObservation, ControlClaim, ControlProofEngine

NOW = 1_000_000.0


def _claim(cid, holds, observed_at, max_age=3600):
    return ControlClaim(
        claim_id=cid, statement=f"claim {cid}", owner="platform",
        max_evidence_age_seconds=max_age,
        evaluator=lambda: ClaimObservation(holds=holds, evidence="e" * 64, observed_at=observed_at),
    )


def test_passing_fresh_claim_is_ok():
    eng = ControlProofEngine()
    eng.register(_claim("all_images_signed", True, NOW))
    proof = eng.evaluate("all_images_signed", now=NOW)
    assert proof.ok and proof.fresh and proof.remediation_deadline is None


def test_failing_claim_creates_remediation_deadline():
    eng = ControlProofEngine()
    eng.register(_claim("no_replayed_capability", False, NOW))
    proof = eng.evaluate("no_replayed_capability", now=NOW)
    assert proof.ok is False and "claim_failed" in proof.reasons
    assert proof.remediation_deadline == NOW + 86400


def test_stale_evidence_is_flagged_and_gates_promotion():
    eng = ControlProofEngine()
    eng.register(_claim("all_workers_attested", True, NOW - 7200, max_age=3600))  # 2h old, max 1h
    proof = eng.evaluate("all_workers_attested", now=NOW)
    assert proof.ok is True and proof.fresh is False and "evidence_stale" in proof.reasons
    assert eng.gate(now=NOW) is False


def test_gate_allows_only_when_all_ok_and_fresh():
    eng = ControlProofEngine()
    eng.register(_claim("a", True, NOW))
    eng.register(_claim("b", True, NOW))
    assert eng.gate(now=NOW) is True
