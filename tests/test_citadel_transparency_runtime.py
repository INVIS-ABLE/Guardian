"""Wave 29 acceptance — Citadel Transparency Fabric + promotion gate (Systems 28 + 29).

Acceptance:
  * inclusion proofs verify (and tampered ones do not),
  * the log is append-only (consistency proofs hold; rewrites are caught),
  * promotion requires an inclusion proof AND the full provenance chain,
  * a missing inclusion proof denies promotion.
"""

from __future__ import annotations

from citadel.foundry import (
    ReleaseCandidate,
    TransparencyLog,
    consistent,
    evaluate_promotion,
    verify_inclusion,
)


def _full_candidate(artefact_id="art-1", **overrides) -> ReleaseCandidate:
    base = dict(
        artefact_id=artefact_id, source_identity=True, lockfile=True, hermetic_build=True,
        independent_rebuild_matches=True, sbom=True, provenance=True, signature=True,
    )
    base.update(overrides)
    return ReleaseCandidate(**base)


# --- inclusion proofs --------------------------------------------------------------------------
def test_inclusion_proof_verifies_for_every_entry():
    log = TransparencyLog()
    for i in range(7):                       # odd count exercises promoted nodes
        log.append(f"artefact-{i}".encode())
    root = log.root()
    for i in range(7):
        proof = log.inclusion_proof(i)
        assert verify_inclusion(proof, root) is True


def test_inclusion_proof_fails_against_wrong_root():
    log = TransparencyLog()
    log.append(b"a")
    log.append(b"b")
    proof = log.inclusion_proof(0)
    assert verify_inclusion(proof, "00" * 32) is False


# --- append-only / consistency -----------------------------------------------------------------
def test_log_is_append_only_consistent():
    log = TransparencyLog()
    for i in range(3):
        log.append(f"e{i}".encode())
    old = log.checkpoint()
    for i in range(3, 6):
        log.append(f"e{i}".encode())
    new = log.checkpoint()
    assert consistent(old, new, log) is True


def test_consistency_rejects_a_rewritten_prefix():
    log = TransparencyLog()
    for i in range(3):
        log.append(f"e{i}".encode())
    old = log.checkpoint()
    # A different prefix root (simulating history rewrite) is not consistent.
    forged = type(old)(size=old.size, root="ff" * 32)
    log.append(b"e3")
    assert consistent(forged, log.checkpoint(), log) is False


# --- promotion gate ----------------------------------------------------------------------------
def test_promotion_requires_inclusion_proof():
    log = TransparencyLog()
    idx = log.append(b"art-1-digest")
    proof = log.inclusion_proof(idx)
    candidate = _full_candidate()

    # with a valid inclusion proof + full chain -> promotable
    ok = evaluate_promotion(candidate, proof, log.root())
    assert ok.promotable is True

    # without an inclusion proof -> denied
    denied = evaluate_promotion(candidate, None, None)
    assert denied.promotable is False
    assert "missing_transparency_inclusion_proof" in denied.reasons


def test_promotion_requires_full_provenance_chain():
    log = TransparencyLog()
    idx = log.append(b"art-2-digest")
    proof = log.inclusion_proof(idx)
    # signature present but provenance + reproducibility missing -> signature alone insufficient
    weak = _full_candidate(artefact_id="art-2", provenance=False, independent_rebuild_matches=False)
    decision = evaluate_promotion(weak, proof, log.root())
    assert decision.promotable is False
    assert "missing_provenance" in decision.reasons
    assert "missing_independent_rebuild_matching_digest" in decision.reasons
