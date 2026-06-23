"""Wave 23 acceptance — Citadel Cryptographic Agility Fabric (System 23).

Acceptance:
  * unknown cryptographic use is a blocking finding (fails CI),
  * deprecated / forbidden algorithms create blocking findings,
  * dual-read is required before cutover (migration),
  * no silent downgrade passes.
"""

from __future__ import annotations

import pytest

from citadel.crypto_agility import (
    AlgorithmPolicy,
    CryptoAgilityVerifier,
    CryptoAsset,
    CryptoInventory,
    HybridScheme,
    MigrationError,
    MigrationPlan,
    MigrationState,
    blocking_findings,
    detect_downgrade,
    hybrid_not_weaker_than_classical,
)


def _asset(asset_id: str, algorithm: str, **kw) -> CryptoAsset:
    return CryptoAsset(asset_id=asset_id, algorithm=algorithm, purpose="signature",
                       library="cryptography", version="42.0", **kw)


# --- acceptance: unknown crypto fails ----------------------------------------------------------
def test_unknown_algorithm_is_a_blocking_finding():
    inv = CryptoInventory()
    inv.register(_asset("a1", "snakeoil-512"))   # not on the allow-list
    findings = inv.scan()
    assert any(f.reason.startswith("unknown algorithm") for f in findings)
    assert blocking_findings(findings), "unknown crypto must be blocking (fail CI)"


def test_forbidden_and_deprecated_algorithms_are_blocking():
    inv = CryptoInventory()
    inv.register(_asset("forbidden", "md5"))
    inv.register(_asset("deprecated", "rsa-2048"))
    by_id = {f.asset_id: f for f in inv.scan()}
    assert by_id["forbidden"].severity.value == "critical"
    assert by_id["deprecated"].severity.value == "high"
    assert len(blocking_findings(list(by_id.values()))) == 2


def test_approved_algorithm_has_no_finding():
    inv = CryptoInventory()
    inv.register(_asset("ok", "ed25519", key_size=256))
    assert inv.scan() == []


# --- acceptance: dual-read before cutover ------------------------------------------------------
def test_cutover_without_dual_read_is_rejected():
    plan = MigrationPlan("k1", "rsa-2048", "ml-dsa-65")
    plan.advance(MigrationState.CLASSIFIED)
    plan.advance(MigrationState.DUAL_WRITE)
    # Jumping straight to new-primary (skipping dual-read) is illegal.
    with pytest.raises(MigrationError):
        plan.advance(MigrationState.NEW_PRIMARY)


def test_proper_migration_reaches_cutover_via_dual_read():
    plan = MigrationPlan("k1", "rsa-2048", "ml-dsa-65")
    for state in (MigrationState.CLASSIFIED, MigrationState.DUAL_WRITE,
                  MigrationState.DUAL_READ, MigrationState.NEW_PRIMARY):
        plan.advance(state)
    assert plan.dual_read_reached and plan.cutover_done


# --- acceptance: no silent downgrade -----------------------------------------------------------
def test_downgrade_is_detected():
    # x25519 (128-bit) was offered but a weaker, deprecated rsa-2048 was negotiated.
    verdict = detect_downgrade(["x25519", "rsa-2048"], "rsa-2048")
    assert verdict.ok is False
    assert any("deprecated" in r or "downgrade" in r for r in verdict.reasons)


def test_no_downgrade_when_strongest_negotiated():
    verdict = detect_downgrade(["x25519", "ml-kem-768"], "ml-kem-768")
    assert verdict.ok is True


def test_unknown_negotiated_algorithm_fails_closed():
    verdict = detect_downgrade(["x25519"], "rot13")
    assert verdict.ok is False
    assert "negotiated_unknown_algorithm" in verdict.reasons


# --- post-quantum hybrid must not weaken classical security ------------------------------------
def test_hybrid_must_keep_pq_and_not_weaken_classical():
    good = HybridScheme("x25519+mlkem768", classical="x25519", post_quantum="ml-kem-768")
    assert hybrid_not_weaker_than_classical(good, replacing="x25519").ok is True

    # Missing the PQ component is rejected.
    bad = HybridScheme("x25519-only", classical="x25519", post_quantum="x25519")
    assert hybrid_not_weaker_than_classical(bad, replacing="x25519").ok is False


# --- composed verifier (the CI gate) -----------------------------------------------------------
def test_verifier_passes_clean_and_fails_dirty():
    clean = CryptoInventory()
    clean.register(_asset("ok", "ed25519", key_size=256))
    report = CryptoAgilityVerifier().verify(clean)
    assert report.ok is True

    dirty = CryptoInventory()
    dirty.register(_asset("bad", "sha1"))
    bad_plan = MigrationPlan("p", "rsa-2048", "ml-dsa-65")
    # Force an inconsistent history that reflects a cutover with no dual-read (defensive check).
    bad_plan.history = [MigrationState.DISCOVERED, MigrationState.NEW_PRIMARY]
    report = CryptoAgilityVerifier().verify(
        dirty, plans=[bad_plan], negotiations=[(["x25519", "rsa-2048"], "rsa-2048")],
    )
    assert report.ok is False
    assert report.blocking_findings and report.migration_violations and report.downgrade_violations


def test_default_policy_marks_known_baseline_algorithms():
    pol = AlgorithmPolicy.default()
    assert pol.is_known("ed25519") and pol.is_known("ml-kem-768")
    assert pol.classify("totally-made-up") is None
