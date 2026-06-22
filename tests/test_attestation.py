"""Phase 2 — evidence system of record + signed attestations."""

from __future__ import annotations

from attestation import HmacSigner, InMemoryEvidenceStore, SystemOfRecord
from core.audit import AuditLog


def test_store_chain_and_signatures_verify():
    store = InMemoryEvidenceStore()
    store.append({"action": "scan", "actor": "guardian"})
    store.append({"action": "deploy", "actor": "guardian"})
    assert store.verify() is True


def test_tampering_breaks_verification():
    store = InMemoryEvidenceStore()
    store.append({"action": "scan", "actor": "guardian"})
    store.append({"action": "deploy", "actor": "guardian"})
    # Mutate a stored record's content; chain + signature must fail.
    store.all()[0].record["actor"] = "attacker"
    assert store.verify() is False


def test_hmac_signature_detects_forgery():
    signer = HmacSigner(b"k1")
    rec = {"a": 1}
    sig = signer.sign(rec)
    assert signer.verify(rec, sig) is True
    assert HmacSigner(b"k2").verify(rec, sig) is False  # different key


def test_deleting_local_cache_does_not_lose_authoritative_evidence(tmp_path):
    # Bulletproof test #10: the system of record survives wiping the local cache.
    cache = AuditLog(log_dir=tmp_path)
    sor = SystemOfRecord(store=InMemoryEvidenceStore(), cache=cache)
    sor.record("deploy", actor="guardian", decision="allowed")
    sor.record("rollback", actor="guardian", decision="allowed")

    # Wipe the local cache file entirely.
    if cache.path.exists():
        cache.path.unlink()

    # Authoritative store still holds the evidence and verifies.
    assert sor.verify() is True
    assert len(sor.store.all()) == 2
