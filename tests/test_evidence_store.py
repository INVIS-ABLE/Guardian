"""The evidence system of record is append-only, redacted, and verifiable."""

from __future__ import annotations

import json

from core.evidence import EvidenceEvent, EvidenceStore, HashChainBackend


def _store(tmp_path) -> EvidenceStore:
    return EvidenceStore(backend=HashChainBackend(log_dir=tmp_path))


def test_record_returns_verifiable_receipt(tmp_path):
    store = _store(tmp_path)
    receipt = store.record(EvidenceEvent(actor="guardian", command_id="semgrep:scan", result="completed"))
    assert receipt.event_id
    assert receipt.entry_hash
    assert receipt.backend == "hash_chain"
    assert store.verify() is True


def test_event_id_is_minted_when_absent(tmp_path):
    store = _store(tmp_path)
    r = store.record(EvidenceEvent(actor="a", command_id="c", result="completed"))
    assert len(r.event_id) == 16


def test_secrets_are_redacted_before_storage(tmp_path):
    store = _store(tmp_path)
    store.record(EvidenceEvent(
        actor="guardian", command_id="x", result="completed",
        attestation="token=ghp_" + "a" * 36,
    ))
    written = (tmp_path / "guardian-audit.jsonl").read_text()
    assert "ghp_aaaa" not in written
    assert "[REDACTED]" in written


def test_chain_detects_tampering(tmp_path):
    store = _store(tmp_path)
    store.record(EvidenceEvent(actor="a", command_id="c1", result="completed"))
    store.record(EvidenceEvent(actor="b", command_id="c2", result="completed"))
    assert store.verify() is True
    # Tamper with a stored entry: the hash chain must now fail verification.
    path = tmp_path / "guardian-audit.jsonl"
    lines = path.read_text().splitlines()
    first = json.loads(lines[0])
    first["detail"]["actor"] = "mallory"
    lines[0] = json.dumps(first, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    assert HashChainBackend(log_dir=tmp_path).verify() is False


def test_redacted_keeps_chain_fields(tmp_path):
    ev = EvidenceEvent(actor="guardian", command_id="c", result="allowed",
                       policy_decision="allow", returncode=0)
    d = ev.redacted()
    assert d["policy_decision"] == "allow"
    assert d["returncode"] == 0
