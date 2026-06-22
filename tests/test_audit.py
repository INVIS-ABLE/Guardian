"""Audit-log tamper-evidence tests."""

from __future__ import annotations

import json

from core.audit import AuditLog


def test_audit_chain_verifies(tmp_path):
    log = AuditLog(log_dir=tmp_path)
    log.record("a", actor="t", scope="s")
    log.record("b", actor="t", scope="s")
    assert log.verify() is True


def test_tampering_is_detected(tmp_path):
    log = AuditLog(log_dir=tmp_path)
    log.record("a", actor="t", scope="s")
    log.record("b", actor="t", scope="s")

    # Tamper with the first record's detail; the chain must now fail verification.
    lines = log.path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["detail"] = {"tampered": True}
    lines[0] = json.dumps(first, sort_keys=True)
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert log.verify() is False
