"""Backup integrity + restore-drill proofs (Phase 6 / area 26).

WORM backups detect tampering and refuse to restore corrupted data; the restore drill proves
recovery by re-verifying the audit hash chain end-to-end.
"""

from __future__ import annotations

import pytest

from core.audit import AuditLog
from recovery import BackupManager, TamperError, run_restore_drill


def test_backup_roundtrip_preserves_bytes():
    mgr = BackupManager()
    data = b"evidence-chain-bytes"
    backup = mgr.snapshot("audit", data)
    assert mgr.verify(backup)
    assert mgr.restore(backup) == data


def test_tampered_backup_detected_and_refused():
    mgr = BackupManager()
    backup = mgr.snapshot("audit", b"original")
    # Simulate at-rest corruption.
    backup.payload = b"corrupted"
    assert not backup.verify()
    with pytest.raises(TamperError):
        mgr.restore(backup)


def test_worm_flag_and_rpo_recorded():
    mgr = BackupManager()
    backup = mgr.snapshot("audit", b"x", worm=True, rpo_seconds=300)
    assert backup.worm is True
    assert backup.rpo_seconds == 300


def test_restore_drill_recovers_and_reverifies_chain(tmp_path):
    audit = AuditLog(log_dir=tmp_path)
    audit.record("detect", actor="guardian")
    audit.record("contain", actor="guardian", decision="allowed")
    assert audit.verify()

    result = run_restore_drill(audit, rpo_seconds=60)
    assert result.ok
    assert result.chain_verified
    assert result.rpo_seconds == 60
    assert audit.path.exists()
    assert audit.verify()  # live file restored and still valid
    assert any("chain re-verify: ok" in s for s in result.steps)


def test_restore_drill_on_empty_audit(tmp_path):
    audit = AuditLog(log_dir=tmp_path)
    # No entries yet — drill still succeeds (empty chain verifies).
    result = run_restore_drill(audit)
    assert result.ok
    assert result.chain_verified


def test_drill_reports_failure_when_backup_tampered(tmp_path, monkeypatch):
    audit = AuditLog(log_dir=tmp_path)
    audit.record("detect", actor="guardian")

    mgr = BackupManager()
    real_snapshot = mgr.snapshot

    def tampering_snapshot(*args, **kwargs):
        backup = real_snapshot(*args, **kwargs)
        backup.payload = backup.payload + b"tamper"  # corrupt after snapshot
        return backup

    monkeypatch.setattr(mgr, "snapshot", tampering_snapshot)

    result = run_restore_drill(audit, mgr)
    assert not result.ok
    assert result.evidence.get("tamper") is True
    assert any("restore refused" in s for s in result.steps)
