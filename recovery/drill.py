"""Backup/restore drill (blueprint area 26 / Phase 6).

A backup is only *proven* once it has been restored and the restored data re-verified. This
drill exercises the full loop against the tamper-evident audit log:

  1. snapshot the audit chain bytes (WORM backup),
  2. simulate loss (the live audit file is destroyed),
  3. restore from the backup (refused if the backup itself was tampered),
  4. re-verify the restored hash chain end-to-end.

It returns a :class:`DrillResult` with measured RPO/RTO and a per-step log — evidence that
recovery actually works, rather than an untested assumption.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from core.audit import AuditLog

from .backup import BackupManager, TamperError


@dataclass
class DrillResult:
    ok: bool
    steps: list[str] = field(default_factory=list)
    rpo_seconds: int = 0
    rto_seconds: float = 0.0
    chain_verified: bool = False
    evidence: dict[str, object] = field(default_factory=dict)


def run_restore_drill(
    audit: AuditLog,
    manager: BackupManager | None = None,
    *,
    rpo_seconds: int = 0,
) -> DrillResult:
    """Snapshot → simulate loss → restore → re-verify the audit hash chain."""
    manager = manager or BackupManager()
    steps: list[str] = []

    # 1) Snapshot the current audit chain (empty file is a valid, verifiable state).
    original = audit.path.read_bytes() if audit.path.exists() else b""
    backup = manager.snapshot(str(audit.path), original, worm=True, rpo_seconds=rpo_seconds)
    steps.append(f"snapshot {backup.id} ({len(original)} bytes, digest={backup.digest[:12]}…)")

    start = time.monotonic()

    # 2) Simulate catastrophic loss of the live evidence file.
    if audit.path.exists():
        audit.path.unlink()
    steps.append("simulated loss: audit file removed")

    # 3) Restore from the WORM backup (raises if the backup was tampered).
    try:
        restored = manager.restore(backup)
    except TamperError as exc:
        steps.append(f"restore refused: {exc}")
        return DrillResult(
            ok=False, steps=steps, rpo_seconds=rpo_seconds,
            rto_seconds=time.monotonic() - start, chain_verified=False,
            evidence={"backup_id": backup.id, "tamper": True},
        )
    audit.path.write_bytes(restored)
    rto = time.monotonic() - start
    steps.append(f"restored {len(restored)} bytes in {rto:.4f}s")

    # 4) Re-verify the restored chain end-to-end, and confirm byte-for-byte fidelity.
    chain_ok = audit.verify()
    identical = restored == original
    steps.append(f"chain re-verify: {'ok' if chain_ok else 'FAILED'}; identical={identical}")

    ok = chain_ok and identical
    return DrillResult(
        ok=ok,
        steps=steps,
        rpo_seconds=rpo_seconds,
        rto_seconds=rto,
        chain_verified=chain_ok,
        evidence={
            "backup_id": backup.id,
            "bytes": len(restored),
            "identical": identical,
            "digest": backup.digest,
        },
    )
