"""Encrypted/verifiable backups (blueprint area 26 / Phase 6).

Models restic-style backups with WORM (write-once) semantics and integrity verification: a
backup records the content digest at creation, so any later tampering is detected and a
restore of corrupted data is refused. A backup that has not been restored *and verified* is
not yet proven — see ``recovery.drill``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone


class TamperError(RuntimeError):
    """Raised when a backup's content no longer matches its recorded digest."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Backup:
    id: str
    source: str
    created_at: str
    digest: str
    worm: bool
    rpo_seconds: int
    payload: bytes = field(repr=False, default=b"")

    def verify(self) -> bool:
        """Recompute the content digest; True if the backup is intact."""
        return _sha256(self.payload) == self.digest


@dataclass
class BackupManager:
    _seq: int = 0
    _store: dict[str, Backup] = field(default_factory=dict)

    def snapshot(self, source: str, data: bytes, *, worm: bool = True, rpo_seconds: int = 0) -> Backup:
        self._seq += 1
        backup = Backup(
            id=f"bk-{self._seq:06d}",
            source=source,
            created_at=datetime.now(timezone.utc).isoformat(),
            digest=_sha256(data),
            worm=worm,
            rpo_seconds=rpo_seconds,
            payload=bytes(data),  # copy
        )
        self._store[backup.id] = backup
        return backup

    def verify(self, backup: Backup) -> bool:
        return backup.verify()

    def restore(self, backup: Backup) -> bytes:
        """Return the backed-up bytes, refusing if integrity verification fails."""
        if not backup.verify():
            raise TamperError(f"backup {backup.id} failed integrity verification; refusing restore")
        return bytes(backup.payload)
