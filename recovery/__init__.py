"""Guardian recovery — verifiable backups + restore drills (Phase 6 / area 26).

Backups are WORM and integrity-checked; a restore is refused if the backup was tampered. A
backup is only *proven* once a drill has restored it and re-verified the audit hash chain.
"""

from __future__ import annotations

from .backup import Backup, BackupManager, TamperError
from .drill import DrillResult, run_restore_drill

__all__ = [
    "Backup",
    "BackupManager",
    "TamperError",
    "DrillResult",
    "run_restore_drill",
]
