"""Backup-verification contract (directive §26).

A backup job that "succeeded" proves nothing on its own. Recovery is *proven* only when the
backup is complete, encrypted, present, readable, has its manifests and recoverable keys,
current restore instructions, correct classification and retention — **and** a restoration
into an isolated environment has actually succeeded. This contract makes that explicit.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class BackupVerification(BaseModel):
    """The evidence that a backup is real and restorable (§26)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    backup_id: str = Field(min_length=1)
    service: str = Field(min_length=1)
    completed: bool = False
    encrypted: bool = False
    object_exists: bool = False
    readable: bool = False
    manifests_exist: bool = False
    keys_recoverable: bool = False
    restore_instructions_current: bool = False
    classification_correct: bool = False
    retention_correct: bool = False
    restoration_tested: bool = False  # a real restore into an isolated environment succeeded

    def missing_checks(self) -> tuple[str, ...]:
        """The unmet verification checks, in declaration order."""
        checks = (
            "completed", "encrypted", "object_exists", "readable", "manifests_exist",
            "keys_recoverable", "restore_instructions_current", "classification_correct",
            "retention_correct", "restoration_tested",
        )
        return tuple(c for c in checks if not getattr(self, c))

    @property
    def is_proven_recovery(self) -> bool:
        """True only when every check passes, restoration included (§26)."""
        return not self.missing_checks()


def assert_proven_recovery(v: BackupVerification) -> None:
    """Fail closed unless recovery is fully proven (restoration test included)."""
    missing = v.missing_checks()
    if missing:
        raise BackupNotProvenError(
            f"backup {v.backup_id!r} is not proven recovery; missing: {list(missing)}"
        )


class BackupNotProvenError(RuntimeError):
    """Raised when a backup has not been proven as recoverable. Fail closed."""


__all__ = [
    "BackupVerification",
    "assert_proven_recovery",
    "BackupNotProvenError",
]
