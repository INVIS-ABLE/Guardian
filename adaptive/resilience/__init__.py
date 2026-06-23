"""Multi-cluster survivability + backup-verification contracts (directive §23–26)."""

from .backups import BackupNotProvenError, BackupVerification, assert_proven_recovery
from .failover import (
    FORBIDDEN_FAILOVER_EFFECTS,
    FailoverInvariantError,
    FailoverPlan,
    validate_failover,
)

__all__ = [
    "FORBIDDEN_FAILOVER_EFFECTS",
    "FailoverPlan",
    "FailoverInvariantError",
    "validate_failover",
    "BackupVerification",
    "assert_proven_recovery",
    "BackupNotProvenError",
]
