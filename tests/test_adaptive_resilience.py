"""Level 6 §23–26: adaptive failover invariants and backup-verification."""

from __future__ import annotations

import pytest

from adaptive.resilience import (
    BackupVerification,
    FailoverInvariantError,
    FailoverPlan,
    assert_proven_recovery,
    validate_failover,
)
from adaptive.resilience.backups import BackupNotProvenError


def _plan(**kw) -> FailoverPlan:
    base = dict(name="region-failover", from_cluster="eu-1", to_cluster="eu-2",
                workloads=("message-relay",))
    base.update(kw)
    return FailoverPlan(**base)


# --- failover (§23) ------------------------------------------------------------
def test_clean_failover_validates():
    validate_failover(_plan())  # no raise


def test_failover_bypassing_opa_is_refused():
    with pytest.raises(FailoverInvariantError):
        validate_failover(_plan(asserted_effects=("bypass_opa",)))


def test_failover_changing_residency_is_refused():
    with pytest.raises(FailoverInvariantError):
        validate_failover(_plan(asserted_effects=("change_data_residency",)))


def test_failover_must_preserve_identity_and_policy():
    with pytest.raises(FailoverInvariantError):
        validate_failover(_plan(preserves_identity=False))
    with pytest.raises(FailoverInvariantError):
        validate_failover(_plan(preserves_policy=False))


def test_failover_to_same_cluster_refused():
    with pytest.raises(FailoverInvariantError):
        validate_failover(_plan(to_cluster="eu-1"))


# --- backups (§26) -------------------------------------------------------------
def _full_backup(**kw) -> BackupVerification:
    base = dict(
        backup_id="b1", service="relay", completed=True, encrypted=True, object_exists=True,
        readable=True, manifests_exist=True, keys_recoverable=True,
        restore_instructions_current=True, classification_correct=True,
        retention_correct=True, restoration_tested=True,
    )
    base.update(kw)
    return BackupVerification(**base)


def test_fully_verified_backup_is_proven_recovery():
    v = _full_backup()
    assert v.is_proven_recovery is True
    assert_proven_recovery(v)  # no raise


def test_backup_without_restoration_test_is_not_proven():
    v = _full_backup(restoration_tested=False)
    assert v.is_proven_recovery is False
    assert "restoration_tested" in v.missing_checks()
    with pytest.raises(BackupNotProvenError):
        assert_proven_recovery(v)


def test_unencrypted_backup_is_not_proven():
    with pytest.raises(BackupNotProvenError):
        assert_proven_recovery(_full_backup(encrypted=False))
