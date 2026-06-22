"""Level 6 §5–7: HealingContract validation and the no-contract-no-repair gate."""

from __future__ import annotations

import pytest

from adaptive.healing.contracts import (
    Environment,
    HealingContract,
    HealingContractViolation,
    RepairAction,
    assert_repair_allowed,
)

# The directive's worked example, in mapping form (camelCase, nested metadata).
EXAMPLE: dict = {
    "apiVersion": "guardian.invisable/v1",
    "kind": "HealingContract",
    "metadata": {
        "service": "message-relay",
        "owner": "privacy-platform",
        "criticality": "critical",
    },
    "health": {
        "sloRef": "message-relay-availability",
        "readinessSignals": [
            {"prometheus": 'up{service="message-relay"} == 1'},
            {"prometheus": "message_delivery_error_rate < 0.01"},
        ],
        "dependencySignals": [
            "postgres_replication_healthy",
            "key_transparency_available",
            "encrypted_mailbox_available",
        ],
    },
    "allowedRepairs": [
        {"action": "restart_replica", "environments": ["staging"], "maximumPerHour": 2},
        {
            "action": "rollback_canary",
            "environments": ["staging", "production"],
            "requires": ["approved_rollout", "failed_safety_analysis"],
        },
        {
            "action": "disable_feature",
            "flag": "new_delivery_path",
            "environments": ["staging", "production"],
            "maximumDurationSeconds": 3600,
        },
    ],
    "forbiddenRepairs": [
        "delete_message_store",
        "bypass_encryption",
        "disable_audit",
        "introduce_plaintext_logging",
    ],
    "rollback": {"required": True, "verificationWindowSeconds": 600},
    "privacy": {"plaintextAccess": "forbidden", "messageKeyAccess": "forbidden"},
}


def test_directive_example_contract_parses():
    c = HealingContract.from_mapping(EXAMPLE)
    assert c.metadata.service == "message-relay"
    assert len(c.allowed_repairs) == 3
    assert len(c.health.readiness_signals) == 2
    assert c.health.readiness_signals[0].source == "prometheus"


def test_no_contract_refuses_repair():
    with pytest.raises(HealingContractViolation):
        assert_repair_allowed(None, RepairAction.RESTART_REPLICA, Environment.STAGING)


def test_permitted_repair_passes_in_declared_environment():
    c = HealingContract.from_mapping(EXAMPLE)
    repair = assert_repair_allowed(c, RepairAction.RESTART_REPLICA, Environment.STAGING)
    assert repair.maximum_per_hour == 2


def test_repair_refused_in_undeclared_environment():
    c = HealingContract.from_mapping(EXAMPLE)
    # restart_replica is staging-only in the example.
    with pytest.raises(HealingContractViolation):
        assert_repair_allowed(c, RepairAction.RESTART_REPLICA, Environment.PRODUCTION)


def test_unlisted_repair_refused():
    c = HealingContract.from_mapping(EXAMPLE)
    with pytest.raises(HealingContractViolation):
        assert_repair_allowed(c, RepairAction.REGIONAL_RECOVERY, Environment.PRODUCTION)


def test_disable_feature_requires_expiry_and_flag():
    bad = dict(EXAMPLE)
    bad["allowedRepairs"] = [
        {"action": "disable_feature", "flag": "x", "environments": ["staging"]}  # no expiry
    ]
    with pytest.raises(ValueError):
        HealingContract.from_mapping(bad)


def test_privacy_must_be_forbidden():
    bad = dict(EXAMPLE)
    bad["privacy"] = {"plaintextAccess": "allowed", "messageKeyAccess": "forbidden"}
    with pytest.raises(ValueError):
        HealingContract.from_mapping(bad)


def test_rollback_required_must_be_true():
    bad = dict(EXAMPLE)
    bad["rollback"] = {"required": False, "verificationWindowSeconds": 600}
    with pytest.raises(ValueError):
        HealingContract.from_mapping(bad)


def test_allowed_repair_cannot_be_structurally_forbidden_action():
    bad = dict(EXAMPLE)
    # 'disable_audit' is structurally forbidden and not a RepairAction — but even if a
    # contract listed a forbidden action string it must be rejected. Use a real action
    # placed into the forbidden set to prove the intersection check.
    bad["allowedRepairs"] = [{"action": "rollback_canary", "environments": ["staging"]}]
    bad["forbiddenRepairs"] = ["rollback_canary"]
    with pytest.raises(ValueError):
        HealingContract.from_mapping(bad)


def test_default_privacy_is_forbidden():
    minimal = {
        "metadata": {"service": "s", "owner": "o", "criticality": "low"},
        "health": {"sloRef": "s-availability"},
        "rollback": {"verificationWindowSeconds": 60},
    }
    c = HealingContract.from_mapping(minimal)
    assert c.privacy.plaintext_access == "forbidden"
    assert c.privacy.message_key_access == "forbidden"
