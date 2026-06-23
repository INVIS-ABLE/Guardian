"""Citadel quorum invariants (Wave-20 invariants 14, 16, 17, 18).

Root operations require a multi-party threshold; participants use separate credentials and separate
evidence reads; recovery credentials live outside the normal runtime plane; the primary cannot
approve the Shadow.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIGS = ROOT / "configs" / "citadel"
ARCH = ROOT / "docs" / "architecture"


def _load(p: Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def _quorum() -> dict:
    return _load(CONFIGS / "quorum.yaml")["citadel"]


def test_root_operations_require_threshold_of_at_least_three():
    q = _quorum()["quorum"]
    for op in ("root_key_rotation", "recovery_activation", "attestation_root_rotation",
               "evidence_root_migration", "transparency_log_migration"):
        assert q[op] >= 3, f"{op} threshold must be >= 3, got {q[op]}"
    assert q["emergency_policy_replacement"] >= 4
    assert q["guardian_wide_freeze"] >= 2


def test_participants_are_independent():
    q = _quorum()["quorum"]
    assert q["participants_use_separate_credentials"] is True      # invariant 16
    assert q["participants_use_separate_evidence_reads"] is True   # invariant 17
    assert q["recovery_credentials_outside_runtime_plane"] is True  # invariant 18


def test_quorum_result_is_fully_attributable():
    q = _quorum()["quorum"]
    for field in ("participants", "participant_identities", "separate_authentication_evidence",
                  "threshold", "result", "signature"):
        assert field in q["result_fields"], f"quorum result must record {field}"


def test_primary_cannot_approve_shadow():
    shadow = _quorum()["shadow"]
    assert shadow["primary_cannot_approve_shadow"] is True          # invariant 14
    assert shadow["may_assume_operational_control"] is False


def test_capabilities_manifest_quorum_threshold_agrees():
    systems = {s["id"]: s for s in _load(ARCH / "citadel_capabilities.yaml")["systems"]}
    assert systems["trust_quorum"]["min_threshold"] >= 3
    assert systems["trust_quorum"]["participants_use_separate_credentials"] is True
