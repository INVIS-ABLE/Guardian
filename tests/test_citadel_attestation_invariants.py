"""Citadel attestation invariants (Wave-20 invariants 8, 27).

No workload receives a capability before identity attestation; a failed attestation denies
capability issuance; attestation is fresh (bounded max age); and attestation never grants
production authority.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIGS = ROOT / "configs" / "citadel"
ARCH = ROOT / "docs" / "architecture"


def _load(p: Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def test_attestation_required_before_capability_and_fresh():
    att = _load(CONFIGS / "attestation.yaml")["citadel"]["attestation"]
    assert att["required_before_capability"] is True        # invariant 8
    assert att["grants_production_authority"] is False       # invariant 2
    assert att["on_failure"] == "deny_capability_issuance"   # invariant 27
    assert att["nonce_required"] is True                     # anti-replay
    assert 0 < att["max_age_minutes"] <= 60


def test_root_of_trust_denies_unattested_platforms():
    rot = _load(CONFIGS / "root-of-trust.yaml")["citadel"]["root_of_trust"]
    assert rot["unattested_platform"] == "deny_capability_issuance"
    assert rot["tpm_required_for_production_workers"] is True
    assert rot["measured_boot_required"] is True
    assert rot["remote_attestation_required"] is True
    assert 0 < rot["attestation_max_age_minutes"] <= 60
    assert rot["on_drift"]["quarantine_worker"] is True


def test_confidential_secret_release_bound_to_failed_attestation():
    cc = _load(CONFIGS / "confidential-compute.yaml")["citadel"]["confidential_compute"]
    assert cc["secret_release_bound_to_measurement"] is True
    assert cc["on_failed_attestation"] == "deny_secret_release"
    assert cc["requirements"]["attestation_bound_secret_release"] is True
    assert cc["requirements"]["evidence_outside_worker_sole_control"] is True


def test_attestation_systems_gate_capability_in_catalogue():
    systems = {s["id"]: s for s in _load(ARCH / "citadel_capabilities.yaml")["systems"]}
    for sid in ("root_of_trust", "confidential_execution"):
        assert systems[sid]["attestation_gates_capability"] is True
        assert systems[sid]["grants_production_authority"] is False
