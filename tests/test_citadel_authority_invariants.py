"""Citadel authority-separation invariants (Wave-20 invariants 1, 2, 11, 12, 14, 15, 23).

The Citadel adds proof, never authority. Attestation gates capability; it never authorises. The
extended execution path keeps the ordering: policy precedes any platform-attestation override, and
attestation precedes capability issuance. The Shadow may freeze but never command.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ARCH = ROOT / "docs" / "architecture"
CONFIGS = ROOT / "configs" / "citadel"


def _load(p: Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def _systems() -> list[dict]:
    return _load(ARCH / "citadel_capabilities.yaml")["systems"]


def _by_id() -> dict[str, dict]:
    return {s["id"]: s for s in _systems()}


def test_no_system_grants_authority_or_production_authority():
    for s in _systems():
        assert s["grants_authority"] is False, f"{s['id']} grants authority"
        assert s["grants_production_authority"] is False, f"{s['id']} grants production authority"


def test_attestation_services_do_not_grant_production_authority():
    attestation = [s for s in _systems() if s.get("is_attestation_service")]
    assert attestation, "expected attestation services (root_of_trust, confidential_execution)"
    for s in attestation:
        assert s["grants_production_authority"] is False, f"{s['id']} attestation grants authority"
        assert s.get("attestation_gates_capability") is True, f"{s['id']} must gate capability"


def test_shadow_may_freeze_but_never_commands():
    shadow = _by_id()["shadow_federation"]
    assert shadow["may_freeze_capability_issuance"] is True
    assert shadow["may_assume_operational_control"] is False     # invariant 15
    assert shadow["primary_cannot_approve_shadow"] is True       # invariant 14
    assert shadow["separate_credentials"] is True


def test_model_output_cannot_override_failed_attestation():
    att = _load(CONFIGS / "attestation.yaml")["citadel"]["attestation"]
    assert att["model_output_cannot_override_failed_attestation"] is True  # invariant 11


def test_execution_path_orders_policy_attestation_capability_evidence():
    flows = _load(ARCH / "citadel_data_flows.yaml")
    order = {step["stage"]: step["step"] for step in flows["extended_execution_path"]}
    # policy precedes platform attestation precedes capability issuance precedes evidence
    assert order["policy_authority"] < order["platform_attestation"]            # invariant 12
    assert order["platform_attestation"] < order["capability_broker"]           # invariant 27/8
    assert order["capability_broker"] < order["evidence_commitment"]
    assert order["evidence_commitment"] < order["transparency_inclusion"]
    assert order["transparency_inclusion"] < order["independent_shadow_verification"]
    assert order["independent_shadow_verification"] < order["quorum_result"]


def test_untrusted_input_never_becomes_instruction():
    flows = _load(ARCH / "citadel_data_flows.yaml")
    barrier = flows["untrusted_input_barrier"]
    assert barrier["rule"] == "never_interpreted_as_instruction"   # invariant 23
    assert "model_output" in barrier["sources"]
