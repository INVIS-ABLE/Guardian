"""Waves 25-26 — Citadel Formal/Protocol model consistency (Systems 25, 26).

The provers (TLC/Apalache, Tamarin) are a laboratory toolchain not run in CI; these tests keep the
formal layer honest: every model exists, declares its properties, models real code, and cites a
proving test that exists — so models and implementations cannot silently diverge.
"""

from __future__ import annotations

from citadel.formal import REGISTRY, import_counterexample, model_issues, verify_all


def test_registry_has_state_machine_and_protocol_models():
    ids = {m.model_id for m in REGISTRY}
    assert "capability_lifecycle" in ids       # TLA+ state machine
    assert "attestation_secret_release" in ids  # Tamarin protocol


def test_every_model_is_present_declared_and_linked():
    assert verify_all() == [], f"formal-model consistency issues: {verify_all()}"


def test_each_model_declares_its_properties_in_the_file():
    for m in REGISTRY:
        assert m.properties, f"{m.model_id} declares no properties"
        assert model_issues(m) == []


def test_counterexample_imports_as_a_fixture():
    fixture = import_counterexample("capability_lifecycle", [{"state": "issued"}, {"state": "consumed"}])
    assert fixture["kind"] == "counterexample" and len(fixture["steps"]) == 2
