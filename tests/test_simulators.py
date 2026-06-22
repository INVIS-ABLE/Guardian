"""Simulator tests — output contract, guardrail integration, audit, evidence."""

from __future__ import annotations

import pytest

from core.evidence import SEVERITIES, SimulatorResult
from core.guardrails import Guardrails, GuardrailViolation
from simulators import REGISTRY


@pytest.mark.parametrize("name", sorted(REGISTRY))
def test_simulator_dry_run_emits_full_contract(name, staging_scope):
    sim = REGISTRY[name](staging_scope, dry_run=True)
    result = sim.run()
    assert isinstance(result, SimulatorResult)
    # Mandatory output contract fields are all populated.
    assert result.scenario_name
    assert result.scope == staging_scope.asset
    assert result.severity in SEVERITIES
    assert result.detection_result
    assert result.containment_result
    assert result.user_safety_impact
    assert result.recommended_fix
    assert result.retest_instructions
    # Dry-run touches only registered test accounts.
    for account in result.test_accounts_used:
        assert account in staging_scope.allowed_test_accounts


def test_simulator_refuses_out_of_scope_mode(staging_scope):
    # Build a guardrails whose scope disallows abuse_simulation by faking allowed_modes.
    from dataclasses import replace

    narrowed = replace(staging_scope, raw={**staging_scope.raw, "allowed_modes": ["code_review"]})
    sim = REGISTRY["privacy_leak"](narrowed, dry_run=True, guardrails=Guardrails(scope=narrowed))
    with pytest.raises(GuardrailViolation):
        sim.run()


def test_evidence_scrubs_secrets():
    res = SimulatorResult(
        scenario_name="x",
        scope="invisable-staging",
        evidence=["api_key=SUPERSECRETVALUE123", "ok line"],
    )
    assert any("[REDACTED]" in e for e in res.evidence)
    assert not any("SUPERSECRETVALUE123" in e for e in res.evidence)


def test_invalid_severity_rejected():
    with pytest.raises(ValueError):
        SimulatorResult(scenario_name="x", scope="s", severity="apocalyptic")
