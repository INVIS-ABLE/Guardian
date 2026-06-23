"""Production-hardening: tenant enforcement is ON automatically in staging/production."""

from __future__ import annotations

import pytest

from core.policy_gate import _tenancy_enforced


def test_tenancy_off_in_development_by_default(monkeypatch):
    monkeypatch.delenv("GUARDIAN_ENV", raising=False)
    monkeypatch.delenv("GUARDIAN_TENANCY_ENFORCE", raising=False)
    assert _tenancy_enforced() is False


@pytest.mark.parametrize("env", ["staging", "production"])
def test_tenancy_on_in_deployed_posture(monkeypatch, env):
    monkeypatch.setenv("GUARDIAN_ENV", env)
    monkeypatch.delenv("GUARDIAN_TENANCY_ENFORCE", raising=False)
    assert _tenancy_enforced() is True


def test_tenancy_forced_on_by_flag_in_development(monkeypatch):
    monkeypatch.setenv("GUARDIAN_ENV", "development")
    monkeypatch.setenv("GUARDIAN_TENANCY_ENFORCE", "1")
    assert _tenancy_enforced() is True


def test_ci_posture_does_not_silently_enforce(monkeypatch):
    # CI keeps the founding-tenant default behaviour unless the flag is set explicitly.
    monkeypatch.setenv("GUARDIAN_ENV", "ci")
    monkeypatch.delenv("GUARDIAN_TENANCY_ENFORCE", raising=False)
    assert _tenancy_enforced() is False
