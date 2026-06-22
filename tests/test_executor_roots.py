"""Capability issuance is gated by the six roots of trust (executor integration)."""

from __future__ import annotations

from uuid import uuid4

from core.roots_of_trust import RootsOfTrust
from core.tools.executor import ToolExecution, ToolExecutor
from core.tools.registry import RefusalReason, ToolRefusal, default_registry

from tests.test_roots_of_trust import _full_context

ARGS = {"target": "github.com/invisable/app", "rules": "p/ci"}


def _execute(executor, *, environment="development", trust=None):
    return executor.execute(
        "static_code_scan", case_id=uuid4(), args=ARGS, environment=environment, trust=trust,
    )


def test_full_trust_lets_a_capability_issue():
    ex = ToolExecutor(default_registry(), roots=RootsOfTrust())
    out = _execute(ex, trust=_full_context(environment="development"))
    assert isinstance(out, ToolExecution)
    assert out.capability == "static_code_scan"


def test_missing_trust_context_is_refused_when_gate_configured():
    ex = ToolExecutor(default_registry(), roots=RootsOfTrust())
    out = _execute(ex, trust=None)
    assert isinstance(out, ToolRefusal)
    assert out.reason is RefusalReason.ROOTS_OF_TRUST_FAILED


def test_one_failing_root_blocks_issuance():
    ex = ToolExecutor(default_registry(), roots=RootsOfTrust())
    ctx = _full_context(environment="development")
    broken = ctx.model_copy(update={"machine": type(ctx.machine)()})  # machine root empty
    out = _execute(ex, trust=broken)
    assert isinstance(out, ToolRefusal)
    assert out.reason is RefusalReason.ROOTS_OF_TRUST_FAILED
    assert "machine" in out.detail


def test_posture_enforces_roots_without_an_explicit_gate(monkeypatch):
    # In a staging/production posture the gate is mandatory even if not passed in.
    monkeypatch.setenv("GUARDIAN_ENV", "staging")
    monkeypatch.setenv("GUARDIAN_MANIFEST_KEY", "real-key")  # required to sign/verify in staging
    ex = ToolExecutor(default_registry())  # no explicit roots gate
    out = ex.execute("static_code_scan", case_id=uuid4(), args=ARGS, environment="staging")
    assert isinstance(out, ToolRefusal)
    assert out.reason is RefusalReason.ROOTS_OF_TRUST_FAILED


def test_development_posture_without_gate_preserves_existing_behaviour(monkeypatch):
    # No gate + development posture => roots not enforced; capability issues as before.
    monkeypatch.setenv("GUARDIAN_ENV", "development")
    monkeypatch.delenv("GUARDIAN_REQUIRE_ROOTS", raising=False)
    ex = ToolExecutor(default_registry())
    out = _execute(ex, trust=None)
    assert isinstance(out, ToolExecution)
