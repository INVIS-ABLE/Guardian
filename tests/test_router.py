"""Tests for the Guardian tool router."""

from __future__ import annotations

import pytest

from core.guardrails import Approval, Guardrails
from core.router import CAPABILITY_MAP, ToolRouter, UnknownCapability


def test_capabilities_listed(staging_scope):
    router = ToolRouter(staging_scope, dry_run=True)
    caps = router.capabilities()
    assert "static_code" in caps and "privacy_simulation" in caps


def test_resolve_unknown_capability_raises(staging_scope):
    router = ToolRouter(staging_scope, dry_run=True)
    with pytest.raises(UnknownCapability):
        router.resolve("definitely_not_a_capability")


def test_route_connector_dry_run(staging_scope):
    router = ToolRouter(staging_scope, dry_run=True)
    result = router.route("static_code", repo="github.com/invisable/app")
    assert result.allowed is True
    assert result.dry_run is True
    assert result.output["dry_run"] is True


def test_route_simulator_dry_run(staging_scope):
    router = ToolRouter(staging_scope, dry_run=True)
    result = router.route("privacy_simulation")
    assert result.allowed is True
    assert result.output["scenario_name"]


def test_approval_gated_capability_refused_without_approval(staging_scope):
    router = ToolRouter(staging_scope, dry_run=True)
    result = router.route("login_resilience", target="staging.invisable.co.uk")
    assert result.allowed is False
    assert "approval" in result.refusal_reason.lower()


def test_approval_gated_capability_allowed_with_approval(staging_scope):
    # An online login-resilience test (hydra) is high-impact: it needs recorded
    # approvals for the high-volume + account-locking actions, an owned target, and a
    # registered test account. With all present + dry-run, the router permits it.
    gr = Guardrails(scope=staging_scope, approvals=[
        Approval(action="high_volume_test", approver="ciso", ticket="OPS-1"),
        Approval(action="account_locking_test", approver="ciso", ticket="OPS-1"),
    ])
    router = ToolRouter(staging_scope, guardrails=gr, dry_run=True)
    result = router.route(
        "login_resilience", target="staging.invisable.co.uk",
        test_account="standard_user_test",
    )
    assert result.allowed is True, result.refusal_reason


def test_every_capability_maps_to_a_registered_tool(staging_scope):
    from connectors import REGISTRY as C
    from simulators import REGISTRY as S

    for cap, (kind, tool) in CAPABILITY_MAP.items():
        registry = C if kind == "connector" else S
        assert tool in registry, f"{cap} -> {tool} not registered in {kind}s"
