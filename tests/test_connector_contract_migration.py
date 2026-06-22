"""Every scanner connector is driven through the GuardianConnector contract."""

from __future__ import annotations

import pytest

from connectors.codeql import CodeQLConnector
from connectors.contract import ActionRequest, ContractViolation, GuardianConnector, SignedAuthorization
from connectors.gitleaks import GitleaksConnector
from connectors.semgrep import SemgrepConnector
from connectors.trivy import TrivyConnector
from connectors.zap import ZapConnector

# (connector class, an enumerated action, a valid in-scope target)
SCANNERS = [
    (CodeQLConnector, "analyze", "github.com/invisable/app"),
    (SemgrepConnector, "scan", "github.com/invisable/app"),
    (GitleaksConnector, "detect", "github.com/invisable/app"),
    (TrivyConnector, "scan", "github.com/invisable/app"),
    (ZapConnector, "baseline", "staging.invisable.co.uk"),
]


@pytest.mark.parametrize("cls,action,target", SCANNERS)
def test_scanner_satisfies_contract(staging_scope, cls, action, target):
    c = cls(staging_scope, dry_run=True)
    assert isinstance(c, GuardianConnector)
    inv = c.inventory()
    assert inv.connector == c.tool
    assert action in inv.actions
    assert inv.fixed_binary == c.binary


@pytest.mark.parametrize("cls,action,target", SCANNERS)
def test_calculate_plan_builds_fixed_argv(staging_scope, cls, action, target):
    c = cls(staging_scope, dry_run=True)
    plan = c.calculate_plan(ActionRequest(action=action, target=target, repo=target))
    assert plan.argv[0] == c.binary
    assert plan.target == target


@pytest.mark.parametrize("cls,action,target", SCANNERS)
def test_plan_rejects_unknown_action(staging_scope, cls, action, target):
    c = cls(staging_scope, dry_run=True)
    with pytest.raises(ContractViolation):
        c.calculate_plan(ActionRequest(action="totally_unknown", target=target))


@pytest.mark.parametrize("cls,action,target", SCANNERS)
def test_plan_rejects_off_allowlist_target(staging_scope, cls, action, target):
    c = cls(staging_scope, dry_run=True)
    with pytest.raises(ContractViolation):
        c.calculate_plan(ActionRequest(action=action, target="evil.example.com"))


@pytest.mark.parametrize("cls,action,target", SCANNERS)
def test_plan_rejects_raw_command_arg(staging_scope, cls, action, target):
    c = cls(staging_scope, dry_run=True)
    with pytest.raises(ContractViolation):
        c.calculate_plan(ActionRequest(action=action, target=target, args={"command": "rm -rf /"}))


def test_execute_refuses_unsigned_authorization(staging_scope):
    c = SemgrepConnector(staging_scope, dry_run=True)
    req = ActionRequest(action="scan", target="github.com/invisable/app", repo="github.com/invisable/app")
    with pytest.raises(ContractViolation):
        c.execute(SignedAuthorization(request=req, approver="ciso", signature=""))


def test_required_approvals_reflects_scope(staging_scope):
    # code_review is not approval-gated; credential audit connectors would be.
    assert SemgrepConnector(staging_scope).required_approvals().required_actions == ()
