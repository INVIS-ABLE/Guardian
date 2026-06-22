"""The connector contract makes dangerous connector behaviour structurally impossible."""

from __future__ import annotations

from time import time

import pytest

from connectors.contract import (
    ActionRequest,
    ApprovalPolicy,
    CleanupResult,
    ConnectorInventory,
    ContractViolation,
    EvidenceBundle,
    ExecutionPlan,
    ExecutionResult,
    GuardianConnector,
    Permission,
    SignedAuthorization,
    ValidationResult,
    assert_no_raw_command,
    authorize_execution,
    target_allowed,
    validate_request,
)


# --- no raw command strings ---------------------------------------------------
@pytest.mark.parametrize("key", ["command", "cmd", "shell", "script", "exec", "eval"])
def test_raw_command_keys_are_rejected(key):
    with pytest.raises(ContractViolation):
        assert_no_raw_command({key: "rm -rf /"})


@pytest.mark.parametrize("value", ["a; rm -rf /", "x && y", "`whoami`", "$(id)", "a|b", "a>b"])
def test_shell_metacharacters_are_rejected(value):
    with pytest.raises(ContractViolation):
        assert_no_raw_command({"path": value})


def test_clean_typed_args_pass():
    assert_no_raw_command({"path": "src/app", "language": "python", "depth": 3}) is None


# --- target allowlist ---------------------------------------------------------
def test_target_allowlist_matching():
    allow = ("staging.invisable.co.uk", "github.com/invisable/app")
    assert target_allowed("staging.invisable.co.uk", allow)
    assert target_allowed("api.staging.invisable.co.uk", allow)        # subdomain
    assert target_allowed("github.com/invisable/app/tree/main", allow)  # subpath
    assert not target_allowed("evil.com", allow)
    assert not target_allowed("staging.invisable.co.uk.evil.com", allow)


def test_validate_request_enforces_action_and_target():
    req = ActionRequest(action="scan", target="staging.invisable.co.uk")
    # unknown action
    with pytest.raises(ContractViolation):
        validate_request(req, allowed_actions=("baseline",), target_allowlist=("staging.invisable.co.uk",))
    # off-allowlist target
    with pytest.raises(ContractViolation):
        validate_request(req, allowed_actions=("scan",), target_allowlist=("other.example",))
    # happy path
    validate_request(req, allowed_actions=("scan",), target_allowlist=("staging.invisable.co.uk",))


# --- signed authorization -----------------------------------------------------
def test_execute_requires_signature():
    req = ActionRequest(action="scan", target="staging.invisable.co.uk")
    with pytest.raises(ContractViolation):
        authorize_execution(SignedAuthorization(request=req, approver="ciso", signature=""))


def test_expired_authorization_is_refused():
    req = ActionRequest(action="scan", target="staging.invisable.co.uk")
    auth = SignedAuthorization(request=req, approver="ciso", signature="sig", expires_at=500)
    with pytest.raises(ContractViolation):
        authorize_execution(auth, now=1000)


def test_valid_authorization_passes():
    req = ActionRequest(action="scan", target="staging.invisable.co.uk")
    auth = SignedAuthorization(request=req, approver="ciso", signature="sig", expires_at=time() + 600)
    authorize_execution(auth)  # no raise


# --- a reference connector satisfies the Protocol -----------------------------
class _RefConnector:
    """Minimal contract-compliant connector used to prove the interface is implementable."""

    ACTIONS = ("baseline_scan",)
    BINARY = "/usr/bin/zap"
    ALLOW = ("staging.invisable.co.uk",)

    def inventory(self) -> ConnectorInventory:
        return ConnectorInventory("zap", "1.0", self.ACTIONS, self.BINARY, "execution")

    def validate_configuration(self) -> ValidationResult:
        return ValidationResult(ok=True)

    def calculate_plan(self, request: ActionRequest) -> ExecutionPlan:
        validate_request(request, allowed_actions=self.ACTIONS, target_allowlist=self.ALLOW)
        return ExecutionPlan(action=request.action, argv=(self.BINARY, "-t", request.target),
                             target=request.target, egress_allowlist=self.ALLOW)

    def required_permissions(self) -> list[Permission]:
        return [Permission("dast:staging")]

    def required_approvals(self) -> ApprovalPolicy:
        return ApprovalPolicy(required_actions=("baseline_scan",), min_reviewers=1)

    def execute(self, authorization: SignedAuthorization) -> ExecutionResult:
        authorize_execution(authorization)
        return ExecutionResult(action=authorization.request.action, returncode=0, output_hash="abc")

    def collect_evidence(self) -> EvidenceBundle:
        return EvidenceBundle(events=[{"action": "baseline_scan"}], signed=True)

    def cleanup(self) -> CleanupResult:
        return CleanupResult(destroyed=True)


def test_reference_connector_satisfies_protocol():
    c = _RefConnector()
    assert isinstance(c, GuardianConnector)


def test_reference_connector_refuses_raw_command_in_plan():
    c = _RefConnector()
    bad = ActionRequest(action="baseline_scan", target="staging.invisable.co.uk",
                        args={"command": "nmap evil.com"})
    with pytest.raises(ContractViolation):
        c.calculate_plan(bad)


def test_reference_connector_execute_refuses_unsigned():
    c = _RefConnector()
    req = ActionRequest(action="baseline_scan", target="staging.invisable.co.uk")
    with pytest.raises(ContractViolation):
        c.execute(SignedAuthorization(request=req, approver="ciso", signature=""))
