"""AI-agent boundary — the model recommends; the central policy decides.

Proves the "model may not" capabilities that are enforced as blocked actions are denied by
the central authority, and that policies/agent_boundary.yaml stays in sync with the code.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from core.guardrails import GuardrailViolation, Guardrails
from core.policy_gate import BLOCKED_ACTIONS, PolicyInput, decide

REPO_ROOT = Path(__file__).resolve().parents[1]
BOUNDARY_FILE = REPO_ROOT / "policies" / "agent_boundary.yaml"

AGENT_BLOCKED = {
    "expand_scope",
    "change_policy",
    "disable_logging",
    "merge_own_security_patch",
    "resolve_own_finding",
    "unrestricted_secret_access",
    "arbitrary_command_execution",
}


def _input(action: str) -> PolicyInput:
    return PolicyInput(
        actor="model", action=action, mode="code_review", environment="staging",
        ownership_verified=True, allowed_modes=["code_review"],
    )


@pytest.mark.parametrize("action", sorted(AGENT_BLOCKED))
def test_agent_action_is_globally_blocked(action):
    assert action in BLOCKED_ACTIONS


@pytest.mark.parametrize("action", sorted(AGENT_BLOCKED))
def test_agent_action_denied_by_policy_gate(action):
    decision = decide(_input(action))
    assert not decision.allow
    assert any(d == f"blocked_action:{action}" for d in decision.denies)


@pytest.mark.parametrize("action", sorted(AGENT_BLOCKED))
def test_guardrails_refuse_agent_action(staging_scope, action):
    with pytest.raises(GuardrailViolation):
        Guardrails(scope=staging_scope).assert_not_blocked(action)


def test_boundary_yaml_blocked_actions_match_code():
    data = yaml.safe_load(BOUNDARY_FILE.read_text(encoding="utf-8"))
    declared = {
        item["id"] for item in data["model_may_not"]
        if item.get("enforcement") == "blocked_action"
    }
    assert declared == AGENT_BLOCKED


def test_boundary_yaml_non_blocked_enforced_elsewhere():
    data = yaml.safe_load(BOUNDARY_FILE.read_text(encoding="utf-8"))
    other = {
        item["id"]: item["enforcement"] for item in data["model_may_not"]
        if item.get("enforcement") != "blocked_action"
    }
    # These are deliberately enforced by complementary controls, not blocked actions.
    assert other.get("approve_production") == "two_person_rule"
    assert other.get("execute_outside_connector") == "connector_contract"
