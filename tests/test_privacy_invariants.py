"""Privacy Fabric invariants — Guardian is the protector of the crypto system, never a
reader inside it. These tests prove the "Guardian must never" boundary is enforced by the
central policy authority and stays in sync with policies/privacy_invariants.yaml.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from core.guardrails import GuardrailViolation, Guardrails
from core.policy_gate import BLOCKED_ACTIONS, PolicyInput, decide, evaluate

REPO_ROOT = Path(__file__).resolve().parents[1]
INVARIANTS_FILE = REPO_ROOT / "policies" / "privacy_invariants.yaml"

PRIVACY_BLOCKED = {
    "decrypt_private_content",
    "access_message_plaintext",
    "copy_private_content_to_memory",
    "send_private_content_to_model",
    "store_decryption_keys",
    "silent_moderation_participant",
    "create_master_access_key",
    "plaintext_in_observability",
    "train_on_user_content",
}


def _input(action: str) -> PolicyInput:
    # A maximally-permissive-looking request: in-scope mode, ownership verified, etc.
    # The privacy invariant must still deny it because the ACTION is globally blocked.
    return PolicyInput(
        actor="guardian",
        action=action,
        mode="code_review",
        environment="staging",
        ownership_verified=True,
        allowed_modes=["code_review"],
    )


@pytest.mark.parametrize("action", sorted(PRIVACY_BLOCKED))
def test_privacy_action_is_globally_blocked(action):
    assert action in BLOCKED_ACTIONS


@pytest.mark.parametrize("action", sorted(PRIVACY_BLOCKED))
def test_privacy_action_denied_by_policy_gate(action):
    decision = decide(_input(action))
    assert not decision.allow
    assert any(d == f"blocked_action:{action}" for d in decision.denies)


@pytest.mark.parametrize("action", sorted(PRIVACY_BLOCKED))
def test_privacy_action_denied_via_evaluate(action):
    # evaluate() is the single entry point (OPA when wired, else the embedded mirror).
    assert not evaluate(_input(action)).allow


@pytest.mark.parametrize("action", sorted(PRIVACY_BLOCKED))
def test_guardrails_refuse_privacy_action(staging_scope, action):
    gr = Guardrails(scope=staging_scope)
    with pytest.raises(GuardrailViolation):
        gr.assert_not_blocked(action)


def test_invariants_yaml_matches_blocked_actions():
    data = yaml.safe_load(INVARIANTS_FILE.read_text(encoding="utf-8"))
    declared = {item["id"] for item in data["guardian_must_never"]}
    # The YAML's never-list and the code's privacy blocks must be exactly the same set —
    # documentation and enforcement cannot drift apart.
    assert declared == PRIVACY_BLOCKED


def test_verifier_never_reads_private_content():
    data = yaml.safe_load(INVARIANTS_FILE.read_text(encoding="utf-8"))
    never = set(data["guardian_verifier"]["never_reads"])
    assert {"message_plaintext", "media_plaintext", "conversation_keys"} <= never
