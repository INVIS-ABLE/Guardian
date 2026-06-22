"""OPA / embedded-evaluator parity.

The external OPA authority (policies/opa/guardian.rego) and the in-process mirror
(core/policy_gate.decide) must agree on every decision. This test runs the same inputs
through both and asserts identical allow/deny — it is the gate that keeps the twin honest.

Skipped automatically when the ``opa`` binary + bundle are not available (e.g. local dev
without OPA); the OPA-policy CI job sets GUARDIAN_USE_OPA=1 and installs opa so it runs.
"""

from __future__ import annotations

import pytest

from core.policy_gate import PolicyInput, _decide_via_opa, _opa_available, decide

pytestmark = pytest.mark.skipif(not _opa_available(), reason="opa binary/bundle not available")

# A matrix spanning the rule space: allow, blocked, mode, ownership, approvals, production.
CASES = [
    PolicyInput(actor="a", action="code_review", mode="code_review", environment="staging",
                ownership_verified=True, allowed_modes=["code_review"]),
    PolicyInput(actor="a", action="hack_back", mode="code_review", environment="staging",
                ownership_verified=True, allowed_modes=["code_review"]),
    PolicyInput(actor="a", action="decrypt_private_content", mode="code_review",
                environment="staging", ownership_verified=True, allowed_modes=["code_review"]),
    PolicyInput(actor="a", action="change_policy", mode="code_review", environment="staging",
                ownership_verified=True, allowed_modes=["code_review"]),
    PolicyInput(actor="a", action="api_security", mode="api_security", environment="staging",
                ownership_verified=True, allowed_modes=["code_review"]),
    PolicyInput(actor="a", action="code_review", mode="code_review", environment="staging",
                domain="staging.invisable.co.uk", ownership_verified=False,
                allowed_modes=["code_review"]),
    PolicyInput(actor="a", action="code_review", mode="code_review", environment="production",
                ownership_verified=True, allowed_modes=["code_review"],
                approval_required=["production_scan"]),
]


@pytest.mark.parametrize("inp", CASES)
def test_opa_matches_embedded(inp):
    embedded = decide(inp)
    opa = _decide_via_opa(inp)
    assert opa.allow == embedded.allow, (
        f"OPA/embedded disagree for action={inp.action!r}: "
        f"opa={opa.allow} ({opa.denies}) vs embedded={embedded.allow} ({embedded.denies})"
    )
