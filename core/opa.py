"""OPA policy-gate bridge.

Guardian's authorization rules live in two places that must agree:

  * ``core/guardrails.py`` — in-process Python enforcement (the source of truth at
    runtime), and
  * ``policies/opa/guardian.rego`` — a declarative twin evaluated by Open Policy
    Agent for defence-in-depth (CI, sidecar, or API boundary).

This module evaluates a decision request against the Rego policy when the ``opa``
binary is installed, and otherwise falls back to an equivalent in-Python decision so
the gate is *always* available and *always* fail-closed — never silently skipped.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import REPO_ROOT
from .guardrails import BLOCKED_ACTIONS, GLOBAL_APPROVAL_REQUIRED
from .scope import Scope

OPA_POLICY_DIR = REPO_ROOT / "policies" / "opa"
OPA_QUERY = "data.guardian.authz.decision"


@dataclass
class PolicyDecision:
    allow: bool
    deny: list[str] = field(default_factory=list)
    engine: str = "python-fallback"   # "opa" when the binary evaluated it

    def to_dict(self) -> dict[str, Any]:
        return {"allow": self.allow, "deny": self.deny, "engine": self.engine}


def build_input(
    scope: Scope,
    *,
    action: str,
    mode: str,
    approvals: list[str] | None = None,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the OPA decision input from a scope + requested action."""
    return {
        "action": action,
        "mode": mode,
        "scope": {
            "environment": scope.environment,
            "allowed_modes": scope.allowed_modes,
            "blocked_actions": scope.blocked_actions,
            "approval_required": scope.approval_required,
        },
        "approvals": approvals or [],
        "target": target,
    }


def evaluate(decision_input: dict[str, Any], *, policy_dir: Path = OPA_POLICY_DIR) -> PolicyDecision:
    """Evaluate a decision input against the Guardian policy.

    Uses the ``opa`` binary if available; otherwise applies the equivalent rules in
    Python so the policy gate is enforced regardless of environment.
    """
    if shutil.which("opa") is not None:
        try:
            return _evaluate_with_opa(decision_input, policy_dir)
        except Exception:
            # Any failure invoking OPA falls back to the in-Python twin (fail-closed),
            # rather than letting an action through unchecked.
            pass
    return _evaluate_in_python(decision_input)


def _evaluate_with_opa(decision_input: dict[str, Any], policy_dir: Path) -> PolicyDecision:
    proc = subprocess.run(  # noqa: S603
        ["opa", "eval", "-d", str(policy_dir), "-I", "-f", "json", OPA_QUERY],
        input=json.dumps(decision_input),
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(proc.stdout)
    value = data["result"][0]["expressions"][0]["value"]
    return PolicyDecision(
        allow=bool(value.get("allow", False)),
        deny=list(value.get("deny", [])),
        engine="opa",
    )


def _evaluate_in_python(decision_input: dict[str, Any]) -> PolicyDecision:
    """Faithful Python port of policies/opa/guardian.rego (fail-closed)."""
    action = decision_input.get("action", "")
    mode = decision_input.get("mode", "")
    scope = decision_input.get("scope", {})
    approvals = set(decision_input.get("approvals", []))
    target = decision_input.get("target")
    deny: list[str] = []

    if action in BLOCKED_ACTIONS:
        deny.append(f"action '{action}' is globally blocked")
    if action in set(scope.get("blocked_actions", [])):
        deny.append(f"action '{action}' is blocked by this scope")
    if mode not in set(scope.get("allowed_modes", [])):
        deny.append(f"mode '{mode}' is not in scope.allowed_modes")
    if scope.get("environment") == "production" and "production_scan" not in approvals:
        deny.append("production scope requires a recorded 'production_scan' approval")

    needs_approval = action in GLOBAL_APPROVAL_REQUIRED or action in set(
        scope.get("approval_required", [])
    )
    if needs_approval and action not in approvals:
        deny.append(f"action '{action}' requires a recorded human approval")

    if target is not None:
        if not target.get("in_scope"):
            deny.append(f"target {target} is not in scope")
        elif not target.get("owned"):
            deny.append(f"ownership of target {target} could not be verified")

    return PolicyDecision(allow=not deny, deny=deny, engine="python-fallback")
