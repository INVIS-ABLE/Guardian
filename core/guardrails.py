"""Guardrails — the mandatory control gates from GUARDRAILS.md, enforced in code.

Every connector, simulator, and agent must pass its intended action through a
``Guardrails`` instance before acting. The gates are default-deny and fail closed.

CLI:
    python -m core.guardrails check scope/invisable-staging.yaml
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Iterable

from .scope import Scope, domain_is_in_scope, load_scope, repo_is_in_scope

# Globally blocked actions — always denied, in every mode and scope. These mirror
# GUARDRAILS.md section 2 and cannot be re-enabled by a scope file.
BLOCKED_ACTIONS: frozenset[str] = frozenset(
    {
        "third_party_scan",
        "real_user_data_access",
        "credential_theft",
        "stealth",
        "persistence",
        "exploit_deployment",
        "hack_back",
        "destructive_testing",
    }
)

# Actions that always require a recorded human approval (GUARDRAILS.md section 3),
# in addition to anything a scope file lists under approval_required.
GLOBAL_APPROVAL_REQUIRED: frozenset[str] = frozenset(
    {
        "production_scan",
        "high_volume_test",
        "account_locking_test",
        "data_export_test",
        "admin_permission_test",
    }
)


class GuardrailViolation(PermissionError):
    """Raised when an action would breach a control gate. Always fail closed."""


@dataclass
class Approval:
    """A recorded human approval for a specific approval-gated action."""

    action: str
    approver: str
    ticket: str  # issue/PR/incident reference — evidence of the decision
    note: str = ""


@dataclass
class Guardrails:
    """Stateful gate checker bound to one scope and a set of recorded approvals."""

    scope: Scope
    approvals: list[Approval] = field(default_factory=list)
    # Ownership verifier: callable(kind, target) -> bool. Defaults to scope membership.
    # In production this is backed by real DNS TXT / GitHub ownership checks.
    ownership_verifier: object | None = None

    # --- scope gates -----------------------------------------------------------
    def assert_owned(self, *, domain: str | None = None, repo: str | None = None) -> None:
        if domain is not None:
            if not domain_is_in_scope(self.scope, domain):
                raise GuardrailViolation(
                    f"Domain '{domain}' is not in scope (allowed: {self.scope.allowed_domains})."
                )
            if not self._verify_ownership("domain", domain):
                raise GuardrailViolation(
                    f"Ownership of domain '{domain}' could not be verified — refusing."
                )
        if repo is not None:
            if not repo_is_in_scope(self.scope, repo):
                raise GuardrailViolation(
                    f"Repo '{repo}' is not in scope (allowed: {self.scope.allowed_repos})."
                )
            if not self._verify_ownership("repo", repo):
                raise GuardrailViolation(
                    f"Ownership of repo '{repo}' could not be verified — refusing."
                )

    def assert_environment(self, *, allow_production: bool = False) -> None:
        if self.scope.is_production() and not allow_production:
            raise GuardrailViolation(
                "Scope targets production; production runs require an approved "
                "'production_scan' approval. Refusing by default."
            )

    def assert_test_account(self, account: str) -> None:
        if account not in self.scope.allowed_test_accounts:
            raise GuardrailViolation(
                f"Account '{account}' is not an allowed test account. "
                "Guardian only ever uses registered test accounts — never real users."
            )

    # --- behaviour gates -------------------------------------------------------
    def assert_mode_allowed(self, mode: str) -> None:
        if mode not in self.scope.allowed_modes:
            raise GuardrailViolation(
                f"Mode '{mode}' is not permitted by this scope "
                f"(allowed: {self.scope.allowed_modes})."
            )

    def assert_not_blocked(self, action: str) -> None:
        if action in BLOCKED_ACTIONS or action in set(self.scope.blocked_actions):
            raise GuardrailViolation(
                f"Action '{action}' is blocked and can never be performed by Guardian."
            )

    # --- approval gate ---------------------------------------------------------
    def assert_approved(self, action: str) -> None:
        gated = action in GLOBAL_APPROVAL_REQUIRED or action in set(self.scope.approval_required)
        if not gated:
            return
        if not any(a.action == action for a in self.approvals):
            raise GuardrailViolation(
                f"Action '{action}' requires a recorded human approval. None found — refusing."
            )

    def record_approval(self, approval: Approval) -> None:
        self.approvals.append(approval)

    # --- composite -------------------------------------------------------------
    def authorize(
        self,
        *,
        mode: str,
        action: str,
        domain: str | None = None,
        repo: str | None = None,
        test_account: str | None = None,
        allow_production: bool = False,
    ) -> None:
        """Run the full gate sequence. Raises GuardrailViolation on any failure."""
        self.assert_environment(allow_production=allow_production)
        self.assert_mode_allowed(mode)
        self.assert_not_blocked(action)
        if domain is not None or repo is not None:
            self.assert_owned(domain=domain, repo=repo)
        if test_account is not None:
            self.assert_test_account(test_account)
        self.assert_approved(action)

    # --- internals -------------------------------------------------------------
    def _verify_ownership(self, kind: str, target: str) -> bool:
        if self.ownership_verifier is not None:
            return bool(self.ownership_verifier(kind, target))  # type: ignore[operator]
        # Default verifier: scope membership is treated as the asserted ownership.
        # Real deployments inject a DNS-TXT / GitHub-ownership verifier here.
        if kind == "domain":
            return domain_is_in_scope(self.scope, target)
        if kind == "repo":
            return repo_is_in_scope(self.scope, target)
        return False


def check_scope(scope: Scope) -> list[str]:
    """Static sanity checks on a scope file. Returns a list of human-readable notes."""
    notes: list[str] = []
    # Ensure the globally blocked actions aren't accidentally listed as allowed modes.
    overlap = BLOCKED_ACTIONS & set(scope.allowed_modes)
    if overlap:
        notes.append(f"WARNING: blocked actions appear in allowed_modes: {sorted(overlap)}")
    if scope.is_production() and "production_scan" not in scope.approval_required:
        notes.append(
            "WARNING: production scope without 'production_scan' in approval_required."
        )
    if not scope.allowed_test_accounts:
        notes.append("WARNING: no test accounts declared — most active tests will be denied.")
    return notes


def _print(lines: Iterable[str]) -> None:
    for line in lines:
        print(line)


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) < 2 or argv[0] != "check":
        print("usage: python -m core.guardrails check <scope_file>")
        return 2
    scope = load_scope(argv[1])
    print(f"Scope OK: asset={scope.asset} env={scope.environment} owner={scope.owner}")
    print(f"  modes:    {', '.join(scope.allowed_modes)}")
    print(f"  domains:  {', '.join(scope.allowed_domains)}")
    print(f"  accounts: {', '.join(scope.allowed_test_accounts)}")
    notes = check_scope(scope)
    if notes:
        _print(notes)
    else:
        print("  No warnings. Guardrails consistent.")
    print(f"  Globally blocked actions enforced: {', '.join(sorted(BLOCKED_ACTIONS))}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
