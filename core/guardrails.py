"""Guardrails — the single central authorization path (GUARDRAILS.md, enforced in code).

Every connector, simulator, and agent passes its intended action through ``authorize()``,
which builds a :class:`~core.policy_gate.PolicyInput` and asks the central policy
(:func:`core.policy_gate.evaluate` — OPA when wired, else the embedded mirror) for ONE
decision. There is no ``allow_production`` escape parameter: production is permitted only by
two distinct, unexpired ``production_scan`` approvals. Denied actions are audited too.

CLI:
    python -m core.guardrails check scope/invisable-staging.yaml
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from time import time
from typing import Iterable

from .audit import AuditLog
from .policy_gate import (
    BLOCKED_ACTIONS,
    GLOBAL_APPROVAL_REQUIRED,
    PRODUCTION_MIN_REVIEWERS,
    ApprovalLite,
    PolicyInput,
    evaluate,
)
from .scope import Scope, domain_is_in_scope, load_scope, repo_is_in_scope

__all__ = [
    "BLOCKED_ACTIONS",
    "GLOBAL_APPROVAL_REQUIRED",
    "GuardrailViolation",
    "Approval",
    "Guardrails",
    "check_scope",
]


class GuardrailViolation(PermissionError):
    """Raised when an action would breach a control gate. Always fail closed."""


@dataclass
class Approval:
    """A recorded human approval for a specific approval-gated action.

    Approvals are action-bound and *expire*: an approval granted months ago must not
    confer permanent authority (acceptance-gate: approvals expire). ``commit`` and
    ``workflow_run`` bind an approval to a specific change/run when supplied.
    """

    action: str
    approver: str
    ticket: str  # issue/PR/incident reference — evidence of the decision
    note: str = ""
    expires_at: float | None = None  # epoch seconds; None = no expiry (discouraged)
    commit: str | None = None
    workflow_run: str | None = None

    def valid(self, now: float | None = None) -> bool:
        now = time() if now is None else now
        return self.expires_at is None or now < self.expires_at

    def _lite(self) -> ApprovalLite:
        return ApprovalLite(action=self.action, approver=self.approver, expires_at=self.expires_at)


@dataclass
class Guardrails:
    """Stateful gate bound to one scope + recorded approvals. ``authorize()`` is the path."""

    scope: Scope
    approvals: list[Approval] = field(default_factory=list)
    # Ownership verifier: callable(kind, target) -> bool. Defaults to scope membership.
    # In production this is backed by real DNS-TXT / GitHub-App ownership checks (which
    # themselves expire — see docs/authorization.md).
    ownership_verifier: object | None = None
    actor: str = "guardian"
    audit: AuditLog = field(default_factory=AuditLog)

    # --- the single authorization path -----------------------------------------
    def authorize(
        self,
        *,
        mode: str,
        action: str,
        domain: str | None = None,
        repo: str | None = None,
        test_account: str | None = None,
        commit: str | None = None,
        workflow_run: str | None = None,
    ) -> None:
        """Ask the central policy for one decision. Raises GuardrailViolation if denied.

        Connectors/agents/simulators MUST NOT decide authorization themselves — they call
        this. Denials are recorded in the audit log as evidence.
        """
        ownership_ok = self._ownership_ok(domain=domain, repo=repo)
        decision = evaluate(
            PolicyInput(
                actor=self.actor,
                action=action,
                mode=mode,
                environment=self.scope.environment,
                domain=domain,
                repo=repo,
                test_account=test_account,
                ownership_verified=ownership_ok,
                allowed_modes=self.scope.allowed_modes,
                blocked_actions=self.scope.blocked_actions,
                approval_required=self.scope.approval_required,
                allowed_test_accounts=self.scope.allowed_test_accounts,
                approvals=[a._lite() for a in self.approvals],
                commit=commit,
                workflow_run=workflow_run,
            )
        )
        if not decision.allow:
            self._audit_denial(action=action, mode=mode, reasons=decision.denies)
            raise GuardrailViolation(
                f"Action '{action}' denied by policy: {decision.reason()}"
            )

    def record_approval(self, approval: Approval) -> None:
        self.approvals.append(approval)

    # --- granular checks (kept for ergonomic sub-checks; all consistent with policy) ----
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

    def assert_environment(self) -> None:
        """Production requires PRODUCTION_MIN_REVIEWERS distinct, unexpired approvals."""
        if self.scope.is_production():
            approvers = {
                a.approver for a in self.approvals if a.action == "production_scan" and a.valid()
            }
            if len(approvers) < PRODUCTION_MIN_REVIEWERS:
                raise GuardrailViolation(
                    f"Production requires {PRODUCTION_MIN_REVIEWERS} distinct approvers for "
                    f"'production_scan'; found {len(approvers)}. Refusing."
                )

    def assert_test_account(self, account: str) -> None:
        if account not in self.scope.allowed_test_accounts:
            raise GuardrailViolation(
                f"Account '{account}' is not an allowed test account. "
                "Guardian only ever uses registered test accounts — never real users."
            )

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

    def assert_approved(self, action: str) -> None:
        gated = action in GLOBAL_APPROVAL_REQUIRED or action in set(self.scope.approval_required)
        if not gated:
            return
        if not any(a.action == action and a.valid() for a in self.approvals):
            raise GuardrailViolation(
                f"Action '{action}' requires a valid recorded human approval. None found."
            )

    # --- internals -------------------------------------------------------------
    def _ownership_ok(self, *, domain: str | None, repo: str | None) -> bool:
        ok = True
        if domain is not None:
            ok = ok and domain_is_in_scope(self.scope, domain) and self._verify_ownership(
                "domain", domain
            )
        if repo is not None:
            ok = ok and repo_is_in_scope(self.scope, repo) and self._verify_ownership("repo", repo)
        return ok

    def _verify_ownership(self, kind: str, target: str) -> bool:
        if self.ownership_verifier is not None:
            return bool(self.ownership_verifier(kind, target))  # type: ignore[operator]
        if kind == "domain":
            return domain_is_in_scope(self.scope, target)
        if kind == "repo":
            return repo_is_in_scope(self.scope, target)
        return False

    def _audit_denial(self, *, action: str, mode: str, reasons: list[str]) -> None:
        try:
            self.audit.record(
                f"authorize:deny:{action}",
                actor=self.actor,
                scope=self.scope.asset,
                decision="denied",
                detail={"mode": mode, "reasons": reasons},
            )
        except Exception:  # pragma: no cover - auditing must never crash enforcement
            pass


def check_scope(scope: Scope) -> list[str]:
    """Static sanity checks on a scope file. Returns a list of human-readable notes."""
    notes: list[str] = []
    overlap = BLOCKED_ACTIONS & set(scope.allowed_modes)
    if overlap:
        notes.append(f"WARNING: blocked actions appear in allowed_modes: {sorted(overlap)}")
    if scope.is_production() and "production_scan" not in scope.approval_required:
        notes.append("WARNING: production scope without 'production_scan' in approval_required.")
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
    _print(notes if notes else ["  No warnings. Guardrails consistent."])
    print(f"  Globally blocked actions enforced: {', '.join(sorted(BLOCKED_ACTIONS))}")
    print("  Authorization authority: core.policy_gate.evaluate (OPA mirror)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
