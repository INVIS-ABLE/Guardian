"""Base connector: a thin, dry-run-aware wrapper around an external security tool.

Connectors never act outside an approved scope. Every connector:
  * checks the relevant guardrail before running,
  * defaults to dry-run (prints the command it *would* run),
  * shells out with a fixed argument list (never an unescaped shell string),
  * returns a structured ConnectorResult.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

from core.audit import AuditLog
from core.guardrails import Guardrails
from core.policy_gate import GLOBAL_APPROVAL_REQUIRED
from core.scope import Scope

from .contract import (
    ActionRequest,
    ApprovalPolicy,
    CleanupResult,
    ConnectorInventory,
    EvidenceBundle,
    ExecutionPlan,
    ExecutionResult,
    Permission,
    SignedAuthorization,
    ValidationResult,
    authorize_execution,
    validate_request,
)


@dataclass
class ConnectorResult:
    tool: str
    command: list[str]
    dry_run: bool
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "command": self.command,
            "dry_run": self.dry_run,
            "returncode": self.returncode,
            "findings": self.findings,
            "note": self.note,
        }


class BaseConnector:
    """Subclass and set ``tool``/``mode``/``action``; implement :meth:`build_command`.

    Implements the :class:`~connectors.contract.GuardianConnector` lifecycle so every
    scanner is driven through the one typed contract — enumerated actions, allowlisted
    targets, and signed-authorization execution — not ad-hoc shell-outs.
    """

    tool: str = "tool"
    binary: str = "tool"
    mode: str = "code_review"
    action: str = "code_review"
    version: str = "0.1.0"
    trust_zone: str = "execution"
    #: enumerated actions this connector will perform (the contract's allowlist). Defaults
    #: to the single guardrail action label; scanners may override with richer verbs.
    ACTIONS: tuple[str, ...] = ()

    def __init__(self, scope: Scope, *, dry_run: bool = True, guardrails: Guardrails | None = None):
        self.scope = scope
        self.dry_run = dry_run
        self.guardrails = guardrails or Guardrails(scope=scope)
        self.audit = AuditLog()

    def build_command(self, **kwargs: Any) -> list[str]:  # pragma: no cover - abstract
        raise NotImplementedError

    def parse(self, result: ConnectorResult) -> ConnectorResult:
        """Override to populate ``findings`` from tool output."""
        return result

    def run(self, *, repo: str | None = None, target: str | None = None, **kwargs: Any) -> ConnectorResult:
        # Connectors never decide authorization themselves — one central policy call.
        self.guardrails.authorize(
            mode=self.mode, action=self.action, domain=target, repo=repo
        )

        command = self.build_command(repo=repo, target=target, **kwargs)
        result = ConnectorResult(tool=self.tool, command=command, dry_run=self.dry_run)

        self.audit.record(
            f"connector:{self.tool}:run", actor="connector", scope=self.scope.asset,
            decision="allowed", detail={"dry_run": self.dry_run, "command": command},
        )

        if self.dry_run:
            result.note = "dry-run: command not executed"
            return result

        if shutil.which(self.binary) is None:
            result.note = f"{self.binary} not installed; skipped (use the docker-compose stack/CI)"
            result.returncode = None
            return result

        proc = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
        result.returncode = proc.returncode
        result.stdout = proc.stdout
        result.stderr = proc.stderr
        return self.parse(result)

    # --- GuardianConnector contract -------------------------------------------------------
    # The 8-method lifecycle from connectors/contract.py. ``run`` remains the low-level
    # execution path; these methods wrap it in the typed, allowlisted, signed contract.
    @property
    def actions(self) -> tuple[str, ...]:
        return self.ACTIONS or (self.action,)

    def _target_allowlist(self) -> tuple[str, ...]:
        return tuple(self.scope.allowed_domains) + tuple(self.scope.allowed_repos)

    def inventory(self) -> ConnectorInventory:
        return ConnectorInventory(
            connector=self.tool, version=self.version, actions=self.actions,
            fixed_binary=self.binary, trust_zone=self.trust_zone,
        )

    def validate_configuration(self) -> ValidationResult:
        notes: list[str] = []
        if not self.actions:
            notes.append("no enumerated actions declared")
        if shutil.which(self.binary) is None:
            notes.append(f"{self.binary} not installed (CI/docker-compose provides it)")
        return ValidationResult(ok=not any("no enumerated" in n for n in notes), notes=notes)

    def calculate_plan(self, request: ActionRequest) -> ExecutionPlan:
        # Gate the request on enumerated actions + allowlisted target (rejects raw commands).
        validate_request(
            request, allowed_actions=self.actions, target_allowlist=self._target_allowlist()
        )
        command = self.build_command(repo=request.repo, target=request.target, **request.args)
        return ExecutionPlan(
            action=request.action, argv=tuple(command), target=request.target,
            egress_allowlist=self._target_allowlist(),
        )

    def required_permissions(self) -> list[Permission]:
        return [Permission(f"{self.mode}:{self.scope.environment}")]

    def required_approvals(self) -> ApprovalPolicy:
        gated = self.action in GLOBAL_APPROVAL_REQUIRED or self.action in set(
            self.scope.approval_required
        )
        return ApprovalPolicy(required_actions=(self.action,) if gated else (), min_reviewers=1)

    def execute(self, authorization: SignedAuthorization) -> ExecutionResult:
        # Execution requires a present, unexpired, signed authorization for the request.
        authorize_execution(authorization)
        req = authorization.request
        result = self.run(repo=req.repo, target=req.target, **req.args)
        output_hash = hashlib.sha256((result.stdout or "").encode("utf-8")).hexdigest()
        return ExecutionResult(
            action=req.action, returncode=result.returncode, output_hash=output_hash,
        )

    def collect_evidence(self) -> EvidenceBundle:
        return EvidenceBundle(events=[{"connector": self.tool, "mode": self.mode}], signed=False)

    def cleanup(self) -> CleanupResult:
        # Stateless scanner wrappers hold no persistent execution environment to destroy.
        return CleanupResult(destroyed=True, notes="stateless connector; nothing to clean up")
