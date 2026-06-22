"""Base connector: a thin, dry-run-aware wrapper around an external security tool.

Connectors never act outside an approved scope. Every connector:
  * checks the relevant guardrail before running,
  * defaults to dry-run (prints the command it *would* run),
  * shells out with a fixed argument list (never an unescaped shell string),
  * returns a structured ConnectorResult.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

from core.audit import AuditLog
from core.guardrails import Guardrails
from core.scope import Scope


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
    """Subclass and set ``tool``/``mode``/``action``; implement :meth:`build_command`."""

    tool: str = "tool"
    binary: str = "tool"
    mode: str = "code_review"
    action: str = "code_review"

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
        # Gate: connectors operate only on in-scope, owned assets in an allowed mode.
        self.guardrails.assert_mode_allowed(self.mode)
        self.guardrails.assert_not_blocked(self.action)
        self.guardrails.assert_approved(self.action)
        if repo is not None:
            self.guardrails.assert_owned(repo=repo)
        if target is not None:
            self.guardrails.assert_owned(domain=target)

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
