"""GitHub repo scanner — orchestrates the static/secret/dependency connectors over an
in-scope, owned repository checkout, and aggregates their findings.

This is the MVP "GitHub repo scanner": given a repo from the scope's allowed_repos and a
local checkout path, it runs Semgrep, Gitleaks, and Trivy (filesystem) and returns a
combined result. It never clones or scans anything outside the scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.guardrails import Guardrails
from core.scope import Scope

from .gitleaks import GitleaksConnector
from .semgrep import SemgrepConnector
from .trivy import TrivyConnector


@dataclass
class RepoScanReport:
    repo: str
    path: str
    results: dict[str, Any] = field(default_factory=dict)

    def total_findings(self) -> int:
        return sum(len(r.get("findings", [])) for r in self.results.values())


class RepoScanner:
    def __init__(self, scope: Scope, *, dry_run: bool = True, guardrails: Guardrails | None = None):
        self.scope = scope
        self.dry_run = dry_run
        self.guardrails = guardrails or Guardrails(scope=scope)

    def scan(self, repo: str, path: str = ".") -> RepoScanReport:
        # Single ownership/scope check up front; connectors re-check their own modes.
        self.guardrails.assert_owned(repo=repo)
        report = RepoScanReport(repo=repo, path=path)

        connectors = []
        if "code_review" in self.scope.allowed_modes:
            connectors.append(("semgrep", SemgrepConnector))
        if "secrets_scan" in self.scope.allowed_modes:
            connectors.append(("gitleaks", GitleaksConnector))
        if "dependency_scan" in self.scope.allowed_modes:
            connectors.append(("trivy", TrivyConnector))

        for key, cls in connectors:
            conn = cls(self.scope, dry_run=self.dry_run, guardrails=self.guardrails)
            res = conn.run(repo=repo, path=path)
            report.results[key] = res.to_dict()
        return report
