"""Gitleaks connector — secrets detection. Reports locations only; never exfiltrates."""

from __future__ import annotations

import json
from typing import Any

from .base import BaseConnector, ConnectorResult


class GitleaksConnector(BaseConnector):
    tool = "gitleaks"
    binary = "gitleaks"
    mode = "secrets_scan"
    action = "secrets_scan"
    ACTIONS = ("detect",)

    def build_command(self, *, repo: str | None = None, target: str | None = None, **kwargs: Any) -> list[str]:
        path = kwargs.get("path", ".")
        report = kwargs.get("report", "gitleaks-report.json")
        return [
            self.binary, "detect",
            "--source", path,
            "--config", "gitleaks/.gitleaks.toml",
            "--report-format", "json",
            "--report-path", report,
            "--redact",            # never write the secret value into the report
            "--no-banner",
        ]

    def parse(self, result: ConnectorResult) -> ConnectorResult:
        # gitleaks writes findings to the report file; surface a count from stdout if present.
        try:
            data = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return result
        for item in data if isinstance(data, list) else []:
            result.findings.append(
                {
                    "rule": item.get("RuleID"),
                    "file": item.get("File"),
                    "line": item.get("StartLine"),
                    "secret": "[REDACTED]",  # value is redacted at source via --redact
                }
            )
        return result
