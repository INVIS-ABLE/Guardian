"""Semgrep connector — static code security scanning."""

from __future__ import annotations

import json
from typing import Any

from .base import BaseConnector, ConnectorResult


class SemgrepConnector(BaseConnector):
    """Runs Semgrep against an in-scope, owned repo checkout."""

    tool = "semgrep"
    binary = "semgrep"
    mode = "code_review"
    action = "code_review"

    def build_command(self, *, repo: str | None = None, target: str | None = None, **kwargs: Any) -> list[str]:
        path = kwargs.get("path", ".")
        config = kwargs.get("config", "semgrep/semgrep.yml")
        return [
            self.binary, "scan",
            "--config", config,
            "--json",
            "--quiet",
            "--error",
            path,
        ]

    def parse(self, result: ConnectorResult) -> ConnectorResult:
        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return result
        for item in data.get("results", []):
            result.findings.append(
                {
                    "rule": item.get("check_id"),
                    "path": item.get("path"),
                    "line": item.get("start", {}).get("line"),
                    "severity": item.get("extra", {}).get("severity", "INFO"),
                    "message": item.get("extra", {}).get("message", ""),
                }
            )
        return result
