"""Trivy connector — filesystem / container / IaC / repo vulnerability scanning."""

from __future__ import annotations

import json
from typing import Any

from .base import BaseConnector, ConnectorResult


class TrivyConnector(BaseConnector):
    tool = "trivy"
    binary = "trivy"
    mode = "dependency_scan"
    action = "dependency_scan"
    ACTIONS = ("scan",)

    def build_command(self, *, repo: str | None = None, target: str | None = None, **kwargs: Any) -> list[str]:
        scan_type = kwargs.get("scan_type", "fs")  # fs | image | config | repo
        path = kwargs.get("path", ".")
        return [
            self.binary, scan_type,
            "--config", "trivy/trivy.yaml",
            "--format", "json",
            "--quiet",
            path,
        ]

    def parse(self, result: ConnectorResult) -> ConnectorResult:
        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return result
        for res in data.get("Results", []) or []:
            for vuln in res.get("Vulnerabilities", []) or []:
                result.findings.append(
                    {
                        "id": vuln.get("VulnerabilityID"),
                        "pkg": vuln.get("PkgName"),
                        "installed": vuln.get("InstalledVersion"),
                        "fixed": vuln.get("FixedVersion"),
                        "severity": vuln.get("Severity"),
                        "target": res.get("Target"),
                    }
                )
        return result
