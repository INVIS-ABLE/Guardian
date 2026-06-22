"""OWASP ZAP connector — controlled DAST via the ZAP Automation Framework.

Only runs against in-scope, owned staging domains, within the scope's rate limits.
Uses an Automation Framework plan (zap/staging-baseline.yaml) — never an ad-hoc,
uncontrolled active scan.
"""

from __future__ import annotations

from typing import Any

from .base import BaseConnector, ConnectorResult


class ZapConnector(BaseConnector):
    tool = "zap"
    binary = "zap.sh"
    mode = "zap_scan"
    action = "zap_scan"

    def run(self, *, repo: str | None = None, target: str | None = None, **kwargs: Any) -> ConnectorResult:
        # Belt-and-braces: ZAP must always have an explicit in-scope target domain.
        if target is None:
            target = self.scope.allowed_domains[0] if self.scope.allowed_domains else None
        if target is None:
            raise PermissionError("ZAP requires an in-scope target domain; none available.")
        return super().run(repo=repo, target=target, **kwargs)

    def build_command(self, *, repo: str | None = None, target: str | None = None, **kwargs: Any) -> list[str]:
        plan = kwargs.get("plan", "zap/staging-baseline.yaml")
        return [
            self.binary,
            "-cmd",
            "-autorun", plan,
        ]

    def parse(self, result: ConnectorResult) -> ConnectorResult:
        result.note = "ZAP plan executed; alerts exported per plan (zap/staging-baseline.yaml)."
        return result
