"""CodeQL connector.

CodeQL primarily runs in CI via .github/workflows/codeql.yml. This connector supports
local database creation + analysis for an in-scope repo checkout when the CLI is present.
"""

from __future__ import annotations

from typing import Any

from .base import BaseConnector, ConnectorResult


class CodeQLConnector(BaseConnector):
    tool = "codeql"
    binary = "codeql"
    mode = "code_review"
    action = "code_review"

    def build_command(self, *, repo: str | None = None, target: str | None = None, **kwargs: Any) -> list[str]:
        # Single-step analysis entry point; CI uses the github/codeql-action instead.
        path = kwargs.get("path", ".")
        language = kwargs.get("language", "javascript")
        db = kwargs.get("db", "codeql/.codeql-db")
        sarif = kwargs.get("sarif", "codeql-results.sarif")
        return [
            self.binary, "database", "analyze", db,
            f"--language={language}",
            "--format=sarifv2.1.0",
            f"--output={sarif}",
            "--",
            f"codeql/codeql-suites/{language}-security-extended.qls",
        ]

    def parse(self, result: ConnectorResult) -> ConnectorResult:
        result.note = "CodeQL SARIF written; ingest via the Evidence Report agent."
        return result
