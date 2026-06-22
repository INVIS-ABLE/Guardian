"""Guardian connectors — dry-run-aware wrappers around security tooling.

Each connector enforces guardrails before invoking its tool and returns a structured
``ConnectorResult``. Tools themselves are installed via the docker-compose stack / CI,
not bundled here.
"""

from __future__ import annotations

from .base import BaseConnector, ConnectorResult
from .codeql import CodeQLConnector
from .credential_audit import HashcatConnector, HydraConnector, JohnConnector
from .gitleaks import GitleaksConnector
from .repo_scanner import RepoScanner
from .semgrep import SemgrepConnector
from .trivy import TrivyConnector
from .zap import ZapConnector

REGISTRY: dict[str, type[BaseConnector]] = {
    c.tool: c
    for c in (
        CodeQLConnector,
        SemgrepConnector,
        GitleaksConnector,
        TrivyConnector,
        ZapConnector,
        # Credential-audit connectors — authorised defensive use only, approval-gated.
        HashcatConnector,
        JohnConnector,
        HydraConnector,
    )
}

__all__ = [
    "BaseConnector",
    "ConnectorResult",
    "CodeQLConnector",
    "SemgrepConnector",
    "GitleaksConnector",
    "TrivyConnector",
    "ZapConnector",
    "HashcatConnector",
    "JohnConnector",
    "HydraConnector",
    "RepoScanner",
    "REGISTRY",
]
