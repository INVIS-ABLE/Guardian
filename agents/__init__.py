"""The 17 Guardian ECC agents.

These are deliberately thin, auditable stubs for the MVP: each declares its role and
the guardrail-respecting work it will perform, and returns a structured result. They
are wired into ECC workflows (see docs/workflow.md). Concrete tool execution lives in
``connectors``; abuse scenarios live in ``simulators``. Agents orchestrate — they never
bypass ``core`` guardrails.
"""

from __future__ import annotations

from typing import Any

from .base import AgentContext, GuardianAgent


class GuardianPlannerAgent(GuardianAgent):
    """Plans a Guardian run from a scope file: which modes, agents, and order."""

    name = "guardian_planner"
    summary = "Builds the run plan (modes, agents, sequencing) from the active scope."

    def act(self) -> dict[str, Any]:
        plan = [m for m in self.scope.allowed_modes]
        return {"planned_modes": plan, "dry_run": self.context.dry_run}


class AssetScopeAgent(GuardianAgent):
    """Verifies asset ownership and that targets are in-scope before anything runs."""

    name = "asset_scope"
    summary = "Resolves and ownership-verifies in-scope assets; default-deny."

    def act(self) -> dict[str, Any]:
        for domain in self.scope.allowed_domains:
            self.guardrails.assert_owned(domain=domain)
        for repo in self.scope.allowed_repos:
            self.guardrails.assert_owned(repo=repo)
        return {"verified_domains": self.scope.allowed_domains,
                "verified_repos": self.scope.allowed_repos}


class ThreatModelAgent(GuardianAgent):
    """Maps the asset to likely threats (MITRE ATT&CK defensive mapping) + safeguarding."""

    name = "threat_model"
    summary = "Produces a defensive threat model and safeguarding risk map."

    def act(self) -> dict[str, Any]:
        return {"threat_model": "see policies/security_standards.md (ATT&CK mapping)",
                "safeguarding_focus": ["vulnerable_user", "grooming_risk", "harassment"]}


class CodeReviewAgent(GuardianAgent):
    """Drives static code security (CodeQL + Semgrep) over allowed repos."""

    name = "code_review"
    summary = "Runs CodeQL/Semgrep on in-scope repos; collects findings as evidence."

    def act(self) -> dict[str, Any]:
        return {"connectors": ["codeql", "semgrep"], "mode": "code_review"}


class DependencyAgent(GuardianAgent):
    """Dependency + supply-chain risk: OSV, Grype/Syft SBOM, Trivy, Dependabot signals."""

    name = "dependency"
    summary = "Assesses dependency and supply-chain risk; SBOM + vuln correlation."

    def act(self) -> dict[str, Any]:
        return {"connectors": ["osv", "syft", "grype", "trivy"], "mode": "dependency_scan"}


class SecretsAgent(GuardianAgent):
    """Secrets detection via Gitleaks/TruffleHog/detect-secrets over allowed repos."""

    name = "secrets"
    summary = "Scans for leaked secrets; never exfiltrates, only reports locations."

    def act(self) -> dict[str, Any]:
        return {"connectors": ["gitleaks"], "mode": "secrets_scan"}


class APISecurityAgent(GuardianAgent):
    """Dynamic API/app testing: ZAP, Schemathesis, Newman against owned staging."""

    name = "api_security"
    summary = "Controlled DAST/API fuzzing on staging within rate limits."

    def act(self) -> dict[str, Any]:
        return {"connectors": ["zap"], "mode": "api_security",
                "rate_limits": self.scope.rate_limits}


class AuthRBACAgent(GuardianAgent):
    """Auth/session/MFA and RBAC/ABAC permission-matrix testing with test accounts."""

    name = "auth_rbac"
    summary = "Validates authn/session/MFA and the role permission matrix."

    def act(self) -> dict[str, Any]:
        return {"mode": "auth_permissions", "accounts": self.scope.allowed_test_accounts}


class PrivacyGDPRAgent(GuardianAgent):
    """Privacy/GDPR: data-minimisation, redaction, export/erasure correctness."""

    name = "privacy_gdpr"
    summary = "Checks privacy/GDPR controls; drives the Privacy Leak Simulator."

    def act(self) -> dict[str, Any]:
        return {"mode": "privacy_leakage", "simulator": "privacy_leak"}


class SafeguardingAgent(GuardianAgent):
    """Safeguarding: protections for vulnerable users, grooming/harassment defences."""

    name = "safeguarding"
    summary = "Verifies safeguarding protections via Playwright journeys + simulators."

    def act(self) -> dict[str, Any]:
        return {"mode": "safeguarding",
                "journeys": "playwright/safeguarding.spec.ts",
                "simulators": ["moderator_abuse", "banned_user_return"]}


class AbuseSimulationAgent(GuardianAgent):
    """Runs the defensive simulator library against owned staging + test accounts."""

    name = "abuse_simulation"
    summary = "Executes simulators; collects detection/containment evidence."

    def act(self) -> dict[str, Any]:
        from simulators import REGISTRY
        return {"mode": "abuse_simulation", "available": sorted(REGISTRY)}


class RuntimeMonitoringAgent(GuardianAgent):
    """Correlates runtime signals (Falco/Wazuh/Prometheus/Loki) for detection."""

    name = "runtime_monitoring"
    summary = "Watches runtime telemetry; maps signals to the malware defence library."

    def act(self) -> dict[str, Any]:
        return {"signals": ["falco", "wazuh", "prometheus", "loki"],
                "library": "policies/malware_defence_library.yaml"}


class PatchProposalAgent(GuardianAgent):
    """Proposes fixes as a patch branch + regression tests. Never edits production."""

    name = "patch_proposal"
    summary = "Generates patch branch + tests; opens a draft PR only."

    def act(self) -> dict[str, Any]:
        return {"opens": "draft_pull_request", "direct_production_change": False}


class TestRunnerAgent(GuardianAgent):
    """Runs unit/integration/security/safeguarding test suites for a proposed fix."""

    name = "test_runner"
    summary = "Executes the full test gate before a fix can be reviewed."

    def act(self) -> dict[str, Any]:
        return {"suites": ["unit", "integration", "security", "safeguarding"]}


class EvidenceReportAgent(GuardianAgent):
    """Assembles the standard evidence report from findings + audit log."""

    name = "evidence_report"
    summary = "Renders evidence reports (reports/templates/report_template.md)."

    def act(self) -> dict[str, Any]:
        return {"template": "reports/templates/report_template.md",
                "output_dir": "reports/generated"}


class HumanApprovalAgent(GuardianAgent):
    """The human-in-the-loop gate. Never auto-approves; records the decision."""

    name = "human_approval"
    summary = "Routes high-impact actions and all PRs to a human; records approval."

    def act(self) -> dict[str, Any]:
        # This agent only *requests* approval; it cannot grant it itself.
        return {"auto_approve": False, "requires": "recorded human decision"}


class LearningMemoryAgent(GuardianAgent):
    """Feeds outcomes back into RAG memory so Guardian improves over time."""

    name = "learning_memory"
    summary = "Stores findings/outcomes in vector memory for future runs."

    def act(self) -> dict[str, Any]:
        return {"vector_db": "qdrant", "collections": ["threat_models", "policies"]}


REGISTRY: dict[str, type[GuardianAgent]] = {
    cls.name: cls
    for cls in (
        GuardianPlannerAgent,
        AssetScopeAgent,
        ThreatModelAgent,
        CodeReviewAgent,
        DependencyAgent,
        SecretsAgent,
        APISecurityAgent,
        AuthRBACAgent,
        PrivacyGDPRAgent,
        SafeguardingAgent,
        AbuseSimulationAgent,
        RuntimeMonitoringAgent,
        PatchProposalAgent,
        TestRunnerAgent,
        EvidenceReportAgent,
        HumanApprovalAgent,
        LearningMemoryAgent,
    )
}

__all__ = ["GuardianAgent", "AgentContext", "REGISTRY"]
