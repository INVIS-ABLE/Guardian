# Guardian agent inventory

The 17 ECC command agents (`agents/__init__.py`, registered in `agents.REGISTRY`).
They orchestrate; they never bypass `core` guardrails. Concrete tool execution lives
in `connectors`. This file is enforced by `tests/test_repo_inventory.py`.

| # | name | class | summary |
| --- | --- | --- | --- |
| 1 | `abuse_simulation` | AbuseSimulationAgent | Executes simulators; collects detection/containment evidence. |
| 2 | `api_security` | APISecurityAgent | Controlled DAST/API fuzzing on staging within rate limits. |
| 3 | `asset_scope` | AssetScopeAgent | Resolves and ownership-verifies in-scope assets; default-deny. |
| 4 | `auth_rbac` | AuthRBACAgent | Validates authn/session/MFA and the role permission matrix. |
| 5 | `code_review` | CodeReviewAgent | Runs CodeQL/Semgrep on in-scope repos; collects findings as evidence. |
| 6 | `dependency` | DependencyAgent | Assesses dependency and supply-chain risk; SBOM + vuln correlation. |
| 7 | `evidence_report` | EvidenceReportAgent | Renders evidence reports (reports/templates/report_template.md). |
| 8 | `guardian_planner` | GuardianPlannerAgent | Builds the run plan (modes, agents, sequencing) from the active scope. |
| 9 | `human_approval` | HumanApprovalAgent | Routes high-impact actions and all PRs to a human; reports approval. |
| 10 | `learning_memory` | LearningMemoryAgent | Stores findings/outcomes in vector memory for future runs. |
| 11 | `patch_proposal` | PatchProposalAgent | Generates patch branch + tests; opens a draft PR only. |
| 12 | `privacy_gdpr` | PrivacyGDPRAgent | Checks privacy/GDPR controls; drives the Privacy Leak Simulator. |
| 13 | `runtime_monitoring` | RuntimeMonitoringAgent | Watches runtime telemetry; maps signals to the malware defence library. |
| 14 | `safeguarding` | SafeguardingAgent | Verifies safeguarding protections via Playwright journeys + simulators. |
| 15 | `secrets` | SecretsAgent | Scans for leaked secrets; never exfiltrates, only reports locations. |
| 16 | `test_runner` | TestRunnerAgent | Executes the full test gate before a fix can be reviewed. |
| 17 | `threat_model` | ThreatModelAgent | Produces a defensive threat model and safeguarding risk map. |
