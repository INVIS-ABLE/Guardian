# Guardian Agents (ECC)

Seventeen bounded, auditable agents. Each declares its role and performs only
guardrail-respecting work. Agents orchestrate; enforcement lives in `core`.

| # | Agent | Role |
|---|-------|------|
| 1 | **Guardian Planner** | Builds the run plan (modes, agents, sequencing) from the active scope. |
| 2 | **Asset Scope** | Resolves and ownership-verifies in-scope assets; default-deny. |
| 3 | **Threat Model** | Produces a defensive threat model + safeguarding risk map (MITRE ATT&CK, defensive). |
| 4 | **Code Review** | Runs CodeQL + Semgrep over allowed repos. |
| 5 | **Dependency** | Dependency/supply-chain risk: OSV, Syft/Grype SBOM, Trivy. |
| 6 | **Secrets** | Gitleaks/TruffleHog/detect-secrets; reports locations only. |
| 7 | **API Security** | Controlled DAST/API fuzzing (ZAP/Schemathesis/Newman) on staging. |
| 8 | **Auth/RBAC** | Authn/session/MFA + RBAC/ABAC permission-matrix testing with test accounts. |
| 9 | **Privacy/GDPR** | Data-minimisation, redaction, export/erasure; drives Privacy Leak Simulator. |
| 10 | **Safeguarding** | Vulnerable-user protections; Playwright journeys + safeguarding simulators. |
| 11 | **Abuse Simulation** | Runs the defensive simulator library. |
| 12 | **Runtime Monitoring** | Correlates Falco/Wazuh/Prometheus/Loki signals to the malware defence library. |
| 13 | **Patch Proposal** | Generates patch branch + regression tests; opens a *draft* PR only. |
| 14 | **Test Runner** | Runs unit/integration/security/safeguarding suites for a proposed fix. |
| 15 | **Evidence Report** | Assembles the standard evidence report from findings + audit log. |
| 16 | **Human Approval** | The human-in-the-loop gate. Never auto-approves; records the decision. |
| 17 | **Learning Memory** | Feeds outcomes back into RAG memory for future runs. |

All agents are registered in `agents.REGISTRY` and share `agents.base.GuardianAgent`,
which provides the audit hook and the guardrails handle. See `agents/__init__.py`.

## Invariants

- No agent can grant its own approval; only the **Human Approval** agent routes to a
  human, and it returns `auto_approve: False`.
- **Patch Proposal** never edits production — it opens draft pull requests only.
- Every agent run is bracketed by `agent:<name>:start` / `:complete` audit entries.
