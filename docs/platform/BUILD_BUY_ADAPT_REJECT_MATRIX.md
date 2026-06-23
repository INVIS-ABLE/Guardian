# Build / Buy / Adapt / Reject Matrix

*Phase 0 deliverable. Decision summary over the candidate catalogue
(`research/repositories/`). The authoritative, machine-readable form is
`research/repositories/decisions.yaml`; this is the human summary.*

> Metadata limitation: live GitHub metadata was unavailable, so licence/maturity
> confirmations are pending discovery (see the catalogue README). The integration
> decisions are architectural and stand on the project's category and purpose.

## Decision vocabulary

| Decision | Meaning |
|----------|---------|
| `retain` | Keep Guardian's existing component; the candidate adds nothing better. |
| `adopt` | Use the project directly (standard/format/library) — Guardian depends on it. |
| `adapt` | Wrap behind the connector contract as a replaceable worker. |
| `integrate` | First-party integration into the control plane. |
| `federate` | External system of record; Guardian stays the canonical authority. |
| `isolate` | Run as an isolated/sandboxed external service (high-risk/active). |
| `benchmark` | Use only as a test fixture / evaluation oracle. |
| `reference` | Architecture/research reference only; not wired in. |
| `defer` | Revisit later (e.g. pending licence or maturity). |
| `reject` | Do not use (offensive, unmaintained, conflicting, or unsafe). |

## Category defaults

| Category | Default | Why |
|----------|---------|-----|
| A — agentic/offensive | `reference` | High-risk; Guardian governs, never becomes an attack agent. |
| B — agent governance / MCP | `benchmark` | Compare with the policy gate; no second authority. |
| C — model security eval | `adapt` | Red-team / model-risk evaluators behind adapters. |
| D — SAST/SCA/DAST | `adapt` | The scanner-connector layer; scope-constrained. |
| E — runtime/detection | `adapt` (observe-only) | Containment is separately approved. |
| F — vuln mgmt / SIEM / TI | `federate` | Guardian owns the canonical finding. |
| G — policy/identity/secrets | `reference` | OPA stays the single authority; adopt gap-fillers only. |
| H — supply chain/signing | `adopt` | Verify origin/contents; preserve attestation chain. |
| I — sandboxing | `adopt` | Isolation tier by tool risk. |
| J — orchestration/GitOps | `reference` | Temporal retained; check licences. |
| K — telemetry/observability | `adopt` | Privacy-filtered, tenant-scoped. |
| L — standards/formats | `adopt` | Open formats over bespoke coupling. |
| M — curated lists | `reference` | Discovery only. |

## Notable per-candidate decisions

### Retain (Guardian already does this well)
OPA · Semgrep · CodeQL · Trivy · ZAP · OSV · Temporal · OpenTelemetry · Prometheus ·
Grafana · Loki · promptfoo · deepeval · ragas · oauth2-proxy.

### Adopt (depend on directly)
cosign · rekor · in-toto · SLSA · CycloneDX · SPDX · STIX2 schemas · SARIF spec ·
SPIFFE/SPIRE · OpenBao · Presidio · Firecracker · gVisor · bubblewrap · libseccomp ·
Sigma · YARA · ATT&CK data · Argo CD · OWASP ASVS/WSTG/SAMM/MASVS/MASTG.

### Adapt (wrap behind the connector contract)
garak · PyRIT · llm-guard · modelscan · Grype · Syft · TruffleHog · Nuclei · httpx ·
Checkov · Kubescape · kube-bench · Prowler · MobSF · Falco · Tetragon · osquery ·
Velociraptor · Cortex · MISP · OpenCTI · IntelOwl · mcp-scan · Scorecard · ORT ·
ScanCode · Langfuse · claude-code-security-review.

### Federate (Guardian stays canonical)
DefectDojo · TheHive.

### Isolate (high-risk/active; isolated tier, authorised targets only)
OpenVAS / gvmd · MITRE CALDERA.

### Defer
n8n *(non-OSI sustainable-use licence — commercial review)* · Windmill *(licence
review)* · subfinder / kube-hunter *(active discovery; owned/authorised assets only)* ·
SonarQube *(commercial-tier features)* · PySyft.

### Reject
PentAGI · pentestagent · hexstrike-ai · Pentest-Swarm-AI · 0xSteph/pentest-ai-agents ·
codexstar69/bug-hunter · 1N3/AttackSurfaceManagement *(uncontrolled offensive paths)*.

### Reference / benchmark
PentestGPT, OWASP appsec-agent/secure-agent-playbook, deterministic-agent-control-
protocol, agent-governance-toolkit (reference); PurpleLlama CybersecurityBenchmarks,
SEC-bench (benchmark); Cedar/Cerbos/OpenFGA (reference — no second policy authority);
all category-M awesome-lists (discovery only).

## Sequencing

These decisions feed `INTEGRATION_PRIORITY_ROADMAP.md` (follow-up). All integrations
land **behind the tenant + authorisation foundation** (Phases A–C), feature-flagged
and reversible, with the standard definition-of-done (pinned, SBOM'd, sandboxed,
egress-controlled, evidence-attributable, tested, rollback-tested).
