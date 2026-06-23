# Competitor & Open-Source Landscape

*Phase 0 deliverable. Narrative companion to the machine-readable catalogue in
`research/repositories/`. See that directory's README for the honesty limitation
(no live GitHub metadata was available; quantitative fields are marked pending
discovery, never fabricated).*

## How to read this

The brief lists ~200 candidate repositories across 13 categories. They are a
**research catalogue, not an installation list**. For each, Guardian independently
decides: retain / adopt / adapt / integrate / federate / isolate / benchmark /
reference / defer / reject. The decisions below are architectural judgements from
each project's category and purpose; numeric metadata (commits, releases, exact
licences) must be confirmed by live discovery before any integration.

## Landscape by category

### A — Agentic / autonomous offensive security
Strix, PentestGPT, PentAGI, hexstrike-ai, Pentest-Swarm-AI and similar demonstrate
autonomous offensive capability. **Guardian's posture: study, do not adopt.** These
are `reference` or `reject`. Guardian is the *control plane* that governs tools; an
unrestricted attack agent is the exact thing the charter forbids (rules 5–7). The
defensible borrowings are *architectural*: how they plan, validate, and sandbox.
Defensive outliers — `anthropics/claude-code-security-review`, OWASP
`secure-agent-playbook` — are `adapt`/`reference`.

### B — Agent governance, control planes, MCP security
This is Guardian's own problem space. `mcp-scan` (invariantlabs) and MCP-firewall
projects are the most relevant: candidate **adapters** for hardening Guardian's MCP
broker against tool poisoning / rug pulls. The rest are `benchmark`/`reference` —
Guardian must not stand up a *second* control authority beside its policy gate.

### C — AI / LLM / model security evaluation
Strong fit with `eval/` and the untrusted-output gateway. `garak`, `PyRIT`,
`llm-guard`, `modelscan` are candidate **adapters** (model red-team, I/O guardrail,
model-serialization admission). `promptfoo`, `deepeval`, `ragas` are already in
Guardian's eval tooling — `retain`.

### D — SAST / SCA / SBOM / DAST
The core scanner-connector layer. Semgrep, CodeQL, Trivy, ZAP, OSV are **already
Guardian connectors** (`retain`); Grype, Syft, TruffleHog, Nuclei, Checkov,
Kubescape, Prowler, MobSF are `adapt` behind the same contract — scope-constrained,
rate-limited, never pointed at arbitrary internet assets. OpenVAS is `isolate`
(network scanner, isolated tier).

### E — Runtime / EDR / detection engineering
Falco, Tetragon, osquery, Wazuh, Velociraptor: `adapt` in **observe-only** mode
first; automated containment is a separate, approval-gated, blast-radius-limited
step. Sigma and YARA are `adopt` as detection *content* formats.

### F — Vuln management / ASPM / SIEM / SOAR / TI
DefectDojo, TheHive, MISP, OpenCTI, IntelOwl: `federate`/`adapt`. **Guardian owns the
canonical finding** (the `CanonicalFinding` contract); these are sources/sinks, not
competing systems of record. Offensive ASM tooling (`1N3/AttackSurfaceManagement`)
is `reject`.

### G — Policy / identity / secrets / privacy
**OPA stays the single policy authority** (`retain`). Cedar, Cerbos, OpenFGA are
`reference` only — introducing a second engine would create contradictory decision
points. SPIFFE/SPIRE (`adopt`, workload identity → `WorkloadTrust`), OpenBao
(`adopt`, secrets/KMS), Presidio (`adopt`, PII redaction for the privacy fabric and
telemetry), oauth2-proxy (`retain`, already in the OIDC model).

### H — Supply chain / signing / provenance
`adopt`: cosign, rekor, in-toto, SLSA, CycloneDX, SPDX — they extend `attestation/`
and `supplychain/`. ORT and ScanCode are `adapt` for licence/dependency automation;
Scorecard is `adapt` for scoring candidates during quarantine review.

### I — Sandboxing / isolation
`adopt` by risk tier: Firecracker (microVM, highest-risk active testing), gVisor
(syscall sandbox), bubblewrap (lightweight), libseccomp (syscall filtering). High-risk
workers must not share the control-plane trust zone.

### J — Orchestration / GitOps
**Temporal is already Guardian's durable workflow engine** (`retain`). Argo CD is
`adopt` for controlled GitOps response. **Licence caution flagged, not fabricated:**
n8n (sustainable-use, non-OSI) and Windmill are `defer` pending commercial-use review.

### K — Telemetry / observability / audit
OpenTelemetry, Prometheus, Grafana, Loki are `retain` (already configured). Langfuse
is `adapt` for LLM/Brain tracing — tenant-scoped and redacted. All telemetry must be
privacy-filtered and incapable of leaking secrets or protected data.

### L — Standards / formats / simulation
`adopt` the open formats: SARIF, CycloneDX, SPDX, STIX/TAXII, ATT&CK, OWASP ASVS/
WSTG/SAMM/MASVS/MASTG (several already mapped). **MITRE CALDERA is `isolate`** —
adversary emulation is high-risk; controlled cyber-range only.

### M — Curated discovery lists
`reference` only — used to *find* candidates; every linked project is independently
verified.

## What this means for Guardian

The landscape confirms the strategy: **Guardian is the trusted control plane, and
most external projects are subordinate, replaceable workers behind the connector
contract** — or simply standards Guardian already speaks. The near-term, high-leverage
integrations are the ones that reinforce the control plane itself: MCP scanning (B),
model-eval adapters (C), supply-chain signing/provenance (H), workload identity and
secrets (G), and isolation tiers (I) — all gated behind the tenant + authorisation
foundation shipped in Phases A–C.
