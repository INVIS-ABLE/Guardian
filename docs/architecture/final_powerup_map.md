
# INVISABLE Guardian — Final Power-Up Master Map

**Document role:** canonical build map for the next major Guardian evolution.

**Repository baseline:** `INVIS-ABLE/Guardian`, branch `claude/laughing-ptolemy-zfeiiu`.

Guardian remains a defensive safeguarding and security immune system for INVISABLE-owned assets. This map increases reasoning depth, execution breadth, observability, evidence quality, resilience, PWA control and specialist coverage without removing the repository's central authorization authority.

---

## 1. Final system identity

Guardian becomes a **federated autonomous defence platform** with six simultaneous identities:

1. **Security command centre** — one live case view across code, cloud, identity, endpoints, networks, PWA and safeguarding.
2. **AI reasoning fabric** — planner, investigator, critic, verifier, remediator and learning loops using structured decisions.
3. **Execution fabric** — browser, shell, API, repository, cloud and forensic workers reached through typed capabilities.
4. **Safeguarding fabric** — protection workflows designed around vulnerable users, abuse, impersonation, stalking, doxxing, fraud, account compromise and evidence preservation.
5. **Evidence fabric** — cryptographically attributable case records, immutable evidence, reproducible findings and signed remediation outcomes.
6. **Recovery fabric** — rollback, containment, disaster recovery, key rotation, service restoration and learning after every incident.

### Final operating loop

```text
Sense → Correlate → Understand → Hypothesise → Plan → Challenge → Authorise
→ Execute → Observe → Verify → Remediate → Retest → Evidence → Approve
→ Release → Monitor → Recover → Learn
```

---

## 2. What stays authoritative from the current repository

These existing concepts remain the spine:

- `core/policy_gate.py` remains the single action-authorisation authority.
- `core/router.py` remains the one capability-to-tool chokepoint, expanded into a typed router fabric.
- `core/guardrails.py` remains the scope and precondition enforcement wrapper.
- `core/audit.py` remains the local tamper-evident audit cache, upgraded with immutable remote evidence.
- `core/evidence.py` remains the evidence normalisation entry point.
- `core/memory.py` remains the memory API, split into production backends and retrieval services.
- The existing 17 ECC agents remain command-level agents.
- Temporal becomes the durable outer case workflow.
- LangGraph becomes the bounded inner reasoning graph.
- OPA remains the policy engine; OpenFGA adds relationship authorisation.
- The current PWA/FastAPI dashboard evolves rather than being discarded.

---

## 3. Sixteen trust and capability zones

```text
01 Edge Zone                 Envoy Gateway, Coraza, CRS, rate limits, bot defence
02 PWA Zone                  Guardian command centre, offline shell, WebAuthn, alerts
03 Human Identity Zone       Keycloak, MFA, passkeys, session and role policy
04 Workload Identity Zone    SPIRE/SPIFFE, mTLS, short-lived service identity
05 Policy Zone               OPA, OpenFGA, Gatekeeper, policy bundles and simulation
06 Case Orchestration Zone   Temporal, case state, approvals, retries and deadlines
07 Reasoning Zone            LangGraph, model broker, planner, critic and verifier
08 Tool Control Zone         capability registry, MCP gateway, schemas and routing
09 Shell Execution Zone      isolated scanner and repository workers
10 Browser Execution Zone    isolated Playwright/CDP workers and evidence capture
11 Data and Memory Zone      PostgreSQL, Qdrant, OpenSearch, graph and cache layers
12 Findings Zone             DefectDojo, Dependency-Track and remediation ledger
13 Evidence Zone             immudb, MinIO WORM, Cosign, Witness and chain of custody
14 Detection Zone            Falco, Tetragon, Wazuh, Suricata, Zeek, CrowdSec, osquery
15 Incident/Recovery Zone    IRIS, TheHive/OpenCTI adapters, backups and restore drills
16 Observability Zone        OTel, Prometheus, Loki, Tempo, Alertmanager and SLOs
```

---

## 4. Final high-level architecture

```text
                                      ┌───────────────────────────────┐
                                      │ INVISABLE Guardian PWA        │
                                      │ cases · tools · evidence      │
                                      │ incidents · safety · recovery │
                                      └───────────────┬───────────────┘
                                                      │
                              ┌───────────────────────▼────────────────────────┐
                              │ Envoy Gateway + Coraza/CRS + oauth2-proxy      │
                              └───────────────────────┬────────────────────────┘
                                                      │
                 ┌────────────────────────────────────▼────────────────────────────────────┐
                 │ Guardian Control API                                                    │
                 │ FastAPI · WebSocket/SSE · GraphQL optional · WebAuthn · case commands   │
                 └───────────────┬─────────────────────┬─────────────────────┬─────────────┘
                                 │                     │                     │
                    ┌────────────▼──────────┐ ┌────────▼─────────┐ ┌────────▼────────────┐
                    │ Identity + Authority  │ │ Temporal Cases   │ │ Evidence + Findings │
                    │ Keycloak/OpenFGA/OPA  │ │ signals/timers   │ │ immudb/MinIO/Dojo   │
                    └────────────┬──────────┘ └────────┬─────────┘ └────────┬────────────┘
                                 │                     │                     │
                                 └─────────────────────▼─────────────────────┘
                                               LangGraph ECC Brain
                                 ┌─────────────────────┬─────────────────────┐
                                 │                     │                     │
                         ┌───────▼────────┐   ┌────────▼────────┐   ┌────────▼─────────┐
                         │ Model Broker   │   │ Memory Fabric   │   │ Typed Tool Router │
                         │ local/remote   │   │ hybrid + graph  │   │ capabilities/MCP  │
                         └───────┬────────┘   └────────┬────────┘   └────────┬─────────┘
                                 │                     │                     │
                         ┌───────▼─────────────────────▼─────────────────────▼─────────┐
                         │ Ephemeral execution fleet                                  │
                         │ gVisor · Firecracker · Kata · Playwright · rootless workers│
                         └───────┬─────────────────────┬─────────────────────┬─────────┘
                                 │                     │                     │
                    ┌────────────▼─────────┐ ┌────────▼─────────┐ ┌────────▼────────────┐
                    │ Code/API/Cloud tools │ │ Detection fabric │ │ Safeguarding fabric │
                    │ SAST/DAST/SCA/IaC    │ │ runtime/network  │ │ abuse/privacy/safety│
                    └──────────────────────┘ └──────────────────┘ └─────────────────────┘
```

---

## 5. Final repository map

The existing directories remain. Add the following structure in-place.

```text
Guardian/
├── .claude/
│   ├── CLAUDE.md
│   ├── architecture_rules.md
│   ├── implementation_directive.md
│   ├── skills/
│   │   ├── guardian-repository-audit/
│   │   ├── guardian-connector-builder/
│   │   ├── guardian-agent-builder/
│   │   ├── guardian-policy-author/
│   │   ├── guardian-evidence-schema/
│   │   ├── guardian-pwa-feature/
│   │   ├── guardian-temporal-workflow/
│   │   └── guardian-release-gate/
│   └── commands/
│       ├── audit.md
│       ├── implement-wave.md
│       ├── add-connector.md
│       ├── add-agent.md
│       ├── add-policy.md
│       └── release-check.md
│
├── core/
│   ├── audit.py
│   ├── brain.py                         # compatibility façade
│   ├── cli.py
│   ├── config.py
│   ├── evidence.py
│   ├── guardrails.py
│   ├── memory.py                        # compatibility façade
│   ├── policy_gate.py
│   ├── router.py                        # compatibility façade
│   ├── scope.py
│   │
│   ├── ai/
│   │   ├── model_gateway.py
│   │   ├── model_registry.py
│   │   ├── model_health.py
│   │   ├── model_router.py
│   │   ├── provider_adapters.py
│   │   ├── local_inference.py
│   │   ├── structured_outputs.py
│   │   ├── context_builder.py
│   │   ├── prompt_registry.py
│   │   ├── prompt_versions.py
│   │   ├── response_validator.py
│   │   ├── tool_call_validator.py
│   │   ├── safety_filters.py
│   │   ├── token_budget.py
│   │   ├── cost_budget.py
│   │   ├── ensemble.py
│   │   ├── fallback.py
│   │   ├── cache.py
│   │   └── telemetry.py
│   │
│   ├── brain/
│   │   ├── graph.py
│   │   ├── state.py
│   │   ├── nodes.py
│   │   ├── edges.py
│   │   ├── planner.py
│   │   ├── investigator.py
│   │   ├── hypothesis.py
│   │   ├── critic.py
│   │   ├── verifier.py
│   │   ├── confidence.py
│   │   ├── prioritiser.py
│   │   ├── risk_engine.py
│   │   ├── stop_conditions.py
│   │   ├── replanner.py
│   │   ├── remediation_graph.py
│   │   ├── incident_graph.py
│   │   ├── safeguarding_graph.py
│   │   ├── learning_graph.py
│   │   ├── checkpoints.py
│   │   └── replay.py
│   │
│   ├── workflows/
│   │   ├── client.py
│   │   ├── worker.py
│   │   ├── case_workflow.py
│   │   ├── incident_workflow.py
│   │   ├── release_workflow.py
│   │   ├── safeguarding_workflow.py
│   │   ├── recovery_workflow.py
│   │   ├── schedules.py
│   │   ├── signals.py
│   │   ├── queries.py
│   │   └── activities/
│   │       ├── reasoning.py
│   │       ├── authorisation.py
│   │       ├── ownership.py
│   │       ├── tool_execution.py
│   │       ├── browser_execution.py
│   │       ├── evidence.py
│   │       ├── findings.py
│   │       ├── approval.py
│   │       ├── remediation.py
│   │       ├── verification.py
│   │       ├── containment.py
│   │       └── recovery.py
│   │
│   ├── tools/
│   │   ├── registry.py
│   │   ├── manifest.py
│   │   ├── capability.py
│   │   ├── schemas.py
│   │   ├── discovery.py
│   │   ├── resolver.py
│   │   ├── typed_router.py
│   │   ├── result_normaliser.py
│   │   ├── result_parser.py
│   │   ├── health.py
│   │   ├── version.py
│   │   ├── provenance.py
│   │   ├── cache.py
│   │   ├── quotas.py
│   │   ├── kill_switch.py
│   │   └── execution/
│   │       ├── base.py
│   │       ├── local_dev.py
│   │       ├── container.py
│   │       ├── gvisor.py
│   │       ├── firecracker.py
│   │       ├── kata.py
│   │       ├── wasm.py
│   │       ├── kubernetes_job.py
│   │       ├── shell.py
│   │       ├── browser.py
│   │       ├── filesystem.py
│   │       ├── network.py
│   │       ├── credentials.py
│   │       ├── resource_limits.py
│   │       └── cleanup.py
│   │
│   ├── mcp/
│   │   ├── gateway.py
│   │   ├── registry.py
│   │   ├── server_manifest.py
│   │   ├── transport.py
│   │   ├── stdio_proxy.py
│   │   ├── http_proxy.py
│   │   ├── schema_filter.py
│   │   ├── response_filter.py
│   │   ├── context_firewall.py
│   │   ├── provenance.py
│   │   ├── health.py
│   │   └── servers/
│   │       ├── playwright.py
│   │       ├── github.py
│   │       ├── filesystem.py
│   │       ├── postgres.py
│   │       ├── qdrant.py
│   │       ├── openapi.py
│   │       └── guardian_native.py
│   │
│   ├── memory/
│   │   ├── service.py
│   │   ├── record.py
│   │   ├── collections.py
│   │   ├── permissions.py
│   │   ├── redaction.py
│   │   ├── ingestion.py
│   │   ├── chunking.py
│   │   ├── embeddings.py
│   │   ├── dense.py
│   │   ├── sparse.py
│   │   ├── hybrid.py
│   │   ├── reranker.py
│   │   ├── graph.py
│   │   ├── retrieval.py
│   │   ├── context_pack.py
│   │   ├── retention.py
│   │   ├── feedback.py
│   │   ├── quality.py
│   │   └── backends/
│   │       ├── in_memory.py
│   │       ├── qdrant.py
│   │       ├── pgvector.py
│   │       ├── opensearch.py
│   │       ├── neo4j.py
│   │       └── object_store.py
│   │
│   ├── evidence/
│   │   ├── model.py
│   │   ├── collector.py
│   │   ├── normaliser.py
│   │   ├── redactor.py
│   │   ├── hasher.py
│   │   ├── signer.py
│   │   ├── attestor.py
│   │   ├── chain_of_custody.py
│   │   ├── timeline.py
│   │   ├── export.py
│   │   ├── replay.py
│   │   ├── retention.py
│   │   └── stores/
│   │       ├── local.py
│   │       ├── immudb.py
│   │       ├── minio.py
│   │       └── postgres.py
│   │
│   ├── findings/
│   │   ├── model.py
│   │   ├── ingest.py
│   │   ├── normalise.py
│   │   ├── deduplicate.py
│   │   ├── correlate.py
│   │   ├── prioritise.py
│   │   ├── suppress.py
│   │   ├── sla.py
│   │   ├── remediation.py
│   │   ├── verification.py
│   │   ├── defectdojo.py
│   │   └── dependency_track.py
│   │
│   ├── identity/
│   │   ├── oidc.py
│   │   ├── sessions.py
│   │   ├── webauthn.py
│   │   ├── roles.py
│   │   ├── openfga.py
│   │   ├── spiffe.py
│   │   ├── certificates.py
│   │   ├── service_tokens.py
│   │   └── break_glass.py
│   │
│   ├── detection/
│   │   ├── event.py
│   │   ├── bus.py
│   │   ├── normalise.py
│   │   ├── correlate.py
│   │   ├── rules.py
│   │   ├── sigma.py
│   │   ├── yara.py
│   │   ├── enrichment.py
│   │   ├── scoring.py
│   │   ├── alert.py
│   │   └── adapters/
│   │       ├── falco.py
│   │       ├── tetragon.py
│   │       ├── wazuh.py
│   │       ├── suricata.py
│   │       ├── zeek.py
│   │       ├── crowdsec.py
│   │       ├── osquery.py
│   │       └── velociaptor.py
│   │
│   ├── safeguarding/
│   │   ├── case.py
│   │   ├── signals.py
│   │   ├── risk.py
│   │   ├── triage.py
│   │   ├── consent.py
│   │   ├── privacy.py
│   │   ├── evidence_pack.py
│   │   ├── trusted_contacts.py
│   │   ├── safe_exit.py
│   │   ├── account_recovery.py
│   │   ├── impersonation.py
│   │   ├── harassment.py
│   │   ├── stalking.py
│   │   ├── doxxing.py
│   │   ├── scam.py
│   │   ├── coercion.py
│   │   ├── content_risk.py
│   │   ├── accessibility.py
│   │   └── escalation.py
│   │
│   ├── remediation/
│   │   ├── planner.py
│   │   ├── patch.py
│   │   ├── branch.py
│   │   ├── tests.py
│   │   ├── pull_request.py
│   │   ├── feature_flag.py
│   │   ├── rollout.py
│   │   ├── canary.py
│   │   ├── rollback.py
│   │   └── post_change.py
│   │
│   ├── incidents/
│   │   ├── model.py
│   │   ├── triage.py
│   │   ├── commander.py
│   │   ├── timeline.py
│   │   ├── containment.py
│   │   ├── eradication.py
│   │   ├── recovery.py
│   │   ├── communication.py
│   │   ├── postmortem.py
│   │   ├── iris.py
│   │   ├── thehive.py
│   │   └── opencti.py
│   │
│   ├── ownership/
│   │   ├── verifier.py
│   │   ├── github.py
│   │   ├── dns.py
│   │   ├── cloud.py
│   │   ├── kubernetes.py
│   │   ├── certificates.py
│   │   ├── evidence.py
│   │   └── expiry.py
│   │
│   └── observability/
│       ├── tracing.py
│       ├── metrics.py
│       ├── logs.py
│       ├── correlation.py
│       ├── audit_bridge.py
│       ├── slos.py
│       ├── health.py
│       └── alerts.py
│
├── agents/
│   ├── base.py
│   ├── registry.py
│   ├── command/                     # existing 17 ECC command agents
│   ├── reasoning/
│   ├── application/
│   ├── identity/
│   ├── cloud/
│   ├── container/
│   ├── network/
│   ├── endpoint/
│   ├── supply_chain/
│   ├── privacy/
│   ├── safeguarding/
│   ├── incident/
│   ├── remediation/
│   ├── evidence/
│   ├── validation/
│   └── learning/
│
├── connectors/
│   ├── base.py
│   ├── registry.py
│   ├── manifests/
│   ├── sast/
│   ├── secrets/
│   ├── dependency/
│   ├── provenance/
│   ├── dast/
│   ├── api/
│   ├── browser/
│   ├── pwa/
│   ├── fuzzing/
│   ├── iac/
│   ├── cloud/
│   ├── kubernetes/
│   ├── container/
│   ├── network/
│   ├── runtime/
│   ├── endpoint/
│   ├── malware/
│   ├── forensics/
│   ├── threat_intel/
│   ├── identity/
│   ├── evidence/
│   ├── findings/
│   ├── ticketing/
│   ├── notifications/
│   └── recovery/
│
├── dashboard/
│   ├── api/
│   ├── auth/
│   ├── websocket/
│   ├── routes/
│   └── schemas/
│
├── pwa/
│   ├── app/
│   ├── components/
│   ├── features/
│   │   ├── command-centre/
│   │   ├── case-room/
│   │   ├── investigation/
│   │   ├── evidence/
│   │   ├── safeguarding/
│   │   ├── incidents/
│   │   ├── findings/
│   │   ├── assets/
│   │   ├── tools/
│   │   ├── models/
│   │   ├── policies/
│   │   ├── memory/
│   │   ├── telemetry/
│   │   ├── approvals/
│   │   └── recovery/
│   ├── service-worker/
│   ├── offline/
│   ├── notifications/
│   ├── accessibility/
│   ├── security/
│   └── tests/
│
├── policies/
│   ├── opa/
│   │   ├── guardian.rego
│   │   ├── model_action.rego
│   │   ├── tool_execution.rego
│   │   ├── shell_execution.rego
│   │   ├── browser_execution.rego
│   │   ├── mcp_server.rego
│   │   ├── network_access.rego
│   │   ├── ownership.rego
│   │   ├── evidence_export.rego
│   │   ├── production_change.rego
│   │   ├── safeguarding_case.rego
│   │   ├── incident_action.rego
│   │   ├── memory_access.rego
│   │   ├── model_selection.rego
│   │   ├── secret_access.rego
│   │   ├── retention.rego
│   │   └── emergency.rego
│   ├── gatekeeper/
│   ├── kyverno/
│   ├── cilium/
│   ├── tetragon/
│   ├── falco/
│   ├── sigma/
│   ├── yara/
│   ├── coraza/
│   ├── privacy/
│   ├── safeguarding/
│   └── retention/
│
├── workflows/
│   ├── repository-assurance/
│   ├── pwa-release/
│   ├── api-assurance/
│   ├── cloud-posture/
│   ├── container-assurance/
│   ├── identity-assurance/
│   ├── threat-hunt/
│   ├── incident-response/
│   ├── account-compromise/
│   ├── vulnerable-user-safeguarding/
│   ├── evidence-export/
│   ├── disaster-recovery/
│   └── continuous-learning/
│
├── eval/
│   ├── reasoning/
│   ├── tool_selection/
│   ├── prompt_injection/
│   ├── context_poisoning/
│   ├── scope_enforcement/
│   ├── false_positive/
│   ├── false_negative/
│   ├── remediation/
│   ├── safeguarding/
│   ├── incident_response/
│   ├── memory/
│   ├── browser/
│   └── shell/
│
├── deploy/
│   ├── compose/
│   ├── helm/
│   ├── kustomize/
│   ├── terraform/
│   ├── ansible/
│   ├── nomad/
│   ├── policies/
│   └── images/
│
├── monitoring/
│   ├── otel/
│   ├── prometheus/
│   ├── grafana/
│   ├── loki/
│   ├── tempo/
│   ├── alertmanager/
│   └── slo/
│
├── evidence/
│   ├── schemas/
│   ├── attestations/
│   ├── exports/
│   └── verification/
│
├── docs/
│   ├── architecture/
│   ├── agents/
│   ├── connectors/
│   ├── workflows/
│   ├── policies/
│   ├── safeguarding/
│   ├── incident-response/
│   ├── operations/
│   ├── recovery/
│   ├── threat-models/
│   ├── runbooks/
│   ├── adr/
│   └── api/
│
└── tests/
    ├── unit/
    ├── integration/
    ├── contract/
    ├── property/
    ├── security/
    ├── chaos/
    ├── performance/
    ├── pwa/
    ├── e2e/
    └── acceptance/
```

---

## 6. ECC command system: 17 command agents expanded into specialist cells

The existing 17 agents stay as the command layer. Each receives subordinate specialist agents.

### 1. Guardian Planner Command
Sub-agents: mission decomposer, dependency planner, parallelisation planner, time-budget planner, evidence planner, rollback planner, approval planner, continuity planner.

### 2. Asset Scope Command
Sub-agents: GitHub ownership verifier, DNS verifier, certificate verifier, cloud-account verifier, Kubernetes-cluster verifier, package-namespace verifier, mobile-app verifier, third-party dependency boundary mapper.

### 3. Threat Model Command
Sub-agents: STRIDE analyst, ATT&CK mapper, abuse-case modeller, trust-boundary mapper, data-flow modeller, vulnerable-user harm modeller, privacy threat modeller, supply-chain threat modeller.

### 4. Code Review Command
Sub-agents: Python reviewer, TypeScript reviewer, JavaScript reviewer, Go reviewer, Rust reviewer, Java/Kotlin reviewer, C/C++ reviewer, infrastructure-code reviewer, cryptography reviewer, concurrency reviewer.

### 5. Dependency Command
Sub-agents: SCA analyst, SBOM builder, reachability analyst, licence analyst, provenance verifier, package-health analyst, dependency-confusion detector, update planner.

### 6. Secrets Command
Sub-agents: working-tree scanner, history scanner, container-layer scanner, CI-log scanner, PWA-bundle scanner, source-map scanner, IaC-state scanner, secret-rotation planner.

### 7. API Security Command
Sub-agents: OpenAPI analyst, schema fuzzer, GraphQL analyst, auth-state tester, webhook tester, rate-limit tester, object-authorisation tester, contract-drift analyst.

### 8. Auth/RBAC Command
Sub-agents: session analyst, MFA/passkey analyst, role-matrix tester, ReBAC tester, tenant-isolation tester, privilege-drift analyst, service-account analyst, recovery-flow analyst.

### 9. Privacy/GDPR Command
Sub-agents: data inventory agent, minimisation agent, retention agent, consent agent, export/erasure tester, redaction agent, telemetry privacy agent, DPIA evidence agent.

### 10. Safeguarding Command
Sub-agents: harassment triage, stalking/doxxing triage, impersonation analyst, scam/phishing analyst, coercion-risk analyst, account-compromise navigator, trusted-contact coordinator, evidence-preservation agent, safe-exit UX agent, accessibility agent.

### 11. Abuse Simulation Command
Sub-agents: account-abuse simulator, moderation-abuse simulator, privacy-leak simulator, rate-limit simulator, workflow-bypass simulator, notification-abuse simulator, support-channel-abuse simulator, synthetic social-engineering simulator.

### 12. Runtime Monitoring Command
Sub-agents: runtime detector, endpoint detector, network detector, identity anomaly detector, cloud audit detector, container anomaly detector, correlation analyst, threat hunter.

### 13. Patch Proposal Command
Sub-agents: patch architect, minimal-diff builder, regression-test builder, migration planner, compatibility reviewer, feature-flag planner, canary planner, rollback author.

### 14. Test Runner Command
Sub-agents: unit runner, integration runner, contract runner, browser runner, security runner, fuzz runner, property-test runner, accessibility runner, performance runner, chaos runner.

### 15. Evidence Report Command
Sub-agents: evidence collector, timeline builder, redactor, hasher, signer, attestor, report writer, machine-export builder, legal hold coordinator.

### 16. Human Approval Command
Sub-agents: approval packet builder, reviewer routing agent, conflict checker, expiry monitor, change-diff presenter, blast-radius presenter, emergency-review coordinator.

### 17. Learning Memory Command
Sub-agents: outcome ingester, retrieval-quality analyst, false-positive learner, false-negative learner, rule candidate builder, prompt evaluator, regression corpus builder, knowledge-retention agent.

### Independent cross-command agents

- **Adversarial Critic:** challenges every proposed conclusion.
- **Independent Verifier:** reruns validation using a different method or tool.
- **Safety Impact Assessor:** scores vulnerable-user impact before remediation and release.
- **Evidence Completeness Auditor:** refuses case closure with missing required evidence.
- **Recovery Readiness Auditor:** confirms rollback and restoration paths exist.
- **Model Behaviour Auditor:** monitors tool selection, hallucination and prompt-injection resistance.

---

## 7. Reasoning and decision graph

```text
CASE_CREATED
  ↓
LOAD_SCOPE_AND_OWNERSHIP
  ↓
BUILD_CONTEXT_PACK
  ↓
CLASSIFY_CASE
  ↓
CREATE_HYPOTHESES
  ↓
GENERATE_INVESTIGATION_PLAN
  ↓
CRITIC_REVIEW
  ├── revise ────────────────┐
  └── accept                 │
       ↓                     │
AUTHORISE_NEXT_CAPABILITY    │
  ↓                          │
EXECUTE_TYPED_TOOL           │
  ↓                          │
NORMALISE_RESULT             │
  ↓                          │
CORRELATE_EVIDENCE           │
  ↓                          │
UPDATE_CONFIDENCE            │
  ├── more evidence ─────────┘
  ├── incident → INCIDENT_GRAPH
  ├── safeguard → SAFEGUARDING_GRAPH
  └── sufficient
       ↓
BUILD_REMEDIATION_OPTIONS
  ↓
BLAST_RADIUS_ANALYSIS
  ↓
DRY_RUN_AND_TEST
  ↓
INDEPENDENT_VERIFICATION
  ↓
APPROVAL_PACKET
  ↓
APPROVED_CHANGE
  ↓
CANARY_OR_FEATURE_FLAG
  ↓
POST_CHANGE_VERIFICATION
  ↓
SIGNED_EVIDENCE_BUNDLE
  ↓
LEARNING_AND_CASE_CLOSURE
```

### Typed Guardian case state

```python
class GuardianCaseState(BaseModel):
    case_id: UUID
    case_type: Literal[
        "assurance", "incident", "safeguarding", "release",
        "recovery", "threat_hunt", "privacy", "identity"
    ]
    status: str
    scope_id: str
    asset_ids: list[str]
    ownership_evidence_ids: list[str]
    objective: str
    observations: list[Observation]
    hypotheses: list[Hypothesis]
    plan: list[PlanStep]
    current_step: int
    tool_results: list[ToolResult]
    findings: list[Finding]
    evidence_ids: list[str]
    risk: RiskAssessment
    safety_impact: SafetyImpact
    confidence: float
    approvals: list[Approval]
    remediation_options: list[RemediationOption]
    selected_remediation: str | None
    verification: list[VerificationResult]
    budget: ExecutionBudget
    trace_id: str
    created_at: datetime
    updated_at: datetime
```

### Structured model output

```python
class GuardianDecision(BaseModel):
    objective: str
    observations_used: list[str]
    hypotheses: list[str]
    selected_capability: str | None
    arguments: dict[str, JsonValue]
    expected_evidence: list[str]
    risk_level: Literal["informational", "low", "medium", "high", "critical"]
    safety_impact: Literal["none", "low", "moderate", "high", "immediate"]
    confidence: float
    requires_approval: bool
    stop_reason: str | None
```

### Reasoning controls

```yaml
reasoning:
  max_graph_steps: 40
  max_tool_calls: 120
  max_replans: 12
  max_parallel_branches: 12
  max_case_wall_time_minutes: 240
  confidence_floor_for_remediation: 0.82
  independent_verification_required: true
  critic_required_for_high_risk: true
  evidence_minimum_per_finding: 2
  model_output_schema_required: true
  hidden_reasoning_storage: false
  decision_summary_storage: true
```

---

## 8. Model fabric

### Model roles

- **Strategic model:** complex planning and multi-domain synthesis.
- **Investigator model:** tool selection and evidence interpretation.
- **Code model:** source review, patch proposals and test generation.
- **Fast classifier:** routing, tagging, severity and deduplication.
- **Embedding model:** dense retrieval.
- **Reranker model:** retrieval quality.
- **Vision model:** screenshots, diagrams and visual evidence.
- **Offline model:** continuity during provider or network failure.
- **Critic model:** independent challenge.
- **Verifier model:** independent final validation.

### Provider abstraction

```text
Guardian Model API
 ├── Anthropic adapter
 ├── OpenAI-compatible adapter
 ├── local vLLM adapter
 ├── Ollama adapter
 ├── llama.cpp adapter
 ├── SGLang adapter
 ├── TGI adapter
 └── deterministic test adapter
```

### Model gateway requirements

- OpenAI-compatible internal API.
- Anthropic message compatibility.
- Model allowlist and health state.
- Role-based routing.
- Prompt version pinning.
- Structured output validation.
- Retries, circuit breakers and provider fallback.
- Per-case token and cost budgets.
- Cache with privacy-aware keys.
- Redaction before provider calls.
- Complete trace correlation.
- Model and prompt evaluation scorecards.
- Provider outage and local-only operation mode.
- Signed model artefact manifests for local models.

### Supply-chain note

Do not install AI gateways or scanner packages from floating package versions. Build Guardian images from reviewed source, lock dependencies, record hashes, create SBOMs, sign images and verify the image digest before execution.

---

## 9. Memory and knowledge fabric

### Storage roles

- **PostgreSQL:** authoritative case metadata, approvals, asset registry and workflow state references.
- **Qdrant:** dense vector retrieval.
- **OpenSearch:** keyword, log and evidence search.
- **Neo4j or PostgreSQL graph model:** asset, identity, finding, incident and dependency relationships.
- **MinIO:** evidence objects and large artefacts.
- **immudb:** immutable audit and evidence index.
- **Valkey/Redis:** short-lived cache, locks and event coordination.

### Expanded collections

```text
invisable_repos
policies
threat_models
app_docs
support_flows
safeguarding_rules
run_outcomes
asset_inventory
ownership_evidence
architecture_decisions
security_findings
remediation_patterns
incident_timelines
threat_intelligence
sigma_rules
yara_rules
falco_rules
codeql_queries
semgrep_rules
api_schemas
pwa_journeys
privacy_requirements
accessibility_requirements
recovery_runbooks
known_false_positives
known_false_negatives
model_evaluations
tool_health
connector_documentation
```

### Retrieval pipeline

```text
Query classification
→ permission filter
→ PII/secret-aware query transformation
→ dense retrieval
→ BM25/sparse retrieval
→ graph-neighbour expansion
→ reciprocal-rank fusion
→ metadata and freshness filtering
→ reranking
→ contradiction detection
→ context compression
→ citation/evidence attachment
```

### Memory quality controls

- Every record has provenance, owner, source hash, classification, retention and expiry.
- Case memory and global memory are separate.
- Findings are not learned as facts until verified.
- False positives and rejected remediations are retained as labelled outcomes.
- Retrieval evaluation runs against a fixed regression set.
- Stale policy and architecture documents are down-ranked.
- Sensitive safeguarding records use separate collections and access policy.

---

## 10. Typed tool and connector fabric

### Capability vocabulary

```text
repo.inventory
repo.diff
repo.history
code.sast
code.query
code.quality
secret.scan
secret.verify
secret.rotate-plan
sca.scan
sbom.generate
sbom.compare
provenance.verify
container.scan
iac.scan
cloud.posture
k8s.posture
web.baseline
web.active-test
api.contract
api.fuzz
browser.journey
browser.accessibility
pwa.offline
pwa.service-worker
identity.matrix
identity.session
privacy.flow
safeguarding.simulation
runtime.query
network.query
endpoint.query
threat-intel.lookup
malware.classify
file.inspect
forensics.timeline
incident.contain
incident.collect
remediation.patch
remediation.test
remediation.pr
evidence.collect
evidence.sign
evidence.export
recovery.backup-verify
recovery.restore-test
```

### Tool manifest schema

```yaml
apiVersion: guardian.invisable/v1
kind: ToolManifest
metadata:
  id: semgrep
  displayName: Semgrep
  version: pinned
spec:
  capabilities: [code.sast]
  connector: connectors.sast.semgrep.SemgrepConnector
  parser: connectors.sast.parsers.semgrep.SemgrepParser
  executionProfile: scanner-standard
  inputSchema: schemas/tools/semgrep-input.json
  outputSchema: schemas/tools/finding-bundle.json
  targetTypes: [repository, source-tree]
  evidenceTypes: [sarif, json, stdout, metrics]
  resourceClass: medium
  timeoutSeconds: 900
  retries: 1
  idempotent: true
  supportsDryRun: true
  healthCheck: semgrep --version
  provenance:
    sourceRepository: https://github.com/semgrep/semgrep
    imageDigest: sha256:REPLACE
    sbom: evidence/sbom/semgrep.cdx.json
    signatureRequired: true
  network:
    mode: none
  filesystem:
    input: read-only
    scratch: ephemeral
    output: evidence-only
  secrets: []
  resultPolicy:
    redact: true
    maximumBytes: 52428800
    retainRaw: true
```

### Execution profiles

```text
scanner-tiny        1 CPU / 1 GiB / 5 min
scanner-standard    2 CPU / 4 GiB / 15 min
scanner-heavy       8 CPU / 16 GiB / 60 min
browser-standard    2 CPU / 4 GiB / 20 min
browser-visual      4 CPU / 8 GiB / 30 min
fuzzer-bounded      8 CPU / 16 GiB / bounded campaign
forensic-isolated   Firecracker worker / no shared host paths
malware-isolated    Firecracker worker / quarantined artefacts
local-development   process adapter for tests only
```

### Router evolution

Replace the static dictionary as the sole registry with:

```text
Capability request
→ schema validation
→ asset and ownership resolution
→ policy decision
→ capability resolver
→ candidate tool scoring
→ health/provenance check
→ execution profile selection
→ ephemeral credential issue
→ worker creation
→ execution and streamed telemetry
→ parser and result normaliser
→ evidence commit
→ worker destruction
→ credential revocation
```

### MCP layer

- Maintain an explicit MCP server registry.
- Import tool schemas only from registered, version-pinned servers.
- Wrap every MCP server behind Guardian's own gateway.
- Validate request and response schemas.
- Bind each MCP tool to Guardian capabilities.
- Record server, tool, version, arguments hash and output hash.
- Support stdio, streamable HTTP and native Guardian transports.
- Provide native servers for Playwright, GitHub, filesystem, Qdrant, PostgreSQL and Guardian case operations.

---

## 11. Shell and browser execution

### Shell worker contract

The reasoning layer requests a typed capability. The connector constructs the reviewed command from validated fields. The execution worker receives a sealed job specification and returns a signed result bundle.

```python
class ExecutionJob(BaseModel):
    job_id: UUID
    case_id: UUID
    tool_id: str
    capability: str
    args: dict[str, JsonValue]
    input_artifacts: list[ArtifactRef]
    execution_profile: str
    credential_refs: list[str]
    target_refs: list[str]
    timeout_seconds: int
    trace_id: str
```

### Browser worker capabilities

- Isolated Chromium, Firefox and WebKit contexts.
- Playwright native API and Playwright MCP adapter.
- Accessibility-tree interaction.
- Screenshot, video, trace, HAR, console and network evidence.
- Multi-user test personas.
- MFA/passkey test harness.
- PWA install, offline, update and service-worker testing.
- Push notification and deep-link testing.
- Accessibility and keyboard-only journeys.
- Visual regression and layout-shift capture.
- Trusted fixture uploads and download quarantine.
- Session-state import from encrypted test-account fixtures.
- Browser extension testing in a separate worker class.

### Browser case artefacts

```text
trace.zip
network.har
console.jsonl
screenshots/
video.webm
accessibility-snapshots/
dom-snapshots/
performance.json
lighthouse.json
axe.json
cookies.redacted.json
service-worker.json
```

---

## 12. Open-source arsenal

### Reasoning Orchestration

**LangGraph**, **Temporal**, **PydanticAI**, **DSPy**, **Haystack**, **LlamaIndex**, **AutoGen**, **Semantic Kernel**, **CrewAI**, **Prefect**, **Dagster**, **Ray**, **Dask**.

### Model Gateway Serving

**Guardian Native Model Gateway**, **LiteLLM**, **vLLM**, **Ollama**, **llama.cpp**, **SGLang**, **Hugging Face TGI**, **LocalAI**, **KServe**, **BentoML**, **Ray Serve**, **Triton Inference Server**, **MLX-LM**.

### Structured Generation

**Pydantic**, **Instructor**, **Outlines**, **Guidance**, **BAML**, **Guardrails AI**, **JSON Schema**, **TypeChat**, **lm-format-enforcer**.

### Ai Security Evaluation

**NeMo Guardrails**, **LLM Guard**, **garak**, **PyRIT**, **Promptfoo**, **Giskard**, **Inspect AI**, **DeepEval**, **Ragas**, **AgentDojo**, **PurpleLlama CyberSecEval**, **ModelScan**, **Microsoft Presidio**, **Rebuff**, **Vigil**, **OpenAI Evals-compatible harness**.

### Ai Observability

**Langfuse**, **Arize Phoenix**, **OpenLIT**, **OpenTelemetry**, **Helicone OSS**, **Traceloop SDK**.

### Memory Retrieval

**Qdrant**, **pgvector**, **OpenSearch**, **Chroma**, **Milvus**, **Weaviate**, **LanceDB**, **Neo4j**, **sentence-transformers**, **FastEmbed**, **FlagEmbedding**, **BM25**, **SPLADE**, **ColBERT**, **FlashRank**, **Docling**, **Unstructured**, **Apache Tika**.

### Sandbox Execution

**gVisor**, **Firecracker**, **Kata Containers**, **nsjail**, **bubblewrap**, **rootless Podman**, **containerd**, **systemd-nspawn**, **WasmEdge**, **Wasmtime**, **seccomp**, **AppArmor**, **SELinux**, **Landlock**, **cgroups v2**, **Linux namespaces**.

### Browser Automation

**Playwright**, **Playwright MCP**, **Selenium**, **Puppeteer**, **Chrome DevTools Protocol**, **Browserless**, **mitmproxy**, **OWASP ZAP browser integration**.

### Sast Code Quality

**CodeQL**, **Semgrep**, **Opengrep**, **Bearer**, **Bandit**, **Ruff**, **mypy**, **Pyright**, **gosec**, **govulncheck**, **Brakeman**, **SpotBugs**, **FindSecBugs**, **PMD**, **cppcheck**, **clang-tidy**, **Clang Static Analyzer**, **Infer**, **cargo-clippy**, **cargo-geiger**, **ESLint**, **eslint-plugin-security**, **njsscan**, **Psalm**, **PHPStan**, **SonarQube Community Build**.

### Secret Detection

**Gitleaks**, **TruffleHog**, **detect-secrets**, **git-secrets**, **secretlint**, **ggshield community tooling**, **Yelp detect-secrets**.

### Dependency Supply Chain

**OSV-Scanner**, **Trivy**, **Syft**, **Grype**, **OWASP Dependency-Check**, **Dependency-Track**, **cdxgen**, **CycloneDX CLI**, **SPDX tools**, **pip-audit**, **npm audit**, **pnpm audit**, **yarn audit**, **cargo-audit**, **bundler-audit**, **retire.js**, **Renovate**, **Dependabot**, **GUAC**, **ORT**.

### Provenance Signing

**Cosign**, **Sigstore Rekor**, **Sigstore Fulcio**, **in-toto**, **Witness**, **SLSA verifier**, **TUF**, **Notary Project**, **ORAS**, **Ratify**, **Notation**.

### Dast Web

**OWASP ZAP**, **Nuclei**, **httpx**, **Katana**, **Naabu**, **Amass**, **Subfinder**, **dnsx**, **Wapiti**, **Nikto**, **SSLyze**, **testssl.sh**, **WhatWeb**, **OWASP Nettacker**.

### Api Security

**Schemathesis**, **RESTler**, **EvoMaster**, **Dredd**, **Newman**, **Step CI**, **Tavern**, **Karate**, **Hurl**, **OpenAPI Diff**, **Spectral**, **Vacuum**, **GraphQL Cop**, **InQL**, **GraphQLmap test harness**.

### Fuzzing Property Mutation

**AFL++**, **libFuzzer**, **Honggfuzz**, **Jazzer**, **Atheris**, **Hypothesis**, **boofuzz**, **Fuzzilli**, **cargo-fuzz**, **go-fuzz**, **OSS-Fuzz**, **ClusterFuzzLite**, **Stryker**, **StrykerJS**, **mutmut**, **Cosmic Ray**, **cargo-mutants**.

### Iac Policy

**Checkov**, **KICS**, **Terrascan**, **Trivy Config**, **Conftest**, **OPA**, **Regula**, **TFLint**, **terraform-compliance**, **Terratest**, **Infracost policy checks**, **Open Policy Containers**.

### Kubernetes Container

**Kubescape**, **kube-bench**, **kube-linter**, **kube-score**, **Polaris**, **Popeye**, **Kyverno**, **Gatekeeper**, **Falco**, **Tetragon**, **Tracee**, **Dockle**, **Hadolint**, **container-structure-test**, **Cilium**, **NeuVector Community Edition**.

### Cloud Security

**Prowler**, **ScoutSuite**, **Steampipe**, **CloudQuery**, **Cartography**, **CloudMapper**, **Cloudsplaining**, **Parliament**, **Principal Mapper**, **IAM Live**, **Cloud Custodian**, **Pacu owned-lab adapter**.

### Runtime Endpoint Network

**Falco**, **Tetragon**, **Tracee**, **Wazuh**, **osquery**, **Suricata**, **Zeek**, **CrowdSec**, **YARA**, **Sigma**, **ClamAV**, **Velociraptor**, **OpenCanary**, **Cowrie**, **Arkime**, **Security Onion**, **SELKS**, **OpenSnitch**, **ntopng**, **Maltrail**, **Snort**.

### Incident Response Threat Intel

**DFIR-IRIS**, **TheHive**, **Cortex**, **MISP**, **OpenCTI**, **Shuffle**, **Timesketch**, **Plaso**, **Velociraptor**, **GRR Rapid Response**, **Autopsy**, **Volatility 3**, **Chainsaw**, **Hayabusa**, **Zircolite**, **Loki IOC Scanner**, **Sigma CLI**, **YARA**.

### Malware File Analysis

**ClamAV**, **YARA**, **capa**, **FLOSS**, **oletools**, **pdfid**, **pdf-parser**, **qpdf**, **ExifTool**, **libmagic**, **Apache Tika**, **binwalk**, **radare2**, **Ghidra**, **Cutter**, **REMnux components**.

### Identity Secrets Pki

**Keycloak**, **OpenFGA**, **OPA**, **SPIRE**, **cert-manager**, **step-ca**, **OpenBao**, **SOPS**, **External Secrets Operator**, **oauth2-proxy**, **Dex**, **Authelia**, **Kanidm**.

### Edge Pwa

**Envoy Gateway**, **Coraza**, **OWASP Core Rule Set**, **ModSecurity**, **Caddy**, **Nginx**, **HAProxy**, **Workbox**, **Lighthouse CI**, **axe-core**, **pa11y**, **DOMPurify**, **Trusted Types**, **Helmet**, **Zod**, **SimpleWebAuthn**, **CSP Evaluator**, **dependency-cruiser**, **Madge**, **Playwright**, **Vitest**, **Jest**, **Testing Library**.

### Observability Evidence

**OpenTelemetry Collector**, **Prometheus**, **Grafana**, **Loki**, **Tempo**, **Alertmanager**, **Jaeger**, **Sentry**, **OpenSearch**, **Fluent Bit**, **Vector**, **immudb**, **MinIO**, **PostgreSQL**, **Sigstore**, **Witness**, **restic**, **Thanos**, **Mimir**.

### Event Data Platform

**NATS JetStream**, **Redpanda**, **Apache Kafka**, **RabbitMQ**, **Debezium**, **PostgreSQL**, **Redis**, **Valkey**, **MinIO**, **OpenSearch**, **ClickHouse**.

### Devsecops Ci

**uv**, **pre-commit**, **pytest**, **Hypothesis**, **nox**, **tox**, **actionlint**, **zizmor**, **OpenSSF Scorecard**, **Renovate**, **Dagger**, **Earthly**, **Tekton**, **Argo Workflows**, **Argo CD**, **Flux**, **Helm**, **Kustomize**, **Trivy Operator**.

### Backup Recovery

**restic**, **Kopia**, **Velero**, **Litestream**, **pgBackRest**, **Barman**, **Rclone**, **MinIO object lock**, **OpenBao Raft snapshots**.


### Arsenal operating model

- Register every candidate in `docs/tooling_catalogue.md` and `docs/architecture/components.yaml`.
- Select one authoritative primary tool for each production capability.
- Keep alternates as fallback, validation, specialist or migration adapters.
- Give every production tool a connector, parser, manifest, test fixture, health check, SBOM, signature and evidence mapping.
- Run tool-conformance tests before a version is promoted.
- Preserve raw results and normalise them into Guardian's common finding and evidence schemas.

---

## 13. Safeguarding fabric for vulnerable people

Guardian's strongest differentiator should be a dedicated safeguarding command system, not only conventional DevSecOps.

### Safety capabilities

1. **Account compromise support** — test recovery journeys, session revocation, passkey/MFA recovery, device inventory and recovery evidence.
2. **Harassment and abuse case room** — collect user-authorised evidence, build timelines, preserve source hashes and manage safe escalation.
3. **Impersonation detection** — compare owned profiles, domains, brand assets and verified identifiers against reported impersonation evidence.
4. **Doxxing exposure checks** — detect accidental exposure across INVISABLE systems, logs, public profiles, support exports and generated files.
5. **Stalking-risk workflow** — privacy-setting checks, location leakage review, metadata review, trusted-contact workflow and evidence packaging.
6. **Scam/phishing defence** — suspicious-message analysis, domain and URL intelligence, brand impersonation monitoring and user-safe reporting.
7. **Coercion-aware UX** — safe-exit journeys, discreet notifications, session privacy and consent-aware evidence collection.
8. **Trusted contacts** — opt-in contact pathways, explicit permissions, time-bound access and auditable actions.
9. **Evidence preservation** — screenshot, message, email, file and URL evidence with provenance and chain of custody.
10. **Accessibility-first operation** — keyboard, screen-reader, low-vision, cognitive-load and low-bandwidth journeys.
11. **Privacy shield** — redact unnecessary personal data from reports, support logs, screenshots and model context.
12. **Human escalation** — route high-impact cases to trained humans with a clear evidence and risk packet.

### Safeguarding case state

```python
class SafeguardingCase(BaseModel):
    case_id: UUID
    consent_record_id: str
    reporter_role: str
    affected_person_ref: str
    risk_categories: list[str]
    immediate_safety_signal: bool
    trusted_contacts: list[str]
    reported_accounts: list[ReportedAccount]
    reported_urls: list[str]
    evidence_ids: list[str]
    timeline: list[TimelineEvent]
    privacy_classification: str
    escalation_status: str
    user_visible_actions: list[SafeAction]
    internal_actions: list[CaseAction]
```

### PWA safeguarding surfaces

- One-tap **Start Safety Case**.
- Guided evidence capture.
- Safe-exit control.
- Trusted-contact panel.
- Account recovery checklist.
- Privacy exposure scan.
- Impersonation report builder.
- Abuse timeline.
- Secure evidence vault.
- Human support handoff.
- Low-bandwidth and offline mode.
- Accessibility mode with simplified language and large controls.

---

## 14. Guardian PWA command centre

### Main navigation

```text
Command Centre
Cases
Safeguarding
Incidents
Investigations
Assets
Identity
Findings
Evidence
Tools
Agents
Models
Memory
Policies
Approvals
Threat Intelligence
Telemetry
Recovery
Administration
```

### Command Centre widgets

- Global posture score.
- Active critical cases.
- Vulnerable-user safety escalations.
- Live Temporal workflows.
- Agent and model health.
- Tool worker queue and capacity.
- Asset coverage.
- Findings by severity and SLA.
- Detection stream.
- Recent blocked actions.
- Evidence integrity status.
- Supply-chain health.
- Backup and recovery status.
- Current change windows.
- Open approval packets.

### Case room

- Objective and scope.
- Asset relationship graph.
- Live agent graph.
- Plan and current step.
- Tool stream.
- Evidence timeline.
- Findings and confidence.
- Critic challenges.
- Remediation options.
- Approval packet.
- Verification results.
- Signed final report.

### Tool room

- Capability catalogue.
- Installed tool versions.
- Health and provenance.
- Connector test status.
- Parser coverage.
- Worker image digest.
- Last execution.
- Failure rate and duration.
- Update candidate.
- SBOM and vulnerabilities.

### Model operations room

- Models by role.
- Provider health.
- Evaluation scorecards.
- Prompt versions.
- Tool-call accuracy.
- Hallucination and refusal regression.
- Prompt-injection resistance.
- Cost and token consumption.
- Local inference capacity.
- Fallback and circuit-breaker state.

### PWA protection requirements

- WebAuthn/passkeys.
- Strict CSP and Trusted Types.
- Service-worker update integrity.
- Encrypted offline case cache with expiry.
- No secrets in IndexedDB or Cache Storage.
- CSRF and origin protections.
- Session inactivity and device revocation.
- Signed release manifest.
- Source-map control.
- Push-notification privacy.
- Accessibility acceptance tests.
- Offline read-only incident pack.

---

## 15. Canonical data models

Create versioned schemas for:

```text
Asset
OwnershipEvidence
Scope
GuardianCase
CaseEvent
Plan
PlanStep
Hypothesis
Observation
RiskAssessment
SafetyImpact
ToolManifest
Capability
ExecutionJob
ToolResult
RawArtifact
EvidenceArtifact
EvidenceBundle
Finding
FindingLocation
ThreatIntelIndicator
DetectionEvent
Incident
SafeguardingCase
ConsentRecord
Approval
RemediationOption
CodeChange
VerificationResult
RecoveryPoint
RecoveryTest
ModelProfile
ModelDecision
PromptVersion
MemoryRecord
AuditEntry
Attestation
```

### Common finding model

```python
class Finding(BaseModel):
    finding_id: UUID
    case_id: UUID
    title: str
    description: str
    category: str
    severity: str
    confidence: float
    asset_refs: list[str]
    locations: list[FindingLocation]
    evidence_ids: list[str]
    tool_ids: list[str]
    cwe: list[str]
    cve: list[str]
    owasp: list[str]
    attack_techniques: list[str]
    safety_impact: SafetyImpact
    exploitability: str
    exposure: str
    status: str
    remediation: list[RemediationOption]
    first_seen: datetime
    last_seen: datetime
```

### Common evidence model

```python
class EvidenceArtifact(BaseModel):
    evidence_id: UUID
    case_id: UUID
    kind: str
    media_type: str
    source: str
    source_tool: str | None
    source_version: str | None
    collected_at: datetime
    sha256: str
    size_bytes: int
    storage_uri: str
    redaction_state: str
    classification: str
    retention_policy: str
    chain_of_custody: list[CustodyEvent]
    signature: str | None
    attestation_uri: str | None
```

---

## 16. Expanded configuration map

```yaml
guardian:
  version: "1.0.0"
  environment_default: staging
  fail_closed: true

  control_plane:
    api: fastapi
    workflow: temporal
    reasoning: langgraph
    policy: opa
    relationship_authorisation: openfga
    identity: keycloak
    workload_identity: spire

  models:
    gateway: guardian-native
    providers: [anthropic, openai-compatible, vllm, ollama, llama-cpp, sglang]
    roles:
      strategic: claude
      investigator: claude
      code: claude
      classifier: local
      critic: independent
      verifier: independent
      embedding: local
      reranker: local
    structured_outputs: true
    prompt_registry: true
    evaluation_required: true

  reasoning:
    max_graph_steps: 40
    max_tool_calls: 120
    max_replans: 12
    max_parallel_branches: 12
    durable_checkpoints: true
    critic_enabled: true
    verifier_enabled: true
    evidence_minimum_per_finding: 2

  execution:
    default_runtime: gvisor
    high_isolation_runtime: firecracker
    browser_runtime: gvisor
    rootless: true
    ephemeral_workspaces: true
    image_signature_verification: true
    sbom_required: true
    streamed_logs: true

  tools:
    registry: configs/tools/registry.yaml
    discovery: manifest
    health_checks: true
    result_schemas: true
    provenance_required: true
    parser_conformance_required: true

  mcp:
    enabled: true
    gateway: internal
    registry: configs/mcp/servers.yaml
    schema_filtering: true
    provenance_required: true

  memory:
    metadata: postgresql
    vectors: qdrant
    search: opensearch
    graph: neo4j
    objects: minio
    cache: valkey
    hybrid_retrieval: true
    reranking: true
    permission_filtering: true

  evidence:
    immutable_index: immudb
    object_store: minio
    signing: cosign
    attestation: witness
    chain_of_custody: true
    worm_retention: true

  findings:
    authority: defectdojo
    dependency_authority: dependency-track
    deduplication: true
    correlation: true
    sla_tracking: true

  safeguarding:
    enabled: true
    separate_access_policy: true
    consent_records: true
    evidence_vault: true
    safe_exit: true
    trusted_contacts: true
    human_escalation: true

  detection:
    runtime: [falco, tetragon, tracee]
    endpoint: [wazuh, osquery, velociaptor]
    network: [suricata, zeek, crowdsec]
    rules: [sigma, yara]
    threat_intel: [misp, opencti]

  observability:
    tracing: opentelemetry
    metrics: prometheus
    logs: loki
    traces: tempo
    dashboards: grafana
    alerts: alertmanager
    slos: true

  recovery:
    backups: restic
    kubernetes: velero
    postgres: pgbackrest
    object_lock: true
    restore_drills: scheduled
```

---

## 17. Policy map

### OPA packages

```text
guardian.scope
guardian.ownership
guardian.action
guardian.model
guardian.tool
guardian.shell
guardian.browser
guardian.mcp
guardian.network
guardian.secret
guardian.evidence
guardian.memory
guardian.finding
guardian.remediation
guardian.release
guardian.incident
guardian.safeguarding
guardian.retention
guardian.recovery
guardian.emergency
```

### Policy decision input

```json
{
  "actor": {},
  "case": {},
  "scope": {},
  "asset": {},
  "ownership": {},
  "capability": {},
  "tool": {},
  "model": {},
  "execution": {},
  "network": {},
  "credentials": {},
  "evidence": {},
  "approvals": [],
  "time": {},
  "environment": "staging"
}
```

### Policy decision output

```json
{
  "allow": true,
  "reason": "approved capability within verified case scope",
  "obligations": [
    "record_raw_evidence",
    "capture_trace",
    "destroy_worker",
    "revoke_credentials"
  ],
  "execution_profile": "scanner-standard",
  "expires_at": "..."
}
```

---

## 18. Core workflows

### Repository assurance

```text
Inventory → ownership → clone at immutable commit → SBOM → secrets → SAST
→ dependency reachability → IaC → tests → findings correlation → patch options
→ regression → draft PR → evidence bundle
```

### PWA release assurance

```text
Build reproducibly → dependency/SBOM → SAST → secret/source-map scan
→ CSP/Trusted Types → service-worker tests → offline tests → accessibility
→ browser matrix → API contract → ZAP baseline → provenance/signature
→ canary → telemetry watch → release evidence
```

### Account-compromise case

```text
Consent → identity verification → active-session inventory → recovery journey
→ credential/session reset plan → device review → evidence preservation
→ trusted contact option → post-recovery monitoring → closure pack
```

### Vulnerable-user safeguarding case

```text
Consent → immediate-risk triage → privacy classification → evidence capture
→ timeline → impersonation/URL/account analysis → account safety checks
→ user-visible safe actions → human escalation → evidence export → follow-up
```

### Incident response

```text
Alert → correlate → severity → incident declaration → collect volatile evidence
→ contain → preserve artefacts → eradicate → restore → verify → monitor
→ postmortem → rules and memory update
```

### Continuous threat hunt

```text
Hypothesis → data-source check → query plan → runtime/network/endpoint search
→ correlation → evidence → finding or closure → detection-rule candidate
```

### Disaster recovery

```text
Select recovery objective → verify backup → isolated restore → integrity checks
→ service tests → identity/key tests → evidence verification → RTO/RPO report
```

---

## 19. Event mesh

Use a common event envelope across Temporal, NATS/Redpanda and telemetry.

```json
{
  "event_id": "uuid",
  "event_type": "guardian.tool.completed",
  "version": 1,
  "occurred_at": "RFC3339",
  "case_id": "uuid",
  "workflow_id": "string",
  "trace_id": "string",
  "actor": "tool-router",
  "asset_refs": ["asset:repo:guardian"],
  "classification": "internal",
  "payload": {},
  "payload_sha256": "...",
  "signature": "..."
}
```

### Event families

```text
guardian.case.*
guardian.scope.*
guardian.ownership.*
guardian.plan.*
guardian.model.*
guardian.policy.*
guardian.tool.*
guardian.browser.*
guardian.finding.*
guardian.evidence.*
guardian.approval.*
guardian.remediation.*
guardian.release.*
guardian.detection.*
guardian.incident.*
guardian.safeguarding.*
guardian.recovery.*
guardian.learning.*
```

---

## 20. Testing and evaluation matrix

### Conventional software tests

- Unit tests for every pure service and schema.
- Contract tests for every connector and parser.
- Integration tests with real local services.
- Property tests for policy, scope, approvals, evidence and state transitions.
- Browser tests for all PWA journeys.
- Accessibility tests for every critical flow.
- Performance tests for case, event and evidence volume.
- Chaos tests for worker, model, vector DB, Temporal and object-store failure.
- Restore tests for every backup type.
- Golden fixture tests for scanner result parsing.

### AI evaluations

- Correct capability selection.
- Tool argument schema accuracy.
- Evidence-grounded conclusions.
- Confidence calibration.
- Hallucinated finding rate.
- False-positive and false-negative rate.
- Prompt-injection resistance.
- Context-poisoning resistance.
- Cross-case data isolation.
- Sensitive-data leakage.
- Critic effectiveness.
- Independent verifier disagreement rate.
- Remediation correctness.
- Regression-test quality.
- Safe stopping behaviour.

### Release acceptance gates

```text
0 critical open defects in Guardian control paths
100% policy property-test pass
100% connector contract-test pass
100% image signature verification
100% required SBOM coverage
100% evidence schema validation
100% critical PWA accessibility journeys pass
0 unsigned production artefacts
0 floating Action or image references
successful backup restore drill
successful incident tabletop exercise
successful safeguarding workflow exercise
independent security review complete
```

---

## 21. Observability and SLOs

### Golden signals

- Case start latency.
- Workflow completion latency.
- Policy decision latency and denial rate.
- Tool queue depth and duration.
- Worker creation failure rate.
- Model latency, errors and fallback rate.
- Retrieval quality and empty-context rate.
- Evidence commit and signature failure rate.
- Finding deduplication rate.
- Detection ingestion delay.
- Incident acknowledgement and containment time.
- Safeguarding human-escalation time.
- Backup age and restore success.

### Initial SLO targets

```text
Control API availability: 99.9%
Policy decision availability: 99.99%
Audit/evidence write durability: 99.999%
Critical alert delivery: 99.9% within 60 seconds
Case workflow replay success: 99.99%
PWA critical journey availability: 99.9%
Backup verification success: 100% scheduled checks
```

---

## 22. Build waves

### Wave 0 — Baseline and repository truth
- Freeze current schemas and tests.
- Generate an exact component inventory.
- Add ADR process and architecture tests.
- Convert roadmap status into machine-readable acceptance checks.

### Wave 1 — Typed contracts
- Add Pydantic case, finding, evidence, tool and decision schemas.
- Introduce versioned JSON schemas.
- Add parser fixture contracts.

### Wave 2 — Router fabric
- Create tool manifests and dynamic registry.
- Preserve the current router façade.
- Add capability resolver and health/provenance checks.

### Wave 3 — Execution workers
- Add rootless container executor.
- Add gVisor execution profile.
- Add job streaming, limits, cleanup and evidence collection.

### Wave 4 — Temporal durability
- Implement case workflow, signals, queries, retries and activity workers.
- Add workflow replay tests.
- Migrate the built-in linear path behind the compatibility façade.

### Wave 5 — LangGraph brain
- Implement typed state graph, planner, critic, verifier and stop conditions.
- Add deterministic test model.
- Add graph checkpoints and replay.

### Wave 6 — Model fabric
- Add native gateway interface and provider adapters.
- Add structured outputs, prompt registry, model health and fallback.
- Add local inference adapter.

### Wave 7 — Memory fabric
- Implement Qdrant and PostgreSQL wiring.
- Add hybrid retrieval, reranking, permissions and evaluation.
- Add evidence-grounded context packs.

### Wave 8 — Browser power
- Add isolated Playwright workers.
- Add PWA install/offline/update, accessibility and visual evidence.
- Add Playwright MCP behind Guardian's MCP gateway.

### Wave 9 — Connector expansion I
- Complete secrets, SAST, SCA, SBOM, provenance, IaC and container families.
- Add result normalisation and DefectDojo integration.

### Wave 10 — Connector expansion II
- Add API, DAST, browser, cloud, Kubernetes, identity and fuzzing families.
- Add Dependency-Track and GUAC integration.

### Wave 11 — Identity and secrets
- Add Keycloak, OpenFGA, SPIRE, OpenBao, SOPS, cert-manager and step-ca.
- Add passkeys and service identity to the PWA/control API.

### Wave 12 — Evidence and attestation
- Add immudb, MinIO WORM, Cosign, Witness and chain-of-custody services.
- Add signed case exports and evidence verification CLI.

### Wave 13 — Detection fabric
- Add Falco, Tetragon, Wazuh, Suricata, Zeek, CrowdSec and osquery adapters.
- Add event normalisation, Sigma/YARA and correlation.

### Wave 14 — Incident and threat intelligence
- Add IRIS, MISP and OpenCTI adapters.
- Build containment, collection, recovery and postmortem workflows.

### Wave 15 — Safeguarding birth
- Build safeguarding case state, consent, evidence vault, safe-exit and trusted-contact flows.
- Add account compromise, impersonation, harassment, stalking, doxxing and scam workflows.
- Complete accessible, low-bandwidth and offline PWA journeys.

### Wave 16 — PWA command centre
- Build live case graph, tool room, model room, evidence room, policy room and recovery room.
- Add WebSocket/SSE updates and push alerts.

### Wave 17 — Recovery fabric
- Add restic, Velero and pgBackRest.
- Automate restore exercises and evidence reports.

### Wave 18 — Evaluation and hardening
- Run Promptfoo, garak, PyRIT, DeepEval, Ragas, chaos tests and load tests.
- Complete independent review and remediation.

### Wave 19 — Production acceptance
- Run end-to-end case exercises.
- Run incident and safeguarding tabletop exercises.
- Verify backups, signatures, policies, approvals and rollback.
- Tag the first Guardian 1.0 release.

---

## 23. Definition of Guardian 1.0 born

Guardian 1.0 is complete only when it can:

1. Open a durable case from a user, release, finding, alert or schedule.
2. Verify the case scope and ownership evidence.
3. Build a permission-filtered context pack.
4. Create and challenge an investigation plan.
5. Select typed capabilities and execute multiple tool families.
6. Operate browser journeys and isolated shell workers.
7. Correlate code, cloud, identity, runtime, network and safeguarding evidence.
8. Produce confidence-scored findings with reproducible evidence.
9. Build patches, tests, rollout and rollback plans.
10. Route approval packets and resume workflows safely.
11. Verify remediation independently.
12. Produce signed, immutable evidence bundles.
13. Detect and manage live incidents.
14. Support vulnerable-user safeguarding cases through the PWA.
15. Recover from infrastructure loss using tested backups.
16. Learn from verified outcomes without learning unverified claims.
17. Show every significant state, decision and artefact in the PWA.

---

## 24. Source references

Repository sources:

- https://github.com/INVIS-ABLE/Guardian
- https://github.com/INVIS-ABLE/Guardian/blob/claude/laughing-ptolemy-zfeiiu/docs/agents.md
- https://github.com/INVIS-ABLE/Guardian/blob/claude/laughing-ptolemy-zfeiiu/docs/tooling_catalogue.md
- https://github.com/INVIS-ABLE/Guardian/blob/claude/laughing-ptolemy-zfeiiu/docs/hardening_roadmap.md
- https://github.com/INVIS-ABLE/Guardian/blob/claude/laughing-ptolemy-zfeiiu/docs/architecture/target_stack.md
- https://github.com/INVIS-ABLE/Guardian/blob/claude/laughing-ptolemy-zfeiiu/docs/architecture/components.yaml
- https://github.com/INVIS-ABLE/Guardian/blob/claude/laughing-ptolemy-zfeiiu/guardian.config.yaml

Key upstream references:

- https://github.com/langchain-ai/langgraph
- https://github.com/temporalio/sdk-python
- https://github.com/microsoft/playwright-mcp
- https://github.com/open-policy-agent/opa
- https://github.com/openfga/openfga
- https://github.com/google/gvisor
- https://github.com/firecracker-microvm/firecracker
- https://github.com/DefectDojo/django-DefectDojo
- https://github.com/DependencyTrack/dependency-track
- https://github.com/falcosecurity/falco
- https://github.com/cilium/tetragon
- https://github.com/OISF/suricata
- https://github.com/zeek/zeek
- https://github.com/qdrant/qdrant
- https://github.com/codenotary/immudb
- https://github.com/sigstore/cosign
- https://github.com/in-toto/witness
- https://github.com/dfir-iris/iris-web
- https://github.com/MISP/MISP
- https://github.com/OpenCTI-Platform/opencti

---

# End state

Guardian is no longer a collection of scanner wrappers. It is a coherent security and safeguarding operating system: durable cases, structured reasoning, typed execution, isolated browser and shell workers, broad open-source coverage, live detection, immutable evidence, controlled remediation, tested recovery and a PWA designed to protect vulnerable people effectively.
