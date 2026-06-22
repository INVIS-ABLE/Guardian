
# Claude Code Directive — Build Guardian Final Power-Up

You are working inside the public repository `INVIS-ABLE/Guardian` on the active Guardian branch.

Read these files before editing:

1. `README.md`
2. `GUARDRAILS.md`
3. `SECURITY_POLICY.md`
4. `guardian.config.yaml`
5. `core/policy_gate.py`
6. `core/guardrails.py`
7. `core/router.py`
8. `core/brain.py`
9. `core/memory.py`
10. `docs/agents.md`
11. `docs/tooling_catalogue.md`
12. `docs/hardening_roadmap.md`
13. `docs/architecture/target_stack.md`
14. `docs/architecture/components.yaml`
15. `GUARDIAN_FINAL_POWERUP_MASTER_MAP.md`

## Mission

Evolve Guardian into the architecture specified in `GUARDIAN_FINAL_POWERUP_MASTER_MAP.md` while preserving compatibility with the current CLI, current configuration, current tests, current agent names and the central authorisation path.

## Non-negotiable engineering rules

- Do not replace the existing project with a new scaffold.
- Extend current modules through compatibility façades.
- `core/policy_gate.py` remains the sole authority for action decisions.
- Every execution path must enter through the Guardian router fabric.
- Model output is untrusted input and must pass typed schema validation.
- The model selects capabilities, not arbitrary executable command strings.
- Every connector must have a manifest, input schema, output schema, parser, fixtures and contract tests.
- Every execution must produce a trace ID, audit event and evidence record.
- Production code must not contain placeholder implementations, fake success responses or silent `pass` branches.
- Tests must fail closed when a required production dependency is unavailable.
- Keep development adapters deterministic and clearly separated from production adapters.
- All public functions and schemas require type annotations.
- Use Python 3.12-compatible code and the repository's existing formatting/linting conventions.
- Update documentation and the machine-readable component manifest with every subsystem.
- Keep commits narrow, reviewable and reversible.

## Working method

For each wave:

1. Audit the current implementation and write a short gap note in the PR description.
2. Add or update schemas first.
3. Add failing tests.
4. Implement the smallest complete vertical slice.
5. Run unit, property, contract and integration tests relevant to the slice.
6. Update documentation, configuration examples and component status.
7. Run the full repository quality and security gates.
8. Commit with a conventional message.

## Required waves

### Wave 0 — Baseline

- Add `docs/architecture/final_powerup_map.md` from the supplied master map.
- Add ADR templates and architecture invariant tests.
- Generate a machine-readable current-state report from `components.yaml`, connector registry, agent registry and router capabilities.

Acceptance:

- Current tests pass unchanged.
- Inventory test confirms every registered connector and capability is documented.

### Wave 1 — Core schemas

Create versioned Pydantic models and JSON schemas for case, event, finding, evidence, tool manifest, execution job, model decision, approval, remediation and verification.

Acceptance:

- Schema round-trip tests.
- Backward compatibility adapters for current `RouteResult`, connector results and evidence reports.

### Wave 2 — Tool registry and router fabric

Create `core/tools/` and make `core/router.py` a compatibility façade over the new typed router. Load manifests from `connectors/manifests/`. Preserve existing capability names.

Acceptance:

- Existing router tests pass.
- Unknown, malformed and unhealthy tools fail before execution.
- Every current connector is represented by a manifest.

### Wave 3 — Execution service

Implement local-development and rootless-container executors, followed by gVisor support. Add job lifecycle, timeouts, quotas, streamed output, evidence capture and cleanup.

Acceptance:

- Contract tests demonstrate worker creation, execution, timeout, cancellation and destruction.
- No connector invokes host subprocesses directly in production mode.

### Wave 4 — Temporal workflow

Implement durable case workflow, activity boundaries, signals, queries, timers, retries and cancellation. Add deterministic replay tests.

Acceptance:

- A case survives worker restart.
- Human approval can suspend and resume a case.
- Policy is re-evaluated immediately before execution.

### Wave 5 — LangGraph reasoning

Implement typed case state, planner, critic, investigator, verifier, confidence and stop-condition nodes. Use a deterministic fake model for tests.

Acceptance:

- Graph test covers investigate, replan, remediate and close paths.
- Invalid model output cannot reach the tool router.
- Critic and verifier results are stored as case events.

### Wave 6 — Model gateway

Implement a Guardian-native provider interface with Anthropic, OpenAI-compatible, vLLM, Ollama, llama.cpp and deterministic adapters. Add prompt registry, structured output validation, budgets, health, fallback and telemetry.

Acceptance:

- Provider failover test.
- Budget exhaustion test.
- Prompt-version and model-version recorded in every decision event.

### Wave 7 — Memory fabric

Split `core/memory.py` into the new memory package while retaining its public API. Implement PostgreSQL metadata and Qdrant vectors. Add hybrid retrieval, reranking, permissions, redaction and retrieval evaluation.

Acceptance:

- Staging/production cannot silently use the local fallback.
- Cross-case and restricted safeguarding memory isolation tests pass.
- Retrieval regression score meets the configured threshold.

### Wave 8 — Browser execution

Implement isolated Playwright workers, traces, HAR, screenshots, video, console, accessibility and PWA journeys. Add Playwright MCP through the Guardian MCP gateway.

Acceptance:

- Chromium, Firefox and WebKit smoke journeys.
- PWA install/offline/update journey.
- Artefacts are stored and attached to the case.

### Wave 9 — Connector families

Create connectors and manifests for the priorities listed in the master map. Start with secrets, SAST, SCA, SBOM, provenance, IaC, container, API and DAST. Normalise findings and evidence.

Acceptance:

- Golden fixtures for every parser.
- SARIF/CycloneDX support where relevant.
- Findings deduplicate across two different tools.

### Wave 10 — Identity, evidence and findings

Add Keycloak, OpenFGA, SPIRE, OpenBao, SOPS, immudb, MinIO, Cosign, Witness, DefectDojo and Dependency-Track integrations.

Acceptance:

- PWA requires OIDC and role checks.
- Workloads obtain short-lived identity.
- Evidence verification CLI proves bundle hashes and signatures.

### Wave 11 — Detection and incident response

Add event adapters for Falco, Tetragon, Wazuh, Suricata, Zeek, CrowdSec and osquery; add Sigma/YARA; add IRIS, MISP and OpenCTI adapters.

Acceptance:

- Synthetic detection produces a durable incident case.
- Incident timeline contains source evidence and correlation decisions.
- Recovery verification closes the incident only after checks pass.

### Wave 12 — Safeguarding fabric

Implement consent, privacy classification, safeguarding case state, evidence vault, safe-exit, trusted contacts, account-compromise, impersonation, harassment, stalking, doxxing and scam workflows.

Acceptance:

- Critical journeys pass keyboard and screen-reader tests.
- Restricted safeguarding records are isolated from ordinary cases.
- User-facing evidence exports are redacted and integrity-verifiable.

### Wave 13 — PWA command centre

Implement the navigation and rooms in the master map. Add live case updates, graph visualisation, evidence viewer, tool health, model scorecards, approvals, incident room and recovery room.

Acceptance:

- PWA meets the critical accessibility journey suite.
- Offline mode exposes only the encrypted, permitted incident pack.
- No sensitive data persists beyond configured expiry.

### Wave 14 — Recovery and acceptance

Add restic, Velero and pgBackRest orchestration, automated restore drills, full eval harness, chaos tests, load tests and release evidence.

Acceptance:

- Full 1.0 acceptance gate in the master map passes.
- Component manifest marks each delivered component honestly.
- Release is reproducible, signed and accompanied by SBOM, provenance and evidence bundle.

## Deliverable format after every wave

Return:

1. Summary of completed work.
2. Exact files added/changed.
3. Tests added and commands run.
4. Current test results.
5. Security or compatibility concerns still open.
6. Next wave entry criteria.

Begin with Wave 0. Do not jump ahead until the current wave has a complete vertical slice and passing acceptance tests.
