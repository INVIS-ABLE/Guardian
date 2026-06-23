# Final Power-Up — wave status

Honest delivery tracker for the waves in `build_directive.md` / `final_powerup_map.md`.
A wave is **delivered** only when its acceptance criteria pass with tests. Anything not
yet delivered is **planned** — never marked done prematurely.

| Wave | Title | Status | Evidence |
| --- | --- | --- | --- |
| 0 | Baseline and repository truth | **delivered** | `core/inventory.py`, `reports/audit/current_state.{json,md}`, `tests/test_repo_inventory.py`, ADR-0001, `invariants.md` |
| 1 | Typed contracts / core schemas | **delivered** | `core/schemas/` (registry, `CaseEvent`, `ExecutionJob`, `GuardianDecision`, `RemediationOption`/`CodeChange`, `Approval`, `EvidenceBundle`, adapters), `schemas/*.json` (23), router emits `CaseEvent`s (`core/router.py`), `tests/test_schemas.py`, `tests/test_router_events.py` |
| 2 | Router fabric | partial (pre-existing `core/tools/` manifest+token gateway) | `core/tools/`, `test_tool_manifest.py`, `test_router*.py` |
| 3 | Execution workers | planned | — |
| 4 | Temporal durability | partial (pre-existing `core/brain/temporal_workflow.py`) | `test_orchestration.py` |
| 5 | LangGraph brain | partial (pre-existing reasoning graph) | `core/brain/graph.py`, `test_reasoning_graph.py`, `test_brain.py` |
| 6 | Model fabric | partial (pre-existing `core/ai/` gateway + adapters) | `test_ai_gateway.py` |
| 7 | Memory fabric | partial (pre-existing `core/memory.py` façade) | `test_memory.py` |
| 8 | Browser power | planned | — |
| 9–10 | Connector expansion I & II | planned | expanded registry catalogued (`configs/tools/guardian.tool-registry.expanded.yaml`) |
| 11 | Identity and secrets | partial (pre-existing `identity/`) | `test_identity.py`, `test_credential_audit.py` |
| 12 | Evidence and attestation | partial (pre-existing `attestation/`, `core/evidence/`) | `test_evidence_store.py`, `test_attestation.py`, `test_signing.py` |
| 13 | Detection fabric | partial (pre-existing `detection/`) | `test_detection.py` |
| 14 | Incident and threat intel | planned | — |
| 15 | Safeguarding birth | planned | safeguarding agent stub present (`agents/__init__.py`) |
| 16 | PWA command centre | partial (pre-existing `dashboard/`) | — |
| 17 | Recovery fabric | planned | — |
| 18 | Evaluation and hardening | partial (pre-existing `eval/`, simulators) | `eval/`, `test_simulators.py` |
| 19 | Production acceptance | planned | — |

> "partial" reflects authoritative machinery already in the repository that predates the
> Final Power-Up and will be evolved in place through compatibility façades — not a claim
> that the wave's full acceptance criteria are met. The authoritative, machine-checked
> view of what exists is `reports/audit/current_state.json`.

## Wave 0 acceptance — met

- [x] Existing tests pass unchanged (377 → still passing; suite now 393 with new tests).
- [x] Every registered agent documented (`agent_inventory.md`, enforced).
- [x] Every registered connector documented (`connector_inventory.md`, enforced).
- [x] Every capability documented (`capability_inventory.md`, enforced).
- [x] Existing architecture represented truthfully (`reports/audit/current_state.json`).
- [x] Inventory test confirms registries ⊆ documentation and no report drift.

## Wave 1 entry criteria (next)

- Wave 0 merged and green in CI.
- Add versioned Pydantic + JSON schemas for case, event, finding, evidence, tool
  manifest, execution job, model decision, approval, remediation, verification.
- Provide backward-compatibility adapters for the current `RouteResult`, connector
  results and evidence reports, with round-trip and migration tests.
