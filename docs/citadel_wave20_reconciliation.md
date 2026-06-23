# Crown Citadel — Wave 20 reconciliation report

Wave 20 is the **honest audit + vertical slice** that precedes Citadel implementation. It reconciles
the existing repository against the Citadel spec, fixes owners, and stands up the machine-readable
manifests + invariant tests. No second owner is created for any existing production function.

## 1. Capability reconciliation (Systems 21–40)

| # | System | Status | Authoritative owner (existing or planned) | Independent verifier |
|---|--------|--------|--------------------------------------------|----------------------|
| 21 | Root-of-Trust Fabric | partial | `core/machine_attestation.py` (+ TPM/Keylime/SPIRE) | `citadel/root_of_trust/verifier.py` |
| 22 | Confidential Execution | partial | `isolation/sandbox.py` (+ Confidential Containers) | `citadel/confidential/verifier.py` |
| 23 | Cryptographic Agility | planned | `citadel/crypto_agility/inventory.py` (liboqs) | `citadel/crypto_agility/downgrade.py` |
| 24 | Key Custody & Threshold | planned | OpenBao | `citadel/quorum/threshold.py` |
| 25 | Formal State-Machine | planned | TLA+/Apalache (models `orchestration/state_machine.py`) | `citadel/formal/counterexamples.py` |
| 26 | Protocol Verification | planned | Tamarin | `citadel/formal/protocol.py` (ProVerif/Verifpal) |
| 27 | Verified Policy | present | OPA (`policies/opa/guardian.rego`) | `core/policy_gate.py` (parity, `test_opa_parity.py`) |
| 28 | Reproducible Build Foundry | partial | `supplychain/provenance.py` (+ Nix/Rekor) | `supplychain/admission.py` |
| 29 | Exposure Intelligence | partial | Cartography | `ownership/verifier.py` |
| 30 | Deception Grid | planned | OpenCanary/Canarytokens | `citadel/deception/evidence.py` |
| 31 | Data-Exfiltration Detection | partial | Presidio (+ gitleaks) | `isolation/egress.py` |
| 32 | Defensive Degradation | present | `containment/adapter.py` | `core/twin/assessment.py` |
| 33 | Immutable Cyber Vault | partial | `recovery/backup.py` | `recovery/drill.py` |
| 34 | Chaos & Recovery Lab | partial | `core/twin` | `resilience/health.py` |
| 35 | Secure Time & Ordering | partial | chrony/NTS | `core/event_fabric/stream.py` |
| 36 | Continuity Mode | partial | `resilience/health.py` | `citadel/continuity/reconciliation.py` |
| 37 | Shadow Guardian Federation | present | `shadow_guardian/verifier.py` | `citadel/quorum/signatures.py` |
| 38 | Trust Quorum | partial | `orchestration/approvals.py` | `citadel/quorum/evidence.py` |
| 39 | Control Proof Engine | partial | `citadel/control_proof/claims.py` | `docs/governance/SECURITY_INVARIANTS.md` |
| 40 | Integrity Constitution | partial | `policies/privacy_invariants.yaml` | `citadel/constitution/runtime_checker.py` |

**Present: 3 · Partial: 11 · Planned: 6.** No duplicate authoritative owner (enforced by
`tests/test_citadel_capabilities_manifest.py`).

## 2. Brain V2 implementation report

Already real in `core/brain/`: `orchestrator.py` (GuardianBrain), `state.py` (typed immutable case
state), `graph.py` (**LangGraph** bounded reasoning graph — wired and used), `nodes.py` (pure delta
nodes), `failures.py` (taxonomy), `temporal_workflow.py` (**Temporal** durable outer workflow).
Reasoning-graph owner = LangGraph; durable-workflow owner = Temporal; authority = OPA via
`core/policy_gate.py`. Capability token is `core/tools/capability.py::CapabilityToken` (single-use,
binding-checked). No `AttestedCapabilityEnvelope` class yet — the Citadel envelope (spec §7) is the
**planned** superset that adds platform/build/identity attestation fields around the existing token.

## 3. Sovereign-plane implementation report

The 20-system Sovereign catalogue (`docs/architecture/sovereign_capabilities.yaml`) is complete; the
four powers (`core/brain`, `core/policy_gate`, `core/tools`, `core/verifier`) all exist as distinct
modules. Evidence fabric (`core/evidence`, `core/event_fabric`, `core/audit.py`), independent
verifier (`core/verifier.py` key-transparency monitor), and Shadow Guardian
(`shadow_guardian/verifier.py`, read-only + freeze latch) are present. immudb/MinIO are planned
system-of-record backends; a local hash chain is the cache today.

## 4. Gap analysis (true GAPs needing new owners)

- **Crypto agility (23)** — no runtime crypto inventory / allowlist / downgrade detection / PQ plan.
- **Key custody & threshold (24)** — no threshold signing or ceremony framework (OpenBao planned).
- **Formal verification (25, 26)** — no `.tla`/Tamarin models yet (state machine + crypto exist).
- **Deception (30)** — no honeytokens/decoys.
- **Exposure intelligence (29)** — partial; no continuous external asset feed yet.

## 5. Trust-root inventory

Six roots already modelled (`docs/architecture/roots_of_trust.md`): human, workload, machine,
software, target, evidence. Machine root: `core/machine_attestation.py` (TPM/PCR/IMA). Software
root: `supplychain/*` + `attestation/signing.py` (Ed25519). Evidence root: `attestation/evidence_store.py`
+ `core/verifier.py`. Citadel adds the **attestation-root** and **transparency-log** roots (planned,
quorum-rotated).

## 6. Key inventory (classes → custody)

root_signing · release_signing · attestation_root · evidence_signing · recovery_root · certificate_authority
· backup_encryption · transparency_log · service_identity · user_export. Today: Ed25519
(`attestation/signing.py`) + HMAC fallback. Planned custody owner: OpenBao with quorum ceremonies
(`configs/citadel/quorum.yaml`).

## 7. Build-path inventory

`pyproject.toml` + `uv.lock` (pinned, `uv lock --check` CI gate) · `.github/workflows/*` (CodeQL,
Semgrep, Trivy, Gitleaks, OPA parity, ZAP, twin-gate, governor). Admission/provenance/SBOM logic in
`supplychain/{admission,provenance,sbom}.py` (code ready; cosign/witness/Rekor CI wiring planned).
Reproducibility + transparency = the build_foundry gap to close in Wave 28/29.

## 8. Deployment-path inventory

`docker-compose.yml` (local) + planned phased stack in `docs/architecture/components.yaml` (Keycloak,
OpenBao, OpenFGA, SPIRE, immudb, Harbor, Dependency-Track, DefectDojo, Falco, Cilium…). Every place
production code can enter is a build-path or deployment-path above; all are pinned by digest/commit.

## 9. Recovery-path inventory

`recovery/backup.py` (WORM + SHA-256), `recovery/drill.py` (restore drill, RPO/RTO), `resilience/health.py`
(control-plane health, fail-closed), `core/ai/routing.py` (local-model continuity). Cyber-vault
isolation (separate identity/network plane, immutable retention) is the Wave-36 gap. See
[`citadel_recovery_model.md`](citadel_recovery_model.md).

## 10. What Wave 20 delivered

5 canonical docs · 5 architecture manifests · 12 configs · 10 invariant test modules (49 tests, 1
honest xfail). Existing tests remain green. The catalogue exposes unbuilt systems honestly via
`status` + the `test_every_system_is_runtime_enforced` xfail. Implementation proceeds with Waves
21–39, each a tested vertical slice gated by [`citadel_acceptance_gate.md`](citadel_acceptance_gate.md).
