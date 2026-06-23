# Guardian Level 6 — Adaptive Immune Fortress

Level 6 turns Guardian into a continuously sensing, evidence-grounded, self-healing and
**safely adaptive** defensive operating system. It **extends** Level 5 — it does not
replace or duplicate any existing authority:

| Authority | Stays the sole owner of |
|---|---|
| OPA | authorisation |
| Temporal | durable workflows |
| Plan Compiler | AI proposal → executable plan |
| Capability Authority | execution permission |
| OpenBao | secrets |
| immudb | immutable evidence |
| DefectDojo | vulnerability findings |
| Git | approved desired state |
| Shadow Guardian | independent verification |
| Privacy Fabric | structurally outside message plaintext + keys |

> **Not built, by design:** no Guardian Adversary, no autonomous offensive capability.

This is a **multi-phase programme** (directive §38, Phases 1–10). This document tracks
what has landed and what is queued.

## What has landed — Phase 1 constitutional core (`adaptive/`)

The autonomic *governor*: it holds no new authority, executes nothing, and never touches
private content. It produces typed recommendations and budgets the existing authorities
consume.

| Module | Directive | Purpose |
|---|---|---|
| `adaptive/autonomy/states.py` | §2, §3 | The five **autonomy classes** (A observe · B investigate · C engineer · D reversible heal · E approval-bound production) and the seven **control states** (NORMAL · WATCH · DEGRADED · DEFENSIVE · CONTAINMENT · RECOVERY · FROZEN) with a deterministic, authority-aware transition machine. The Brain may *recommend* a transition but may not *force* a higher-authority state; it may always make Guardian safer (→ DEGRADED / FROZEN) on its own. |
| `adaptive/autonomy/degradation.py` | §34 | The typed `EnvironmentHealth` snapshot (each authority/sensor HEALTHY · DEGRADED · MISSING, plus telemetry completeness, recent repair success, incident severity). |
| `adaptive/autonomy/budgets.py` | §34, §13, §17, §35 | `compute_autonomy_budget()` — deterministically narrows the permitted autonomy classes as uncertainty rises. Every removal records a reason. |
| `adaptive/healing/contracts.py` | §5, §7, §27 | The `HealingContract` (parses the directive's example YAML), the canonical reversible `RepairAction`s mapped to the §7 healing-hierarchy layers, structural privacy/rollback enforcement, and `assert_repair_allowed()` — **Guardian refuses to repair a service without a valid contract**. |
| `adaptive/healing/runbooks.py` | §6 | The restricted **Healing Runbook IR** — typed `RepairAction`s bound to exact targets with bounded scalar args, **no arbitrary shell**; mandatory rollback/abort/verification criteria and budgets (max operations/duration/blast-radius/cooldown), rejected at construction otherwise. |
| `adaptive/healing/compiler.py` | §6, §22 | The **runbook compiler + 10-gate pipeline**. Decides the deterministic gates (schema · ownership · data-classification) fail-closed; the authority-owned gates (CUE · Z3 · OPA · synthetic · staging · rollback-verification · human-approval) stay `PENDING_EXTERNAL` until a signed `GateAttestation` arrives. A runbook is `production_eligible` only when **all ten** pass. `plan_execution_jobs()` materialises operations into the existing `core.schemas.execution.ExecutionJob` (never shell), each still requiring a one-use capability token. |
| `adaptive/healing/hierarchy.py` | §7 | **Self-healing hierarchy selection** — picks the *lowest viable* repair layer (1 process replacement → 10 regional recovery) and refuses to jump to a broader repair while a narrower one is viable. |
| `adaptive/healing/anti_oscillation.py` | §35 | **Anti-oscillation governor** — per-target repair locks, cooldowns, per-window rate limits, loop/flapping detection, and a freeze-and-escalate after repeated failure. Grants nothing; only allows or refuses, with a reason. |
| `adaptive/slo/definitions.py` | §9 | **SLOs** including the INVISABLE invariant objectives (privacy, safeguarding, notification confidentiality, cross-tenant access, encryption-downgrade, key-directory consistency, account recovery), marked `privacy_critical`. Registry flags critical services with no SLO. |
| `adaptive/slo/burn_rates.py` | §9 | **Error-budget burn** — burn rate, remaining budget, exhaustion and multi-window severity bands. |
| `adaptive/slo/safety_gates.py` | §9 | **Availability-vs-privacy safety gate** — rejects any repair that regresses a privacy-critical invariant, regardless of availability benefit. |
| `adaptive/telemetry/completeness.py` | §13 | **Telemetry-completeness authority** — scores each sensor's health (silence, schema drift, auth/signature, data loss, clock skew, latency); a silent sensor is *not* a healthy system. Per-service score is the weakest sensor and feeds the autonomy budget. |
| `adaptive/controls/effectiveness.py` | §30 | **Control-effectiveness scoring** — flags controls installed-but-not-functioning, without telemetry, with stale rules, or with broken assumptions; cross-control analysis finds singly-protected assets and correlated failure. |
| `adaptive/prediction/` | §29 | **Advisory predictors** — certificate/key expiry, capacity exhaustion (linear projection), recovery readiness. Recommend only; never act, never authorise. |
| `adaptive/memory/immune.py` | §21 | **Immune memory** — five classes (known-good · incident · repair · control · uncertainty) with **decaying trust**: confidence halves over a half-life unless revalidated; retracted/expired items carry zero trust. No item is ever permanently trusted. |
| `adaptive/resilience/failover.py` | §23 | **Failover invariants** — a failover plan asserting any forbidden effect (bypass OPA / change residency / unapproved digest / weaken encryption / stale policy or secrets) is rejected; identity, policy and quorum must be preserved. |
| `adaptive/resilience/backups.py` | §26 | **Backup-verification** — a backup is *proven recovery* only when every check passes **including a real restoration test**; a successful backup job without a restore test is not proven recovery. |
| `adaptive/learning/outcomes.py` | §20 | **Outcome learning** — the typed `OutcomeRecord` and a learner that only ever emits `PROPOSED` proposals (new detection / threshold / runbook / eval case / docs / twin correction); proposals enter review and never change production directly. |

Class **E is never granted autonomously**: the budget only ever reasons about A–D, and E
always returns to the existing identity/ownership/policy/approval/attestation/evidence
gates.

### Key safety behaviours (all tested)

- Authority **decreases** as uncertainty increases (§34): missing evidence stops all
  execution; missing OPA disables healing; a stale digital twin disables target-changing
  actions; missing Shadow Guardian disables high-risk actions; missing model monitoring
  disables *model-driven* (not deterministic) healing; low telemetry completeness lowers
  confidence; repeated repair failure freezes automation (§35).
- The Brain cannot force itself into DEFENSIVE / CONTAINMENT / RECOVERY without an
  external `AuthorityGrant` (OPA / human / Capability Authority).
- A HealingContract with `rollback.required = false`, a non-`forbidden` privacy stance, or
  a `disable_feature` repair without an expiry is rejected at construction.

- The runbook compiler **cannot** make a runbook production-eligible on its own: OPA,
  staging, rollback-verification and human-approval gates require recorded external
  attestations, so "human approval before production eligibility" (§6) holds by construction.
- A runbook operation **cannot** carry shell — operations are typed `RepairAction`s with
  scalar args only; a `command`/`script`/`exec` arg or a non-scalar value is rejected.

- An availability win that regresses any privacy-critical SLO is **rejected** by the safety
  gate, regardless of the reliability benefit (§9).
- Repairs are attempted **lowest-layer-first** and a broader repair cannot skip a viable
  narrower one (§7); repeated failure **freezes** automation for that target and escalates (§35).

- A silent/unauthenticated sensor lowers telemetry completeness, which lowers autonomy (§13).
- Immune-memory trust **decays** unless revalidated; nothing is permanently trusted (§21).
- A failover that would loosen any control, or a backup never proven by restoration, is
  refused (§23, §26). The outcome learner can only *propose* — never change production (§20).

Tests: `test_autonomy_states`, `test_autonomy_budget`, `test_healing_contracts`,
`test_healing_runbooks`, `test_slo`, `test_anti_oscillation`, `test_healing_hierarchy`,
`test_telemetry_completeness`, `test_control_effectiveness`, `test_immune_memory`,
`test_prediction`, `test_adaptive_resilience`, `test_outcome_learning`,
`test_integrations_contracts` (142 cases).

## Integration-contract layer (`adaptive/integrations/`, directive §4, §10, §11, §15–16, §18, §24, §28)

The external control-plane and MLOps systems are infra-bound, so they land as **typed
manifests, adapter contracts and invariant validators** — the part CI and the gates
enforce. The real network-talking adapters are deployment-specific and implement these
shapes. **No integration grants authority**; all produce evidence/signals only.

| Module | Directive | Invariant enforced |
|---|---|---|
| `integrations/base.py` | §4, §11, §37 | `IntegrationAdapter` protocol + `assert_no_authority()` — an adapter claiming authority is refused. |
| `integrations/reconciliation.py` | §24 | One authoritative controller per resource (OpenTofu/Cluster API/Crossplane/Argo CD); conflicting ownership fails CI; Crossplane may not own constitutional infra. |
| `integrations/delivery.py` | §4, §10 | Failed safety signal → rollback; missing signal → hold (no promotion); only all-passing → promote. Keptn/Argo grant no authority. |
| `integrations/models.py` | §15, §16, §18 | Every model has an approved digest + reproducible dataset + rollback version; production endpoints use approved digests and are isolated/revocable; a model never self-promotes (promotion needs an `AuthorityGrant`); challengers promote only on clean safety/privacy/drift metrics. |
| `integrations/datasets.py` | §15, §19 | Datasets need lineage + validation; features need an owner, leakage check and allowed consumers; forbidden-class data (plaintext/keys/secrets) can never become training data. |
| `integrations/flink.py` | §11 | Jobs are signed, tenant-isolated, checkpointed and replay-tested, and **never grant authority**. |
| `integrations/wasm.py` | §28 | Extensions are signed, import-allowlisted, no-network/no-filesystem by default, fully limited (memory/fuel/timeout/output); Wasm cannot be the boundary for high-risk scanners. |

## Queued (genuinely external)

What remains is the *running deployment* of those systems (Argo/Karmada/Crossplane/Flink/
MLflow/KServe instances) and their concrete network adapters — operational wiring, not new
Guardian logic. They implement the contracts above and register as evidence sources.

## Acceptance-test traceability (directive §39)

Items already enforced in code by this increment:

| # | Acceptance criterion | Where |
|---|---|---|
| 9 | Drift reduces autonomy instead of increasing it | `budgets.py` (model health/monitoring → narrower budget) |
| 10 | Missing telemetry lowers confidence | `budgets.py` (`telemetry_completeness` thresholds) |
| 11 | Missing evidence stops execution | `budgets.py` (evidence authority MISSING → drop C+D) |
| 13 | Every autonomous repair has a HealingContract | `assert_repair_allowed()` fail-closed |
| 14 | Every autonomous repair has a tested rollback | `HealingContract.rollback.required`; `Runbook` requires `rollback_criteria` + `verification_steps` |
| 16 | Repeated repair failure freezes automation | `budgets.py` (`HEAL_MIN_REPAIR_SUCCESS`) |
| 30 | Private-message keys never enter Guardian | `PrivacyPolicy` structural `forbidden` |
| 31 | No self-healing action weakens encryption | `STRUCTURALLY_FORBIDDEN_REPAIRS` |
| 32 | No availability repair bypasses privacy controls | forbidden-repair intersection check |
| §6 | No runbook contains arbitrary shell; all actions compile into existing Plan IR (`ExecutionJob`) | `runbooks.py` (no-shell, scalar-args); `compiler.plan_execution_jobs()` |
| §6 | Human approval before production eligibility | `compiler.py` (production needs all 10 gates incl. human-approval attestation) |
| 12 | Every critical service has an SLO | `slo/definitions.py` (`SLORegistry.services_without_slo`) |
| 16 | Repeated repair failure freezes automation | `anti_oscillation.py` (freeze + escalate) |
| §7 | Select lowest viable repair; no jump to broader | `hierarchy.py` (`select_repair`, `assert_no_layer_jump`) |
| §9 | Action improving availability but weakening privacy is rejected | `slo/safety_gates.py` |
| §35 | Anti-oscillation (cooldowns, locks, loop detection) | `anti_oscillation.py` |
| 10 | Missing telemetry lowers confidence | `telemetry/completeness.py` (silent sensor → low score → lower autonomy) |
| 22 | Multi-cluster failover preserves identity and policy | `resilience/failover.py` (`validate_failover`) |
| 23 | Backup restoration is tested before recovery is "proven" | `resilience/backups.py` (`is_proven_recovery`) |
| §20 | Learned proposals never change production directly | `learning/outcomes.py` (always `PROPOSED`) |
| §21 | No memory item receives permanent trust automatically | `memory/immune.py` (decaying `effective_trust`) |
| §29 | Predictors recommend; preventive action stays in approved envelopes | `prediction/` (advisory `Prediction`) |
| §30 | Identify controls installed-but-not-functioning / singly-protected assets | `controls/effectiveness.py` |
| 1 | No learning process changes OPA policy | `integrations/base.py` (`assert_no_authority`) |
| 2 | No model changes its own production manifest / self-promotes | `integrations/models.py` (`promote_challenger` needs `AuthorityGrant`) |
| 3 | No model directly issues capabilities | `integrations/base.py` (adapters grant no authority) |
| 4 | Every learned model has a reproducible dataset | `models.py` (`dataset_ref`); `datasets.py` |
| 5 | Every dataset has lineage and validation | `datasets.py` (`assert_dataset_governed`) |
| 6 | Every model has an approved registry version | `models.py` (`ModelManifest`, `eval_ref`) |
| 7 | Every production inference endpoint uses an approved digest | `models.py` (`assert_endpoint_valid`) |
| 8 | Every model can be rolled back | `models.py` (`rollback_version` required) |
| 24 | Conflicting reconciler ownership fails CI | `integrations/reconciliation.py` (`assert_no_conflicts`) |
| 34 | Wasm extensions have explicit capabilities and limits | `integrations/wasm.py` (`assert_wasm_safe`) |
| 35 | Event-processing state recovers from checkpoints | `integrations/flink.py` (checkpoint policy required) |

Remaining §39 items (15, 17, 19, 25–29, 33, 36–40) depend on the *running* external systems
(failover drills, restoration tests, region loss) and are validated by their contracts here
plus operational rehearsal; this matrix grows as each system is deployed.

## Design principle (directive §40)

Build intelligence broadly. Grant authority narrowly. Make recovery automatic where safe.
Make uncertainty visible. Make every lesson earned through evidence. Senses authenticated ·
memory evidence-based · learning governed · plans typed · actions capability-constrained ·
healing reversible · adaptation measurable · authority external · privacy boundary
structural · **failures reduce autonomy** · every important result independently provable.
