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

Tests: `tests/test_autonomy_states.py`, `tests/test_autonomy_budget.py`,
`tests/test_healing_contracts.py`, `tests/test_healing_runbooks.py` (52 cases).

## Queued (subsequent increments)

Following the directive's Phase order (§38) and the required layout (§37):

- **Anti-oscillation controls** (§35) — cooldowns, repair locks, loop detection, backoff.
- **SLO + error-budget + telemetry-completeness** layer (§9, §13, Phase 1 remainder).
- **Self-healing hierarchy executor** (§7) — lowest-viable-layer selection.
- Integrations (§37) are **adapters** behind the existing authorities — Argo CD/Rollouts,
  Keptn, OpenFeature/Flipt, Cluster API, Karmada, Crossplane, OpenTofu, Node Problem
  Detector/Kured/Descheduler, Velero/Kanister/CloudNativePG, Flink, and the governed
  learning stack (lakeFS/Great Expectations/OpenLineage/Feast/MLflow/KServe/Evidently/
  Alibi Detect/NannyML/River/Label Studio). None grants authority; all produce evidence
  and signals.

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

Remaining §39 items (1–8, 12, 15, 17–29, 33–40) are covered by the queued increments and
the existing Level 5 authorities; this matrix grows as each phase lands.

## Design principle (directive §40)

Build intelligence broadly. Grant authority narrowly. Make recovery automatic where safe.
Make uncertainty visible. Make every lesson earned through evidence. Senses authenticated ·
memory evidence-based · learning governed · plans typed · actions capability-constrained ·
healing reversible · adaptation measurable · authority external · privacy boundary
structural · **failures reduce autonomy** · every important result independently provable.
