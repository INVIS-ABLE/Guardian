# Guardian Mythos Hive — AI Architecture (Wave 0)

This directory holds the **Wave 0 (inventory only)** deliverables for migrating Guardian's
AI brain to a fully self-hosted, INVISABLE-owned Mythos Hive — multiple open-weight
specialist models unified into one Guardian brain through deterministic routing, shared
typed contracts, shared evidence/memory, independent cross-checking and Guardian-owned
inference/evaluation/observability.

> **No implementation code is changed by Wave 0.** These documents are the gate that must
> be approved before any Wave 1 code lands. Guardian is **not** self-hosted yet: production
> inference still routes to external Claude/GPT via `core/ai/`. See the Hard Completion Rule
> in [`wave0_inventory.md`](./wave0_inventory.md).

## Documents

| Doc | Wave 0 deliverable |
|---|---|
| [`wave0_inventory.md`](./wave0_inventory.md) | Current AI architecture, external-provider dependency map, proposed repository map, registry-schema gap, security posture, known limitations. |
| [`model_capability_matrix.md`](./model_capability_matrix.md) | Logical Hive roles, capability matrix for the 20 sources, deterministic routing matrix, reviewer-independence rule. |
| [`../licences/model_licence_matrix.md`](../licences/model_licence_matrix.md) | Licence & derivative-use matrix (preliminary — must be verified at mirror time), data-governance findings. |
| [`compute_storage_estimate.md`](./compute_storage_estimate.md) | VRAM/GPU and artifact-storage planning estimates per wave. |
| [`migration_plan.md`](./migration_plan.md) | No-external-inference migration plan, build waves with acceptance gates, risk register, unresolved decisions, rollback procedures. |

## Key finding

Guardian already ships the exact control seam this programme needs — a single fail-closed
`ModelGateway` (`core/ai/`) with typed contracts, a pinned registry, deterministic routing,
context/output firewalls, budgets and immutable provenance. The migration is a **backend
swap behind a stable interface** (replace external Claude/GPT providers with Guardian-owned
self-hosted services and broaden the model taxonomy), **not** a re-architecture — and must
preserve every existing safety guarantee (no model authority, privacy boundary, evidence
fencing, fail-closed, no training on user content).

## Status

Wave 0 complete pending human approval. Wave 1 (internal model gateway + real local
provider + offline-enforcing CI guard) begins only after that approval.
