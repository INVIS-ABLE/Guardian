# Guardian Mythos Hive — Wave 0 Inventory & Migration Plan

> **Status:** Wave 0 (inventory only). **No implementation code is changed by this
> wave.** This document and its siblings are the gating deliverables required before any
> Wave 1 code lands. See the
> [Master Build Directive](#0-scope-of-this-document) summary below.
>
> **Hard completion rule (restated):** Guardian does **not** have its own AI merely
> because an endpoint is configured, a key is added, a repo is cloned, a name appears in
> config, a mock exists, docs were written, or one prompt produced an answer. The Brain is
> *operational* only when inference runs locally, production egress to model providers is
> denied, all artifacts are mirrored + digest-pinned + licence-approved, routing is
> deterministic, outputs are typed, evaluations pass, cross-tenant tests pass, evidence is
> recorded, revocation is proven, and **no external model API key is present**.

---

## 0. Scope of this document

The directive asked Wave 0 to produce seven artifacts. They are split across this set:

| # | Wave 0 deliverable | Where |
|---|---|---|
| 1 | Current AI dependency map | §1, §2 here |
| 2 | Proposed repository map | §4 here |
| 3 | Model capability matrix | [`model_capability_matrix.md`](./model_capability_matrix.md) |
| 4 | Licence & derivative-use matrix | [`../licences/model_licence_matrix.md`](../licences/model_licence_matrix.md) |
| 5 | Compute & storage estimate | [`compute_storage_estimate.md`](./compute_storage_estimate.md) |
| 6 | No-external-inference migration plan | [`migration_plan.md`](./migration_plan.md) |
| 7 | Risks & unresolved decisions | [`migration_plan.md` §Risks](./migration_plan.md#risk-register) |

The 21-item directive deliverable list is answered by the same set;
[`migration_plan.md`](./migration_plan.md) carries the implementation-stage / test /
rollback / PR-summary items.

---

## 1. Current Guardian AI architecture

Guardian is **not** a greenfield. It already ships the exact control seam the directive
calls for — a single, fail-closed model gateway with typed contracts, a pinned registry,
deterministic routing, a context firewall, an output firewall, budgets and immutable
provenance. The directive's job is therefore **not** to invent this architecture but to
**replace its production inference backends with Guardian-owned self-hosted services** and
**broaden its model taxonomy** from a 6-class tier to the ~20 logical Hive roles.

### 1.1 The model gateway (`core/ai/`)

Every model call goes through one path. (`docs/ai_gateway.md`,
`core/ai/gateway.py:45-219`.)

```
ModelRequest ─▶ ModelGateway.complete()
  1. context firewall   core/ai/context_firewall.py   refuse forbidden content; classify
  2. routing            core/ai/routing.py            work_class+classification → ModelClass
  3. registry           core/ai/registry.py           ModelClass → pinned ModelSpec
  4. privacy boundary   context_firewall.enforce_boundary
  5. budgets            core/ai/budgets.py            output-token pre / cost post
  6. provider           core/ai/provider_*.py         call backend, bounded retries, NO fallback
  7. output firewall    core/ai/output_firewall.py    screen for high-risk output
  8. provenance         core/ai/provenance.py         emit immutable ModelCallRecord
─▶ ModelResponse(text, trust=MODEL_GENERATED, high_risk, firewall_findings, record)
```

| Component | File | Responsibility |
|---|---|---|
| Typed contracts | `core/ai/schemas.py:1-172` | `WorkClass`, `ModelClass`, `ModelSpec`, `ModelRequest`, `ModelResponse`, gateway error types. Strict (`extra="forbid"`), facts frozen. |
| Gateway | `core/ai/gateway.py:45-219` | The 8-step pipeline above; `default_gateway()` wires registry + 3 providers. |
| Registry | `core/ai/registry.py:21-115` | Allow-list of pinned `ModelSpec`s indexed by id and capability class. |
| Routing | `core/ai/routing.py:41-73` | Pure, deterministic work→class map + sensitive-content override. |
| Context firewall | `core/ai/context_firewall.py:1-119` | Computes data classification; fences evidence as data; refuses `MESSAGE_PLAINTEXT`/`DECRYPTION_KEY`; renders instruction/data-separated prompt. |
| Output firewall | `core/ai/output_firewall.py:1-38` | Flags instruction overrides, approval claims, scope/policy changes, tool invocations, secret exfiltration. |
| Budgets | `core/ai/budgets.py:1-55` | Output-token pre-check, cost post-check; `BudgetExceededError`. |
| Provenance | `core/ai/provenance.py:32-69` | Immutable `ModelCallRecord` (pinned id, provider, template hash, evidence ids, classification, tenant/case, tokens, cost, retries, routing reason). |
| Provider base | `core/ai/provider_base.py:28-49` | `ModelProvider` protocol: `available()` + `complete()`. Gateway never imports an SDK directly. |

### 1.2 Current model taxonomy (to be broadened)

`WorkClass` (`core/ai/schemas.py:24-37`) and `ModelClass` (`:39-47`) today:

| WorkClass | → ModelClass | Today's backing model |
|---|---|---|
| `parsing` | `fast` | `claude-haiku-4-5-20251001` (Anthropic) |
| `sensitive` | `local` | `guardian-local` (deterministic **stub** — no real model) |
| `reasoning` | `strong_reasoning` | `claude-opus-4-8` (Anthropic) |
| `patch` | `strong_coding` | `claude-opus-4-8` (Anthropic) |
| `review` | `judge` | `gpt-judge-pinned` (OpenAI) |
| `policy` | `none` | **No model** — deterministic authority (correct, keep) |

This is a sound *shape* but a thin *taxonomy*: there is no vision, audio, video,
document/OCR, extraction, retrieval, detection, segmentation or safety-sensor class, and
the three substantive tiers are all external Claude/GPT.

### 1.3 The Brain that consumes the gateway

- **Inner reasoning graph** — LangGraph `StateGraph` over a typed `GuardianCaseState`
  (`core/brain/graph.py`, nodes in `core/brain/nodes.py`): intake → scope_verify → plan →
  collect → analyse → challenge → adjudicate → controlled_execution → observe → learn, with
  a hard step cap (`DEFAULT_MAX_STEPS=50`) to prevent open-ended loops.
- **Outer durable workflow** — Temporal (`core/brain/temporal_workflow.py`) owns retries,
  suspension and crash-replay.
- **Agents** — the 17 ECC agents (`agents/`, `docs/agents.md`) decide and delegate; per
  `docs/ai_gateway.md:73-77` they are **today thin stubs not yet wired to the gateway**.
- **Memory / RAG** — `core/memory.py`: default `hash_embed()` (deterministic, dependency-
  free, 256-dim) with a real vector backend deferred (`_build_vector_backend()` returns
  `None`). Qdrant is the configured target (`guardian.config.yaml:21-31`, `docker-compose.yml`).
- **Policy authority** — `core/policy_gate.py` + `policies/opa/guardian.rego` +
  `policies/agent_boundary.yaml`. **Models recommend; policy decides.** Already enforced.

### 1.4 Pre-existing guarantees the directive can build on (do not regress)

- A model never decides authority (`WorkClass.POLICY` → `PolicyRoutingError`).
- Private content never reaches a model (`MESSAGE_PLAINTEXT` / `DECRYPTION_KEY` refused).
- Sensitive content stays local unless `allow_external_processing=True`.
- Untrusted evidence is fenced as data (indirect-injection defence).
- Failure fails closed; **no silent fallback to a different model**.
- Model output is `MODEL_GENERATED` trust — never auto-promoted to evidence/memory.
- Every call emits an immutable `ModelCallRecord`.
- `policies/privacy_invariants.yaml` + `GUARDRAILS.md`: no training on user content, no
  plaintext to model, no key storage. `policies/agent_boundary.yaml`: model may not
  expand scope, change policy, disable logging, merge/resolve its own work, run arbitrary
  commands, or hold unrestricted secrets.

---

## 2. Existing external model-provider dependencies (the gap to close)

| Dependency | Location | Provider / key | Production impact |
|---|---|---|---|
| `claude-opus-4-8` (reasoning) | `core/ai/registry.py:57-66`, `guardian.config.yaml:16-17` | Anthropic; `ANTHROPIC_API_KEY` | **External inference.** Used by `reasoning` work class. |
| `claude-opus-4-8` (coding) | `core/ai/registry.py:67-76` | Anthropic; `ANTHROPIC_API_KEY` | **External inference.** Used by `patch` work class. |
| `claude-haiku-4-5-20251001` (fast) | `core/ai/registry.py:77-86` | Anthropic; `ANTHROPIC_API_KEY` | **External inference.** Used by `parsing` work class. |
| `gpt-judge-pinned` (judge) | `core/ai/registry.py:89-98` | OpenAI; `OPENAI_API_KEY` | **External inference.** Used by `review` work class. |
| Anthropic SDK | `core/ai/provider_anthropic.py:25-33` | `anthropic` pip pkg + key | Optional dep; lazily imported. |
| OpenAI SDK | `core/ai/provider_openai.py` | `openai` pip pkg + key | Optional dep; lazily imported. |
| NeMo Guardrails main model | `policies/guardrails/nemo/config.yml:13-16` | `engine: anthropic`, `claude-opus-4-8` | Declared but **not invoked in code** (no `nemoguardrails` import found). |
| Promptfoo eval provider | `eval/promptfooconfig.yaml:18` | `anthropic:messages:claude-opus-4-8` | CI/eval path; external when run. |
| Ragas / DeepEval judge | `eval/ragas/`, `eval/deepeval/` | Optional external judge | Degrade to deterministic checks offline. |
| `guardian-local` | `core/ai/provider_local.py:23-60` | none (offline) | **Deterministic stub — runs no real model.** This is the hook Wave 1 replaces. |

**Mitigating facts already true:** all external SDKs are *optional* and lazily imported;
the gateway *already* fails closed when a key is absent; sensitive/private content is
*already* never sent off-box. The migration is therefore a **backend swap behind a stable
interface**, not a re-architecture.

**What is missing for "Guardian-owned":** a real local inference plane; an artifact mirror
with digest pinning; the broadened model taxonomy; per-model registry metadata
(licence, digests, modalities, GPU/VRAM, permitted data classes); offline-enforcing CI;
and removal of external providers from the *production* registry.

---

## 3. Repositories inspected (Wave 0 read-only)

Only the **Guardian repository itself** was inspected in Wave 0. No external model
repositories were cloned — per directive, external repos may be cloned **only** into an
isolated research directory after approval, with licence + commit + digest recorded. The
20 model sources and the serving/training/eval stacks named in the directive are catalogued
(with their declared upstream repos and *preliminary, to-be-verified* licences) in
[`../licences/model_licence_matrix.md`](../licences/model_licence_matrix.md). **None of
those licences are treated as approved until verified against the actual upstream
revision at mirror time.**

Guardian files inspected (non-exhaustive, grounded references):
`README.md`, `guardian.config.yaml`, `pyproject.toml`, `requirements.txt`,
`core/ai/*.py`, `core/brain/*.py`, `core/memory.py`, `core/policy_gate.py`,
`core/evidence/*.py`, `core/tools/*.py`, `agents/`, `policies/opa/guardian.rego`,
`policies/agent_boundary.yaml`, `policies/privacy_invariants.yaml`,
`policies/guardrails/nemo/config.yml`, `eval/`, `docker-compose.yml`,
`.github/workflows/`, `docs/ai_gateway.md`, `docs/architecture/components.yaml`,
`docs/architecture/brain_tools.yaml`, `GUARDRAILS.md`, `SECURITY_POLICY.md`.

---

## 4. Proposed repository map (target, additive — not a rewrite)

The directive's target tree is **largely already present under different names**. The
proposal is to *adapt toward* it additively, preserving existing modules. Mapping:

| Directive target | Guardian today | Action |
|---|---|---|
| `brain/coordinator,router,adjudicator,context-firewall,prompt-registry,model-registry,budgets,cancellation,confidence,provenance` | `core/brain/`, `core/ai/{routing,context_firewall,registry,budgets,provenance}.py` | **Reuse.** Add prompt-registry, confidence, cancellation, adjudicator as `core/ai/` / `core/brain/` modules. |
| `model-services/{general,reasoning,coding,vision,audio,video,document,extraction,retrieval,safety}` | — (none) | **New.** One service adapter per class behind `ModelProvider`. |
| `inference/{gateway,vllm,sglang,vllm-omni,llama-cpp,scheduling,gpu-allocation,batching,health,observability}` | — (none) | **New** private AI plane. `gateway` = a Guardian-owned OpenAI-compatible inference gateway the providers call. |
| `model-artifacts/{manifests,licences,attestations,adapters,revocations}` | — (none) | **New.** Digest-pinned mirror manifests; this is the trust root for "no runtime downloads". |
| `schemas/{model,evidence,memory,routing,findings,tools,evaluation}` | `core/ai/schemas.py`, `core/evidence/models.py`, `core/tools/manifest.py` | **Reuse + extend** the registry schema (§MODEL REGISTRY SCHEMA). |
| `policies/{model-routing,data-classification,privacy,tool-use,model-promotion}` | `policies/opa/`, `policies/agent_boundary.yaml`, `policies/privacy_invariants.yaml` | **Reuse + add** `model-routing` and `model-promotion` policy. |
| `evaluation/{capability,security,grounding,…}` | `eval/{deepeval,promptfoo,ragas}` | **Reuse + extend** with garak/PyRIT-style security suites. |
| `memory/{working,episodic,semantic,entities,evidence,retention,deletion}` | `core/memory.py`, `core/evidence/store.py` | **Reuse + structure.** |
| `apps/guardian-pwa`, `edge/cloudflare`, `deployment/{kubernetes,gpu-nodes,…}` | `dashboard/`, `docker-compose.yml`, `isolation/`, `identity/` | **New/extend** for the Cloudflare edge plane and GPU node plane. |
| `docs/{ai-architecture,model-cards,licences,threat-models,operations,decisions}` | `docs/`, `docs/governance/`, **`docs/ai-architecture/` (this set)**, **`docs/licences/`** | **Started here.** |

**Deployment separation** (directive) maps onto Guardian's existing trust zones
(`docs/architecture/target_stack.md`): Cloudflare = edge/app plane (never holds weights);
private AI plane = inference + GPU; separated authority plane = OPA + Shadow Guardian +
secrets. The browser never connects to a GPU worker; the worker never holds production
root credentials; the Cloudflare Worker never holds weights.

---

## 5. Model registry schema — gap analysis

The directive's required registry fields vs. today's `ModelSpec`
(`core/ai/schemas.py:63-82`):

| Directive field | Present today? | Note |
|---|---|---|
| `logical_name` | partial (`ModelClass`) | Add the ~20 stable logical Hive names. |
| `internal_model_id` | `model_id` | Rename/alias; make it an internal id, not an upstream id. |
| `upstream_family` | `family` | Keep (used for judge independence). |
| `upstream_repository`, `upstream_revision` | ✗ | **Add** (provenance). |
| `weight/tokenizer/processor/configuration/adapter_digest` | ✗ | **Add** (digest pinning — the core of "no runtime downloads"). |
| `licence`, `derivative_status`, `attribution` | ✗ | **Add** (honest provenance). |
| `input/output_modalities` | ✗ | **Add** (multimodal routing). |
| `context_limit`, `maximum_output` | `max_output_tokens` only | **Add** `context_limit`. |
| `structured_output_support`, `tool_proposal_support` | ✗ | **Add**. |
| `memory_requirement`, `GPU_requirement`, `quantisation` | ✗ | **Add** (scheduling). |
| `permitted/prohibited_data_classes`, `approved_agent_roles` | partial (routing override) | **Add** explicitly per model. |
| `evaluation_version`, `safety_baseline` | `eval_version` on the call record only | **Add** to the spec. |
| `cost_per_local_gpu_second`, `maximum_request_budget` | `*_price_per_mtok` | **Replace** $/Mtok with GPU-second cost. |
| `health_state`, `promotion_state`, `revocation_state` | ✗ | **Add** the lifecycle states (DISCOVERED…OPERATIONAL…REVOKED). |

---

## 6. Security posture for the AI plane (Wave 0 findings)

Already enforced (keep): no model authority, privacy boundary, evidence fencing,
fail-closed, immutable provenance, no training on user content, agent-boundary policy.

Gaps to close in later waves (tracked in
[`migration_plan.md`](./migration_plan.md)):

- **Offline enforcement.** Production must set `HF_HUB_OFFLINE=1`,
  `TRANSFORMERS_OFFLINE=1`, `local_files_only=True`; inference workers must have
  **deny-by-default egress** (today only `isolation/egress.py` exists as a primitive).
- **`trust_remote_code`.** Any model needing custom code must have it vendored, reviewed,
  scanned, pinned, signed and run under the worker's restricted identity. No unaudited
  dynamic imports.
- **CI guard.** Add a CI check that **fails** if a production code path can reach an
  external model provider or if a provider key is required (directive Wave 1 acceptance).
- **Worker identity.** mTLS/workload identity gateway→worker; workers accept calls only
  from the gateway; no public ingress; non-root; read-only model mount.

---

## 7. Known limitations of Wave 0

- Licences in [`../licences/model_licence_matrix.md`](../licences/model_licence_matrix.md)
  are **preliminary** (from prior knowledge, not from the live repos) and must be verified
  at the exact mirror revision before any model is promoted past `LICENSE_REVIEWED`.
- Compute/storage figures in
  [`compute_storage_estimate.md`](./compute_storage_estimate.md) are **order-of-magnitude
  planning estimates**, not measured. The directive forbids promoting a model on size
  alone; real latency/throughput/GPU-second cost must be measured in Wave 5.
- No code is changed in Wave 0; the gateway is still wired to external providers. Nothing
  in this wave makes Guardian "self-hosted" yet — by design and per the Hard Completion Rule.

---

## 8. Next step (gate)

Wave 1 may begin **only after human approval of this Wave 0 set**. Wave 1 builds the
Guardian-owned internal inference gateway + a real (non-stub) local provider behind the
existing `ModelProvider` interface, plus the offline-enforcing CI guard — with the
acceptance test that **all tests pass with no external model account and CI fails on any
outbound provider call**. See [`migration_plan.md`](./migration_plan.md).
