# Mythos Hive — No-External-Inference Migration Plan, Risks & Rollback (Wave 0)

> The plan to move Guardian from external Claude/GPT inference to a fully Guardian-owned
> self-hosted Hive — **behind the existing `core/ai` gateway interface**, additively, with
> no regression to the safety guarantees already in place. Wave 0 changes **no
> implementation code**; this is the approved-before-build blueprint.

## 1. Why this is a backend swap, not a rewrite

Guardian already has the hard part: one fail-closed gateway, typed contracts, deterministic
routing, context/output firewalls, budgets, immutable provenance, and the `ModelProvider`
seam (`core/ai/provider_base.py`). External SDKs are already *optional* and the gateway
already fails closed without keys. The migration replaces **what `provider` is wired in**
and **what the registry advertises**, then broadens the taxonomy. The application (agents,
reasoning graph) keeps calling the same `ModelGateway.complete()`.

## 2. Build waves (acceptance-gated)

Each wave is gated; a wave starts only after the prior wave's acceptance passes and a human
approves. Maps directive Waves 0–8 onto Guardian.

| Wave | Goal | Key change (behind existing interfaces) | Acceptance gate |
|---|---|---|---|
| **0** (this) | Inventory + plan | docs only | This set approved by a human. |
| **1** | Internal model gateway | New `inference/gateway` (OpenAI-compatible, Guardian-owned) + a **real** local provider replacing the stub behind `ModelProvider`; logical model registry; offline-enforcing CI guard. | All tests pass with **no external model account**; CI **fails on any outbound model-provider call**; no provider secret required. |
| **2** | Local utility models | GLiNER, BGE, PaddleOCR, Whisper, Granite Guardian as `model-services/{extraction,retrieval,document,audio,safety}`. | Every artifact internally mirrored; offline + network-disabled startup succeeds; output schemas pass; cross-tenant tests pass. |
| **3** | Engineering + vision | Qwen3-Coder, Devstral Small 2, Phi-4 Vision, Qwen3-VL. | Repo analysis offline; patch gen sandbox-only; visual evidence keeps source refs; **one model cannot verify its own patch**. |
| **4** | General + reasoning council | Granite 4, OLMo 3, R1-distill, Magistral, Mistral Small 4, ERNIE 4.5. | Deterministic routing works; reviewer-family separation enforced; disagreements retained; **model failure does not increase authority**. |
| **5** | Large + omnimodal | Mistral Large 3, full R1, Qwen3-Omni, InternVideo, SAM 2, Grounding DINO (as compute allows). | Capacity/latency/throughput/GPU-second cost **measured**; nothing promoted for size alone. |
| **6** | Guardian derivatives | PEFT adapters on approved datasets; evaluate vs base; provenance manifests; **rollback to base always available**. | Promote only proven improvements; immediate base rollback proven. |
| **7** | Distilled Guardian core | Evidence-grounded SFT from permitted teachers (DeepSeek-R1 MIT first); train Guardian reasoner/router/security-classifier/retriever. | Evaluated against all parent systems; **no hidden chain-of-thought distilled**. |
| **8** | From-scratch (optional) | OLMo-core stack; lawful data, reproducible configs, safety evals. | Not required for first operational Hive. |

## 3. Wave 1 detail (the first code wave — for the follow-up PR)

1. **`inference/gateway`** — a Guardian-owned OpenAI-compatible HTTP service (façade over
   vLLM/SGLang/llama.cpp later). In Wave 1 it can front a single small local model or a
   deterministic echo for CI.
2. **Real local provider** — implement `complete()` in a new provider that calls the
   internal gateway over the private plane (replacing `provider_local.py`'s stub for real
   deployments; keep a deterministic provider for CI/offline tests).
3. **Logical registry** — extend `ModelSpec`/registry with the §MODEL REGISTRY SCHEMA
   fields (digests, modalities, GPU/VRAM, permitted/prohibited data classes, promotion +
   revocation state) and the ~20 logical names (mapping in
   [`model_capability_matrix.md`](./model_capability_matrix.md)).
4. **Remove external providers from the production registry** (keep adapters out of the
   default prod wiring; gateway already fails closed).
5. **Offline-enforcing CI guard** — a test/CI job that fails if a production import path can
   reach `anthropic`/`openai`/network model endpoints, or if a provider key is required.
6. **Provenance** — extend `ModelCallRecord` to record artifact digests + GPU seconds.

**Tests to add (Wave 1):** no-external-account run; CI egress-deny proof; registry schema
validation; logical-name routing; fail-closed on `REVOKED`/`DEGRADED`; reviewer-family
separation; cross-tenant isolation.

## 4. Deployment separation (target)

- **Cloudflare plane:** PWA, authenticated edge API, sessions, streaming, rate limits,
  approval + model-status UI. **No weights, no GPU access, no production authority, no
  registry signing keys.** Browser never connects to a GPU worker.
- **Private AI plane:** model gateway, GPU scheduler, model/embedding/rerank/doc/audio/video
  services, eval workers. Deny-by-default egress; gateway-only ingress; non-root; read-only
  model mount; mTLS/workload identity; no production root credentials.
- **Authority plane:** OPA, capability authority, approval verification, evidence authority,
  secrets, Shadow Guardian, sovereign keys.

Hardware-neutral internal inference API → moving to the future INVISABLE rack requires only
a deployment-config + registry-endpoint + capacity-policy change, **never** an application
business-logic change.

## 5. Risk register

| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | **Mistral Large 3 weights non-commercial** | High | High | VERIFY licence at mirror; exclude from prod or obtain commercial agreement (licence matrix §4.1). |
| R2 | **GLiNER / multimodal weights non-commercial** | Medium | High | Choose commercial-safe checkpoints or train Guardian derivatives on owned data. |
| R3 | **Silent external fallback reintroduced** | Low | Critical | CI guard fails on provider import/egress; gateway has no fallback by design (`gateway.py:104-127`). |
| R4 | **`trust_remote_code` RCE** in custom model code | Medium | Critical | Vendor + review + scan + pin + sign; run under restricted worker identity; deny dynamic imports. |
| R5 | **GPU capacity insufficient** for Wave 4/5 | Medium | Medium | Scheduler load/unload; rented bare-metal for bursty frontier; phase promotion by measured cost. |
| R6 | **Cross-tenant leakage via batching/KV-cache** | Low | Critical | No cross-tenant batching unless isolation proven; clear temp context post-call; cross-tenant eval suite. |
| R7 | **Indirect prompt injection via OCR/transcript/image** | Medium | High | Context firewall fences all evidence as data (already enforced); injection eval suite (garak/PyRIT). |
| R8 | **Quality regression vs Claude/GPT** on hard reasoning | Medium | Medium | Reasoning council + independent adjudicator; capability/calibration eval gates; keep abstention first-class. |
| R9 | **Model promotes itself / escalates authority** | Low | Critical | Deterministic router; OPA authority; agent-boundary policy; promotion needs human (`policies/model-promotion`). |
| R10 | **Artifact tampering / unpinned weights** | Low | Critical | SHA-256 digest pinning + attestation + SBOM in `model-artifacts/`; offline env flags; signed mirror. |
| R11 | **Distillation licence breach** | Medium | High | Only distil from explicitly-permitted teachers (DeepSeek-R1 MIT first); review terms per teacher. |
| R12 | **Eval paths still call external models** (Promptfoo/Ragas) | Medium | Medium | Repoint eval providers to local gateway or mark clearly as non-production external. |

## 6. Unresolved decisions (need human/owner input)

1. **Serving engine priority** — vLLM vs SGLang vs llama.cpp as the Wave 1 default for the
   internal gateway? (Recommend vLLM for GPU OpenAI-compat; llama.cpp for CPU/dev.)
2. **Mistral Large 3** — pursue a commercial self-host agreement, or exclude it and lead
   reasoning with DeepSeek-R1 + OLMo 3 + a council? (Recommend: exclude until licence
   verified; lead with R1/OLMo.)
3. **GPU sourcing for Wave 4/5** — rented bare-metal now vs wait for the INVISABLE rack?
4. **Embedding migration** — replace `hash_embed` with BGE in Wave 2, and which vector
   backend to wire first (`core/memory.py:_build_vector_backend` is a stub today)?
5. **Keep external providers as a break-glass** (disabled, key-gated, audited) or delete the
   adapters entirely? (Directive favours absence of external keys; recommend remove from
   prod wiring, retain adapters only behind an explicit non-production flag.)
6. **Promotion authority** — who are the human approvers for `model-promotion` (two-person,
   mirroring `production_scan`)?

## 7. Rollback procedures

- **Per wave:** every wave is additive behind the gateway. Reverting a wave = revert its PR;
  the registry returns to the prior pinned set; the gateway fails closed for any class with
  no available model (no silent downgrade). No application code changes.
- **Per model:** set `revocation_state=REVOKED` (or `promotion_state` below `OPERATIONAL`) in
  the registry → router stops selecting it → fail closed for that class. Revocation must be
  proven by test (directive Hard Completion Rule).
- **Per derivative (Wave 6):** each adapter manifest pins its base; `Guardian-*-v1` rollback
  = drop the adapter, serve the base checkpoint. Base digest retained in the mirror.
- **Whole programme:** because nothing is removed from the existing gateway in Wave 0, and
  Wave 1+ only swaps providers/registry, reverting to the current (external-provider)
  behaviour is a configuration/registry change, not a redesign.

## 8. Definition of done (restating the Hard Completion Rule)

The Guardian Brain is **operational** only when: inference runs locally; production egress
to model providers is denied; all artifacts mirrored + digest-pinned + licence-approved;
routing deterministic; outputs typed; evaluations pass; cross-tenant tests pass; evidence
recorded; revocation proven; **and no external model API key is present.** None of:
endpoint configured, key added, repo cloned, name in config, mock exists, docs written,
weights downloadable, or one prompt answered — counts on its own.
