# Mythos Hive — Model Capability & Routing Matrix (Wave 0)

> Planning artifact. Maps the directive's 20 model sources onto stable **logical Hive
> roles**, the proposed **model-service classes**, and a **deterministic routing matrix**.
> No model here is approved or operational; every row enters at promotion state
> `DISCOVERED`. Licences are tracked separately in
> [`../licences/model_licence_matrix.md`](../licences/model_licence_matrix.md).

## 1. Logical Hive roles (stable names — application code uses these only)

Per directive: business logic must reference **logical names**, never upstream model ids.
These extend the existing `ModelClass` taxonomy (`core/ai/schemas.py:39-47`).

| Logical name | Service class | Primary candidate(s) | Reviewer family must differ |
|---|---|---|---|
| `guardian-fast` | general | Mistral Small 4 / Granite 4 | — |
| `guardian-general` | general | Granite 4 / Mistral Small 4 | — |
| `guardian-strategist` | reasoning | Mistral Large 3 | yes (vs reviewer) |
| `guardian-reasoner` | reasoning | DeepSeek-R1 (distill) | yes |
| `guardian-reasoning-reviewer` | reasoning | Magistral Small / OLMo 3 / ERNIE 4.5 | **must differ from reasoner family** |
| `guardian-code-primary` | coding | Qwen3-Coder | — |
| `guardian-code-reviewer` | coding | Devstral Small 2 | **must differ from code-primary** |
| `guardian-vision-primary` | vision | Qwen3-VL | — |
| `guardian-vision-reviewer` | vision | Phi-4 Reasoning Vision | **must differ from vision-primary** |
| `guardian-omni` | omni | Qwen3-Omni | — |
| `guardian-transcriber` | audio | Whisper | — |
| `guardian-video` | video | InternVideo | — |
| `guardian-object-detector` | detection | Grounding DINO | — |
| `guardian-segmenter` | segmentation | SAM 2 | — |
| `guardian-document-parser` | document | PaddleOCR | — |
| `guardian-entity-extractor` | extraction | GLiNER | — |
| `guardian-embedder` | retrieval | BGE / FlagEmbedding | — |
| `guardian-reranker` | retrieval | BGE reranker | — |
| `guardian-risk-sensor` | safety | Granite Guardian | sensor only — **not** policy authority |
| `guardian-independent-adjudicator` | reasoning | (different family from the producer) | **must differ from producer** |

## 2. Capability matrix (the 20 sources)

`I` = input modalities, `O` = output. Sizes/VRAM are planning estimates (see
[`compute_storage_estimate.md`](./compute_storage_estimate.md)); they are **not measured**.

| # | Upstream | Hive role(s) | I → O | Service | Serving | Notes |
|---|---|---|---|---|---|---|
| 1 | Mistral Large 3 | strategist | text → text | reasoning | vLLM/SGLang | Frontier strategic analysis; large VRAM; Wave 5. |
| 2 | Mistral Small 4 | fast/general | text(+img) → text | general | vLLM | Fast multimodal generalist. |
| 3 | DeepSeek-R1 | reasoner | text → text | reasoning | vLLM/SGLang | Deep/falsification reasoning; distill variants first. |
| 4 | Granite 4 | general/reasoning-reviewer | text → text(structured) | general | vLLM | Enterprise structured output, RAG, governance. |
| 5 | OLMo 3 | reasoning-reviewer | text → text | reasoning | vLLM | Transparent independent reasoning; native-train base. |
| 6 | ERNIE 4.5 | reasoning-reviewer | text(+img) → text | reasoning/vision | vLLM | Independent multilingual/multimodal. |
| 7 | Devstral Small 2 | code-reviewer | text → text | coding | vLLM | Repo analysis, debugging, test gen. |
| 8 | Magistral Small | reasoning-reviewer | text → text | reasoning | vLLM/llama.cpp | Compact reasoning, calculations, review. |
| 9 | Qwen3-Coder | code-primary | text → text | coding | vLLM/SGLang | Large-repo coding, patch/test gen. |
| 10 | Phi-4 Reasoning Vision 15B | vision-reviewer | image+text → text | vision | vLLM | Screenshot/doc/interface reasoning. |
| 11 | Granite Guardian | risk-sensor | text → risk-score | safety | vLLM | Prompt/response risk, groundedness, tool-hallucination **sensor**. |
| 12 | GLiNER | entity-extractor | text → spans | extraction | native/llama.cpp | NER, relationships, PII discovery. Light. |
| 13 | Qwen3-VL | vision-primary | image+text → text | vision | vLLM | Image/screenshot/diagram/doc/video-frame. |
| 14 | Qwen3-Omni | omni | audio+video+img+text → text | omni | vllm-omni/SGLang | Unified multimodal understanding. |
| 15 | Whisper | transcriber | audio → text | audio | faster-whisper/native | Local ASR; independent transcript cross-check. |
| 16 | InternVideo | video | video → text/embed | video | native | Long-form temporal video analysis. |
| 17 | SAM 2 | segmenter | image/video → mask | segmentation | native | Segment/track approved regions. |
| 18 | Grounding DINO | object-detector | image+text → boxes | detection | native | NL-directed detection. |
| 19 | PaddleOCR | document-parser | image/PDF → text/layout | document | native | OCR, tables, forms, layout. Light. |
| 20 | FlagEmbedding/BGE | embedder/reranker | text → vector/score | retrieval | native/vLLM | Dense+sparse+rerank, hybrid search. |

## 3. Deterministic routing matrix

Routing remains a **pure, deterministic first stage** (extends `core/ai/routing.py`). The
model never selects its own authority, never escalates, never adds tools, never recurses.

### 3.1 Inputs to the router (per directive)
task type · input modality · data classification · tenant · required latency · required
confidence · estimated complexity · context size · specialist capability · model health ·
GPU availability · evaluation score · local compute budget.

### 3.2 Effort tiers (no majority voting, no model debate, no recursion)

| Request tier | Pattern | Roles engaged |
|---|---|---|
| **Routine** | one efficient model | `guardian-fast` or specialist |
| **Important** | primary + different-family reviewer | e.g. `guardian-reasoner` + `guardian-reasoning-reviewer` |
| **High-impact conclusion** | primary + independent reviewer + deterministic evidence verification + explicit disagreement record | producer + `guardian-independent-adjudicator` |
| **Code change** | code model generates → **different family** reviews → deterministic tests verify (one model cannot verify its own patch) | `guardian-code-primary` → `guardian-code-reviewer` → test runner |
| **Visual conclusion** | perception model → reasoning model → evidence references retained | `guardian-vision-primary` → reasoner |

### 3.3 Modality routing

| Input modality | First-stage role |
|---|---|
| text (routine) | `guardian-fast` / `guardian-general` |
| text (deep) | `guardian-reasoner` (+ reviewer) |
| code/repo | `guardian-code-primary` (+ `guardian-code-reviewer`) |
| image/screenshot/diagram | `guardian-vision-primary` (+ `guardian-vision-reviewer`) |
| document/PDF/scan | `guardian-document-parser` → vision/reasoner |
| audio | `guardian-transcriber` → reasoner |
| video | `guardian-video` / `guardian-omni` |
| object/region request | `guardian-object-detector` → `guardian-segmenter` |
| retrieval/RAG | `guardian-embedder` → `guardian-reranker` |
| entity/PII | `guardian-entity-extractor` |
| **any** | `guardian-risk-sensor` runs as a passive sensor in parallel (advisory only) |

### 3.4 Hard routing invariants (unchanged from today, must not regress)

- `WorkClass.POLICY` → **no model** (`PolicyRoutingError`). Authority is deterministic.
- Sensitive classes (`CONFIDENTIAL`/`RESTRICTED`/`PII`/`HEALTH`) → forced local unless
  `allow_external_processing=True`. After migration *all* inference is local, so this
  becomes "forced to the boundary-respecting on-box service".
- `MESSAGE_PLAINTEXT` / `DECRYPTION_KEY` → refused before any prompt is built.
- Provider unavailable / model `DEGRADED` or `REVOKED` → **fail closed, no silent
  downgrade**. A failed/unavailable reviewer must not increase the producer's authority.
- A model may not route itself to additional authority or trigger recursive agent loops.

## 4. Reviewer-independence rule (family separation)

The registry already carries `family` for exactly this (`core/ai/schemas.py:78`). Wave 4+
enforces: the `*-reviewer` / `guardian-independent-adjudicator` engaged for a conclusion
**must have a different `upstream_family`** than the producer — so a conclusion is never
accepted merely because copies of the same model agree.

## 5. Granite Guardian is a sensor, not an authority

`guardian-risk-sensor` emits advisory risk signals (prompt-risk, injection, response-risk,
groundedness, tool-hallucination). It **never** allows/denies. OPA + `core/policy_gate.py`
remain the only deterministic allow/deny authority (`policies/opa/guardian.rego`).
