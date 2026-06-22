# Mythos Hive — Licence & Derivative-Use Matrix (Wave 0)

> **PRELIMINARY — NOT APPROVAL.** The licences below are recorded from prior knowledge of
> the upstream projects as a *planning starting point*. Per the directive ("DO NOT BLINDLY
> COPY REPOSITORIES" / "NO EXTERNAL RUNTIME DOWNLOADS"), **none is treated as approved**.
> Before any model advances past promotion state `LICENSE_REVIEWED`, each row must be
> re-verified against the **exact upstream revision and the actual `LICENSE`/model-card
> files at mirror time**, recording: code licence, **separate** model-weight licence,
> **separate** dataset licence, required attribution, and the exact commit + SHA-256
> digest. Where a row says **VERIFY**, treat the licence as unknown until confirmed.

## Legend

- **Code** = source/integration repo licence. **Weights** = model-weight licence (often
  different from code). **Commercial self-host** = may INVISABLE run it in production on
  its own infra? **Distil-from** = may Guardian train on this model's *outputs*?
  (Directive: do not distil until terms are explicitly reviewed for that purpose.)
- ✅ permissive/allowed · ⚠️ conditional/needs care · ❓ VERIFY · 🚫 prohibited/blocked.

## 1. Specialist models (the 20 sources)

| # | Model | Upstream repo | Code (prelim) | Weights (prelim) | Commercial self-host | Distil-from | Flags |
|---|---|---|---|---|---|---|---|
| 1 | Mistral Large 3 | mistralai (mistral-common) | Apache-2.0 (common) | **❓ likely Mistral Research/Commercial Licence** | ⚠️ **VERIFY** | ❓ | **Large weights historically non-Apache; may require a commercial agreement. Do not assume open.** |
| 2 | Mistral Small 4 | mistralai | Apache-2.0 | ❓ likely Apache-2.0 | ✅* | ❓ | Small Mistral models have been Apache-2.0; VERIFY for "4". |
| 3 | DeepSeek-R1 | deepseek-ai/DeepSeek-R1 | MIT | MIT | ✅ | ✅ (MIT permits) | **Distillation explicitly permitted** by DeepSeek terms — preferred teacher. |
| 4 | Granite 4 | ibm-granite/granite-4.0-language-models | Apache-2.0 | ❓ Apache-2.0 | ✅* | ❓ | IBM Granite has been Apache-2.0; VERIFY. |
| 5 | OLMo 3 | allenai/OLMo-core | Apache-2.0 | ❓ Apache-2.0 + open data | ✅* | ✅* | Fully open incl. data — strongest provenance; native-train base. |
| 6 | ERNIE 4.5 | PaddlePaddle/ERNIE | Apache-2.0 | ❓ Apache-2.0 | ✅* | ❓ | Baidu open-sourced ERNIE 4.5; VERIFY per-checkpoint. |
| 7 | Devstral Small 2 | mistralai/mistral-vibe (+ common) | Apache-2.0 | ❓ Apache-2.0 | ✅* | ❓ | VERIFY weight licence for "2". |
| 8 | Magistral Small | mistralai (mistral-common) | Apache-2.0 | ❓ Apache-2.0 | ✅* | ❓ | VERIFY. |
| 9 | Qwen3-Coder | QwenLM/Qwen3-Coder | Apache-2.0 | ❓ Apache-2.0 | ✅* | ❓ | Qwen3 series largely Apache-2.0; VERIFY checkpoint. |
| 10 | Phi-4 Reasoning Vision 15B | microsoft/Phi-4-reasoning-vision-15B | MIT | ❓ MIT | ✅* | ❓ | Phi-4 family has been MIT; VERIFY. |
| 11 | Granite Guardian | ibm-granite/granite-guardian | Apache-2.0 | ❓ Apache-2.0 | ✅* | n/a | Sensor only. VERIFY. |
| 12 | GLiNER | urchade/GLiNER | Apache-2.0 (code) | ⚠️ **mixed: some checkpoints CC-BY-NC** | ⚠️ **per-checkpoint** | ❓ | **Some GLiNER weights are non-commercial (CC-BY-NC). Must pick a commercial-safe checkpoint or train Guardian-GLiNER on owned data.** |
| 13 | Qwen3-VL | QwenLM/Qwen3-VL | Apache-2.0 | ❓ Apache-2.0 | ✅* | ❓ | VERIFY. |
| 14 | Qwen3-Omni | QwenLM/Qwen3-Omni | Apache-2.0 | ❓ **VERIFY** | ⚠️ ❓ | ❓ | Omni/multimodal checkpoints sometimes differ; VERIFY. |
| 15 | Whisper | openai/whisper | MIT | MIT | ✅ | n/a | Clean. |
| 16 | InternVideo | OpenGVLab/InternVideo | Apache-2.0 (code) | ❓ mixed (MIT/Apache/other) | ⚠️ ❓ | ❓ | VERIFY weight licence per variant. |
| 17 | SAM 2 | facebookresearch/sam2 | Apache-2.0 | ❓ Apache-2.0 | ✅* | n/a | VERIFY (some Meta releases differ). |
| 18 | Grounding DINO | IDEA-Research/GroundingDINO | Apache-2.0 | ❓ Apache-2.0 | ✅* | n/a | VERIFY weight licence. |
| 19 | PaddleOCR | PaddlePaddle/PaddleOCR | Apache-2.0 | ❓ Apache-2.0 | ✅* | n/a | Clean-ish; VERIFY model files. |
| 20 | FlagEmbedding / BGE | FlagOpen/FlagEmbedding | MIT | ❓ MIT | ✅* | ❓ | BGE models generally MIT; VERIFY reranker/checkpoint. |

`*` permissive *if* the preliminary licence is confirmed at mirror time.

## 2. Infrastructure (serving / training / evaluation)

| Component | Repo | Licence (prelim) | Flags |
|---|---|---|---|
| vLLM | vllm-project/vllm | Apache-2.0 | ✅ |
| SGLang | sgl-project/sglang | Apache-2.0 | ✅ |
| vllm-omni | vllm-project/vllm-omni | ❓ Apache-2.0 | VERIFY (newer). |
| llama.cpp | ggml-org/llama.cpp | MIT | ✅ |
| transformers / peft / trl | huggingface/* | Apache-2.0 | ✅ |
| OLMo-core | allenai/OLMo-core | Apache-2.0 | ✅ |
| open-r1 | huggingface/open-r1 | Apache-2.0 | ✅ |
| DeepSpeed | deepspeedai/DeepSpeed | Apache-2.0 | ✅ |
| Megatron-LM | NVIDIA/Megatron-LM | ⚠️ NVIDIA custom (BSD-3 + restrictions) | **VERIFY redistribution terms.** |
| lm-evaluation-harness | EleutherAI/* | MIT | ✅ |
| promptfoo | promptfoo/promptfoo | MIT | ✅ |
| garak | NVIDIA/garak | Apache-2.0 | ✅ |
| PyRIT | Azure/PyRIT | MIT | ✅ |

## 3. Derivative-naming policy (honest provenance)

Per directive, Guardian derivatives must **preserve provenance** and never imply INVISABLE
trained the foundation model from scratch. Approved naming pattern:

`Guardian-R1-Security-Distill-v1`, `Guardian-Granite-Operations-v1`,
`Guardian-Qwen-Code-v1`, `Guardian-Qwen-Vision-v1`, `Guardian-BGE-Retrieval-v1`,
`Guardian-GLiNER-Security-v1`.

Every derivative manifest (`model-artifacts/manifests/`) must state: base model, base
revision, base licence, Guardian dataset version, training method, hyperparameters,
training-code revision, training hardware, training duration, checkpoint digest, evaluation
results, limitations, attribution, permitted uses, prohibited uses.

## 4. Blocking findings to resolve before Wave 2/6

1. **Mistral Large 3 weight licence** — likely *not* permissive; may need a commercial
   self-host agreement or exclusion from the production set. **VERIFY before any mirror.**
2. **GLiNER non-commercial checkpoints** — select a commercial-safe checkpoint, or train
   `Guardian-GLiNER-Security-v1` on INVISABLE-owned data instead.
3. **Qwen3-Omni / InternVideo / Grounding DINO / SAM 2 weight licences** — confirm per
   exact checkpoint; multimodal/vision weights often diverge from their code licence.
4. **Distillation terms** — only DeepSeek-R1 (MIT) is currently a clearly-permitted
   teacher. Do **not** distil from any other model's outputs until its terms are reviewed
   for training use (directive: prohibited data list).
5. **Megatron-LM** redistribution terms if used in the training stack.

## 5. Data-governance findings (training data)

Guardian already enforces the prohibitions the directive restates
(`policies/privacy_invariants.yaml`, `GUARDRAILS.md`): **no** training on private-message
plaintext, communication keys, passwords, tokens, raw health records, unapproved user
content, cross-tenant data, or external-model outputs whose terms forbid training. The
four training-data layers (public defensive knowledge → INVISABLE-authored → sanitised
operational learning → prohibited) must be encoded as dataset manifests under
`training/datasets/` with provenance + legal basis before any Wave 6/7 fine-tuning.
**Memory is not weights:** durable org knowledge stays in evidence/entities/semantic
retrieval (`core/memory.py`, `core/evidence/`), not in model parameters.
