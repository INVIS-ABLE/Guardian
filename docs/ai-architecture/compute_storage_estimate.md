# Mythos Hive — Compute & Storage Estimate (Wave 0)

> **Order-of-magnitude planning estimates only — not measured.** The directive forbids
> promoting a model on size alone; real latency, throughput and **cost per local GPU
> second** must be measured in Wave 5 (`evaluation/cost/`). VRAM figures assume common
> quantisations and will vary with serving engine, context length, batch size and KV-cache.

## 1. VRAM per model (serving, single replica)

| Tier | Models | Approx params | VRAM @ practical quant | Min GPU |
|---|---|---|---|---|
| Utility (light) | GLiNER, PaddleOCR, BGE/FlagEmbedding, Grounding DINO, SAM 2 | <1B each | 1–6 GB each (often CPU/GPU-light) | 1× 8–16 GB (shared) |
| Audio | Whisper large-v3 | ~1.5B | ~6–10 GB | 1× 16 GB |
| Compact LLM | Mistral Small 4, Magistral Small, Granite 4 (small), Devstral Small 2 | ~7–24B | 8–24 GB (4–8 bit) | 1× 24–48 GB |
| Coding | Qwen3-Coder (mid) | ~30B class | 24–48 GB (4-bit) | 1–2× 48 GB |
| Reasoning | DeepSeek-R1 distill (8–32B), OLMo 3 | 8–32B | 16–48 GB | 1× 48–80 GB |
| Vision | Qwen3-VL, Phi-4 Reasoning Vision 15B, ERNIE-VL | 7–15B+ | 16–40 GB | 1× 48 GB |
| Omni/Video | Qwen3-Omni, InternVideo | multimodal | 24–80 GB | 1× 80 GB |
| Safety sensor | Granite Guardian | ~2–8B | 6–16 GB | shared |
| Frontier | **Mistral Large 3**, full DeepSeek-R1 | 100B–670B | 140 GB–1 TB+ (multi-GPU/quant) | 2–8× 80 GB (Wave 5 only) |

## 2. Phased capacity plan

| Wave | Models | Indicative GPU footprint |
|---|---|---|
| **W1** internal gateway + real local provider (one small general model) | 1 compact LLM | 1× 24–48 GB GPU (or CPU for stub) |
| **W2** utility models (GLiNER, BGE, PaddleOCR, Whisper, Granite Guardian) | 5 light/medium | 1–2× 24 GB GPU |
| **W3** engineering + vision (Qwen3-Coder, Devstral, Phi-4 Vision, Qwen3-VL) | 4 medium | 2–4× 48 GB GPU |
| **W4** general + reasoning council (Granite 4, OLMo 3, R1-distill, Magistral, Mistral Small 4, ERNIE) | 6 medium | 4–6× 48–80 GB GPU |
| **W5** large + omni (Mistral Large 3, full R1, Qwen3-Omni, InternVideo, SAM 2, Grounding DINO) | frontier | 8+× 80 GB GPU (rented bare-metal or future rack) |

These do not all run hot at once: the GPU scheduler (`inference/scheduling/`,
`inference/gpu-allocation/`) load/unloads by demand. A realistic **Wave 1–4 operational
floor is ~4–8 datacentre GPUs (48–80 GB)**; Wave 5 frontier work is bursty and a candidate
for rented bare-metal until the INVISABLE rack exists.

## 3. Storage (artifact mirror — `model-artifacts/`)

Production does **no runtime downloads**; every artifact is mirrored into
INVISABLE-controlled object storage with upstream source, exact revision, SHA-256 digest,
size, licence, attestation/SBOM, approval + revocation status, and object-store location.

| Bucket | Rough size |
|---|---|
| Utility + audio model weights (W2) | ~30–60 GB |
| Engineering + vision (W3) | ~120–250 GB |
| General + reasoning council (W4) | ~250–500 GB |
| Frontier + omni (W5) | ~1–3 TB |
| Adapters (PEFT, Wave 6) | ~1–20 GB total |
| Tokenizers/processors/configs/chat-templates/eval records | <10 GB |
| **Mirror total (W2–W5)** | **~1.5–4 TB** |

Plus headroom for **multiple pinned revisions** (rollback to base requires keeping prior
digests), evaluation datasets, and checkpoints from any Wave 6/7 training. Plan **≥8–10 TB**
durable, versioned, access-controlled object storage with content-addressable digests.

## 4. Network & isolation cost

- Inference workers: **deny-by-default egress**; pull weights only from the internal mirror
  over the private plane. No public ingress; gateway-only access (mTLS/workload identity).
- Offline env flags in production: `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`,
  `local_files_only=True`.

## 5. What must be *measured* (not estimated) before promotion

Per directive `evaluation/cost/`: GPU seconds, energy estimate, memory use, throughput,
tokens/second, **cost per verified task**. A model reaches `OPERATIONAL` only after these
are recorded alongside capability/grounding/security/privacy/reliability gates — never
because it is larger.
