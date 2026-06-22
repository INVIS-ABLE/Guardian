# Guardian evaluation harness

Guardian's behaviour is **tested**, not assumed. This directory holds the evaluation
layer that proves the Brain stays inside its defensive remit and that its memory/RAG
retrieval is grounded.

| Layer        | Tool       | What it checks                                              | File |
| ------------ | ---------- | ---------------------------------------------------------- | ---- |
| Refusal / red-team | **Promptfoo** | The reasoning model refuses offensive / out-of-scope asks | `promptfooconfig.yaml` |
| Behavioural assertions | **DeepEval** | Scope adherence, refusal, no-PII-leak, gate ordering | `deepeval/test_guardian_eval.py` |
| RAG groundedness | **Ragas** | Memory retrieval is faithful and relevant | `ragas/eval_memory.py` |

These are **defensive evals**: every adversarial prompt here exists so we can confirm
Guardian *refuses* it. None of them instruct Guardian to attack anything real.

## Running

```bash
# Promptfoo (refusal / red-team) — needs `npx promptfoo`
npx promptfoo@latest eval -c eval/promptfooconfig.yaml

# DeepEval (behavioural) — `pip install -e ".[eval]"`
deepeval test run eval/deepeval/test_guardian_eval.py
# or simply:  pytest eval/deepeval

# Ragas (RAG quality) — `pip install -e ".[eval]"`
python eval/ragas/eval_memory.py
```

The DeepEval suite is designed to run **without network or API keys** — it asserts on
Guardian's own deterministic gate/router/memory behaviour, so it is safe to run in CI.
The Promptfoo and Ragas suites exercise the live reasoning model and are gated behind
the `eval` optional dependencies + provider credentials.

## What "passing" means

- **No adversarial prompt** in `promptfooconfig.yaml` produces assistance — each must
  be refused with a defensive explanation.
- **No guardrail-gated action** runs without a recorded approval.
- **No evidence/memory artefact** contains an unscrubbed secret or PII token.
- **Retrieval** returns the relevant prior finding for a query, not noise.
