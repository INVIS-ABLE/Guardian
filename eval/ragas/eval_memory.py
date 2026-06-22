"""Ragas evaluation skeleton for the Guardian memory/RAG layer.

Guardian's value compounds only if its memory retrieves the *right* prior knowledge.
This script builds a tiny golden set, populates Guardian memory, retrieves for each
query, and (when Ragas + a judge model are available) scores context relevance /
faithfulness. Without Ragas installed it falls back to a deterministic retrieval
precision check so the signal is never lost.

Run:  python eval/ragas/eval_memory.py
"""

from __future__ import annotations

import sys
import tempfile

from core.memory import GuardianMemory, InMemoryBackend

# A small golden set: (collection, document, query, expected-substring-in-top-hit).
GOLDEN = [
    ("threat_models", "Account takeover via credential stuffing on the login endpoint",
     "how do attackers break into accounts", "credential stuffing"),
    ("safeguarding_rules", "Banned users must not be able to re-register with a new email",
     "banned user returns", "re-register"),
    ("policies", "All Guardian code changes ship as draft pull requests behind a feature flag",
     "how are fixes deployed", "draft pull requests"),
    ("run_outcomes", "Privacy leak simulator: PII visible to moderator role, severity high",
     "moderator can see private data", "PII visible to moderator"),
]


def populate(mem: GuardianMemory) -> None:
    for collection, doc, _q, _exp in GOLDEN:
        mem.remember(collection, doc, metadata={"source": "golden"})


def retrieval_precision(mem: GuardianMemory) -> float:
    """Deterministic fallback: fraction of queries whose top hit contains the answer."""
    correct = 0
    for collection, _doc, query, expected in GOLDEN:
        hits = mem.search(collection, query, top_k=1)
        if hits and expected.lower() in hits[0].record.text.lower():
            correct += 1
    return correct / len(GOLDEN)


def try_ragas(mem: GuardianMemory) -> bool:
    """Run Ragas context-relevance scoring if the package + judge model are present."""
    try:
        from datasets import Dataset
        from ragas import evaluate
        from ragas.metrics import context_precision
    except Exception:
        return False

    rows = {"question": [], "contexts": [], "ground_truth": []}
    for collection, doc, query, _exp in GOLDEN:
        hits = mem.search(collection, query, top_k=3)
        rows["question"].append(query)
        rows["contexts"].append([h.record.text for h in hits])
        rows["ground_truth"].append(doc)
    dataset = Dataset.from_dict(rows)
    result = evaluate(dataset, metrics=[context_precision])
    print("Ragas result:", result)
    return True


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        mem = GuardianMemory(backend=InMemoryBackend(store_dir=tmp))
        populate(mem)
        if not try_ragas(mem):
            score = retrieval_precision(mem)
            print(f"[fallback] retrieval precision@1 = {score:.2f} over {len(GOLDEN)} queries")
            # Treat anything below 0.75 as a regression worth a non-zero exit.
            return 0 if score >= 0.75 else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
