# Guardian Wave 2 — Reasoning over the awareness graphs

> **The leap from a map to a conclusion.** Wave 1 gave Guardian *awareness* — the digital twin,
> identity graph, lineage graph, endpoint and event fabrics. Wave 2 reasons *over* them: it forms
> competing hypotheses, finds the causal link that actually has to be cut, and only asserts a
> conclusion its track record justifies. All three engines ([`core/reasoning/`](../core/reasoning))
> are **read-only and metadata-only** — cognition proposes, authority disposes.

## #7 — Evidence & competing-hypothesis engine

[`core/reasoning/hypothesis.py`](../core/reasoning/hypothesis.py) adjudicates rival hypotheses
**from the evidence**, never by majority vote or by which claim sounds most confident. For each
hypothesis it recomputes status and confidence over the typed evidence
([`core/evidence/models.py`](../core/evidence/models.py)):

- *verified* evidence (validated + a trusted trust-class) counts fully; unverified evidence is weak
  corroboration only — an untrusted log line is **not** proof;
- a hypothesis with **no verified support** or **any unresolved contradiction** can never be
  `supported`/`confirmed` — it becomes `inconclusive` (the grounding rule);
- it reports **"insufficient evidence"** rather than inventing a conclusion.

The case adjudicator picks the leading hypothesis by *evidence grounding* (verified support, then
confidence), and **flags unresolved disagreement** when two rivals are both evidence-supported —
exactly the situation a human must resolve.

```python
from core.reasoning import adjudicate
case = adjudicate(hypotheses, evidence_items)   # → CaseVerdict
case.leading()            # the evidence-grounded leader, or None (abstained)
case.unresolved_disagreement   # True ⇒ two supported rivals; escalate to a human
```

## #8 — Causal root-cause engine

[`core/reasoning/causal.py`](../core/reasoning/causal.py) turns an attack path into *causation*
using counterfactuals over the digital twin — *"would the incident still have happened without
this node?"* — separating the **first event**, the **root cause** (the earliest necessary link to
cut), **enabling conditions**, **amplifiers** (the choke points), and **symptoms**.

```bash
guardian reason-causal twin/invisable-sample.yaml --observed id:ci-token --sink data:ciphertext
# Incident reaching data:ciphertext:
#   first event:    id:ci-token
#   root cause:     repo:guardian   (earliest necessary link — cut this)
#   enabling:       repo:guardian → img:messaging → svc:messaging-relay → db:mailbox
#   amplifiers:     db:mailbox, img:messaging, repo:guardian
#   symptoms:       db:mailbox → data:ciphertext
```

That points remediation at the link that actually breaks the chain — not the alert's immediate
symptom.

## #10 — Confidence calibration & abstention

[`core/reasoning/calibration.py`](../core/reasoning/calibration.py) learns whether a "90%
confident" claim is right ~90% of the time, and:

- **recalibrates** a raw confidence down to what its track record justifies, and
- **abstains** when a claimed confidence overshoots historical accuracy (or falls below a floor) —
  *"insufficient evidence for a safe conclusion"*, which the Sovereign design treats as
  intelligence, not weakness.

It composes with #7: pass a `Calibrator` to `adjudicate(...)` and an over-confident-but-thinly-
evidenced hypothesis is automatically downgraded to `inconclusive`. Outcomes are booleans (was the
conclusion correct?), never content, and persist to JSONL so calibration survives across runs.

```python
from core.reasoning import Calibrator, adjudicate
cal = Calibrator(store="reports/calibration.jsonl")
cal.record(confidence=0.9, correct=False)        # feedback from a resolved case
adjudicate(hypotheses, evidence, calibrator=cal) # confidence now reflects the track record
```

## What this is not

These engines never grant authority, place a control, or execute a remediation — they produce
*verdicts and explanations* for the policy gate and a human to act on. No private content enters
any of them (the evidence privacy labels and the twin's metadata-only boundary still hold).
