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

### The ACH overlay — matrix, diagnosticity, and what to test next

[`core/reasoning/ach.py`](../core/reasoning/ach.py) adds the other half of Heuer's *Analysis of
Competing Hypotheses* on top of the adjudicator: where the adjudicator says *how grounded* each
hypothesis is, the overlay says *what to look at and what to test next*. It **reuses the
adjudicator's `contradiction_weight`** — it never re-derives evidence weighting, so the two views
can't drift — and adds:

- the **matrix** — consistent `+` / inconsistent `−` / neutral `·` for every (hypothesis,
  evidence) pair;
- **diagnosticity** — which evidence *discriminates* between hypotheses versus **non-diagnostic**
  noise (consistent with everything, so it decides nothing);
- a **least-contradicted ranking** with a decisiveness margin — ACH favours the hypothesis hardest
  to *disprove*, not the one with the most support; and
- the leading hypothesis's **falsification tests** — what to collect next to seek disproof.

```bash
guardian reason-ach    cases/invisable-ci-token-case.yaml   # ranked least-contradicted + verdict + next tests
guardian reason-matrix cases/invisable-ci-token-case.yaml   # the consistency grid
```

On the sample *"leaked CI token"* case (three rivals: external attacker / insider / false alarm),
the overlay leads with **external attacker** — `[confirmed]` by the adjudicator *and*
least-contradicted (zero verified contradictions, decisively separated) — flags the three denied
deploys as **non-diagnostic** (consistent with every hypothesis), and surfaces the threat-intel
correlation as the test to run next. Cases are loaded from a spec by
[`core/reasoning/cases.py`](../core/reasoning/cases.py) (evidence keys → UUIDs); the production
case-store seam fails closed.

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

## #9 — Multi-model reasoning council

[`core/reasoning/council.py`](../core/reasoning/council.py) runs a serious case through bounded,
adversarial **roles** — primary investigator → sceptic → alternative-hypothesis analyst →
attack-path analyst → privacy examiner → **evidence adjudicator** — and the adjudicator decides
**from the evidence, not by majority vote**. Each role is a deterministic function over the typed
contracts (so the council is replayable and testable offline); in production each role is routed to
an appropriate — and for critical cases a *different* — model family via the `core.ai` gateway.

```python
from core.reasoning import Case, convene
verdict = convene(Case(evidence=evidence, hypotheses=hypotheses, twin=twin,
                       observed=("attacker",), sink="data"))
verdict.decision         # proceed | insufficient_evidence | contradicted | escalate
verdict.requires_human   # True whenever it did not cleanly converge
verdict.sceptic_challenges, verdict.attack_path, verdict.privacy_violations
```

It **escalates to a human** whenever the evidence is insufficient, contradicted, disputed (two
grounded rivals), *or unchallenged* (only one hypothesis — no real contest), and **blocks** if any
case material carries privacy-forbidden content. It never executes anything.

## #11 — Autonomous threat-hunting engine

[`core/reasoning/hunting.py`](../core/reasoning/hunting.py) continuously generates and runs
defensive *hunts* over the awareness graphs, and names the permanent **detection** each validated
hit should become. Every hunt is read-only, budgeted, privacy-filtered (metadata only) and
reproducible; a hunt is *skipped* (not failed) when its input graph is absent.

```bash
guardian threat-hunt --twin twin/invisable-sample.yaml \
  --identity identity_graph/invisable-identity-sample.yaml \
  --lineage  lineage/invisable-lineage-sample.yaml
# [HIGH  ] Privilege-escalation path available (privilege_escalation_path)  hits: id:human-dev
# [HIGH  ] Data outside its approved boundary (data_outside_boundary)       hits: f:analytics.diag_stats, …
# [MEDIUM] Dormant identity holds sensitive privilege (dormant_sensitive_identity)  hits: id:old-deploy
```

Hunts span every domain: entry-identity-reaches-regulated-data and single-point-of-failure (twin),
privilege-escalation and dormant-sensitive-privilege (identity), boundary and retention violations
(lineage). Use `--fail-on-high` to gate CI on any high/critical hit.

## Runtime-triggered investigation — nervous system → brain

[`core/reasoning/incident.py`](../core/reasoning/incident.py) is the capstone that wires the layers
into one flow: a live signal on the **event fabric** (#5) flags at-risk assets on the **twin**
(runtime fold), the **causal engine** (#8) explains how it reaches the crown jewels, the signals
become typed **evidence**, and the **council** (#9) adjudicates competing hypotheses (active
compromise vs. controls held). Because a raw sensor alert is *unverified tool output*, the council
cannot confirm it alone — so the pipeline **escalates to a human** with the whole picture rather
than acting.

```bash
guardian incident twin/invisable-sample.yaml event_fabric/invisable-stream.yaml
# INCIDENT — 6 notable signal(s); 6 asset(s) at risk; reaching data:ciphertext;
#            council: INSUFFICIENT EVIDENCE; root cause: db:mailbox
#   at risk now: api:messaging, data:ciphertext, db:mailbox, img:messaging, repo:guardian, svc:messaging-relay
#   decision:    INSUFFICIENT EVIDENCE  → ESCALATE TO HUMAN
```

That is the Sovereign diagram realised end to end — *event fabric → reasoning council → escalate* —
and exactly the right posture: Guardian **notices, explains, and escalates**; it never auto-acts on
an unverified signal.

## What this is not

These engines never grant authority, place a control, or execute a remediation — they produce
*verdicts and explanations* for the policy gate and a human to act on. No private content enters
any of them (the evidence privacy labels and the twin's metadata-only boundary still hold).
