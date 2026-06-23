# Guardian Forensic Timeline Reconstruction

> **Sovereign plane, Wave 1, system #6 — the capstone of Wave 1 (Omniscience).** It consumes the
> [real-time event fabric](event_fabric.md) (#5) and reconstructs an incident chronology so the
> Brain reasons from *sequence*, not isolated alerts
> ([`sovereign_ops_plane.md`](sovereign_ops_plane.md); upstream: Timesketch). This page documents
> the first slice **implemented in code** ([`core/timeline/`](../core/timeline)).

## What it does

The event fabric gives Guardian one durable stream of normalized events. A **`Sketch`** (the
Timesketch term for an investigation) turns that stream into a *story*:

```bash
guardian timeline event_fabric/invisable-stream.yaml
#    +    0s (Δ   0s) benign             build.image_signed → SUCCESS [id:ci-token→img:messaging]
#    +  300s (Δ 300s) initial_access     auth.session_new_asn → OBSERVED [id:ci-token→svc:messaging-relay]
#  ★ +  330s (Δ  30s) execution          pr.force_push → OBSERVED [id:ci-token→repo:guardian]
#  ★ +  360s (Δ  30s) privilege_escalation policy.production_deploy → DENY [id:ci-token→svc:messaging-relay]
#  ★ … (the denial burst) …
#  ★ +  430s (Δ  10s) exfiltration       network.unexpected_egress → BLOCKED
#    +  450s (Δ  20s) containment        workflow.containment_started → SUCCESS

guardian timeline-phases event_fabric/invisable-stream.yaml
#   initial_access → execution → privilege_escalation → exfiltration → containment
#   span 460s over 10 events; time-to-contain: 450s
```

The flat stream becomes a narrative the Brain can reason over: *a token used from a new network,
a force-push, a burst of escalation attempts, a runtime detection, exfiltration, then
containment* — with the **timing** (Δ between steps) and **dwell** (time-to-contain) that
distinguish a slow burn from a smash-and-grab.

## What it answers

| Question | Method | Forensic value |
| -------- | ------ | -------------- |
| What happened, in order? | `chronology()` | ordered beats with Δ-from-previous and elapsed-from-start |
| What did *this* principal / asset do? | `for_actor` / `for_target` | a single credential's or service's thread, end to end |
| What surrounded this alert? | `window(id, before, after)` | analyst context pull around a pivot |
| What actually matters? | `key_events()` | the skeleton — HIGH+ or flagged pivots only |
| What phase are we in? | `phases()` | events bucketed recon → … → containment |
| How fast did we respond? | `dwell()` | incident span and time-to-contain (dwell time) |
| Tell me the story | `narrate()` | numbered, timestamped story lines |

## How it works

| Piece | File | Role |
| ----- | ---- | ---- |
| Typed models | [`core/timeline/models.py`](../core/timeline/models.py) | `TimelineEvent`, the `Phase` lifecycle vocabulary, and outputs (`Beat`, `PhaseBucket`, `DwellMetrics`) |
| Reconstruction engine | [`core/timeline/sketch.py`](../core/timeline/sketch.py) | `Sketch`: the seven reconstruction queries above, all deterministic (ordered by `(ts, id)`) |
| Ingestion | [`core/timeline/ingest.py`](../core/timeline/ingest.py) | `from_fabric` (the #5 → #6 integration), `classify_phase` (transparent heuristic), `build_from_spec`/`load_sketch`, and `from_timesketch` (production hook) |

**It is the integration point of Wave 1.** `from_fabric` reads the event fabric directly;
each event's `actor` is an [identity-graph](identity_graph.md) principal and its `target` a
[digital-twin](digital_twin.md) asset — so a reconstructed thread points straight at the actor
you can `id-escalate` and the target you can `twin-blast`. Phase inference is a transparent,
keyword-based heuristic over the canonical `source`/`action`/`outcome`, so the chronology
auto-buckets; an explicit `phase` in a spec always wins.

## Privacy boundary

Timeline events carry **metadata only** — *that* something happened and when, never message
contents or key material. Structurally outside private content, like every Wave-1 system.

## The production path

In production, chronologies are reconstructed in **Timesketch** from the event fabric and
forensic artefacts. `from_timesketch()` is the seam and **fails closed** — it raises rather than
returning an empty chronology, because an empty timeline would falsely imply *"nothing happened
in sequence"*. Until it is wired, sketches are reconstructed from the event fabric
(`from_fabric`) or an explicit spec. Next increments: Timesketch wiring, feeding the
reconstructed sequence (and dwell metrics) into the Brain's case intake, and automatic story
generation for every opened case.

---

*With system #6 merged, **Wave 1 — Omniscience** is complete in first-slice form: the digital
twin, identity graph, data-lineage graph, endpoint fabric, event fabric and forensic timeline —
the situational-awareness foundation the Wave-2 reasoning systems build on.*
