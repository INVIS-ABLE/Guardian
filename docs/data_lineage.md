# Guardian Data Lineage & Privacy Graph

> **Sovereign plane, Wave 1, system #3** — the data-flow companion to the
> [live cyber digital twin](digital_twin.md) (system #1) and the
> [identity & permission attack graph](identity_graph.md) (system #2)
> ([`sovereign_ops_plane.md`](sovereign_ops_plane.md)). The twin reasons over **assets**, the
> identity graph over **principals**; this graph reasons over **data fields and how they
> flow**. This page documents the first slice **implemented in code**
> ([`core/lineage/`](../core/lineage)), and the production path beyond it.

## What it answers

A field-level lineage graph of the INVISABLE estate that answers, instantly and auditably, the
four data questions from the Sovereign doc:

| Question | Query | What it surfaces |
| -------- | ----- | ---------------- |
| **Field-level lineage** | `downstream(f)` / `upstream(f)` | where a field's data flows to, and where it came from |
| **Classification propagation** | `propagated_classifications(f)` | a field's *true* sensitivity — its declared class unioned with every upstream contributor's |
| **Processor-boundary violations** | `boundary_violations()` | data that flowed into a boundary not approved to hold it — *"a new integration moves a health field outside its approved boundary"* |
| **Retention / deletion obligations** | `retention_violations()` | derived data that would outlive the strictest deletion obligation of any field it descends from |

```bash
guardian lineage-class    lineage/invisable-lineage-sample.yaml f:analytics.diag_stats
#   declared: internal
#   effective: health  (from {health, internal})     ← health propagated through the ETL

guardian lineage-boundary lineage/invisable-lineage-sample.yaml      # exits non-zero — gates CI
#   f:analytics.diag_stats   health   not approved in zone:analytics (introduced by f:ehr.diagnosis)
#   f:analytics.cohort_id    pii      not approved in zone:analytics (introduced by f:ehr.patient_id)

guardian lineage-retention lineage/invisable-lineage-sample.yaml     # exits non-zero — gates CI
#   f:analytics.diag_stats   keeps none    > obligation 3650d (from f:ehr.diagnosis)
#   f:analytics.cohort_id    keeps 7300d   > obligation 3650d (from f:ehr.patient_id)
```

That is the canonical privacy detection: a health field and a PII field, correctly held in the
clinical boundary, are moved by a new analytics integration into a warehouse that is **not
approved** for them — and the deletion obligation that should have travelled with them did not.

## How it works

| Piece | File | Role |
| ----- | ---- | ---- |
| Typed models | [`core/lineage/models.py`](../core/lineage/models.py) | `Field`, `Boundary`, `Flow`, the result types (`LineageNode`, `BoundaryViolation`, `RetentionViolation`), and the sensitivity `rank`/`peak` helpers |
| Graph + queries | [`core/lineage/graph.py`](../core/lineage/graph.py) | in-memory directed flow graph; the four BFS queries, each carrying the shortest explanatory path |
| Ingestion seam | [`core/lineage/ingest.py`](../core/lineage/ingest.py) | `build_from_spec` / `load_graph` (YAML) now; `from_datahub` is the production hook |

Two design choices make the findings trustworthy:

- **Classification propagation is a set union, not a numeric collapse.** A field's effective
  sensitivity is the *set* of every class reaching it upstream, so boundary checks are
  **categorical**: a boundary approved for PII but not HEALTH still rejects HEALTH, even though
  both are RESTRICTED-tier. Each violation names the nearest upstream field that introduced the
  offending class — the report points straight at the integration that moved the data.
- **Deletion obligations propagate downstream.** Derived data may not outlive the strictest
  (smallest `retention_days`) obligation of any field it descends from; a field with no
  obligation of its own violates if any ancestor imposes one.

## Privacy boundary (enforced)

Identical to the twin and identity graph: this graph holds **metadata about fields, never their
contents**. A field classified `HEALTH` is a *label* ("this column holds health data"), never a
record. A node may never be classified `MESSAGE_PLAINTEXT` or `DECRYPTION_KEY` — those denote
content itself, and the lineage graph is structurally outside private content.

## The production path

In production the graph is **continuously populated from DataHub**, fed by **OpenLineage** run
events from the data platform. `from_datahub()` is the seam and **fails closed** — it raises
rather than returning a silently-empty graph, because an empty boundary-violation result would
falsely imply *"no data has crossed a boundary"*. Until that source is provisioned, graphs are
built from explicit specs. Next increments: DataHub/OpenLineage ingestion, a persisted store
for scale, PR-time boundary/retention gates on schema and integration changes, and joining
lineage to the twin and identity graph (a leaked principal's reachable datasets become lineage
roots).
