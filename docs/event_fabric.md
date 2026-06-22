# Guardian Real-Time Security Event Fabric

> **Sovereign plane, Wave 1, system #5** — Guardian's **nervous system**, beside the
> [digital twin](digital_twin.md) (#1), [identity attack graph](identity_graph.md) (#2),
> [data lineage graph](data_lineage.md) (#3) and [endpoint fabric](endpoint_fabric.md) (#4)
> ([`sovereign_ops_plane.md`](sovereign_ops_plane.md)). This page documents the first slice
> **implemented in code** ([`core/event_fabric/`](../core/event_fabric)), and the production
> path beyond it.

## What it does

Eight heterogeneous signal sources — **OPA, Temporal, GitHub, identity, Cilium, Falco, build,
model** — are normalized into **one canonical event shape** and appended to a single durable,
ordered, tamper-evident stream that doubles as an analytical store. The Brain reasons over one
fused timeline instead of eight disconnected feeds.

```bash
guardian events-stats   event_fabric/invisable-stream.yaml --by source
guardian events-spikes  event_fabric/invisable-stream.yaml --window 60 --threshold 3 --outcome deny
#   id:ci-token   3 events  2026-06-22T22:01:00+00:00 → 2026-06-22T22:01:40+00:00
guardian events-verify  event_fabric/invisable-stream.yaml
#   event stream (10 events): OK
```

The sample is the *"leaked CI token"* incident as the fabric would see it: a token used from a
new network → a force-push → **a burst of three policy denials in 40 s** (the spike) → a Falco
runtime detection → anomalous egress → containment workflow → a model hypothesis. One stream,
correlated.

## How it works

| Piece | File | Role |
| ----- | ---- | ---- |
| Typed models | [`core/event_fabric/models.py`](../core/event_fabric/models.py) | the canonical `SecurityEvent` (source, action, severity, outcome, actor, target, labels), the source/severity/outcome vocabularies, and `StoredEvent` (offset + chained digest) |
| Stream + store | [`core/event_fabric/stream.py`](../core/event_fabric/stream.py) | `EventFabric`: append-only hash-chained log; `query`/`counts_by`/`spikes` analytics; `replay` and `verify` |
| Ingestion | [`core/event_fabric/ingest.py`](../core/event_fabric/ingest.py) | per-source normalizers (`normalize_opa`/`github`/`falco`/`model` + dispatch), `build_from_spec`/`load_stream`, and `from_redpanda` (production hook) |

Two properties make it trustworthy as a nervous system:

- **Durable & ordered** — every event gets a monotonic offset and a hash-chained digest
  (`sha256(prev_digest + canonical(event))`, mirroring [`core/audit.py`](../core/audit.py)), so
  the stream is replayable from any offset and any retroactive edit or reordering is caught by
  `verify()`.
- **Analytical** — `query` (filter by source/severity/actor/target/outcome/time), `counts_by`
  (aggregation), and `spikes` (per-actor sliding-window burst detection) turn a flat log into
  correlated signal — *one actor, N events within W seconds*.

The `actor` and `target` fields are deliberately the identity-graph principal id and the twin
asset id, so the event fabric **joins** to systems #1 and #2: a spike names an `actor` you can
immediately run `id-escalate` on, and a `target` you can run `twin-blast` on.

## Privacy boundary

The fabric records **metadata only** — *that* a policy denied an action, *that* a syscall fired
— never message bodies or key material. A node may never be classified `MESSAGE_PLAINTEXT` or
`DECRYPTION_KEY`. Structurally outside private content, like every Wave-1 system.

## The production path

In production the canonical stream is the **Redpanda** durable log, queried from the
**ClickHouse** analytical store; normalizers run at the edge as events arrive. `from_redpanda()`
is the seam and **fails closed** — it raises rather than returning an empty fabric, because an
empty stream would falsely imply *"no security events"* and blind the nervous system. Next
increments: Redpanda/ClickHouse wiring, the remaining source normalizers (Temporal, identity,
Cilium, build), and feeding correlated spikes into the forensic timeline (system #6) and the
Brain's case intake.
