# Guardian Endpoint Intelligence Fabric

> **Sovereign plane, Wave 1, system #4** — the fourth omniscience system, beside the
> [digital twin](digital_twin.md) (#1), [identity attack graph](identity_graph.md) (#2) and
> [data lineage graph](data_lineage.md) (#3) ([`sovereign_ops_plane.md`](sovereign_ops_plane.md)).
> This page documents the first slice **implemented in code**
> ([`core/endpoint/`](../core/endpoint)), and the production path beyond it.

## What it gives — and the one rule

Structured OS-state visibility across the fleet (open ports, kernel modules, startup items,
sudoers, logins …) via **osquery** — but under a hard governance invariant:

> **Signed, reviewed query packs only — never model-generated commands.**

The model never writes ad-hoc osquery SQL. A human reviewer signs a reviewed pack offline, and
[`EndpointFabric`](../core/endpoint/fabric.py) — the reference monitor — admits a pack only
when **every** condition holds:

| Condition | Why |
| --------- | --- |
| Signed by a **trusted reviewer key** the fabric was told to trust, verifying over the pack's canonical bytes | the reviewed content is exactly what runs — tampering after review breaks admission |
| **Reviewer ≠ author** | separation of duties: nobody approves their own pack |
| Pack id is new | no silent redefinition of an approved pack |

Thereafter `vet_query` answers the only run-time question that matters — *is this exact query a
member of an admitted pack?* Anything else (ad-hoc, model-generated, a whitespace-mangled or
column-changed variant) is refused, **fail-closed**.

```bash
guardian endpoint-packs endpoint/invisable-packs.yaml
#   Admitted 2 signed, reviewed pack(s):
#     pack:integrity-monitoring  (author secops-engineer → reviewed by secops-lead, signed by rev-demo)
#         listening_ports  [all @ 300s] SELECT pid, port, protocol, address FROM listening_ports
#         ...

guardian endpoint-vet endpoint/invisable-packs.yaml "SELECT pid, port, protocol, address FROM listening_ports"
#   APPROVED — pack:integrity-monitoring:listening_ports

guardian endpoint-vet endpoint/invisable-packs.yaml "SELECT * FROM shadow"
#   REFUSED — ad-hoc / model-generated osquery is not allowed
```

## How it works

| Piece | File | Role |
| ----- | ---- | ---- |
| Typed models | [`core/endpoint/models.py`](../core/endpoint/models.py) | `OsqueryQuery` (read-only `SELECT`/`WITH` enforced), `QueryPack` (+ `canonical_bytes` the reviewer signs), `PackSignature`, `QueryVerdict` |
| Reference monitor | [`core/endpoint/fabric.py`](../core/endpoint/fabric.py) | `EndpointFabric.admit` (the gate) and `vet_query` / `require` (the run-time decision); `schedule()` emits the osquery config from admitted packs only |
| Ingestion seam | [`core/endpoint/ingest.py`](../core/endpoint/ingest.py) | `load_reviewed_packs` (YAML content), `build_from_spec` (content + signatures), `seal_and_admit` (demo signing), `from_fleet` (production hook) |

Two layers of defence-in-depth back the invariant: osquery is inherently read-only, and the
`OsqueryQuery` model still **refuses any query that is not a pure `SELECT`/`WITH`** before it
can enter a pack — so Guardian can never issue a mutating endpoint command, by data or by code.

### Why the repo holds pack *content* but no signatures

[`endpoint/invisable-packs.yaml`](../endpoint/invisable-packs.yaml) is the **reviewed content**
— the queries a human approved — and deliberately contains no keys or signatures (secrets never
live in the repo as plaintext). A reviewer signs a pack offline with their own key; the fabric
verifies that signature against a trusted reviewer key provisioned out of band. The CLI's
`seal_and_admit` simulates this for demos: it generates a one-off reviewer key, signs the
reviewed packs, and admits them into a fabric that trusts only that key — exercising the full
sign → verify → admit → vet flow without provisioning real keys. Signing reuses
[`core/signing.py`](../core/signing.py) (Ed25519, with the deterministic HMAC fallback for CI).

## Privacy boundary

The fabric reports **OS metadata** (ports, modules, packages, logins) — never message contents
or keys. It is structurally outside private content, like the other Wave-1 systems.

## The production path

In production the fabric is populated from **Fleet**, which distributes the signed packs and
collects osquery results across the fleet. `from_fleet()` is that seam and **fails closed** — it
raises rather than returning a fabric with default trust, because the trusted reviewer keys and
the approved packs must come from a provisioned source, never a default. Next increments: Fleet
ingestion, result collection into the event fabric (system #5), and pack-review gates in CI so a
new or changed pack cannot ship without an independent signed review.
