# Guardian Live Cyber Digital Twin

> **Sovereign plane, Wave 1, system #1** — the foundation the identity graph, attack-path
> forecasting and blast-radius reasoning all build on
> ([`sovereign_ops_plane.md`](sovereign_ops_plane.md)). This page documents the first slice that
> is **implemented in code** ([`core/twin/`](../core/twin)), and the production path beyond it.

## What it answers

A typed relationship graph of the INVISABLE estate that answers, instantly and auditably:

> *"What would be affected if this credential, repository, machine, identity or package were
> compromised?"*

```bash
guardian twin-blast twin/invisable-sample.yaml id:ci-token
# Blast radius of identity 'CI deploy token' (id:ci-token):
#   [1] repository       repo:guardian        (can_write:repo:guardian)
#   [2] container_image  img:messaging        (… → builds:img:messaging)
#   [3] service          svc:messaging-relay  (… → deploys:svc:messaging-relay)
#   [4] database         db:mailbox           (… → reads:db:mailbox)
#   [5] data_class       data:ciphertext      (… → stores:data:ciphertext)

guardian twin-path twin/invisable-sample.yaml id:ci-token data:ciphertext
# id:ci-token → can_write → repo:guardian → builds → img:messaging → deploys →
#   svc:messaging-relay → reads → db:mailbox → stores → data:ciphertext
```

That is the canonical *"leaked CI token → messaging compromise"* chain from the Sovereign doc —
produced as an actual attack path with affected assets, not a single isolated alert.

## How it works

| Piece | File | Role |
| ----- | ---- | ---- |
| Typed models | [`core/twin/models.py`](../core/twin/models.py) | `AssetKind`, `RelationKind`, frozen Pydantic `AssetNode`/`Relationship`, and the `BlastRadius` result |
| Graph + queries | [`core/twin/graph.py`](../core/twin/graph.py) | in-memory directed graph; `blast_radius()` (forward BFS, shortest explanatory paths) and `attack_path()` (shortest path) |
| Ingestion seam | [`core/twin/ingest.py`](../core/twin/ingest.py) | `build_from_spec` / `load_twin` (YAML) now; `from_cartography` is the production hook |

**Edges point in the direction a compromise propagates**, so blast radius is a directed
reachability and every impacted asset carries the *shortest* explanatory path — the result is
auditable, not just a set.

## Privacy boundary (enforced)

The twin holds **metadata and relationships, never private content**. A node may never be
classified `MESSAGE_PLAINTEXT` or `DECRYPTION_KEY` — those denote content, and the model rejects
them. An `encryption_key` asset is a key *identifier*; a `data_class` asset is a *category label*
(e.g. "message ciphertext"), never records. This mirrors the Verifier's boundary and the Privacy
Fabric: Guardian protects the cryptographic system while remaining structurally outside it.

## PR-time blast-radius gate

The twin becomes an **active guardrail**: given the assets a change touches, compute what a
compromise of each would *reach*, flag sensitive sinks (regulated data, encryption keys, data
stores), and **gate the change before it deploys** — instead of waiting for a scanner to find
the exposure afterwards ([`core/twin/assessment.py`](../core/twin/assessment.py)).

```bash
guardian twin-assess twin/invisable-sample.yaml --changed id:ci-token --fail-on high
# id:ci-token (identity): HIGH — 6 impacted, 2 sensitive
#     [high    ] reaches confidential data class 'Message ciphertext'  (can_write:… → stores:data:ciphertext)
#     [medium  ] reaches data store 'Encrypted mailbox store'          (can_write:… → reads:db:mailbox)
# blast-radius gate: HIGH (fail-on=high) → FAIL      # exit 1, gating CI
```

Severity is driven by the most sensitive sink reached: regulated data classes (`health`/`pii`/
`restricted`) are **critical**, `confidential` data and encryption keys are **high**, data
stores/queues/certificates are **medium**. Every sensitive hit carries its explanatory path, so a
reviewer sees *how* the change reaches the sink. The command **fails closed on a typo** — an
unknown changed-asset id raises rather than reporting a clean bill of health. It is read-only: it
proposes a verdict, it authorises nothing.

### Ambient — it runs on every PR

The gate is wired into CI ([`.github/workflows/twin-gate.yml`](../.github/workflows/twin-gate.yml)).
A repo-scoped twin ([`twin/guardian-repo.yaml`](../twin/guardian-repo.yaml)) maps this repo's
sensitive paths to assets via each asset's `paths` globs; the workflow diffs the PR, resolves
changed files to assets (`resolve_changed_assets`), and runs `guardian twin-gate`:

```bash
git diff --name-only "$BASE_SHA" HEAD | \
  guardian twin-gate twin/guardian-repo.yaml --files-from - --fail-on critical
```

It is conservative by default (`--fail-on critical`): a change reaching regulated user content —
e.g. touching the E2EE crypto layer — **blocks for review**; a change reaching only confidential
evidence (e.g. the policy authority) is reported but does not block. Unmapped changes (docs,
tests) pass cleanly. Tune `--fail-on` to raise or lower the bar.

## The production path

In production the twin is **continuously populated from Cartography / CloudQuery and persisted in
PostgreSQL** (the catalogue owner is `lyft/cartography`). `from_cartography()` is the seam and
**fails closed** — it raises rather than returning a silently-empty twin, because an empty blast
radius would falsely imply *"nothing is affected"*. Until that source is provisioned, twins are
built from explicit specs. Next increments: Cartography ingestion, a PostgreSQL-backed store for
scale, and feeding the graph into predictive attack-path forecasting (NetworkX) and PR-time
blast-radius checks.
