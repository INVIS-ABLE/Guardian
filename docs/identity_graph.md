# Guardian Identity & Permission Attack Graph

> **Sovereign plane, Wave 1, system #2** — the BloodHound-style companion to the
> [live cyber digital twin](digital_twin.md) ([`sovereign_ops_plane.md`](sovereign_ops_plane.md)).
> The twin reasons over **assets** (*"what is affected if this is compromised?"*); this graph
> reasons over **principals and permissions**. This page documents the first slice that is
> **implemented in code** ([`core/identity_graph/`](../core/identity_graph)), and the
> production path beyond it.

## What it answers

A typed graph of who-can-do-what across the INVISABLE estate, answering the four identity
questions from the Sovereign doc — instantly and auditably:

| Question | Query | What it surfaces |
| -------- | ----- | ---------------- |
| **Effective + transitive permissions** | `effective_permissions(p)` | what a principal can actually do once group/role membership is followed to its closure |
| **Privilege-escalation paths** | `escalation_paths(p)` | how a principal could *acquire* rights it does not hold today — by assuming a role or rewriting another principal's grants |
| **Dormant privilege** | `dormant_privileges(...)` | privileged principals that have gone quiet — unused standing access is a removal candidate and a blast-radius multiplier if the credential leaks |
| **Separation-of-duties breaks** | `separation_of_duties_breaks(...)` | a single principal that can perform two duties policy requires be held by different people (e.g. *author* **and** *approve* a release) |

```bash
guardian id-perms    identity_graph/invisable-identity-sample.yaml id:human-dev
# Effective permissions of human 'Developer' (id:human-dev):
#   write            repo:guardian            (via role:repo-writer) [author]

guardian id-escalate identity_graph/invisable-identity-sample.yaml id:human-dev
# id:human-dev → can_assume → role:release-admin
#       gains: approve_release:repo:guardian

guardian id-dormant  identity_graph/invisable-identity-sample.yaml --idle-days 30 --as-of 2026-06-22
#   id:old-deploy      idle 506d        1 perm(s) [sensitive]

guardian id-sod      identity_graph/invisable-identity-sample.yaml
#   id:release-bot     release author/approver: write (author) + approve_release (approve)
```

## How it works

| Piece | File | Role |
| ----- | ---- | ---- |
| Typed models | [`core/identity_graph/models.py`](../core/identity_graph/models.py) | `PrincipalKind`, `EdgeKind`, frozen `Principal`/`IdentityEdge`/`Grant`, and the result types (`EffectivePermission`, `EscalationPath`, `DormantPrincipal`, `SoDBreak`) |
| Graph + queries | [`core/identity_graph/graph.py`](../core/identity_graph/graph.py) | in-memory directed graph; the four BFS queries above, each carrying the shortest explanatory path |
| Ingestion seam | [`core/identity_graph/ingest.py`](../core/identity_graph/ingest.py) | `build_from_spec` / `load_graph` (YAML) now; `from_bloodhound` is the production hook |

**Two edge families with deliberately different power** — this is the crux of the model:

- **Inheritance** (`member_of`): the source *already holds* every grant of the target.
  Following inheritance to its closure gives a principal's **effective** permissions.
- **Escalation** (`can_assume`, `can_grant`): the source can *acquire* the target's grants by
  taking an action — assuming a role, or rewriting the target's permissions. These are the
  edges **escalation paths** are made of.

Because effective permissions follow inheritance only, a principal reachable by pure
membership adds nothing new to an escalation result (its grants are already effective). So
`escalation_paths` reports exactly the routes that *grow* a principal's privilege, and each
reported path lists precisely the permissions it would gain.

## Privacy boundary (enforced)

Identical to the twin: this graph holds **identity metadata and permission relationships,
never private content**. A principal is an identifier; a grant names an *action* on a
*resource* (`deploy` on `svc:messaging-relay`), never the data itself. Guardian protects the
access-control system while remaining structurally outside private content — mirroring the
Verifier's boundary and the Privacy Fabric.

## The production path

In production the graph is **continuously populated from BloodHound** (and the cloud IAM /
directory connectors that feed it). `from_bloodhound()` is the seam and **fails closed** — it
raises rather than returning a silently-empty graph, because an empty escalation or SoD result
would falsely imply *"no one can escalate"*. Until that source is provisioned, graphs are built
from explicit specs. Next increments: BloodHound/IAM ingestion, a persisted store for scale,
joining the identity graph to the twin (a leaked principal's grants become twin blast-radius
seeds), and feeding both into predictive attack-path forecasting (system #12).
