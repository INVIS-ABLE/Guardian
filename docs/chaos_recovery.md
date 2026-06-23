# Guardian Digital-Twin Chaos & Recovery Simulator

> **Sovereign plane, Wave 3, system #17 — the Wave-3 capstone.** Failure simulations run against
> a **clone** of the digital twin (#1), never production, to answer the question the Sovereign doc
> poses: *which controls actually work?* ([`sovereign_ops_plane.md`](sovereign_ops_plane.md)).

## Real, twin-driven simulation

The simulation is **computed from the actual twin** ([`core/twin/chaos.py`](../core/twin/chaos.py)),
not transcribed from a spec. For a failure of `target`:

- **predicted impact** = `twin.blast_radius(target)` — everything the model says a loss of
  `target` propagates to, *ignoring defences*;
- **actual impact** = the same directed propagation, but a **working security control** (a
  `SECURITY_CONTROL` asset with a `PROTECTS` edge) is a **firebreak**: the asset it protects
  survives and does not propagate the failure onward;
- **contained_by_controls** = predicted − actual = *exactly which controls worked*.

A scenario may mark controls as **degraded** (the chaos injection — *"what if Sigstore is also
down?"*); the firebreak disappears, the actual impact grows, and the game-day shows the control's
real worth. Recovery timing (RTO) is a genuine observation and stays an input.

```bash
guardian twin-chaos twin/invisable-sample.yaml chaos/invisable-twin-gameday.yaml
#   s1-repo-compromise   fail repo:guardian → CONTAINED   ✓ controls held: ctrl:sigstore (saved 5)
#   s2-...-control-down  fail repo:guardian → 5 impacted  [controls down: ctrl:sigstore]
#   s3-service-outage    fail svc:messaging-relay → 3 impacted  RTO 540s/300s ✗RTO
#   controls that actually worked: ctrl:sigstore×1
guardian twin-chaos-gate twin/invisable-sample.yaml chaos/invisable-twin-gameday.yaml  # non-zero on RTO breach
```

In the sample, Sigstore admission **fully contains** a repository compromise (a malicious build
can't be admitted, so nothing downstream is reached) — but degrade that one control and the full
blast lands on the service, DB and message ciphertext. That difference is computed from the twin
graph, not asserted.

## How it works

| Piece | File | Role |
| ----- | ---- | ---- |
| Engine | [`core/twin/chaos.py`](../core/twin/chaos.py) | `simulate_failure(twin, target, degraded_controls=…)` (predicted via `blast_radius`, actual via firebreak propagation), `run_gameday`, `load_gameday` |
| CLI | [`core/cli.py`](../core/cli.py) | `twin-chaos` (report) and `twin-chaos-gate` (fails on an RTO breach) |
| Reused | [`core/twin/graph.py`](../core/twin/graph.py), [`core/chaos/`](../core/chaos) | the real twin graph + `blast_radius`; `FailureMode` vocabulary and the clone-only guard (`ChaosSimulator`) are reused, not redefined |

It **closes the Wave-1 → Wave-3 loop**: the twin (#1) *predicts* blast radius; this simulator
*measures* it against the twin's own control semantics and reports which defences actually
contain a failure. **Clone-only** is enforced by reusing `core.chaos`'s guard — a production twin
reference is refused, so the simulator can never inject failures into production. Read-only and
metadata-only, like the rest of the twin.

## The production path

The `degraded_controls` and RTO observations come from a real game-day platform driving failures
against a captured clone of the live twin; the predicted/actual blast radii are always computed
from the twin graph. Next increments: clone-capture from the live twin, a chaos platform
(Litmus/Gremlin) to inject the declared failures, and feeding `contained_by_controls` back as
evidence of control efficacy.

---

*With #17, **Wave 3 — Proof & controlled experimentation** is complete in first-slice form:
adversary-emulation lab (#13), fuzzing farm (#14), crypto-proof lab (#15), binary/malware lab
(#16) and the twin-driven chaos & recovery simulator (#17) — Guardian can now prove its controls
work, not just assert them.*
