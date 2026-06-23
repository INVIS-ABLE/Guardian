# Guardian Digital-Twin Chaos & Recovery Simulator

> **Sovereign plane, Wave 3, system #17 — the Wave-3 capstone.** Failure simulations run against
> a **clone** of the digital twin (#1), never production: kill a region / IdP / OPA / secrets
> store / CA / key rotation / queue / DB / audit log / network, then compare the model's
> *predicted* blast radius against the *actual* impact ([`sovereign_ops_plane.md`](sovereign_ops_plane.md)).
> First slice in [`core/chaos/`](../core/chaos).

The [`ChaosSimulator`](../core/chaos/simulator.py) closes the loop on the twin's predictions:

- **Clone-only.** It refuses any reference not marked a clone (`shadow`/`replica`/`ephemeral`/…),
  so it can never inject failures into the production twin.
- **Surprises** — every divergence between predicted and actual impact is a learning signal:
  *unpredicted impact* (something broke the map missed — a gap to fix) and *overpredicted impact*
  (a control held where the model feared failure — resilience to bank).
- **Gate** — `chaos-gate` fails on a map gap or an RTO breach; **model accuracy** (fraction of
  scenarios predicted exactly) tells Guardian how much to trust the twin's blast-radius forecasts.

```bash
guardian chaos chaos/invisable-gameday.yaml
#   policy_engine_down  svc:messaging-relay  RTO 95s/120s
#         ‼ unpredicted_impact: db:mailbox            ← the twin map missed this dependency
#   region_outage       svc:messaging-relay  RTO 540s/300s ✗RTO
guardian chaos-gate chaos/invisable-gameday.yaml   # non-zero on a map gap or RTO breach
```

It closes the Wave-1 → Wave-3 loop: the twin (#1) *predicts* blast radius; this simulator
*measures* it against reality and feeds the corrections back. `from_chaos_platform()` fails
closed — an absent game-day is not a passed one.

---

*With #17, **Wave 3 — Proof & controlled experimentation** is complete in first-slice form:
adversary-emulation lab (#13), fuzzing farm (#14), crypto-proof lab (#15), binary/malware lab
(#16) and chaos & recovery simulator (#17) — Guardian can now prove its controls work, not just
assert them.*
