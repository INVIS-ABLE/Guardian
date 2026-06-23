# Guardian Continuous Adversary-Emulation Lab

> **Sovereign plane, Wave 3, system #13 — the first Proof system.** Wave 1 gave Guardian
> awareness and Wave 2 gave it reasoning; Wave 3 lets it **prove** its controls work by attacking
> them — *in a disposable lab only* ([`sovereign_ops_plane.md`](sovereign_ops_plane.md); upstream:
> CALDERA / Atomic Red Team / Stratus). First slice in [`core/emulation/`](../core/emulation).

## The two rules

1. **Lab only.** Emulation runs in the disposable range and *nowhere else*. The harness
   ([`AdversaryLab`](../core/emulation/lab.py)) refuses any non-range environment with a
   `LabOnlyViolation` before processing a single result — emulation never touches production.
2. **Every bypass becomes a regression test.** For each emulated ATT&CK technique the lab answers
   three questions — *was it prevented? detected by an independent sensor? was evidence
   preserved?* — and mints a permanent test for every gap, so a control failure can never
   silently reappear.

```bash
guardian emulate emulation/invisable-attack-plan.yaml
#   ○ detected T1078.004   Valid Accounts: Cloud Accounts by identity
#   ✓ blocked  T1567       Exfiltration Over Web Service
#   ✗ bypass   T1098       Account Manipulation
#   ✗ bypass   T1562.001   Impair Defenses: Disable or Modify Tools  [no evidence]
#   blocked 2  detected 2  bypass 2  evidence-gaps 1
#   regression tests minted (3):
#     + [bypass]       T1098 must be prevented or detected by an independent sensor
#     + [bypass]       T1562.001 must be prevented or detected by an independent sensor
#     + [evidence_gap] T1562.001 must preserve forensic evidence when it fires

guardian emulate-gate emulation/invisable-attack-plan.yaml   # exits non-zero on any bypass
```

The sample replays the Wave-1 *"leaked CI token"* kill chain against the controls: the stolen-
token use and the in-container shell are **detected**, the exfiltration and C2 are **blocked**,
but account manipulation and defense-impairment **bypass** everything — and the latter leaves no
evidence. Each gap is minted into a regression test, and the gate fails.

## Verdicts and gaps

| Per technique | Meaning |
| ------------- | ------- |
| **blocked** | a preventive control stopped it (best case) |
| **detected** | not prevented, but an independent sensor caught it |
| **bypass** | neither prevented nor detected — a silent control failure → regression test |
| **evidence gap** | the technique fired but no forensic evidence was preserved → regression test |

`emulate-gate` exits non-zero if the operation found **any bypass**, so a regression in the
controls fails CI.

## How it works

| Piece | File | Role |
| ----- | ---- | ---- |
| Typed models | [`core/emulation/models.py`](../core/emulation/models.py) | `Tactic`, `Technique`, `TechniqueResult` (→ `Verdict`), `RegressionTest`, `EmulationReport` |
| Lab harness | [`core/emulation/lab.py`](../core/emulation/lab.py) | `AdversaryLab` — enforces lab-only, classifies results, mints a regression per gap |
| Ingestion | [`core/emulation/ingest.py`](../core/emulation/ingest.py) | `build_from_spec` / `load_operation` (YAML); `from_caldera` (production hook, fails closed) |

It executes nothing itself and asserts **no authority** — it adjudicates the results the range
produced (autonomy level 3 / engineering). It builds on the prior waves: the techniques map to
the same kill chain the [event fabric](event_fabric.md) and [forensic timeline](forensic_timeline.md)
observed, the sensors that "detect" are those same Wave-1 systems, and a bypass is exactly the
kind of finding the [competing-hypothesis engine](competing_hypotheses.md) would weigh.

## Privacy & safety boundary

Lab-only and metadata-only: the harness records *that* a technique was or wasn't caught, never
production data, and structurally cannot run against production. `from_caldera()` fails closed —
an empty report would falsely imply *"no technique bypassed our controls,"* the most dangerous
false negative for a defensive lab.

## The production path

In production the results come from **CALDERA** orchestrating **Atomic Red Team** / **Stratus Red
Team** techniques against the cloned range. Next increments: CALDERA ingestion, emitting the
minted regression tests into the test suite automatically, and scheduling continuous operations
so every control change is re-attacked before it ships.
