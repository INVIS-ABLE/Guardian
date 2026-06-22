# Forensic timeline

`forensics/` reconstructs an ordered incident timeline from heterogeneous security events
(target architecture §17). It is **read-only** analysis over a canonical event envelope
(`TimelineEvent`, a subset of the §16 event-fabric schema) — it draws conclusions and
authorises nothing.

`ForensicTimeline.build(events) -> TimelineReport` performs:

| Step | What | Why |
| ---- | ---- | --- |
| de-duplicate | drop repeated deliveries by `event_id` | a replay is not a second event |
| clock-skew correction | add a per-`source` offset to align clocks | events from skewed nodes sort correctly |
| ordering | stable sort by corrected time | a true sequence, not arrival order |
| causal links | `preceded_by` = prior event in the same `case_id`/`trace_id` group | reconstruct what led to what |
| missing-event detection | a trigger action without its required follow-ups | a step that should have happened didn't |
| **unsupported success** | a `success` event with no required independent corroboration in the same case | **a tool claims success but the evidence is absent** |
| integrity anomalies | any event that arrived without a valid integrity signal | tampered/forged telemetry |

## The load-bearing check

> *"identify when a tool claims success but expected independent evidence is absent"* (§17)

`corroboration` maps a successful action to the source whose independent event must back it
up. A connector reporting `scan: success` with **no `evidence`-ledger append in the same
case** is flagged `unsupported_success:<case>:scan:no_evidence`. This is the timeline-level
counterpart to the Shadow Guardian's transition check and the evidence ledger's append
receipt: three independent angles on *"did the thing it claims to have done actually leave
the evidence it should have?"*

`TimelineReport.chain_of_custody()` exports the ordered record for evidence hand-off.
