# Phase 6 — Resilience & Recovery

Guardian must behave safely when its own foundations wobble. This phase proves two
properties: **when the control plane degrades, sensitive actions stop** (fail closed), and
**when evidence is lost, it can be recovered and re-verified** (proven backups).

Both are defensive-only: nothing here targets third parties, reaches production directly, or
bypasses human approval. They make Guardian *less* capable under uncertainty, not more.

## 1. Fail-closed on control-plane outage (area 23)

`resilience/` models the control-plane services a sensitive action depends on:

| Dependency | Why it gates execution |
| ---------- | ---------------------- |
| **OPA** | The authority. Its absence is already fail-closed in `core/policy_gate.py`. |
| **OpenBao** | Short-lived credentials. No broker ⇒ no credential ⇒ no execution. |
| **immudb** | Evidence system of record. No authoritative evidence ⇒ don't act. |
| **Temporal** | Durable workflow state. Degraded ⇒ pause, don't push ahead. |

`ControlPlane` tracks each dependency's `DependencyState` (`UP` / `DEGRADED` / `DOWN`).
`guard_sensitive_action(...)` refuses — raising `SensitiveActionBlocked` — if any required
dependency is not fully `UP`, and audits the refusal as `decision="denied"`. A `DEGRADED`
state blocks just like `DOWN`: partial availability is not enough for a state-changing action.

```python
cp = ControlPlane.all_up()
cp.set_state("openbao", DependencyState.DOWN)
guard_sensitive_action(cp, action="deploy_patch", audit=audit)  # -> SensitiveActionBlocked
```

Auditing is best-effort and must never crash enforcement: even if the audit sink throws, the
action is still refused. Evidence and operator visibility deliberately stay available so the
outage itself is observable.

## 2. Verifiable backups + restore drill (area 26)

`recovery/` provides WORM (write-once) backups with integrity verification:

- `BackupManager.snapshot(source, data)` records the content SHA-256 at creation.
- `Backup.verify()` recomputes the digest; any at-rest tampering is detected.
- `BackupManager.restore(backup)` **refuses** (`TamperError`) if verification fails — Guardian
  never restores corrupted evidence.

`run_restore_drill(audit, manager)` proves recovery actually works against the tamper-evident
audit log:

1. snapshot the audit chain bytes (WORM),
2. simulate catastrophic loss (the live audit file is destroyed),
3. restore from the backup (refused if the backup was tampered),
4. re-verify the restored hash chain end-to-end via `AuditLog.verify()`.

It returns a `DrillResult` with a per-step log and measured **RPO** (recovery point, declared)
and **RTO** (recovery time, measured). A backup is only *proven* once a drill has restored it
and re-verified the chain — an untested backup is treated as an assumption, not a control.

## Tests

- `tests/test_resilience.py` — all-up permits; each of OPA/OpenBao/immudb/Temporal down (or
  degraded) blocks; refusals are audited as denied; a broken audit sink still blocks.
- `tests/test_recovery.py` — backup roundtrip; tamper detected and restore refused; full drill
  recovers and re-verifies the chain (incl. empty chain); a tampered backup yields `ok=False`.
