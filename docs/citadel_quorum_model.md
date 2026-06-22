# Crown Citadel — quorum model

Root-level operations are never held by a single service or person. They require a **multi-party
threshold** of independent participants with **separate credentials** and **separate evidence reads**.
Owner: `orchestration/approvals.py` (the existing `ApprovalLedger`, extended with thresholds in
`configs/citadel/quorum.yaml`). Verifier: `citadel/quorum/evidence.py` (independent).

## Operations requiring quorum

| Operation | Threshold | Rationale |
|-----------|-----------|-----------|
| Root-key rotation | 3 | no single custodian controls the root |
| Attestation-root rotation | 3 | trust anchor for every worker |
| Recovery activation | 3 | recovery is high-blast-radius |
| Evidence-root migration | 3 | preserves the chain of custody |
| Transparency-log migration | 3 | preserves public verifiability |
| Emergency policy replacement | 4 | overrides the reference monitor |
| Guardian-wide capability freeze | 2 | fast defensive stop |
| Re-enrolment after catastrophic compromise | 4 | rebuilds all trust |

## Quorum result record (signed, immutable)

```
operation · participants · participant_identities · separate_authentication_evidence ·
submitted_decision · timestamp · policy_digest · target_digest · evidence_digest ·
threshold · result · signature
```

## Invariants (enforced by `tests/test_citadel_quorum_invariants.py`)

- **Threshold** — root operations need ≥ 3 distinct participants; emergency policy ≥ 4 (invariants 16–17).
- **Separate credentials** — participants authenticate independently; no shared secret.
- **Separate evidence reads** — participants verify against independent evidence, not one feed.
- **Recovery credentials outside runtime** — drawn from an offline plane (invariant 18).
- **Primary ≠ Shadow approver** — the primary Guardian cannot approve the Shadow (invariant 14), and
  the Shadow cannot assume operational control (invariant 15).

## Relationship to the Shadow

The Shadow (`shadow_guardian/verifier.py`) may **freeze** capability issuance on divergence but never
commands. Only a **Sovereign-Root quorum** clears the freeze — the primary cannot clear its own.
Quorum is thus the dispute-resolution authority between the primary and the Shadow, and the gate for
every irreversible root change.
