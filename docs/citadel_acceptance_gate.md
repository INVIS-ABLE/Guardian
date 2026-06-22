# Crown Citadel — acceptance gate

The Crown Citadel is **not** declared operational until every line below holds. This gate is the
terminal state of Waves 21–39; Wave 20 (reconciliation) only stands up the manifests and tests that
make this gate measurable. Each item names the system that satisfies it.

## Coverage (must be 100%)

```
100% production workers have verifiable workload identity          (root_of_trust, existing SPIRE)
100% sensitive workers have current platform attestation           (root_of_trust)
100% critical artefacts have SBOM, provenance and signature        (build_foundry)
100% critical builds pass independent reproduction                 (build_foundry)
100% promoted artefacts have transparency inclusion proofs         (build_foundry / transparency)
100% root operations require quorum                                (trust_quorum)
100% key ceremonies produce signed evidence                        (key_custody)
100% critical state machines have formal models                    (formal_state_machine)
100% formal-model changes are rechecked                            (formal_state_machine)
100% cyber-vault classes pass restore tests                        (cyber_vault)
100% critical control claims have fresh evidence                   (control_proof_engine)
100% deception assets have no real privileges                      (deception_grid)
100% Citadel event types trace to a case or control claim          (control_proof_engine)
```

## Must be ZERO

```
0 private-message plaintext in Citadel systems                     (privacy barrier)
0 production authority in the Shadow Guardian                      (shadow_federation)
0 production authority in model systems                            (authority invariants)
0 unregistered workers receiving capabilities                     (root_of_trust)
0 expired capabilities executing                                  (core/tools, shadow_federation)
0 unsigned policy bundles in production                           (verified_policy)
0 critical time-integrity failures left unresolved               (secure_time)
```

## Exercises (must pass)

Catastrophic control-plane recovery · compromised-worker · corrupted-build · transparency-log
recovery · crypto-rotation · clock-manipulation · evidence-tampering · quorum-compromise ·
safeguarding privacy-boundary. Plus independent architecture, cryptographic, recovery and
accessibility reviews, and a signed Citadel assurance report.

## Wave-20 status against this gate

Wave 20 delivers the **measurement apparatus**, not the green gate. Today:

- The 30 Wave-20 invariants are encoded and pass at the manifest/config level
  (`tests/test_citadel_*.py`, 49 tests).
- Runtime enforcement of `planned`/`partial` systems is **not** yet complete — surfaced honestly by
  the `test_every_system_is_runtime_enforced` xfail and the `status` field in the catalogue.
- The gate above turns green only as Waves 21–39 land each system as a tested vertical slice.

Per the directive: *do not declare the Citadel operational until the above holds.* This document is
the checklist that prevents premature "operational" claims.
