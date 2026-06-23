# Guardian Cryptographic Protocol Proof Lab

> **Sovereign plane, Wave 3, system #15.** Symbolic verification of the protocols that protect
> INVISABLE — device enrolment, key agreement, group membership, forward secrecy, account
> recovery — answering *"does this flow keep its security property against an active attacker?"*
> ([`sovereign_ops_plane.md`](sovereign_ops_plane.md); upstream: Tamarin / Verifpal / ProVerif).
> First slice in [`core/crypto_proof/`](../core/crypto_proof).

The [`CryptoProofLab`](../core/crypto_proof/lab.py) adjudicates the prover's results:

- each property is **proved**, **falsified** (an attack exists — the symbolic trace is attached),
  or **unknown** (the prover didn't conclude — kept distinct from a genuine failure);
- a falsified **critical** property is a real **break**; `crypto-proof-gate` fails on any break.

```bash
guardian crypto-proof crypto_proof/invisable-protocols.yaml
#   ✓ proved      proto:message-key      forward_secrecy
#   ✗ falsified   proto:account-recovery recovery_soundness
#         ↪ attacker initiates recovery for the victim handle …
guardian crypto-proof-gate crypto_proof/invisable-protocols.yaml   # non-zero on a break
```

**The cardinal rule — symbolic only.** It reviews the crypto *system*, **never plaintext or key
material**: the models refuse any property or trace step that names real content/keys, so proof
artefacts are abstract by construction. `from_provers()` fails closed (an absent proof is not a
passed proof).
