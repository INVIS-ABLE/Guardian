# Shadow Guardian

An **independent verifier** of high-risk Guardian transitions (target architecture §35).
It re-checks what the primary Guardian issues — one-use capability tokens
(`core/tools/capability.py`) and their signed tool manifests (`core/tools/manifest.py`) —
and can **freeze** capability issuance when it sees an unexplained divergence.

> The Shadow Guardian cannot perform production actions. It verifies and freezes; it never
> executes, issues, or deploys (`tests/test_shadow_guardian.py::test_shadow_holds_no_execution_methods`).

## Why a separate package

`shadow_guardian/` is deliberately **not** part of `core`. It does not import the
primary's hashing/signing helpers — it **recomputes them independently**
(`_independent_args_hash`, its own manifest-HMAC check against its own copy of the trusted
key). A bug or compromise on the primary side therefore cannot make the Shadow agree by
construction. In production it runs as a separate codebase, cloud account, and key set,
with read-only access and no execution credentials.

## What it checks

For each transition `verify_transition(token, signed_manifest, observed, evidence_receipt)`
independently re-derives and compares:

| Check | Catches |
| ----- | ------- |
| `manifest_signature` | a forged/altered tool manifest |
| `token_unexpired` | a capability used past its window |
| `tool_digest_matches_manifest` | a token pointing at a different image than its manifest |
| `args_hash_matches_observed` | the executor running **different args** than were authorised |
| `token_binds_observed_call` | case/tool/env rebinding |
| `limits_not_increased` | a token granting more CPU/memory/runtime/output than the manifest |
| `network_matches_manifest` | egress widened beyond the manifest |
| `evidence_receipt_present` | execution without an immutable evidence record |

Any failure trips the **freeze latch**.

## The freeze latch and issuance gate

```
divergence ──▶ FreezeLatch.trip() ──▶ ShadowGate.assert_issuable() raises CapabilityFrozen
                                          ▲
            Shadow Guardian unavailable ──┘  (fail closed: loss of the Shadow also freezes)
```

- The latch is **one-way**: once tripped, only the **Sovereign Root** may clear it
  (`clear_by_sovereign_root(authorized=True)`); the primary Guardian cannot clear its own freeze.
- The capability **issuer consults `ShadowGate.assert_issuable()` before minting** a
  high-risk capability — so a divergence (or an unavailable Shadow) stops new issuance,
  satisfying the recovery invariant *"Loss of the Shadow Guardian freezes high-risk actions."*

## Relationship to the other authority components

This completes the independent-verification leg of the authority split. The other three
pieces already exist and are **not** duplicated here:

- Proof-carrying capabilities — `core/tools/capability.py`
- Tool Intelligence Registry / signed manifests — `core/tools/registry.py`, `manifest.py`
- Context Firewall — `core/ai/context_firewall.py`

The Shadow Guardian is the component that watches them.
