# INVISABLE Privacy Fabric

The Privacy Fabric is the platform layer that makes INVISABLE Life / INVISABLE Chat
**private by architecture, not by promise**. Its design goal is concrete:

> Even a full backend compromise must not automatically expose the vulnerable people who
> trusted INVISABLE.

This is not "more security tools." It is a layering where the cryptographic boundary sits
**above** the infrastructure that Guardian defends — so the people who protect the system
are structurally unable to read inside it.

## Honest privacy claims

INVISABLE commits to claims it can actually keep, which is both stronger and safer than an
absolute one:

- INVISABLE **cannot read private conversations** (client-side E2EE; server relays ciphertext).
- It stores the **minimum possible metadata**.
- It retains encrypted data **only as long as necessary** (see [retention_and_legal.md](retention_and_legal.md)).
- It contains **no advertising trackers**.
- It gives users **meaningful control** over deletion and identity.

Benchmark: **Signal-level communications privacy**, major-provider DDoS protection,
zero-trust internal networking, hardened mobile clients, and **independent cryptographic
audit** — not endpoint-AV parity.

## Target structure

```
INVISABLE Life / INVISABLE Chat
            │
            ▼
Client cryptography and device security
            │
            ▼
Metadata-minimising message relay
            │
            ▼
INVISABLE Privacy Fabric
            │
     ┌──────┴───────┐
     ▼              ▼
Guardian         Safety systems
infrastructure   user-controlled reporting
protection
```

## The Guardian boundary (non-negotiable)

Guardian protects **infrastructure, code, identities and availability**. It must **never**
be given general access to decrypted private conversations.

| Guardian **watches** | Guardian **never receives** |
| -------------------- | --------------------------- |
| infrastructure, identities, policies | message plaintext |
| anomalies, abuse signals, availability | media plaintext |
| key-directory integrity (Verifier) | conversation keys |

These boundaries are **enforced**, not just documented:

- The "Guardian must never" list in [`policies/privacy_invariants.yaml`](../../policies/privacy_invariants.yaml)
  is mirrored as globally **blocked actions** in `core/policy_gate.py` and
  `policies/opa/guardian.rego`. Any request to `decrypt_private_content`,
  `copy_private_content_to_memory`, `train_on_user_content`, etc. is denied by the central
  authority — default-deny, fail-closed — and audited.
- Tests in `tests/test_privacy_invariants.py` prove every invariant is denied for every input.

Guardian's one privacy-adjacent **active** role is the **Verifier**: it independently
monitors the append-only key-transparency directory using public proofs and signed
checkpoints only.

## The architecture to aim for

```
User device
├── hardware-backed identity key
├── E2EE session state
├── encrypted message database
├── local media encryption
└── private notification handling
           │
           ▼ ciphertext only
Global DDoS + WAF edge          ── Ring 1
           │ mTLS
           ▼
Envoy + Coraza (OWASP CRS)      ── Ring 3
           │
           ▼
Metadata-minimising ingress relay   (sealed sender, two-hop)
           │
           ▼
Encrypted delivery mailbox
           │
     ┌─────┴─────────────┐
     ▼                   ▼
Key transparency     Encrypted object storage
service              (ciphertext only)
     │
     ▼
Independent Guardian Verifier
```

Network enforcement is layered across **five independent rings** (Ring 2 locked origin,
Ring 4 Cilium zero-trust service mesh, Ring 5 runtime containment) — see
[five_ring_firewall.md](five_ring_firewall.md).

## Document map

| Area | Document |
| ---- | -------- |
| Five-ring network defence | [five_ring_firewall.md](five_ring_firewall.md) |
| Messaging cryptography (Signal vs MLS, key transparency, sealed sender, backups) | [messaging_crypto.md](messaging_crypto.md) |
| Retention classes + UK-GDPR / DPIA / safeguarding | [retention_and_legal.md](retention_and_legal.md) |
| The 14 delivery epics (ordered) | [epics.md](epics.md) |
| ADR 0001 — messaging protocol (Signal vs MLS) · Epic 2 | [adr/0001-messaging-protocol.md](adr/0001-messaging-protocol.md) |
| ADR 0002 — key transparency & the Guardian Verifier · Epic 3 | [adr/0002-key-transparency.md](adr/0002-key-transparency.md) |
| Existing crypto module layer (data-at-rest, sessions, audit) | [../crypto_architecture.md](../crypto_architecture.md) |
| Guardian's own control gates | [../../GUARDRAILS.md](../../GUARDRAILS.md) |

## The moderation reality

A server **cannot** both be unable to read messages and continuously scan all messages for
abuse. The Fabric resolves this explicitly (see [messaging_crypto.md](messaging_crypto.md#moderation-model))
with three clearly separated space types and **privacy-preserving, user-controlled
reporting** — never a hidden moderation key on a channel labelled E2EE.

> A conversation must never silently downgrade to a weaker protocol, and a channel must
> never be labelled E2EE while a hidden moderation key is retained.
