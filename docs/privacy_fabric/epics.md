# Privacy Fabric — delivery epics

Ordered. Each epic is independently shippable and has a clear "done" definition. Guardian's
role across all of them is **defensive**: analyse, simulate against owned staging, propose
PRs, gather evidence, and verify — never read private content.

| # | Epic | Outcome / definition of done |
| - | ---- | ---------------------------- |
| 1 | **Privacy Threat Model** | Documented adversaries (stalkers, abusive household members, hostile admins, criminal attackers, compromised devices, insiders, social engineers, metadata correlation) with mapped defences. Seeded in [retention_and_legal.md](retention_and_legal.md#privacy-threat-model). |
| 2 | **Cryptographic Architecture Decision** | 🟡 ADR drafted ([adr/0001-messaging-protocol.md](adr/0001-messaging-protocol.md), *Proposed*) — Signal 1:1 / MLS groups / SFrame calls; awaiting cryptographer sign-off on libsignal licensing, MLS suite, migration & revocation. See [messaging_crypto.md](messaging_crypto.md). |
| 3 | **Key Transparency Service** | 🟢 Guardian **Verifier** implemented ([`core/verifier.py`](../../core/verifier.py), `tests/test_verifier.py`) + design ADR ([adr/0002-key-transparency.md](adr/0002-key-transparency.md)); production verifiable-log directory + Ed25519 checkpoints pending. |
| 4 | **Metadata-Minimising Relay** | Sealed sender, two-hop routing, short-lived delivery credentials; ingress/delivery split with separate datastores. |
| 5 | **Device Trust Service** | Per-device identities, linking, verification, revocation, recovery. |
| 6 | **Five-Ring Network Defence** | Edge DDoS/WAF, locked origin, Envoy+Coraza app firewall, Cilium zero-trust, runtime enforcement. See [five_ring_firewall.md](five_ring_firewall.md). |
| 7 | **Encrypted Attachment Pipeline** | Client-side encryption, metadata removal, ciphertext-only storage, on-device thumbnails. |
| 8 | **Private Calling Plane** | WebRTC + SFrame, hardened TURN/SFU, MLS-based call-key management. |
| 9 | **Privacy-Preserving Notifications** | Opaque APNs/FCM wake-ups only; local download+decrypt; user visibility controls. |
| 10 | **Safety Without Backdoors** | User-controlled reporting, signed evidence (message franking), explicit support-room participation, anti-harassment controls. |
| 11 | **Private Telemetry** | Redaction, pseudonymisation, no third-party trackers, strict retention. See [retention_and_legal.md](retention_and_legal.md). |
| 12 | **Mobile Assurance Programme** | MASVS/MASTG as release gates, device-compromise testing, crypto test vectors, external mobile pentests. |
| 13 | **Independent Cryptographic Audit** | External review of protocol integration, key storage, randomness, multi-device, backup, migration. |
| 14 | **Privacy Red Team** | Attempts at social-graph discovery, user enumeration, cross-tenant leakage, metadata correlation, recovery abuse. |

## Sequencing notes

- **1 → 2 first.** The threat model and the crypto ADR gate everything else; do not build
  relays or clients before the protocol suite is decided and signed off.
- **3, 4, 5** form the privacy backbone (key transparency, metadata minimisation, device
  trust) and can proceed in parallel once the ADR lands.
- **6** (five-ring defence) is independent infrastructure and can start immediately.
- **12, 13, 14** are assurance gates — they validate the rest and should be scheduled into
  [../governance/SECURITY_TESTING_CALENDAR.md](../governance/SECURITY_TESTING_CALENDAR.md).

## Guardian epics vs Privacy Fabric epics

These extend, not replace, the hardening work in [../hardening_roadmap.md](../hardening_roadmap.md).
Guardian's deliverables for each epic are PRs, evidence reports, simulators (owned staging
only), and the Verifier — all within the boundary enforced by
[`policies/privacy_invariants.yaml`](../../policies/privacy_invariants.yaml).
