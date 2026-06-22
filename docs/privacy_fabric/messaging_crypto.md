# Messaging cryptography architecture

This is the **messaging plane** of the Privacy Fabric. It complements the data-at-rest /
session crypto modules in [../crypto_architecture.md](../crypto_architecture.md).

## Rule 0 — do not invent message encryption

**Do not design a new cryptographic protocol.** Guardian and engineering may *integrate,
test, and document* a protocol, but the cryptographic design must come from established,
peer-reviewed specifications and be reviewed by professional cryptographers. This rule is
load-bearing; everything below is integration of existing specs.

## Protocol split

A versioned cryptographic abstraction selects the suite per conversation type. A
conversation must **never silently downgrade** to a weaker protocol.

| Conversation type | Protocol | Why |
| ----------------- | -------- | --- |
| Private 1:1 chat | **Signal Protocol** (X3DH/PQXDH + Double Ratchet + Sesame) | Forward secrecy + post-compromise security; per-device sessions; async prekeys |
| Large private groups (Discord-style) | **MLS (RFC 9420)** | Designed for async encrypted groups from 2 to thousands; efficient tree-based membership/key updates |
| Group call media | **SFrame (RFC 9605)** over WebRTC; keys via MLS | SFU forwards media using routing metadata without decrypting audio/video |

Signal's current specs of interest: **PQXDH** (post-quantum initial key agreement),
**Double Ratchet** (continually changing message keys), **Sesame** (async multi-device),
and ongoing post-quantum ratcheting (ML-KEM work).

> **libsignal licensing/maintenance note:** the official implementation is AGPL-3.0 and
> Signal states use outside Signal is unsupported with APIs that may change. Adoption
> requires a **licensing review, a pinned compatibility layer, and a maintenance plan**
> before use. This is an explicit decision item, not an assumption.

### The versioned suite must pin

```
Conversation type → Protocol suite → Cipher suite → Key lifecycle
                  → Device lifecycle → Migration procedure → Backward-compatibility period
```

A specialist (not Guardian, not an LLM) signs off each row.

## Private 1:1 requirements

Per-device identity keys; asynchronous prekeys; forward secrecy; post-compromise security;
a new message key as the ratchet advances; safety-number / QR verification; key-change
warnings; per-device session revocation; **no server-held decryption keys**.

## Key transparency

E2EE is weakened if a malicious/compromised server can secretly substitute an identity key.
Build a key-transparency service:

- Append-only **verifiable key directory**; inclusion + consistency proofs.
- Client-side verification; key-change notifications; independent monitors.
- Signed checkpoints stored **outside** the messaging service; device-specific key history.
- **No silent key replacement**; recovery events clearly displayed to contacts.

The **Guardian Verifier** independently monitors this directory (public proofs/checkpoints
only — never private content or keys). See `guardian_verifier` in
[`policies/privacy_invariants.yaml`](../../policies/privacy_invariants.yaml).

## Sealed-sender delivery (metadata minimisation)

Ordinary E2EE protects contents but can expose *who sent what to whom*. Use a
metadata-reduced envelope:

```
Encrypted message content
        ↓
Encrypted sender envelope
        ↓
Short-lived delivery credential
        ↓
Relay receives destination but minimal sender identity
```

For stronger separation, run **two operationally separate services** with separate
databases, keys, administrators, and logs:

```
Ingress relay      — knows connection source, not final account destination
Delivery service   — knows destination mailbox, not original connection identity
```

Timing and IP-correlation remain hard problems and are acknowledged, not hand-waved.

## Pseudonymous identity by default

Random internal account IDs; usernames / QR invite links; private profiles by default; no
public phone-number discovery by default; no global people directory; optional (not
mandatory) contact discovery; login identity separated from public profile; easy username
rotation; block/identity-reset controls; **no advertising identifiers**; no marketing
device fingerprinting; pseudonymous abuse-prevention credentials.

## Client-side encryption, notifications, attachments, calls

- **Client storage:** hardware-backed keys (iOS Secure Enclave / Keychain, Android
  Keystore + StrongBox where available); encrypted local DBs; exclude plaintext from
  backups/previews; never log plaintext or place secrets in crash/analytics. **OWASP
  MASVS/MASTG are mandatory release gates** (see [epics.md](epics.md), Mobile Assurance).
- **Notifications:** push payloads carry only an opaque wake-up
  (`{"event":"encrypted_content_available","opaque_mailbox_hint":"…"}`); the app then
  authenticates, downloads the encrypted envelope, and decrypts locally. User settings for
  content visibility, quiet hours, and shared-device disguise.
- **Attachments:** per-file single-use media key; authenticated encryption on-device;
  thumbnails encrypted separately and generated on-device; ciphertext-only upload; opaque
  object names; strip EXIF/location before encryption unless the user opts to keep it;
  expiry for undelivered media; the CDN/image processor never sees plaintext.
- **Calls:** WebRTC transport protection + application-level E2EE above the SFU; SFrame for
  multi-party media; MLS for call-key distribution; self-run or contractually
  content-prohibited TURN/SFU; short-lived TURN credentials; no call-detail records by
  default; unmistakable indicator when recording/transcription is enabled.

## Moderation model

A server cannot be both unable to read messages and continuously scanning them. Resolve it
explicitly with three space types — never break E2EE quietly:

| Space | Encryption | Moderation |
| ----- | ---------- | ---------- |
| Private chats | Full E2EE | **User-controlled reporting only**; block/mute/invite controls; rate-limited requests; unknown senders restricted. Guardian sees infra/abuse signals, not plaintext. |
| Private support rooms | Full E2EE | The support worker is an **explicit cryptographic participant**, visible to all; documented retention/safeguarding; no invisible admin access. |
| Public / community | Explicit choice | Either server-readable + actively moderated **or** E2EE + client-side controls + user reports. **Never** label E2EE while keeping a hidden moderation key. |

### Privacy-preserving abuse reporting

On report, the **client** (not the server) selects the messages to disclose, includes
minimal surrounding context, shows exactly what will be sent, attaches cryptographic
authenticity evidence (investigate **message franking**), encrypts the report to the
safeguarding team, excludes unrelated messages, records consent/status, and avoids
prematurely notifying the accused where that creates danger. Emergency safeguarding is
designed *with* safeguarding professionals and privacy counsel — not bolted on later.

## Backups — E2EE only

Two explicit modes; **never a universal company recovery key**:

- **Maximum privacy:** no cloud message backup; device-to-device transfer only; losing all
  authorised devices may lose history.
- **Encrypted recovery:** client-encrypted backup; recovery key never reaches INVISABLE;
  user-held recovery phrase / hardware-backed recovery; memory-hard KDF + strong rate
  limiting; backup key separate from account password; every restore raises a visible
  security notification; users can destroy the backup and its key.
