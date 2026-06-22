# Crypto Threat Model

Scope: the INVISABLE encryption/hashing layer (`security/crypto`) and how it protects
vulnerable users of Guardian and the PWA. Framed loosely on STRIDE, mapped to mitigations
in code.

## Assets

- User credentials (passwords) and sessions.
- Sensitive profile data: health/disability, contact, safeguarding flags.
- Private user-to-user messages.
- Admin audit trail (evidence).
- Encryption keys (KEKs, DEKs, identity keys).

## Adversaries

- External attacker (credential stuffing, XSS, MITM, stolen backups).
- Malicious/compromised insider (admin abuse, log tampering).
- Stolen device / shared device (PWA cache, tokens at rest).
- Supply-chain attacker (malicious crypto-lib version).

## Threats → mitigations

| Threat (STRIDE) | Scenario | Mitigation (module) |
| --------------- | -------- | ------------------- |
| **Spoofing** | Stolen refresh token replayed | Refresh rotation + reuse detection revokes family (3). |
| **Spoofing** | SIM-swap defeats SMS MFA | Prefer passkey/TOTP; `amr` records method (3; mobile modules). |
| **Tampering** | Admin edits audit history | Hash chain + Ed25519 signatures detect any change (8). |
| **Tampering** | Ciphertext cut-and-paste between records | AEAD with context AAD fails authentication (5). |
| **Repudiation** | Admin denies an action | Signed, chained audit entries (8). |
| **Info disclosure** | DB/backup theft | Argon2id passwords (1); AEAD field encryption (5); keys kept apart (4). |
| **Info disclosure** | XSS steals token from localStorage | Tokens never in localStorage; HttpOnly cookies (2). |
| **Info disclosure** | Stolen device reads PWA cache | Service worker must not cache sensitive responses; checker rule (9). |
| **Info disclosure** | Unencrypted data export leaks PII | All exports encrypted (6); checker verifies (9). |
| **Info disclosure** | Server reads private messages | Client-held keys; server relays ciphertext only (7). |
| **Info disclosure** | Key stored beside ciphertext | Envelope encryption; checker rule (4, 9). |
| **DoS** | Huge password input exhausts memory | Input size cap before Argon2id (1). |
| **Elevation** | alg-confusion / "none" JWT | Algorithm pinned on verify (3). |
| **Supply chain** | Malicious crypto-lib version | Exact-pinned libs; OSV/Trivy scan; checker enforces pinning (9, CI). |

## Residual risks / assumptions

- The KEK store (KMS/Vault) is trusted and correctly access-controlled. If it is breached,
  envelope encryption alone does not protect data — pair with KMS audit + least privilege.
- The baseline E2EE path (libsodium `crypto_box`) lacks forward secrecy; enable libsignal
  for high-risk messaging.
- Client endpoint compromise (malware on the user's device) is out of scope for this layer;
  addressed by the mobile defence modules and runtime monitoring.
- Cryptography protects data; it does not replace authorization — IDOR/access-control checks
  remain the Auth/RBAC + Privacy agents' responsibility.
