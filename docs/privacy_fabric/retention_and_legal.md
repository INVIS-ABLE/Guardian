# Retention classes & legal architecture

"Leave no residue" is meaningless as a vague promise. It is defined here as **enforced
retention classes** plus the UK-GDPR work that must complete before production.

## Retention classes (defined and enforced)

### Message contents
- Server holds **ciphertext only**.
- Deleted after acknowledged delivery or expiry (depending on multi-device needs).
- Disappearing-message timers enforced by clients, supported by server-side expiry.
- Users are told plainly that recipients may still copy or photograph content.

### Undelivered content
- Short maximum queue lifetime; automatic encrypted-object expiry; **no indefinite mailbox storage**.

### Network metadata
- No message content. Avoid long-lived source-IP storage; short operational-security retention.
- Pseudonymised/aggregated where possible; security records separate from user profiles;
  strictly controlled re-identification.

### Application logs
- No message bodies, encryption keys, usernames, emails, or phone numbers unless essential.
- Opaque correlation IDs; automated sensitive-data detection; short retention for detailed
  logs; longer **aggregate** security metrics only where necessary.

### Analytics
- **No Meta / advertising / cross-app tracking SDKs.** Prefer self-hosted aggregate analytics.
- Opt-in diagnostics; differential privacy on aggregate product statistics where practical.
- **Never** use private conversations to train Guardian or any model
  (enforced: `train_on_user_content` is a globally blocked action).

These classes align with the existing data classification in
[../governance/DATA_CLASSIFICATION.md](../governance/DATA_CLASSIFICATION.md) and key
management in [../governance/KEY_MANAGEMENT_PLAN.md](../governance/KEY_MANAGEMENT_PLAN.md).

## Legal architecture (UK GDPR)

Health information is **special-category personal data** under UK GDPR (Article 9) and
receives additional protection. Processing likely to create high risk requires a **DPIA**,
particularly where health or other special-category data is involved.

### Complete before production
- [ ] Full data inventory.
- [ ] Lawful-basis analysis.
- [ ] Article 9 condition analysis for health information.
- [ ] **DPIA**.
- [ ] Retention schedule (the classes above, with concrete durations).
- [ ] Safeguarding impact assessment.
- [ ] Threat model covering abusive partners, stalkers, hostile family members, and
      compromised devices (see [privacy threat model](#privacy-threat-model)).
- [ ] Procedures for data-subject rights and deletion.
- [ ] Processor and subprocessor contracts.
- [ ] International-transfer review.
- [ ] **ICO consultation** if high risks cannot be sufficiently mitigated.

### Children
If children may use the service: high-privacy defaults, private profiles, and restricted
stranger contact. The ICO Children's Code highlights high privacy by default and the
heightened risks of public profiles and unsolicited contact.

## Privacy threat model

The Privacy Fabric defends specifically against adversaries that ordinary security misses:

| Adversary | Primary defence |
| --------- | --------------- |
| Abusive partner / household member with device access | client app lock, hidden notifications, per-device revocation, rapid local deletion |
| Stalker attempting discovery/enumeration | pseudonymous IDs, no global directory, optional contact discovery, rate limits |
| Hostile administrator / insider | E2EE (no server plaintext), no master key, key transparency, privileged-activity monitoring |
| Compromised backend | ciphertext-only storage, sealed sender, Guardian boundary (no keys/plaintext) |
| Metadata correlation | sealed sender, two-hop relay, short-lived credentials, minimal retention |
| Social engineer | step-up auth, device-bound sessions, key-change warnings |

This extends — and must stay consistent with — [../governance/THREAT_MODEL.md](../governance/THREAT_MODEL.md)
and [../governance/TRUST_BOUNDARIES.md](../governance/TRUST_BOUNDARIES.md).
