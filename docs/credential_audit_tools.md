# Credential-Audit Tools — Authorised Defensive Use Only

Guardian integrates three well-known credential tools **strictly for defensive
auditing** of INVISABLE-owned auth controls. They are dual-use; Guardian constrains
them so they can only ever be used to *strengthen* INVISABLE systems, never to attack
third parties or steal credentials.

| Tool | Role in Guardian | Upstream |
| ---- | ---------------- | -------- |
| **hashcat** | Offline **password-policy strength audit** against a synthetic/consented test corpus — confirms weak/breached passwords are rejected and the policy resists offline cracking. | https://github.com/hashcat/hashcat |
| **John the Ripper** | Same offline password-policy strength audit (alternative engine). | https://github.com/openwall/john |
| **THC Hydra** | **Online login-defence resilience** check on owned staging with a test account — confirms rate limiting, lockout, and MFA contain credential-stuffing / password-spray. | https://github.com/vanhauser-thc/thc-hydra |

Connectors: `connectors/credential_audit.py` (`HashcatConnector`, `JohnConnector`,
`HydraConnector`).

## Guardrails applied (non-negotiable)

- **Owned only** — `assert_owned` restricts targets to in-scope INVISABLE domains/repos.
- **Test accounts only** — `assert_test_account`; Hydra refuses without a registered
  test account. Guardian never targets real users.
- **No real credentials** — hashcat/john refuse unless given an explicit
  `hash_corpus` flagged `synthetic=True`. Real user password hashes are never audited.
  `real_user_data_access` and `credential_theft` remain globally blocked.
- **Human approval required** — `credential_audit` is in `GLOBAL_APPROVAL_REQUIRED`;
  Hydra additionally asserts `high_volume_test` **and** `account_locking_test` approvals.
- **Controlled volume** — Hydra runs low task counts / small candidate lists so the test
  trips the defence rather than generating uncontrolled load.
- **No secrets recorded** — recovered plaintext is never written to evidence; only
  policy verdicts and counts are reported (and run through the secret scrubber).
- **Dry-run by default** — like every connector.

## Intended outcome

A **PASS** is when the defence wins: weak passwords are rejected (policy resists the
offline audit) and online attempts are stopped by rate limiting / lockout / MFA. These
tools exist to prove those protections hold for vulnerable users — not to break them.

## How they map

- `password_policy_strength` simulator → hashcat / john
- `login_defence_resilience` simulator → hydra
- Both align with OWASP ASVS V2 (Authentication) and the
  credential-stuffing / password-spray entries in the defensive simulator library.
