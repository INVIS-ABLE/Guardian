# Data Classification

> Status: draft — owner TBD. Part of Guardian governance (docs/governance/).

Classes and handling rules. Default to the most protective class on doubt.

- PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED (real-user PII / health / safeguarding)
- RESTRICTED never reaches models, scanners, logs, or non-prod without a dual-approval broker
- Field-level encryption + tokenisation for RESTRICTED (security/crypto/fieldEncryption.ts)
- DLP (Presidio) at model in/out, scanner output, evidence, logs, exports (area 13)
- Retention expiry, legal hold, subject-access & deletion workflows
