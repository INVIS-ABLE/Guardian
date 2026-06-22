# Disaster Recovery Plan

> Status: draft — owner TBD. Part of Guardian governance (docs/governance/).

RPO/RTO and restore procedures (blueprint area 26).

- Defined RPO/RTO per service
- Immutable, isolated backups (restic + object-lock/WORM); separate keys & identities
- Restore order: OpenBao → immudb (verify) → Temporal → app state
- Quarterly full restore exercises with recorded evidence
- Ransomware / malicious-admin recovery scenarios
