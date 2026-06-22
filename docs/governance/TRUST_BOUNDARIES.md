# Trust Boundaries

> Status: draft — owner TBD. Part of Guardian governance (docs/governance/).

The Guardian management plane must not share a trust boundary with the systems it protects (blueprint area 5).

- Separate: cloud accounts, clusters, networks, keys, identity realms, CI runners, backups, logging
- Management plane initiates narrowly-authorised work via controlled gateways only
- Protected apps cannot administer Guardian
- No environment trusted because it is 'internal' (zero trust)
- Boundary crossings: GitHub App, DNS challenge, OPA decision, egress gateway
