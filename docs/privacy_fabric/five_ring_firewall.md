# Five-ring firewall architecture

There is no single "best firewall." The strongest result comes from **several independent
enforcement layers**, so that defeating one does not defeat the system. Each ring is
operated, configured, and monitored independently.

```
Internet
  │
  ▼  Ring 1 — Global edge defence  (Anycast DDoS + WAF + bot mgmt)
  │  mTLS
  ▼  Ring 2 — Locked origin        (edge-only mTLS, hidden origin, no public infra)
  │
  ▼  Ring 3 — API/app firewall      (Envoy Gateway → Coraza + OWASP CRS)
  │
  ▼  Ring 4 — Zero-trust service    (Cilium default-deny, identity policy, wg encryption)
  │
  ▼  Ring 5 — Runtime containment   (Tetragon enforce + Falco detect + gVisor sandbox)
  │
  ▼  Application services
```

> Guardian **monitors and proposes** changes to these rings (PRs, evidence, anomaly
> alerts). It does not silently reconfigure production, and none of these rings give it
> access to decrypted content — they carry **ciphertext only**.

## Ring 1 — Global edge defence

Every public endpoint sits behind one major Anycast security edge (Cloudflare, Akamai, or
the native cloud equivalent). No direct public access to the origin.

- Network-, transport-, and HTTP-layer DDoS mitigation (separate systems, not one knob).
- Managed WAF rules; bot and credential-stuffing protection.
- API schema validation; per-user, per-device, per-route rate limits.
- TLS 1.3; HSTS; DNSSEC; restrictive CAA records; automated certificate rotation.
- Separate controls for API, media, WebSocket, and authentication traffic.
- Emergency global rate limiting; geo-controls only where genuinely justified.

## Ring 2 — Locked origin

Even if someone learns the origin address, they must not be able to talk to it.

- Edge-to-origin **mutual TLS**; origin firewall allowlists; rotating origin certificates.
- Private load balancers; hidden origin addresses.
- No public Kubernetes nodes; no public databases, queues, observability, or admin panels.
- Administrative access only via an **identity-aware gateway** with passkeys / hardware keys.

## Ring 3 — API and application firewall

A second, independent barrier inside the perimeter — not a duplicate of every edge rule.

```
Managed edge → Envoy Gateway → Coraza + OWASP Core Rule Set → Application services
```

- Explicit route allowlists; strict JSON/Protobuf schemas; maximum body sizes.
- WebSocket connection/message limits; upload decompression limits; content-type enforcement.
- Request deadlines; replay protection; signed webhooks; idempotency keys; SSRF protection.
- Separate authentication vs messaging rate limits; device-bound session tokens.
- Risk-based step-up authentication.

## Ring 4 — Zero-trust service firewall (Cilium)

- Default-deny **ingress and egress**; identity-based service policies.
- Explicit DNS and destination allowlists; no general internet access from app workloads.
- Separate namespaces for identity, messaging, media, Guardian, and administration.
- Transparent **WireGuard/IPsec** encryption between workloads; SPIFFE/SPIRE identities.
- Mutual authentication for high-value services; Hubble network-flow monitoring.

> Do not rely on Cilium beta features as the *only* production boundary until they pass
> your own testing.

## Ring 5 — Runtime containment

- **Tetragon** (eBPF) for process/file/syscall/network enforcement; **Falco** as an
  independent detection layer; **gVisor** for untrusted scanners and uploaded content.
- Read-only containers; non-root users; dropped Linux capabilities; seccomp + AppArmor.
- Immutable deployments; no Docker socket; no host mounts.
- Per-service CPU/memory/process/disk limits.
- Suricata/Zeek at controlled network chokepoints — not blindly on every connection.

## Why five rings

| Threat | Stopped primarily at |
| ------ | -------------------- |
| Volumetric / L7 DDoS | Ring 1 |
| Origin discovery + direct hit | Ring 2 |
| App-layer injection / abuse | Ring 3 |
| Lateral movement after a foothold | Ring 4 |
| Container escape / malicious upload | Ring 5 |

Mapping to Guardian's monitoring scope lives in
[`policies/privacy_invariants.yaml`](../../policies/privacy_invariants.yaml) under
`guardian_may_monitor`.
