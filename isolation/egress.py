"""Default-deny egress control (Phase 3 / blueprint area 7).

Outbound traffic is as dangerous as inbound for an AI agent: instructions in a malicious
document must not become a data-exfiltration request. This policy is **default-deny** with an
explicit allowlist, and always blocks the cloud metadata service, loopback, link-local, and
private ranges (unless explicitly permitted). The destination is resolved to an IP and the IP
is checked — defeating DNS-rebinding tricks (resolve immediately before connect, check the IP).

In deployment, Cilium network policy + an authenticated egress gateway enforce this at the
network layer; this module is the in-process decision used by connectors before any outbound
call.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

# Cloud metadata endpoints (AWS/GCP/Azure/OpenStack) — always blocked.
METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254"})


@dataclass
class EgressDecision:
    allow: bool
    reason: str


@dataclass
class EgressPolicy:
    allowed_hosts: set[str] = field(default_factory=set)  # exact hostnames
    allowed_cidrs: list[str] = field(default_factory=list)  # e.g. ["140.82.112.0/20"]
    allow_private: bool = False  # only when a job legitimately needs an internal endpoint
    default_deny: bool = True

    def _cidrs(self) -> list[ipaddress._BaseNetwork]:
        return [ipaddress.ip_network(c, strict=False) for c in self.allowed_cidrs]

    def decide(self, destination: str) -> EgressDecision:
        """Decide for a hostname or a (resolved) IP literal."""
        ip = _as_ip(destination)
        if ip is not None:
            if destination in METADATA_IPS or str(ip) in METADATA_IPS:
                return EgressDecision(False, "blocked: cloud metadata endpoint")
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
                return EgressDecision(False, "blocked: loopback/link-local/reserved range")
            if ip.is_private and not self.allow_private:
                return EgressDecision(False, "blocked: private range")
            for net in self._cidrs():
                if ip in net:
                    return EgressDecision(True, f"allowed: matches {net}")
            return EgressDecision(False, "denied: not in egress allowlist")
        # Hostname path (must still be resolved + IP-checked before connecting).
        if destination in self.allowed_hosts:
            return EgressDecision(True, "allowed: host on allowlist")
        return EgressDecision(False, "denied: host not on allowlist")

    def allows(self, destination: str) -> bool:
        return self.decide(destination).allow


def _as_ip(value: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None
