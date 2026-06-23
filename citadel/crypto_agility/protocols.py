"""Protocol inventory (Citadel System 23).

Tracks negotiated protocol versions (TLS, SSH, …) and flags deprecated/forbidden versions so a
weak protocol cannot quietly remain in service.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Minimum acceptable versions; anything below is a finding.
_MIN_VERSIONS = {"tls": (1, 2), "ssh": (2, 0)}
_FORBIDDEN = {"tls": {(1, 0), (1, 1)}, "ssl": {(3, 0)}}


@dataclass(frozen=True)
class ProtocolUse:
    protocol: str          # "tls", "ssh", "ssl"
    version: tuple[int, int]
    endpoint: str = ""


@dataclass
class ProtocolInventory:
    uses: list[ProtocolUse] = field(default_factory=list)

    def register(self, use: ProtocolUse) -> None:
        self.uses.append(use)

    def findings(self) -> list[str]:
        out: list[str] = []
        for u in self.uses:
            proto = u.protocol.lower()
            if u.version in _FORBIDDEN.get(proto, set()):
                out.append(f"{u.endpoint or proto}: forbidden {proto} {u.version[0]}.{u.version[1]}")
            elif proto in _MIN_VERSIONS and u.version < _MIN_VERSIONS[proto]:
                out.append(f"{u.endpoint or proto}: {proto} below minimum version")
        return out


__all__ = ["ProtocolUse", "ProtocolInventory"]
