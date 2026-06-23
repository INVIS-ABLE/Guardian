"""Guardian Crown Citadel — the high-assurance plane beneath Brain V2 + the Sovereign plane.

The Citadel adds PROOF, not authority (docs/citadel_plane.md). Each subsystem reuses an existing
authoritative owner and adds one independently implemented verifier; no subsystem grants authority.
Wave 21 lands the first runtime slice: ``citadel.root_of_trust`` (Hardware root of trust).
"""

from __future__ import annotations

__all__ = ["root_of_trust"]
