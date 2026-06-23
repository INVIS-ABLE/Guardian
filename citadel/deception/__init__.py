"""Citadel System 30 — Deception and Tripwire Grid (Wave 30).

Plant honeytokens/decoys that hold no real privilege or data; a trigger yields signed evidence and
routes an alert; deception credentials can never authenticate to production; expired assets are
removed. Owner: OpenCanary/Canarytokens (production). Independent verifier: ``evidence.py``.
"""

from __future__ import annotations

from .evidence import (
    TriggerEvidence,
    deny_production_auth,
    record_trigger,
    verify_trigger,
)
from .registry import (
    DeceptionAsset,
    DeceptionKind,
    DeceptionRegistry,
    new_honeytoken,
)

__all__ = [
    "TriggerEvidence", "deny_production_auth", "record_trigger", "verify_trigger",
    "DeceptionAsset", "DeceptionKind", "DeceptionRegistry", "new_honeytoken",
]
