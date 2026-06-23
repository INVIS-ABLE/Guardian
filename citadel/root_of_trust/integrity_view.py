"""Platform-integrity view model — data for the PWA Trust Centre / Platform Integrity screen.

A pure projection of the inventory + recent attestations + drift events into a read-only summary
(no secrets, no private content). The dashboard renders this; tests assert it directly.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .inventory import PlatformInventory
from .schemas import DriftEvent, PlatformAttestation, PlatformStatus


def platform_integrity_summary(
    inventory: PlatformInventory,
    attestations: Iterable[PlatformAttestation] = (),
    drift_events: Iterable[DriftEvent] = (),
    *,
    now: float | None = None,
) -> dict[str, Any]:
    """Build the Platform Integrity screen's data: inventory counts, attestation freshness, drift."""
    platforms = inventory.all_platforms()
    by_status = {s.value: 0 for s in PlatformStatus}
    for p in platforms:
        by_status[p.status.value] += 1

    attestation_rows = [
        {
            "node_id": a.node_id,
            "ok": a.ok,
            "reasons": list(a.reasons),
            "attested_at": a.attested_at,
            "expires_at": a.expires_at,
            "expired": (now is not None and a.is_expired(now)),
            "evidence_digest": a.evidence_digest,
        }
        for a in attestations
    ]

    return {
        "total_platforms": len(platforms),
        "enrolled": by_status[PlatformStatus.ENROLLED.value],
        "quarantined": by_status[PlatformStatus.QUARANTINED.value],
        "revoked": by_status[PlatformStatus.REVOKED.value],
        "platforms": [
            {
                "node_id": p.node_id,
                "status": p.status.value,
                "attestation_max_age_seconds": p.attestation_max_age_seconds,
                "golden_pcr_count": len(p.golden_pcrs),
                "approved_firmware": sorted(p.approved_firmware),
                "approved_kernels": sorted(p.approved_kernels),
            }
            for p in platforms
        ],
        "attestations": attestation_rows,
        "drift_events": [
            {"node_id": d.node_id, "event_type": d.event_type,
             "reasons": list(d.reasons), "at": d.at, "detail": d.detail}
            for d in drift_events
        ],
    }


__all__ = ["platform_integrity_summary"]
