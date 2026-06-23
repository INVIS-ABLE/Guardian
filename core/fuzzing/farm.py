"""The fuzzing-farm engine (Sovereign plane, Wave 3, system #14).

``FuzzFarm`` turns raw fuzzer output into durable knowledge. Given a campaign's crash
observations, it:

  * **dedupes by crash signature** — a thousand inputs that hit the same bug are one
    ``UniqueCrash`` (keeping the highest severity seen and the first/seed input hash);
  * **mints a regression seed** for every unique crash, so the bug can never silently return;
  * reports breadth (crashes per target) and whether the campaign found any new crash (the gate
    signal).

It runs nothing and asserts no authority — it adjudicates results a fuzzing engine produced, and
references crash inputs by hash only (never the bytes), so a malicious corpus entry never becomes
content.
"""

from __future__ import annotations

from typing import Iterable

from .models import (
    CrashObservation,
    FuzzReport,
    FuzzTarget,
    RegressionSeed,
    Severity,
    UniqueCrash,
)

_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


class FuzzError(ValueError):
    """Raised on structural errors (crash references an unknown target, empty campaign name)."""


class FuzzFarm:
    """Adjudicates a fuzzing campaign: dedup crashes and mint regression seeds."""

    def __init__(self, targets: Iterable[FuzzTarget]) -> None:
        self._targets: dict[str, FuzzTarget] = {}
        for t in targets:
            if t.id in self._targets:
                raise FuzzError(f"duplicate fuzz target: {t.id}")
            self._targets[t.id] = t

    def report(self, campaign: str, observations: Iterable[CrashObservation]) -> FuzzReport:
        """Dedup observations by signature and mint a regression seed per unique crash."""
        if not campaign or not campaign.strip():
            raise FuzzError("campaign name must be non-empty")

        materialised = tuple(observations)
        for o in materialised:
            if o.target_id not in self._targets:
                raise FuzzError(f"crash references unknown target: {o.target_id}")

        # Dedup by (target, signature): keep the highest severity seen, count occurrences, and
        # remember the first input hash as the regression seed.
        grouped: dict[tuple[str, str], UniqueCrash] = {}
        for o in materialised:
            key = (o.target_id, o.signature)
            existing = grouped.get(key)
            if existing is None:
                grouped[key] = UniqueCrash(
                    target_id=o.target_id, signature=o.signature, kind=o.kind,
                    severity=o.severity, occurrences=1, seed_hash=o.input_hash,
                )
            else:
                worst = max(existing.severity, o.severity, key=lambda s: _SEVERITY_RANK[s])
                grouped[key] = existing.model_copy(update={
                    "occurrences": existing.occurrences + 1, "severity": worst,
                })

        unique = tuple(sorted(
            grouped.values(),
            key=lambda c: (-_SEVERITY_RANK[c.severity], c.target_id, c.signature),
        ))
        seeds = tuple(
            RegressionSeed(
                target_id=c.target_id, signature=c.signature, seed_hash=c.seed_hash,
                requirement=f"{self._targets[c.target_id].surface} must not {c.kind.value} on "
                            f"seed {c.seed_hash[:12]} (signature {c.signature[:12]})",
            )
            for c in unique
        )
        return FuzzReport(
            campaign=campaign, targets=tuple(self._targets.values()),
            unique_crashes=unique, regression_seeds=seeds, observations=len(materialised),
        )
