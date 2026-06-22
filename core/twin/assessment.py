"""PR-time blast-radius assessment (Sovereign plane, Wave 2 toward system #12).

Turns the digital twin from a query tool into an active guardrail: given the assets a change
touches, compute what a compromise of each would *reach*, flag when it reaches sensitive sinks
(regulated data, encryption keys, data stores), and gate the change BEFORE it deploys — rather
than waiting for a scanner to find the resulting exposure afterwards (docs/digital_twin.md,
docs/sovereign_ops_plane.md).

This is a read-only analysis over the twin: it proposes a verdict, it does not authorise
anything. CI calls :func:`assess_change` (or ``guardian twin-assess``) and fails the job when
the result breaches a configured severity threshold.
"""

from __future__ import annotations

from enum import IntEnum

from pydantic import BaseModel, ConfigDict

from core.evidence.models import Classification

from .graph import DigitalTwin
from .models import AssetKind, AssetNode, ImpactStep


class Severity(IntEnum):
    """Ordered severity so thresholds compare with ``>=``."""

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_label(cls, label: str) -> "Severity":
        try:
            return cls[label.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity '{label}' (use {[s.label for s in cls]})") from exc


# Data-class sensitivity → severity (the regulated tiers drive the gate).
_CLASS_SEVERITY: dict[Classification, Severity] = {
    Classification.HEALTH: Severity.CRITICAL,
    Classification.PII: Severity.CRITICAL,
    Classification.RESTRICTED: Severity.CRITICAL,
    Classification.CONFIDENTIAL: Severity.HIGH,
    Classification.INTERNAL: Severity.MEDIUM,
    Classification.PUBLIC: Severity.LOW,
}


def _sink_severity(asset: AssetNode) -> tuple[Severity, str]:
    """Severity contribution of *reaching* this asset, and a human reason. NONE ⇒ not a sink."""
    if asset.kind == AssetKind.DATA_CLASS:
        sev = _CLASS_SEVERITY.get(asset.classification, Severity.MEDIUM)
        return sev, f"reaches {asset.classification.value} data class '{asset.name}'"
    if asset.kind == AssetKind.ENCRYPTION_KEY:
        return Severity.HIGH, f"reaches encryption key '{asset.name}'"
    if asset.kind == AssetKind.DATABASE:
        return Severity.MEDIUM, f"reaches data store '{asset.name}'"
    if asset.kind == AssetKind.QUEUE:
        return Severity.MEDIUM, f"reaches queue '{asset.name}'"
    if asset.kind == AssetKind.CERTIFICATE:
        return Severity.MEDIUM, f"reaches certificate '{asset.name}'"
    return Severity.NONE, ""


class SensitiveHit(BaseModel):
    """A sensitive asset reachable from a changed asset, with how it is reached."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    asset: AssetNode
    severity: Severity
    reason: str
    distance: int
    path: tuple[ImpactStep, ...]


class AssetAssessment(BaseModel):
    """The blast assessment of one changed asset."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    origin: AssetNode
    impacted_count: int
    severity: Severity
    hits: tuple[SensitiveHit, ...]


class BlastAssessment(BaseModel):
    """The combined assessment of every changed asset in a change set."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    assessments: tuple[AssetAssessment, ...]
    severity: Severity

    def breaches(self, threshold: Severity) -> bool:
        return self.severity >= threshold


def assess_change(
    twin: DigitalTwin,
    changed_ids: list[str],
    *,
    max_depth: int | None = None,
) -> BlastAssessment:
    """Assess what a compromise of each changed asset would reach in the twin.

    Unknown ids raise (via the twin) — a typo must not silently produce a clean bill of health.
    """
    assessments: list[AssetAssessment] = []
    overall = Severity.NONE
    for cid in changed_ids:
        radius = twin.blast_radius(cid, max_depth=max_depth)
        hits: list[SensitiveHit] = []
        worst = Severity.NONE
        for item in radius.impacted:
            sev, reason = _sink_severity(item.asset)
            if sev == Severity.NONE:
                continue
            hits.append(
                SensitiveHit(
                    asset=item.asset, severity=sev, reason=reason,
                    distance=item.distance, path=item.path,
                )
            )
            worst = max(worst, sev)
        hits.sort(key=lambda h: (-int(h.severity), h.distance, h.asset.id))
        assessments.append(
            AssetAssessment(
                origin=twin.asset(cid),
                impacted_count=len(radius.impacted),
                severity=worst,
                hits=tuple(hits),
            )
        )
        overall = max(overall, worst)
    return BlastAssessment(assessments=tuple(assessments), severity=overall)
