"""Autonomous threat-hunting engine — Sovereign system #11.

Guardian continuously generates and runs *defensive hunting hypotheses* over the awareness
graphs — impossible access paths, dormant privilege activation, data leaving its boundary,
single points of failure — and turns a validated hunt into a permanent detection
(docs/sovereign_ops_plane.md #11).

Every hunt here is, by construction:
  * **read-only** — it queries the graphs, it changes nothing;
  * **budgeted** — capped result count so a hunt can never flood;
  * **privacy-filtered** — it reasons over metadata (ids, classifications), never content;
  * **reproducible** — deterministic over the same graphs;
  * **promotable** — each result names the detection it should become.

A hunt is skipped (not failed) when its input graph is absent, so the same registry runs
against whatever awareness Guardian currently has.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from pydantic import BaseModel, ConfigDict

from core.evidence.models import Classification, Severity
from core.twin import DigitalTwin
from core.twin.forecast import chokepoint_ranking, default_sinks, default_sources

DEFAULT_BUDGET = 100

# Data classes that are "regulated" — reaching them from an entry point is high-signal.
_REGULATED = frozenset({Classification.HEALTH, Classification.PII, Classification.RESTRICTED})


class HuntResult(BaseModel):
    """The output of one hunt: what it found and the detection it should become."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hunt_id: str
    title: str
    severity: Severity
    hits: tuple[str, ...]                 # ids of the implicated assets/principals/fields
    detection: str                        # the permanent detection a validated hit should seed
    truncated: bool = False               # True if the budget capped the hit list


def _result(hunt_id, title, severity, hits, detection, budget) -> HuntResult | None:
    hits = tuple(dict.fromkeys(hits))
    if not hits:
        return None
    return HuntResult(
        hunt_id=hunt_id, title=title, severity=severity,
        hits=hits[:budget], detection=detection, truncated=len(hits) > budget,
    )


# --- twin hunts ---------------------------------------------------------------
def hunt_external_reaches_regulated(twin: DigitalTwin, *, budget: int = DEFAULT_BUDGET) -> HuntResult | None:
    """Entry-point identities whose compromise would reach regulated (health/PII) data."""
    sinks = {
        a.id for a in twin.assets()
        if a.kind.value == "data_class" and a.classification in _REGULATED
    }
    if not sinks:
        return None
    hits: list[str] = []
    for src in default_sources(twin):
        reached = set(twin.blast_radius(src).asset_ids()) & sinks
        if reached:
            hits.append(src)
    return _result("external_reaches_regulated", "Entry identity reaches regulated data",
                   "high", hits, "alert: new path from an external identity to health/PII data", budget)


def hunt_single_point_of_failure(twin: DigitalTwin, *, budget: int = DEFAULT_BUDGET,
                                 min_paths: int = 2) -> HuntResult | None:
    """Single nodes whose compromise cuts many attacker paths to sensitive sinks (SPOF)."""
    if not default_sinks(twin):
        return None
    chokes = [c for c in chokepoint_ranking(twin) if c.paths_cut >= min_paths]
    hits = [c.node for c in chokes]
    return _result("single_point_of_failure", "Single point of failure to crown jewels",
                   "medium", hits, "control-gap: add an independent control at this choke point", budget)


# --- identity hunts -----------------------------------------------------------
def hunt_dormant_sensitive(identity: Any, *, as_of: date | None = None, idle_days: int = 90,
                           budget: int = DEFAULT_BUDGET) -> HuntResult | None:
    """Dormant principals that still hold a sensitive grant (revoke candidates)."""
    ref = as_of or date.today()
    dormant = identity.dormant_privileges(as_of=ref, idle_days=idle_days, sensitive_only=True)
    hits = [d.principal.id for d in dormant]
    return _result("dormant_sensitive_identity", "Dormant identity holds sensitive privilege",
                   "medium", hits, "alert: sensitive grant held by an inactive principal", budget)


def hunt_privilege_escalation(identity: Any, *, budget: int = DEFAULT_BUDGET) -> HuntResult | None:
    """Principals that can acquire rights beyond their effective set (escalation seams)."""
    hits: list[str] = []
    for p in identity.principals():
        if any(ep.uses_escalation for ep in identity.escalation_paths(p.id)):
            hits.append(p.id)
    return _result("privilege_escalation_path", "Privilege-escalation path available",
                   "high", hits, "alert: principal can escalate to rights beyond its grants", budget)


# --- lineage hunts ------------------------------------------------------------
def hunt_boundary_violations(lineage: Any, *, budget: int = DEFAULT_BUDGET) -> HuntResult | None:
    """Fields holding data their boundary is not approved for."""
    hits = [v.field for v in lineage.boundary_violations()]
    return _result("data_outside_boundary", "Data outside its approved boundary",
                   "high", hits, "alert: classification not approved for this boundary", budget)


def hunt_retention_violations(lineage: Any, *, budget: int = DEFAULT_BUDGET) -> HuntResult | None:
    """Derived fields that would outlive an upstream deletion obligation."""
    hits = [v.field for v in lineage.retention_violations()]
    return _result("retention_violation", "Derived data outlives a deletion obligation",
                   "medium", hits, "alert: field retained past an upstream obligation", budget)


def run_hunts(
    *,
    twin: DigitalTwin | None = None,
    identity: Any | None = None,
    lineage: Any | None = None,
    as_of: date | None = None,
    budget: int = DEFAULT_BUDGET,
) -> tuple[HuntResult, ...]:
    """Run every hunt whose input graph is present. Returns only the hunts that found something."""
    results: list[HuntResult | None] = []
    if twin is not None:
        results.append(hunt_external_reaches_regulated(twin, budget=budget))
        results.append(hunt_single_point_of_failure(twin, budget=budget))
    if identity is not None:
        results.append(hunt_dormant_sensitive(identity, as_of=as_of, budget=budget))
        results.append(hunt_privilege_escalation(identity, budget=budget))
    if lineage is not None:
        results.append(hunt_boundary_violations(lineage, budget=budget))
        results.append(hunt_retention_violations(lineage, budget=budget))
    return tuple(r for r in results if r is not None)
