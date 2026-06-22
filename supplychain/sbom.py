"""SBOM, VEX exploitability, and risk-based prioritisation (Phase 4 / blueprint area 17).

Prioritise vulnerabilities by *real* risk, not raw CVSS: combine asset exposure, runtime
reachability, CISA KEV status, EPSS probability, user-safety impact, and OpenVEX exploitability
("package present" ≠ "actually exploitable in this product"). DependencyTrack + GUAC + OpenVEX
are the deployment systems; this is the in-process scoring used to set remediation deadlines.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class VexStatus(str, Enum):
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


@dataclass
class Vulnerability:
    id: str  # e.g. CVE-2026-1234
    package: str
    severity: str  # low|medium|high|critical
    cvss: float = 0.0


@dataclass
class VexStatement:
    vuln_id: str
    status: VexStatus
    justification: str = ""


@dataclass
class RiskContext:
    internet_exposed: bool = False
    runtime_loaded: bool = True  # is the vulnerable component actually loaded/reachable?
    kev: bool = False  # CISA Known Exploited Vulnerabilities
    epss: float = 0.0  # 0..1 exploit probability
    user_safety_impact: bool = False  # affects vulnerable-user safety
    compensating_controls: bool = False


@dataclass
class Prioritisation:
    vuln_id: str
    score: float
    tier: str  # critical|high|medium|low|info
    remediation_days: int
    exploitable: bool


# Remediation SLAs (days) per tier.
_SLA = {"critical": 1, "high": 7, "medium": 30, "low": 90, "info": 180}


def is_exploitable(vuln_id: str, vex: list[VexStatement]) -> bool:
    """OpenVEX: NOT_AFFECTED/FIXED are not exploitable; AFFECTED/UNDER_INVESTIGATION are (conservative)."""
    statuses = [v.status for v in vex if v.vuln_id == vuln_id]
    if not statuses:
        return True  # no statement → assume exploitable until triaged
    # If any statement clears it AND none mark it affected, treat as not exploitable.
    if any(s in (VexStatus.NOT_AFFECTED, VexStatus.FIXED) for s in statuses) and not any(
        s == VexStatus.AFFECTED for s in statuses
    ):
        return False
    return True


def prioritise(
    vuln: Vulnerability, ctx: RiskContext, vex: list[VexStatement] | None = None
) -> Prioritisation:
    """Risk-based score → tier → remediation deadline."""
    vex = vex or []
    exploitable = is_exploitable(vuln.id, vex)

    base = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 2.0}.get(vuln.severity.lower(), 3.0)
    score = base
    if not exploitable or not ctx.runtime_loaded:
        score *= 0.3  # not reachable / not exploitable → strongly de-prioritised
    if ctx.kev:
        score += 3.0  # known exploited in the wild
    score += 2.0 * ctx.epss
    if ctx.internet_exposed:
        score += 1.5
    if ctx.user_safety_impact:
        score += 2.0
    if ctx.compensating_controls:
        score -= 1.0
    score = max(0.0, round(score, 2))

    if score >= 10:
        tier = "critical"
    elif score >= 7:
        tier = "high"
    elif score >= 4:
        tier = "medium"
    elif score > 0:
        tier = "low"
    else:
        tier = "info"

    return Prioritisation(
        vuln_id=vuln.id,
        score=score,
        tier=tier,
        remediation_days=_SLA[tier],
        exploitable=exploitable,
    )
