"""SLOs, error-budget burn, and the availability-vs-privacy safety gate (directive §9)."""

from .burn_rates import BurnResult, BurnSeverity, compute_burn
from .definitions import (
    PRIVACY_CRITICAL_KINDS,
    SLO,
    SLOKind,
    SLORegistry,
)
from .safety_gates import (
    EffectDirection,
    SafetyVerdict,
    evaluate_repair_safety,
)

__all__ = [
    "SLOKind",
    "SLO",
    "SLORegistry",
    "PRIVACY_CRITICAL_KINDS",
    "BurnSeverity",
    "BurnResult",
    "compute_burn",
    "EffectDirection",
    "SafetyVerdict",
    "evaluate_repair_safety",
]
