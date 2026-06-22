"""Guardian detection-as-code (blueprint area 19 / Phase 6).

Portable, version-controlled, ATT&CK-mapped detection rules + an engine that turns telemetry
events into detections and **recommended** reversible containment — which still passes the
deterministic containment adapter's human-approval/policy gates before anything happens.
"""

from __future__ import annotations

from .engine import DEFAULT_RULES_DIR, Detection, DetectionEngine
from .rules import Condition, DetectionRule, Response, load_rules, rule_from_dict

__all__ = [
    "DetectionEngine",
    "Detection",
    "DEFAULT_RULES_DIR",
    "DetectionRule",
    "Condition",
    "Response",
    "load_rules",
    "rule_from_dict",
]
