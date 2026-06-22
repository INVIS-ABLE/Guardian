"""Detection engine (blueprint area 19 / Phase 6).

Evaluates telemetry events against detection-as-code rules and produces ATT&CK-mapped
``Detection`` results. A detection may carry a **recommended** reversible containment action —
but the engine never executes it. The recommendation is a ``ContainmentRequest`` that must
still pass the deterministic containment adapter (and its human-approval / policy gates) before
anything happens. Detect → recommend → (human/policy) → contain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from containment.actions import REVERSIBLE_ACTIONS
from containment.adapter import ContainmentRequest

from .rules import DetectionRule, load_rules

DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "rules"


@dataclass
class Detection:
    rule_id: str
    title: str
    severity: str
    attack: list[str]
    confidence: float
    event: dict[str, Any]
    recommended_action: str | None = None
    recommended_target: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "attack": self.attack,
            "confidence": self.confidence,
            "recommended_action": self.recommended_action,
            "recommended_target": self.recommended_target,
        }


@dataclass
class DetectionEngine:
    rules: list[DetectionRule] = field(default_factory=list)

    @classmethod
    def from_dir(cls, directory: str | Path = DEFAULT_RULES_DIR) -> "DetectionEngine":
        return cls(rules=load_rules(directory))

    def evaluate(self, event: dict[str, Any]) -> list[Detection]:
        """Return all detections that fire for this event."""
        out: list[Detection] = []
        for rule in self.rules:
            if not rule.matches(event):
                continue
            action = target = None
            if rule.response is not None:
                action = rule.response.action
                target = event.get(rule.response.target_field)
            out.append(
                Detection(
                    rule_id=rule.id, title=rule.title, severity=rule.severity,
                    attack=rule.attack, confidence=rule.confidence, event=event,
                    recommended_action=action,
                    recommended_target=str(target) if target is not None else None,
                )
            )
        return out

    @staticmethod
    def recommend_containment(detection: Detection) -> ContainmentRequest | None:
        """Build a (still-unexecuted) containment recommendation from a detection.

        The action must be a known reversible containment action and the target must be
        present; otherwise no recommendation is made (Guardian recommends, it does not act).
        """
        if detection.recommended_action is None or detection.recommended_target is None:
            return None
        if detection.recommended_action not in REVERSIBLE_ACTIONS:
            return None
        return ContainmentRequest(
            action=detection.recommended_action,
            target=detection.recommended_target,
            confidence=detection.confidence,
            evidence_ref=f"detection:{detection.rule_id}",
            actor="runtime_monitoring_agent",
        )
