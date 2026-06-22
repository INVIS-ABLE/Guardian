"""Detection-as-code rule model + loader (blueprint area 19 / Phase 6).

Portable, version-controlled detection rules (Sigma-inspired) with positive/negative tests,
ATT&CK technique mapping (defensive only), and a recommended **reversible** containment
response. Rules are data (`detection/rules/*.yaml`); the engine evaluates events against them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_OPS = ("equals", "contains", "in", "gte", "regex")


@dataclass(frozen=True)
class Condition:
    field: str
    op: str
    value: Any

    def matches(self, event: dict[str, Any]) -> bool:
        val = event.get(self.field)
        if self.op == "equals":
            return val == self.value
        if self.op == "contains":
            return isinstance(val, str) and isinstance(self.value, str) and self.value in val
        if self.op == "in":
            return val in self.value
        if self.op == "gte":
            return isinstance(val, (int, float)) and not isinstance(val, bool) and val >= self.value
        if self.op == "regex":
            return isinstance(val, str) and re.search(self.value, val) is not None
        return False


@dataclass(frozen=True)
class Response:
    action: str  # a reversible containment action name (containment.REVERSIBLE_ACTIONS)
    target_field: str  # which event field holds the exact target id


@dataclass
class DetectionRule:
    id: str
    title: str
    severity: str
    attack: list[str]  # ATT&CK technique ids, e.g. ["T1505.003"]
    confidence: float
    all_: list[Condition] = field(default_factory=list)
    any_: list[Condition] = field(default_factory=list)
    response: Response | None = None
    logsource: str = ""

    def matches(self, event: dict[str, Any]) -> bool:
        if self.all_ and not all(c.matches(event) for c in self.all_):
            return False
        if self.any_ and not any(c.matches(event) for c in self.any_):
            return False
        return bool(self.all_ or self.any_)


def _parse_condition(raw: dict[str, Any]) -> Condition:
    fld = raw.get("field")
    if not fld:
        raise ValueError(f"condition missing 'field': {raw}")
    for op in _OPS:
        if op in raw:
            return Condition(field=fld, op=op, value=raw[op])
    raise ValueError(f"condition has no known operator {(_OPS)}: {raw}")


def rule_from_dict(data: dict[str, Any]) -> DetectionRule:
    det = data.get("detection", {}) or {}
    all_ = [_parse_condition(c) for c in det.get("all", [])]
    any_ = [_parse_condition(c) for c in det.get("any", [])]
    if not all_ and not any_:
        raise ValueError(f"rule {data.get('id')} has no detection conditions")
    resp = None
    if data.get("response"):
        resp = Response(
            action=data["response"]["action"], target_field=data["response"]["target_field"]
        )
    conf = float(data.get("confidence", 0.5))
    if not (0.0 <= conf <= 1.0):
        raise ValueError(f"rule {data.get('id')} confidence out of range")
    return DetectionRule(
        id=data["id"],
        title=data.get("title", data["id"]),
        severity=data.get("severity", "medium"),
        attack=list(data.get("attack", [])),
        confidence=conf,
        all_=all_,
        any_=any_,
        response=resp,
        logsource=data.get("logsource", ""),
    )


def load_rules(directory: str | Path) -> list[DetectionRule]:
    d = Path(directory)
    rules = [rule_from_dict(yaml.safe_load(p.read_text(encoding="utf-8"))) for p in sorted(d.glob("*.yaml"))]
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate detection rule ids: {dupes}")
    return rules
