"""Deterministic containment adapter (blueprint area 21 / Phase 6).

Guardian may *recommend* containment, but **no AI-generated command executes** — every order
passes this deterministic adapter, which validates each parameter against the action's fixed
schema. The adapter:

  - accepts only enumerated, reversible actions (never a raw command string);
  - enforces the action's confidence threshold and blast-radius cap;
  - requires a recorded human approval for high-impact actions;
  - consults the central policy (an injected `policy_check`, backed by OPA in deployment);
  - issues an order with an **exact target, expiry, and documented rollback**, and audits it;
  - tracks active orders so they can be rolled back and auto-expire.

A rejected order is audited too — Guardian records what it refused to do, not just what it did.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from time import time
from typing import Callable

from core.audit import AuditLog

from .actions import REVERSIBLE_ACTIONS, ContainmentAction


class ContainmentRejected(PermissionError):
    """Raised when a containment request fails deterministic validation or policy."""


@dataclass
class ContainmentRequest:
    action: str
    target: str  # exact target identifier (token id, pod name, indicator, …)
    confidence: float  # 0..1 detection confidence
    evidence_ref: str  # link to the finding/evidence that justifies this
    requested_ttl: int | None = None
    blast_radius: int = 1
    approval_token: str | None = None  # required for high-impact actions
    actor: str = "runtime_monitoring_agent"


@dataclass
class ContainmentOrder:
    order_id: str
    action: str
    target: str
    ttl_seconds: int
    issued_at: float
    expires_at: float
    rollback_procedure: str
    max_blast_radius: int
    confidence: float
    evidence_ref: str
    active: bool = True

    def is_expired(self, now: float | None = None) -> bool:
        now = time() if now is None else now
        return self.ttl_seconds > 0 and now >= self.expires_at


# A policy hook: returns True if the central authority permits this containment. Defaults to
# allow (deterministic validation still applies); deployment injects an OPA-backed check.
PolicyCheck = Callable[[ContainmentRequest, ContainmentAction], bool]


@dataclass
class DeterministicContainmentAdapter:
    audit: AuditLog = field(default_factory=AuditLog)
    policy_check: PolicyCheck | None = None
    _active: dict[str, ContainmentOrder] = field(default_factory=dict)

    def validate(self, req: ContainmentRequest) -> list[str]:
        """Deterministically validate every parameter. Returns violations ([] = valid)."""
        v: list[str] = []
        spec = REVERSIBLE_ACTIONS.get(req.action)
        if spec is None:
            # No free-form / AI-invented actions: not on the reversible allowlist.
            return [f"action '{req.action}' is not a pre-approved reversible action"]
        if not spec.reversible:
            v.append("action is not reversible")
        if not isinstance(req.target, str) or not req.target.strip():
            v.append("exact target is required")
        if not req.evidence_ref:
            v.append("evidence reference is required")
        if not (0.0 <= req.confidence <= 1.0):
            v.append("confidence must be in [0,1]")
        elif req.confidence < spec.min_confidence:
            v.append(f"confidence {req.confidence} below threshold {spec.min_confidence}")
        if req.blast_radius < 1:
            v.append("blast_radius must be >= 1")
        elif req.blast_radius > spec.max_blast_radius:
            v.append(f"blast radius {req.blast_radius} exceeds cap {spec.max_blast_radius}")
        if spec.requires_human_approval and not req.approval_token:
            v.append("a human approval token is required for this action")
        if req.requested_ttl is not None and req.requested_ttl < 0:
            v.append("requested_ttl must be >= 0")
        return v

    def issue(self, req: ContainmentRequest, *, now: float | None = None) -> ContainmentOrder:
        """Validate + policy-check, then issue an auditable, reversible order. Else reject."""
        now = time() if now is None else now
        spec = REVERSIBLE_ACTIONS.get(req.action)
        violations = self.validate(req)
        if violations:
            self._audit(req, "rejected", detail={"violations": violations})
            raise ContainmentRejected("; ".join(violations))
        assert spec is not None  # validate() guarantees this
        if self.policy_check is not None and not self.policy_check(req, spec):
            self._audit(req, "denied", detail={"reason": "policy"})
            raise ContainmentRejected("containment denied by policy")

        # TTL: requested value capped at the action's default ceiling.
        ttl = spec.default_ttl_seconds
        if req.requested_ttl is not None and (spec.default_ttl_seconds == 0 or req.requested_ttl <= spec.default_ttl_seconds):
            ttl = req.requested_ttl
        order = ContainmentOrder(
            order_id=secrets.token_hex(8),
            action=req.action,
            target=req.target,
            ttl_seconds=ttl,
            issued_at=now,
            expires_at=now + ttl,
            rollback_procedure=spec.rollback_procedure,
            max_blast_radius=spec.max_blast_radius,
            confidence=req.confidence,
            evidence_ref=req.evidence_ref,
        )
        self._active[order.order_id] = order
        self._audit(req, "issued", detail={"order_id": order.order_id, "ttl": ttl})
        return order

    def rollback(self, order_id: str) -> bool:
        """Reverse a containment order (every order is reversible by construction)."""
        order = self._active.get(order_id)
        if order is None or not order.active:
            return False
        order.active = False
        self.audit.record(
            "containment:rollback", actor="operator", decision="allowed",
            detail={"order_id": order_id, "action": order.action, "target": order.target},
        )
        return True

    def expire_due(self, now: float | None = None) -> list[str]:
        """Auto-expire orders past their TTL; returns the expired order ids."""
        now = time() if now is None else now
        expired = [oid for oid, o in self._active.items() if o.active and o.is_expired(now)]
        for oid in expired:
            self._active[oid].active = False
            self.audit.record(
                "containment:expired", actor="system", decision="allowed",
                detail={"order_id": oid},
            )
        return expired

    def active_orders(self) -> list[ContainmentOrder]:
        return [o for o in self._active.values() if o.active]

    def _audit(self, req: ContainmentRequest, decision: str, detail: dict) -> None:
        try:
            self.audit.record(
                f"containment:{req.action}", actor=req.actor, decision=decision,
                detail={"target": req.target, "confidence": req.confidence,
                        "evidence": req.evidence_ref, **detail},
            )
        except Exception:  # pragma: no cover - auditing must never crash enforcement
            pass
