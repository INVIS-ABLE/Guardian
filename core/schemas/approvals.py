"""Approval record schema (Final Power-Up §23).

This is the durable *record* of a human approval decision — who approved what, when, the
approval packet, the blast radius shown to the reviewer, and the binding fields. It is
distinct from ``core.policy_gate.ApprovalLite``, which is the runtime *capability* the
policy engine evaluates; an :class:`Approval` record can be projected to that capability
via :meth:`binding`. Keeping them separate preserves one owner per concern: the policy
gate owns enforcement, this schema owns the auditable record.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = 1


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Approval(BaseModel):
    """An auditable record of an approval decision for a specific change."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    approval_id: UUID = Field(default_factory=uuid4)
    case_id: UUID
    action: str = Field(min_length=1)
    approvers: tuple[str, ...] = ()
    required_approvers: int = Field(ge=1, default=1)
    granted: bool = False
    rationale: str = ""
    blast_radius: str = ""
    packet_ref: str = ""
    requested_at: datetime = Field(default_factory=_utcnow)
    decided_at: datetime | None = None
    expires_at: datetime | None = None
    # Binding fields — the approval is for this exact change, not the action in the abstract.
    target: str | None = None
    commit: str | None = None
    workflow_run: str | None = None

    def is_satisfied(self) -> bool:
        """True when granted and the required number of distinct approvers signed off."""
        return self.granted and len(set(self.approvers)) >= self.required_approvers

    def binding(self) -> dict[str, str | None]:
        """The binding fields a policy capability (ApprovalLite) would enforce."""
        return {"target": self.target, "commit": self.commit, "workflow_run": self.workflow_run}


__all__ = ["Approval", "SCHEMA_VERSION"]
