"""Remediation option + code change schemas (Final Power-Up §23).

A remediation is proposed, never auto-applied: each option carries its concrete code
changes, an independent risk/blast-radius assessment, the regression tests that must
pass, and an explicit rollback. The selected option still flows through approval and
independent verification before anything is applied.
"""

from __future__ import annotations

from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = 1

RemediationRisk = Literal["low", "medium", "high", "critical"]


class CodeChange(BaseModel):
    """A single file change within a remediation option (a reviewable unit diff)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1)
    language: str = ""
    diff: str = ""
    additions: int = Field(ge=0, default=0)
    deletions: int = Field(ge=0, default=0)


class RemediationOption(BaseModel):
    """One proposed fix with its changes, risk, tests and rollback (master map §23)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    option_id: UUID = Field(default_factory=uuid4)
    case_id: UUID
    finding_ids: tuple[str, ...] = ()
    title: str = Field(min_length=1, max_length=300)
    description: str = ""
    strategy: str = ""  # e.g. "patch" | "config" | "rotate-secret" | "dependency-bump"
    changes: tuple[CodeChange, ...] = ()
    risk: RemediationRisk = "medium"
    blast_radius: str = ""
    regression_tests: tuple[str, ...] = ()
    rollback: str = ""
    requires_feature_flag: bool = False
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)


__all__ = ["RemediationOption", "CodeChange", "RemediationRisk", "SCHEMA_VERSION"]
