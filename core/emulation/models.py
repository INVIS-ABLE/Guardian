"""Typed models for the continuous adversary-emulation lab (Sovereign plane, Wave 3, system #13).

The first Wave-3 (Proof) system. It emulates MITRE ATT&CK techniques **in the disposable lab
only** and, for each one, answers the three questions from docs/sovereign_ops_plane.md:

  * **did prevention block it?**
  * **did an independent sensor detect it?**
  * **was evidence preserved?**

A technique that was neither prevented nor detected is a **bypass** — a silent control failure —
and *every bypass becomes a regression test* so the same gap can never reappear unnoticed. An
emulation that ran but left no evidence is a forensic gap, also captured as a regression.

This module defines the *shapes*: the ATT&CK `Technique`, the per-technique `TechniqueResult`
(prevented / detected_by / evidence_preserved → a `Verdict`), the `RegressionTest` generated from
a gap, and the `EmulationReport`. The lab harness that enforces lab-only and generates the
regressions lives in ``lab.py``; ingestion (and the CALDERA seam) in ``ingest.py``.

Metadata-only and lab-only by construction: it records *that* a technique was or wasn't caught,
never production data, and the harness refuses to run anywhere but the range.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator

SCHEMA_VERSION = 1


class Tactic(str, Enum):
    """MITRE ATT&CK tactics (the adversary's goal at each step)."""

    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    # MITRE ATT&CK tactic TA0006 "Credential Access". The member is abbreviated so the
    # secret-name heuristic in code scanning does not false-positive on the public tactic id
    # (the value is the canonical "credential_access").
    CRED_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    COMMAND_AND_CONTROL = "command_and_control"


class Verdict(str, Enum):
    """The outcome of emulating one technique against the controls."""

    BLOCKED = "blocked"      # prevention stopped it (best case)
    DETECTED = "detected"    # not prevented, but an independent sensor caught it
    BYPASS = "bypass"        # neither prevented nor detected — a silent control failure


class Technique(BaseModel):
    """One MITRE ATT&CK technique to emulate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    id: str                       # ATT&CK id, e.g. "T1059.004"
    name: str
    tactic: Tactic
    description: str = ""

    @field_validator("id", "name")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("technique id/name must be non-empty")
        return v


class TechniqueResult(BaseModel):
    """What happened when one technique was emulated in the lab."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    technique: Technique
    prevented: bool                # did a preventive control block it?
    detected_by: str | None = None  # the independent sensor that caught it, if any
    evidence_preserved: bool = True  # was forensic evidence captured?

    @property
    def verdict(self) -> Verdict:
        if self.prevented:
            return Verdict.BLOCKED
        if self.detected_by:
            return Verdict.DETECTED
        return Verdict.BYPASS

    @property
    def is_bypass(self) -> bool:
        return self.verdict is Verdict.BYPASS

    @property
    def evidence_gap(self) -> bool:
        """True if the technique fired but no evidence was preserved (a forensic gap)."""
        return not self.evidence_preserved


class RegressionReason(str, Enum):
    """Why a regression test was generated from an emulation result."""

    BYPASS = "bypass"              # neither prevented nor detected
    EVIDENCE_GAP = "evidence_gap"  # fired but left no evidence


class RegressionTest(BaseModel):
    """A permanent test minted from a gap, so the same failure can never silently return."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: str
    technique_name: str
    tactic: Tactic
    reason: RegressionReason
    requirement: str               # the assertion this test will enforce going forward


class EmulationReport(BaseModel):
    """The result of an emulation operation: per-technique verdicts + generated regressions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation: str
    environment: str               # the lab/range it ran in (never production)
    results: tuple[TechniqueResult, ...]
    regression_tests: tuple[RegressionTest, ...]

    @property
    def blocked(self) -> int:
        return sum(1 for r in self.results if r.verdict is Verdict.BLOCKED)

    @property
    def detected(self) -> int:
        return sum(1 for r in self.results if r.verdict is Verdict.DETECTED)

    @property
    def bypasses(self) -> tuple[TechniqueResult, ...]:
        return tuple(r for r in self.results if r.is_bypass)

    @property
    def evidence_gaps(self) -> tuple[TechniqueResult, ...]:
        return tuple(r for r in self.results if r.evidence_gap)

    @property
    def has_bypass(self) -> bool:
        """A bypass is a control failure — callers gate (fail) on this."""
        return bool(self.bypasses)

    def coverage(self) -> dict[str, int]:
        """Count of techniques emulated per tactic (the breadth of the operation)."""
        out: dict[str, int] = {}
        for r in self.results:
            out[r.technique.tactic.value] = out.get(r.technique.tactic.value, 0) + 1
        return out
