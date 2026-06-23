"""Typed models for the continuous fuzzing farm (Sovereign plane, Wave 3, system #14).

CI fuzzing of the security-critical parsers — crypto envelopes, attachments, tokens, evidence
formats — so a crash is found by Guardian in the lab before an attacker finds it in production
(docs/sovereign_ops_plane.md; upstream: ClusterFuzzLite / AFL++ / Atheris / Jazzer / Schemathesis).

The engine's job is to turn a noisy stream of fuzzer crashes into durable knowledge: **dedupe by
crash signature** (a thousand inputs that hit the same bug are one finding), classify each unique
crash, and **mint a regression seed for every new one** so the same crash can never silently
return. Crash *inputs* are referenced by hash only — never inlined — so the farm stays metadata-
only and a malicious corpus entry never becomes content the model ingests.

Shapes only: the `FuzzTarget`, the per-crash `CrashKind`, the deduped `UniqueCrash`, the
`RegressionSeed` minted from it, and the `FuzzReport`. The farm engine lives in ``farm.py``.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator

SCHEMA_VERSION = 1


class CrashKind(str, Enum):
    """The class of failure a fuzz input provoked."""

    CRASH = "crash"              # segfault / uncaught exception
    ASSERTION = "assertion"      # an invariant check fired
    TIMEOUT = "timeout"          # input caused a hang
    OOM = "oom"                  # out-of-memory
    LEAK = "leak"                # memory / resource leak
    UB = "undefined_behaviour"   # sanitizer-detected UB


class Severity(str, Enum):
    """Triage severity of a unique crash."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FuzzTarget(BaseModel):
    """A harness fuzzing one security-critical surface (a parser / decoder / verifier)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    id: str                       # e.g. "fuzz:crypto-envelope"
    name: str
    surface: str                  # what it parses, e.g. "crypto_envelope" | "attachment" | "token"
    engine: str = "atheris"       # the fuzzing engine driving it

    @field_validator("id", "name", "surface")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("target id/name/surface must be non-empty")
        return v


class CrashObservation(BaseModel):
    """One observed crash from a campaign — input referenced by hash, never inlined."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: str
    signature: str                # dedup key: stack/bug hash (many inputs → one signature)
    kind: CrashKind
    input_hash: str               # sha256 of the crashing input (the corpus reference)
    severity: Severity = Severity.MEDIUM

    @field_validator("target_id", "signature", "input_hash")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("crash target_id/signature/input_hash must be non-empty")
        return v


class UniqueCrash(BaseModel):
    """A deduplicated crash: one bug, however many inputs reached it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: str
    signature: str
    kind: CrashKind
    severity: Severity
    occurrences: int              # how many observations collapsed into this one bug
    seed_hash: str                # the first (smallest-seen) input hash — the regression seed


class RegressionSeed(BaseModel):
    """A corpus seed + assertion minted from a unique crash, so the bug stays fixed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: str
    signature: str
    seed_hash: str
    requirement: str              # what the regression test will assert going forward


class FuzzReport(BaseModel):
    """The outcome of a fuzzing campaign: deduped crashes + the regression seeds minted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    campaign: str
    targets: tuple[FuzzTarget, ...]
    unique_crashes: tuple[UniqueCrash, ...]
    regression_seeds: tuple[RegressionSeed, ...]
    observations: int             # total raw crashes seen before dedup

    @property
    def has_new_crash(self) -> bool:
        """Any unique crash is a control gap — callers gate (fail CI) on this."""
        return bool(self.unique_crashes)

    def of_severity(self, *severities: Severity) -> tuple[UniqueCrash, ...]:
        wanted = set(severities)
        return tuple(c for c in self.unique_crashes if c.severity in wanted)

    def by_target(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for c in self.unique_crashes:
            out[c.target_id] = out.get(c.target_id, 0) + 1
        return out
