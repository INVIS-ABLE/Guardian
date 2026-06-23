"""Typed models for the cryptographic protocol proof lab (Sovereign plane, Wave 3, system #15).

Symbolic verification of the *protocols* that protect INVISABLE — device enrolment, key
agreement, group membership, forward secrecy, account recovery — answering "does this flow keep
its security property against an active attacker?" (docs/sovereign_ops_plane.md; upstream:
Tamarin / Verifpal / ProVerif).

The cardinal rule is the privacy boundary, stated as strongly as anywhere in Guardian: the lab
reviews the crypto **system**, **never plaintext or key material**. These models describe
protocols, the properties claimed of them, and proof outcomes — when a property is *falsified*
the result carries the symbolic **attack trace** (a sequence of abstract steps), never a real
message or key.

Shapes only: the `Protocol`, the `PropertyKind` vocabulary, the `ProofResult` (proved /
falsified / unknown, with an attack trace when falsified) and the `ProofReport`. The lab engine
lives in ``lab.py``.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator

SCHEMA_VERSION = 1

# Tokens that would betray real content/keys leaking into a symbolic model. A proof artefact is
# about abstract terms only; these never belong in a trace step or property.
_FORBIDDEN_TOKENS = ("plaintext", "private_key", "secret_key", "decryption_key", "message_body")


def _refuse_content(text: str) -> str:
    low = text.lower()
    for token in _FORBIDDEN_TOKENS:
        if token in low:
            raise ValueError(
                f"crypto-proof artefacts are symbolic only — '{token}' suggests real content/key "
                "material, which never enters the proof lab (it reviews the system, not secrets)"
            )
    return text


class PropertyKind(str, Enum):
    """The security properties a protocol flow can be asked to keep."""

    SECRECY = "secrecy"                       # the attacker never learns the abstract secret term
    AUTHENTICATION = "authentication"         # peers agree on who they're talking to
    INTEGRITY = "integrity"                   # messages can't be undetectably altered
    FORWARD_SECRECY = "forward_secrecy"       # past sessions stay safe after a key compromise
    POST_COMPROMISE = "post_compromise"       # sessions heal after compromise (PCS)
    AGREEMENT = "agreement"                   # both sides agree on the session/group state
    RECOVERY_SOUNDNESS = "recovery_soundness"  # account recovery can't be abused to impersonate


class ProofStatus(str, Enum):
    """The outcome of attempting to prove one property."""

    PROVED = "proved"          # holds against the modelled attacker
    FALSIFIED = "falsified"    # an attack exists (trace attached)
    UNKNOWN = "unknown"        # the prover did not terminate / is inconclusive


class Protocol(BaseModel):
    """A protocol flow under symbolic review."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    id: str                       # e.g. "proto:device-enrolment"
    name: str
    prover: str = "tamarin"       # the symbolic prover used

    @field_validator("id", "name")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("protocol id/name must be non-empty")
        return v


class SecurityProperty(BaseModel):
    """A claimed property of a protocol — what the proof must establish."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: PropertyKind
    description: str
    critical: bool = True         # a falsified critical property fails the gate

    @field_validator("description")
    @classmethod
    def _symbolic_only(cls, v: str) -> str:
        return _refuse_content(v)


class ProofResult(BaseModel):
    """The result of proving one property of one protocol."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_id: str
    property: SecurityProperty
    status: ProofStatus
    attack_trace: tuple[str, ...] = ()  # symbolic steps, present only when falsified

    @field_validator("attack_trace")
    @classmethod
    def _symbolic_trace(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for step in v:
            _refuse_content(step)
        return v

    @property
    def is_break(self) -> bool:
        """A falsified *critical* property is a real protocol break."""
        return self.status is ProofStatus.FALSIFIED and self.property.critical


class ProofReport(BaseModel):
    """The outcome of a proof run over a protocol's properties."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocols: tuple[Protocol, ...]
    results: tuple[ProofResult, ...]

    @property
    def breaks(self) -> tuple[ProofResult, ...]:
        return tuple(r for r in self.results if r.is_break)

    @property
    def unknowns(self) -> tuple[ProofResult, ...]:
        return tuple(r for r in self.results if r.status is ProofStatus.UNKNOWN)

    @property
    def has_break(self) -> bool:
        """A falsified critical property — callers gate (fail) on this."""
        return bool(self.breaks)

    def proved(self) -> int:
        return sum(1 for r in self.results if r.status is ProofStatus.PROVED)
