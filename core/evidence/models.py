"""Typed evidence-graph contracts — the claim-and-evidence backbone of the Brain.

Guardian's intelligence must reason from a *claim-and-evidence graph*, not a chat
transcript (target architecture §4). Every conclusion the Brain reaches has to be
traceable to original raw evidence, the tool that produced it, and the
analyst/model that interpreted it — and it must be possible to say "the evidence
is insufficient" rather than inventing a conclusion.

These are strict Pydantic v2 models:

* ``extra="forbid"``      — an unexpected field is a bug, not silently absorbed.
* ``frozen=True``         — evidence and conclusions are immutable; nodes return
                            *new* objects, they never mutate shared state in place.
* discriminated scalars   — enums and ``Literal`` rather than free strings.
* provenance everywhere    — every object can be traced to where it came from.
* trust + classification  — content carries its trust level and data class so the
                            context firewall (§8) can keep untrusted/tainted data
                            from ever becoming an instruction or trusted evidence.

This module is deliberately backend-free: it defines the *shapes*. Wiring these
into the reasoning graph, the knowledge graph and persistent stores comes later in
the build order; getting the contracts right first is build-order step 1.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from core.tenancy import INVISABLE_TENANT_ID

SCHEMA_VERSION = 1


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class _Frozen(BaseModel):
    """Base for every evidence object: strict, immutable, versioned."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION


# --- classification + trust ----------------------------------------------------
class Classification(str, Enum):
    """Data-classification label that must *propagate* through every transformation.

    The coarse tiers mirror docs/governance/DATA_CLASSIFICATION.md
    (PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED). ``PII``/``HEALTH`` are finer
    labels for the RESTRICTED tier; ``MESSAGE_PLAINTEXT`` and ``DECRYPTION_KEY`` are
    tracked so the privacy boundary can refuse to let them near a model or long-term
    memory (policy_gate BLOCKED_ACTIONS enforce the act; the label lets us detect and
    refuse *content* too).
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"  # real-user PII / health / safeguarding (governance tier)
    PII = "pii"
    HEALTH = "health"
    MESSAGE_PLAINTEXT = "message_plaintext"
    DECRYPTION_KEY = "decryption_key"


# Classifications that must never be sent to a model or written to trusted memory.
PRIVACY_FORBIDDEN: frozenset[Classification] = frozenset(
    {Classification.MESSAGE_PLAINTEXT, Classification.DECRYPTION_KEY}
)


class TrustLevel(str, Enum):
    """Context-firewall trust classes (target architecture §8).

    Ordered loosely from most to least authoritative. The firewall's core rule:
    instructions found inside UNTRUSTED_EVIDENCE / TOOL_OUTPUT / RETRIEVED_MEMORY /
    MODEL_GENERATED content are *data*, never commands, and a low-trust input can
    never silently be promoted to drive policy or another agent's instructions.
    """

    SYSTEM_POLICY = "system_policy"
    TRUSTED_CONFIG = "trusted_config"
    VERIFIED_EVIDENCE = "verified_evidence"
    UNTRUSTED_EVIDENCE = "untrusted_evidence"
    USER_INSTRUCTION = "user_instruction"
    TOOL_OUTPUT = "tool_output"
    RETRIEVED_MEMORY = "retrieved_memory"
    MODEL_GENERATED = "model_generated"


# Trust levels that may NOT, on their own, be treated as verified evidence.
_UNVERIFIED_TRUST: frozenset[TrustLevel] = frozenset(
    {
        TrustLevel.UNTRUSTED_EVIDENCE,
        TrustLevel.TOOL_OUTPUT,
        TrustLevel.RETRIEVED_MEMORY,
        TrustLevel.MODEL_GENERATED,
    }
)


class ValidationState(str, Enum):
    UNVALIDATED = "unvalidated"
    VALIDATED = "validated"
    REJECTED = "rejected"


# --- provenance ----------------------------------------------------------------
class Provenance(_Frozen):
    """Where a piece of evidence came from and how it was transformed.

    Every finding must be traceable to original raw evidence, the tool + version +
    digest that produced it, when it was acquired, the asset/commit it concerns, the
    parser that read it, its transformation history, and the analyst/model that
    interpreted it (target architecture §4).
    """

    tool: str
    tool_version: str | None = None
    tool_digest: str | None = None  # e.g. sha256 of the scanner image
    parser_version: str | None = None
    acquired_at: datetime = Field(default_factory=_utcnow)
    asset: str | None = None
    commit: str | None = None
    interpreted_by: str | None = None  # analyst id or model id (via the AI gateway)
    transformations: tuple[str, ...] = ()  # ordered history, e.g. ("sarif->finding",)


class AssetRef(_Frozen):
    """A reference into the security knowledge graph / digital twin (§5, §14)."""

    kind: str  # repo | commit | package | image | service | api | identity | ...
    identifier: str
    name: str | None = None


# --- evidence ------------------------------------------------------------------
class EvidenceItem(_Frozen):
    """One immutable piece of evidence with full provenance, trust and classification.

    The ``summary`` is a short human/model-readable description; ``source_hash`` and
    ``content_hash`` make the item content-addressable and tamper-evident. Raw
    artifacts live in the raw-evidence store (§9) and are referenced by hash, not
    inlined, so this object stays bounded.
    """

    id: UUID = Field(default_factory=uuid4)
    tenant_id: str = INVISABLE_TENANT_ID  # owning tenant; isolates evidence per tenant
    kind: str  # e.g. "sarif_result" | "log_line" | "sbom_entry" | "dns_txt"
    summary: str = Field(max_length=4000)
    classification: Classification = Classification.INTERNAL
    trust_level: TrustLevel = TrustLevel.UNTRUSTED_EVIDENCE
    validation_state: ValidationState = ValidationState.UNVALIDATED
    provenance: Provenance
    source_hash: str | None = None  # hash of the raw artifact this was derived from
    content_hash: str | None = None  # hash of this item's normalised content
    assets: tuple[AssetRef, ...] = ()

    @property
    def is_verified_evidence(self) -> bool:
        """True only if this item is validated AND not from an unverified trust class."""
        return (
            self.validation_state is ValidationState.VALIDATED
            and self.trust_level not in _UNVERIFIED_TRUST
        )

    @property
    def is_privacy_forbidden(self) -> bool:
        """True if this content must never reach a model or trusted memory."""
        return self.classification in PRIVACY_FORBIDDEN


# --- conclusions ---------------------------------------------------------------
class TestProposal(_Frozen):
    """A falsification test that would confirm or disprove a hypothesis."""

    description: str
    expected_if_true: str
    expected_if_false: str
    safe_to_run: bool = False  # must be proven safe before any execution


HypothesisStatus = Literal[
    "unverified",
    "supported",
    "contradicted",
    "inconclusive",
    "confirmed",
]


class Hypothesis(_Frozen):
    """A claim with explicit supporting AND contradicting evidence (§4).

    Confidence is never asserted on its own: a high-confidence ``confirmed``
    hypothesis with an incomplete evidence graph is exactly what the Brain must
    refuse to produce. ``uncertainty_reasons`` and ``falsification_tests`` force the
    model to show its work and to say what would change its mind.
    """

    id: UUID = Field(default_factory=uuid4)
    statement: str = Field(max_length=4000)
    supporting_evidence_ids: tuple[UUID, ...] = ()
    contradicting_evidence_ids: tuple[UUID, ...] = ()
    affected_assets: tuple[AssetRef, ...] = ()
    attack_techniques: tuple[str, ...] = ()  # e.g. MITRE ATT&CK technique ids
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    uncertainty_reasons: tuple[str, ...] = ()
    falsification_tests: tuple[TestProposal, ...] = ()
    status: HypothesisStatus = "unverified"

    @property
    def has_supporting_evidence(self) -> bool:
        return len(self.supporting_evidence_ids) > 0

    @property
    def is_grounded(self) -> bool:
        """A grounded conclusion cites evidence and resolves its contradictions.

        Used by the grounding gate: the Brain may not emit a ``supported`` or
        ``confirmed`` conclusion that has no supporting evidence, or that still has
        unresolved contradicting evidence.
        """
        if self.status in ("supported", "confirmed"):
            if not self.has_supporting_evidence:
                return False
            if self.contradicting_evidence_ids:
                return False
        return True


Severity = Literal["info", "low", "medium", "high", "critical"]


class Finding(_Frozen):
    """A normalised, deduplicated finding traceable to evidence and an asset (§4)."""

    id: UUID = Field(default_factory=uuid4)
    tenant_id: str = INVISABLE_TENANT_ID  # owning tenant; isolates findings per tenant
    title: str = Field(max_length=500)
    severity: Severity = "info"
    description: str = Field(max_length=8000, default="")
    asset: AssetRef
    evidence_ids: tuple[UUID, ...] = ()
    hypothesis_id: UUID | None = None
    provenance: Provenance
    classification: Classification = Classification.INTERNAL


class ProposedAction(_Frozen):
    """A remediation/containment option the Brain proposes — never self-executes.

    A model may *propose* this; only deterministic policy + recorded human approval
    can authorise it (target architecture §1: "a model must never decide whether it
    has authority to proceed").
    """

    id: UUID = Field(default_factory=uuid4)
    kind: str  # patch | containment | detection | rollback | ...
    summary: str = Field(max_length=4000)
    target: AssetRef
    finding_ids: tuple[UUID, ...] = ()
    residual_risk: str = ""
    rollback_plan: str = ""
    requires_approval: bool = True


class PolicyDecisionRecord(_Frozen):
    """An immutable record of a deterministic policy decision for the case."""

    action: str
    mode: str
    allow: bool
    denies: tuple[str, ...] = ()
    decided_at: datetime = Field(default_factory=_utcnow)
    policy_digest: str | None = None


class VerificationResult(_Frozen):
    """The verdict of an independent verifier over a finding or proposed action."""

    subject_id: UUID
    verifier: str  # id of the verifying agent/model (must differ from the producer)
    passed: bool
    reasons: tuple[str, ...] = ()
    verified_at: datetime = Field(default_factory=_utcnow)


__all__ = [
    "SCHEMA_VERSION",
    "Classification",
    "PRIVACY_FORBIDDEN",
    "TrustLevel",
    "ValidationState",
    "Provenance",
    "AssetRef",
    "EvidenceItem",
    "TestProposal",
    "HypothesisStatus",
    "Hypothesis",
    "Severity",
    "Finding",
    "ProposedAction",
    "PolicyDecisionRecord",
    "VerificationResult",
]
