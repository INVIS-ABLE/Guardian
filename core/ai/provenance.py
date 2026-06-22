"""Provenance for model calls — the immutable record every call must produce (§2).

The gateway records one :class:`ModelCallRecord` per call. It captures exactly what
the target architecture asks for: the pinned model id and provider, the prompt-template
version and hash, the tool-schema version, the input evidence ids, the output hash,
token usage and cost, the data classification, tenant and case ids, timeout and retry
count, whether external processing was permitted, the evaluation version, and the
model-routing reason. That record is what lets an independent verifier reconstruct
every decision the Brain made.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from ..evidence.models import Classification


def hash_text(text: str) -> str:
    """Stable content hash used for prompt templates and model outputs."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ModelCallRecord(BaseModel):
    """Immutable audit record of a single model call. Frozen and strict."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # identity of the call
    model_id: str
    provider: str
    routing_reason: str
    work_class: str

    # framing + inputs
    prompt_template_version: str
    prompt_template_hash: str
    tool_schema_version: str | None = None
    input_evidence_ids: tuple[UUID, ...] = ()
    data_classification: Classification = Classification.INTERNAL
    external_processing_permitted: bool = False

    # tenancy / case
    tenant_id: UUID
    case_id: UUID

    # output + accounting
    output_hash: str | None = None
    input_tokens: int = Field(ge=0, default=0)
    output_tokens: int = Field(ge=0, default=0)
    cost_usd: float = Field(ge=0.0, default=0.0)

    # execution
    timeout_s: float = 0.0
    retry_count: int = Field(ge=0, default=0)
    eval_version: str | None = None
    succeeded: bool = True
    error: str | None = None

    created_at: datetime = Field(default_factory=_utcnow)


__all__ = ["hash_text", "ModelCallRecord"]
