"""Typed contracts for the model gateway (target architecture §2).

Every model call in Guardian goes through one gateway. These are the request /
response / spec shapes it speaks, plus the gateway's structured error types. Like the
evidence contracts they are strict (``extra="forbid"``) and, where they represent a
fact rather than a builder, frozen.

Nothing here talks to a provider or the network — that is the providers' job. This
module just defines *what* a model call is and *what work class* it serves, so routing,
budgets, the firewalls and provenance can all reason about it deterministically.
"""

from __future__ import annotations

from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from ..evidence.models import EvidenceItem, TrustLevel


# --- work + model classes ------------------------------------------------------
class WorkClass(str, Enum):
    """What *kind* of work a call does — the input to the routing policy (§2).

    Crucially, ``POLICY`` exists so the gateway can *refuse* it: authority, scope and
    approval decisions are deterministic and must never be delegated to a model.
    """

    PARSING = "parsing"          # parse / classify / dedupe        → fast or local
    SENSITIVE = "sensitive"      # sensitive-content processing     → approved private/local
    REASONING = "reasoning"      # deep attack-path reasoning       → strong reasoning model
    PATCH = "patch"              # patch / code generation          → strong coding model
    REVIEW = "review"            # critical conclusion review       → independent judge model
    POLICY = "policy"            # policy / authority / approval     → NO MODEL (deterministic)


class ModelClass(str, Enum):
    """The capability tier a concrete model provides."""

    FAST = "fast"
    LOCAL = "local"
    STRONG_REASONING = "strong_reasoning"
    STRONG_CODING = "strong_coding"
    JUDGE = "judge"
    NONE = "none"


# Default mapping from work class to model class. Routing may override it (e.g. force
# a local model for sensitive content); see core.ai.routing.
DEFAULT_WORK_ROUTING: dict[WorkClass, ModelClass] = {
    WorkClass.PARSING: ModelClass.FAST,
    WorkClass.SENSITIVE: ModelClass.LOCAL,
    WorkClass.REASONING: ModelClass.STRONG_REASONING,
    WorkClass.PATCH: ModelClass.STRONG_CODING,
    WorkClass.REVIEW: ModelClass.JUDGE,
    WorkClass.POLICY: ModelClass.NONE,
}


# --- model spec ----------------------------------------------------------------
class ModelSpec(BaseModel):
    """A pinned, registered model the gateway is allowed to call.

    ``model_id`` is an exact pinned snapshot (Anthropic publishes pinned snapshot IDs,
    not moving aliases). ``performs_external_processing`` drives the privacy boundary:
    a model that ships data off-box may not receive sensitive content unless the caller
    explicitly permits it. Prices are *estimates* for budget accounting and can be
    overridden via configuration — they are not authoritative billing figures.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    model_id: str
    provider: str
    model_class: ModelClass
    family: str  # for independence checks: a judge must differ from the producer's family
    performs_external_processing: bool
    max_output_tokens: int = Field(ge=1, default=4096)
    input_price_per_mtok: float = Field(ge=0.0, default=0.0)
    output_price_per_mtok: float = Field(ge=0.0, default=0.0)


# --- request / response --------------------------------------------------------
class ModelRequest(BaseModel):
    """A request to the gateway. The caller declares the work class and supplies typed
    evidence; the gateway decides which model (if any) may run it and how to frame it.

    ``instruction`` and ``extra_context`` are the *trusted* task framing. ``evidence``
    is untrusted/typed material to reason over — the context firewall renders it as
    data, never as instructions (§8).
    """

    model_config = ConfigDict(extra="forbid")

    work_class: WorkClass
    tenant_id: UUID
    case_id: UUID
    instruction: str = Field(max_length=20000)
    prompt_template_version: str
    extra_context: str = Field(max_length=20000, default="")
    evidence: tuple[EvidenceItem, ...] = ()
    tool_schema_version: str | None = None
    eval_version: str | None = None
    # Whether the caller permits sensitive content to be processed by an external model.
    # Default False: the gateway will route sensitive content to a local/private model
    # or fail closed rather than ship it off-box.
    allow_external_processing: bool = False
    max_output_tokens: int = Field(ge=1, le=32000, default=1024)
    timeout_s: float = Field(gt=0, le=600, default=60.0)
    max_retries: int = Field(ge=0, le=5, default=1)


class ModelResponse(BaseModel):
    """The gateway's answer: model text plus the firewall verdict and the audit record.

    ``trust_level`` is always ``MODEL_GENERATED`` — model output can never become
    verified evidence or trusted memory without separate validation (§8). ``high_risk``
    flags output the output firewall thinks must not reach a tool unreviewed.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str
    trust_level: TrustLevel = TrustLevel.MODEL_GENERATED
    high_risk: bool = False
    firewall_findings: tuple[str, ...] = ()
    record: "ModelCallRecord"


# --- errors --------------------------------------------------------------------
class GatewayError(RuntimeError):
    """Base class for every gateway refusal. Always fail closed — never fall back."""


class PolicyRoutingError(GatewayError):
    """Raised when a model is asked to do work reserved for deterministic policy."""


class PrivacyBoundaryError(GatewayError):
    """Raised when a request would send forbidden/over-classified content to a model."""


class ModelUnavailableError(GatewayError):
    """Raised when no permitted, available model can serve the request. Fail closed."""


class BudgetExceededError(GatewayError):
    """Raised when a call would exceed its token/cost budget."""


# Resolve the forward reference to ModelCallRecord (defined in provenance.py).
from .provenance import ModelCallRecord  # noqa: E402

ModelResponse.model_rebuild()


__all__ = [
    "WorkClass",
    "ModelClass",
    "DEFAULT_WORK_ROUTING",
    "ModelSpec",
    "ModelRequest",
    "ModelResponse",
    "ModelCallRecord",
    "GatewayError",
    "PolicyRoutingError",
    "PrivacyBoundaryError",
    "ModelUnavailableError",
    "BudgetExceededError",
]
