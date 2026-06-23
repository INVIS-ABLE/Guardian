"""Model lifecycle, KServe endpoints and champion/challenger (directive §15, §16, §18).

Encodes the model-governance invariants the acceptance tests demand (§39):

* every model has an approved registry version and a reproducible dataset (#4, #6);
* every production inference endpoint uses an approved model digest (#7);
* every model can be rolled back (#8);
* no model changes its own production manifest and no model promotes itself (#2) —
  promotion requires an external :class:`AuthorityGrant`;
* a challenger never controls operations and is promoted only on better/equal safety with
  human approval (§18).

Typed contracts + fail-closed validators. The real MLflow/KServe wiring lives in the
deployment behind these shapes.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from ..autonomy.states import AuthorityGrant, _AUTHORITY_ROLES


class ModelStage(str, Enum):
    REGISTERED = "registered"
    EVALUATED = "evaluated"
    SHADOW = "shadow"
    CHAMPION = "champion"
    CHALLENGER = "challenger"
    ARCHIVED = "archived"
    REVOKED = "revoked"


class ModelManifest(BaseModel):
    """An approved, reproducible, rollback-able model version (§15)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")  # approved model digest
    runtime_image: str = Field(min_length=1)
    dataset_ref: str = Field(min_length=1)  # reproducible dataset (#4)
    eval_ref: str = Field(min_length=1)     # evaluation evidence (#6)
    rollback_version: str | None = None     # required unless this is the base (#8)
    is_base: bool = False
    stage: ModelStage = ModelStage.REGISTERED

    def model_post_init(self, _ctx: object) -> None:
        if not self.is_base and not self.rollback_version:
            raise ValueError("model must declare a rollback_version (every model rolls back, #8)")


class KServeEndpoint(BaseModel):
    """An approved inference endpoint (§15). Must reference an approved digest and isolate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    model_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    runtime_image: str = Field(min_length=1)
    cpu_limit: float = Field(gt=0.0)
    memory_limit_mb: int = Field(gt=0)
    network_isolated: bool = True
    tenant_id: str = Field(min_length=1)
    input_schema_ref: str = Field(min_length=1)
    output_schema_ref: str = Field(min_length=1)
    monitoring_enabled: bool = True
    canary_supported: bool = True
    revocable: bool = True


class ModelGovernanceError(RuntimeError):
    """Raised when a model action would violate a governance invariant. Fail closed."""


def assert_endpoint_valid(endpoint: KServeEndpoint, approved_digests: set[str]) -> None:
    """A production endpoint must use an approved digest, be isolated and revocable (#7)."""
    if endpoint.model_digest not in approved_digests:
        raise ModelGovernanceError(
            f"endpoint {endpoint.name!r} uses unapproved model digest {endpoint.model_digest}"
        )
    if not endpoint.network_isolated:
        raise ModelGovernanceError(f"endpoint {endpoint.name!r} must be network-isolated")
    if not endpoint.monitoring_enabled:
        raise ModelGovernanceError(f"endpoint {endpoint.name!r} must have monitoring enabled")
    if not endpoint.revocable:
        raise ModelGovernanceError(f"endpoint {endpoint.name!r} must be immediately revocable")


class ChallengerMetrics(BaseModel):
    """Evaluation of a challenger vs the champion (§18)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    safety_at_least_equal: bool
    performance_validated: bool
    privacy_regression: bool
    cross_tenant_leakage: bool
    drift_stable: bool


def promote_challenger(
    challenger: ModelManifest,
    metrics: ChallengerMetrics,
    *,
    approval: AuthorityGrant | None,
) -> ModelManifest:
    """Promote a challenger to champion, fail-closed (§18, acceptance #2).

    A model never promotes itself: promotion requires a valid external authority grant.
    Promotion is refused unless safety is at least equal, performance validated, there is no
    privacy regression and no cross-tenant leakage, and drift is stable.
    """
    if approval is None or approval.role not in _AUTHORITY_ROLES:
        raise ModelGovernanceError("challenger promotion requires an external authority grant (#2)")
    if not metrics.safety_at_least_equal:
        raise ModelGovernanceError("challenger safety is worse than champion — refused (§18)")
    if not metrics.performance_validated:
        raise ModelGovernanceError("challenger performance not validated — refused (§18)")
    if metrics.privacy_regression:
        raise ModelGovernanceError("challenger shows a privacy regression — refused (§18)")
    if metrics.cross_tenant_leakage:
        raise ModelGovernanceError("challenger shows cross-tenant leakage — refused (§18)")
    if not metrics.drift_stable:
        raise ModelGovernanceError("challenger drift is unstable — refused (§18)")
    return challenger.model_copy(update={"stage": ModelStage.CHAMPION})


class ContinualUpdate(BaseModel):
    """A record of an incremental (River) model update (§16). Fully reproducible + rollback."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    model_name: str = Field(min_length=1)
    previous_model_hash: str = Field(min_length=1)
    new_model_hash: str = Field(min_length=1)
    feature_window: str = Field(min_length=1)
    input_lineage: str = Field(min_length=1)
    evaluation_result: str = Field(min_length=1)
    drift_result: str = Field(min_length=1)
    rollback_point: str = Field(min_length=1)  # the last approved checkpoint (§16)


__all__ = [
    "ModelStage",
    "ModelManifest",
    "KServeEndpoint",
    "ModelGovernanceError",
    "assert_endpoint_valid",
    "ChallengerMetrics",
    "promote_challenger",
    "ContinualUpdate",
]
