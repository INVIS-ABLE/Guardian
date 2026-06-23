"""Multi-cluster failover invariants (directive §23).

Failover must move workloads to safety *without* loosening any control. The directive is
explicit about what failover must never do, and this module encodes exactly that list as a
fail-closed validator: a failover plan asserting any forbidden effect is rejected before it
could run. This grants nothing — OPA and the Capability Authority still gate the actual move.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

# Effects a failover must never have (§23). A plan that sets any of these is refused.
FORBIDDEN_FAILOVER_EFFECTS: frozenset[str] = frozenset(
    {
        "bypass_opa",
        "bypass_workload_identity",
        "deploy_unapproved_digest",
        "change_data_residency",
        "change_encryption_requirements",
        "restore_stale_policy",
        "use_stale_secrets",
    }
)


class FailoverPlan(BaseModel):
    """A declarative regional/cluster failover plan (§23)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    from_cluster: str = Field(min_length=1)
    to_cluster: str = Field(min_length=1)
    workloads: tuple[str, ...]
    # Asserted effects of executing this plan; any forbidden one fails validation.
    asserted_effects: tuple[str, ...] = ()
    preserves_identity: bool = True
    preserves_policy: bool = True
    min_healthy_clusters_after: int = Field(ge=1, default=1)
    quorum_preserved: bool = True


class FailoverInvariantError(RuntimeError):
    """Raised when a failover plan would violate a survivability invariant. Fail closed."""


def validate_failover(plan: FailoverPlan) -> None:
    """Refuse a failover plan that loosens any control (§23). Fail closed."""
    forbidden = sorted(set(plan.asserted_effects) & FORBIDDEN_FAILOVER_EFFECTS)
    if forbidden:
        raise FailoverInvariantError(
            f"failover {plan.name!r} asserts forbidden effect(s): {forbidden}"
        )
    if plan.from_cluster == plan.to_cluster:
        raise FailoverInvariantError("failover target cluster must differ from source")
    if not plan.preserves_identity:
        raise FailoverInvariantError("failover must preserve workload identity (§23)")
    if not plan.preserves_policy:
        raise FailoverInvariantError("failover must preserve policy (§23)")
    if not plan.quorum_preserved:
        raise FailoverInvariantError("failover must preserve quorum (split-brain risk, §23)")


__all__ = [
    "FORBIDDEN_FAILOVER_EFFECTS",
    "FailoverPlan",
    "FailoverInvariantError",
    "validate_failover",
]
