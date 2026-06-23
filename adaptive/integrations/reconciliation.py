"""Infrastructure-reconciliation ownership (directive §24).

Three reconcilers, each owning a distinct layer: OpenTofu (foundational static infra),
Cluster API (Kubernetes cluster lifecycle), Crossplane (application-facing managed
resources). Argo CD owns application desired state. The hard rule: **no resource may be
owned by more than one authoritative controller**, and conflicting ownership must fail CI
and block deployment. Crossplane additionally may not own Guardian constitutional infra.

This is a deterministic registry + validator — exactly the check the directive wants run in
CI.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Controller(str, Enum):
    OPENTOFU = "opentofu"          # foundational static infrastructure
    CLUSTER_API = "cluster_api"    # Kubernetes cluster lifecycle
    CROSSPLANE = "crossplane"      # application-facing managed resources
    ARGO_CD = "argo_cd"            # application desired state


# Crossplane "cannot administer root accounts or Guardian constitutional infrastructure".
_CROSSPLANE_FORBIDDEN_FOR_CONSTITUTIONAL = True


class ManagedResource(BaseModel):
    """A resource and the single controller authoritative for it (§24)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: str = Field(min_length=1)
    authoritative_controller: Controller
    desired_state_source: str = Field(min_length=1)  # e.g. a git ref
    owner: str = Field(min_length=1)
    lifecycle: str = "managed"
    drift_policy: str = "correct"
    recovery_policy: str = "restore"
    constitutional: bool = False  # Guardian constitutional infrastructure


class OwnershipConflict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: str
    controllers: tuple[Controller, ...]


class ReconciliationError(RuntimeError):
    """Raised on conflicting ownership or a forbidden controller. Fail CI / block deploy."""


class ReconciliationRegistry:
    """The authoritative-controller registry (§24). One controller per resource."""

    def __init__(self) -> None:
        self._claims: dict[str, set[Controller]] = {}
        self._resources: list[ManagedResource] = []

    def register(self, resource: ManagedResource) -> None:
        if (
            _CROSSPLANE_FORBIDDEN_FOR_CONSTITUTIONAL
            and resource.constitutional
            and resource.authoritative_controller is Controller.CROSSPLANE
        ):
            raise ReconciliationError(
                f"Crossplane may not own constitutional resource {resource.resource_id!r} (§24)"
            )
        self._claims.setdefault(resource.resource_id, set()).add(
            resource.authoritative_controller
        )
        self._resources.append(resource)

    def conflicts(self) -> list[OwnershipConflict]:
        """Resources claimed by more than one controller."""
        return [
            OwnershipConflict(resource_id=rid, controllers=tuple(sorted(ctrls, key=lambda c: c.value)))
            for rid, ctrls in self._claims.items()
            if len(ctrls) > 1
        ]

    def assert_no_conflicts(self) -> None:
        """Fail closed if any resource has more than one authoritative controller (§24)."""
        conflicts = self.conflicts()
        if conflicts:
            ids = ", ".join(c.resource_id for c in conflicts)
            raise ReconciliationError(
                f"conflicting reconciler ownership must fail CI: {ids}"
            )


__all__ = [
    "Controller",
    "ManagedResource",
    "OwnershipConflict",
    "ReconciliationError",
    "ReconciliationRegistry",
]
