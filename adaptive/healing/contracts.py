"""The HealingContract — the machine-readable licence to autonomously repair a service.

Directive §5: every healable component must publish a HealingContract, and *Guardian must
refuse to autonomously repair a service without a valid one*. The contract declares which
reversible repairs are eligible, in which environments, with what limits, plus the
structural privacy and rollback guarantees that can never be traded away for availability.

These are strict Pydantic v2 models with camelCase aliases, so the directive's example
YAML parses directly via :meth:`HealingContract.from_mapping`. Cross-field rules that the
directive assigns to CUE are enforced here too (defence in depth) so a malformed contract
fails closed before it could ever reach the runbook compiler, OPA or Temporal.

This module decides *eligibility*, not authority. A repair being eligible under a contract
is necessary but not sufficient: the Plan Compiler, Capability Authority, OPA and the
autonomy budget still gate every actual action.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Criticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Environment(str, Enum):
    DEVELOPMENT = "development"
    CI = "ci"
    STAGING = "staging"
    PRODUCTION = "production"


class RepairAction(str, Enum):
    """The canonical, pre-approved reversible repair actions (directive §1 Class D, §7)."""

    RESTART_REPLICA = "restart_replica"  # layer 1
    REPLACE_STATELESS_REPLICA = "replace_stateless_replica"  # layer 1
    RESCHEDULE_WORKLOAD = "reschedule_workload"  # layer 2
    SCALE_SERVICE = "scale_service"  # layer 3
    ROLLBACK_CONFIGURATION = "rollback_configuration"  # layer 4
    ROLLBACK_ARTIFACT = "rollback_artifact"  # layer 5
    ROLLBACK_CANARY = "rollback_canary"  # layer 5
    DISABLE_FEATURE = "disable_feature"  # layer 6
    REVOKE_CREDENTIAL = "revoke_credential"  # layer 7
    QUARANTINE_ARTIFACT = "quarantine_artifact"  # layer 7
    NETWORK_ISOLATION = "network_isolation"  # layer 8
    ISOLATE_WORKLOAD = "isolate_workload"  # layer 8
    EVACUATE_CLUSTER = "evacuate_cluster"  # layer 9
    REGIONAL_RECOVERY = "regional_recovery"  # layer 10
    PAUSE_WORKFLOW = "pause_workflow"
    DRAIN_AND_REBOOT_NODE = "drain_and_reboot_node"
    BACKUP_RESTORE_VERIFICATION = "backup_restore_verification"


# Self-healing hierarchy layer for each action (directive §7). The healing engine must
# pick the lowest viable layer and never jump to a broader repair while a narrower one
# remains viable.
REPAIR_LAYER: dict[RepairAction, int] = {
    RepairAction.RESTART_REPLICA: 1,
    RepairAction.REPLACE_STATELESS_REPLICA: 1,
    RepairAction.RESCHEDULE_WORKLOAD: 2,
    RepairAction.SCALE_SERVICE: 3,
    RepairAction.ROLLBACK_CONFIGURATION: 4,
    RepairAction.ROLLBACK_ARTIFACT: 5,
    RepairAction.ROLLBACK_CANARY: 5,
    RepairAction.DISABLE_FEATURE: 6,
    RepairAction.REVOKE_CREDENTIAL: 7,
    RepairAction.QUARANTINE_ARTIFACT: 7,
    RepairAction.NETWORK_ISOLATION: 8,
    RepairAction.ISOLATE_WORKLOAD: 8,
    RepairAction.EVACUATE_CLUSTER: 9,
    RepairAction.REGIONAL_RECOVERY: 10,
    RepairAction.PAUSE_WORKFLOW: 1,
    RepairAction.DRAIN_AND_REBOOT_NODE: 2,
    RepairAction.BACKUP_RESTORE_VERIFICATION: 1,
}

# Repairs that are *always* forbidden, regardless of what a contract declares. These encode
# the Privacy Fabric and audit invariants that no availability concern may override (§5, §9).
STRUCTURALLY_FORBIDDEN_REPAIRS: frozenset[str] = frozenset(
    {
        "delete_message_store",
        "bypass_encryption",
        "disable_audit",
        "introduce_plaintext_logging",
        "decrypt_private_content",
        "access_message_plaintext",
        "store_decryption_keys",
        "disable_encryption",
    }
)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class MetricCheck(_Model):
    """A single readiness/health signal, e.g. ``{prometheus: "up{...} == 1"}``."""

    source: str
    expr: str


class HealthSpec(_Model):
    slo_ref: str = Field(alias="sloRef")
    readiness_signals: tuple[MetricCheck, ...] = Field(default=(), alias="readinessSignals")
    dependency_signals: tuple[str, ...] = Field(default=(), alias="dependencySignals")

    @field_validator("readiness_signals", mode="before")
    @classmethod
    def _coerce_signals(cls, v: Any) -> Any:
        """Accept the YAML form ``[{prometheus: expr}, ...]`` and normalise to MetricCheck."""
        if v is None:
            return ()
        out: list[Any] = []
        for item in v:
            if isinstance(item, MetricCheck):
                out.append(item)
            elif isinstance(item, Mapping):
                if "source" in item and "expr" in item:
                    out.append({"source": item["source"], "expr": item["expr"]})
                elif len(item) == 1:
                    (source, expr), = item.items()
                    out.append({"source": source, "expr": str(expr)})
                else:
                    raise ValueError(f"readiness signal must be a single-key mapping: {item!r}")
            else:
                raise ValueError(f"readiness signal must be a mapping, got {type(item).__name__}")
        return out


class AllowedRepair(_Model):
    action: RepairAction
    environments: tuple[Environment, ...]
    maximum_per_hour: int | None = Field(default=None, ge=0, alias="maximumPerHour")
    maximum_duration_seconds: int | None = Field(
        default=None, ge=1, alias="maximumDurationSeconds"
    )
    requires: tuple[str, ...] = ()
    flag: str | None = None

    @model_validator(mode="after")
    def _check_action_constraints(self) -> "AllowedRepair":
        # A feature disable must carry an expiry and the flag it controls (§5, §27).
        if self.action is RepairAction.DISABLE_FEATURE:
            if self.maximum_duration_seconds is None:
                raise ValueError("disable_feature requires maximumDurationSeconds (an expiry)")
            if not self.flag:
                raise ValueError("disable_feature requires the feature 'flag' it controls")
        return self


class RollbackPolicy(_Model):
    required: bool = True
    verification_window_seconds: int = Field(alias="verificationWindowSeconds", ge=1)


class PrivacyPolicy(_Model):
    # Structural: these can only ever be "forbidden". Any other value is a contract bug.
    plaintext_access: str = Field(default="forbidden", alias="plaintextAccess")
    message_key_access: str = Field(default="forbidden", alias="messageKeyAccess")

    @field_validator("plaintext_access", "message_key_access")
    @classmethod
    def _must_be_forbidden(cls, v: str) -> str:
        if v != "forbidden":
            raise ValueError("privacy access must be 'forbidden' (Privacy Fabric is structural)")
        return v


class ContractMetadata(_Model):
    service: str
    owner: str
    criticality: Criticality


class HealingContractViolation(RuntimeError):
    """Raised when a repair is attempted that no valid contract permits. Fail closed."""


class HealingContract(_Model):
    api_version: str = Field(default="guardian.invisable/v1", alias="apiVersion")
    kind: str = "HealingContract"
    metadata: ContractMetadata
    health: HealthSpec
    allowed_repairs: tuple[AllowedRepair, ...] = Field(default=(), alias="allowedRepairs")
    forbidden_repairs: tuple[str, ...] = Field(default=(), alias="forbiddenRepairs")
    rollback: RollbackPolicy
    privacy: PrivacyPolicy = PrivacyPolicy()

    @model_validator(mode="after")
    def _check_contract(self) -> "HealingContract":
        if self.kind != "HealingContract":
            raise ValueError(f"unexpected kind {self.kind!r}")
        # Rollback is mandatory for any autonomous repair (§5, acceptance #14).
        if not self.rollback.required:
            raise ValueError("rollback.required must be true — every autonomous repair is reversible")
        # No allowed repair may name a structurally- or contract-forbidden action.
        forbidden = STRUCTURALLY_FORBIDDEN_REPAIRS | set(self.forbidden_repairs)
        for repair in self.allowed_repairs:
            if repair.action.value in forbidden:
                raise ValueError(
                    f"allowed repair {repair.action.value!r} is in the forbidden set"
                )
        return self

    @property
    def effective_forbidden(self) -> frozenset[str]:
        return STRUCTURALLY_FORBIDDEN_REPAIRS | frozenset(self.forbidden_repairs)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "HealingContract":
        """Build from the directive's YAML/JSON shape (camelCase, nested metadata)."""
        return cls.model_validate(dict(data))

    def repair_for(
        self, action: RepairAction, environment: Environment
    ) -> AllowedRepair | None:
        for repair in self.allowed_repairs:
            if repair.action is action and environment in repair.environments:
                return repair
        return None


def assert_repair_allowed(
    contract: HealingContract | None,
    action: RepairAction,
    environment: Environment,
) -> AllowedRepair:
    """Fail closed unless a valid contract explicitly permits this exact repair here.

    This is the gate behind directive §5: "Guardian must refuse to autonomously repair a
    service without a valid HealingContract." Eligibility only — the Plan Compiler,
    Capability Authority, OPA and the autonomy budget still gate the real action.
    """
    if contract is None:
        raise HealingContractViolation(
            f"no HealingContract for this service — refusing to repair via {action.value}"
        )
    if action.value in contract.effective_forbidden:
        raise HealingContractViolation(f"repair {action.value!r} is forbidden by contract")
    repair = contract.repair_for(action, environment)
    if repair is None:
        raise HealingContractViolation(
            f"contract for service '{contract.metadata.service}' does not permit "
            f"{action.value!r} in {environment.value}"
        )
    return repair


__all__ = [
    "Criticality",
    "Environment",
    "RepairAction",
    "REPAIR_LAYER",
    "STRUCTURALLY_FORBIDDEN_REPAIRS",
    "MetricCheck",
    "HealthSpec",
    "AllowedRepair",
    "RollbackPolicy",
    "PrivacyPolicy",
    "ContractMetadata",
    "HealingContract",
    "HealingContractViolation",
    "assert_repair_allowed",
]
