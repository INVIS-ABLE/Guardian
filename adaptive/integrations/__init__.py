"""Integration-contract layer (directive §4, §10, §11, §15–16, §18, §24, §28).

Typed manifests, adapter contracts and invariant validators for the external control-plane
and MLOps systems. Every integration sits behind Guardian's existing authorities and
produces evidence/signals only — none grants authority. The real network-talking adapters
are deployment-specific and implement these shapes; this package is what CI and the gates
validate against.
"""

from .base import (
    AdapterHealth,
    AuthorityViolation,
    IntegrationAdapter,
    Signal,
    assert_no_authority,
)
from .datasets import (
    FORBIDDEN_TRAINING_CLASSES,
    DataGovernanceError,
    DatasetManifest,
    FeatureDefinition,
    assert_dataset_governed,
    assert_feature_governed,
)
from .delivery import (
    RolloutAction,
    RolloutDecision,
    SafetySignal,
    SignalStatus,
    evaluate_rollout,
)
from .flink import (
    FlinkJobError,
    FlinkJobManifest,
    FlinkResourceLimits,
    assert_flink_job_valid,
)
from .models import (
    ChallengerMetrics,
    ContinualUpdate,
    KServeEndpoint,
    ModelGovernanceError,
    ModelManifest,
    ModelStage,
    assert_endpoint_valid,
    promote_challenger,
)
from .reconciliation import (
    Controller,
    ManagedResource,
    OwnershipConflict,
    ReconciliationError,
    ReconciliationRegistry,
)
from .wasm import WasmExtensionError, WasmModuleManifest, assert_wasm_safe

__all__ = [
    # base
    "AdapterHealth", "Signal", "IntegrationAdapter", "AuthorityViolation", "assert_no_authority",
    # reconciliation
    "Controller", "ManagedResource", "OwnershipConflict", "ReconciliationError",
    "ReconciliationRegistry",
    # delivery
    "SignalStatus", "SafetySignal", "RolloutAction", "RolloutDecision", "evaluate_rollout",
    # models
    "ModelStage", "ModelManifest", "KServeEndpoint", "ModelGovernanceError",
    "assert_endpoint_valid", "ChallengerMetrics", "promote_challenger", "ContinualUpdate",
    # datasets
    "FORBIDDEN_TRAINING_CLASSES", "DatasetManifest", "FeatureDefinition", "DataGovernanceError",
    "assert_dataset_governed", "assert_feature_governed",
    # flink
    "FlinkResourceLimits", "FlinkJobManifest", "FlinkJobError", "assert_flink_job_valid",
    # wasm
    "WasmModuleManifest", "WasmExtensionError", "assert_wasm_safe",
]
