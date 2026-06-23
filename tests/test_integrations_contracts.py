"""Level 6 §4/§10/§11/§15-16/§18/§24/§28: integration-contract invariants."""

from __future__ import annotations

import pytest

from adaptive.autonomy.states import AuthorityGrant
from adaptive.integrations import (
    ChallengerMetrics,
    Controller,
    DatasetManifest,
    FeatureDefinition,
    FlinkJobManifest,
    FlinkResourceLimits,
    KServeEndpoint,
    ManagedResource,
    ModelManifest,
    ReconciliationError,
    ReconciliationRegistry,
    RolloutAction,
    SafetySignal,
    SignalStatus,
    WasmModuleManifest,
    assert_dataset_governed,
    assert_endpoint_valid,
    assert_feature_governed,
    assert_flink_job_valid,
    assert_no_authority,
    assert_wasm_safe,
    evaluate_rollout,
    promote_challenger,
)
from adaptive.integrations.datasets import DataGovernanceError
from adaptive.integrations.flink import FlinkJobError
from adaptive.integrations.models import ModelGovernanceError
from adaptive.integrations.wasm import WasmExtensionError

DIGEST = "sha256:" + "a" * 64
DIGEST2 = "sha256:" + "b" * 64


# --- base: no integration grants authority -------------------------------------
class _Adapter:
    name = "argo"
    grants_authority = False

    def health(self):  # pragma: no cover - trivial
        from adaptive.integrations import AdapterHealth
        return AdapterHealth(name=self.name, available=True)


class _RogueAdapter:
    name = "rogue"
    grants_authority = True

    def health(self):  # pragma: no cover
        from adaptive.integrations import AdapterHealth
        return AdapterHealth(name=self.name, available=True)


def test_adapter_without_authority_is_accepted():
    assert_no_authority(_Adapter())  # no raise


def test_adapter_claiming_authority_is_refused():
    from adaptive.integrations import AuthorityViolation
    with pytest.raises(AuthorityViolation):
        assert_no_authority(_RogueAdapter())


# --- reconciliation (§24) ------------------------------------------------------
def test_conflicting_ownership_fails():
    reg = ReconciliationRegistry()
    reg.register(ManagedResource(resource_id="db1", authoritative_controller=Controller.CROSSPLANE,
                                 desired_state_source="git#a", owner="team"))
    reg.register(ManagedResource(resource_id="db1", authoritative_controller=Controller.OPENTOFU,
                                 desired_state_source="git#b", owner="team"))
    assert reg.conflicts()
    with pytest.raises(ReconciliationError):
        reg.assert_no_conflicts()


def test_single_owner_is_clean():
    reg = ReconciliationRegistry()
    reg.register(ManagedResource(resource_id="cluster1", authoritative_controller=Controller.CLUSTER_API,
                                 desired_state_source="git#a", owner="team"))
    reg.assert_no_conflicts()  # no raise


def test_crossplane_cannot_own_constitutional_infra():
    reg = ReconciliationRegistry()
    with pytest.raises(ReconciliationError):
        reg.register(ManagedResource(resource_id="opa", authoritative_controller=Controller.CROSSPLANE,
                                     desired_state_source="git#a", owner="sec", constitutional=True))


# --- progressive delivery (§10) ------------------------------------------------
def test_failed_signal_rolls_back():
    d = evaluate_rollout((SafetySignal(name="latency", status=SignalStatus.FAIL),))
    assert d.action is RolloutAction.ROLLBACK
    assert "latency" in d.failing


def test_missing_signal_holds_promotion():
    d = evaluate_rollout((SafetySignal(name="latency", status=SignalStatus.PASS),),
                         required=("error_rate",))
    assert d.action is RolloutAction.HOLD
    assert "error_rate" in d.missing


def test_all_passing_promotes():
    d = evaluate_rollout((SafetySignal(name="latency", status=SignalStatus.PASS),
                          SafetySignal(name="errors", status=SignalStatus.PASS)))
    assert d.action is RolloutAction.PROMOTE


def test_no_signals_holds():
    assert evaluate_rollout(()).action is RolloutAction.HOLD


# --- model governance (§15, §18, acceptance #2/#7/#8) --------------------------
def _model(**kw) -> ModelManifest:
    base = dict(name="m", version="1", digest=DIGEST, runtime_image="img:1",
                dataset_ref="ds:1", eval_ref="ev:1", rollback_version="0")
    base.update(kw)
    return ModelManifest(**base)


def test_model_requires_rollback_version():
    with pytest.raises(ValueError):
        _model(rollback_version=None, is_base=False)


def test_base_model_may_omit_rollback():
    m = _model(rollback_version=None, is_base=True)
    assert m.is_base is True


def test_endpoint_must_use_approved_digest():
    ep = KServeEndpoint(name="e", model_digest=DIGEST2, runtime_image="img", cpu_limit=1.0,
                        memory_limit_mb=512, tenant_id="t1", input_schema_ref="i",
                        output_schema_ref="o")
    with pytest.raises(ModelGovernanceError):
        assert_endpoint_valid(ep, approved_digests={DIGEST})
    # approved digest passes
    ep2 = ep.model_copy(update={"model_digest": DIGEST})
    assert_endpoint_valid(ep2, approved_digests={DIGEST})


def test_challenger_cannot_self_promote_without_authority():
    good = ChallengerMetrics(safety_at_least_equal=True, performance_validated=True,
                             privacy_regression=False, cross_tenant_leakage=False, drift_stable=True)
    with pytest.raises(ModelGovernanceError):
        promote_challenger(_model(stage="challenger"), good, approval=None)


def test_challenger_promotion_refused_on_privacy_regression():
    bad = ChallengerMetrics(safety_at_least_equal=True, performance_validated=True,
                            privacy_regression=True, cross_tenant_leakage=False, drift_stable=True)
    grant = AuthorityGrant(granted_by="human", role="human_approver")
    with pytest.raises(ModelGovernanceError):
        promote_challenger(_model(stage="challenger"), bad, approval=grant)


def test_challenger_promotion_succeeds_with_authority_and_clean_metrics():
    good = ChallengerMetrics(safety_at_least_equal=True, performance_validated=True,
                             privacy_regression=False, cross_tenant_leakage=False, drift_stable=True)
    grant = AuthorityGrant(granted_by="human", role="human_approver")
    promoted = promote_challenger(_model(stage="challenger"), good, approval=grant)
    assert promoted.stage.value == "champion"


# --- dataset/feature governance (§15, acceptance #4/#5) ------------------------
def test_dataset_needs_lineage_and_validation():
    with pytest.raises(DataGovernanceError):
        assert_dataset_governed(DatasetManifest(name="d", version="1", source_uri="s",
                                                lineage=(), validation_passed=True))
    with pytest.raises(DataGovernanceError):
        assert_dataset_governed(DatasetManifest(name="d", version="1", source_uri="s",
                                                lineage=("ingest",), validation_passed=False))


def test_forbidden_class_dataset_refused():
    with pytest.raises(DataGovernanceError):
        assert_dataset_governed(DatasetManifest(name="d", version="1", source_uri="s",
                                                lineage=("x",), validation_passed=True,
                                                classification="message_plaintext"))


def test_governed_dataset_passes():
    assert_dataset_governed(DatasetManifest(name="d", version="1", source_uri="s",
                                            lineage=("ingest", "redact"), validation_passed=True))


def test_feature_needs_leakage_check_and_consumers():
    with pytest.raises(DataGovernanceError):
        assert_feature_governed(FeatureDefinition(name="f", owner="o", source="s",
                                                  freshness_seconds=60, retention_seconds=600,
                                                  leakage_checked=False, allowed_consumers=("m",)))


# --- flink (§11, acceptance #35) ----------------------------------------------
def _flink(**kw) -> FlinkJobManifest:
    base = dict(name="corr", source_version="1", artifact_digest=DIGEST,
                input_topics=("events",), output_topics=("signals",), state_schema_version=1,
                checkpoint_interval_seconds=30, resource_limits=FlinkResourceLimits(task_slots=2, memory_mb=512),
                replay_tests_passed=True)
    base.update(kw)
    return FlinkJobManifest(**base)


def test_flink_job_valid():
    assert_flink_job_valid(_flink())


def test_flink_job_without_replay_tests_refused():
    with pytest.raises(FlinkJobError):
        assert_flink_job_valid(_flink(replay_tests_passed=False))


def test_flink_job_granting_authority_refused():
    with pytest.raises(FlinkJobError):
        assert_flink_job_valid(_flink(grants_authority=True))


# --- wasm (§28, acceptance #34) -----------------------------------------------
def _wasm(**kw) -> WasmModuleManifest:
    base = dict(name="redactor", digest=DIGEST, declared_imports=("redact", "log"),
                memory_limit_bytes=1_000_000, fuel_limit=1_000_000, timeout_ms=500,
                output_limit_bytes=100_000, input_schema_ref="i", output_schema_ref="o")
    base.update(kw)
    return WasmModuleManifest(**base)


def test_wasm_module_within_limits_is_safe():
    assert_wasm_safe(_wasm())


def test_wasm_network_request_refused():
    with pytest.raises(WasmExtensionError):
        assert_wasm_safe(_wasm(allow_network=True))


def test_wasm_unknown_import_refused():
    with pytest.raises(WasmExtensionError):
        assert_wasm_safe(_wasm(declared_imports=("socket_open",)))


def test_wasm_high_risk_scanner_refused():
    with pytest.raises(WasmExtensionError):
        assert_wasm_safe(_wasm(high_risk_scanner=True))
