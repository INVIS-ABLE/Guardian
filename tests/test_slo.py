"""Level 6 §9: SLOs, error-budget burn, and the availability-vs-privacy safety gate."""

from __future__ import annotations

from adaptive.slo import (
    SLO,
    BurnSeverity,
    EffectDirection,
    SLOKind,
    SLORegistry,
    compute_burn,
    evaluate_repair_safety,
)


def _avail() -> SLO:
    return SLO(name="relay-availability", service="message-relay",
               kind=SLOKind.AVAILABILITY, objective=0.999, window_seconds=2_592_000)


# --- definitions / registry ----------------------------------------------------
def test_privacy_slo_is_marked_critical():
    slo = SLO(name="relay-privacy", service="message-relay",
              kind=SLOKind.PRIVACY_INVARIANT, objective=1.0, window_seconds=86_400)
    assert slo.is_privacy_critical is True
    assert _avail().is_privacy_critical is False


def test_registry_finds_critical_services_without_slo():
    reg = SLORegistry([_avail()])
    missing = reg.services_without_slo(["message-relay", "key-directory"])
    assert missing == ["key-directory"]


# --- burn rates ----------------------------------------------------------------
def test_healthy_service_has_low_burn():
    r = compute_burn(_avail(), achieved_ratio=1.0)
    assert r.burn_rate == 0.0
    assert r.severity is BurnSeverity.OK
    assert r.exhausted is False


def test_fast_burn_is_critical():
    # objective 0.999 -> budget 0.001; achieved 0.98 -> bad 0.02 -> burn 20x
    r = compute_burn(_avail(), achieved_ratio=0.98)
    assert r.burn_rate > 14.0
    assert r.severity is BurnSeverity.CRITICAL
    assert r.exhausted is True


def test_zero_tolerance_objective_exhausts_on_any_bad_event():
    slo = SLO(name="x-tenant", service="s", kind=SLOKind.CROSS_TENANT_ACCESS,
              objective=1.0, window_seconds=86_400)
    ok = compute_burn(slo, achieved_ratio=1.0)
    assert ok.exhausted is False and ok.severity is BurnSeverity.OK
    bad = compute_burn(slo, achieved_ratio=0.999)
    assert bad.exhausted is True and bad.severity is BurnSeverity.CRITICAL


# --- safety gate (§9) ----------------------------------------------------------
def test_availability_gain_that_weakens_privacy_is_rejected():
    verdict = evaluate_repair_safety({
        SLOKind.AVAILABILITY: EffectDirection.IMPROVE,
        SLOKind.PRIVACY_INVARIANT: EffectDirection.REGRESS,
    })
    assert verdict.allowed is False
    assert SLOKind.PRIVACY_INVARIANT in verdict.weakened_invariants


def test_pure_availability_improvement_is_allowed():
    verdict = evaluate_repair_safety({SLOKind.AVAILABILITY: EffectDirection.IMPROVE})
    assert verdict.allowed is True


def test_encryption_downgrade_regression_rejected_even_with_many_gains():
    verdict = evaluate_repair_safety({
        SLOKind.AVAILABILITY: EffectDirection.IMPROVE,
        SLOKind.LATENCY: EffectDirection.IMPROVE,
        SLOKind.ENCRYPTION_DOWNGRADE: EffectDirection.REGRESS,
    })
    assert verdict.allowed is False
    assert SLOKind.ENCRYPTION_DOWNGRADE in verdict.weakened_invariants


def test_regressing_non_critical_slo_is_allowed_by_this_gate():
    # Latency regression is not a privacy invariant; this gate allows it (others decide).
    verdict = evaluate_repair_safety({SLOKind.LATENCY: EffectDirection.REGRESS})
    assert verdict.allowed is True
