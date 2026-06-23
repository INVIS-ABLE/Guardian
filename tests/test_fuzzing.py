"""Tests for the continuous fuzzing farm (Sovereign plane, Wave 3, system #14)."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.fuzzing import (
    CrashKind,
    CrashObservation,
    FuzzError,
    FuzzFarm,
    FuzzTarget,
    Severity,
    build_from_spec,
    from_clusterfuzz,
    load_campaign,
)

CAMPAIGN = Path(__file__).resolve().parent.parent / "fuzzing" / "invisable-fuzz-campaign.yaml"


def _target(tid="fuzz:t") -> FuzzTarget:
    return FuzzTarget(id=tid, name="T", surface="parser")


def _crash(tid="fuzz:t", sig="s", sev=Severity.MEDIUM, h="sha256:1") -> CrashObservation:
    return CrashObservation(target_id=tid, signature=sig, kind=CrashKind.CRASH, input_hash=h, severity=sev)


def test_dedup_by_signature_keeps_worst_severity():
    farm = FuzzFarm([_target()])
    report = farm.report("c", [
        _crash(sig="bug-A", sev=Severity.HIGH, h="sha256:1"),
        _crash(sig="bug-A", sev=Severity.CRITICAL, h="sha256:2"),
        _crash(sig="bug-A", sev=Severity.LOW, h="sha256:3"),
    ])
    assert report.observations == 3
    assert len(report.unique_crashes) == 1
    u = report.unique_crashes[0]
    assert u.occurrences == 3
    assert u.severity is Severity.CRITICAL      # worst severity wins
    assert u.seed_hash == "sha256:1"            # first input is the regression seed


def test_regression_seed_per_unique_crash():
    farm = FuzzFarm([_target("fuzz:a"), _target("fuzz:b")])
    report = farm.report("c", [_crash("fuzz:a", "x"), _crash("fuzz:b", "y")])
    assert len(report.unique_crashes) == 2
    assert len(report.regression_seeds) == 2
    assert report.has_new_crash


def test_crash_for_unknown_target_refused():
    farm = FuzzFarm([_target("fuzz:a")])
    with pytest.raises(FuzzError):
        farm.report("c", [_crash("fuzz:ghost", "x")])


def test_duplicate_target_refused():
    with pytest.raises(FuzzError):
        FuzzFarm([_target("dup"), _target("dup")])


def test_empty_campaign_passes_gate():
    report = FuzzFarm([_target()]).report("c", [])
    assert not report.has_new_crash
    assert report.regression_seeds == ()


# --- sample --------------------------------------------------------------------
def test_sample_dedups_envelope_bug():
    report = load_campaign(CAMPAIGN)
    # Three envelope observations collapse to one unique crash; 3 unique overall.
    assert report.observations == 5
    assert len(report.unique_crashes) == 3
    env = next(c for c in report.unique_crashes if c.target_id == "fuzz:crypto-envelope")
    assert env.occurrences == 3 and env.severity is Severity.CRITICAL
    assert report.has_new_crash


def test_build_from_spec_and_severity_filter():
    report = build_from_spec({
        "campaign": "c",
        "targets": [{"id": "fuzz:t", "name": "T", "surface": "p"}],
        "crashes": [
            {"target_id": "fuzz:t", "signature": "a", "kind": "crash", "input_hash": "h1", "severity": "critical"},
            {"target_id": "fuzz:t", "signature": "b", "kind": "timeout", "input_hash": "h2", "severity": "low"},
        ],
    })
    assert len(report.of_severity(Severity.CRITICAL)) == 1


def test_from_clusterfuzz_fails_closed():
    with pytest.raises(NotImplementedError):
        from_clusterfuzz()


def test_load_campaign_missing_file():
    with pytest.raises(FileNotFoundError):
        load_campaign(Path("/no/such/c.yaml"))
