"""Wave 1 acceptance: canonical schemas, JSON-Schema export, and compat adapters.

Covers the build-directive Wave 1 acceptance criteria:
  * every canonical schema produces a valid JSON Schema, and the committed
    ``schemas/<name>-v1.json`` files stay in sync (export determinism),
  * the new ``CaseEvent`` envelope round-trips and is content-addressable,
  * backward-compatibility adapters lift the legacy ``RouteResult`` and
    ``ConnectorResult`` shapes into ``CaseEvent`` without changing the legacy types.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from core import schemas
from core.schemas.registry import REPO_ROOT, all_json_schemas

SCHEMAS_DIR = REPO_ROOT / "schemas"


def test_registry_is_non_empty_and_named() -> None:
    names = schemas.schema_names()
    assert names, "registry must expose canonical schemas"
    # the genuinely-new envelope and a few authoritative re-exports must be present
    for expected in ("case_event", "finding", "evidence_item", "guardian_case_state",
                     "tool_manifest", "verification_result"):
        assert expected in names, f"{expected} missing from canonical registry"


def test_every_schema_produces_valid_json_schema() -> None:
    for name, schema in all_json_schemas().items():
        assert isinstance(schema, dict) and schema, f"{name} produced no JSON Schema"
        assert "type" in schema or "$ref" in schema or "properties" in schema, name


def test_committed_json_schemas_are_in_sync(tmp_path) -> None:
    # Export to a temp dir and compare with the committed schemas/ files.
    written = schemas.export_json_schemas(out_dir=tmp_path)
    assert written, "export wrote nothing"
    for path in written:
        committed = SCHEMAS_DIR / path.name
        assert committed.exists(), f"missing committed schema {path.name} (run export)"
        assert json.loads(committed.read_text()) == json.loads(path.read_text()), (
            f"{path.name} drifted — regenerate with core.schemas.export_json_schemas()"
        )


def test_case_event_round_trips() -> None:
    ev = schemas.CaseEvent.create(
        event_type="guardian.case.created",
        actor="steward",
        payload={"z": 1, "a": {"nested": True}},
        case_id=uuid4(),
        trace_id="trace-123",
    )
    restored = schemas.CaseEvent.model_validate(json.loads(ev.model_dump_json()))
    assert restored == ev


def test_case_event_payload_hash_is_canonical_and_order_independent() -> None:
    a = schemas.CaseEvent.create(event_type="e", actor="x", payload={"a": 1, "b": 2})
    b = schemas.CaseEvent.create(event_type="e", actor="x", payload={"b": 2, "a": 1})
    assert a.payload_sha256 == b.payload_sha256
    assert a.payload_intact() and b.payload_intact()


def test_case_event_detects_tampering() -> None:
    ev = schemas.CaseEvent.create(event_type="e", actor="x", payload={"k": "v"})
    tampered = ev.model_copy(update={"payload": {"k": "evil"}})
    assert not tampered.payload_intact()


def test_case_event_signature_preserves_payload_hash() -> None:
    ev = schemas.CaseEvent.create(event_type="e", actor="x", payload={"k": "v"})
    signed = ev.signed("sig:abc")
    assert signed.signature == "sig:abc"
    assert signed.payload_sha256 == ev.payload_sha256
    assert signed.payload_intact()


def test_case_event_is_frozen() -> None:
    ev = schemas.CaseEvent.create(event_type="e", actor="x")
    with pytest.raises(Exception):
        ev.actor = "someone-else"  # type: ignore[misc]


def test_route_result_adapter_completed() -> None:
    from core.router import RouteResult

    rr = RouteResult(capability="static_code", kind="connector", tool="semgrep",
                     allowed=True, dry_run=True, output={"findings": []})
    ev = schemas.route_result_to_event(rr, trace_id="t1")
    assert ev.event_type == "guardian.tool.completed"
    assert ev.actor == "tool-router"
    assert ev.trace_id == "t1"
    assert ev.payload["capability"] == "static_code"
    assert "tool:semgrep" in ev.asset_refs
    assert ev.payload_intact()


def test_route_result_adapter_refused() -> None:
    from core.router import RouteResult

    rr = RouteResult(capability="dast", kind="connector", tool="zap",
                     allowed=False, dry_run=True, refusal_reason="out of scope")
    ev = schemas.route_result_to_event(rr)
    assert ev.event_type == "guardian.tool.refused"
    assert ev.payload["refusal_reason"] == "out of scope"


def test_connector_result_adapter() -> None:
    from connectors.base import ConnectorResult

    cr = ConnectorResult(tool="gitleaks", command=["gitleaks", "detect"], dry_run=True,
                         findings=[{"rule": "aws-key"}], note="dry-run")
    ev = schemas.connector_result_to_event(cr, case_id=uuid4())
    assert ev.event_type == "guardian.tool.connector"
    assert ev.actor == "connector:gitleaks"
    assert ev.payload["findings"] == [{"rule": "aws-key"}]
    assert ev.payload_intact()


def test_adapters_do_not_mutate_legacy_types() -> None:
    # The legacy RouteResult.to_dict() shape is unchanged by adaptation.
    from core.router import RouteResult

    rr = RouteResult(capability="secrets", kind="connector", tool="gitleaks",
                     allowed=True, dry_run=False)
    before = rr.to_dict()
    schemas.route_result_to_event(rr)
    assert rr.to_dict() == before


# --- Wave 1 slice 2: execution / decision / remediation / approval / bundle ----------

def test_execution_job_round_trip_and_secret_free() -> None:
    from uuid import uuid4

    job = schemas.ExecutionJob(
        case_id=uuid4(), tool_id="semgrep", capability="code.sast",
        args={"config": "auto"}, execution_profile="scanner-standard", timeout_seconds=600,
    )
    assert schemas.ExecutionJob.model_validate(json.loads(job.model_dump_json())) == job
    # credentials are references, never inline secrets
    assert job.credential_refs == ()


def test_artifact_ref_requires_sha256_form() -> None:
    with pytest.raises(Exception):
        schemas.ArtifactRef(artifact_id="a", sha256="not-a-hash")
    ok = schemas.ArtifactRef(artifact_id="a", sha256="sha256:" + "0" * 64)
    assert ok.sha256.startswith("sha256:")


def test_guardian_decision_is_capability_not_command() -> None:
    d = schemas.GuardianDecision(
        objective="investigate", selected_capability="secret.scan",
        arguments={"path": "."}, confidence=0.8, requires_approval=False,
    )
    assert d.selected_capability == "secret.scan"
    assert "command" not in d.model_dump()  # the model never carries a raw command
    assert schemas.GuardianDecision.model_validate(json.loads(d.model_dump_json())) == d


def test_guardian_decision_terminal() -> None:
    stop = schemas.GuardianDecision(objective="done", selected_capability=None,
                                    stop_reason="sufficient evidence")
    assert stop.is_terminal() is True


def test_guardian_decision_rejects_out_of_range_confidence() -> None:
    with pytest.raises(Exception):
        schemas.GuardianDecision(objective="x", confidence=1.5)


def test_remediation_option_round_trip() -> None:
    from uuid import uuid4

    opt = schemas.RemediationOption(
        case_id=uuid4(), title="bump lodash", strategy="dependency-bump",
        changes=(schemas.CodeChange(path="package.json", additions=1, deletions=1),),
        risk="low", rollback="revert the bump", confidence=0.9,
    )
    assert schemas.RemediationOption.model_validate(json.loads(opt.model_dump_json())) == opt


def test_approval_satisfaction_requires_distinct_quorum() -> None:
    from uuid import uuid4

    cid = uuid4()
    assert not schemas.Approval(case_id=cid, action="a", approvers=("x",), required_approvers=2,
                                granted=True).is_satisfied()
    assert not schemas.Approval(case_id=cid, action="a", approvers=("x", "x"),
                                required_approvers=2, granted=True).is_satisfied()
    assert schemas.Approval(case_id=cid, action="a", approvers=("x", "y"),
                            required_approvers=2, granted=True).is_satisfied()
    # not granted -> never satisfied
    assert not schemas.Approval(case_id=cid, action="a", approvers=("x", "y"),
                                required_approvers=2, granted=False).is_satisfied()


def test_evidence_bundle_merkle_root_and_tamper() -> None:
    from uuid import uuid4

    h = ["sha256:" + c * 64 for c in "abc"]
    bundle = schemas.EvidenceBundle.create(case_id=uuid4(), evidence_ids=("e1", "e2", "e3"),
                                           evidence_sha256=tuple(h))
    assert bundle.root_intact()
    # order independence
    h2 = list(reversed(h))
    other = schemas.EvidenceBundle.create(case_id=bundle.case_id, evidence_ids=("e3", "e2", "e1"),
                                          evidence_sha256=tuple(h2))
    assert bundle.merkle_root == other.merkle_root
    # tamper detection
    tampered = bundle.model_copy(update={"evidence_sha256": ("sha256:" + "f" * 64,)})
    assert not tampered.root_intact()


def test_evidence_bundle_signature_preserves_root() -> None:
    from uuid import uuid4

    b = schemas.EvidenceBundle.create(case_id=uuid4(), evidence_ids=("e1",),
                                      evidence_sha256=("sha256:" + "a" * 64,))
    signed = b.signed("sig:xyz", attestation_uri="dsse://att")
    assert signed.signature == "sig:xyz" and signed.attestation_uri == "dsse://att"
    assert signed.merkle_root == b.merkle_root and signed.root_intact()
