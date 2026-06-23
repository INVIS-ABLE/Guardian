"""Wave 3 seam — running a sealed ExecutionJob through the guarded executor.

Acceptance: a typed ``ExecutionJob`` (Wave 1) drives the Wave 2 executor through the one
guarded path; the job's content-addressed inputs bind the capability token; unknown
capabilities yield a structured refusal, not an exception.
"""

from __future__ import annotations

from uuid import uuid4

from core.schemas.execution import ArtifactRef, ExecutionJob
from core.tools.executor import ToolExecution, ToolExecutor
from core.tools.jobs import run_execution_job
from core.tools.registry import RefusalReason, ToolRefusal, default_registry


def _job(capability: str, **over) -> ExecutionJob:
    base = dict(case_id=uuid4(), tool_id="semgrep", capability=capability, args={"config": "auto"})
    base.update(over)
    return ExecutionJob(**base)


def test_run_job_executes_through_executor():
    ex = ToolExecutor(default_registry())
    out = run_execution_job(ex, _job("static_code_scan"), environment="staging")
    assert isinstance(out, ToolExecution)
    assert out.tool == "semgrep"
    assert out.capability == "static_code_scan"


def test_unknown_capability_job_refuses():
    ex = ToolExecutor(default_registry())
    out = run_execution_job(ex, _job("does-not-exist"), environment="staging")
    assert isinstance(out, ToolRefusal)
    assert out.reason is RefusalReason.UNKNOWN_CAPABILITY


def test_job_input_artifacts_bind_the_token():
    # Two jobs with different input artifacts must mint distinct tokens (different binding),
    # so both can run without a token-reuse refusal.
    ex = ToolExecutor(default_registry())
    art = ArtifactRef(artifact_id="sbom", sha256="sha256:" + "a" * 64)
    out1 = run_execution_job(ex, _job("static_code_scan", input_artifacts=(art,)),
                             environment="staging")
    out2 = run_execution_job(ex, _job("static_code_scan"), environment="staging")
    assert isinstance(out1, ToolExecution) and isinstance(out2, ToolExecution)
    assert out1.token_id != out2.token_id


def test_credentials_stay_references_on_the_job():
    # The job carries credential *references*, never secrets; the bridge passes none through.
    job = _job("static_code_scan", credential_refs=("vault://ci/semgrep-token",))
    assert job.credential_refs == ("vault://ci/semgrep-token",)
    ex = ToolExecutor(default_registry())
    out = run_execution_job(ex, job, environment="staging")
    assert isinstance(out, ToolExecution)
