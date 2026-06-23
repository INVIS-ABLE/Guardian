"""ExecutionJob → executor bridge (Wave 3 — execution workers, seam to Wave 1/2).

An execution worker is handed a sealed :class:`~core.schemas.execution.ExecutionJob` —
the secret-free, content-addressed description of one tool call produced upstream — and
must run it through the one guarded path to a tool: the :class:`ToolExecutor`. This
module is that bridge. It deliberately does **not** invent a second execution path; it
unseals the job into the executor's call and returns the executor's typed result (or its
structured refusal). Real isolated execution still depends on a configured sandbox
runner behind the same ``ToolRunner`` interface — without one the executor fails closed
to a dry-run, exactly as before.
"""

from __future__ import annotations

from ..roots_of_trust import TrustContext
from core.schemas.execution import ExecutionJob

from .executor import ToolExecution, ToolExecutor
from .registry import ToolRefusal


def run_execution_job(
    executor: ToolExecutor,
    job: ExecutionJob,
    *,
    environment: str,
    approved: bool = False,
    trust: TrustContext | None = None,
) -> ToolExecution | ToolRefusal:
    """Run a sealed ExecutionJob through the guarded executor.

    The job's content-addressed ``input_artifacts`` become the executor's bound input
    hashes, so the minted capability token is tied to the exact inputs. Credentials are
    *references* on the job and are never materialised here — the executor/sandbox broker
    resolves them. Returns the executor's ``ToolExecution`` or a structured ``ToolRefusal``.
    """
    return executor.execute(
        job.capability,
        case_id=job.case_id,
        args=job.args,
        environment=environment,
        approved=approved,
        input_artifact_hashes=tuple(a.sha256 for a in job.input_artifacts),
        trust=trust,
    )


__all__ = ["run_execution_job"]
