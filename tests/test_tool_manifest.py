"""Tests for the signed tool-manifest gateway (build-order step 5)."""

from __future__ import annotations

from uuid import uuid4


from core.tools import (
    DryRunRunner,
    RefusalReason,
    ResourceLimits,
    ToolExecution,
    ToolExecutor,
    ToolManifest,
    ToolRefusal,
    ToolRegistry,
    TokenStore,
    default_registry,
    hash_args,
    issue_token,
    sign_manifest,
)
from core.tools.manifest import SignedManifest


def _manifest(capability="static_code_scan", *, envs=("development", "staging"),
              approval=False) -> ToolManifest:
    return ToolManifest(
        capability=capability, tool="semgrep", image_digest="sha256:" + "a" * 64,
        input_schema="schemas/in.json", output_schema="schemas/out.json",
        allowed_environments=envs, requires_approval=approval,
    )


# --- manifest signing ---------------------------------------------------------
def test_manifest_hash_is_deterministic():
    m = _manifest()
    assert m.manifest_hash() == _manifest().manifest_hash()


def test_sign_and_verify_roundtrip():
    signed = sign_manifest(_manifest())
    assert signed.verify() is True


def test_tampered_manifest_fails_verification():
    signed = sign_manifest(_manifest())
    forged = SignedManifest(
        manifest=signed.manifest.model_copy(update={"tool": "evil-tool"}),
        signature=signed.signature,
    )
    assert forged.verify() is False


# --- registry resolution (structured refusals) --------------------------------
def test_resolve_known_capability():
    reg = ToolRegistry([sign_manifest(_manifest())])
    m = reg.resolve("static_code_scan", environment="staging")
    assert isinstance(m, ToolManifest) and m.tool == "semgrep"


def test_unknown_capability_is_structured_refusal_not_exception():
    reg = default_registry()
    result = reg.resolve("hallucinated_capability", environment="staging")
    assert isinstance(result, ToolRefusal)
    assert result.reason is RefusalReason.UNKNOWN_CAPABILITY


def test_environment_not_allowed_is_refused():
    reg = ToolRegistry([sign_manifest(_manifest(envs=("staging",)))])
    result = reg.resolve("static_code_scan", environment="production")
    assert isinstance(result, ToolRefusal)
    assert result.reason is RefusalReason.ENVIRONMENT_NOT_ALLOWED


def test_forged_signature_refused_in_production_posture(monkeypatch):
    monkeypatch.setenv("GUARDIAN_ENV", "production")
    monkeypatch.setenv("GUARDIAN_MANIFEST_KEY", "real-key")
    # A manifest "signed" with the wrong signature must be refused when posture demands it.
    signed = SignedManifest(manifest=_manifest(), signature="deadbeef")
    reg = ToolRegistry([signed])
    result = reg.resolve("static_code_scan", environment="staging")
    assert isinstance(result, ToolRefusal)
    assert result.reason is RefusalReason.SIGNATURE_INVALID


# --- capability tokens (one-use, bound) ---------------------------------------
def test_token_binds_to_exact_call():
    m = _manifest()
    case = uuid4()
    token = issue_token(m, case_id=case, args={"target": "repo-a"}, environment="staging")
    assert token.matches(case_id=case, tool_digest=m.image_digest,
                         args_hash=hash_args({"target": "repo-a"}), environment="staging")
    # Different args do not match the token.
    assert not token.matches(case_id=case, tool_digest=m.image_digest,
                            args_hash=hash_args({"target": "repo-b"}), environment="staging")


def test_token_is_single_use():
    m = _manifest()
    token = issue_token(m, case_id=uuid4(), args={}, environment="staging")
    store = TokenStore()
    assert store.consume(token) is True
    assert store.consume(token) is False  # second use rejected


def test_expired_token_is_rejected():
    from datetime import datetime, timedelta, timezone

    m = _manifest()
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    token = issue_token(m, case_id=uuid4(), args={}, environment="staging",
                        ttl_seconds=1, now=past)
    assert TokenStore().consume(token) is False


# --- executor -----------------------------------------------------------------
def _executor() -> ToolExecutor:
    return ToolExecutor(default_registry())


def test_executor_runs_known_capability_dry_run():
    out = _executor().execute("static_code_scan", case_id=uuid4(), args={"target": "r"},
                              environment="staging")
    assert isinstance(out, ToolExecution)
    assert out.tool == "semgrep" and out.executed is False
    assert out.output_hash.startswith("sha256:")


def test_executor_refuses_unknown_capability():
    out = _executor().execute("not_a_capability", case_id=uuid4(), args={},
                              environment="staging")
    assert isinstance(out, ToolRefusal)
    assert out.reason is RefusalReason.UNKNOWN_CAPABILITY


def test_executor_requires_approval_for_gated_capability():
    ex = _executor()
    denied = ex.execute("password_strength", case_id=uuid4(), args={}, environment="staging")
    assert isinstance(denied, ToolRefusal)
    assert denied.reason is RefusalReason.APPROVAL_REQUIRED
    allowed = ex.execute("password_strength", case_id=uuid4(), args={},
                        environment="staging", approved=True)
    assert isinstance(allowed, ToolExecution)


def test_executor_output_is_bounded():
    # A tiny output-byte limit truncates the runner's output.
    tiny = _manifest()
    tiny = tiny.model_copy(update={"limits": ResourceLimits(output_bytes=10)})
    reg = ToolRegistry([sign_manifest(tiny)])

    class _Chatty(DryRunRunner):
        def run(self, manifest, token, args):
            from core.tools import RunOutput
            return RunOutput(text="x" * 1000, executed=False)

    out = ToolExecutor(reg, runner=_Chatty()).execute(
        "static_code_scan", case_id=uuid4(), args={}, environment="staging")
    assert isinstance(out, ToolExecution)
    assert out.truncated is True and len(out.output) <= 10
