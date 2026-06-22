"""Tests for the Guardian memory/RAG layer."""

from __future__ import annotations

import pytest

from core.memory import GuardianMemory, InMemoryBackend, cosine, get_backend, hash_embed


@pytest.fixture()
def memory(tmp_path):
    return GuardianMemory(backend=InMemoryBackend(store_dir=tmp_path))


def test_remember_and_search_roundtrip(memory):
    memory.remember("threat_models", "account takeover via credential stuffing")
    memory.remember("threat_models", "grooming risk in unmoderated chat")
    hits = memory.search("threat_models", "credential stuffing attack", top_k=1)
    assert hits
    assert "credential stuffing" in hits[0].record.text


def test_unknown_collection_is_refused(memory):
    with pytest.raises(ValueError):
        memory.remember("not_a_real_collection", "x")


def test_secrets_are_scrubbed_before_storage(memory):
    rec = memory.remember("run_outcomes", "leak: password=SuperSecret123 in config")
    assert "SuperSecret123" not in rec.text
    assert "[REDACTED]" in rec.text


def test_metadata_is_scrubbed(memory):
    rec = memory.remember("run_outcomes", "finding", metadata={"token": "ghp_" + "a" * 36})
    assert "ghp_" not in str(rec.metadata)


def test_persistence_across_instances(tmp_path):
    m1 = GuardianMemory(backend=InMemoryBackend(store_dir=tmp_path))
    m1.remember("policies", "all fixes ship as draft pull requests")
    m2 = GuardianMemory(backend=InMemoryBackend(store_dir=tmp_path))
    assert m2.count("policies") == 1
    hits = m2.search("policies", "how are fixes shipped", top_k=1)
    assert hits and "draft pull requests" in hits[0].record.text


def test_remember_finding_summarises(memory):
    rec = memory.remember_finding(
        {"tool": "semgrep", "rule": "sql-injection", "severity": "high", "message": "tainted query"}
    )
    assert "semgrep" in rec.text and "sql-injection" in rec.text


def test_hash_embed_is_unit_normalised():
    v = hash_embed("guardian defensive security")
    assert abs(cosine(v, v) - 1.0) < 1e-6


# --- backend fail-closed by deployment posture (mirrors the policy gate) -------
def test_get_backend_falls_back_in_development(monkeypatch):
    monkeypatch.delenv("GUARDIAN_REQUIRE_VECTOR_BACKEND", raising=False)
    monkeypatch.setenv("GUARDIAN_ENV", "development")
    assert isinstance(get_backend(), InMemoryBackend)


def test_get_backend_fails_closed_in_production(monkeypatch):
    # In a production posture an unavailable approved backend must NOT silently fall back.
    monkeypatch.delenv("GUARDIAN_REQUIRE_VECTOR_BACKEND", raising=False)
    monkeypatch.setenv("GUARDIAN_ENV", "production")
    with pytest.raises(RuntimeError, match="fail closed"):
        get_backend()


def test_get_backend_explicit_require_overrides_posture(monkeypatch):
    monkeypatch.delenv("GUARDIAN_ENV", raising=False)
    monkeypatch.setenv("GUARDIAN_REQUIRE_VECTOR_BACKEND", "1")
    with pytest.raises(RuntimeError, match="fail closed"):
        get_backend()
