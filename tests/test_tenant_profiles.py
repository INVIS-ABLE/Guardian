"""Tenant profile loading (Phase E): INVISABLE as an explicit, auditable tenant."""

from __future__ import annotations

import pytest

from core.tenancy import (
    INVISABLE_TENANT_ID,
    DeploymentMode,
    TenantProfileError,
    TenantStatus,
    load_tenant,
    load_tenant_registry,
    tenant_from_dict,
)

PROFILE = "tenants/invisable.yaml"


# --- the committed INVISABLE profile ------------------------------------------
def test_invisable_profile_loads_as_first_class_tenant():
    t = load_tenant(PROFILE)
    assert t.tenant_id == INVISABLE_TENANT_ID
    assert t.legal_name == "INVISABLE"
    assert t.deployment_mode == DeploymentMode.SINGLE_TENANT_SELF_HOSTED
    assert t.status == TenantStatus.ACTIVE
    assert t.active is True
    assert t.administrators  # has at least one administrator


def test_registry_includes_invisable():
    reg = load_tenant_registry()
    inv = reg.get(INVISABLE_TENANT_ID)
    assert inv is not None and inv.legal_name == "INVISABLE"


# --- loader fail-closed behaviour ---------------------------------------------
def test_missing_profile_fails_closed(tmp_path):
    with pytest.raises(TenantProfileError):
        load_tenant(tmp_path / "nope.yaml")


def test_profile_without_tenant_mapping_fails_closed(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("schema_version: 1\n", encoding="utf-8")
    with pytest.raises(TenantProfileError):
        load_tenant(p)


def test_unknown_deployment_mode_fails_closed():
    with pytest.raises(TenantProfileError):
        tenant_from_dict({"tenant_id": "x", "deployment_mode": "warp_drive"})


def test_missing_tenant_id_fails_closed():
    with pytest.raises(TenantProfileError):
        tenant_from_dict({"legal_name": "No Id"})


def test_a_loaded_profile_can_be_suspended():
    t = tenant_from_dict({"tenant_id": "acme", "status": "suspended"})
    assert t.status == TenantStatus.SUSPENDED
    assert t.active is False


# --- registry builds from a directory of profiles -----------------------------
def test_registry_loads_extra_tenant_from_dir(tmp_path):
    (tmp_path / "globex.yaml").write_text(
        "tenant:\n"
        "  tenant_id: globex\n"
        "  legal_name: Globex Corp\n"
        "  deployment_mode: multi_tenant_saas\n"
        "  status: active\n",
        encoding="utf-8",
    )
    reg = load_tenant_registry(tmp_path)
    assert INVISABLE_TENANT_ID in reg            # always seeded
    g = reg.get("globex")
    assert g is not None and g.deployment_mode == DeploymentMode.MULTI_TENANT_SAAS


def test_missing_dir_returns_seeded_registry(tmp_path):
    reg = load_tenant_registry(tmp_path / "absent")
    assert INVISABLE_TENANT_ID in reg
