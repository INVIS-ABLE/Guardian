"""Tests for the endpoint intelligence fabric (Sovereign plane, Wave 1, system #4).

These exercise the real signature-enforcement path using runtime-generated keys, so they hold
under either signing backend (Ed25519 or the HMAC fallback) — see core/signing.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.endpoint import (
    EndpointError,
    EndpointFabric,
    OsqueryQuery,
    PackSignature,
    QueryPack,
    UnapprovedQueryError,
    build_from_spec,
    from_fleet,
    load_reviewed_packs,
    seal_and_admit,
    sign_pack,
)
from core.signing import generate_keypair

SAMPLE = Path(__file__).resolve().parent.parent / "endpoint" / "invisable-packs.yaml"


def _pack(author="eng", reviewer="lead", sql="SELECT pid, port FROM listening_ports") -> QueryPack:
    return QueryPack(
        id="pack:test", name="Test", author=author, reviewed_by=reviewer,
        queries=(OsqueryQuery(name="ports", query=sql),),
    )


# --- models / read-only invariant ----------------------------------------------
def test_query_must_be_read_only():
    with pytest.raises(ValueError):
        OsqueryQuery(name="bad", query="DROP TABLE processes")
    with pytest.raises(ValueError):
        OsqueryQuery(name="bad", query="UPDATE config SET x = 1")
    # SELECT and WITH are accepted.
    assert OsqueryQuery(name="ok", query="WITH t AS (SELECT 1) SELECT * FROM t")


def test_pack_requires_queries_and_unique_names():
    with pytest.raises(ValueError):
        QueryPack(id="p", name="p", author="a", reviewed_by="b", queries=())
    with pytest.raises(ValueError):
        QueryPack(id="p", name="p", author="a", reviewed_by="b", queries=(
            OsqueryQuery(name="dup", query="SELECT 1"),
            OsqueryQuery(name="dup", query="SELECT 2"),
        ))


# --- admission (the gate) ------------------------------------------------------
def test_admit_accepts_correctly_signed_reviewed_pack():
    kp = generate_keypair()
    fabric = EndpointFabric({"rev": kp.public})
    pack = _pack()
    fabric.admit(pack, sign_pack(pack, kp.private, "rev"))
    assert pack.id in fabric
    assert fabric.admitting_key(pack.id) == "rev"


def test_admit_refuses_untrusted_key():
    kp = generate_keypair()
    fabric = EndpointFabric({"rev": kp.public})
    pack = _pack()
    sig = PackSignature(key_id="someone-else", signature=sign_pack(pack, kp.private, "rev").signature)
    with pytest.raises(EndpointError, match="untrusted key"):
        fabric.admit(pack, sig)


def test_admit_refuses_tampered_content():
    kp = generate_keypair()
    fabric = EndpointFabric({"rev": kp.public})
    pack = _pack(sql="SELECT pid, port FROM listening_ports")
    sig = sign_pack(pack, kp.private, "rev")
    # Same id/signature, but the queries were changed after signing — must not verify.
    tampered = QueryPack(id=pack.id, name=pack.name, author=pack.author, reviewed_by=pack.reviewed_by,
                         queries=(OsqueryQuery(name="ports", query="SELECT * FROM shadow"),))
    with pytest.raises(EndpointError, match="does not verify"):
        fabric.admit(tampered, sig)


def test_admit_refuses_author_as_own_reviewer():
    kp = generate_keypair()
    fabric = EndpointFabric({"rev": kp.public})
    pack = _pack(author="same", reviewer="same")
    with pytest.raises(EndpointError, match="separation of duties"):
        fabric.admit(pack, sign_pack(pack, kp.private, "rev"))


def test_admit_refuses_duplicate_pack():
    kp = generate_keypair()
    fabric = EndpointFabric({"rev": kp.public})
    pack = _pack()
    fabric.admit(pack, sign_pack(pack, kp.private, "rev"))
    with pytest.raises(EndpointError, match="duplicate"):
        fabric.admit(pack, sign_pack(pack, kp.private, "rev"))


# --- vetting (the core refusal) ------------------------------------------------
def test_vet_approves_member_query_and_refuses_adhoc():
    fabric = seal_and_admit(load_reviewed_packs(SAMPLE))
    approved = fabric.vet_query("SELECT pid, port, protocol, address FROM listening_ports")
    assert approved.approved is True
    assert approved.pack == "pack:integrity-monitoring"
    adhoc = fabric.vet_query("SELECT * FROM shadow")
    assert adhoc.approved is False
    assert "refused" in adhoc.reason


def test_vet_tolerates_whitespace_but_not_changes():
    fabric = seal_and_admit(load_reviewed_packs(SAMPLE))
    # Extra whitespace and a trailing semicolon still match the approved query.
    assert fabric.vet_query("SELECT  pid, port, protocol, address   FROM listening_ports;").approved
    # A changed column list is a different query — refused.
    assert not fabric.vet_query("SELECT pid FROM listening_ports").approved


def test_require_raises_on_unapproved():
    fabric = seal_and_admit(load_reviewed_packs(SAMPLE))
    pack_id, name = fabric.require("SELECT username, tty, host, time FROM last")
    assert (pack_id, name) == ("pack:identity-hygiene", "last_logins")
    with pytest.raises(UnapprovedQueryError):
        fabric.require("SELECT * FROM processes")


def test_schedule_is_built_from_admitted_packs_only():
    fabric = seal_and_admit(load_reviewed_packs(SAMPLE))
    schedule = fabric.schedule()
    assert "pack:integrity-monitoring.listening_ports" in schedule
    assert schedule["pack:integrity-monitoring.kernel_modules"]["platform"] == "linux"
    # Every scheduled query is a read-only SELECT/WITH.
    assert all(str(v["query"]).lstrip().lower().startswith(("select", "with"))
               for v in schedule.values())


# --- ingestion seam ------------------------------------------------------------
def test_build_from_spec_admits_with_signatures():
    kp = generate_keypair()
    pack = _pack()
    sig = sign_pack(pack, kp.private, "rev")
    fabric = build_from_spec({
        "trusted_reviewers": {"rev": kp.public},
        "packs": [{"pack": pack.model_dump(mode="json"),
                   "signature": sig.model_dump(mode="json")}],
    })
    assert pack.id in fabric


def test_sample_loads_and_seals():
    packs = load_reviewed_packs(SAMPLE)
    assert {p.id for p in packs} == {"pack:integrity-monitoring", "pack:identity-hygiene"}
    fabric = seal_and_admit(packs)
    assert len(fabric) == 2


def test_from_fleet_fails_closed():
    with pytest.raises(NotImplementedError):
        from_fleet()


def test_load_reviewed_packs_missing_file():
    with pytest.raises(FileNotFoundError):
        load_reviewed_packs(Path("/no/such/packs.yaml"))
