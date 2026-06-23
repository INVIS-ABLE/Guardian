"""Wave 24 acceptance — Citadel Key Custody / Threshold Trust + Quorum (Systems 24 + 38).

Acceptance:
  * one identity cannot complete a root operation,
  * ceremony evidence verifies,
  * recovery operations need an offline recovery custodian (material outside the runtime plane),
  * the quorum can be independently re-verified.
"""

from __future__ import annotations

from core import signing
from citadel.quorum import (
    KeyCeremony,
    KeyClass,
    Participant,
    ParticipantRegistry,
    ParticipantRole,
    Proposal,
    RootOperation,
    ThresholdGate,
    build_result,
    cast_vote,
    independently_verify,
)

NOW = 1_000_000.0


def _participant(pid: str, role=ParticipantRole.CUSTODIAN, offline=False):
    kp = signing.generate_keypair()
    return Participant(participant_id=pid, public_key=kp.public, role=role, offline=offline), kp.private


def _proposal(op=RootOperation.ROOT_KEY_ROTATION, ttl=3600.0):
    return Proposal(
        proposal_id="prop-1", operation=op, target_digest="t" * 64, policy_digest="p" * 64,
        created_at=NOW, expires_at=NOW + ttl,
    )


def _registry(participants):
    reg = ParticipantRegistry()
    for p, _ in participants:
        reg.enrol(p)
    return reg


# --- acceptance: one identity cannot complete a root operation ---------------------------------
def test_single_identity_cannot_satisfy_threshold():
    parts = [_participant(f"c{i}") for i in range(3)]
    reg = _registry(parts)
    proposal = _proposal()  # root_key_rotation -> threshold 3
    gate = ThresholdGate(registry=reg)

    # one participant voting (even repeatedly) cannot satisfy a threshold of 3
    p0, priv0 = parts[0]
    gate.submit(proposal, cast_vote(p0, priv0, proposal), now=NOW)
    gate.submit(proposal, cast_vote(p0, priv0, proposal), now=NOW)  # duplicate collapses to one
    decision = gate.decide(proposal, now=NOW)
    assert decision.satisfied is False
    assert decision.distinct_approvers == 1


def test_threshold_met_by_distinct_participants():
    parts = [_participant(f"c{i}") for i in range(3)]
    reg = _registry(parts)
    proposal = _proposal()
    gate = ThresholdGate(registry=reg)
    for p, priv in parts:
        assert gate.submit(proposal, cast_vote(p, priv, proposal), now=NOW) is True
    decision = gate.decide(proposal, now=NOW)
    assert decision.satisfied is True and decision.distinct_approvers == 3


def test_credential_reuse_is_rejected_at_enrolment():
    p0, _ = _participant("c0")
    reg = ParticipantRegistry()
    reg.enrol(p0)
    clone = Participant(participant_id="c1", public_key=p0.public_key, role=ParticipantRole.CUSTODIAN)
    try:
        reg.enrol(clone)
        assert False, "credential reuse must be rejected"
    except ValueError:
        pass


# --- acceptance: expiry ------------------------------------------------------------------------
def test_votes_after_expiry_are_rejected():
    parts = [_participant(f"c{i}") for i in range(3)]
    reg = _registry(parts)
    proposal = _proposal(ttl=100.0)
    gate = ThresholdGate(registry=reg)
    p, priv = parts[0]
    assert gate.submit(proposal, cast_vote(p, priv, proposal), now=NOW + 200) is False
    assert gate.decide(proposal, now=NOW + 200).satisfied is False


# --- acceptance: recovery needs an offline recovery custodian ----------------------------------
def test_recovery_activation_requires_offline_recovery_custodian():
    # three runtime custodians, but recovery needs an OFFLINE recovery custodian in the quorum
    runtime = [_participant(f"c{i}") for i in range(3)]
    reg = _registry(runtime)
    proposal = _proposal(op=RootOperation.RECOVERY_ACTIVATION)  # threshold 3
    gate = ThresholdGate(registry=reg)
    for p, priv in runtime:
        gate.submit(proposal, cast_vote(p, priv, proposal), now=NOW)
    decision = gate.decide(proposal, now=NOW)
    assert decision.satisfied is False
    assert any("recovery" in r for r in decision.reasons)

    # add an offline recovery custodian and their vote -> now satisfied
    rc, rc_priv = _participant("rec", role=ParticipantRole.RECOVERY_CUSTODIAN, offline=True)
    reg.enrol(rc)
    gate.submit(proposal, cast_vote(rc, rc_priv, proposal), now=NOW)
    assert gate.decide(proposal, now=NOW).satisfied is True


# --- acceptance: ceremony evidence verifies ----------------------------------------------------
def test_ceremony_evidence_and_independent_verification():
    parts = [_participant(f"c{i}") for i in range(3)]
    reg = _registry(parts)
    proposal = _proposal()
    gate = ThresholdGate(registry=reg)
    votes = []
    for p, priv in parts:
        v = cast_vote(p, priv, proposal)
        votes.append(v)
        gate.submit(proposal, v, now=NOW)
    decision = gate.decide(proposal, now=NOW)

    ceremony = KeyCeremony(
        ceremony_id="cer-1", key_class=KeyClass.ROOT_SIGNING, proposal=proposal,
        decision=decision, participant_ids=tuple(p.participant_id for p, _ in parts),
        performed_at=NOW,
    )
    assert ceremony.ok and len(ceremony.evidence_digest) == 64

    result = build_result(ceremony)
    assert result.result == "approved" and result.threshold == 3
    # independent re-verification from the raw votes agrees
    assert independently_verify(reg, proposal, votes) is True


def test_independent_verification_rejects_single_voter():
    parts = [_participant(f"c{i}") for i in range(3)]
    reg = _registry(parts)
    proposal = _proposal()
    p0, priv0 = parts[0]
    only_one = [cast_vote(p0, priv0, proposal), cast_vote(p0, priv0, proposal)]
    assert independently_verify(reg, proposal, only_one) is False
