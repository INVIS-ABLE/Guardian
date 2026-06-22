"""Guardian Verifier — independent monitor of the key-transparency directory.

This is Guardian's ONE privacy-relevant active role (see policies/privacy_invariants.yaml,
``guardian_verifier``). End-to-end encryption is weakened if a malicious or compromised
server can secretly substitute someone's identity key. The Verifier independently checks an
append-only, verifiable key directory so silent key replacement is detectable.

**Boundary (enforced):** the Verifier reads only PUBLIC verifiable data — key leaves
(identity, device, public key, epoch), inclusion/consistency proofs, and signed checkpoints.
It has no method to read message plaintext, media, or private/conversation keys, and it
rejects any leaf that carries such fields (:class:`VerifierBoundaryError`).

This module implements the verifiable log + the checks. In production the signed checkpoints
use Ed25519 and are stored outside the messaging service; here they use HMAC so the logic is
fully testable offline. The cryptographic *primitive* is swappable; the verification logic
is the point.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from . import signing

# Fields that must never appear in the public key directory the Verifier ingests.
_FORBIDDEN_LEAF_FIELDS = frozenset(
    {"private_key", "plaintext", "message", "conversation_key", "secret", "media"}
)


class VerifierBoundaryError(PermissionError):
    """Raised if the Verifier is asked to ingest non-public (private) content."""


@dataclass(frozen=True)
class KeyLeaf:
    """A public entry in the key directory: identity's device key at an epoch."""

    identity: str
    device: str
    public_key: str
    epoch: int
    recovery: bool = False     # True ⇒ this key change is an explicit, displayed recovery

    def canonical(self) -> bytes:
        return json.dumps(
            {
                "identity": self.identity, "device": self.device,
                "public_key": self.public_key, "epoch": self.epoch, "recovery": self.recovery,
            },
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")


def _leaf_from_public(d: dict[str, Any]) -> KeyLeaf:
    forbidden = _FORBIDDEN_LEAF_FIELDS & set(d)
    if forbidden:
        raise VerifierBoundaryError(
            f"Verifier may only ingest public key data; forbidden fields present: {sorted(forbidden)}"
        )
    return KeyLeaf(
        identity=d["identity"], device=d["device"], public_key=d["public_key"],
        epoch=int(d.get("epoch", 0)), recovery=bool(d.get("recovery", False)),
    )


@dataclass(frozen=True)
class SignedCheckpoint:
    size: int
    root: str
    epoch: int
    signature: str


@dataclass
class VerifierReport:
    ok: bool
    size: int
    root: str
    alerts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "size": self.size, "root": self.root, "alerts": self.alerts}


class KeyTransparencyLog:
    """Append-only, hash-chained log of public key leaves (a verifiable key directory)."""

    GENESIS = "0" * 64

    def __init__(self) -> None:
        self._leaves: list[KeyLeaf] = []
        self._hashes: list[str] = []

    @staticmethod
    def _chain(prev: str, leaf: KeyLeaf) -> str:
        return hashlib.sha256(prev.encode("utf-8") + leaf.canonical()).hexdigest()

    def append(self, leaf: KeyLeaf | dict[str, Any]) -> str:
        if isinstance(leaf, dict):
            leaf = _leaf_from_public(leaf)
        prev = self._hashes[-1] if self._hashes else self.GENESIS
        h = self._chain(prev, leaf)
        self._leaves.append(leaf)
        self._hashes.append(h)
        return h

    @property
    def size(self) -> int:
        return len(self._leaves)

    def root(self) -> str:
        return self._hashes[-1] if self._hashes else self.GENESIS

    def leaves(self) -> tuple[KeyLeaf, ...]:
        return tuple(self._leaves)

    def root_at(self, size: int) -> str:
        """Recompute the root over the first ``size`` leaves (for consistency checks)."""
        prev = self.GENESIS
        for leaf in self._leaves[:size]:
            prev = self._chain(prev, leaf)
        return prev

    @staticmethod
    def _checkpoint_message(size: int, root: str, epoch: int) -> bytes:
        return f"{size}:{root}:{epoch}".encode()

    def checkpoint(self, signer_private_key: str, epoch: int) -> SignedCheckpoint:
        root = self.root()
        sig = signing.sign(signer_private_key, self._checkpoint_message(self.size, root, epoch))
        return SignedCheckpoint(size=self.size, root=root, epoch=epoch, signature=sig)


class GuardianVerifier:
    """Independently verifies a key-transparency log. Public data only."""

    def __init__(self, signer_public_key: str) -> None:
        # The trusted checkpoint-signing PUBLIC key (Ed25519 in production; hex-encoded).
        self._signer_public_key = signer_public_key

    # --- checkpoint signature --------------------------------------------------
    def verify_checkpoint(self, log: KeyTransparencyLog, checkpoint: SignedCheckpoint) -> bool:
        message = KeyTransparencyLog._checkpoint_message(
            checkpoint.size, checkpoint.root, checkpoint.epoch
        )
        signed_ok = signing.verify(self._signer_public_key, message, checkpoint.signature)
        return signed_ok and checkpoint.root == log.root_at(checkpoint.size)

    # --- consistency (append-only) ---------------------------------------------
    def verify_consistency(self, log: KeyTransparencyLog, earlier: SignedCheckpoint) -> bool:
        """A later log must extend an earlier checkpoint: the first N leaves are unchanged."""
        return log.size >= earlier.size and log.root_at(earlier.size) == earlier.root

    # --- inclusion -------------------------------------------------------------
    def verify_inclusion(self, log: KeyTransparencyLog, leaf: KeyLeaf) -> bool:
        return leaf in log.leaves()

    # --- silent key replacement ------------------------------------------------
    def detect_silent_key_replacement(self, log: KeyTransparencyLog) -> list[str]:
        """A device's public key may change only via a leaf flagged ``recovery``."""
        alerts: list[str] = []
        latest: dict[tuple[str, str], str] = {}
        for leaf in log.leaves():
            key = (leaf.identity, leaf.device)
            prev_pk = latest.get(key)
            if prev_pk is not None and prev_pk != leaf.public_key and not leaf.recovery:
                alerts.append(f"silent_key_replacement:{leaf.identity}/{leaf.device}")
            latest[key] = leaf.public_key
        return alerts

    # --- top-level monitor -----------------------------------------------------
    def monitor(
        self,
        log: KeyTransparencyLog,
        *,
        current_checkpoint: SignedCheckpoint | None = None,
        previous_checkpoint: SignedCheckpoint | None = None,
    ) -> VerifierReport:
        alerts: list[str] = []
        if current_checkpoint is not None and not self.verify_checkpoint(log, current_checkpoint):
            alerts.append("checkpoint_invalid")
        if previous_checkpoint is not None and not self.verify_consistency(log, previous_checkpoint):
            alerts.append("checkpoint_inconsistency")
        alerts.extend(self.detect_silent_key_replacement(log))
        return VerifierReport(ok=not alerts, size=log.size, root=log.root(), alerts=alerts)
