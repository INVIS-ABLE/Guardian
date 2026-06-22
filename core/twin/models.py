"""Typed models for the live cyber digital twin (Sovereign plane, Wave 1, system #1).

The digital twin is a continuously-updated relationship graph of everything Guardian
protects — repositories, services, identities, keys, data classes and the edges between
them — so Guardian can answer instantly: *"what would be affected if this credential,
repository, machine, identity or package were compromised?"* (docs/sovereign_ops_plane.md).

This module defines the *shapes* only; the graph algorithms live in ``graph.py`` and the
ingestion seam (Cartography / CloudQuery → PostgreSQL in production) in ``ingest.py``.

Privacy boundary (enforced here): the twin holds **metadata and relationships, never
private content**. An ``encryption_key`` asset is a key *identifier*, not key material; a
``data_class`` asset is a *category label*, not records. A node may therefore never be
classified ``MESSAGE_PLAINTEXT`` or ``DECRYPTION_KEY`` — those are content, and the twin is
structurally outside private content (mirrors core/verifier.py and the Privacy Fabric).
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator

from core.evidence.models import Classification

SCHEMA_VERSION = 1

# Classifications that denote private *content* — never permitted on a twin node, which
# only ever carries metadata. (The policy gate blocks the *actions*; this blocks content.)
_FORBIDDEN_NODE_CLASSES = frozenset({Classification.MESSAGE_PLAINTEXT, Classification.DECRYPTION_KEY})


class AssetKind(str, Enum):
    """The kinds of asset the twin models. Coarse but covers the INVISABLE estate."""

    REPOSITORY = "repository"
    COMMIT = "commit"
    CONTAINER_IMAGE = "container_image"
    SERVICE = "service"
    API = "api"
    DOMAIN = "domain"
    CERTIFICATE = "certificate"
    CLOUD_RESOURCE = "cloud_resource"
    K8S_WORKLOAD = "k8s_workload"
    IDENTITY = "identity"  # human | service | machine (see AssetNode.subtype)
    DATABASE = "database"
    QUEUE = "queue"
    ENCRYPTION_KEY = "encryption_key"
    DEPENDENCY = "dependency"
    SECURITY_CONTROL = "security_control"
    DATA_CLASS = "data_class"


class RelationKind(str, Enum):
    """Directed edges, oriented in the direction impact/compromise PROPAGATES.

    Reading an edge ``A --kind--> B`` as "compromising A can affect B" is what makes blast
    radius a simple directed reachability over outgoing edges. e.g. a leaked CI token:
    ``identity --can_write--> repo --produces--> image --deploys--> service --reads--> db``.
    """

    HAS_ROLE = "has_role"          # identity → identity/role
    CAN_ACCESS = "can_access"      # identity → resource
    CAN_WRITE = "can_write"        # identity → repository
    BUILDS = "builds"              # repository/commit → image (CI)
    PRODUCES = "produces"          # build → container_image
    SIGNS = "signs"                # identity/key → image/artifact
    DEPLOYS = "deploys"            # image → service/k8s_workload
    DEPENDS_ON = "depends_on"      # service/repo → dependency
    EXPOSES = "exposes"            # service → api/domain
    READS = "reads"               # service → database/data_class
    WRITES = "writes"             # service → database
    STORES = "stores"             # database/queue → data_class
    PROTECTS = "protects"          # security_control → asset (defensive edge)


class AssetNode(BaseModel):
    """One asset in the twin. Immutable, strict, metadata-only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    id: str                       # stable identifier, e.g. "repo:INVIS-ABLE/Guardian"
    kind: AssetKind
    name: str
    subtype: str | None = None    # e.g. identity: "human" | "service" | "machine"
    classification: Classification = Classification.INTERNAL
    owner: str | None = None      # team/owner for blast-radius reporting
    paths: tuple[str, ...] = ()   # source-path globs that map a code change to this asset

    @field_validator("id", "name")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("asset id/name must be non-empty")
        return v

    @field_validator("classification")
    @classmethod
    def _no_private_content(cls, v: Classification) -> Classification:
        if v in _FORBIDDEN_NODE_CLASSES:
            raise ValueError(
                f"twin nodes hold metadata only — classification '{v.value}' denotes private "
                "content and is refused (the twin is structurally outside private content)"
            )
        return v


class Relationship(BaseModel):
    """A directed, typed edge between two assets (by id)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    src: str
    dst: str
    kind: RelationKind

    @field_validator("src", "dst")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("relationship src/dst must be non-empty asset ids")
        return v


class ImpactStep(BaseModel):
    """One hop on a blast-radius / attack path: ``via`` relation reaching ``asset``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    via: RelationKind
    asset: str


class ImpactedAsset(BaseModel):
    """An asset reachable from a compromised origin, with the shortest path to it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    asset: AssetNode
    distance: int
    path: tuple[ImpactStep, ...]


class BlastRadius(BaseModel):
    """The full set of assets affected if ``origin`` were compromised."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    origin: str
    impacted: tuple[ImpactedAsset, ...]

    def asset_ids(self) -> tuple[str, ...]:
        return tuple(i.asset.id for i in self.impacted)

    def of_kind(self, kind: AssetKind) -> tuple[ImpactedAsset, ...]:
        return tuple(i for i in self.impacted if i.asset.kind == kind)
