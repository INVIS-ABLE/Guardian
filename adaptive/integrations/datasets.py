"""Dataset and feature governance (directive §15, §19).

Every learned model trains on a *reproducible, governed* dataset: versioned source
(lakeFS), validated (Great Expectations), with lineage recorded (OpenLineage). Every
feature (Feast) has an owner, source, classification, freshness requirement, allowed
consumers, retention and a leakage analysis. Forbidden-class data (private-message
plaintext, keys, raw secrets) may never become a training feature.

Typed manifests + fail-closed validators (acceptance #4, #5).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

# Data classes that may never be used for training/features (directive §16 prohibited data).
FORBIDDEN_TRAINING_CLASSES: frozenset[str] = frozenset(
    {
        "message_plaintext",
        "decryption_key",
        "password",
        "access_token",
        "raw_secret",
        "unredacted_health",
    }
)


class DatasetManifest(BaseModel):
    """A versioned, validated, lineage-tracked dataset (§15)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    source_uri: str = Field(min_length=1)
    lineage: tuple[str, ...] = ()       # OpenLineage transform steps
    validation_passed: bool = False     # Great Expectations gate
    classification: str = "internal"
    tenant_isolated: bool = True
    redaction_applied: bool = False


class FeatureDefinition(BaseModel):
    """A governed feature (Feast): owned, classified, leakage-checked (§15)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    source: str = Field(min_length=1)
    classification: str = "internal"
    freshness_seconds: int = Field(gt=0)
    online_offline_consistent: bool = True
    allowed_consumers: tuple[str, ...] = ()
    retention_seconds: int = Field(gt=0)
    leakage_checked: bool = False


class DataGovernanceError(RuntimeError):
    """Raised when a dataset/feature is not lawfully usable for training. Fail closed."""


def assert_dataset_governed(dataset: DatasetManifest) -> None:
    """A dataset is usable only if validated, lineage-tracked and not forbidden-class (#4, #5)."""
    if dataset.classification in FORBIDDEN_TRAINING_CLASSES:
        raise DataGovernanceError(
            f"dataset {dataset.name!r} classified {dataset.classification!r} — forbidden for training"
        )
    if not dataset.lineage:
        raise DataGovernanceError(f"dataset {dataset.name!r} has no lineage (#5)")
    if not dataset.validation_passed:
        raise DataGovernanceError(f"dataset {dataset.name!r} has not passed validation (#5)")
    if not dataset.tenant_isolated:
        raise DataGovernanceError(f"dataset {dataset.name!r} is not tenant-isolated")


def assert_feature_governed(feature: FeatureDefinition) -> None:
    """A feature is usable only if owned, classified-safe, leakage-checked and scoped."""
    if feature.classification in FORBIDDEN_TRAINING_CLASSES:
        raise DataGovernanceError(
            f"feature {feature.name!r} classified {feature.classification!r} — forbidden"
        )
    if not feature.leakage_checked:
        raise DataGovernanceError(f"feature {feature.name!r} has no leakage analysis")
    if not feature.allowed_consumers:
        raise DataGovernanceError(f"feature {feature.name!r} declares no allowed consumers")


__all__ = [
    "FORBIDDEN_TRAINING_CLASSES",
    "DatasetManifest",
    "FeatureDefinition",
    "DataGovernanceError",
    "assert_dataset_governed",
    "assert_feature_governed",
]
