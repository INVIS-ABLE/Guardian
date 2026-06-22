"""Guardian evidence package.

Two layers live here:

* :mod:`core.evidence.report` — the existing simulator/connector evidence model
  (``SimulatorResult``) and the Markdown/JSON report generator. Re-exported here so
  ``from core.evidence import SimulatorResult, write_report, scrub`` keeps working.
* :mod:`core.evidence.models` — the typed *evidence-graph* contracts the Brain
  reasons over (``EvidenceItem``, ``Hypothesis``, ``Finding`` …). Build-order step 1.
"""

from __future__ import annotations

from .models import (
    SCHEMA_VERSION,
    AssetRef,
    Classification,
    EvidenceItem,
    Finding,
    Hypothesis,
    PolicyDecisionRecord,
    Provenance,
    ProposedAction,
    Severity,
    TestProposal,
    TrustLevel,
    ValidationState,
    VerificationResult,
)
from .report import (
    DEFAULT_OUTPUT_DIR,
    SEVERITIES,
    TEMPLATE_PATH,
    SimulatorResult,
    scrub,
    write_report,
)
from .store import (
    EvidenceEvent,
    EvidenceReceipt,
    EvidenceStore,
    HashChainBackend,
    get_backend,
)

__all__ = [
    # report layer (unchanged public API)
    "SEVERITIES",
    "TEMPLATE_PATH",
    "DEFAULT_OUTPUT_DIR",
    "SimulatorResult",
    "scrub",
    "write_report",
    # evidence system of record
    "EvidenceEvent",
    "EvidenceReceipt",
    "EvidenceStore",
    "HashChainBackend",
    "get_backend",
    # typed evidence-graph contracts
    "SCHEMA_VERSION",
    "Classification",
    "TrustLevel",
    "ValidationState",
    "Provenance",
    "AssetRef",
    "EvidenceItem",
    "TestProposal",
    "Hypothesis",
    "Severity",
    "Finding",
    "ProposedAction",
    "PolicyDecisionRecord",
    "VerificationResult",
]
