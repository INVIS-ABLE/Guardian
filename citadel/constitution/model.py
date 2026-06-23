"""Guardian Integrity Constitution (Citadel System 40, Wave 40).

A machine-readable set of permanently-prohibited actions and invariants. Every Guardian component
declares which clauses it implements, which it depends on, which tests prove them, and which runtime
evidence confirms compliance. The validator checks those bindings are complete; the runtime checker
enforces the prohibitions. Owner: policies/privacy_invariants.yaml (the privacy constitution, reused
and generalised). Independent verifier: ``runtime_checker``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ClauseCategory(str, Enum):
    PROHIBITED_ACTION = "prohibited_action"
    PRIVACY = "privacy"
    SAFEGUARDING = "safeguarding"
    AUTHORITY_SEPARATION = "authority_separation"
    EVIDENCE = "evidence"
    RECOVERY = "recovery"
    KEY_CUSTODY = "key_custody"


@dataclass(frozen=True)
class ConstitutionClause:
    clause_id: str
    category: ClauseCategory
    statement: str


@dataclass(frozen=True)
class ComponentBinding:
    component: str
    implements: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    proving_tests: tuple[str, ...] = ()
    runtime_evidence: tuple[str, ...] = ()


# The permanently-prohibited actions (generalised from policies/privacy_invariants.yaml +
# policies/opa/guardian.rego BLOCKED_ACTIONS). Never permitted, by any component, ever.
PROHIBITED_ACTIONS: frozenset[str] = frozenset(
    {
        "decrypt_private_content", "access_message_plaintext", "store_decryption_keys",
        "train_on_user_data", "third_party_scan", "credential_theft", "stealth", "persistence",
        "exploit_deployment", "arbitrary_command_execution", "bypass_approval",
        "change_its_own_policies", "widen_scope", "grant_itself_permissions",
        "model_grants_production_authority", "shadow_assumes_operational_control",
    }
)

CORE_CLAUSES: tuple[ConstitutionClause, ...] = (
    ConstitutionClause("C-PRIV-1", ClauseCategory.PRIVACY,
                       "Private-message plaintext never enters Guardian systems."),
    ConstitutionClause("C-AUTH-1", ClauseCategory.AUTHORITY_SEPARATION,
                       "No model or Shadow service grants production authority."),
    ConstitutionClause("C-EVID-1", ClauseCategory.EVIDENCE,
                       "Evidence cannot be deleted by the service that created it."),
    ConstitutionClause("C-REC-1", ClauseCategory.RECOVERY,
                       "Recovery is incomplete until evidence and identity integrity pass."),
    ConstitutionClause("C-KEY-1", ClauseCategory.KEY_CUSTODY,
                       "No single identity can complete a root operation."),
    ConstitutionClause("C-PROH-1", ClauseCategory.PROHIBITED_ACTION,
                       "Permanently-prohibited actions are denied by default."),
)


@dataclass
class Constitution:
    clauses: dict[str, ConstitutionClause] = field(default_factory=dict)

    @classmethod
    def default(cls) -> "Constitution":
        return cls(clauses={c.clause_id: c for c in CORE_CLAUSES})

    def has(self, clause_id: str) -> bool:
        return clause_id in self.clauses


__all__ = [
    "ClauseCategory", "ConstitutionClause", "ComponentBinding", "PROHIBITED_ACTIONS",
    "CORE_CLAUSES", "Constitution",
]
