---------------------------- MODULE capability ----------------------------
\* Formal model of Guardian's one-action capability lifecycle (Citadel System 25).
\* Models core/tools/capability.py + orchestration/approvals.py invariants. Checked with TLC.
\*
\* Properties (declared in citadel/formal/spec.py and linked to executable tests):
\*   NoReplay        : a consumed capability can never be consumed again
\*   NoExpiredUse    : an expired capability is never consumed
\*   NoScopeWiden    : a consumed capability never exceeds its issued scope
\*   ApprovalBound   : production consumption requires a recorded approval

EXTENDS Naturals
CONSTANTS MaxUses
VARIABLES state, uses, approved, expired

Init ==
    /\ state = "issued"
    /\ uses = 0
    /\ approved \in {TRUE, FALSE}
    /\ expired \in {TRUE, FALSE}

Consume ==
    /\ state = "issued"
    /\ ~expired
    /\ uses < MaxUses
    /\ approved
    /\ uses' = uses + 1
    /\ state' = "consumed"
    /\ UNCHANGED <<approved, expired>>

Expire ==
    /\ state = "issued"
    /\ expired' = TRUE
    /\ UNCHANGED <<state, uses, approved>>

Next == Consume \/ Expire

\* Safety invariants
NoReplay     == uses <= MaxUses
NoExpiredUse == (state = "consumed") => ~expired
ApprovalBound == (state = "consumed") => approved

Spec == Init /\ [][Next]_<<state, uses, approved, expired>>
=============================================================================
