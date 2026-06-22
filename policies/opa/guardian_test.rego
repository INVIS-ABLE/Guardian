# Tests for the Guardian authorization policy. Run with: opa test policies/opa
# Also usable via conftest in CI to validate the same Rego the Python gate mirrors.
package guardian.authz

# A plain in-scope staging action is allowed.
test_staging_action_allowed if {
	allow with input as {
		"action": "code_review", "mode": "code_review", "environment": "staging",
		"ownership_verified": true, "allowed_modes": ["code_review"],
		"blocked_actions": [], "approval_required": [], "allowed_test_accounts": [],
		"approvals": [], "now": 1000,
	}
}

# A blocked action is denied no matter what.
test_blocked_action_denied if {
	not allow with input as {
		"action": "hack_back", "mode": "abuse_simulation", "environment": "staging",
		"ownership_verified": true, "allowed_modes": ["abuse_simulation"],
		"blocked_actions": [], "approval_required": [], "allowed_test_accounts": [],
		"approvals": [], "now": 1000,
	}
}

# Production with a single approver is denied (two-person rule).
test_production_single_approver_denied if {
	not allow with input as {
		"action": "code_review", "mode": "code_review", "environment": "production",
		"ownership_verified": true, "allowed_modes": ["code_review"],
		"blocked_actions": [], "approval_required": ["production_scan"],
		"allowed_test_accounts": [],
		"approvals": [{"action": "production_scan", "approver": "ciso", "expires_at": null}],
		"now": 1000,
	}
}

# Production with two distinct approvers is allowed.
test_production_two_distinct_allowed if {
	allow with input as {
		"action": "code_review", "mode": "code_review", "environment": "production",
		"ownership_verified": true, "allowed_modes": ["code_review"],
		"blocked_actions": [], "approval_required": ["production_scan"],
		"allowed_test_accounts": [],
		"approvals": [
			{"action": "production_scan", "approver": "ciso", "expires_at": null},
			{"action": "production_scan", "approver": "head_of_eng", "expires_at": null},
		],
		"now": 1000,
	}
}

# An expired approval does not satisfy an approval-gated action.
test_expired_approval_denied if {
	not allow with input as {
		"action": "credential_audit", "mode": "credential_audit", "environment": "staging",
		"ownership_verified": true, "allowed_modes": ["credential_audit"],
		"blocked_actions": [], "approval_required": ["credential_audit"],
		"allowed_test_accounts": [],
		"approvals": [{"action": "credential_audit", "approver": "ciso", "expires_at": 500}],
		"now": 1000,
	}
}
