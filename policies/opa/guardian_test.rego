# Tests for the Guardian OPA authorization policy.
# Run:  opa test policies/opa -v
package guardian.authz

import future.keywords.in

staging_scope := {
	"environment": "staging",
	"allowed_modes": ["code_review", "secrets_scan"],
	"blocked_actions": [],
	"approval_required": ["production_scan", "credential_audit"],
}

test_allows_in_scope_code_review if {
	allow with input as {
		"action": "code_review",
		"mode": "code_review",
		"scope": staging_scope,
		"approvals": [],
		"target": {"kind": "repo", "in_scope": true, "owned": true},
	}
}

test_denies_globally_blocked_action if {
	not allow with input as {
		"action": "hack_back",
		"mode": "code_review",
		"scope": staging_scope,
		"approvals": [],
	}
}

test_denies_mode_not_in_scope if {
	not allow with input as {
		"action": "api_security",
		"mode": "api_security",
		"scope": staging_scope,
		"approvals": [],
	}
}

test_denies_production_without_approval if {
	not allow with input as {
		"action": "code_review",
		"mode": "code_review",
		"scope": {
			"environment": "production",
			"allowed_modes": ["code_review"],
			"blocked_actions": [],
			"approval_required": ["production_scan"],
		},
		"approvals": [],
	}
}

test_allows_production_with_approval if {
	allow with input as {
		"action": "code_review",
		"mode": "code_review",
		"scope": {
			"environment": "production",
			"allowed_modes": ["code_review"],
			"blocked_actions": [],
			"approval_required": ["production_scan"],
		},
		"approvals": ["production_scan"],
		"target": {"kind": "repo", "in_scope": true, "owned": true},
	}
}

test_denies_unowned_target if {
	not allow with input as {
		"action": "code_review",
		"mode": "code_review",
		"scope": staging_scope,
		"approvals": [],
		"target": {"kind": "domain", "in_scope": true, "owned": false},
	}
}

test_denies_approval_gated_without_approval if {
	not allow with input as {
		"action": "credential_audit",
		"mode": "code_review",
		"scope": staging_scope,
		"approvals": [],
	}
}
