# identity_test.rego
# Acceptance tests for NF.IDENTITY.PRIVILEGED_ASSURANCE.
#
# Covers published fixtures P-OPA-01, 02, 03, 11, 12, 13, 14, 15 plus
# positive (allow), malformed-input, and violation-precedence cases.
#
# Note on IDs: fixture identifiers and asset IDs appear in TEST DATA only,
# never in policy source. The anti-shortcut standard prohibits embedding
# them in implementation logic; supplying them as test inputs is how the
# published suite is exercised.
#
# reference_time is pinned explicitly so tests are deterministic whether or
# not control-state.json is loaded alongside them.

package policy.identity_test

import rego.v1

import data.policy.identity

ref := "2026-07-13T08:00:00Z"

# ---------- published negative fixtures ----------

test_p_opa_01_privileged_human_weak_mfa_denied if {
	d := identity.decision with input as {
		"type": "human",
		"privileged": true,
		"mfa": "sms",
		"resource_id": "asset-d738f3",
	} with data.generated_at as ref

	d.allow == false
	d.control_id == "NF.IDENTITY.PRIVILEGED_ASSURANCE"
	d.resource_id == "asset-d738f3"
	d.violation_code == "IDENTITY_MFA_WEAK"
}

test_p_opa_02_privileged_service_missing_owner_denied if {
	d := identity.decision with input as {
		"type": "service",
		"privileged": true,
		"credential_age_days": 20,
		"owner": null,
		"resource_id": "asset-331d6f",
	} with data.generated_at as ref

	d.allow == false
	d.violation_code == "IDENTITY_OWNER_MISSING"
}

test_p_opa_03_privileged_service_stale_credential_denied if {
	d := identity.decision with input as {
		"type": "service",
		"privileged": true,
		"credential_age_days": 180,
		"owner": "platform",
		"resource_id": "asset-162e42",
	} with data.generated_at as ref

	d.allow == false
	d.violation_code == "IDENTITY_CREDENTIAL_STALE"
}

test_p_opa_11_expired_exception_denied if {
	d := identity.decision with input as {
		"approved_by": "ciso",
		"compensating_control": "segmentation",
		"expires_at": "2026-06-01T00:00:00Z",
		"owner": "risk",
		"reason": "legacy",
		"resource_id": "asset-139b25",
	} with data.generated_at as ref

	d.allow == false
	d.violation_code == "EXCEPTION_EXPIRED"
}

test_p_opa_12_incomplete_exception_denied if {
	d := identity.decision with input as {
		"approved_by": "ciso",
		"compensating_control": "segmentation",
		"expires_at": "2026-08-01T00:00:00Z",
		"owner": "risk",
		"reason": null,
		"resource_id": "asset-250642",
	} with data.generated_at as ref

	d.allow == false
	d.violation_code == "EXCEPTION_INCOMPLETE"
}

test_p_opa_13_privileged_human_weak_mfa_denied if {
	d := identity.decision with input as {
		"type": "human",
		"privileged": true,
		"mfa": "sms",
		"resource_id": "asset-8005ec",
	} with data.generated_at as ref

	d.allow == false
	d.resource_id == "asset-8005ec"
	d.violation_code == "IDENTITY_MFA_WEAK"
}

test_p_opa_14_privileged_service_missing_owner_denied if {
	d := identity.decision with input as {
		"type": "service",
		"privileged": true,
		"credential_age_days": 20,
		"owner": null,
		"resource_id": "asset-1dd3f2",
	} with data.generated_at as ref

	d.allow == false
	d.violation_code == "IDENTITY_OWNER_MISSING"
}

test_p_opa_15_privileged_service_stale_credential_denied if {
	d := identity.decision with input as {
		"type": "service",
		"privileged": true,
		"credential_age_days": 180,
		"owner": "platform",
		"resource_id": "asset-2309c3",
	} with data.generated_at as ref

	d.allow == false
	d.violation_code == "IDENTITY_CREDENTIAL_STALE"
}

# ---------- positive cases (allow) ----------

test_privileged_human_phishing_resistant_allowed if {
	d := identity.decision with input as {
		"type": "human",
		"privileged": true,
		"mfa": "phishing-resistant",
		"resource_id": "asset-pos-01",
	} with data.generated_at as ref

	d.allow == true
	not d.violation_code
}

test_non_privileged_human_weak_mfa_allowed if {
	d := identity.decision with input as {
		"type": "human",
		"privileged": false,
		"mfa": "totp",
		"resource_id": "asset-pos-02",
	} with data.generated_at as ref

	d.allow == true
}

test_privileged_service_owned_and_current_allowed if {
	d := identity.decision with input as {
		"type": "service",
		"privileged": true,
		"credential_age_days": 20,
		"owner": "platform",
		"resource_id": "asset-pos-03",
	} with data.generated_at as ref

	d.allow == true
}

test_valid_unexpired_exception_allowed if {
	d := identity.decision with input as {
		"approved_by": "ciso",
		"compensating_control": "segmentation",
		"expires_at": "2026-08-01T00:00:00Z",
		"owner": "risk",
		"reason": "legacy hardware",
		"resource_id": "asset-pos-04",
	} with data.generated_at as ref

	d.allow == true
}

# ---------- malformed input (fail closed) ----------

test_empty_string_owner_treated_as_missing if {
	d := identity.decision with input as {
		"type": "service",
		"privileged": true,
		"credential_age_days": 20,
		"owner": "",
		"resource_id": "asset-mal-01",
	} with data.generated_at as ref

	d.allow == false
	d.violation_code == "IDENTITY_OWNER_MISSING"
}

test_unparseable_expiry_fails_closed if {
	d := identity.decision with input as {
		"approved_by": "ciso",
		"compensating_control": "segmentation",
		"expires_at": "not-a-timestamp",
		"owner": "risk",
		"reason": "legacy",
		"resource_id": "asset-mal-02",
	} with data.generated_at as ref

	d.allow == false
	d.violation_code == "EXCEPTION_INCOMPLETE"
}

test_exception_missing_compensating_control_denied if {
	d := identity.decision with input as {
		"approved_by": "ciso",
		"expires_at": "2026-08-01T00:00:00Z",
		"owner": "risk",
		"reason": "legacy",
		"resource_id": "asset-mal-03",
	} with data.generated_at as ref

	d.allow == false
	d.violation_code == "EXCEPTION_INCOMPLETE"
}

# ---------- deterministic precedence ----------

test_owner_missing_precedes_stale_credential if {
	d := identity.decision with input as {
		"type": "service",
		"privileged": true,
		"credential_age_days": 180,
		"owner": null,
		"resource_id": "asset-prec-01",
	} with data.generated_at as ref

	d.violation_code == "IDENTITY_OWNER_MISSING"
	count(identity.violations) == 0 with input as {} # sanity: no input, no violations
}

test_full_violation_set_retained if {
	v := identity.violations with input as {
		"type": "service",
		"privileged": true,
		"credential_age_days": 180,
		"owner": null,
		"resource_id": "asset-prec-02",
	} with data.generated_at as ref

	"IDENTITY_OWNER_MISSING" in v
	"IDENTITY_CREDENTIAL_STALE" in v
	count(v) == 2
}