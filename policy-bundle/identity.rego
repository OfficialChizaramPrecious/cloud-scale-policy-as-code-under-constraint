# identity.rego
# Control: NF.IDENTITY.PRIVILEGED_ASSURANCE
# Rule source: control-state.json ("Privileged human identities require
# phishing-resistant MFA; privileged service identities require an owner
# and credentials no older than 90 days.")
#
# Design notes (defend these at review):
# - No asset IDs, fixture IDs, expected counts, or case answers appear in
#   this source (anti-shortcut standard).
# - Exceptions fail closed: malformed, incomplete, or expired exception
#   objects are denied. Per published fixtures P-OPA-11/12, exception
#   violations are emitted under this control's ID.
# - Violation precedence is explicit and deterministic so hidden fixtures
#   with reordered fields produce stable output.
# - AI-assisted drafting disclosed in decision-log.md; logic verified by
#   candidate via `opa test`.

package policy.identity

import rego.v1

control_id := "NF.IDENTITY.PRIVILEGED_ASSURANCE"

max_credential_age_days := 90

# ---------- input classification ----------

is_identity_input if input.type == "human"

is_identity_input if input.type == "service"

# An exception object is identified by its required-field shape, not by ID.
is_exception_input if {
	not is_identity_input
	has_any_exception_field
}

has_any_exception_field if input.expires_at
has_any_exception_field if input.approved_by
has_any_exception_field if input.compensating_control

# ---------- identity violations ----------

# Privileged humans must use phishing-resistant MFA.
violations contains "IDENTITY_MFA_WEAK" if {
	input.type == "human"
	input.privileged == true
	input.mfa != "phishing-resistant"
}

# Privileged service identities must have an owner.
violations contains "IDENTITY_OWNER_MISSING" if {
	input.type == "service"
	input.privileged == true
	not valid_owner(input.owner)
}

# Privileged service credentials must be no older than 90 days.
violations contains "IDENTITY_CREDENTIAL_STALE" if {
	input.type == "service"
	input.privileged == true
	input.credential_age_days > max_credential_age_days
}

valid_owner(owner) if {
	is_string(owner)
	owner != ""
}

# ---------- exception validation (fail closed) ----------

# Required fields: owner, reason, approved_by, expires_at, compensating_control.
exception_required_fields := {"owner", "reason", "approved_by", "expires_at", "compensating_control"}

violations contains "EXCEPTION_INCOMPLETE" if {
	is_exception_input
	some field in exception_required_fields
	not present_and_nonempty(field)
}

violations contains "EXCEPTION_EXPIRED" if {
	is_exception_input
	all_fields_present
	expired(input.expires_at)
}

all_fields_present if {
	every field in exception_required_fields {
		present_and_nonempty(field)
	}
}

present_and_nonempty(field) if {
	value := input[field]
	value != null
	value != ""
}

# An exception is expired when expires_at is not after the evaluation
# reference time. Reference time comes from the versioned state's
# generated_at (data.control_state.generated_at), NOT wall-clock time,
# so decisions are reproducible. Adapt the data path to your harness.
expired(expires_at) if {
	ref_ns := time.parse_rfc3339_ns(reference_time)
	exp_ns := time.parse_rfc3339_ns(expires_at)
	exp_ns <= ref_ns
}
reference_time := t if {
	t := data.generated_at
}

reference_time := t if {
	not data.generated_at
	t := data.control_state.generated_at
}
# Malformed expiry timestamps also fail closed as expired/invalid.
violations contains "EXCEPTION_INCOMPLETE" if {
	is_exception_input
	all_fields_present
	not parseable(input.expires_at)
}

parseable(ts) if time.parse_rfc3339_ns(ts)

# ---------- deterministic decision ----------

# Explicit precedence so exactly one violation_code is reported even when
# multiple violations exist; full set is preserved in `violations`.
precedence := [
	"IDENTITY_MFA_WEAK",
	"IDENTITY_OWNER_MISSING",
	"IDENTITY_CREDENTIAL_STALE",
	"EXCEPTION_EXPIRED",
	"EXCEPTION_INCOMPLETE",
]

primary_violation := code if {
	some code in precedence
	code in violations
	every earlier in earlier_codes(code) { not earlier in violations }
}

earlier_codes(code) := [c |
	some i, c in precedence
	some j, d in precedence
	d == code
	i < j
]

default allow := false

allow if {
	applicable
	count(violations) == 0
}

applicable if is_identity_input
applicable if is_exception_input

decision := {
	"allow": allow,
	"control_id": control_id,
	"resource_id": input.resource_id,
	"violation_code": primary_violation,
} if {
	applicable
	count(violations) > 0
}

decision := {
	"allow": true,
	"control_id": control_id,
	"resource_id": input.resource_id,
} if {
	applicable
	count(violations) == 0
}