# endpoint.rego
# Control: NF.ENDPOINT.MANAGED_HEALTH
# Rule source: control-state.json ("In-scope endpoints must be managed,
# disk-encrypted, EDR-healthy, and seen within 24 hours of generated_at.")
#
# Design notes (defend these at review):
# - No asset IDs, fixture IDs, expected counts, or case answers in source.
# - Freshness is measured against the versioned state's generated_at, NOT
#   wall-clock time, so the same input always yields the same decision.
# - reference_time resolves the state file whether the harness loads it at
#   the data root or namespaced under control_state.
# - fresh_endpoint is a zero-argument rule that reads input.last_seen
#   directly. This is deliberate: a function called as fresh(input.last_seen)
#   becomes undefined when the field is absent, which makes the enclosing
#   violation rule undefined and silently ALLOWS the endpoint. Reading the
#   field inside the rule means a missing or unparseable timestamp leaves
#   fresh_endpoint undefined, so "not fresh_endpoint" fires and the device
#   fails closed as stale. This bug was found by the acceptance suite; see
#   decision-log D-15.
# - A timestamp later than the state snapshot is not treated as fresh; a
#   device cannot legitimately report after the snapshot was taken.
# - Deterministic violation precedence, same pattern as the other files.

package policy.endpoint

import rego.v1

control_id := "NF.ENDPOINT.MANAGED_HEALTH"

freshness_window_ns := 86400000000000 # 24 hours in nanoseconds

# ---------- data-path resolution ----------

reference_time := t if {
	t := data.generated_at
}

reference_time := t if {
	not data.generated_at
	t := data.control_state.generated_at
}

# ---------- applicability ----------

applicable if is_boolean(input.managed)

# ---------- violations ----------

violations contains "ENDPOINT_UNMANAGED" if {
	applicable
	input.managed == false
}

violations contains "ENDPOINT_DISK_UNENCRYPTED" if {
	applicable
	input.disk_encrypted == false
}

violations contains "ENDPOINT_EDR_UNHEALTHY" if {
	applicable
	input.edr_healthy == false
}

violations contains "ENDPOINT_STALE" if {
	applicable
	not fresh_endpoint
}

fresh_endpoint if {
	ref_ns := time.parse_rfc3339_ns(reference_time)
	seen_ns := time.parse_rfc3339_ns(input.last_seen)
	ref_ns - seen_ns <= freshness_window_ns
	seen_ns <= ref_ns
}

# ---------- deterministic decision ----------

precedence := [
	"ENDPOINT_UNMANAGED",
	"ENDPOINT_DISK_UNENCRYPTED",
	"ENDPOINT_EDR_UNHEALTHY",
	"ENDPOINT_STALE",
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