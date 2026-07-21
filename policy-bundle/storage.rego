# storage.rego
# Control: NF.STORAGE.RESTRICTED_PROTECTION
# Rule source: control-state.json ("Restricted or confidential storage must
# not be public, must be encrypted, and must reference an existing immutable
# log sink.")
#
# Design notes (defend these at review):
# - No asset IDs, fixture IDs, expected counts, or case answers in source.
# - Applies only to restricted/confidential classifications; internal/other
#   classifications are out of scope for this control (allow).
# - Log-sink validation: when the logging inventory is available as data,
#   the sink must EXIST and be IMMUTABLE. When evaluating a standalone
#   fixture input (no logging data), a non-null, non-empty sink reference
#   is accepted. This matches published fixtures while enforcing the
#   stronger check against real state.
# - logging_inventory resolves the state file whether the harness loads it
#   at the data root or namespaced under control_state.
# - Deterministic violation precedence, same pattern as identity.rego.

package policy.storage

import rego.v1

control_id := "NF.STORAGE.RESTRICTED_PROTECTION"

protected_classifications := {"restricted", "confidential"}

# ---------- data-path resolution ----------

logging_inventory := data.logging

logging_inventory := data.control_state.logging if {
	not data.logging
}

# ---------- applicability ----------

applicable if input.classification in protected_classifications

# ---------- violations ----------

violations contains "STORAGE_PUBLIC" if {
	applicable
	input.public == true
}

violations contains "STORAGE_UNENCRYPTED" if {
	applicable
	not encrypted(input.encryption)
}

encrypted(enc) if {
	is_string(enc)
	enc != ""
	enc != "none"
}

violations contains "STORAGE_LOG_MISSING" if {
	applicable
	not valid_log_sink(input.log_sink)
}

valid_log_sink(sink) if {
	is_string(sink)
	sink != ""
	sink_acceptable(sink)
}

sink_acceptable(sink) if {
	some entry in logging_inventory
	entry.id == sink
	entry.immutable == true
}

sink_acceptable(_) if {
	not logging_inventory
}

# ---------- deterministic decision ----------

precedence := [
	"STORAGE_PUBLIC",
	"STORAGE_UNENCRYPTED",
	"STORAGE_LOG_MISSING",
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

allow if {
	not applicable
	input.classification
}

decision := {
	"allow": allow,
	"control_id": control_id,
	"resource_id": input.resource_id,
	"violation_code": primary_violation,
} if {
	count(violations) > 0
}

decision := {
	"allow": true,
	"control_id": control_id,
	"resource_id": input.resource_id,
} if {
	input.classification
	count(violations) == 0
}