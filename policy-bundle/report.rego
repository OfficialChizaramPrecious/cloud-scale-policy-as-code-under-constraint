# report.rego
# Generates the machine-readable compliance report required by the project.
#
# This module contains NO control logic of its own. It runs the three
# assigned control policies over every asset in the versioned state and
# assembles their decisions. If a policy changes, the report changes with
# it; if the state changes (new asset, new exception), the report updates
# without any edit to policy source.
#
# Each entry carries: policy ID, asset locator, allow/deny, violation code,
# and evidence locator, as required by the brief.
#
# The *_inventory rules resolve the state file whether the harness loads it
# at the data root or namespaced under control_state.

package policy.report

import rego.v1

import data.policy.endpoint
import data.policy.identity
import data.policy.storage

state_file := "control-state.json"

# ---------- data-path resolution ----------

identity_inventory := data.identities

identity_inventory := data.control_state.identities if {
	not data.identities
}

storage_inventory := data.storage

storage_inventory := data.control_state.storage if {
	not data.storage
}

endpoint_inventory := data.endpoints

endpoint_inventory := data.control_state.endpoints if {
	not data.endpoints
}

exception_inventory := data.exceptions

exception_inventory := data.control_state.exceptions if {
	not data.exceptions
}

reference_time := data.generated_at

reference_time := data.control_state.generated_at if {
	not data.generated_at
}

# ---------- per-collection decisions ----------

identity_decisions[id] := e if {
	some i, asset in identity_inventory
	id := asset.id
	candidate := object.union(asset, {"resource_id": id})
	d := identity.decision with input as candidate
	loc := sprintf("%s#/identities/%d", [state_file, i])
	e := {
		"policy_id": identity.control_id,
		"resource_id": id,
		"asset_locator": loc,
		"allow": d.allow,
		"violation_code": object.get(d, "violation_code", null),
		"evidence_locator": loc,
	}
}

storage_decisions[id] := e if {
	some i, asset in storage_inventory
	id := asset.id
	candidate := object.union(asset, {"resource_id": id})
	d := storage.decision with input as candidate
	loc := sprintf("%s#/storage/%d", [state_file, i])
	e := {
		"policy_id": storage.control_id,
		"resource_id": id,
		"asset_locator": loc,
		"allow": d.allow,
		"violation_code": object.get(d, "violation_code", null),
		"evidence_locator": loc,
	}
}

endpoint_decisions[id] := e if {
	some i, asset in endpoint_inventory
	id := asset.id
	candidate := object.union(asset, {"resource_id": id})
	d := endpoint.decision with input as candidate
	loc := sprintf("%s#/endpoints/%d", [state_file, i])
	e := {
		"policy_id": endpoint.control_id,
		"resource_id": id,
		"asset_locator": loc,
		"allow": d.allow,
		"violation_code": object.get(d, "violation_code", null),
		"evidence_locator": loc,
	}
}

exception_decisions[id] := e if {
	some i, exc in exception_inventory
	id := exc.id
	d := identity.decision with input as exc
	loc := sprintf("%s#/exceptions/%d", [state_file, i])
	e := {
		"policy_id": identity.control_id,
		"resource_id": id,
		"asset_locator": loc,
		"allow": d.allow,
		"violation_code": object.get(d, "violation_code", null),
		"evidence_locator": loc,
	}
}

# ---------- assembled report ----------
# Object keys iterate in sorted order, so decision order is deterministic.

identity_list := [v | some _, v in identity_decisions]

storage_list := [v | some _, v in storage_decisions]

endpoint_list := [v | some _, v in endpoint_decisions]

exception_list := [v | some _, v in exception_decisions]

decisions := array.concat(
	array.concat(identity_list, storage_list),
	array.concat(endpoint_list, exception_list),
)

denied := [d | some d in decisions; d.allow == false]

compliance_report := {
	"schema_version": "1.0",
	"source_state": state_file,
	"reference_time": reference_time,
	"controls_evaluated": sort([
		identity.control_id,
		storage.control_id,
		endpoint.control_id,
	]),
	"decisions": decisions,
	"summary": {
		"total_decisions": count(decisions),
		"allowed": count(decisions) - count(denied),
		"denied": count(denied),
	},
}