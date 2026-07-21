# endpoint_test.rego
# Acceptance tests for NF.ENDPOINT.MANAGED_HEALTH.
#
# Covers published fixtures P-OPA-07, 08, 09, 10 plus positive, boundary,
# malformed-input, and precedence cases.
#
# reference_time is pinned explicitly so freshness results do not depend on
# wall-clock time or on control-state.json being loaded alongside the tests.

package policy.endpoint_test

import rego.v1

import data.policy.endpoint

ref := "2026-07-13T08:00:00Z"

# ---------- published negative fixtures ----------

test_p_opa_07_unmanaged_endpoint_denied if {
	d := endpoint.decision with input as {
		"disk_encrypted": true,
		"edr_healthy": true,
		"last_seen": "2026-07-13T07:00:00Z",
		"managed": false,
		"resource_id": "asset-dff441",
	} with data.generated_at as ref

	d.allow == false
	d.control_id == "NF.ENDPOINT.MANAGED_HEALTH"
	d.resource_id == "asset-dff441"
	d.violation_code == "ENDPOINT_UNMANAGED"
}

test_p_opa_08_unencrypted_disk_denied if {
	d := endpoint.decision with input as {
		"disk_encrypted": false,
		"edr_healthy": true,
		"last_seen": "2026-07-13T07:00:00Z",
		"managed": true,
		"resource_id": "asset-1241d7",
	} with data.generated_at as ref

	d.allow == false
	d.violation_code == "ENDPOINT_DISK_UNENCRYPTED"
}

test_p_opa_09_unhealthy_edr_denied if {
	d := endpoint.decision with input as {
		"disk_encrypted": true,
		"edr_healthy": false,
		"last_seen": "2026-07-13T07:00:00Z",
		"managed": true,
		"resource_id": "asset-1217fb",
	} with data.generated_at as ref

	d.allow == false
	d.violation_code == "ENDPOINT_EDR_UNHEALTHY"
}

test_p_opa_10_stale_endpoint_denied if {
	d := endpoint.decision with input as {
		"disk_encrypted": true,
		"edr_healthy": true,
		"last_seen": "2026-07-01T07:00:00Z",
		"managed": true,
		"resource_id": "asset-9ab9be",
	} with data.generated_at as ref

	d.allow == false
	d.violation_code == "ENDPOINT_STALE"
}

# ---------- positive and boundary cases ----------

test_healthy_endpoint_allowed if {
	d := endpoint.decision with input as {
		"disk_encrypted": true,
		"edr_healthy": true,
		"last_seen": "2026-07-13T07:50:00Z",
		"managed": true,
		"resource_id": "asset-pos-20",
	} with data.generated_at as ref

	d.allow == true
	not d.violation_code
}

test_endpoint_seen_just_inside_window_allowed if {
	d := endpoint.decision with input as {
		"disk_encrypted": true,
		"edr_healthy": true,
		"last_seen": "2026-07-12T08:00:00Z",
		"managed": true,
		"resource_id": "asset-pos-21",
	} with data.generated_at as ref

	d.allow == true
}

test_endpoint_seen_just_outside_window_denied if {
	d := endpoint.decision with input as {
		"disk_encrypted": true,
		"edr_healthy": true,
		"last_seen": "2026-07-12T07:59:00Z",
		"managed": true,
		"resource_id": "asset-neg-21",
	} with data.generated_at as ref

	d.allow == false
	d.violation_code == "ENDPOINT_STALE"
}

# ---------- malformed input (fail closed) ----------

test_missing_last_seen_treated_as_stale if {
	d := endpoint.decision with input as {
		"disk_encrypted": true,
		"edr_healthy": true,
		"managed": true,
		"resource_id": "asset-mal-20",
	} with data.generated_at as ref

	d.allow == false
	d.violation_code == "ENDPOINT_STALE"
}

test_unparseable_last_seen_treated_as_stale if {
	d := endpoint.decision with input as {
		"disk_encrypted": true,
		"edr_healthy": true,
		"last_seen": "yesterday",
		"managed": true,
		"resource_id": "asset-mal-21",
	} with data.generated_at as ref

	d.allow == false
	d.violation_code == "ENDPOINT_STALE"
}

# ---------- deterministic precedence ----------

test_unmanaged_precedes_other_violations if {
	d := endpoint.decision with input as {
		"disk_encrypted": false,
		"edr_healthy": false,
		"last_seen": "2026-07-01T07:00:00Z",
		"managed": false,
		"resource_id": "asset-prec-20",
	} with data.generated_at as ref

	d.violation_code == "ENDPOINT_UNMANAGED"
}

test_full_violation_set_retained if {
	v := endpoint.violations with input as {
		"disk_encrypted": false,
		"edr_healthy": false,
		"last_seen": "2026-07-01T07:00:00Z",
		"managed": false,
		"resource_id": "asset-prec-21",
	} with data.generated_at as ref

	"ENDPOINT_UNMANAGED" in v
	"ENDPOINT_DISK_UNENCRYPTED" in v
	"ENDPOINT_EDR_UNHEALTHY" in v
	"ENDPOINT_STALE" in v
	count(v) == 4
}