# storage_test.rego
# Acceptance tests for NF.STORAGE.RESTRICTED_PROTECTION.
#
# Covers published fixtures P-OPA-04, 05, 06, 16, 17, 18 plus positive,
# out-of-scope, audit-log (immutable sink), and precedence cases.
#
# The logging inventory is supplied explicitly so tests are deterministic
# whether or not control-state.json is loaded alongside them.

package policy.storage_test

import rego.v1

import data.policy.storage

logging_fixture := [
	{"id": "audit-main", "immutable": true, "retention_days": 365},
	{"id": "audit-legacy", "immutable": false, "retention_days": 14},
]

# ---------- published negative fixtures ----------

test_p_opa_04_restricted_public_denied if {
	d := storage.decision with input as {
		"classification": "restricted",
		"encryption": "customer-managed",
		"log_sink": "audit-main",
		"public": true,
		"resource_id": "asset-131b99",
	} with data.logging as logging_fixture

	d.allow == false
	d.control_id == "NF.STORAGE.RESTRICTED_PROTECTION"
	d.resource_id == "asset-131b99"
	d.violation_code == "STORAGE_PUBLIC"
}

test_p_opa_05_confidential_unencrypted_denied if {
	d := storage.decision with input as {
		"classification": "confidential",
		"encryption": "none",
		"log_sink": "audit-main",
		"public": false,
		"resource_id": "asset-c776f0",
	} with data.logging as logging_fixture

	d.allow == false
	d.violation_code == "STORAGE_UNENCRYPTED"
}

test_p_opa_06_restricted_missing_log_sink_denied if {
	d := storage.decision with input as {
		"classification": "restricted",
		"encryption": "customer-managed",
		"log_sink": null,
		"public": false,
		"resource_id": "asset-ea13c7",
	} with data.logging as logging_fixture

	d.allow == false
	d.violation_code == "STORAGE_LOG_MISSING"
}

test_p_opa_16_restricted_public_denied if {
	d := storage.decision with input as {
		"classification": "restricted",
		"encryption": "customer-managed",
		"log_sink": "audit-main",
		"public": true,
		"resource_id": "asset-71ce8b",
	} with data.logging as logging_fixture

	d.allow == false
	d.resource_id == "asset-71ce8b"
	d.violation_code == "STORAGE_PUBLIC"
}

test_p_opa_17_confidential_unencrypted_denied if {
	d := storage.decision with input as {
		"classification": "confidential",
		"encryption": "none",
		"log_sink": "audit-main",
		"public": false,
		"resource_id": "asset-d76d96",
	} with data.logging as logging_fixture

	d.allow == false
	d.violation_code == "STORAGE_UNENCRYPTED"
}

test_p_opa_18_restricted_missing_log_sink_denied if {
	d := storage.decision with input as {
		"classification": "restricted",
		"encryption": "customer-managed",
		"log_sink": null,
		"public": false,
		"resource_id": "asset-f3b038",
	} with data.logging as logging_fixture

	d.allow == false
	d.violation_code == "STORAGE_LOG_MISSING"
}

# ---------- audit-log behaviour: sink must be immutable ----------

test_non_immutable_sink_rejected if {
	d := storage.decision with input as {
		"classification": "restricted",
		"encryption": "customer-managed",
		"log_sink": "audit-legacy",
		"public": false,
		"resource_id": "asset-log-01",
	} with data.logging as logging_fixture

	d.allow == false
	d.violation_code == "STORAGE_LOG_MISSING"
}

test_unknown_sink_rejected if {
	d := storage.decision with input as {
		"classification": "restricted",
		"encryption": "customer-managed",
		"log_sink": "sink-that-does-not-exist",
		"public": false,
		"resource_id": "asset-log-02",
	} with data.logging as logging_fixture

	d.allow == false
	d.violation_code == "STORAGE_LOG_MISSING"
}

# ---------- positive and scope cases ----------

test_compliant_restricted_store_allowed if {
	d := storage.decision with input as {
		"classification": "restricted",
		"encryption": "customer-managed",
		"log_sink": "audit-main",
		"public": false,
		"resource_id": "asset-pos-10",
	} with data.logging as logging_fixture

	d.allow == true
	not d.violation_code
}

test_internal_classification_out_of_scope_allowed if {
	d := storage.decision with input as {
		"classification": "internal",
		"encryption": "none",
		"log_sink": "audit-main",
		"public": false,
		"resource_id": "asset-pos-11",
	} with data.logging as logging_fixture

	d.allow == true
}

# ---------- malformed input (fail closed) ----------

test_empty_string_sink_denied if {
	d := storage.decision with input as {
		"classification": "confidential",
		"encryption": "customer-managed",
		"log_sink": "",
		"public": false,
		"resource_id": "asset-mal-10",
	} with data.logging as logging_fixture

	d.allow == false
	d.violation_code == "STORAGE_LOG_MISSING"
}

# ---------- deterministic precedence ----------

test_public_precedes_unencrypted if {
	d := storage.decision with input as {
		"classification": "restricted",
		"encryption": "none",
		"log_sink": null,
		"public": true,
		"resource_id": "asset-prec-10",
	} with data.logging as logging_fixture

	d.violation_code == "STORAGE_PUBLIC"
}

test_full_violation_set_retained if {
	v := storage.violations with input as {
		"classification": "restricted",
		"encryption": "none",
		"log_sink": null,
		"public": true,
		"resource_id": "asset-prec-11",
	} with data.logging as logging_fixture

	"STORAGE_PUBLIC" in v
	"STORAGE_UNENCRYPTED" in v
	"STORAGE_LOG_MISSING" in v
	count(v) == 3
}