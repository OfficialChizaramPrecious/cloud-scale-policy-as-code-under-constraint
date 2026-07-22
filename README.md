# GRC Advanced 1 — Policy Gap Under Constraint

Stage 5 submission: policy-as-code implementation of three assigned control outcomes for CloudScale Dynamics, along with the supporting gap analysis, corrected framework mapping, evidence index, and policy addendum.

**Repository:** https://github.com/OfficialChizaramPrecious/cloud-scale-policy-as-code-under-constraint.git

**Frozen commit:** 9eb95b08bb18b11bb16054eeb504314e0f7412c3
**Candidate:** Chizaram Precious / UBI-2026-0099

---

## What this is

This project implements the three control outcomes assigned in `control-state.json` as OPA/Rego policies.

| Control | Requirement |
|---|---|
| `NF.IDENTITY.PRIVILEGED_ASSURANCE` | Privileged human identities require phishing-resistant MFA; privileged service identities require a named owner and credentials nthat are not older than 90 days |
| `NF.STORAGE.RESTRICTED_PROTECTION` | Restricted or confidential storage must not be public, must be encrypted, and must reference an existing immutable log sink |
| `NF.ENDPOINT.MANAGED_HEALTH` | In-scope endpoints must be managed, disk-encrypted, EDR-healthy, and available within 24 hours of the state's `generated_at` |

For every asset, the policy engine produces a decision containing the policy ID, asset locator, allow/deny result, violation code, and evidence locator. Those decisions are then used to generate `compliance-report.json`, which is always produced automatically and should never be edited by hand.

## Prerequisites

Before getting started, make sure you have:

- **OPA** 1.18.2 or later — this is a single binary, so no installation is required. Download it from https://www.openpolicyagent.org/docs/latest/#running-opa and place `opa` (or `opa.exe`) either in your repository root or somewhere on your system PATH.
- You don't need an additional runtime, package manager, or network access.

Verified environment: Windows 11 (windows/amd64), OPA 1.18.2, Rego v1.

## Commands

I advice you run all commands from the repository root.

### Provision — verify the toolchain

```bash
opa version
```

### Build — regenerate the compliance report from state

PowerShell:

```powershell
opa eval -d policy-bundle/ -d control-state.json "data.policy.report.compliance_report" --format pretty | Set-Content -Encoding utf8 compliance-report.json
```

POSIX shell:

```bash
opa eval -d policy-bundle/ -d control-state.json "data.policy.report.compliance_report" --format pretty > compliance-report.json
```

### Test — run the acceptance suite

```bash
opa test policy-bundle/ tests/ -v
```

Expected result: all tests pass, covering the 18 published fixtures along with the positive, malformed-input, exception-expiry, audit-log, and precedence cases.

To generate a machine-readable report:

```powershell
opa test policy-bundle/ tests/ --format json | Set-Content -Encoding utf8 tests/test-results.json
```

### Check — parse and type-check the bundle

```bash
opa check policy-bundle/
```

If nothing is returned, all modules compiled successfully.

### Clean — then we remove generated outputs

PowerShell:

```powershell
Remove-Item -ErrorAction SilentlyContinue compliance-report.json, tests/test-results.json, bundle.tar.gz
```

POSIX shell:

```bash
rm -f compliance-report.json tests/test-results.json bundle.tar.gz
```

## Repository layout

```text
policy-bundle/          Rego source
  identity.rego         NF.IDENTITY.PRIVILEGED_ASSURANCE
  storage.rego          NF.STORAGE.RESTRICTED_PROTECTION
  endpoint.rego         NF.ENDPOINT.MANAGED_HEALTH
  report.rego           Report generator; contains no control logic
tests/                  Acceptance suite, one file per control
schemas/                JSON Schema for inputs, decisions, and the report
control-state.json      Assigned state; authoritative input
compliance-report.json  It was generated after the report.rego  — you should do not edit by hand
```

The supporting governance and analysis artifacts (`policy-gap-report.pdf`, `policy-addendum.pdf`, `control-mapping.csv`, `evidence-index.csv`, `decision-log.md`, `continuity-record.md`, `integrity-attestation.md`, `manifest.sha256`, and `assessment-manifest.json`) are all located in the repository root.

## Reproducing the results

To reproduce the project output:

1. Run `opa check policy-bundle/` to confirm the modules compile.
2. Run `opa test policy-bundle/ tests/ -v` to verify the acceptance suite passes.
3. Run the build command shown above to regenerate `compliance-report.json`.

The report is deterministic. Expiry and freshness checks are evaluated against the `generated_at` value in `control-state.json`, rather than the current system time. This means running the project on a different day still produces byte-identical output.

## Adding a state fixture or exception

New assets and exceptions can be added by updating the state file only—**no policy source changes are required.**

1. Add the new object to the appropriate array in `control-state.json` (`identities`, `storage`, `endpoints`, or `exceptions`), making sure it matches the structure defined in `schemas/input.schema.json`.
2. Re-run the build command.
3. The new asset will appear in `compliance-report.json` with its own decision, asset locator, and violation code, and the `summary` counts will update automatically.

The policies process the inventory generically. They do not contain hard-coded asset IDs, fixture identifiers, expected verdicts, or counts. As long as the new case is covered by the existing violation vocabulary in `schemas/decision.schema.json`, no changes to `policy-bundle/` are needed.

## Design notes

- **Deterministic violation selection.** Each control defines an explicit precedence list and emits exactly one `violation_code`. The complete set of violations remains available at `<package>.violations`. Since Rego set iteration order is not guaranteed, precedence is defined explicitly instead of being inferred.

- **Fail closed.** Exceptions that are missing any of the five governance fields (owner, reason, approver, expiry, or compensating control), or that contain an unparseable or expired date, are denied. Endpoints with missing or unparseable timestamps are also treated as stale.

- **Harness-independent data paths.** State collections resolve correctly whether the state file is loaded at the data root or namespaced under `control_state`.

A full explanation of the design decisions—including rejected alternatives and the fail-open defect identified during the acceptance suite—is documented in `decision-log.md`.

## Integrity

`manifest.sha256` is generated only after every other project file has been finalized.

To verify file integrity:

PowerShell:

```powershell
Get-FileHash -Algorithm SHA256 <file>
```

POSIX shell:

```bash
sha256sum -c manifest.sha256
```