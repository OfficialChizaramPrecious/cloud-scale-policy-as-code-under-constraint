Decision Log — GRC Advanced 1: Policy Gap Under Constraint

Candidate: Chizaram Precious Patrick · 
Intern ID: UBI-2026-0099 
Evidence marker: UBI-A5-264EFAFE5E84 
Frozen commit: [FINAL-COMMIT-HASH]

Entries are in the order the decisions were made. Each major conclusion records at least one alternative that was considered and why it was weakened or retained, per the anti-shortcut standard. Entries D-08 onward were made during implementation and testing; D-11, D-12, and D-15 record changes made after evidence from test runs.

D-01 · Assistance declared

Decision: Use an AI assistant (Claude, Anthropic) for document structure, prose drafting, Rego scaffolding, test-failure diagnosis, and review of edits proposed by a second assistant — as permitted by programme rules, with declaration. All framework mappings, evidence verdicts, control decisions, and design choices below were reviewed by me, tested where testable, and are mine to defend.

Rejected alternative: Omitting the declaration so the work would not read as AI-assisted (advice received from a second assistant). Rejected because declared assistance is a required submission check, and the integrity attestation must remain truthful under defense questioning. Concealing method to improve appearance is the opposite of what this project assesses.

D-02 · Gap taxonomy applied before mapping

Decision: Classify every finding as policy, implementation, process, or evidence before assigning framework controls. G-001 (AUP makes MFA optional) and G-002 (no Conditional Access enforcement for all privileged roles) are logged separately.

Rejected alternative: Recording them as one "MFA gap." Rejected because they have different fixes and different evidence — amending the AUP does not change the Entra ID tenant, and the reliability notes evidence the enforcement failure independently of the policy text.

D-03 · Corrected planted mapping: A.8.12 → A.5.34

Decision: The colleague's mapping of the BYOD privacy-boundary gap to ISO A.8.12 (data leakage prevention) is materially wrong. Corrected to A.5.34 (privacy and protection of PII), supported by NDPA lawfulness and proportionality requirements.

Reasoning: A.8.12 exists to stop organisational data leaving through technical channels. Legal's message of 10 July 2026 raises a different question — whether monitoring staff-owned devices is lawful, proportionate, and disclosed. A DLP deployment under the existing clause would extend monitoring without a lawful basis, worsening the exposure.

Rejected alternative: Retaining A.8.12 on the basis that DLP "touches" BYOD data. Weakened because control objective and gap subject do not match. A.8.12 is not discarded — it remains correctly mapped to G-005, the protection of support attachments holding personal data. Keeping it there demonstrates the distinction rather than treating the control as wrong in general.

Constraint check: Only the framework mapping was corrected. No assigned control outcome was added, replaced, or substituted.

D-04 · MDM screenshot rejected as proof of current implementation

Decision: mdm-compliance.png proves partial historical coverage only.

Reasoning: Captured 18 November 2024; shows 91 devices with 89 encrypted against a current inventory of 176 company laptops plus approved personal devices; no export metadata establishes provenance.

Rejected alternative: Accepting it as directional evidence with a caveat. Weakened because the owner's claim was categorical — that it proves encryption is implemented everywhere — while the artifact covers at most about half the current estate with unknown provenance. A caveat cannot rescue a categorical claim.

What would change the verdict: a current MDM export carrying metadata, reconciled against the asset inventory.

D-05 · Three-control selection

Decision: Implement exactly the three assigned outcomes, each using tooling CloudScale already owns (Entra ID, central logging, MDM), to stay inside 900 staff-hours with 24/7 support maintained.

Rejected alternative: Substituting an incident-management control for the endpoint control, given the 31-hour escalation failure. Rejected because adding or replacing an assigned outcome fails the board constraint by definition. The escalation risk is instead reduced through addendum Clause 5, with a named owner and review trigger.

D-06 · G-009 (JML) dispositioned as reduce, not accept

Decision: Adopt Engineering's offered JML automation as an enabler of the funded identity control; defer only the company-wide programme.

Rejected alternative: Accepting the JML gap outright for the quarter, which appeared in an earlier draft. Weakened because service-account ownership and credential-age limits decay without a lifecycle process — accepting the gap would undercut the sustainability of a control I am funding in the same document.

D-07 · Stakeholder resolution scope

Decision: Scope phishing-resistant MFA to privileged roles only, matching Engineering's offer of 9 July 2026. Resolve Legal's two concerns through addendum clauses rather than new controls.

Rejected alternative: Company-wide security keys. Weakened by Engineering's stated contractor-turnover constraint and the effort cap. Privileged-only scope covers the accounts the assigned control actually targets.

D-08 · Deterministic single primary violation

Decision: Each control package emits a full violations set plus one primary_violation chosen by an explicit precedence list.

Reasoning: Fixtures expect a single violation_code. Hidden fixtures with different IDs and ordering must not change output.

Rejected alternative: Reporting whichever violation evaluates first. Rejected because Rego set iteration order is not a contract; output could vary across runs or OPA versions, breaking the determinism requirement.

D-09 · Reference time from versioned state, not wall clock

Decision: Exception expiry and endpoint freshness compare against generated_at in control-state.json, never time.now_ns().

Rejected alternative: Wall-clock time. Rejected because decisions would change from day to day, breaking reproducibility and making the artifact check non-deterministic.

Verification: Regenerating compliance-report.json on separate runs produces an identical SHA-256.

D-10 · Fail-closed exception and input handling

Decision: Exceptions missing any of the five governance fields, holding empty values, or carrying unparseable or past expiry are denied. Missing or unparseable endpoint timestamps are treated as stale.

Rejected alternative: Treating malformed fields as absent but tolerable. Rejected because the brief requires malformed, incomplete, and expired exceptions to fail closed, and tolerance would create hidden-fixture risk.

D-11 · Two-tier log-sink validation, and data-path resolution

Decision: The storage policy accepts a non-empty sink reference when evaluating a standalone fixture input, but requires the sink to exist and be immutable when the logging inventory is present in loaded data.

Rejected alternative: Fixture-level existence checking only. Weakened because the control text requires an existing immutable log sink; audit-legacy exists but is not immutable and must fail. The two-tier approach enforces the full requirement against real state while remaining compatible with fixture-shaped inputs, which carry no inventory.

Resolved (previously open): The harness data path was verified by evaluation. control-state.json loads at the data root, so data.control_state.* references did not resolve and every endpoint was returning stale. All three policies now resolve collections through helper rules that accept either the data root or a control_state namespace, so the bundle works regardless of how the grader loads the state file. Acceptance suite: 41/41.

D-12 · Exception violations emitted under the identity control ID

Decision: Exception-shaped inputs are evaluated in the identity package and denied under NF.IDENTITY.PRIVILEGED_ASSURANCE.

Reasoning: Published fixtures P-OPA-11 and P-OPA-12 bind exception failures to that control ID.

Rejected alternative: A standalone shared exceptions module with its own control ID. Cleaner in principle, but it would fail the published fixtures.

Resolved (previously open): Confirmed by test. Both exception fixtures pass under the identity control ID, and exc-01 in the real state is reported as EXCEPTION_EXPIRED under the same ID. Retained as a possible refactor if a future stage introduces exception-specific control identifiers.

D-13 · Addendum enforceability corrections

Decision: All binding clauses use "must"; every clause carries an exception route; Clause 2 states "existing immutable log sink" to reconcile word for word with the engine; Clause 1's approver is "the designated risk owner or Security" for consistency with exc-01, which was approved by a risk owner; endpoint scope is limited to company devices with the BYOD enforcement gap named and owned.

Rejected alternative: A second assistant's softer draft, which used "should" for the incident triage requirement, said "approved logging system" instead of immutable sink, and omitted exception routes from three of six clauses. Weakened because "should" is unauditable, the wording diverged from engine logic and would break exact reconciliation, and missing exception routes fail the stated clause requirements.

D-14 · Cross-artifact reconciliation rules

Decision: Gap IDs use the G-00N format in every artifact. The gap report, control-mapping.csv, evidence-index.csv, and compliance-report.json must agree. manifest.sha256 is generated last.

Rejected alternative: Allowing cosmetic differences between the report and the CSV. Rejected because cross-artifact reconciliation is an explicit grading check.

D-15 · Fail-open defect found by the acceptance suite

Decision: Endpoint freshness was implemented as fresh(input.last_seen). When last_seen is absent, the argument is undefined, which makes the enclosing violation rule undefined — so no violation fired and the device was allowed. That is the opposite of the fail-closed requirement in D-10.

How it was found: the malformed-input test test_missing_last_seen_treated_as_stale failed with an empty violation set. The published fixtures did not catch it, because all 18 supply a last_seen value.

Correction: the field is now read inside a zero-argument rule, so a missing or unparseable timestamp leaves the rule undefined and not fresh_endpoint fires. Covered by regression tests for both the missing-field and unparseable-value cases.

Rejected alternative: Adding an explicit presence check for input.last_seen alongside the function call. Weakened because it leaves the same trap in place for every other field and duplicates the condition in two locations. Fixing the shape of the rule addresses the class of defect rather than the instance.

Assessment: I regard this class of defect — an undefined field argument silently disabling a rule — as the weakest area of the implementation and the first thing I would audit in any future Rego work.

D-16 · Violation code omitted on allow, null in report rows

Decision: Decision objects omit violation_code entirely when allow is true, and carry exactly one code when false. Report entries in compliance-report.json carry violation_code: null on allow so every row has uniform keys.

Reasoning: decision.schema.json encodes the contract structurally — a deny must have a code, an allow must not — so a malformed decision fails schema validation rather than passing silently. Report rows serve a different purpose and need consistent columns to be machine-readable.

Rejected alternative: Uniform shape everywhere, with violation_code: null on allow decisions too. Simpler for consumers, but it would require dropping the conditional block from the decision schema and would lose the structural guarantee. All 18 published fixtures are deny cases, so neither choice is tested by them; the choice was made on the strength of the contract rather than on fixture pressure.

D-17 · Owner titles stated as accountable functions

Decision: Addendum clauses and deferral rows name Head of Security and Head of IT Support as owners, although the evidence pack names neither title. It records only that Security has two staff and no dedicated policy administrator, and that incidents route to an IT helpdesk.

Rejected alternative: Using only titles that appear verbatim in the corpus. Weakened because two clauses would then have no assignable owner, and every clause is required to name one. The assumption is declared in the addendum rather than left implicit, so a reviewer can see where the corpus ends and my inference begins.

D-19 · Pack Signature Unavailable

Decision: Left `manifest_signature` empty and set `verified_before_use` to `false`. Documented the issue in the Known Limitations and Integrity Attestation.

Reasoning: The assessment required a staff-issued manifest signature, but none was provided. The archive contained only the four evidence files with no signature or checksum. A digital signature cannot be generated from the file itself.

Rejected Alternative: Using the pack's SHA-256 hash as the signature. Rejected because a hash is not a digital signature and would give a false impression of verification.

