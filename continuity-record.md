# Continuity Record — Stage 5, GRC Advanced 1

**Candidate:** Chizaram Precious 
**Track:** GRC 
**Date:** 7-22-2026

Programme context

The UBI programme runs in two phases. Phase 1 was generalist: all interns worked the same Sankofa Digital investigation across Stages 0–4, covering SOC analysis, ethical hacking, and GRC. Phase 2 is track specialisation; I selected GRC (recorded in my Phase 1 Ethics Stance and Track Selection submission). This capstone is the first project of my specialised track, so continuity runs from the GRC deliverables of Phase 1.

1. Previous-stage component reused

Component: The typed risk-and-control record model I built in Phase 1, expressed across three deliverables:

Phase 1 artifact	Date	Structure contributed
Risk Register (Stage 4 Task 1)	29 June 2026	Row model: ID, risk statement, justified likelihood/impact, one concrete control, accountable owner role, evidence citation
Control Mapping — NIST CSF 2.0 / ISO 27001:2022 / MITRE D3FEND	Phase 1, Stage 4	Row model: finding ID, observed weakness, stage/task evidence, one CSF identifier, one ISO Annex A control; plus coverage-check and evidence-appendix sections
30/60/90 Remediation Roadmap	03 July 2026	Row model: action ID, window, action, owner role, budget tier, evidence cite, CSF function, ISO control; plus an explicit deferral list with evidence, deferral window, and justification

Version pinning: These deliverables were produced as documents and were not held in version control, so no commit hash exists for them. In place of a commit, each reused artifact is pinned by filename, submission date, and SHA-256 hash recorded in evidence-index.csv. Stage 5 establishes the first Git-tracked repository for my GRC line; the frozen 40-character commit for this stage is recorded in assessment-manifest.json and becomes the pin that Stage 6 cites.

2. Interface consumed and backward-compatible extension

Consumed: the Phase 1 finding-record interface — one finding → one risk statement → one accountable owner → one NIST CSF 2.0 identifier → one ISO/IEC 27001:2022 Annex A control → one evidence citation.

Stage 5's control-mapping.csv consumes that interface directly. Every Phase 1 field survives; the columns are renamed to the assigned template but carry the same meaning (risk_statement, nist_csf_2_id, iso_27001_2022_control, evidence_needed, owner captured in the decision field alongside the review trigger).

Backward-compatible extensions added at Stage 5:

gap_type — findings are now separated into policy, implementation, process, and evidence gaps. Phase 1 treated all findings as technical weaknesses; the taxonomy is additive and does not invalidate any Phase 1 row.
exact_locator — Phase 1 cited evidence at file level (e.g. Stage 2 Task 1 – notes/es-creds-extract.json). Stage 5 narrows this to a precise position inside the artifact (clause number, JSON pointer, named block). This strengthens the same citation field rather than replacing it.
why_it_applies — an explicit justification for each framework mapping.
decision — each finding now carries an implement/reduce/defer/accept disposition with owner and review trigger, required by the board constraint.

Method carried forward. The correction logged in my Phase 1 control mapping ("One mistake I almost made" — I nearly forced most weaknesses into Access Control, then corrected by asking what each weakness was mainly about) is the same test I applied to the planted mapping in this stage. It is why the BYOD privacy-boundary gap was remapped from A.8.12 (data leakage prevention) to A.5.34 (privacy and protection of PII), while A.8.12 was retained for the support-attachment protection gap where it does apply. The reasoning method is reused, not the finding.

Deferral discipline carried forward. The Phase 1 roadmap's explicit deferral list (each deferral carrying evidence, a deferral window, and a stated reason it waits) is the ancestor of this stage's deferral treatment under the three-control board constraint. Stage 5 extends it by requiring a named owner and a review trigger on every non-implemented finding.

Legal basis carried forward. My Phase 1 NDPA notification work (Sections 40 and 41, Nigeria Data Protection Act 2023, including the 72-hour notification window and the discipline of stating what is still being verified) is the source of the legal reasoning in this stage's Legal Basis section and of the four-hour triage requirement in addendum Clause 5 — a helpdesk route that took 31 hours to escalate cannot support a 72-hour statutory clock.

3. Provenance evidence

Phase 1 provenance held at artifact level: every risk-register row, mapping row, and roadmap action cited the stage, task, and source file it came from, and no recommendation appeared without a citation. That chain is intact in the delivered documents and was not changed  by in this  stage.

Stage 5 preserves and strengthens the same rule. Every claim in policy-gap-report.pdf has a row in evidence-index.csv giving artifact path, exact locator, collection time, SHA-256, what it proves, what it does not prove, and the alternative considered. Machine claims additionally reconcile to compliance-report.json, which is regenerated from control-state.json through documented commands rather than edited by hand.

Scope limit, stated deliberately: Phase 1 and Stage 5 concern different fictional clients (Sankofa Digital; CloudScale Dynamics). No evidence artifact, finding, or figure transfers between them, and none is claimed to. What carries forward is the record model, the mapping method, the deferral discipline, and the legal reasoning — not data.

4. Migration record (incompatible changes)

M-01 — Documents to executable policy. Phase 1 delivered controls as written recommendations. Stage 5 requires the same controls to be executable: three assigned outcomes implemented as OPA/Rego policies emitting machine-readable decisions with violation codes. Incompatibility: a prose recommendation has no deterministic output and cannot be tested. Migration: each control is expressed as a typed rule over the versioned control-state.json schema, with the written control text in the addendum worded to reconcile exactly with the engine logic. The Phase 1 documents remain valid as governance records; they are not re-executed.

M-02 — Unversioned to version-controlled. Phase 1 artifacts were standalone documents with no repository, no commits, and no build commands. Migration: Stage 5 initialises the Git repository, records the frozen commit in assessment-manifest.json, and pins Phase 1 artifacts by SHA-256 in evidence-index.csv in place of commits. From this stage onward the GRC line is version-controlled.

M-03 — MITRE D3FEND column dropped. The Phase 1 mapping carried a third framework column (D3FEND counter-technique). Stage 5 requires NIST CSF 2.0 and ISO/IEC 27001:2022 Annex A identifiers only. Migration: the field is dropped from the schema rather than left empty; the Phase 1 D3FEND values remain in the archived artifact and can be reintroduced as an optional field without breaking the current row model.

M-04 — Scoring model deferred, not carried. Phase 1 scored risk with a 1–5 likelihood/impact matrix (NIST SP 800-30 Rev. 1). Stage 5 prioritises by board constraint and control assignment rather than numeric score, so the matrix is not consumed here. Migration: the priority field in control-mapping.csv records high/medium/low derived from regulatory exposure and funded-control status. The 800-30 matrix remains available for reintroduction where quantitative scoring is required.

5. Handed forward to Stage 6
Typed control model — control identifier, rule statement, applicability condition, and violation codes, defined in schemas/.
Exception model — owner, reason, approver, expiry, compensating control, with fail-closed handling for incomplete, malformed, or expired exceptions.
Evidence-quality model — the proves / does-not-prove / alternative-considered / disposition columns in evidence-index.csv, with SHA-256 pinning and exact locators.
Decision ledger — compliance-report.json, regenerable from state through documented commands, plus the reasoning trail in decision-log.md.
Deferral register — every non-implemented finding with owner and review trigger, in control-mapping.csv.
The frozen commit for this stage is 656400772e11efa51a224a0dc87c09a77e4a9e48, recorded in assessment-manifest.json, and is the pin Stage 6 cites as its previous-stage reference.