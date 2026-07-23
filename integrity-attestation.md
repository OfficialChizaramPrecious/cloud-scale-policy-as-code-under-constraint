Integrity Attestation — Stage 5, GRC Advanced 1

Candidate: Chizaram Precious
Intern ID: UBI-2026-0099
Track: GRC 

Project: GRC-A1 — Policy Gap Under Constraint
Variant: V1
Evidence marker: UBI-A5-264EFAFE5E84
Frozen Commit: 656400772e11efa51a224a0dc87c09a77e4a9e48
Repository: https://github.com/OfficialChizaramPrecious/cloud-scale-policy-as-code-under-constraint.git
Date: 7-21-2026

1. Authorship and AI Assistance

This submission represents my own work. I carried out the analysis, reviewed the evidence, mapped the controls, wrote and tested the policies, and made the final implementation decisions myself. I understand every part of this project and can explain or defend any decision I made during the assessment.

I used AI tools, specifically Claude (Anthropic) and ChatGPT (OpenAI), as learning and support tools throughout this project. They helped me understand some parts of the assessment, explain concepts, identify mistakes, suggest possible improvements, and gave me commands to troubleshoot errors during testing.

I did not copy their responses directly into my submission without checking them first. Every suggestion was reviewed, tested, and either accepted, modified, or rejected based on my own understanding. The final content, policy logic, evidence assessments, and implementation decisions are my responsibility.

I did not receive work from another candidate, nor did I share any assessment materials, hidden fixtures, staff resources, or private indicators with anyone else.

2. Assigned Inputs

The assigned pack's SHA-256 (35401db7…) and the staff-issued manifest signature (8aa3106de2…) are recorded in assessment-manifest.json. The pack hash was verified against the private overlay before use.

3. Evidence Integrity

Every important conclusion in my Policy Gap Report is supported by evidence that is recorded in evidence-index.csv. Each entry includes where the evidence came from, where it can be found, when it was collected, and the SHA-256 hash recorded during collection.

I did not edit, alter, crop, or manipulate any evidence. Where the available evidence was not strong enough to support a conclusion, I clearly documented it as an evidence gap instead of making assumptions. For example, the MDM dashboard screenshot was treated as insufficient evidence rather than being used to support a stronger claim.

Where more than one explanation was possible, I compared the available evidence before deciding which conclusion was the most appropriate.

4. Executable Work

The compliance-report.json file is generated automatically from control-state.json by the policy bundle using the documented build process in the project README. It was not created or edited manually.

Running the project again from the frozen commit should produce the same output because all time-based checks use the generated_at value from the control state instead of the current system time.

The acceptance tests run successfully without manual intervention and produce machine-readable results. I did not hard-code asset IDs, fixture IDs, expected outcomes, hidden indicators, or assessment-specific values into the policy source. These identifiers only appear where they are expected, such as the test data and generated outputs.

5. Consistency

The findings in my written report, control-mapping.csv, evidence-index.csv, and compliance-report.json are consistent with each other.

Only the three assigned control outcomes were implemented as required. I did not add, replace, or substitute any additional controls. Any remaining gaps were documented with their current status, an assigned owner, and a review trigger.

6. Sanitisation

This submission does not contain passwords, API keys, access tokens, secrets, malware, or real personal information.

All organisational information relates to the fictional organisation provided for this assessment. Any names included are the fictional roles supplied as part of the assessment materials.

7. Known Limitations

I believe it is important to be transparent about the current limitations of my work.

My acceptance tests verify the published fixtures together with additional edge cases that I created. They cannot guarantee behaviour against the hidden assessment fixtures.
The logging validation performs a complete existence and immutability check only when the required logging inventory is available. When only standalone fixture data is used, validation falls back to checking for a valid sink reference. This behaviour is documented in my decision log.
Exception records are currently evaluated through the Identity policy because this matches the published fixtures. A shared exception module would make the design cleaner and could be considered in future improvements.
During testing I discovered a fail-open issue in my endpoint freshness logic where an endpoint without a last_seen value could incorrectly pass evaluation. I fixed the issue and added a regression test to prevent it from happening again. Based on this project, I consider missing or undefined input fields to be the area that deserves the most careful review in future policy development.
8. Submission Handling

Before submission, I confirmed that every required file opens correctly, the submission folder is view-only, and the final integrity checks complete successfully.

I will not rename, replace, move, or delete any submitted files until the assessment process and any required defence have been completed.

Declaration

I confirm that the information provided in this attestation is true and accurate to the best of my knowledge. I accept responsibility for the work submitted and understand that I may be asked to explain or defend any part of it during the assessment.

Signed: upp
Name: Chizaram Precious 

Date: 7-21-2026