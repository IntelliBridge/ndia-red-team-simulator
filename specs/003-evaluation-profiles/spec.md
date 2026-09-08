# F003 — Evaluation Profiles

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned  
**Suggested owner role:** Evaluation lead  
**Required reviewers:** Product owner; independent reviewer; security/data reviewer

## What and why

Define versioned, reviewable evaluation configurations that bind approved benign catalog inputs to explicit tests, controls, limits, and explanation support before any run can be requested.

## Scope

- Create draft profile records and immutable profile versions.
- Select compatible approved model and dataset versions.
- Record evaluation definitions, benign controls, limits, evaluator settings, explanation support, and known limitations.
- Validate compatibility and completeness.
- Require author-independent approval and publish the approved immutable version.
- Archive profiles while preserving historical references.

## Exclusions

- Executing profiles or selecting a runtime.
- Tactical attack instructions, exploit recipes, poisoning pipelines, unrestricted code, or operational targets.
- Universal SHAP requirements or causal claims from attribution.
- Editing an approved/published version in place.
- Domain-specific implementation until D001/D005 resolve.

## Prioritized user stories

### US1 (P1) — Draft a bounded profile

As an Analyst, I can draft an evaluation profile from approved compatible catalog versions with explicit benign controls and limits.

**Independent test:** Compose a draft using approved and disallowed combinations; verify validation, save, empty, and permission behavior without executing anything.

- **Given** compatible approved inputs, **when** an Analyst saves required definitions and controls, **then** a new draft version is visible.
- **Given** archived, unapproved, or incompatible inputs, **when** save or validation is requested, **then** it fails with specific corrective guidance.
- **Given** explanation support is unavailable for the chosen domain, **when** the draft is viewed, **then** unavailability and its implication are explicit rather than fabricated.

### US2 (P1) — Independently approve and publish

As a Reviewer, I can review a complete profile authored by someone else and publish exactly the approved version.

**Independent test:** Verify independent approval, stale-version rejection, validation evidence, immutable publication, and direct-request authorization.

- **Given** a validated draft by another author, **when** a Reviewer approves it, **then** the exact version becomes published and immutable.
- **Given** the author attempts approval, **when** the action is submitted, **then** it is blocked even if the author is an Owner.
- **Given** the draft changed after review opened, **when** approval is submitted, **then** the stale decision fails and requires renewed review.

### US3 (P2) — Revise or retire a profile

As an Analyst, I can create a new draft from a published profile or archive a profile without altering prior runs.

**Independent test:** Revise, archive, and attempt deletion across unused and referenced versions.

- **Given** a published version, **when** revision starts, **then** a distinct draft version is created with lineage.
- **Given** a profile used by a run, **when** it is archived, **then** new selection stops while prior run provenance remains readable.
- **Given** an unused draft, **when** deletion is confirmed, **then** only that draft is removed; referenced or published versions are blocked.

## Functional requirements

- **FR-001:** Only active Owners and Analysts MAY create or edit profile drafts; Reviewers and Viewers MUST be read-only except approval actions allowed by role.
- **FR-002:** A profile MUST have a stable project-scoped ID and immutable version IDs with author and lineage.
- **FR-003:** Each version MUST reference exact approved, non-archived model and dataset versions and report compatibility results.
- **FR-004:** Each version MUST state purpose, evaluation definitions, denominators, benign controls, bounds, evaluator settings, explanation type/support, and limitations.
- **FR-005:** Content MUST remain non-operational and MUST NOT store executable attack recipes, tactical instructions, unrestricted code, or poisoning workflows.
- **FR-006:** States MUST include draft, in_review, published, rejected, and archived; state changes require actor, timestamp, and reason where applicable.
- **FR-007:** Submission MUST validate completeness, catalog state, compatibility, and D005-defined criteria; failures MUST identify affected fields without publishing.
- **FR-008:** Publication MUST require an authorized Reviewer or Owner other than the author, and MUST bind the decision to the exact reviewed version.
- **FR-009:** Published versions MUST be immutable; changes MUST create a linked draft and require renewed independent review.
- **FR-010:** Only active Owners and Analysts MAY archive or request deletion; archive MUST prevent new run selection while preserving existing run references, and hard deletion MUST be limited to unused drafts after confirmation.
- **FR-011:** List, editor, validation, review, and archive UI MUST explicitly handle loading, empty, unsupported explanation, stale, denied, rejected, and unavailable states.
- **FR-012:** Every mutation MUST enforce project/object authorization server-side and emit the agreed F008 event envelope; event failure MUST prevent silent state change.

## Key entities

- **Profile:** Stable project-scoped profile identity.
- **ProfileVersion:** Immutable inputs, definitions, controls, limits, settings, limitations, author, state, and lineage.
- **CompatibilityAssessment:** Exact input versions, checks, support status, and reasons.
- **ProfileReview:** Exact version, independent reviewer, decision, reason, and timestamp.

## Edge cases

- An approved input is archived while a profile awaits review.
- Explanation support is partial for only some evaluation definitions.
- Two editors branch from the same published profile.
- Review and archive requests race.
- Validation criteria change after a version is published.

## Success criteria

- **SC-001:** Focused checks reject 100% of sampled publish attempts lacking independent approval, required controls, compatible approved inputs, or explicit limitations.
- **SC-002:** Every sampled published profile remains byte-for-byte unchanged while revisions receive distinct version IDs and renewed review.
- **SC-003:** In moderated review, users correctly identify supported explanations, benign controls, limitations, and exact catalog versions for all sampled profiles.

## Unresolved decisions and gates

- **D001:** First domain blocks domain-specific profile content.
- **D002:** Managed identity through F001 blocks authorized implementation.
- **D003:** Catalog formats constrain compatibility.
- **D005:** Definitions, controls, denominators, thresholds, and explanation support block publication rules.
- **D007:** Named owner and independent reviewer remain unassigned.