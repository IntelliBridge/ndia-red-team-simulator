# F002 — Evaluation Catalog

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned  
**Suggested owner role:** Evaluation researcher  
**Required reviewers:** Product owner; security/data reviewer

## What and why

Maintain traceable, versioned metadata for benign model and dataset resources so profiles and runs refer to reviewed provenance rather than mutable labels.

## Scope

- Register stable model and dataset records with immutable metadata versions.
- Reference only approved public or synthetic benign fixtures in the initial scope.
- Review provenance and approval status independently of authorship.
- Edit drafts by creating or updating an unused draft version.
- Archive records or versions without breaking historical references.
- Hard-delete only unused draft versions after explicit confirmation.

## Exclusions

- Arbitrary uploads, executable artifacts, arbitrary endpoints, secrets, or provider setup.
- Fetching or executing a model or dataset.
- Sensitive, operational, mission-system, weapons, or combat-targeting content.
- Profile definition, run execution, evidence, or retention purge.

## Prioritized user stories

### US1 (P1) — Register traceable benign metadata

As an Analyst, I can create a model or dataset record and draft version with provenance and an approved fixture reference.

**Independent test:** Create each record type, validate required metadata, and verify unsupported or unapproved references fail without partial records.

- **Given** an approved public fixture reference and complete provenance, **when** an Analyst saves a draft, **then** a stable record and draft version are visible.
- **Given** an arbitrary endpoint or upload, **when** registration is attempted, **then** it is rejected with D003-gated guidance.
- **Given** no records, **when** the catalog opens, **then** a benign empty state offers registration only to permitted roles.

### US2 (P1) — Review and approve a version

As an independent Reviewer, I can inspect provenance and approve or reject a draft version for later profile use.

**Independent test:** Verify author independence, required provenance, permissions, immutable approval, and visible rejection reasons.

- **Given** a complete draft authored by another member, **when** a Reviewer approves it, **then** that exact version becomes approved and immutable.
- **Given** the author is also the acting Reviewer, **when** approval is attempted, **then** it is blocked.
- **Given** missing provenance, **when** review is submitted, **then** approval fails and the missing fields are identified.

### US3 (P2) — Retire or remove safely

As an Analyst or Owner acting within policy, I can archive referenced catalog material or delete only an unused draft.

**Independent test:** Attempt archive and delete against referenced, approved, unused-draft, and stale versions.

- **Given** a version referenced by a profile or run, **when** retirement is requested, **then** it is archived and historical references remain readable.
- **Given** an unused draft, **when** an authorized user confirms deletion, **then** it is removed and the outcome is recorded.
- **Given** a referenced or non-draft version, **when** hard deletion is requested, **then** it is blocked with reference context.

## Functional requirements

- **FR-001:** Only active Owners and Analysts MAY create/edit drafts, archive, or request eligible draft deletion; Reviewers and Viewers are read-only except for a separately authorized review action.
- **FR-002:** Each record MUST have a stable project-scoped ID and one or more immutable version IDs with explicit type.
- **FR-003:** Each version MUST capture source, license/usage statement, public-or-synthetic classification, domain, content summary, and non-secret fixture reference.
- **FR-004:** Initial references MUST come from an approved benign fixture allowlist; uploads and arbitrary endpoints MUST be rejected pending D003.
- **FR-005:** Version states MUST include draft, approved, rejected, and archived, with actor, reason, and timestamp for review transitions.
- **FR-006:** Approval MUST require an authorized Reviewer or Owner who did not author the version; an Owner cannot bypass independence.
- **FR-007:** Approved versions MUST be immutable; descriptive changes MUST create a new draft version.
- **FR-008:** Only active Owners and Analysts MAY archive; archived versions MUST be excluded from new selections while remaining readable wherever historically referenced.
- **FR-009:** Only active Owners and Analysts MAY request hard deletion, which MUST be limited to unused drafts, require explicit confirmation, and fail if any profile, run, or governance reference exists.
- **FR-010:** Catalog list/detail UI MUST expose type, version, provenance, state, archived status, loading, empty, validation, denied, stale, and unavailable behavior.
- **FR-011:** Mutations MUST enforce project/object authorization server-side and emit the agreed F008 event envelope without sensitive payloads.
- **FR-012:** Duplicate, stale, missing-reference, and event-write failures MUST be explicit and MUST NOT produce partial approval or deletion.

## Key entities

- **CatalogRecord:** Stable project-scoped identity and model/dataset type.
- **ModelVersion:** Immutable metadata version, provenance, benign reference, author, and state.
- **DatasetVersion:** Immutable metadata version, provenance, benign reference, author, and state.
- **CatalogReview:** Version, independent reviewer, decision, reason, and timestamp.
- **FixtureReference:** Approved non-secret pointer and governance classification.

## Edge cases

- A fixture is withdrawn after an approved version was used by a run.
- A draft becomes referenced between delete confirmation and commit.
- Two reviewers decide the same draft concurrently.
- Source metadata changes without changing the underlying fixture.
- A catalog result exists but is filtered out because it is archived.

## Success criteria

- **SC-001:** Focused checks show 100% of approved sampled versions contain all required provenance and an approved benign fixture reference.
- **SC-002:** Focused lifecycle checks permit hard deletion for unused drafts only and preserve every sampled historical reference after archive.
- **SC-003:** In moderated review, users identify record type, exact version, provenance, and approval state for all sampled catalog entries without opening another tool.

## Unresolved decisions and gates

- **D001:** First domain determines domain-specific metadata.
- **D002:** Managed identity blocks authorized implementation through F001.
- **D003:** Permitted formats, access method, and proposed catalog approval policy require product/security review.
- **D007:** Named owner and reviewers remain unassigned.
- **Catalog approval:** FR-006 now matches the proposed shared access matrix: an independent Reviewer or Owner may approve. This resolves the document inconsistency, not the pending D003 approval.