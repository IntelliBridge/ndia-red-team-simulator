# Feature Specification: Findings Review

**Feature:** F006 — Findings Review  
**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested role: independent review lead)  
**Approval required:** Product owner, engineering reviewer, security/data reviewer
## What and why

Findings review turns authorized observations into traceable, revisable, independently reviewed judgments. It keeps evidence, observation, interpretation, and candidate recommendation separate, prevents authors from approving their own work even when they are owners, and requires a compatible reviewed retest before resolution.
## Scope

- Evidence-linked findings based on F004 evidence and F001 authorization.
- Distinct observation, interpretation, and candidate recommendation fields.
- Draft revisions, submission, independent confirmation, dismissal, change request, retest request, and resolution.
- Review reasons, revision history, authorship, reviewer identity, and linked retest evidence.
- Optional navigation to an F005 evidence view when available.
- Explicit empty, stale-revision, incompatible-retest, denied, and unavailable-evidence states.
## Exclusions

- Editing F004 evidence or treating F005 visualizations as new evidence.
- Automatic confirmation from detectors or automatic application of a defense.
- Claims that recommendations work before a separate compatible comparison supports them.
- Operational, tactical, weapons, sensitive-target, or attack-recipe content.
- Owner override of independent review or resolution requirements.

## User stories

### US1 — Author an evidence-linked finding (P1)

As an analyst, I want to draft and revise a finding with separated claims so a reviewer can trace each statement to evidence.

**Independent test:** Create a draft from authorized evidence, revise it, and submit a frozen revision without requiring F005, reports, or retention tooling.

- **Given** authorized readable F004 evidence, **When** an analyst creates a draft, **Then** evidence references and separate observation, interpretation, and candidate recommendation fields are recorded.
- **Given** a draft owned by the actor, **When** it is edited, **Then** a new draft revision preserves prior revision history.
- **Given** required evidence is missing or unreadable, **When** submission is attempted, **Then** submission fails explicitly and the draft remains draft.

### US2 — Independently review a finding (P1)

As an independent reviewer, I want to confirm, dismiss, or return a submitted revision so judgments remain accountable.

**Independent test:** Submit one finding and exercise each permitted review outcome using a different actor, then verify self-review is blocked for an owner-author.

- **Given** a finding is `in_review`, **When** an eligible non-author reviewer confirms it, **Then** the exact revision becomes `confirmed` with a review reason and history.
- **Given** the reviewer is the revision author, **When** confirmation is attempted, **Then** it fails even if that actor has the Owner role.
- **Given** a reviewer requests changes, **When** the decision is recorded, **Then** a new editable draft revision is created and renewed review is required.

### US3 — Retest and resolve (P2)

As a reviewer, I want a confirmed finding linked to a compatible retest so resolution is based on evidence rather than a rerun alone.

**Independent test:** Link compatible and incompatible retests to a confirmed finding and verify only a separately reviewed compatible retest permits resolution.

- **Given** a confirmed finding, **When** an authorized actor requests a retest, **Then** it becomes `retest_requested` without changing or applying its candidate recommendation.
- **Given** a linked retest is incompatible or incomplete, **When** resolution is attempted, **Then** resolution is blocked with the unmet conditions.
- **Given** a compatible retest has reviewed evidence, **When** an eligible non-author reviewer resolves the finding, **Then** the decision and evidence link are retained.

## Functional requirements

- **FR-001:** All reads and mutations MUST require active project membership, server-side object authorization, and role checks from F001.
- **FR-002:** Owners and Analysts MUST be able to create finding drafts from readable F004 evidence with separate observation, interpretation, and candidate recommendation content.
- **FR-003:** Draft edits MUST create or preserve identifiable revisions; submitted and reviewed revisions MUST be immutable, and post-review changes MUST create a new revision.
- **FR-004:** Submission MUST validate required evidence references and move an eligible draft to `in_review`; missing, inaccessible, or incompatible evidence MUST fail explicitly.
- **FR-005:** Eligible Reviewers or Owners MUST be able to confirm, dismiss with reason, or return an `in_review` revision to `draft`, but MUST NOT review a revision they authored.
- **FR-006:** Finding states MUST follow `draft`, `in_review`, `confirmed`, `dismissed`, `retest_requested`, and `resolved` transitions defined by the shared contract; stale or invalid transitions MUST fail.
- **FR-007:** Confirmed findings MUST support a retest request, while resolution MUST require a compatible linked retest and an independent review of its relevant evidence.
- **FR-008:** Recommendations MUST remain labeled candidate actions, MUST preserve their supporting rationale and revision, and MUST NOT be applied automatically to a model, profile, or run.
- **FR-009:** F005 evidence-view links MAY be offered when available, but F006 MUST operate directly from F004 evidence references and MUST not depend on F005.
- **FR-010:** Finding/review records MUST expose author, reviewer, timestamps, reasons, evidence links, revision history, and limitations while distinguishing observation from interpretation.
- **FR-011:** Ordinary archive and delete of submitted or reviewed revisions MUST be unavailable; draft withdrawal and any later retention deletion MUST be authorized, explicit, and history-preserving.
- **FR-012:** Empty queues, unavailable evidence, revoked access, stale revisions, incompatible retests, and persistence failures MUST be shown explicitly without false confirmation or resolution.

## Key entities

- **Finding:** Project-scoped identity and current state over immutable revisions.
- **FindingRevision:** Evidence references, observation, interpretation, candidate recommendations, author, limitations, and submission status.
- **Recommendation:** Revision-bound candidate action, not an applied defense.
- **Review:** Independent actor, exact revision, decision, reason, and timestamp.
- **RetestLink:** Original finding revision, linked F004 run/evidence, compatibility assessment, and review status.

## Edge cases

- A finding author later becomes an Owner; self-approval remains blocked.
- Two reviewers decide against the same revision concurrently; only one valid transition is accepted.
- Evidence access is revoked after drafting but before submission or review.
- A new revision is made while a reviewer has an older revision open.
- A retest finishes partially or changes one unapproved variable.
- A recommendation is removed in a later draft; prior reviewed content remains historical.

## Success criteria

- **SC-001:** In focused checks, 100% of self-confirmation attempts, including Owner-authors, fail without changing finding state.
- **SC-002:** Every sampled reviewed finding links its exact revision to readable evidence or an explicit later redaction marker and separates observation, interpretation, and recommendation.
- **SC-003:** In acceptance review, zero sampled findings reach `resolved` without a compatible linked retest and recorded independent review.

## Unresolved decisions

- **D001:** First benign domain and domain language.
- **D005:** Evidence thresholds, compatibility, and review criteria.
- **D006:** Retention handling for withdrawn drafts and historical evidence.
- **D007:** Accountable owner and independent reviewers.