# Tasks: Findings Review

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested role: independent review lead)  
All paths are proposed future targets. Task IDs are scoped to F006.
## Setup and contracts
- [ ] **T001** [Product Lead] Route D001/D005/D006/D007 decisions to the shared owners; retain gates in `specs/006-findings-review/plan.md`.
- [ ] **T002** [Domain Modeler] Define revisions, reviews, recommendations, and retest links in `specs/006-findings-review/data-model.md`.
- [ ] **T003** [API Lead] Define state commands and read projections in `specs/006-findings-review/contracts/findings.yaml`.
- [ ] **T004** [Integration Owner] Coordinate accepted API edits in `lib/api-spec/openapi.yaml` and regenerate `lib/api-client-react/` and `lib/api-zod/`.
- [ ] **T005** [Database Engineer] Propose persistence only after review in `lib/db/src/schema/findings.ts`.
## US1 — Author a finding
- [ ] **T006** [Backend Engineer] Implement authorized draft creation and evidence validation in `artifacts/api-server/src/routes/assurance/findings.ts`.
- [ ] **T007** [Backend Engineer] Implement immutable revision and stale-write behavior in `artifacts/api-server/src/services/assurance/finding-review.ts`.
- [ ] **T008** [Frontend Engineer] Build separated observation, interpretation, and candidate recommendation editor in `artifacts/ai-assurance/src/features/findings/FindingEditor.tsx`.
- [ ] **T009** [Frontend Engineer] Build unavailable-evidence, validation, and conflict states in `artifacts/ai-assurance/src/features/findings/FindingState.tsx`.
- [ ] **T010** [Test Engineer] Verify create/edit/submit, revision history, and evidence failures in `artifacts/api-server/src/tests/assurance/findings-authoring.test.ts`.
## US2 — Independently review
- [ ] **T011** [Backend Engineer] Implement authoritative transition and non-author review checks in `artifacts/api-server/src/services/assurance/finding-review.ts`.
- [ ] **T012** [Frontend Engineer] Build review queue and exact-revision view in `artifacts/ai-assurance/src/features/findings/ReviewQueue.tsx`.
- [ ] **T013** [Frontend Engineer] Build confirm, dismiss-with-reason, and request-changes controls in `artifacts/ai-assurance/src/features/findings/ReviewDecision.tsx`.
- [ ] **T014** [Test Engineer] Verify all transition edges, self-review denial including Owner, and concurrent decisions in `artifacts/api-server/src/tests/assurance/findings-review.test.ts`.
- [ ] **T015** [P] [Accessibility Reviewer] Specify review labels and focus behavior in `specs/006-findings-review/contracts/review-accessibility.md`.
## US3 — Retest and resolve
- [ ] **T016** [Evaluation Researcher] Define compatibility inputs after D005 in `specs/006-findings-review/contracts/retest-compatibility.md`.
- [ ] **T017** [Backend Engineer] Implement retest request/link and reviewed-resolution guards in `artifacts/api-server/src/services/assurance/finding-review.ts`.
- [ ] **T018** [Frontend Engineer] Build retest status and compatibility view in `artifacts/ai-assurance/src/features/findings/RetestReview.tsx`.
- [ ] **T019** [Test Engineer] Verify partial, incompatible, unreviewed, and valid retest outcomes in `artifacts/api-server/src/tests/assurance/findings-retest.test.ts`.
## Cross-cutting verification
- [ ] **T020** [Security Engineer] Verify object authorization, blocked archive/delete, and explicit retention handoff in `artifacts/api-server/src/tests/assurance/findings-authorization.test.ts`.
- [ ] **T021** [Frontend Test Engineer] Verify empty/error states and optional F005 link absence in `artifacts/ai-assurance/src/tests/findings-review.test.tsx`.
- [ ] **T022** [Independent Reviewer] Trace US1–US3 and SC-001–SC-003 evidence in `specs/006-findings-review/acceptance.md`.

## Requirement coverage

| Requirement | Tasks |
| --- | --- |
| FR-001 | T006, T011, T014, T020 |
| FR-002 | T006, T008, T010 |
| FR-003 | T007, T010, T014 |
| FR-004 | T006, T009, T010 |
| FR-005 | T011, T013, T014 |
| FR-006 | T003, T011, T014 |
| FR-007 | T016, T017, T018, T019 |
| FR-008 | T008, T017, T020 |
| FR-009 | T012, T021 |
| FR-010 | T002, T007, T012 |
| FR-011 | T007, T020 |
| FR-012 | T009, T014, T019, T021 |