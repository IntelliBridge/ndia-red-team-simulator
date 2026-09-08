# F003 — Proposed Tasks

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested: Evaluation lead)  
Tasks are future work; no checkbox indicates completion.

## Gate and setup tasks

- [ ] **T001** Product/evaluation leads: resolve D001, D003, and D005 in `specs/_shared/decisions.md` through the designated shared-file owner.
- [ ] **T002** Project owner: resolve D007 and confirm approved F001, F002, and minimal F008 contracts.
- [ ] **T003** Evaluation lead: draft profile/version, compatibility, review, lineage, and immutable publication rules in `specs/003-evaluation-profiles/data-model.md`.
- [ ] **T004** API contract owner: draft `specs/003-evaluation-profiles/contracts/evaluation-profiles.openapi.yaml`; after review coordinate `lib/api-spec/openapi.yaml` and regeneration.
- [ ] **T005** Security/evaluation reviewers: review the declarative content boundary and reject operational recipes, unrestricted code, and unsupported explanation claims.

## US1 — Draft a bounded profile

- [ ] **T006** Data engineer: after T003, propose profile/version/review/reference constraints in `lib/db/src/schema/evaluation-profiles.ts`.
- [ ] **T007** Backend engineer: after T004 and T006, implement proposed draft and compatibility validation in `artifacts/api-server/src/services/assurance/evaluation-profiles.ts`.
- [ ] **T008** Backend engineer: after T007, expose authorized profile routes and explicit field/support failures in `artifacts/api-server/src/routes/assurance/evaluation-profiles.ts`.
- [ ] **T009** [P] Frontend engineer: after T004, implement proposed editor, catalog selector, controls, limits, explanation support, and validation states in `artifacts/ai-assurance/src/features/evaluation-profiles/ProfileEditor.tsx`.

## US2 — Independently approve and publish

- [ ] **T010** Backend engineer: after T007, implement exact-version submission/review, author independence, stale rejection, immutable publication, and F008 event calls.
- [ ] **T011** [P] Frontend engineer: after T004, implement review summary plus approve/reject controls in `artifacts/ai-assurance/src/features/evaluation-profiles/ProfileReview.tsx`.
- [ ] **T012** Test engineer: after T008 and T010, add permission, compatibility, independence, content-boundary, stale, immutability, and event checks in `artifacts/api-server/src/tests/assurance/evaluation-profiles.test.ts`.

## US3 — Revise or retire

- [ ] **T013** Backend engineer: after T006 and T010, implement linked revision, archive, historical visibility, and unused-draft delete guard.
- [ ] **T014** Frontend engineer: after T009 and T011, add version history, revise/archive/delete confirmations, and empty/denied/stale/unavailable states under `artifacts/ai-assurance/src/features/evaluation-profiles/`.
- [ ] **T015** [P] Test engineer: after T009, T011, and T014, add proposed editor/review/lifecycle UI checks in `artifacts/ai-assurance/src/tests/evaluation-profiles.test.tsx`.
- [ ] **T016** Engineering reviewer: review US1–US3 acceptance and traceability; do not claim execution or completed verification.

## Requirement coverage

| Requirement | Proposed task coverage |
| --- | --- |
| FR-001 | T004, T007, T008, T010, T012 |
| FR-002 | T003, T004, T006, T013 |
| FR-003 | T003, T007, T009, T012 |
| FR-004 | T001, T003, T007, T009 |
| FR-005 | T005, T007, T012 |
| FR-006 | T003, T004, T006, T010, T013 |
| FR-007 | T007, T008, T009, T012 |
| FR-008 | T010, T011, T012 |
| FR-009 | T006, T010, T012, T013 |
| FR-010 | T006, T013, T014, T015 |
| FR-011 | T008, T009, T011, T014, T015 |
| FR-012 | T002, T008, T010, T012, T013 |