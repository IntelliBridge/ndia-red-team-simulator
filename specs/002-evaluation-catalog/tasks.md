# F002 — Proposed Tasks

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested: Evaluation researcher)  
Tasks are future work; no checkbox indicates completion.

## Gate and setup tasks

- [ ] **T001** Product/evaluation leads: resolve D001 and D003, including the proposed independent catalog approval policy, through the designated owner of `specs/_shared/decisions.md`.
- [ ] **T002** Project owner: resolve D007 and confirm F001 plus minimal F008 contracts are approved.
- [ ] **T003** Evaluation researcher: draft provenance, fixture, version, review, and reference invariants in `specs/002-evaluation-catalog/data-model.md`.
- [ ] **T004** API contract owner: draft `specs/002-evaluation-catalog/contracts/evaluation-catalog.openapi.yaml`; after review coordinate `lib/api-spec/openapi.yaml` and regeneration.
- [ ] **T005** Security/data reviewer: review the benign fixture allowlist governance and confirm uploads, arbitrary endpoints, secrets, and executable artifacts are excluded.

## US1 — Register traceable metadata

- [ ] **T006** Data engineer: after T003, propose record/version/review/reference constraints in `lib/db/src/schema/evaluation-catalog.ts`.
- [ ] **T007** Backend engineer: after T004 and T006, implement proposed registration and validation in `artifacts/api-server/src/services/assurance/evaluation-catalog.ts`.
- [ ] **T008** Backend engineer: after T007, expose proposed authorized catalog routes in `artifacts/api-server/src/routes/assurance/evaluation-catalog.ts`.
- [ ] **T009** [P] Frontend engineer: after T004, implement proposed list and draft editor, including empty/validation/denied states, in `artifacts/ai-assurance/src/features/evaluation-catalog/CatalogEditor.tsx`.

## US2 — Independent review

- [ ] **T010** Backend engineer: after T007, implement version-bound independent review, immutable approval, rejection reasons, conflicts, and required events in the catalog service.
- [ ] **T011** [P] Frontend engineer: after T004, implement provenance detail and approve/reject behavior in `artifacts/ai-assurance/src/features/evaluation-catalog/CatalogReview.tsx`.
- [ ] **T012** Test engineer: after T008 and T010, add authorization, provenance, independence, immutability, duplicate, and event-failure checks in `artifacts/api-server/src/tests/assurance/evaluation-catalog.test.ts`.

## US3 — Archive or guarded delete

- [ ] **T013** Backend engineer: after T006, implement archive filtering and transactional unused-draft deletion guard in the catalog service/routes.
- [ ] **T014** Frontend engineer: after T009 and T011, add archive/delete confirmation, stale/reference conflict, loading, and unavailable behavior under `artifacts/ai-assurance/src/features/evaluation-catalog/`.
- [ ] **T015** [P] Test engineer: after T009, T011, and T014, add proposed lifecycle UI checks in `artifacts/ai-assurance/src/tests/evaluation-catalog.test.tsx`.
- [ ] **T016** Engineering reviewer: review US1–US3 acceptance and traceability; retain unchecked status until the owning agent runs verification.

## Requirement coverage

| Requirement | Proposed task coverage |
| --- | --- |
| FR-001 | T004, T007, T008, T012 |
| FR-002 | T003, T004, T006 |
| FR-003 | T003, T005, T007, T012 |
| FR-004 | T005, T007, T009, T012 |
| FR-005 | T003, T004, T006, T010 |
| FR-006 | T010, T011, T012 |
| FR-007 | T006, T010, T012 |
| FR-008 | T013, T014, T015 |
| FR-009 | T006, T013, T014, T012 |
| FR-010 | T009, T011, T014, T015 |
| FR-011 | T002, T007, T008, T010, T013 |
| FR-012 | T007, T010, T012, T013 |