# F004 — Proposed Tasks

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested: Platform lead)  
Tasks are future work; no checkbox indicates completion.

## Gate and setup tasks

- [ ] **T001** Product/evaluation leads: resolve D001, D003, and D005 through the designated owner of `specs/_shared/decisions.md`.
- [ ] **T002** Platform/security reviewers: resolve D004, including runtime ownership, isolation, ceilings, authentication, ordering, timeout, and cancellation; install nothing.
- [ ] **T003** Project owner: resolve D007 and confirm approved F001–F003 contracts plus the F008 event writer contract.
- [ ] **T004** Platform/data engineers: draft snapshots, transitions, idempotency, ordering, errors, completeness, and lineage in `specs/004-run-management/data-model.md`.
- [ ] **T005** API contract owner: draft `specs/004-run-management/contracts/run-management.openapi.yaml`; after review coordinate `lib/api-spec/openapi.yaml` and regeneration.
- [ ] **T006** Platform/security reviewers: draft and approve `specs/004-run-management/contracts/execution-adapter.openapi.yaml` without implementing a worker.

## US1 — Request and observe a run

- [ ] **T007** Data engineer: after T004, propose run/transition/request constraints in `lib/db/src/schema/run-management.ts`.
- [ ] **T008** Backend engineer: after T005–T007, implement proposed authorization, immutable snapshot, idempotent request, and no-runtime refusal in `artifacts/api-server/src/services/assurance/run-management.ts`.
- [ ] **T009** Backend engineer: after T008, expose proposed run request/list/detail routes in `artifacts/api-server/src/routes/assurance/run-management.ts`.
- [ ] **T010** [P] Frontend engineer: after T005, implement proposed run trigger/list/detail and every empty/lifecycle/unavailable state in `artifacts/ai-assurance/src/features/run-management/RunManagement.tsx`.

## US2 — Cancel safely

- [ ] **T011** Backend engineer: after T006–T008, implement authenticated idempotent adapter updates, valid transitions, cancel ordering, stale rejection, and required events.
- [ ] **T012** [P] Frontend engineer: after T005, implement cancellation confirmation, cancel_requested, race, denied, and stale behavior in `artifacts/ai-assurance/src/features/run-management/RunActions.tsx`.
- [ ] **T013** Test engineer: after T009 and T011, add matrix, state-machine, race, adapter-authentication, event-failure, and no-web-fallback checks in `artifacts/api-server/src/tests/assurance/run-management.test.ts`.

## US3 — Retry without rewriting history

- [ ] **T014** Backend engineer: after T008 and T011, implement current-eligibility checks, new linked retry/rerun creation, partial completeness, and safe errors.
- [ ] **T015** Frontend engineer: after T010 and T012, add retry confirmation, blocked eligibility, lineage, partial-evidence, skipped, explanation-unavailable, and error presentation.
- [ ] **T016** [P] Test engineer: after T010, T012, and T015, add proposed lifecycle UI checks in `artifacts/ai-assurance/src/tests/run-management.test.tsx`.
- [ ] **T017** Engineering reviewer: review US1–US3 acceptance and traceability; no live run or completed-test claim is permitted.

## Requirement coverage

| Requirement | Proposed task coverage |
| --- | --- |
| FR-001 | T005, T008, T009, T013 |
| FR-002 | T003, T004, T008, T013 |
| FR-003 | T004, T007, T008, T013 |
| FR-004 | T004, T007, T011, T013 |
| FR-005 | T002, T006, T008, T011, T013 |
| FR-006 | T002, T008, T010, T013 |
| FR-007 | T004, T011, T012, T013 |
| FR-008 | T007, T014, T015, T016 |
| FR-009 | T006, T011, T013 |
| FR-010 | T004, T014, T015, T016 |
| FR-011 | T010, T012, T015, T016 |
| FR-012 | T003, T008, T011, T013, T014 |