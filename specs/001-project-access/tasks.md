# F001 — Proposed Tasks

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested: Engineering lead)  
Tasks are future work; no checkbox indicates completion.

## Gate and setup tasks

- [ ] **T001** Product owner: resolve D002 bootstrap, managed invitation delivery acknowledgement, identity matching, expiry, revocation, and duplicate behavior in `specs/_shared/decisions.md` through its designated owner; send no invitation.
- [ ] **T002** Project owner: resolve D007 by assigning owner and reviewers in the decision register.
- [ ] **T003** Security reviewer: approve the minimal F008 event envelope and fail-closed policy proposed by F008.
- [ ] **T004** Backend engineer: inspect existing auth/database conventions and draft Project, Membership, Invitation, and access-decision invariants in `specs/001-project-access/data-model.md`.
- [ ] **T005** API contract owner: draft and review access plus invitation issue/revoke/accept operations in `specs/001-project-access/contracts/project-access.openapi.yaml`; after acceptance coordinate `lib/api-spec/openapi.yaml` and regeneration.

## US1 — Authorized project entry

- [ ] **T006** Backend engineer: propose managed-session and object-action authorization handling in `artifacts/api-server/src/services/assurance/project-access.ts`.
- [ ] **T007** Backend engineer: propose protected project/session endpoints and explicit denial/unavailability responses in `artifacts/api-server/src/routes/assurance/project-access.ts`.
- [ ] **T008** [P] Frontend engineer: after T005, implement proposed sign-in/project-entry/action-visibility states in `artifacts/ai-assurance/src/features/project-access/ProjectAccessGate.tsx`.
- [ ] **T009** [P] Test engineer: after T006–T007, add focused absent/suspended/removed/expiry and role-matrix checks in `artifacts/api-server/src/tests/assurance/project-access.test.ts`.

## US2 — Safe membership management

- [ ] **T010** Data engineer: after T004, add proposed transactional membership/revision constraints in `lib/db/src/schema/project-access.ts`.
- [ ] **T011** Backend engineer: after T010, implement proposed role/status transitions, stale-write handling, last-owner guard, and required events in the F001 service/routes.
- [ ] **T012** [P] Frontend engineer: after T005, implement role edit, suspend, restore, remove confirmations and conflict behavior in `artifacts/ai-assurance/src/features/project-access/MembershipEditor.tsx`.
- [ ] **T013** Test engineer: after T011, add concurrency, direct-authorization, event-failure, and transition checks to the F001 server test.

## US3 — Managed invitation onboarding and roster review

- [ ] **T014** Backend engineer: after T004–T005 and T010, implement proposed Owner-only issue/revoke, provider-acknowledged states, verified identity acceptance, atomic membership creation, expiry, mismatch, and duplicate handling in the F001 service/routes.
- [ ] **T015** [P] Frontend engineer: after T005, implement proposed project/role/recipient issue and revoke behavior in `artifacts/ai-assurance/src/features/project-access/InvitationManager.tsx`.
- [ ] **T016** [P] Frontend engineer: after T005, implement proposed verified acceptance plus expired/revoked/mismatched/duplicate/provider-failure outcomes in `artifacts/ai-assurance/src/features/project-access/InvitationAcceptance.tsx`.
- [ ] **T017** Test engineer: after T014, add provider acknowledgement/failure, authorization, expiry, revocation, identity match, concurrency, duplicate, and no-access checks to the F001 server test.
- [ ] **T018** Frontend engineer: after T007 and T012, implement roster filtering plus loading/empty/denied/stale/unavailable outcomes in `artifacts/ai-assurance/src/features/project-access/MembershipRoster.tsx`.
- [ ] **T019** [P] Test engineer: after T008, T012, T015, T016, and T018, add proposed invitation and roster UI behavior checks in `artifacts/ai-assurance/src/tests/project-access.test.tsx`.
- [ ] **T020** Engineering reviewer: review acceptance evidence mapping for US1–US3; do not mark implementation complete until focused checks are actually run by the owning agent.

## Requirement coverage

| Requirement | Proposed task coverage |
| --- | --- |
| FR-001 | T001, T004, T006, T009, T014, T017 |
| FR-002 | T006, T007, T009, T013, T014, T017 |
| FR-003 | T005, T006, T008, T009 |
| FR-004 | T001, T008, T019 |
| FR-005 | T003, T011, T013 |
| FR-006 | T004, T005, T010, T011, T014 |
| FR-007 | T010, T011, T013 |
| FR-008 | T001, T004, T005, T014, T015, T017 |
| FR-009 | T011, T012, T013, T019 |
| FR-010 | T004, T010, T011 |
| FR-011 | T008, T012, T015, T016, T018, T019 |
| FR-012 | T006, T007, T009, T013 |
| FR-013 | T004, T005, T014, T015, T017 |
| FR-014 | T001, T005, T014, T015, T017, T019 |
| FR-015 | T001, T004, T014, T016, T017 |
| FR-016 | T004, T005, T014, T016, T017, T019 |