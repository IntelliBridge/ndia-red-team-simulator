# Tasks: Audit and Governance

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested role: security and data governance lead)  
All paths are proposed future targets. Task IDs are scoped to F008.
## Setup and foundational event contract
- [ ] **T001** [Security Architect] Resolve G2 field, allowlist, bounds, and failure-policy proposal in `specs/008-audit-governance/contracts/audit-event.yaml`.
- [ ] **T002** [Domain Modeler] Define event, policy, retention, and deletion-marker ownership in `specs/008-audit-governance/data-model.md`.
- [ ] **T003** [API Lead] Define writer result and governance interfaces in `specs/008-audit-governance/contracts/governance-policy.yaml`.
- [ ] **T004** [Integration Owner] Coordinate accepted API changes in `lib/api-spec/openapi.yaml` and regenerate `lib/api-client-react/` and `lib/api-zod/`.
- [ ] **T005** [Database Engineer] Propose append-only event persistence in `lib/db/src/schema/audit-events.ts`.
## US1 — Minimal accountable events
- [ ] **T006** [Backend Engineer] Implement envelope validation and append-only writer in `artifacts/api-server/src/services/assurance/audit-writer.ts`.
- [ ] **T007** [Security Engineer] Implement allowlist, bounds, prohibited-content rejection, and explicit writer outcomes in `artifacts/api-server/src/services/assurance/audit-writer.ts`.
- [ ] **T008** [Test Engineer] Verify create, idempotency, mutation rejection, secret/raw-payload rejection, and failure signaling in `artifacts/api-server/src/tests/assurance/audit-writer.test.ts`.
- [ ] **T009** [P] [Integration Engineer] Define caller integration guidance without feature cycles in `specs/008-audit-governance/contracts/event-integration.md`.
## US2 — Browse event history
- [ ] **T010** [Backend Engineer] Implement Owner-only bounded queries in `artifacts/api-server/src/services/assurance/audit-query.ts`.
- [ ] **T011** [Backend Engineer] Expose authorized audit reads in `artifacts/api-server/src/routes/assurance/audit.ts`.
- [ ] **T012** [Frontend Engineer] Build filters, pagination, and history table in `artifacts/ai-assurance/src/features/governance/AuditHistory.tsx`.
- [ ] **T013** [Frontend Engineer] Build empty, denied, unavailable, and history-gap disclosure in `artifacts/ai-assurance/src/features/governance/AuditState.tsx`.
- [ ] **T014** [Security Test Engineer] Verify Owner-only access, cross-project isolation, cursor errors, and concurrent appends in `artifacts/api-server/src/tests/assurance/audit-query.test.ts`.
## US3 — Policy and retention
- [ ] **T015** [Data Governance Lead] Route D006/D007 approval and define no-duration policy rules in `specs/008-audit-governance/contracts/retention-policy.md`.
- [ ] **T016** [Database Engineer] Propose versioned policy and retention persistence in `lib/db/src/schema/governance-policies.ts`.
- [ ] **T017** [Backend Engineer] Implement draft/review/approval and deny-by-default policy decisions in `artifacts/api-server/src/services/assurance/governance-policy.ts`.
- [ ] **T018** [Frontend Engineer] Build policy revisions and approval UI in `artifacts/ai-assurance/src/features/governance/GovernancePolicy.tsx`.
- [ ] **T019** [Backend Engineer] After D006 and storage gates only, implement authorized retention outcomes and deletion markers in `artifacts/api-server/src/services/assurance/retention.ts`.
- [ ] **T020** [Frontend Engineer] After D006 only, build confirmation and partial-result views in `artifacts/ai-assurance/src/features/governance/RetentionRequest.tsx`.
- [ ] **T021** [Test Engineer] Verify stale/unauthorized policy changes, versioned export decisions, blocked pre-D006 purge, and truthful markers in `artifacts/api-server/src/tests/assurance/governance-policy.test.ts`.
## Cross-cutting verification
- [ ] **T022** [Content Reviewer] Verify application-history and non-tamper-proof language in `artifacts/ai-assurance/src/tests/governance-content.test.tsx`.
- [ ] **T023** [Independent Reviewer] Trace US1–US3 and SC-001–SC-003 evidence in `specs/008-audit-governance/acceptance.md`.

## Requirement coverage

| Requirement | Tasks |
| --- | --- |
| FR-001 | T001, T006, T008 |
| FR-002 | T001, T007, T008 |
| FR-003 | T005, T006, T008 |
| FR-004 | T001, T006, T008, T009 |
| FR-005 | T010, T011, T014 |
| FR-006 | T010, T012, T013, T014 |
| FR-007 | T002, T016, T017, T018, T021 |
| FR-008 | T003, T017, T021 |
| FR-009 | T015, T019, T020, T021 |
| FR-010 | T002, T019, T021 |
| FR-011 | T013, T022 |
| FR-012 | T007, T013, T017, T020, T021 |