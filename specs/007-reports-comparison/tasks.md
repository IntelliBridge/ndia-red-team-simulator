# Tasks: Reports and Comparison

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested role: assurance reporting lead)  
All paths are proposed future targets. Task IDs are scoped to F007.
## Setup and contracts
- [ ] **T001** [Product Lead] Route D001/D005/D006/D007 to shared decision owners and retain unresolved gates in `specs/007-reports-comparison/plan.md`.
- [ ] **T002** [Domain Modeler] Define immutable snapshots, exports, comparisons, and archive state in `specs/007-reports-comparison/data-model.md`.
- [ ] **T003** [API Lead] Define snapshot, export, and comparison interfaces in `specs/007-reports-comparison/contracts/reports.yaml`.
- [ ] **T004** [Security/Data Reviewer] Map the future F008 policy decision fields in `specs/007-reports-comparison/contracts/export-policy.md`.
- [ ] **T005** [Integration Owner] Coordinate accepted edits to `lib/api-spec/openapi.yaml` and regenerate `lib/api-client-react/` and `lib/api-zod/`.
## US1 — Versioned snapshot
- [ ] **T006** [Database Engineer] Propose approved snapshot persistence in `lib/db/src/schema/report-snapshots.ts`.
- [ ] **T007** [Backend Engineer] Implement authorized atomic snapshot creation and archive transitions in `artifacts/api-server/src/services/assurance/report-snapshots.ts`.
- [ ] **T008** [Backend Engineer] Expose report reads and commands in `artifacts/api-server/src/routes/assurance/reports.ts`.
- [ ] **T009** [Frontend Engineer] Build snapshot composer and stale-source states in `artifacts/ai-assurance/src/features/reports/ReportComposer.tsx`.
- [ ] **T010** [Frontend Engineer] Build immutable report view and partial labels in `artifacts/ai-assurance/src/features/reports/ReportSnapshotView.tsx`.
- [ ] **T011** [Test Engineer] Verify source versions, atomic failure, immutability, archive/restore, and partial labels in `artifacts/api-server/src/tests/assurance/report-snapshots.test.ts`.
## US2 — Policy-permitted exports
- [ ] **T012** [Backend Engineer] Integrate approved F008 policy and artifact authorization in `artifacts/api-server/src/services/assurance/report-export.ts`.
- [ ] **T013** [P] [Report Engineer] Define equivalent PDF/JSON canonical mappings in `specs/007-reports-comparison/contracts/export-formats.md`.
- [ ] **T014** [Backend Engineer] Implement policy-approved PDF and JSON generation in `artifacts/api-server/src/services/assurance/report-export.ts`.
- [ ] **T015** [Frontend Engineer] Build export controls and denied/redacted/failure states in `artifacts/ai-assurance/src/features/reports/ReportExport.tsx`.
- [ ] **T016** [Security Test Engineer] Verify role, policy, redaction, artifact retrieval, and cross-format behavior in `artifacts/api-server/src/tests/assurance/report-export.test.ts`.
## US3 — Compatible comparisons
- [ ] **T017** [Evaluation Researcher] Define compatibility and variable inventory after D005 in `specs/007-reports-comparison/contracts/run-compatibility.md`.
- [ ] **T018** [Backend Engineer] Implement compatibility gating and metric-family alignment in `artifacts/api-server/src/services/assurance/run-comparison.ts`.
- [ ] **T019** [Frontend Engineer] Build changed/unchanged/unknown variable display in `artifacts/ai-assurance/src/features/reports/RunComparison.tsx`.
- [ ] **T020** [Frontend Engineer] Build denominator, coverage, missing-value, and no-comparable-runs states in `artifacts/ai-assurance/src/features/reports/ComparisonMetrics.tsx`.
- [ ] **T021** [Test Engineer] Verify compatible, incompatible, unknown, and no-universal-score cases in `artifacts/api-server/src/tests/assurance/run-comparison.test.ts`.
## Cross-cutting verification
- [ ] **T022** [Frontend Test Engineer] Verify report/export/comparison UI states in `artifacts/ai-assurance/src/tests/reports-comparison.test.tsx`.
- [ ] **T023** [Independent Reviewer] Trace US1–US3 and SC-001–SC-003 evidence in `specs/007-reports-comparison/acceptance.md`.

## Requirement coverage

| Requirement | Tasks |
| --- | --- |
| FR-001 | T007, T008, T012, T016 |
| FR-002 | T002, T007, T010, T011 |
| FR-003 | T007, T009, T011 |
| FR-004 | T010, T011, T014 |
| FR-005 | T013, T014, T016 |
| FR-006 | T004, T012, T015, T016 |
| FR-007 | T017, T018, T019, T021 |
| FR-008 | T018, T020, T021 |
| FR-009 | T010, T019, T023 |
| FR-010 | T006, T007, T011 |
| FR-011 | T009, T015, T020, T022 |