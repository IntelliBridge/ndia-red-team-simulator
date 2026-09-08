# Tasks: Evidence Workbench

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested role: evaluation research lead)  
All paths are proposed future targets. Task IDs are scoped to F005.
## Setup and contracts
- [ ] **T001** [Evaluation Researcher] Resolve D001/D005 presentation rules in `specs/_shared/decisions.md` through the shared decision owner; do not edit from this package.
- [ ] **T002** [API Lead] Review F004 Evidence and F001 authorization contracts; record the F005 projection in `specs/005-evidence-workbench/contracts/evidence-view.yaml`.
- [ ] **T003** [Data Reviewer] Define field-level display/redaction mapping in `specs/005-evidence-workbench/data-model.md`.
- [ ] **T004** [Integration Owner] Propose coordinated read endpoints in `lib/api-spec/openapi.yaml` and regeneration of `lib/api-client-react/` and `lib/api-zod/`.
## US1 — Compare evidence
- [ ] **T005** [Backend Engineer] Implement authorized evidence selection/read projection in `artifacts/api-server/src/routes/assurance/evidence.ts`.
- [ ] **T006** [Backend Engineer] Implement pairing, provenance, and completeness logic in `artifacts/api-server/src/services/assurance/evidence-view.ts`.
- [ ] **T007** [Frontend Engineer] Build run/family/case navigation in `artifacts/ai-assurance/src/features/evidence/EvidenceWorkbench.tsx`.
- [ ] **T008** [Frontend Engineer] Build paired and single-sided observation states in `artifacts/ai-assurance/src/features/evidence/components/EvidenceComparison.tsx`.
- [ ] **T009** [Test Engineer] Verify authorization, provenance, partial state, and absent-side behavior in `artifacts/api-server/src/tests/assurance/evidence-workbench.test.ts`.
## US2 — Metrics and coverage
- [ ] **T010** [P] [Evaluation Researcher] Define approved metric labels and reconciliation examples in `specs/005-evidence-workbench/contracts/metric-context.md`.
- [ ] **T011** [Backend Engineer] Project metric definition, counts, exclusions, units, and coverage in `artifacts/api-server/src/services/assurance/evidence-view.ts`.
- [ ] **T012** [Frontend Engineer] Build metric and coverage display with zero/unknown denominator handling in `artifacts/ai-assurance/src/features/evidence/components/MetricContext.tsx`.
- [ ] **T013** [Frontend Engineer] Add empty, retrieval-error, and schema-incompatible views in `artifacts/ai-assurance/src/features/evidence/components/EvidenceState.tsx`.
- [ ] **T014** [Test Engineer] Verify denominator reconciliation and no universal-score aggregation in `artifacts/ai-assurance/src/tests/evidence-workbench.test.tsx`.
## US3 — Explanations and optional summaries
- [ ] **T015** [P] [Evaluation Researcher] Map modality support and required limitations in `specs/005-evidence-workbench/contracts/explanation-view.md`.
- [ ] **T016** [Backend Engineer] Implement supported/unsupported explanation projection in `artifacts/api-server/src/services/assurance/evidence-view.ts`.
- [ ] **T017** [Frontend Engineer] Build SHAP-conditional and text-evidence views in `artifacts/ai-assurance/src/features/evidence/components/ExplanationView.tsx`.
- [ ] **T018** [Frontend Engineer] Add optional F006 summary adapter in `artifacts/ai-assurance/src/features/evidence/components/RecommendationSummary.tsx`.
- [ ] **T019** [Test Engineer] Verify unsupported, redacted, and absent-summary behavior in `artifacts/ai-assurance/src/tests/evidence-workbench.test.tsx`.
## Cross-cutting verification
- [ ] **T020** [Security Engineer] Verify server-side object authorization and blocked create/edit/archive/delete requests in `artifacts/api-server/src/tests/assurance/evidence-authorization.test.ts`.
- [ ] **T021** [Accessibility Reviewer] Verify semantic comparison order and non-color state labels in `artifacts/ai-assurance/src/tests/evidence-accessibility.test.tsx`.
- [ ] **T022** [Independent Reviewer] Trace acceptance evidence to US1–US3 and SC-001–SC-003 in `specs/005-evidence-workbench/acceptance.md`.

## Requirement coverage

| Requirement | Tasks |
| --- | --- |
| FR-001 | T002, T005, T009, T020 |
| FR-002 | T005, T007, T009 |
| FR-003 | T006, T008, T009 |
| FR-004 | T006, T008, T013, T019 |
| FR-005 | T010, T011, T012, T014 |
| FR-006 | T015, T016, T017, T019 |
| FR-007 | T015, T017, T019 |
| FR-008 | T005, T020 |
| FR-009 | T018, T019 |
| FR-010 | T005, T013, T020 |
| FR-011 | T012, T017, T022 |