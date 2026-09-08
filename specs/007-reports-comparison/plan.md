# Implementation Plan: Reports and Comparison

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested role: assurance reporting lead)  
**Constraint:** Planning only; no implementation begins from this document.
## Proposed technical approach

1. Reuse the existing pnpm monorepo, shared backend, API contract, and future assurance frontend.
2. Define immutable ReportSnapshot, ExportRequest, and RunComparison contracts referencing source versions rather than mutable projections.
3. Build snapshot composition from F004 evidence and F006 reviewed revisions with server-side authorization.
4. Obtain a versioned F008 export/redaction policy decision before creating any PDF or JSON artifact.
5. Render PDF and JSON from one canonical snapshot projection so semantics and labels agree.
6. Evaluate comparison compatibility before metric alignment; expose changed, unchanged, and unknown variables.
7. Preserve metric-family definitions and missingness; do not add a universal score.
8. Emit the accepted minimal F008 event envelope for snapshot, archive, export, and denied-export outcomes.

## Clarification and approval gates

- **G1 / D001:** Select the benign domain before domain-specific report presentation.
- **G2 / D005:** Approve metric definitions and exact compatible-run rules.
- **G3 / D006:** Approve export redaction, license, artifact access, and retention policy before export implementation.
- **G4:** Review F004 source and F006 revision contracts before snapshot contract approval.
- **G5 / D007:** Assign owner/reviewers and approve spec, data model, interface, and plan.

## Dependencies and sequencing

- **Foundational contracts:** F001 authorization, F004 immutable run/evidence versions, and F008 minimal event envelope.
- **Required feature:** F006 reviewed finding/recommendation/retest revisions for reviewed report content.
- **Required policy contract:** F008 export/redaction decision interface; full F008 audit browser is not required.
- F007 consumes these contracts and creates no dependency back from F004, F006, or F008.
- Retention execution remains F008-owned and is not implemented as report deletion.

## Interface and data ownership

- F007 owns ReportSnapshot, ExportRequest status, and RunComparison projections.
- F004 owns runs/evidence; F006 owns findings/reviews; F008 owns policy and audit history.
- Proposed API edits: `lib/api-spec/openapi.yaml`, coordinated by the integration owner.
- Proposed schema: `lib/db/src/schema/report-snapshots.ts` after data-model approval.
- Proposed routes: `artifacts/api-server/src/routes/assurance/reports.ts`.
- Proposed services: `artifacts/api-server/src/services/assurance/report-snapshots.ts`, `artifacts/api-server/src/services/assurance/report-export.ts`, and `artifacts/api-server/src/services/assurance/run-comparison.ts`.
- Proposed frontend feature: `artifacts/ai-assurance/src/features/reports/`.
- Proposed backend checks: `artifacts/api-server/src/tests/assurance/reports-comparison.test.ts`.
- Proposed frontend checks: `artifacts/ai-assurance/src/tests/reports-comparison.test.tsx`.
- Generated clients in `lib/api-client-react/` and validators in `lib/api-zod/` are regenerated, never hand-edited.

## Verification strategy

- Snapshot integrity checks for exact versions, failed composition, archives, and partial labels.
- Permission/redaction checks for generation and retrieval of both formats.
- Cross-format semantic checks over the same canonical snapshot.
- Compatibility matrix checks including unknown variables and missing metric families.
- UI checks for empty, denied, redacted, archived, incompatible, and generation-failure states.

## Readiness statement

No report generator, schema, route, UI, export storage, or platform task is approved yet. Exact targets remain proposed until gates close and the existing scaffold is reconfirmed.