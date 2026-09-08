# Implementation Plan: Evidence Workbench

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested role: evaluation research lead)  
**Constraint:** Planning only; no implementation begins from this document.
## Proposed technical approach

1. Reuse the existing pnpm monorepo, shared backend, and future assurance frontend.
2. Consume the reviewed F004 Evidence contract through read-only endpoints; do not duplicate evidence persistence.
3. Define a presentation contract for comparison slots, metric context, explanation support, completeness, and limitations.
4. Add server-side project and object authorization before evidence projection.
5. Build separate UI regions for selection, paired observations, metrics/coverage, explanations, and optional recommendation summaries.
6. Treat F006 summaries as an optional adapter: if its contract is absent, F005 remains complete and no dependency cycle is created.
7. Represent unsupported, absent, partial, redacted, incompatible-schema, and retrieval-error states explicitly.
8. Emit only the approved minimal F008 event envelope for relevant reads if policy requires it; do not wait for the full audit browser.

## Clarification and approval gates

- **G1 / D001:** Select one public/synthetic benign domain before modality-specific behavior.
- **G2 / D005:** Approve metric definitions, denominator rules, coverage semantics, and supported explanation types.
- **G3:** F004 Evidence schema and read authorization contract reviewed before endpoint or UI implementation.
- **G4:** Security/data reviewer confirms payload display and redaction boundaries.
- **G5 / D007:** Assign owner and reviewers; approve spec and plan before implementation.
## Dependencies and sequencing

- **Foundational contract:** F001 membership/authorization and F004 Evidence identifiers, completeness, provenance, and schema version.
- **Foundational contract:** F008 minimal event envelope may be consumed without depending on full F008 governance.
- **Required feature:** F004 result ingestion must supply genuine evidence before integrated acceptance.
- **Optional integration:** F006 recommendation-summary projection may be consumed when available; F005 never owns or blocks F006.
- F007 may consume F005 presentation concepts, but no reciprocal runtime dependency is introduced.

## Interface and data ownership

- F004 owns Evidence and source payload references.
- F005 owns only read projections and interaction state; it creates no evidence record.
- F006 owns Recommendation and Review state.
- Proposed API contract edits: `lib/api-spec/openapi.yaml` coordinated by the shared integration owner.
- Proposed backend routes: `artifacts/api-server/src/routes/assurance/evidence.ts`.
- Proposed backend service: `artifacts/api-server/src/services/assurance/evidence-view.ts`.
- Proposed frontend page: `artifacts/ai-assurance/src/features/evidence/EvidenceWorkbench.tsx`.
- Proposed frontend components: `artifacts/ai-assurance/src/features/evidence/components/`.
- Generated clients remain in `lib/api-client-react/` and validation in `lib/api-zod/`; never hand-edit either.
- Proposed focused backend checks: `artifacts/api-server/src/tests/assurance/evidence-workbench.test.ts`.
- Proposed focused frontend checks: `artifacts/ai-assurance/src/tests/evidence-workbench.test.tsx`.

## Verification strategy

- Contract checks for complete, partial, unavailable, unsupported, redacted, and incompatible-schema responses.
- Authorization checks for cross-project IDs, revoked membership, and mutation attempts.
- UI checks for paired and single-sided evidence, denominator-zero behavior, and no fabricated explanation.
- Accessibility checks for labels, reading order, keyboard selection, and non-color-only completeness indicators.
- Integration check with genuine approved benign evidence; fixtures remain clearly labeled before that point.

## Readiness statement

No software, schema, provider, or platform task is authorized by this plan. Exact paths are proposals and must be confirmed against the scaffold after all gates close.