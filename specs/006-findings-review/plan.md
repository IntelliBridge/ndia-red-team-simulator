# Implementation Plan: Findings Review

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested role: independent review lead)  
**Constraint:** Planning only; no implementation begins from this document.
## Proposed technical approach

1. Reuse the pnpm monorepo, shared API contract, shared backend, and future assurance frontend.
2. Define Finding, immutable FindingRevision, Recommendation, Review, and RetestLink contracts around the authoritative finding states.
3. Consume F001 authorization and F004 evidence references directly.
4. Enforce state transitions, optimistic revision checks, object authorization, and non-author review in the backend service and persistence boundary.
5. Present observation, interpretation, and candidate recommendation as distinct authored regions.
6. Offer an optional navigation adapter to F005 without requiring F005 for core creation or review.
7. Record approved minimal F008 events for mutations once the foundational envelope is accepted.
8. Never invoke model, profile, run, or defense changes from recommendation actions.

## Clarification and approval gates

- **G1 / D001:** Select one benign domain before domain-specific labels or examples.
- **G2 / D005:** Approve evidence sufficiency, retest compatibility, and review criteria.
- **G3:** F001 role/object authorization and F004 evidence-reference contracts reviewed.
- **G4 / D006:** Decide historical retention behavior before destructive draft withdrawal is implemented.
- **G5 / D007:** Assign owner and independent reviewers and obtain required document approvals.
## Dependencies and sequencing

- **Foundational contract:** F001 membership, role, and non-author authorization behavior.
- **Foundational contract:** F004 immutable run/evidence identifiers, completeness, and compatibility inputs.
- **Foundational contract:** F008 minimal event envelope can be emitted without waiting for full governance UI.
- **Required features:** F001 and F004 must exist for integrated release.
- **Optional feature:** F005 may provide a richer view link; F006 remains independently functional to avoid a cycle.
- F007 consumes reviewed F006 revisions; F006 does not depend on reporting.

## Interface and data ownership

- F006 owns Finding, FindingRevision, Recommendation, Review, and RetestLink.
- F004 owns Run and Evidence; F006 stores references, not copies presented as source evidence.
- Proposed API edits: `lib/api-spec/openapi.yaml`, coordinated by the shared integration owner.
- Proposed schema: `lib/db/src/schema/findings.ts` after data-model review.
- Proposed backend route: `artifacts/api-server/src/routes/assurance/findings.ts`.
- Proposed backend service: `artifacts/api-server/src/services/assurance/finding-review.ts`.
- Proposed frontend feature: `artifacts/ai-assurance/src/features/findings/`.
- Generated targets: `lib/api-client-react/` and `lib/api-zod/`; never hand-edit.
- Proposed backend checks: `artifacts/api-server/src/tests/assurance/findings-review.test.ts`.
- Proposed frontend checks: `artifacts/ai-assurance/src/tests/findings-review.test.tsx`.

## Verification strategy

- State-table checks for every allowed and rejected transition.
- Authorization checks across roles, projects, self-review, stale revisions, and revoked membership.
- Data-integrity checks for exact revision/evidence linkage and immutable reviewed content.
- UI checks for separated claim types, empty queues, conflicts, inaccessible evidence, and incompatible retests.
- Acceptance using genuine approved benign evidence; any interim fixture is visibly labeled.

## Readiness statement

No implementation, migration, integration setup, or defense application is authorized. Proposed paths require scaffold confirmation after all decision and review gates close.