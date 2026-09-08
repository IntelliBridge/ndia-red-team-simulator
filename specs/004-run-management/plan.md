# F004 — Proposed Plan

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested: Platform lead)  
**Implementation authorization:** None; this is a technical proposal only.

## Approach

1. Resolve D004 before selecting any runtime; never assume a standalone worker exists in Replit.
2. Define run snapshots, transitions, errors, idempotency, ordering, completeness, and lineage in `specs/004-run-management/data-model.md`.
3. Define user run operations in `specs/004-run-management/contracts/run-management.openapi.yaml`.
4. Separately define the authenticated adapter boundary in `specs/004-run-management/contracts/execution-adapter.openapi.yaml`.
5. Coordinate accepted user operations into shared OpenAPI and use existing generators.
6. Add shared API orchestration only after F001–F003 contracts and the F008 event writer are approved.
7. Keep execution outside the web process; if an approved adapter is absent, expose explicit unavailability.
8. Add run list/detail/trigger/cancel/retry UI in the future approved frontend artifact.

## Clarification and approval gates

- **G1 / D001, D003, D005:** Approve domain, inputs, definitions, and supported capabilities.
- **G2 / D004:** Approve runtime, isolation, ceilings, authentication, timeout, cancellation, and deployment ownership.
- **G3:** F001 authorization, F002 catalog, and F003 published-profile contracts are approved.
- **G4:** F008 event writer contract and required-event failure policy are approved.
- **G5 / D007:** Assign feature owner, platform/security reviewers, and adapter owner.
- No live or stub execution implementation begins until G1–G5 close.

## Dependencies and sequencing

- Full dependencies: F001, F002, and F003.
- Foundational dependency: F008 event writer contract, not full audit-governance behavior.
- F004 owns orchestration and adapter ingestion; later evidence features consume run/evidence references.
- Suggested sequence: runtime decision → data/contracts → orchestration → approved adapter integration → UI → focused verification.

## Ownership and proposed paths

| Concern | Owner role | Proposed exact path |
| --- | --- | --- |
| Data model | Platform + data engineer | `specs/004-run-management/data-model.md` |
| User contract | API contract owner | `specs/004-run-management/contracts/run-management.openapi.yaml` |
| Adapter contract | Platform/security reviewer | `specs/004-run-management/contracts/execution-adapter.openapi.yaml` |
| Shared API integration | API contract owner | `lib/api-spec/openapi.yaml` |
| Run service | Backend engineer | `artifacts/api-server/src/services/assurance/run-management.ts` |
| Run routes | Backend engineer | `artifacts/api-server/src/routes/assurance/run-management.ts` |
| Persistence schema | Data engineer | `lib/db/src/schema/run-management.ts` |
| Run UI | Frontend engineer | `artifacts/ai-assurance/src/features/run-management/` |
| Server checks | Test engineer | `artifacts/api-server/src/tests/assurance/run-management.test.ts` |
| UI checks | Test engineer | `artifacts/ai-assurance/src/tests/run-management.test.tsx` |

## Interface and data boundaries

- F004 owns Run, transition ordering, request identity, retry lineage, adapter handoff, and safe errors.
- F003 supplies an immutable published profile snapshot referencing F002 versions; F001 authorizes actors.
- The future runtime owns bounded execution; it may communicate only through the approved adapter contract.
- F008 receives bounded events; evidence payloads, artifacts, secrets, and raw inputs are excluded.

## Focused verification proposal

- State-machine checks for all allowed/forbidden transitions, races, idempotency, and terminal immutability.
- Authorization checks for trigger/cancel/retry and adapter authentication.
- Provenance checks across retry/rerun and partial-evidence/error distinctions.
- UI checks for every lifecycle, confirmation, empty, denied, stale, partial, and unavailable state.
- A no-runtime check must prove explicit refusal and no web-process fallback; it is not a live run.

## No implementation yet

All paths and adapter shapes are proposals. Do not install a runtime, create workers, call providers, add routes/schemas/generated code, or build run UI before gate closure and package approval.