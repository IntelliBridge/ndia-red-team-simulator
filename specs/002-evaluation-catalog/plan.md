# F002 — Proposed Plan

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested: Evaluation researcher)  
**Implementation authorization:** None; this is a technical proposal only.

## Approach

1. Resolve domain/format gates and document catalog invariants in `specs/002-evaluation-catalog/data-model.md`.
2. Define model/dataset record, version, review, archive, and guarded-delete operations in `specs/002-evaluation-catalog/contracts/evaluation-catalog.openapi.yaml`.
3. Coordinate approved operations into `lib/api-spec/openapi.yaml`, then use existing generators.
4. Add catalog routes/services to the shared API with F001 object authorization and F008 event envelope integration.
5. Represent approved benign fixtures as governed references, never uploads, arbitrary endpoints, secrets, or executable payloads.
6. Add catalog list/detail/editor/review UI in the future frontend only after standard artifact creation and path review.
7. Add persistence only after reviewing existing database conventions and reference constraints.

## Clarification and approval gates

- **G1 / D001:** Choose one benign domain and use case.
- **G2 / D003:** Approve fixture governance and the shared matrix's proposed independent catalog approval authority; uploads/endpoints remain deferred.
- **G3 / D002:** F001 managed identity and authorization contract is approved.
- **G4:** Agree F008 event envelope and failure behavior.
- **G5 / D007:** Assign owner and required reviewers; approve data model and contract.
- No implementation begins until G1–G5 close.

## Dependencies and sequencing

- Full dependency: F001 for membership and object authorization.
- Foundational contract only: F008 event writer; full F008 UI/retention is not required.
- F002 publishes immutable approved version references consumed by F003; it does not depend on F003.
- Suggested sequence: decisions → data model/contract → persistence/service → UI → focused verification.

## Ownership and proposed paths

| Concern | Owner role | Proposed exact path |
| --- | --- | --- |
| Data model | Evaluation researcher + data engineer | `specs/002-evaluation-catalog/data-model.md` |
| Feature contract | API contract owner | `specs/002-evaluation-catalog/contracts/evaluation-catalog.openapi.yaml` |
| Shared API integration | API contract owner | `lib/api-spec/openapi.yaml` |
| Catalog service | Backend engineer | `artifacts/api-server/src/services/assurance/evaluation-catalog.ts` |
| Catalog routes | Backend engineer | `artifacts/api-server/src/routes/assurance/evaluation-catalog.ts` |
| Persistence schema | Data engineer | `lib/db/src/schema/evaluation-catalog.ts` |
| Catalog UI | Frontend engineer | `artifacts/ai-assurance/src/features/evaluation-catalog/` |
| Server checks | Test engineer | `artifacts/api-server/src/tests/assurance/evaluation-catalog.test.ts` |
| UI checks | Test engineer | `artifacts/ai-assurance/src/tests/evaluation-catalog.test.tsx` |

## Interface and data boundaries

- F002 owns stable records, immutable versions, provenance, reviews, states, and approved fixture references.
- F001 supplies actor/project authorization; F008 receives bounded events.
- F003 consumes exact approved non-archived version IDs and compatibility metadata, never mutable labels.
- Fixture content remains outside catalog metadata storage and cannot be executed by this feature.

## Focused verification proposal

- Contract checks for record types, lifecycle states, provenance validation, and conflict responses.
- Authorization and author-independent approval checks through direct requests.
- Referential checks for archive visibility and hard-delete race prevention.
- UI checks for create/edit/review/archive/delete confirmations and all empty/failure states.
- Verify every accepted reference is approved, benign, public/synthetic, and non-secret.

## No implementation yet

All paths are proposed. Do not add uploads, endpoints, provider access, schema changes, routes, generated code, or UI before gate closure and package approval.