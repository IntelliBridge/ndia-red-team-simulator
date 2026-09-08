# F003 — Proposed Plan

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested: Evaluation lead)  
**Implementation authorization:** None; this is a technical proposal only.

## Approach

1. Resolve domain and evaluation-definition gates before finalizing profile fields.
2. Define profile/version, compatibility, review, lineage, and immutability invariants in `specs/003-evaluation-profiles/data-model.md`.
3. Propose draft, validate, submit, review, revise, archive, and guarded-delete operations in `specs/003-evaluation-profiles/contracts/evaluation-profiles.openapi.yaml`.
4. Coordinate approved operations into the shared OpenAPI and regenerate existing clients/validators.
5. Implement later as shared API routes/services consuming F001 authorization and exact F002 version references.
6. Keep compatibility validation declarative and non-operational; store no attack recipes or executable code.
7. Add editor, validation summary, review, and version-history UI in the future approved frontend artifact.

## Clarification and approval gates

- **G1 / D001:** Select the single benign domain.
- **G2 / D003:** Approve catalog formats and metadata needed for compatibility.
- **G3 / D005:** Approve definitions, controls, denominators, thresholds, and modality-appropriate explanation support.
- **G4:** F001 authorization and F002 approved-version contracts are reviewed.
- **G5:** F008 minimal event envelope is agreed.
- **G6 / D007:** Assign owner and independent reviewers; approve data/contract proposal.
- No implementation begins until G1–G6 close.

## Dependencies and sequencing

- Full dependencies: F001 authorization and F002 catalog behavior/contracts.
- Foundational contract only: F008 event writer; no dependency on full audit UI.
- F004 consumes published ProfileVersion snapshots; F003 does not depend on F004.
- Suggested sequence: decisions → data/contract review → validation service → lifecycle service → UI → verification.

## Ownership and proposed paths

| Concern | Owner role | Proposed exact path |
| --- | --- | --- |
| Data model | Evaluation lead + data engineer | `specs/003-evaluation-profiles/data-model.md` |
| Feature contract | API contract owner | `specs/003-evaluation-profiles/contracts/evaluation-profiles.openapi.yaml` |
| Shared API integration | API contract owner | `lib/api-spec/openapi.yaml` |
| Profile service | Backend engineer | `artifacts/api-server/src/services/assurance/evaluation-profiles.ts` |
| Profile routes | Backend engineer | `artifacts/api-server/src/routes/assurance/evaluation-profiles.ts` |
| Persistence schema | Data engineer | `lib/db/src/schema/evaluation-profiles.ts` |
| Profile UI | Frontend engineer | `artifacts/ai-assurance/src/features/evaluation-profiles/` |
| Server checks | Test engineer | `artifacts/api-server/src/tests/assurance/evaluation-profiles.test.ts` |
| UI checks | Test engineer | `artifacts/ai-assurance/src/tests/evaluation-profiles.test.tsx` |

## Interface and data boundaries

- F003 owns Profile, ProfileVersion, compatibility result, review, state, and lineage.
- F002 remains source of catalog provenance/state; F003 stores exact references and validation result.
- F004 may consume published immutable snapshots but cannot edit or approve them.
- Explanation settings express support and limitations, not causal truth or generated evidence.

## Focused verification proposal

- Contract and server checks for compatibility, required controls, version-bound approval, and role enforcement.
- Immutability checks ensuring published versions cannot change and revisions receive new identities.
- Content-boundary checks rejecting executable code and prohibited operational recipe fields.
- UI checks for draft/edit/validate/review/revise/archive/delete and unsupported/empty/failure states.
- Trace checks to US1–US3 and all requirements; no run execution is part of verification.

## No implementation yet

These exact paths are proposals. Do not create schemas, routes, validators, generated clients, profile UI, or domain logic until decisions and reviews approve implementation.