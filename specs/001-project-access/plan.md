# F001 — Proposed Plan

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested: Engineering lead)  
**Implementation authorization:** None; this is a technical proposal only.

## Approach

1. Confirm D002 and review managed session, invitation delivery acknowledgement, identity matching, expiry, and revocation contracts; add no custom credentials or tokens.
2. Define project, membership, invitation, role/status, revision, and access-decision invariants in `specs/001-project-access/data-model.md`.
3. Propose access and managed-invitation operations in `specs/001-project-access/contracts/project-access.openapi.yaml`, then coordinate accepted operations into `lib/api-spec/openapi.yaml`.
4. Extend the existing shared API with authorization middleware and project-access routes/services; do not create another server.
5. Add the future UI to the standard `artifacts/ai-assurance/` artifact only after that artifact and exact paths are approved.
6. Persist membership and non-secret invitation lifecycle metadata through the existing database package only after current conventions are reviewed.
7. Emit the minimal agreed F008 event envelope for privileged and denied actions; do not wait for full audit UI.
8. Generate clients and validators through the existing generation flow; never hand-edit generated output.

## Clarification and approval gates

- **G1 / D002:** Select managed identity provider, session claims, initial Owner bootstrap, delivery acknowledgement, identity matching, expiry, revocation, and duplicate behavior.
- **G2:** Product owner ratifies the role matrix and proposed future invitation journey; no invitation is sent during planning.
- **G3:** F008 reviewers approve the minimal event envelope and failure policy.
- **G4 / D007:** Assign feature owner, engineering reviewer, and security/data reviewer.
- **G5:** Engineering reviewer confirms exact scaffold paths and existing database/auth conventions.
- No implementation begins until G1–G5 are closed and this package is approved.

## Dependencies and sequencing

- No other full feature is a prerequisite.
- F008 contributes only its foundational event envelope, avoiding a cycle with its full history UI.
- F002–F007 depend on F001 authorization contracts; expose stable role/decision interfaces before their implementations.
- Suggested sequence: clarify → data/contract review → backend authorization and invitation lifecycle → UI flows → focused verification.

## Ownership and proposed paths

| Concern | Owner role | Proposed exact path |
| --- | --- | --- |
| Feature data model | Backend engineer | `specs/001-project-access/data-model.md` |
| Reviewable contract | API contract owner | `specs/001-project-access/contracts/project-access.openapi.yaml` |
| Shared API integration | API contract owner | `lib/api-spec/openapi.yaml` |
| Authorization middleware | Security/backend engineer | `artifacts/api-server/src/services/assurance/project-access.ts` |
| Access routes | Backend engineer | `artifacts/api-server/src/routes/assurance/project-access.ts` |
| Persistence schema | Data engineer | `lib/db/src/schema/project-access.ts` |
| Membership UI | Frontend engineer | `artifacts/ai-assurance/src/features/project-access/` |
| Invitation issue/revoke UI | Frontend engineer | `artifacts/ai-assurance/src/features/project-access/InvitationManager.tsx` |
| Invitation acceptance UI | Frontend engineer | `artifacts/ai-assurance/src/features/project-access/InvitationAcceptance.tsx` |
| Focused server checks | Test engineer | `artifacts/api-server/src/tests/assurance/project-access.test.ts` |
| Focused UI checks | Test engineer | `artifacts/ai-assurance/src/tests/project-access.test.tsx` |

## Interface and data boundaries

- F001 owns application identity references, Project, Membership, Invitation lifecycle, role/status transitions, and authorization decisions.
- The approved provider owns authentication, recipient verification, and delivery acknowledgement; F001 stores no passwords or custom authentication/invitation tokens.
- Replit collaboration remains outside the application membership and invitation contract.
- Other features consume project/member identity and an object-action authorization decision, not raw provider tokens.
- F008 consumes bounded event envelopes with no secrets or object payloads.

## Focused verification proposal

- Contract validation for role/invitation states, conflicts, provider failures, acknowledgement, and denied responses.
- Server checks for every matrix action, object isolation, session expiry, identity matching, duplicate acceptance, revocation, and event-write failure.
- Transactional concurrency checks proving the last active Owner cannot be removed.
- UI checks for issue/revoke/accept behavior and loading, empty, delivery-failed, expired, mismatched, duplicate, conflict, denied, and unavailable states.
- Trace acceptance evidence to US1–US3 and FR-001–FR-016 without claiming tests have run.

## No implementation yet

These paths and steps are proposed. Do not configure a provider, send an invitation, onboard a person, or create schemas, routes, generated clients, or UI until all gates and reviews are complete.