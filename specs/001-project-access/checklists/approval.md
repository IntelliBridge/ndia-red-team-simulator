# F001 Project Access: approval record

Created 2026-09-09 from `specs/_shared/readiness-checklist.md` ("Approval record").
This file records who approved the specification and when. Nothing in it is a
signature until a named person writes their name and date. Generation is not
approval. D007 (named feature owners and independent reviewers) is OPEN in
`specs/_shared/decisions.md`, so every name below is blank.

## Reviewers

| Role | Name | Date |
| --- | --- | --- |
| Product owner | | |
| Engineering reviewer | | |
| Security reviewer (relevant: authentication, roles, tenant isolation) | | |

## Scope under review

`specs/001-project-access/spec.md` as reconciled on 2026-09-08 (the table at
the top of the file). US2 and US3 and FR-006, FR-007, FR-009, FR-013 to FR-016
are deferred to Phase B. FR-004 is superseded. SC-001 is amended, SC-002 and
SC-003 are deferred to Phase B.

## Remaining non-blocking limitations

- Roles travel in the token claim and are not re-read per request, so a role
  change in Keycloak takes effect at the next token or cookie expiry (FR-012).
- Phase A has two membership states, present and absent. Suspension and a
  retained "removed" record wait on FR-006 (Phase B).
- No in-app membership editor, no last-owner guard, no invitation entity.
- Denied requests answer 403 and are not written to the audit chain (a Phase B
  addition to F008).
- Dev-token mode (`REDSIM_AUTH_MODE=dev`) is allowed for the demo by D002 and
  refused when `REDSIM_ENV=prod`.

## Open decisions that touch this feature

- D007: no owners or reviewers are named. The product owner assigns them.
- D006: not blocking for F001.

## Decision

Decision: Draft

The named reviewers change this line to `Changes requested` or `Approved for
implementation`. "Done" is a separate gate and is recorded in `evidence.md`.
