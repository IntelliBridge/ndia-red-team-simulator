# F003 Evaluation Profiles: approval record

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
| Data reviewer (relevant: attack sets, eps grids and the MRI weights are the evaluation definitions of D005) | | |

## Scope under review

`specs/003-evaluation-profiles/spec.md` as reconciled on 2026-09-08. In Phase A
a profile is the admitted campaign configuration frozen on the `Run`. US2
(publish, approve, revise) is Phase B. SC-001 and the revision clause of
SC-002 follow US2 to Phase B. SC-002's immutability clause and SC-003 apply to
the snapshot.

## Remaining non-blocking limitations

- No profile entity, no publish or approval step, no revision history. The
  configuration is validated at admission and frozen with the run.
- The MRI weight vector is fixed per project (`PUT
  /v1/projects/{slug}/ml-scoring`, Phase B wave B2) and never renormalised. A
  campaign with non-default weights carries a badge in its report.
- Plan gate G6 (D007) stays open.

## Open decisions that touch this feature

- D007: no owners or reviewers are named. The product owner assigns them.
- D006: not blocking for F003.

## Decision

Decision: Draft

The named reviewers change this line to `Changes requested` or `Approved for
implementation`. "Done" is a separate gate and is recorded in `evidence.md`.
