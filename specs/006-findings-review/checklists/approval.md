# F006 Findings Review: approval record

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
| Security or data reviewer (relevant only if the review workflow stores reviewer identities beyond the audit chain: not required in Phase A) | | |

## Scope under review

`specs/006-findings-review/spec.md` as reconciled on 2026-09-08. SC-001 and
SC-003 were placed in Phase B, SC-002 applies in Phase A to machine-derived
findings. Phase B wave B2 built the review workflow (`services.finding_review`,
`POST /v1/findings/{id}/review/{transition}`), so evidence for SC-001 and
SC-003 now exists and is listed in `evidence.md`.

## Remaining non-blocking limitations

- Independence is by identity, not by rank. `PATCH /v1/findings/{id}/status`
  keeps the Phase A plain-string `forbidden` for the independence refusal,
  while the review decisions emit the structured `reviewer_not_independent`.
- A redaction marker on evidence waits on D006 (OPEN).
- `FindingType` has no LLM or manual literal yet (README "Open items").
- The findings pages have not been exercised in a browser against a running
  stack.

## Open decisions that touch this feature

- D007: no owners or reviewers are named. The product owner assigns them.
- D006: retention and redaction of finding evidence are OPEN.

## Decision

Decision: Draft

The named reviewers change this line to `Changes requested` or `Approved for
implementation`. "Done" is a separate gate and is recorded in `evidence.md`.
