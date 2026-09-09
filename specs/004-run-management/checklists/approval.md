# F004 Run Management: approval record

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
| Security reviewer (relevant: the sandbox child, rlimits, credential-free environment, cancel and timeout semantics of D004) | | |

## Scope under review

`specs/004-run-management/spec.md` as reconciled on 2026-09-08. SC-001 to
SC-003 are amended to the redsim state machine (`redsim/workers/job_state.py`),
the frozen `Run` and `Job` snapshot plus `Provenance`, and the 503 / 501 /
`failed` outcomes when the runtime is unavailable.

## Remaining non-blocking limitations

- One Celery job runs a whole campaign in one sandbox child (accepted
  divergence from the per-attack chain of product spec 10.3).
- The sandbox is process isolation plus rlimits, not a network or filesystem
  jail (`SECURITY.md` "Known gaps").
- A broker outage at admission answers `503 queue_unavailable` with the rows
  rolled back (brief item D5, divergence from product spec 10, unrecorded).
- Per-project capacity caps (Phase B wave B3) bind batch and bulk-verify
  members. The single-run admissions do not consult the capacity service yet.

## Open decisions that touch this feature

- D007: no owners or reviewers are named. The product owner assigns them.
- D006: not blocking for F004.

## Decision

Decision: Draft

The named reviewers change this line to `Changes requested` or `Approved for
implementation`. "Done" is a separate gate and is recorded in `evidence.md`.
