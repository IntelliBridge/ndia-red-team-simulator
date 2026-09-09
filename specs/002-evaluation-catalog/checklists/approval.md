# F002 Evaluation Catalog: approval record

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
| Security reviewer (relevant: model upload admission, sandboxed loading) | | |
| Data reviewer (relevant: dataset licences and the D3 bounds) | | |

## Scope under review

`specs/002-evaluation-catalog/spec.md` as reconciled on 2026-09-08. US2,
FR-005, FR-006 and FR-008 are deferred to Phase B. FR-004 is superseded by
D003. SC-001 reads "manifest-recorded license and sha256", SC-002's archive
half is Phase B, SC-003 is unchanged.

## Remaining non-blocking limitations

- No independent Reviewer approval of a catalog version. Bundled assets are
  approved at build time by D003 and their manifest. Uploads are admitted by
  rule with the upload event on the audit chain.
- No archive flag. `DELETE /v1/models/{id}` is an audited soft delete that
  keeps the row for history. The "blocked with reference context" response for
  a target referenced by a run is not built.
- Consumed datasets (`POST /v1/datasets`, Phase B wave B3) are admitted for
  image and tabular slices only. Text and detection slices answer `501`.
- Endpoint targets (Phase B wave B2) carry no ownership verification
  (`verified: false`, ENDPOINT-26).

## Open decisions that touch this feature

- D007: no owners or reviewers are named. The product owner assigns them.
- D006: retention of blobs and evidence after a delete is a D006 operation,
  not catalog editing.

## Decision

Decision: Draft

The named reviewers change this line to `Changes requested` or `Approved for
implementation`. "Done" is a separate gate and is recorded in `evidence.md`.
