# F007 Reports and Comparison: approval record

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
| Data reviewer (relevant: reports show open, unclassified imagery under the D3 bounds, and the export redaction policy is D006) | | |

## Scope under review

`specs/007-reports-comparison/spec.md` as reconciled on 2026-09-08. Formats are
Markdown, JSON and HTML, and since Phase B wave B2 also PDF (a third projection
of the record, never a recomputation). FR-006 (export and redaction policy) and
the export half of US2 wait on D006.

## Remaining non-blocking limitations

- No export-redaction policy is applied. Every report says so in its
  limitations section until D006 resolves.
- Reading and downloading a report are one route gated by membership. The
  access matrix's "Viewer: No" on export is not enforced separately.
- The campaign completion path writes `report.md`, `report.json` and
  `report.html` and no `report_snapshots` row. The PDF and the first snapshot
  come from `POST /v1/runs/{id}/report.render` (README "Open items").
- Comparison is variable-level and never produces a mean, rank or aggregate.
  A batch compare (Phase B wave B3) returns comparability groups only.
- Demo figures quoted in prose are illustrative and labelled so.

## Open decisions that touch this feature

- D006: export redaction, licence restrictions and retention are OPEN. No
  owner is named.
- D007: no owners or reviewers are named. The product owner assigns them.

## Decision

Decision: Draft

The named reviewers change this line to `Changes requested` or `Approved for
implementation`. "Done" is a separate gate and is recorded in `evidence.md`.
