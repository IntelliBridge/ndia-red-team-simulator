# F005 Evidence Workbench: approval record

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
| Data reviewer (relevant: the workbench displays open, unclassified imagery under the D3 bounds) | | |

## Scope under review

`specs/005-evidence-workbench/spec.md` as reconciled on 2026-09-08. SC-001 to
SC-003 are unchanged in meaning. SC-003's "representative supported fixtures"
are labelled fixtures and are never shown as results.

## Remaining non-blocking limitations

- The web pages render the mounted routes (PR #22) but have not been exercised
  in a browser against a running stack (README "Open items").
- SHAP is supporting evidence, not causal proof. The centre-mass ratio is
  labelled heuristic. KernelSHAP for images is not built.
- The MRI is per campaign and never shown without its subscores, the
  per-family table with denominators and the eps curve.

## Open decisions that touch this feature

- D007: no owners or reviewers are named. The product owner assigns them.
- D006: not blocking for F005.

## Decision

Decision: Draft

The named reviewers change this line to `Changes requested` or `Approved for
implementation`. "Done" is a separate gate and is recorded in `evidence.md`.
