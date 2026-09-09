# F008 Audit and Governance: approval record

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
| Security reviewer (relevant: the hash-chained audit log, redaction, WORM export) | | |
| Data reviewer (relevant: retention and purge are D006) | | |

## Scope under review

`specs/008-audit-governance/spec.md` as reconciled on 2026-09-08. SC-001 and
SC-003 are amended, SC-002 is deferred to Phase B (policy versions do not
exist).

## Remaining non-blocking limitations

- No purge path exists. Retention operations wait on D006.
- Denied requests (403) are not written to the audit chain.
- A raw-payload allowlist validator on audit detail is Phase B (FR-002). In
  Phase A the ML detail builders are tested for carrying ids, digests and
  counts only.
- `redsim/audit/redact.py` blanks keys containing `token` and known secret
  shapes. A JWT pattern is an open item (README "Open items").
- WORM export is env-gated (`REDSIM_WORM_EXPORT=1`) and has not been run on
  the deployed runtime.

## Open decisions that touch this feature

- D006: retention period, export redaction, licence restrictions and audit
  metadata retention are OPEN. No owner is named.
- D007: no owners or reviewers are named. The product owner assigns them.

## Decision

Decision: Draft

The named reviewers change this line to `Changes requested` or `Approved for
implementation`. "Done" is a separate gate and is recorded in `evidence.md`.
