# Shared Planning Baseline

**Status:** Proposed contracts and conventions; no application behavior is implemented by these documents.

## Feature boundaries

| ID | Slug | Owns |
| --- | --- | --- |
| F001 | 001-project-access | Application identity, project membership, role enforcement |
| F002 | 002-evaluation-catalog | Versioned model and dataset metadata, compatibility and approval status |
| F003 | 003-evaluation-profiles | Versioned evaluation definitions, drafts, validation, approval |
| F004 | 004-run-management | Run lifecycle, approved execution adapter, cancellation and result ingestion |
| F005 | 005-evidence-workbench | Evidence browsing, metrics context, modality-appropriate explanations |
| F006 | 006-findings-review | Findings, reviewer decisions, candidate recommendations and retest links |
| F007 | 007-reports-comparison | Versioned report snapshots, exports, compatible-run comparisons |
| F008 | 008-audit-governance | Shared event contract, audit history, approved retention and redaction |

## Proposed access matrix

Application membership is not inherited automatically from Replit collaboration.

| Action | Owner | Analyst | Reviewer | Viewer |
| --- | --- | --- | --- | --- |
| Read project evidence and reviewed findings | Yes | Yes | Yes | Yes |
| Register catalog entries and draft profiles | Yes | Yes | No | No |
| Start/cancel authorized evaluations | Yes | Yes | No | No |
| Create/edit finding drafts and candidate recommendations | Yes | Yes | No | No |
| Approve catalog versions and profiles; confirm/dismiss findings | Yes, except own authored item | No | Yes, except own authored item | No |
| Export policy-permitted reports | Yes | Yes | Yes | No |
| Manage members, policy, or retention | Yes | No | No | No |

Project resource actions require active membership and object-level authorization. Initial owner bootstrap and invitation acceptance are narrowly scoped onboarding exceptions defined by F001/D002; invitation acceptance still requires a verified matching managed identity and an eligible invitation, and grants no pre-acceptance project access. Enforce independent approval for catalog versions, profile approval, and finding confirmation. An owner may not bypass this check. Removing the last owner is blocked. This is a proposed role matrix requiring team review, not a record of permissions already implemented.

## Proposed entities and invariants

- **Project / Membership:** project ID, member identity, role, status. A project must retain an active owner.
- **Invitation:** project, intended role, recipient identity binding, provider-managed reference, creator, expiry, and pending/accepted/revoked/expired/failed status. An invitation alone grants no access. Acceptance requires managed identity verification and idempotent membership creation; a duplicate must not silently overwrite an existing role. Do not store or log invitation secrets in these documents, exports, or ordinary audit metadata.
- **ModelVersion / DatasetVersion:** project ID, stable record ID, immutable version ID, provenance, domain, approval/archive status, non-secret reference. Descriptive edits must not rewrite versions used by a run.
- **ProfileVersion:** selected model/dataset version compatibility, evaluation definitions, benign controls, limits, evaluator and explanation settings, author, approver, approval status. Approved versions are immutable.
- **Run:** immutable project and input-version snapshot, status, actor, request identity, timestamps, environment/evaluator versions, outcome counts, evidence references and reason for interruption.
- **Evidence:** run ID, example ID, original/baseline observations, evaluated observations, metric definition, explanation type and configuration, limitations, payload reference, schema version.
- **Finding / Recommendation / Review:** supporting evidence references, observation, interpretation, candidate action, author, review status/history and linked retest.
- **ReportSnapshot:** selected run/finding/review versions, scope, coverage, provenance, limitations, redaction policy and export format.
- **AuditEvent:** event ID, project ID, actor or service identity, timestamp, action, entity type/ID/version, outcome, correlation ID, bounded non-sensitive metadata. No secrets, raw model artifacts, or input payloads.

These are planning concepts, not a database migration or final API schema. The implementation owner must define reviewed `contracts/` and `data-model.md` inside the applicable feature directory.

## Run state contract

Allowed states: `queued`, `running`, `cancel_requested`, `completed`, `failed`, `cancelled`, `timed_out`.

- `queued` → `running`, `cancelled`, `failed`, or `timed_out`.
- `running` → `completed`, `failed`, `timed_out`, or `cancel_requested`.
- `cancel_requested` → `cancelled`, `failed`, or `timed_out`; a racing completion may be recorded only if the worker completed before cancellation was accepted, with a retained ordering record.
- Terminal states never become running again. A retry or rerun creates a new linked run.
- Transport failure, skipped cases, unavailable explanations, and incomplete evidence are not model success or model failure.
- Preserve partial evidence with explicit completeness; never display partial results as a complete evaluation.

## Finding state contract

Allowed states: `draft`, `in_review`, `confirmed`, `dismissed`, `retest_requested`, `resolved`.

The author can edit drafts. Submitting creates a reviewable revision. Reviewers confirm, dismiss with a reason, or request changes back to `draft`. A confirmed finding can request a retest. Resolution requires review of a compatible linked retest; a rerun alone is not proof of resolution. Changes after review create a new revision and require renewed review.

## Proposed implementation locations

Reuse the existing pnpm monorepo and shared backend instead of replacing the stack.

- Future frontend: `artifacts/ai-assurance/`, created through the standard artifact flow only when implementation begins. This directory is a proposal and does not exist yet.
- API contract: `lib/api-spec/openapi.yaml`; generated client: `lib/api-client-react/`; generated validation: `lib/api-zod/`.
- Backend feature modules: `artifacts/api-server/src/routes/assurance/` and `artifacts/api-server/src/services/assurance/`.
- Persistence schemas: `lib/db/src/schema/`, only after the reviewed data model and existing database configuration are checked.
- Focused checks: `artifacts/api-server/src/tests/assurance/` and the future frontend's `src/tests/`.
- No worker runtime or provider SDK is selected. F004 must document its approved location and execution contract before runtime implementation.

Paths mentioned in feature tasks are proposed targets, not claims that files already exist. Each plan must confirm exact paths before its implementation is marked ready.

## Parallel work and shared-file ownership

F001 and F008's minimal event contract are foundation work. F008's full audit UI and retention tooling can follow later; do not defer event capture.

After contract approval, frontend, backend, and evidence research can work in parallel on separate files. One integration owner coordinates changes to the shared OpenAPI document, schema index, and generated clients. Regenerate clients after each accepted contract change; never hand-edit generated files.

Fixtures used before live execution must be visibly labeled as fixtures. The final demonstration must use genuine evidence from the approved benign evaluation, not fabricated integration results.