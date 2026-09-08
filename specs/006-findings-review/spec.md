# Feature Specification: Findings Review

## Reconciliation with the product spec (2026-09-08)

Under the consolidated product spec ([docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md](../../docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md); decisions D1, D4, D9, D10) F006 is the feature-level layer over aegis's `Finding` row (`aegis/db/models.py`) and its `AegisFinding` detail in `Finding.schema_blob` (`aegis/schema.py`), John Sasser's derived-severity rules (S1 section 8.5, written to `Finding.severity`), the candidate recommendations produced by the `harden.recommend` job (S1 section 9), and the verify-after-harden loop (`verify.replay`: `aegis/services/verify.py`, `aegis/workers/tasks/verify.py`) that yields a measured ΔMRI. Access control is aegis Keycloak OIDC / NextAuth plus `aegis/api/policy.py` role checks and Postgres RLS (F001). The evidence a finding cites is the `RunRecord` content of `aegis/ml/schema.py` — `Measurement` rows with denominators (`n`, `n_correct`), per-sample `Observation` rows, `Interpretation(kind="inferred")`, `CandidateRecommendation(status="candidate", validation="not evaluated")`, `limitations` (always including `STANDING_LIMITATIONS`) and `reviewer_notes` — persisted in `Finding.schema_blob` and in `Artifact` rows by `attack.run` / `explain.run` (F004) and shown on John's three-pane `/findings/[id]` screen (`web/src/app/findings/[id]/page.tsx`, F005). Milestones: M1 (findings written with metrics and derived severity), M3 (candidate recommendations), M5 (the findings screen), M6 (verify loop and ΔMRI). The human review workflow this spec describes comes after Phase A (John's B1+), which is the Spec Kit's Slice 3. Every mutation emits a hash-chained audit event through `AuditWriter.append(action=…, actor=…, target=…)` in `aegis/audit/chain.py` (D4(c), F008). Nothing in the ML vertical is implemented yet; the paths above name the aegis platform code that exists and the contracts the vertical must fit.

**Decision on review states (D10 asked for one).** Finding review states and the `FindingRevision` / `Review` / `RetestLink` entities are a **Phase B** addition. Two items are cheap enough for Phase A because they add no state and no table, and are permitted only after the D8 demo-critical order (image path → MRI scorecard → verify-after-harden → tabular → ONNX upload → Fargate) is complete: (1) `reviewer_notes` free text (already a `RunRecord` field) edited through an audited `PATCH`; (2) dismiss-with-reason, written as aegis `status=false_positive` with the reason in the audit event detail and gated at the `approver` role. Both need a new `Action` member in `aegis/api/policy.py` — the enum has no finding-review action today, and `aegis/api/v1/findings.py` currently exposes only `GET` list and `GET` one. Everything else in US1–US3 (drafts, submission, confirm, request changes, resolve, independent-reviewer identity, concurrent-decision guard) stays Phase B.

**Decision register.** D001 (domain: image classification on open, unclassified aerial / military-vehicle imagery plus a tabular classifier; CIFAR-10 is the CI fixture only) and D005 (per-family metrics with denominators, benign noise control, eps sweep, SHAP, MRI per D9, severity thresholds per S1 8.5) are **RESOLVED** in [specs/_shared/decisions.md](../_shared/decisions.md) as of 2026-09-08; D006 (retention) and D007 (named owners and reviewers) remain **OPEN**. The "Unresolved decisions" section below predates that and is left as written.

**Vocabulary note.** S1 section 4 says `Finding.validation_state` is reused as `verified` / `still_vulnerable`. Those are the verify *outcome* names; the worker maps them to the stored values `poc_passed` / `poc_failed` / `inconclusive` (`aegis/workers/tasks/verify.py`). Per D10 the stored vocabulary is canonical; UI labels must describe the measured result under the in-scope attacks (D9(iii)) and never say "hardened", "verified safe" or "deployment-ready".

| Requirement | Status after consolidation | Note |
| --- | --- | --- |
| US1 | deferred to Phase B | Human-authored drafts need `FindingRevision`. In Phase A a finding is machine-derived: `attack.run` creates the `Finding` when an attack crosses its success threshold (S1 8.5) and the worker writes the separated fields; no analyst types them. |
| US2 | deferred to Phase B | Exception: dismiss-with-reason (cheap Phase A item above) → `status=false_positive`. Confirm and request-changes need the revision model. In Phase A no human authors a finding or a candidate, so the self-review rule is vacuous; in Phase B the author is the `CurrentUser` subject recorded on the revision. |
| US3 | amended | Retest = a `verify.replay` job that applies an ART preprocessing defense (feature squeezing / spatial smoothing) to a worker-side hardened variant and re-runs the identical campaign — same model × modality × attack set × eps grid × reference budget (D9(i)) — then writes `validation_state` and ΔMRI (D4(a), D9(iv)). That is Phase A. Human "resolve" (`status=fixed`) needs the Phase B review; Phase A never displays a finding as resolved. |
| FR-001 | amended | F001 is aegis: Keycloak OIDC / NextAuth session, `policy.check(user, Action, project_id)` and `has_project_access`, Postgres RLS. Role mapping: Owner → `admin`, Analyst → `remediator`, Reviewer → `approver`, Viewer → any active project membership (aegis's lowest rank is `scanner`; reads are membership-gated). Dev-token mode is allowed for the demo (D002). |
| FR-002 | amended | The separated fields are unchanged and enforced by `Literal` types in `aegis/ml/schema.py`, stored in `Finding.schema_blob`. Creation by Owners/Analysts is Phase B; Phase A findings are created by the worker with `source_tool` naming the ML attack task and `Job.created_by` the actor who started the campaign. |
| FR-003 | deferred to Phase B | Immutable revisions need `FindingRevision`. Phase A: `schema_blob` is written once by the worker; every later mutation (notes, dismiss, verify) is an append-only audit event, and the chain is the history. |
| FR-004 | amended | There is no human submission in Phase A. The worker writes a `Finding` only when its cited `Measurement` rows (with `n`) and `Artifact` rows exist; otherwise the job ends `Job.status=failed` (`aegis/workers/job_state.py`) and no `Finding` row is created. Spec Kit `in_review` corresponds to aegis `open`. |
| FR-005 | amended | Dismiss-with-reason → `status=false_positive`, gated at `approver`, reason mandatory in the audit detail (Phase A cheap item). Confirm and return-to-draft → Phase B. Because `admin` outranks `approver` in `_ROLE_RANK`, the non-author rule must be an identity comparison against the revision author, not a role check (Phase B). |
| FR-006 | superseded | aegis `Finding.status` (`open` / `fixing` / `fixed` / `failed` / `false_positive`, `aegis/schema.py`) and `validation_state` (`unvalidated` / `poc_passed` / `poc_failed` / `inconclusive`) are canonical (D10). The Spec Kit states map onto them per the table below. Illegal transitions must fail the way `IllegalJobTransition` does for jobs. |
| FR-007 | amended | Retest request = `POST /v1/findings/{id}/verify` (exists; `Action.VERIFY_REPLAY`, minimum role `remediator`) → `Job.type=verify.replay`. Compatibility = identical campaign settings (D9(i)); a retest with different settings is recorded as incompatible and carries no ΔMRI. Gating resolution on an independent review → Phase B. |
| FR-008 | amended | Candidates keep `status="candidate"`, `validation="not evaluated"` until a verify job attaches a measured ΔMRI (D9(iv)); S1's "expected gain" is removed from pane 3 of the findings screen. Applying a defense is permitted only as the explicit, audited `verify.replay` on a worker-side hardened variant for measurement; the registered `Target`, the campaign configuration and the candidate text are never modified. |
| FR-009 | amended | F005 and F006 share John's `/findings/[id]` screen, so the "MAY link, MUST not depend" separation is moot. F006 controls (Verify, dismiss, notes) sit on that page and act through `/v1/findings/{id}/…`; the page renders from `Finding` and `Artifact` rows, never from F005-only state. |
| FR-010 | amended | Author → `source_tool` and `Job.created_by` (Phase A), revision author (Phase B); reviewer, timestamps, reasons → the `AuditEvent` chain (`actor`, `created_at`, `detail`); evidence links → `Measurement.id` / `Observation.id` and `Artifact.id` inside `schema_blob`; limitations → `RunRecord.limitations`; revision history → Phase B. The observation / interpretation distinction is unchanged. |
| FR-011 | unchanged | aegis exposes no finding delete or archive; `AuditEvent` is append-only (`tests/test_audit_append_only.py`); retention stays under D006 (OPEN). |
| FR-012 | unchanged | Concrete aegis signals: an empty `/v1/findings` list; HTTP 403 from `policy.check`; `Job.status=failed`; `validation_state=inconclusive`; an incompatible retest flagged with no ΔMRI. No state may render as confirmed or resolved in Phase A. |

State mapping referenced by FR-006 and FR-007:

| Spec Kit finding state | aegis representation | Phase |
| --- | --- | --- |
| `draft` | None in Phase A (no human-authored findings); Phase B `FindingRevision` in draft | B |
| `in_review` | `status=open`, `validation_state=unvalidated` — machine-derived, awaiting human review | A |
| `confirmed` | Phase B review record on the exact revision; `status` stays `open` | B |
| `dismissed` | `status=false_positive` plus an audit event carrying the reason | A (cheap item) |
| `retest_requested` | `status=fixing` while a `verify.replay` job is `queued` or `running` | A |
| `resolved` | `status=fixed` only after `validation_state=poc_passed` **and** an independent review; Phase A shows the measured `validation_state` and ΔMRI, nothing more | B |

`validation_state=poc_failed` leaves `status=open` (the finding stands, with the measured result shown). `status=failed` is not written by the ML vertical; a verify job that cannot run leaves `Job.status=failed` and `validation_state=inconclusive`.

Success criteria: SC-001 and SC-003 become Phase B acceptance checks; SC-002 applies in Phase A to machine-derived findings (exact `Measurement` / `Observation` / `Artifact` ids and the four separated fields). Key entities: `Finding` → the `findings` row; `Recommendation` → `CandidateRecommendation` in `schema_blob`; `RetestLink` in Phase A is the `verify.replay` `Job` row (`Job.detail.finding_id`) plus the ΔMRI record; `FindingRevision`, `Review` and a full `RetestLink` are Phase B tables added by an Alembic migration under `aegis/db/migrations/versions/`.

**plan.md and tasks.md items that point at Replit monorepo locations (D10 replaces them with aegis paths; the files are not rewritten here):**

- plan.md "Proposed technical approach" item 1 (pnpm monorepo, shared API contract, shared backend, future assurance frontend) → aegis FastAPI service `aegis/api/`, Celery worker `aegis/workers/`, Next.js app `web/` (`@aegis/web`), shared components `packages/design-system/`.
- plan.md item 7 (minimal F008 event envelope) → `aegis/audit/chain.py` `AuditWriter.append`; dotted action names in the existing style (`verify.replay`, `scan.start`), e.g. `finding.dismiss`, `finding.notes`.
- plan.md `lib/api-spec/openapi.yaml` → `aegis/api/v1/findings.py` and `aegis/api/v1/verify.py`; FastAPI generates the OpenAPI document, there is no hand-maintained YAML.
- plan.md `lib/db/src/schema/findings.ts` → `aegis/db/models.py` (`Finding`, `Artifact`, `Job`, `AuditEvent`) plus, for Phase B tables only, an Alembic migration in `aegis/db/migrations/versions/`.
- plan.md `artifacts/api-server/src/routes/assurance/findings.ts` → `aegis/api/v1/findings.py`.
- plan.md `artifacts/api-server/src/services/assurance/finding-review.ts` → `aegis/services/verify.py` (retest admission, exists) and a new `aegis/services/finding_review.py` (Phase B).
- plan.md `artifacts/ai-assurance/src/features/findings/` → `web/src/app/findings/page.tsx` and `web/src/app/findings/[id]/page.tsx`; shared pieces in `packages/design-system/src/components/` (`finding-card.tsx` exists).
- plan.md `lib/api-client-react/` and `lib/api-zod/` → none; the web app calls `/v1` through `web/src/lib/api.ts` (`api<T>()`); no generated client or zod layer exists.
- plan.md `artifacts/api-server/src/tests/assurance/findings-review.test.ts` → `tests/test_findings_review.py` (flat `tests/` layout, sqlite `conftest.py`; `tests/test_verify.py` already covers `verify.replay`).
- plan.md `artifacts/ai-assurance/src/tests/findings-review.test.tsx` → co-located `web/src/app/findings/[id]/page.test.tsx` (existing pattern).
- tasks.md T004 → `aegis/api/v1/findings.py`; the "regenerate `lib/api-client-react/` and `lib/api-zod/`" step has no aegis equivalent.
- tasks.md T005 → `aegis/db/models.py` and `aegis/db/migrations/versions/`.
- tasks.md T006 → `aegis/api/v1/findings.py`.
- tasks.md T007 and T011 → `aegis/services/finding_review.py` (new, Phase B).
- tasks.md T008 → `web/src/app/findings/[id]/page.tsx` (Phase B editor); shared editor pieces in `packages/design-system/src/components/`.
- tasks.md T009 → `web/src/app/findings/[id]/page.tsx`.
- tasks.md T010 → `tests/test_findings_authoring.py` (Phase B).
- tasks.md T012 → `web/src/app/findings/page.tsx` (the existing list with severity filter; add a status filter).
- tasks.md T013 → `web/src/app/findings/[id]/page.tsx`.
- tasks.md T014 → `tests/test_findings_review.py`.
- tasks.md T017 → `aegis/services/verify.py` (retest link = `verify.replay` admission) and `aegis/workers/tasks/verify.py` (outcome → `validation_state`, ΔMRI).
- tasks.md T018 → `web/src/app/findings/[id]/page.tsx` (`validation_state` chip and ΔMRI panel).
- tasks.md T019 → extend `tests/test_verify.py`; ML-side checks under `tests/ml/` with the `ml` marker.
- tasks.md T020 → `tests/test_findings_authorization.py`, beside `tests/test_project_access_read.py`.
- tasks.md T021 → `web/src/app/findings/[id]/page.test.tsx` and `web/src/app/findings/page.test.tsx`.
- tasks.md T001–T003, T015, T016 and T022 point at `specs/006-findings-review/*` and remain valid locations; T001's D001 and D005 are now RESOLVED in `specs/_shared/decisions.md`, D006 and D007 remain OPEN.

**Feature:** F006 — Findings Review  
**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested role: independent review lead)  
**Approval required:** Product owner, engineering reviewer, security/data reviewer
## What and why

Findings review turns authorized observations into traceable, revisable, independently reviewed judgments. It keeps evidence, observation, interpretation, and candidate recommendation separate, prevents authors from approving their own work even when they are owners, and requires a compatible reviewed retest before resolution.
## Scope

- Evidence-linked findings based on F004 evidence and F001 authorization.
- Distinct observation, interpretation, and candidate recommendation fields.
- Draft revisions, submission, independent confirmation, dismissal, change request, retest request, and resolution.
- Review reasons, revision history, authorship, reviewer identity, and linked retest evidence.
- Optional navigation to an F005 evidence view when available.
- Explicit empty, stale-revision, incompatible-retest, denied, and unavailable-evidence states.
## Exclusions

- Editing F004 evidence or treating F005 visualizations as new evidence.
- Automatic confirmation from detectors or automatic application of a defense.
- Claims that recommendations work before a separate compatible comparison supports them.
- Operational, tactical, weapons, sensitive-target, or attack-recipe content.
- Owner override of independent review or resolution requirements.

## User stories

### US1 — Author an evidence-linked finding (P1)

As an analyst, I want to draft and revise a finding with separated claims so a reviewer can trace each statement to evidence.

**Independent test:** Create a draft from authorized evidence, revise it, and submit a frozen revision without requiring F005, reports, or retention tooling.

- **Given** authorized readable F004 evidence, **When** an analyst creates a draft, **Then** evidence references and separate observation, interpretation, and candidate recommendation fields are recorded.
- **Given** a draft owned by the actor, **When** it is edited, **Then** a new draft revision preserves prior revision history.
- **Given** required evidence is missing or unreadable, **When** submission is attempted, **Then** submission fails explicitly and the draft remains draft.

### US2 — Independently review a finding (P1)

As an independent reviewer, I want to confirm, dismiss, or return a submitted revision so judgments remain accountable.

**Independent test:** Submit one finding and exercise each permitted review outcome using a different actor, then verify self-review is blocked for an owner-author.

- **Given** a finding is `in_review`, **When** an eligible non-author reviewer confirms it, **Then** the exact revision becomes `confirmed` with a review reason and history.
- **Given** the reviewer is the revision author, **When** confirmation is attempted, **Then** it fails even if that actor has the Owner role.
- **Given** a reviewer requests changes, **When** the decision is recorded, **Then** a new editable draft revision is created and renewed review is required.

### US3 — Retest and resolve (P2)

As a reviewer, I want a confirmed finding linked to a compatible retest so resolution is based on evidence rather than a rerun alone.

**Independent test:** Link compatible and incompatible retests to a confirmed finding and verify only a separately reviewed compatible retest permits resolution.

- **Given** a confirmed finding, **When** an authorized actor requests a retest, **Then** it becomes `retest_requested` without changing or applying its candidate recommendation.
- **Given** a linked retest is incompatible or incomplete, **When** resolution is attempted, **Then** resolution is blocked with the unmet conditions.
- **Given** a compatible retest has reviewed evidence, **When** an eligible non-author reviewer resolves the finding, **Then** the decision and evidence link are retained.

## Functional requirements

- **FR-001:** All reads and mutations MUST require active project membership, server-side object authorization, and role checks from F001.
- **FR-002:** Owners and Analysts MUST be able to create finding drafts from readable F004 evidence with separate observation, interpretation, and candidate recommendation content.
- **FR-003:** Draft edits MUST create or preserve identifiable revisions; submitted and reviewed revisions MUST be immutable, and post-review changes MUST create a new revision.
- **FR-004:** Submission MUST validate required evidence references and move an eligible draft to `in_review`; missing, inaccessible, or incompatible evidence MUST fail explicitly.
- **FR-005:** Eligible Reviewers or Owners MUST be able to confirm, dismiss with reason, or return an `in_review` revision to `draft`, but MUST NOT review a revision they authored.
- **FR-006:** Finding states MUST follow `draft`, `in_review`, `confirmed`, `dismissed`, `retest_requested`, and `resolved` transitions defined by the shared contract; stale or invalid transitions MUST fail.
- **FR-007:** Confirmed findings MUST support a retest request, while resolution MUST require a compatible linked retest and an independent review of its relevant evidence.
- **FR-008:** Recommendations MUST remain labeled candidate actions, MUST preserve their supporting rationale and revision, and MUST NOT be applied automatically to a model, profile, or run.
- **FR-009:** F005 evidence-view links MAY be offered when available, but F006 MUST operate directly from F004 evidence references and MUST not depend on F005.
- **FR-010:** Finding/review records MUST expose author, reviewer, timestamps, reasons, evidence links, revision history, and limitations while distinguishing observation from interpretation.
- **FR-011:** Ordinary archive and delete of submitted or reviewed revisions MUST be unavailable; draft withdrawal and any later retention deletion MUST be authorized, explicit, and history-preserving.
- **FR-012:** Empty queues, unavailable evidence, revoked access, stale revisions, incompatible retests, and persistence failures MUST be shown explicitly without false confirmation or resolution.

## Key entities

- **Finding:** Project-scoped identity and current state over immutable revisions.
- **FindingRevision:** Evidence references, observation, interpretation, candidate recommendations, author, limitations, and submission status.
- **Recommendation:** Revision-bound candidate action, not an applied defense.
- **Review:** Independent actor, exact revision, decision, reason, and timestamp.
- **RetestLink:** Original finding revision, linked F004 run/evidence, compatibility assessment, and review status.

## Edge cases

- A finding author later becomes an Owner; self-approval remains blocked.
- Two reviewers decide against the same revision concurrently; only one valid transition is accepted.
- Evidence access is revoked after drafting but before submission or review.
- A new revision is made while a reviewer has an older revision open.
- A retest finishes partially or changes one unapproved variable.
- A recommendation is removed in a later draft; prior reviewed content remains historical.

## Success criteria

- **SC-001:** In focused checks, 100% of self-confirmation attempts, including Owner-authors, fail without changing finding state.
- **SC-002:** Every sampled reviewed finding links its exact revision to readable evidence or an explicit later redaction marker and separates observation, interpretation, and recommendation.
- **SC-003:** In acceptance review, zero sampled findings reach `resolved` without a compatible linked retest and recorded independent review.

## Unresolved decisions

- **D001:** First benign domain and domain language.
- **D005:** Evidence thresholds, compatibility, and review criteria.
- **D006:** Retention handling for withdrawn drafts and historical evidence.
- **D007:** Accountable owner and independent reviewers.