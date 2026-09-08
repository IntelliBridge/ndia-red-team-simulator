# F003 — Evaluation Profiles

## Reconciliation with the product spec (2026-09-08)

Under the consolidated product spec ([docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md](../../docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md), decision D10) an evaluation profile is an **approved attack-campaign configuration**: one model (an redsim `Target` of kind `ml_model_artifact`) × one modality × a declared attack set (Phase A: FGSM and PGD for image, PGD and HopSkipJump for tabular, drawn from the `redsim/ml/attacks/` registry) × a declared L∞ ε grid (default {0.01, 0.03, 0.1}) × a reference budget × a bundled sample dataset with `n_samples` and `seed` as the denominators × the benign random-noise control at the same ε × explanation settings × the Model Robustness Index weight vector (0.35/0.25/0.20/0.10/0.10, D9). "Approved" in Phase A means every element is drawn from the server-side catalog fixed by the product spec (registered attack ids with `params_schema` bounds, bundled datasets with manifests, the fixed weights); the user-declared fields are the attack subset, ε grid, `n_samples`, `seed`, `include_control`, `explain_k`, and the LLM-narrative opt-in. The configuration is validated at admission (`POST /v1/models/{id}/attacks`, the ML counterpart of `redsim/services/scans.py`), written once as an immutable JSON snapshot on the `Run` the campaign creates and echoed into each `attack.run` `Job.detail`, hashed into the campaign-start audit event that the admission service emits before enqueue (`redsim/audit/chain.py`), and carried in report provenance so a rerun or a ΔMRI comparison can prove the settings were identical (D9(i)). The code contract today is `RunConfig` in `redsim/ml/schema.py` (single `attack_id`, `params`, `n_samples`, `seed`, `include_control`, `explain_k`, `llm_narrative`); the product spec widens it to an attack set, an ε grid, and the scoring weights, and John's M0 step adds the `Target.kind` and `Job.type` values it references (free string columns in `redsim/db/models.py`; API-side validation, an Alembic revision only if a column is added). Authorization is redsim RBAC (`redsim/api/policy.py`): Owner ↔ `admin`, Reviewer ↔ `approver`, Analyst ↔ `remediator` (campaign start is the new `Action.ATTACK_RUN`, `attack.run`, registered at `remediator` — not `scan.start`, which sits at `scanner`), Viewer ↔ any active membership (`scanner`; reads are gated by `ensure_project_access`, and there is no read-only role in Phase A); the shared baseline (`specs/_shared/architecture.md`) and the product spec's access-matrix section are authoritative for the exact mapping. Milestones: the Phase A configuration lands with **M1** (image load + attack), is extended by **M4** (tabular), and is reused unchanged by **M6** (verify-after-harden re-attacks with the same snapshot). The named, reviewable, independently approved Profile/ProfileVersion lifecycle this spec describes (US2, US3, FR-006, FR-008, FR-010) is **Phase B**: John's Phase A adds no new core tables, and D8 already states that Phase A as decided exceeds the 1–2 day build. Gates: D001, D002, D003 and D005 are RESOLVED on 2026-09-08 (see `specs/_shared/decisions.md`); D007 remains OPEN. Nothing here claims the ML vertical is implemented — `redsim/ml/` holds contracts only.

| Requirement | Status after consolidation | Note |
| --- | --- | --- |
| US1 | amended | "Draft a profile" becomes "configure a campaign" in the Run-attack launcher on `/models/[id]` (John §11). Validation still fails with field-specific guidance (HTTP 422) and refuses unavailable targets (`TargetStatus` `not_implemented` → 501 carrying `reason`); explanation unavailability stays explicit — no SHAP output is fabricated for an unsupported domain or estimator. What is saved is the immutable Run snapshot, not a reusable draft record. |
| US2 | deferred to Phase B | No per-profile independent approval in Phase A; the approved set is the server-side catalog itself. Author-independence and stale-version rejection become Phase B `ProfileReview` rules — redsim has the `approver` rank but no "not the author" check today. |
| US3 | deferred to Phase B | The Phase A equivalent of "revise" is starting a new campaign (a new Run) from an existing Run's snapshot through F004 rerun; comparison is permitted only when the D9(i) settings match. Archive/delete of named profiles is Phase B; retiring bundled models or datasets belongs to F002. |
| FR-001 | amended | Roles map onto redsim RBAC: configure/start ↔ `policy.check` on the new `Action.ATTACK_RUN` (`attack.run`) at `remediator` and above (not `scan.start`); read ↔ any project membership (`scanner` and above; no read-only role in Phase A). The Owner/Analyst/Reviewer/Viewer vocabulary survives in prose only. |
| FR-002 | amended | Phase A identity is the Run id (project- and org-scoped by Postgres RLS) plus the sha256 of the canonical configuration JSON as the version id; author is `Run.created_by`; lineage is the `verify.replay` link between the hardened re-run and the original Finding (`Finding.validation_state`). Stable Profile ids with separate ProfileVersion ids are Phase B. |
| FR-003 | amended | "Approved model version" = a `Target` of kind `ml_model_artifact` that is bundled or accepted under the D2 upload rules (ONNX preferred, state_dict with explicit architecture, pickles refused, loaded only in the sandboxed worker), identified by `model_sha256`. "Approved dataset version" = a bundled dataset named in the asset manifest (CIFAR-10 for CI fixtures; open, unclassified aerial/military-vehicle imagery for the demo per D3). Compatibility = target modality vs attack family, dataset input shape vs model manifest, and estimator support for the requested explainer; results are returned in the 422 body and stored in the snapshot. Endpoint targets (`ml_model_endpoint`) are Phase B. |
| FR-004 | amended | Content becomes concrete: attack set, ε grid, reference budget, `n_samples` + `seed` (denominators), `include_control` (benign noise at the same ε), `explain_k` and the per-modality SHAP type (image saliency; TreeExplainer bar/beeswarm for tabular), the MRI weight vector (D9), and limitations = `STANDING_LIMITATIONS` plus campaign-specific entries. Purpose remains free text. |
| FR-005 | amended | Attack ids with bounded `params_schema` values are declarative references to the ART-backed registry, not stored recipes; executable code and pickled models remain refused (D2). Dataset references may point at open, unclassified military-vehicle imagery per D3, recorded as a divergence from the constitution's non-operational language with the D3 bounds (evaluate and harden a classifier only; never train, optimize, or deploy targeting or weapons models; no mission-system connections). |
| FR-006 | deferred to Phase B | draft / in_review / published / rejected / archived apply to the Phase B named profile. The Phase A snapshot has no lifecycle of its own; the campaign follows the redsim Job machine (`redsim/workers/job_state.py`: queued → running → succeeded / failed / cancelled) and the Run status. |
| FR-007 | amended | Validation runs at admission, before the audit event and the enqueue: completeness, target status, compatibility, ε inside each attack's bounds, `n_samples` 10–1000, `explain_k` 0–32. D005 is RESOLVED (D11), so the "D005-defined criteria" are now: per-family metrics with denominators, benign noise control, ε sweep, SHAP per John's table, MRI per D9, severity thresholds per John §8.5. |
| FR-008 | deferred to Phase B | See US2. |
| FR-009 | amended | Immutability holds by construction: the snapshot is written once at admission, never updated, and its hash sits in the audit chain and the report. A "change" is a new campaign (a new Run), not a linked draft; renewed independent review is Phase B. |
| FR-010 | deferred to Phase B | Archive and guarded hard-delete of named profiles are Phase B. Phase A keeps only redsim's existing `DELETE /v1/targets/{id}`; Runs and their snapshots are never deleted (audit chain, WORM export). |
| FR-011 | amended | Phase A UI is the Run-attack launcher on `/models/[id]` with loading, validation-error, denied (403), unavailable (501 `not_implemented` with reason) and explanation-unsupported states, plus a read-only configuration panel on `/runs/[id]`. List, editor, review, and archive screens for named profiles are Phase B. |
| FR-012 | amended | The "F008 event envelope" is the redsim hash-chained `AuditEvent` (`redsim/audit/chain.py`; Postgres-backed, JSONL offline). The admission service emits it before the enqueue, so an event-write failure aborts the request — the pattern checked by `tests/test_admission_audit_before_enqueue.py`. |

Also affected: the exclusion "Domain-specific implementation until D001/D005 resolve" is lifted (both RESOLVED); SC-001 and the revision clause of SC-002 follow US2 to Phase B, while SC-002's immutability clause and SC-003 apply in Phase A to the snapshot (a reader can identify the controls, limitations, `model_sha256`, and dataset version of any campaign).

### plan.md and tasks.md items that point at the wrong (Replit monorepo) locations

Listed only — plan.md and tasks.md are not rewritten here and no task box is checked.

| Item | Location named there | Correct redsim location |
| --- | --- | --- |
| plan.md Approach step 4; ownership row "Shared API integration"; tasks.md T004 | `lib/api-spec/openapi.yaml` plus regenerated clients/validators | There is no hand-maintained OpenAPI file and no generated client: FastAPI generates the schema from the Pydantic bodies in `redsim/api/v1/*.py`, and the web client is hand-written in `web/src/lib/api.ts`. The feature contract draft may stay at `specs/003-evaluation-profiles/contracts/evaluation-profiles.openapi.yaml` as a review artifact. |
| plan.md Approach step 5; ownership row "Profile service"; tasks.md T007, T010, T013 | `artifacts/api-server/src/services/assurance/evaluation-profiles.ts` | `redsim/services/` — a campaign-admission module beside `redsim/services/scans.py` (validate → snapshot → audit → enqueue), with the configuration model in `redsim/ml/schema.py` (`RunConfig`, widened per the product spec). |
| ownership row "Profile routes"; tasks.md T008 | `artifacts/api-server/src/routes/assurance/evaluation-profiles.ts` | `redsim/api/v1/` — `POST /v1/models/{id}/attacks` in a new `models.py` router mounted in `redsim/api/app.py` (John §10), gated by `redsim/api/policy.py`. |
| ownership row "Persistence schema"; tasks.md T006 | `lib/db/src/schema/evaluation-profiles.ts` | `redsim/db/models.py` plus an Alembic revision in `redsim/db/migrations/versions/` (the next after `0009_tenant_org_id_guard.py`, needed only if the campaign/score record adds a column; the M0 `Target.kind` / `Job.type` values themselves are API-validated string values, not DDL). Phase B Profile / ProfileVersion / ProfileReview tables go in the same two places. |
| plan.md Approach step 7; ownership row "Profile UI"; tasks.md T009, T011, T014 | `artifacts/ai-assurance/src/features/evaluation-profiles/` (`ProfileEditor.tsx`, `ProfileReview.tsx`) | `web/src/app/models/[id]/` (new; the Run-attack launcher, Phase A) and, for Phase B, `web/src/app/profiles/`; shared pieces under `web/src/components/`. The app is `@redsim/web`. |
| ownership row "Server checks"; tasks.md T012 | `artifacts/api-server/src/tests/assurance/evaluation-profiles.test.ts` | `tests/ml/` — pytest with the `ml` marker where torch/ART/SHAP are needed, the `TinyTarget` fake in `tests/ml/fakes.py`, and the sqlite session factory from `tests/conftest.py`; the audit-before-enqueue check follows `tests/test_admission_audit_before_enqueue.py`. |
| ownership row "UI checks"; tasks.md T015 | `artifacts/ai-assurance/src/tests/evaluation-profiles.test.tsx` | Vitest tests co-located with the page, e.g. `web/src/app/models/[id]/page.test.tsx` (`web/vitest.config.ts`); end-to-end flows in `web/tests/*.spec.ts` (Playwright). |

Paths that are already correct but whose meaning shifts: tasks.md T001 (`specs/_shared/decisions.md`) is record-keeping, not an open gate, because D001, D003 and D005 are RESOLVED; plan.md steps 2–3 and tasks.md T003 (`specs/003-evaluation-profiles/data-model.md`, `contracts/`) remain spec-tree review artifacts, with the reviewed data model in code being `redsim/ml/schema.py` and the product spec fixing which snapshot fields live on the Run versus `Finding.schema_blob` versus `Artifact` rows. Plan gates G1 (D001), G2 (D003) and G3 (D005) are closed by D11; G6 (D007) remains open.

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned  
**Suggested owner role:** Evaluation lead  
**Required reviewers:** Product owner; independent reviewer; security/data reviewer

## What and why

Define versioned, reviewable evaluation configurations that bind approved benign catalog inputs to explicit tests, controls, limits, and explanation support before any run can be requested.

## Scope

- Create draft profile records and immutable profile versions.
- Select compatible approved model and dataset versions.
- Record evaluation definitions, benign controls, limits, evaluator settings, explanation support, and known limitations.
- Validate compatibility and completeness.
- Require author-independent approval and publish the approved immutable version.
- Archive profiles while preserving historical references.

## Exclusions

- Executing profiles or selecting a runtime.
- Tactical attack instructions, exploit recipes, poisoning pipelines, unrestricted code, or operational targets.
- Universal SHAP requirements or causal claims from attribution.
- Editing an approved/published version in place.
- Domain-specific implementation until D001/D005 resolve.

## Prioritized user stories

### US1 (P1) — Draft a bounded profile

As an Analyst, I can draft an evaluation profile from approved compatible catalog versions with explicit benign controls and limits.

**Independent test:** Compose a draft using approved and disallowed combinations; verify validation, save, empty, and permission behavior without executing anything.

- **Given** compatible approved inputs, **when** an Analyst saves required definitions and controls, **then** a new draft version is visible.
- **Given** archived, unapproved, or incompatible inputs, **when** save or validation is requested, **then** it fails with specific corrective guidance.
- **Given** explanation support is unavailable for the chosen domain, **when** the draft is viewed, **then** unavailability and its implication are explicit rather than fabricated.

### US2 (P1) — Independently approve and publish

As a Reviewer, I can review a complete profile authored by someone else and publish exactly the approved version.

**Independent test:** Verify independent approval, stale-version rejection, validation evidence, immutable publication, and direct-request authorization.

- **Given** a validated draft by another author, **when** a Reviewer approves it, **then** the exact version becomes published and immutable.
- **Given** the author attempts approval, **when** the action is submitted, **then** it is blocked even if the author is an Owner.
- **Given** the draft changed after review opened, **when** approval is submitted, **then** the stale decision fails and requires renewed review.

### US3 (P2) — Revise or retire a profile

As an Analyst, I can create a new draft from a published profile or archive a profile without altering prior runs.

**Independent test:** Revise, archive, and attempt deletion across unused and referenced versions.

- **Given** a published version, **when** revision starts, **then** a distinct draft version is created with lineage.
- **Given** a profile used by a run, **when** it is archived, **then** new selection stops while prior run provenance remains readable.
- **Given** an unused draft, **when** deletion is confirmed, **then** only that draft is removed; referenced or published versions are blocked.

## Functional requirements

- **FR-001:** Only active Owners and Analysts MAY create or edit profile drafts; Reviewers and Viewers MUST be read-only except approval actions allowed by role.
- **FR-002:** A profile MUST have a stable project-scoped ID and immutable version IDs with author and lineage.
- **FR-003:** Each version MUST reference exact approved, non-archived model and dataset versions and report compatibility results.
- **FR-004:** Each version MUST state purpose, evaluation definitions, denominators, benign controls, bounds, evaluator settings, explanation type/support, and limitations.
- **FR-005:** Content MUST remain non-operational and MUST NOT store executable attack recipes, tactical instructions, unrestricted code, or poisoning workflows.
- **FR-006:** States MUST include draft, in_review, published, rejected, and archived; state changes require actor, timestamp, and reason where applicable.
- **FR-007:** Submission MUST validate completeness, catalog state, compatibility, and D005-defined criteria; failures MUST identify affected fields without publishing.
- **FR-008:** Publication MUST require an authorized Reviewer or Owner other than the author, and MUST bind the decision to the exact reviewed version.
- **FR-009:** Published versions MUST be immutable; changes MUST create a linked draft and require renewed independent review.
- **FR-010:** Only active Owners and Analysts MAY archive or request deletion; archive MUST prevent new run selection while preserving existing run references, and hard deletion MUST be limited to unused drafts after confirmation.
- **FR-011:** List, editor, validation, review, and archive UI MUST explicitly handle loading, empty, unsupported explanation, stale, denied, rejected, and unavailable states.
- **FR-012:** Every mutation MUST enforce project/object authorization server-side and emit the agreed F008 event envelope; event failure MUST prevent silent state change.

## Key entities

- **Profile:** Stable project-scoped profile identity.
- **ProfileVersion:** Immutable inputs, definitions, controls, limits, settings, limitations, author, state, and lineage.
- **CompatibilityAssessment:** Exact input versions, checks, support status, and reasons.
- **ProfileReview:** Exact version, independent reviewer, decision, reason, and timestamp.

## Edge cases

- An approved input is archived while a profile awaits review.
- Explanation support is partial for only some evaluation definitions.
- Two editors branch from the same published profile.
- Review and archive requests race.
- Validation criteria change after a version is published.

## Success criteria

- **SC-001:** Focused checks reject 100% of sampled publish attempts lacking independent approval, required controls, compatible approved inputs, or explicit limitations.
- **SC-002:** Every sampled published profile remains byte-for-byte unchanged while revisions receive distinct version IDs and renewed review.
- **SC-003:** In moderated review, users correctly identify supported explanations, benign controls, limitations, and exact catalog versions for all sampled profiles.

## Unresolved decisions and gates

- **D001:** First domain blocks domain-specific profile content.
- **D002:** Managed identity through F001 blocks authorized implementation.
- **D003:** Catalog formats constrain compatibility.
- **D005:** Definitions, controls, denominators, thresholds, and explanation support block publication rules.
- **D007:** Named owner and independent reviewer remain unassigned.