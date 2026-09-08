# Feature Specification: Evidence Workbench

## Reconciliation with the product spec (2026-09-08)

Under decision D10 (product owner, 2026-09-08) this feature is the feature-level layer beneath the product spec at [`docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`](../../docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md), which supersedes both earlier spec sources; where this file and the product spec differ, the product spec wins. F005 maps onto the full aegis platform (D1) as John Sasser's three-pane findings screen plus the evidence panels of the run page, and onto his milestones **M2** (SHAP artifacts as `Artifact` rows), **M5** (UI: `/models`, launcher, and the three-pane `/findings/[id]` screen) and, for display only, **M4** (tabular views) and **M6** (the measured ΔMRI after verify-after-harden, whose comparison logic belongs to F007). Concretely: pane 1 shows the original input beside the adversarial input (image pair, or tabular feature diff) together with the benign random-noise control at the same eps; pane 2 shows SHAP for clean versus adversarial (image saliency; tabular `TreeExplainer` bar and beeswarm, D4d), streamed from `Artifact` rows; pane 3 shows F006's projection — candidate recommendations from the rule layer with the optional Pythia-written narrative (D5). The run page (`web/src/app/runs/[id]/page.tsx`, exists) carries the per-family measurement table with denominators, the eps-sweep robustness curve (D4b), and — never without those two and its five subscores — the Model Robustness Index scorecard (D9). Backend: read-only projections over `GET /v1/runs/{id}` and `GET /v1/findings?run=` / `GET /v1/findings/{id}` (`aegis/api/v1/runs.py`, `aegis/api/v1/findings.py`, both exist) plus `GET /v1/artifacts/{id}`, which John's spec lists as reuse but which the restored API does not have (no artifacts router is registered in `aegis/api/app.py`), so it is new work in `aegis/api/v1/artifacts.py` serving `Artifact.location` through `aegis/storage` with the strict CSP headers from `aegis/api/security_headers.py`. Authorization is aegis's `get_current_user` plus `ensure_project_access` / `ensure_run_access` (`aegis/api/policy.py`) on top of Postgres row-level security keyed by `org_id` (migration `0006_tenant_rls`); the access matrix's Viewer/Reviewer/Analyst/Owner map onto aegis `scanner` / `remediator` / `approver` / `admin`, and any active `ProjectMembership` suffices to read. The evidence contract is `aegis/ml/schema.py`: `Measurement` (family `clean` / `evasion` / `control`, `n`, `n_correct`, `accuracy`, `per_class`, attack params including eps), `Observation` (artifact paths with `artifact_sha256`, `confidence_clean` / `confidence_adv`, `center_mass_ratio_*` typed `metric_kind="heuristic"`), `Interpretation` (`kind="inferred"`), `CandidateRecommendation` (`status="candidate"`, `validation="not evaluated"`, `narrative_source` `rules` / `llm`), `Provenance` (versions, `model_sha256`, `nondeterminism`) and `limitations` (`STANDING_LIMITATIONS`). Which of those fields live in `Finding.schema_blob` (JSONB), in `Artifact` rows, and in the campaign/score record is fixed by the product spec; F005 reads whatever it designates and persists nothing of its own. William's Replit monorepo paths in `plan.md` and `tasks.md` are replaced by the aegis paths listed at the end of this section (D10). None of the ML vertical is implemented today: the repository holds the restored aegis platform and contract-only scaffolding (`aegis/ml/schema.py`, `aegis/ml/targets/base.py`, `aegis/ml/attacks/base.py`, `aegis/llm/pythia.py`, `tests/ml/fakes.py`); this section records intent, not delivered behavior.

### Requirement status after consolidation

Status values: **unchanged** (meaning holds; only the implementing component changes), **amended** (meaning changes under D1–D13 as noted), **superseded** (replaced by a product-spec rule), **deferred to Phase B**.

| Requirement | Status after consolidation | Note |
| --- | --- | --- |
| US1 — Compare evidence | amended | "Original/baseline vs evaluated" becomes pane 1 of John's screen: clean input beside the adversarial input at the finding's eps, plus the benign random-noise control at the same eps (S2 constraint, kept). "Stable evidence and run references" are `Run.id`, `Finding.id`, `Target.id` with `Provenance.model_sha256`, `Artifact.id` + `sha256`, and `RunConfig` (dataset, split, seed, attack params). Partial completeness comes from aegis `Job.status` per run stage, not a separate evidence flag. |
| US2 — Understand metrics and coverage | amended | The result-family view is the `Measurement` table (`clean` / `evasion` per attack per eps / `control`) with `n`, `n_correct`, `per_class`, plus the eps-sweep robustness curve with per-eps denominators (D4b). One derived per-campaign summary, the MRI, is added under the D9 constraints listed at FR-005; the curve and the table are what D9(ii) requires to accompany it. |
| US3 — Inspect appropriate explanations | amended | SHAP is in scope for both Phase A modalities (image saliency; tabular `TreeExplainer` bar and beeswarm, D4d), so the "supported" branch is the norm and "unsupported" applies to targets with `status="not_implemented"` (black-box endpoints, LLM domain — Phase B). The `center_mass_ratio` proxy is shown labelled heuristic. F006 summaries are `CandidateRecommendation` objects (`candidate` / `not evaluated`, enforced by Literal types) with the optional narrative labelled "LLM-generated narrative of rule outputs", written through Pythia from metrics and a SHAP text summary only (D5). The "F006 unavailable" case in the independent test stays valid. |
| FR-001 | unchanged | Implemented by aegis: `get_current_user`, `ensure_project_access` / `ensure_run_access` (`aegis/api/policy.py`), RLS by `org_id` (D1, F001 mapping). Every role reads; no F005 action needs more than membership. |
| FR-002 | amended | Browsing dimensions are re-vocabularied: run = aegis `Run` (one attack campaign against one model target, John §4); test family = `Measurement.family` × `attack_id` × eps; case = `Observation.sample_index` and the derived `Finding` rows; completeness = aegis `Job.status` (`queued` / `running` / `succeeded` / `failed` / `cancelled`, `aegis/workers/job_state.py`) plus `RunRecord.stages_done`. William's `completed` maps to `succeeded`; `timed_out` is `failed` with the reason recorded; `cancel_requested` is the `run.cancel` service action, not a stored state. |
| FR-003 | amended | "Input-version and configuration references" are the model artifact (`Target.value` S3 key + `Provenance.model_sha256`, bundled or ONNX/state_dict upload per D2), the sample dataset reference and split, the seed, and the attack set with its eps grid and reference budget (the F003 campaign configuration stored with the Run). The side-by-side pair gains the control at the same eps. |
| FR-004 | unchanged | State sources: absent = no `Artifact` / `Observation` recorded; skipped = stage not in `stages_done` or `Job` `cancelled`; partial = a Run whose Jobs ended in mixed terminal states; failed-to-load = error from `/v1/artifacts/{id}` or the blob store; unsupported = `TargetStatus` / `RunStatus` `not_implemented` with its `reason`. The constitution's "no fixture data presented as results" rule applies: `tests/ml/fakes.py` (`TinyTarget`) and the CIFAR-10 CI fixture (D3) never appear in the workbench as results. |
| FR-005 | amended | Per-family definition, numerator, denominator, exclusions and coverage are unchanged and come from `Measurement`. The clause "unrelated metrics MUST NOT become a universal score" is narrowed by D9: the workbench displays the Model Robustness Index (five subscores weighted 0.35 / 0.25 / 0.20 / 0.10 / 0.10, aggregate, grade band) under binding constraints — (i) one MRI per campaign = one model × one modality × a declared attack set × a declared eps grid × a reference budget, never aggregated across modalities or domains and never compared across campaigns with different settings; (ii) never shown without its five subscores, the per-family accuracy table with `n`, and the eps curve; (iii) grade-band reading text is attack-scoped and states that no grade is a readiness or certification statement; (iv) ΔMRI is a measured delta on this model at these settings. The subscore inputs (`acc_clean`, `acc_adv`, `asr`, `conf_gap`, `expl_shift`) render as measurements; the aggregate renders in a separate, labelled derived-summary panel. Recorded as a divergence from the brief's "avoid a universal score" principle (D9 vi). |
| FR-006 | amended | SHAP is recorded as supported for image and tabular white-box targets in Phase A (John §7 table; D4d); KernelSHAP for black-box targets and text token attribution are Phase B. Explanation configuration and provenance are `Provenance.shap`, the explainer parameters the product spec records (background size, sample count, explained-sample count `explain_k`), and `Observation.metric_note`. The explanation-shift signal `expl_shift` feeds the MRI dimension `S_expl` and is displayed as derived, not as an observation. |
| FR-007 | deferred to Phase B | LLM-domain evidence (garak detectors, text inputs/outputs) is Phase B only (D6); when it lands, garak's OpenAI-compatible generator points at Pythia. In Phase A the LLM domain appears as a target with `status="not_implemented"` and a stated reason; no text-evidence panel is built. The clause "MUST NOT fabricate visual attribution" remains in force for every modality. |
| FR-008 | amended | F005's own endpoints stay GET-only and F005 persists nothing. John's screen places actions on the same page — "Verify fix" (`POST /v1/findings/{id}/verify`, exists, `Action.VERIFY_REPLAY`), explain and harden triggers (`POST /v1/findings/{id}/explain`, `/harden`, new) — these are F004 actions (Celery `verify.replay`, `explain.run`, `harden.recommend`) rendered adjacent to the evidence behind aegis `RoleGated` / `policy.check`, not F005 mutations. Reviewer notes (S2 `reviewer_notes`) belong to F006. |
| FR-009 | amended | The optional summary is the ranked list of `CandidateRecommendation` rows from the deterministic rule layer, each citing `triggered_by` measurement ids, plus the optional Pythia narrative (`narrative_source="llm"`, default off, `AEGIS_ML_LLM_MODEL` + `PYTHIA_*` env). John's "expected robustness gain" column is superseded by D9(iv): a recommendation shows no numeric gain until the verify loop has measured ΔMRI on this model at these settings; before that the column reads "not evaluated". Absence of recommendations still leaves evidence browsing complete. |
| FR-010 | unchanged | 403 from `ensure_project_access`, 404 for unknown ids, cross-tenant rows filtered by RLS. "Schema-incompatible" means a `Finding.schema_blob` that fails `aegis/ml/schema.py` validation (`aegis/schema.py` already notes historical unvalidated blobs); it is shown as an explicit state, never coerced. |
| FR-011 | amended | `STANDING_LIMITATIONS` (plus run-specific `limitations`) are always rendered; a succeeded run cannot omit them (`RunRecord` validator). Add the D9(iii) statements: grades describe robustness under the in-scope attacks only and are not readiness or certification statements. "Detector flags are not confirmed findings" is Phase B wording (garak); its Phase A counterpart is that a `Finding` row is a derived threshold crossing (John §8.5 severity rules), not a reviewed judgment — review states follow F006's reconciliation. |

Success criteria SC-001–SC-003 are unchanged in meaning; SC-003's "representative supported fixtures" must be visibly labelled fixtures and are never shown as results. Of the decisions listed under "Unresolved decisions" below, D001 and D005 are RESOLVED per D11 (recorded in `specs/_shared/decisions.md`: image classification on open, unclassified aerial / military-vehicle imagery plus a tabular classifier; per-family metrics with denominators, benign noise control, eps sweep, SHAP per John's table, MRI per D9, severity thresholds per John §8.5); D007 stays OPEN. The Exclusions above stand: D3's demo imagery is a bounded team decision (open, unclassified, licensed public data only; the tool evaluates and hardens a classifier's robustness and never trains, optimizes or deploys targeting or weapons models; no mission-system connections) and the workbench displays that data under those bounds.

### plan.md and tasks.md items pointing at Replit monorepo paths

These are listed, not rewritten; `plan.md` and `tasks.md` are left as William Yiu authored them. "exists" means the file is in the restored aegis platform today; "new" means it does not exist yet.

**plan.md**

- "Proposed technical approach" item 1, "pnpm monorepo, shared backend, and future assurance frontend" → aegis: FastAPI in `aegis/api/`, Celery in `aegis/workers/`, Next.js app `web/` (`@aegis/web`, exists), shared components `packages/design-system/` (exists).
- Item 8 and "Dependencies" — "F008 minimal event envelope" → aegis hash-chained audit log, `aegis/audit/chain.py` (`AuditWriter.append`; `PostgresAuditWriter`, `JsonlAuditWriter` offline). D4(c) requires events for upload / attack / explain / harden / verify; whether evidence reads are audited is set by the product spec.
- "Proposed API contract edits: `lib/api-spec/openapi.yaml`" → aegis has no hand-written OpenAPI file; the contract is the FastAPI routers in `aegis/api/v1/*.py` (served at `/openapi.json`) and the Pydantic models in `aegis/ml/schema.py`.
- "Proposed backend routes: `artifacts/api-server/src/routes/assurance/evidence.ts`" → `aegis/api/v1/findings.py` (exists), `aegis/api/v1/runs.py` (exists), `aegis/api/v1/artifacts.py` (new, `GET /v1/artifacts/{id}`), registered in `aegis/api/app.py`.
- "Proposed backend service: `artifacts/api-server/src/services/assurance/evidence-view.ts`" → a new module under `aegis/services/` (for example `aegis/services/ml_evidence.py`); note the existing `aegis/services/evidence.py` is the compliance evidence-pack generator and is not this.
- "Proposed frontend page: `artifacts/ai-assurance/src/features/evidence/EvidenceWorkbench.tsx`" → `web/src/app/findings/[id]/page.tsx` (exists; today a `FindingCard` plus Verify button, to become the three-pane screen) and `web/src/app/runs/[id]/page.tsx` (exists; per-family table, eps curve, scorecard).
- "Proposed frontend components: `artifacts/ai-assurance/src/features/evidence/components/`" → `packages/design-system/src/components/` (shared; the existing `evidence-diff.tsx` is a unified text diff usable for the tabular feature diff, not for image pairs) or `web/src/components/` for page-local pieces.
- "Generated clients remain in `lib/api-client-react/` and validation in `lib/api-zod/`" → no generated client exists in aegis; `web/src/lib/api.ts` is the hand-maintained typed fetch layer (its `Finding` / `FindingSchemaBlob` types must grow the ML shape), and request/response validation is Pydantic on the server.
- "Proposed focused backend checks: `artifacts/api-server/src/tests/assurance/evidence-workbench.test.ts`" → pytest under `tests/ml/` (marker `ml`, `TinyTarget` from `tests/ml/fakes.py`) for projection logic, and `tests/` with the `sqlite_session_factory` conftest harness for route behavior (`tests/test_project_access_read.py` and `tests/test_list_endpoint_scoping.py` exist for the access pattern).
- "Proposed focused frontend checks: `artifacts/ai-assurance/src/tests/evidence-workbench.test.tsx`" → colocated vitest files `web/src/app/findings/[id]/page.test.tsx` and `web/src/app/runs/[id]/page.test.tsx` (both exist).

**tasks.md**

- T004 `lib/api-spec/openapi.yaml`, `lib/api-client-react/`, `lib/api-zod/` → FastAPI routers in `aegis/api/v1/` and `web/src/lib/api.ts`; nothing is regenerated.
- T005 `artifacts/api-server/src/routes/assurance/evidence.ts` → `aegis/api/v1/findings.py` (exists) and `aegis/api/v1/artifacts.py` (new).
- T006, T011, T016 `artifacts/api-server/src/services/assurance/evidence-view.ts` → new module under `aegis/services/` (for example `aegis/services/ml_evidence.py`), building projections from `aegis/ml/schema.py`.
- T007 `artifacts/ai-assurance/src/features/evidence/EvidenceWorkbench.tsx` → `web/src/app/findings/[id]/page.tsx` and `web/src/app/runs/[id]/page.tsx` (both exist).
- T008 `.../components/EvidenceComparison.tsx` → `packages/design-system/src/components/evidence-comparison.tsx` (new; kebab-case per the design-system convention).
- T012 `.../components/MetricContext.tsx` → `packages/design-system/src/components/metric-context.tsx` (new).
- T013 `.../components/EvidenceState.tsx` → `packages/design-system/src/components/evidence-state.tsx` (new).
- T017 `.../components/ExplanationView.tsx` → `packages/design-system/src/components/explanation-view.tsx` (new).
- T018 `.../components/RecommendationSummary.tsx` → `packages/design-system/src/components/recommendation-summary.tsx` (new).
- T009 `artifacts/api-server/src/tests/assurance/evidence-workbench.test.ts` → `tests/ml/` (pytest, marker `ml`) for pairing / provenance / partial-state logic, `tests/` sqlite harness for route checks.
- T014, T019 `artifacts/ai-assurance/src/tests/evidence-workbench.test.tsx` → `web/src/app/runs/[id]/page.test.tsx` and `web/src/app/findings/[id]/page.test.tsx` (exist).
- T020 `artifacts/api-server/src/tests/assurance/evidence-authorization.test.ts` → `tests/` alongside `tests/test_project_access_read.py` and `tests/test_tenant_rls.py` (exist).
- T021 `artifacts/ai-assurance/src/tests/evidence-accessibility.test.tsx` → `web/src/app/findings/[id]/page.a11y.test.tsx` (new, following the existing `web/src/app/findings/page.a11y.test.tsx` pattern).
- T001, T002, T003, T010, T015, T022 point at `specs/005-evidence-workbench/...` and `specs/_shared/decisions.md`; those locations are correct. T001's D001/D005 are RESOLVED per D11.


**Feature:** F005 — Evidence Workbench  
**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested role: evaluation research lead)  
**Approval required:** Product owner, engineering reviewer, security/data reviewer
## What and why

The evidence workbench lets authorized project members inspect original or baseline observations beside evaluated observations for one completed or partial run. It makes denominators, coverage, missing evidence, explanation limitations, and provenance visible so that measurements are not mistaken for causal conclusions.

## Scope

- Read-only browsing of F004 evidence for public or synthetic benign evaluations.
- Side-by-side original/baseline and evaluated evidence where both exist.
- Metric definitions, numerator, denominator, excluded or skipped cases, and coverage.
- Modality-appropriate explanations: SHAP only when configured and supported; text evidence for LLM evaluations.
- Optional display of F006 recommendation summaries without making F005 depend on F006.
- Explicit partial, unavailable, unsupported, empty, and access-denied states.

## Exclusions

- Editing evidence, run records, findings, reviews, or recommendations.
- Causal attribution, certification, universal scores, or operational-readiness claims.
- Fabricated heatmaps or substitute explanations when an explanation is unsupported.
- Tactical, weapons, live-target, sensitive-data, or attack-recipe functionality.
- Starting runs, applying defenses, or changing models from this workbench.

## User stories

### US1 — Compare evidence (P1)

As an authorized analyst or reviewer, I want original/baseline and evaluated observations shown together so I can inspect what changed without losing provenance.

**Independent test:** Open one authorized evidence item with two observations and verify labels, versions, completeness, and limitations without any finding or report feature.

- **Given** a member can read a run containing both observations, **When** they open an evidence item, **Then** both are shown side by side with stable evidence and run references.
- **Given** only one observation is available, **When** the item opens, **Then** the absent side is labeled unavailable with its recorded reason and no substitute content.
- **Given** the run is partial, **When** evidence is viewed, **Then** partial completeness remains visible at item and run context.

### US2 — Understand metrics and coverage (P1)

As a reviewer, I want every metric shown with its denominator and coverage so I can judge the limits of the result.

**Independent test:** Open a result family containing evaluated, skipped, and unavailable cases and reconcile its displayed counts to the source evidence contract.

- **Given** a metric has a definition and counts, **When** it is displayed, **Then** its numerator, denominator, units, exclusions, and coverage are visible.
- **Given** no evidence exists for a selected family, **When** it is selected, **Then** an empty state explains that no evidence was recorded rather than showing zero success.
- **Given** evidence cannot be loaded, **When** retrieval fails, **Then** an explicit retryable or terminal error is shown without stale values.

### US3 — Inspect appropriate explanations (P2)

As an analyst, I want supported explanations and optional reviewed recommendation summaries clearly separated from observations so I do not mistake interpretation for measurement.

**Independent test:** View one supported explanation, one unsupported explanation, and the page with F006 unavailable; evidence remains useful in all three cases.

- **Given** a supported explanation exists, **When** it is opened, **Then** its type, configuration, source, and limitations are visible.
- **Given** SHAP is unsupported or absent, **When** explanation space is shown, **Then** an unsupported state appears and no heatmap is fabricated.
- **Given** F006 supplies summaries, **When** they are displayed, **Then** they are labeled candidate or reviewed summaries and remain distinct from evidence.

## Functional requirements

- **FR-001:** The workbench MUST require active project membership and server-authorized object access before returning run or evidence content.
- **FR-002:** The workbench MUST let authorized members browse and select read-only evidence by run, test family, case, and recorded completeness.
- **FR-003:** The workbench MUST present original/baseline and evaluated observations side by side when available, preserving evidence, run, input-version, and configuration references.
- **FR-004:** The workbench MUST label absent, skipped, partial, failed-to-load, and unsupported evidence distinctly and MUST NOT infer missing values.
- **FR-005:** Every metric MUST expose its definition, numerator, denominator, units, exclusions, skipped/unavailable counts, and coverage scope; unrelated metrics MUST NOT become a universal score.
- **FR-006:** Explanations MUST identify modality, explanation type, configuration, provenance, and limitations; SHAP MUST appear only when the run records it as supported.
- **FR-007:** LLM evidence MUST use recorded text-oriented inputs/outputs, detector observations, or review evidence and MUST NOT fabricate visual attribution.
- **FR-008:** Evidence and explanations MUST remain read-only; create, edit, archive, and delete actions are not permitted in F005, and unauthorized mutation attempts MUST fail.
- **FR-009:** Optional F006 recommendation summaries MAY be displayed when authorized and available, but MUST be labeled separately and their absence MUST not impair core evidence browsing.
- **FR-010:** Empty, access-denied, not-found, schema-incompatible, and retrieval-failure states MUST be explicit and MUST not expose content from another project.
- **FR-011:** The workbench MUST disclose that attribution is not causal proof, detector flags are not confirmed findings, and partial or passing results are not certification.

## Key entities

- **Evidence:** F004-owned immutable observation references, metric context, explanation metadata, limitations, schema version, and completeness.
- **EvidenceComparisonView:** Read-only selection of available original/baseline and evaluated observations; it creates no new evidence.
- **MetricContext:** Definition, numerator, denominator, units, exclusions, coverage, and unavailable or skipped counts.
- **ExplanationView:** Supported modality-specific explanation plus configuration, provenance, and limitations.
- **RecommendationSummary:** Optional F006-owned projection, never evidence and never edited here.

## Edge cases

- A run completes while the viewer has a previously partial page open.
- Original and evaluated payloads have different but compatible display shapes.
- Metric denominator is zero or unknown; no percentage is calculated.
- Explanation metadata exists but its payload is unavailable or redacted.
- A referenced recommendation revision is withdrawn or no longer readable.
- Membership is revoked between list retrieval and item retrieval.

## Success criteria

- **SC-001:** In acceptance review, 100% of sampled metric views expose a reconcilable denominator, exclusions, and coverage or an explicit unavailable reason.
- **SC-002:** In acceptance review, every sampled unsupported explanation displays a labeled unsupported state and zero fabricated visual attribution.
- **SC-003:** Authorized reviewers complete baseline/evaluated comparison for at least 90% of representative supported fixtures without consulting raw storage references.

## Unresolved decisions

- **D001:** First benign domain determines evidence presentation.
- **D005:** Metric definitions, denominators, thresholds, and explanation support.
- **D007:** Accountable owner and independent reviewers.