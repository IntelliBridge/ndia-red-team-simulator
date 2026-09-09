# redsim (Adversarial ML Red-Team Simulator)

Non-operational proof of concept that evaluates and hardens the robustness of
ML classifiers under adversarial evasion attacks: ART attacks with a benign
noise control and an epsilon sweep, SHAP as supporting evidence, a per-campaign
Model Robustness Index, candidate hardening recommendations, and a
verify-after-harden loop that reports a measured delta. Open, unclassified,
public data only. It never trains, optimizes or deploys targeting or weapons
models and connects to no mission system.

The repository is a fork of IntelliBridge's `aegis` security platform. The
product owner decided on 2026-09-08 to keep the FULL aegis platform (FastAPI,
Celery, Postgres + Alembic, Redis, S3/MinIO, Keycloak/NextAuth, RBAC and
Postgres RLS, hash-chained audit log, per-task LLM routing, observability) and
add one vertical under `redsim/ml/`. The pentest domain (14 scanner adapters,
Kali, CAI agents, GitHub remediation, ticketing, CI gate) is deleted for good.

This file is the working guide for anyone (human or agent) editing the tree.
It describes `main` at `703f8f6` (2026-09-09: the four Phase A completion
waves and Phase B waves B0 to B3) plus Phase B wave B4, the end-to-end
evidence, the `make check-phase-b` gate, the fix pass those files demanded and
this documentation pass, pushed to `main` together and verified from this
tree; statements marked "wave B4" are the ones that tree added. Phase B is
planned in `docs/plans/12-phase-b-plan.md` (five waves, every one landed, a
dated status line each); no Phase B route is a `501` stub. The
interoperability narrative is `docs/interop.md`; the Phase B testing addendum
is spec 22.6 and the Phase B completion criteria are spec 26.7.

## Authoritative docs, in order

1. `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`. The
   consolidated product spec, 27 sections. Section 8 is the architecture,
   section 9 model loading and isolation, section 10 the job and worker flow
   (10.5 audit vocabulary, 10.6 failure classes), section 11 the datasets,
   section 17 the API surface (17.3 the error-code table), section 18 the web
   UI, section 20 deployment (20.3 environment variables), section 22
   testing, section 24 the demo script, section 26 completion criteria.
2. `docs/project-brief.md`. Governance brief. Its reporting principles are
   design constraints. "Decisions taken (2026-09-08)" records every decision
   and every knowing divergence from the brief and the constitution.
3. `specs/README.md` and `specs/00N-*/` (F001 to F008) with
   `specs/_shared/` (decision register, shared architecture, readiness
   checklist). Feature layer beneath the product spec. Where a feature file
   and the product spec conflict, the product spec wins. D006 and D007 are
   OPEN in the register and have no owners.
4. `docs/plans/00-master-plan.md` (workstreams WS0 to WS7, integration waves,
   corrected shared contracts, the Phase B schema announcements in section 0)
   plus the phase files `docs/plans/01-…` to `08-…`,
   `docs/plans/09-gap-register-2026-09-08.md` (the 560-item spec-versus-tree
   register that drove the four Phase A completion waves),
   `docs/plans/10-remaining-work-brief.md` (packages A to F outside the
   waves), `docs/plans/11-phase-b-register-2026-09-09.md` (309 items) and
   `docs/plans/12-phase-b-plan.md` (waves B0 to B4 with a status line each).
   Section 8 of `docs/plans/01-p0-contracts-api-skeleton.md` is the change
   protocol for everything P0 froze and the place divergences are recorded.
5. `docs/architecture/*`. `auth.md`, `audit-chain.md`, `multi-tenancy.md`,
   `observability.md` describe the platform, `ml-vertical.md` the vertical,
   `diagrams/` the current pictures. `overview.md` still carries pentest-era
   sections that no longer exist.
6. `docs/ops/pythia.md` for the LLM gateway, `docs/dev/ci.md` for the CI
   contract, `docs/dev/testing.md` for the test tiers, `docs/api/v1.md` for
   the mounted routes and `docs/api/endpoint-contract.md` for the `endpoint-v1`
   predict contract.

Superseded, history only: `docs/adversarial-ml-redteam-spec.md` (and `.html`)
and `docs/superpowers/specs/2026-09-08-redsim-design.md`. Do not build against
them.

## Naming

- Product and UI name: redsim, long form "Adversarial ML Red-Team Simulator".
- Python namespace: `redsim`. Import as `redsim.…`. The console script is
  `redsim`, environment variables are `REDSIM_*`, the API title is "Redsim
  API", the session cookie is `redsim_api_session`, the CSRF cookie and header
  are `redsim_csrf` and `X-Redsim-CSRF`, the config file is `redsim.yaml`.
  Decision D7 was amended by the product owner on 2026-09-08 (commit
  `b39d933`): `aegis` survives only as the name of the upstream fork.
- Web workspace packages: `@redsim/web` (in `web/`) and
  `@redsim/design-system` (in `packages/design-system/`). Web environment
  variables are `NEXT_PUBLIC_REDSIM_*`.
- Compose services and images are `redsim-*`, the Helm chart is
  `deploy/helm/redsim`, the CI workflow is `.github/workflows/redsim-ci.yml`.
- Mentions of `aegis` that refer to the upstream project or to history (fork
  provenance, "restored from the aegis head", the ADRs) are correct and stay.
  Anything that describes this package, its paths, env vars, CLI, services,
  cookies or chart says redsim.

## What is on the tree (`main` at `703f8f6` plus wave B4)

Verified by importing the app and reading its OpenAPI document (72
operations, 69 under `/v1`), importing the ML registries and reading the
routers, services, tasks and tests of the wave B4 commits and fix pass.

### API process (`redsim.api.app:create_app()`)

`create_app()` mounts `health`, `ml_capabilities`, `attacks`, `datasets`,
`defenses`, `models`, `models_bulk` (wave B3, before `batches` so it serves
`/v1/models/bulk` and `/v1/ml/capacity`), `artifacts`, `compare`,
`ml_findings`, `runs`, `runs_cancel`, `findings`, `audit`, `reports`,
`scanners`, `verify`, `targets`, `auth_profiles`, `projects`, `logs`,
`org_cost`, the Phase B routers `batches`, `llm`, `integrations` (the dataset
export, consume and manifest rows live in `datasets`), and the WebSocket
router, with the `IdempotencyMiddleware` (wave B2) added innermost inside
the tenant scope: 69 HTTP routes under `/v1` (39 Phase A, 16 built by wave B2
of which five replaced B0 stubs and eleven are new paths, 14 built by wave B3
in place of the last B0 stubs; no route is a stub), plus `GET /health`,
`/metrics`, `GET /v1/__settings` and `/docs` outside prod, and
`WS /v1/runs/{id}/events`. `POST /v1/scans` was unmounted by P0 and answers
404.

| Group | Routes |
|---|---|
| ML catalog | `GET /v1/ml/capabilities` (secret-free roster, `sandbox_enabled` always true; since wave B4 every Phase B block is read from the tree, never asserted: `text` and `detection` `available` when their runner module imports and a registered adapter carries `modality:<m>`, with the runner, attacks and explainer named; `llm` `available` when the probe routes are mounted and the committed catalog loads, with the probe sets, `n_probes`, the expected garak version and the D9 note; `endpoint_connector` `available` with the `endpoint-v1` `contract` summary, the auth kinds, the black-box attacks and the `limits_env`, and `ownership_verification` `not_implemented` with the ENDPOINT-26 reason; `explainers` per modality and the `explainer_roster` from `redsim.ml.explain.base` with detection `not_implemented` and its reason; an `interop` block for the export, consume, ATLAS and integrations rows), `GET /v1/attacks` (each row with its `capabilities` tags and the `domains` derived from them; `?modality=` filters on those tags since wave B4, the rule admission applies, so `hopskipjump` lists under `image` and `pgd` under `tabular`; plus a `plugins` block with the opt-in `redsim.ml.attacks` discovery rows, `c3868e5`; since wave B3 each row carries `atlas_technique`, `atlas_techniques` and `atlas_reason` from `redsim.ml.atlas` and the response an `atlas` release citation, `AttackInfo` unchanged), `GET /v1/datasets` (rows from `assets/MANIFEST.json`, says so when no manifest is built; since wave B3 also the consumed `ds-…` rows of the caller's memberships or `?project=`, with `consumed_count`), `GET /v1/defenses` (five rows; since the B2 integration each row's `phase` and `status` come from its catalog entry, so the training defenses say `phase: "B"`) |
| Interoperability (wave B3, `interop-contribute`, `interop-consume`, `atlas-foundry`; `docs/interop.md`) | `POST /v1/runs/{id}/dataset` (membership, `dataset.export`, remediator; `services.ml_datasets_export.admit_export` writes the `dataset.export` row, a follow-up `Run` with scanner `ml.dataset_export` and a `dataset.export` `Job`, then enqueues `redsim.dataset_export` on `scans`; `409 export_unavailable` for a non-campaign, non-terminal or slice-less run, `409 export_in_flight`, `422 fixture_not_exportable`, `503 queue_unavailable` with the rows rolled back; one export per run, a second call answers the existing manifest with `status: exists`; `202 {dataset_id, status, type, run_id, job_id, job_ids, status_url, dataset_url}`), `GET /v1/datasets/{id}` (a consumed record by `ds-…` id, or a run's Croissant manifest as `application/ld+json`, digest-checked, `404` until exported), `POST /v1/datasets` (multipart only; membership, `dataset.register`, remediator; `411`, `413 dataset_too_large` over `REDSIM_ML_DATASET_UPLOAD_MAX_MB` 256, `415 unsupported_dataset_format` for a JSON body or a non-Parquet or pickle-shaped part or a non-Croissant manifest, `422 remote_reference_refused` for any `contentUrl` that is not a bare uploaded file name, `422 license_required`, `422 schema_undeclared` naming the field, `501` for `text` and `detection` slices; every refusal a `success=False` `dataset.register` row, nothing persisted; success writes the row, the blobs, the `ml_datasets` row in `validating`, an `ml.dataset_ingest` `Run` with no target and a `dataset.validate` `Job`, then enqueues `redsim.ml_dataset_validate` on `scans`; `201` record with `ingest_run_id`, `ingest_job_id`, `enqueued`), `GET /v1/runs/{id}/atlas-coverage` (membership; the number-free coverage view from `redsim.ml.atlas.coverage`: `exercised`, `declared_not_run`, `catalog_outside_declared`, `controls`, `techniques_exercised`, the release citation and the statement; `404` without a record, `409 llm_target_required`, `409 score_unavailable` on a digest mismatch), `GET /v1/integrations` (authenticated; `foundry` `disabled` by default, `misconfigured` with the rule, or `configured`, booleans only, never a host or token; `lattice` `not_implemented` text only by D3), `POST /v1/runs/{id}/integrations/foundry` (`integration.push`, admin; body `{auth_profile_id, target_ref?, payload: "scorecard"}`; `501 integration_disabled` with `reason` `disabled` or `misconfigured` while `REDSIM_INTEGRATION_FOUNDRY_URL` is unset or fails the egress rules or the `REDSIM_INTEGRATION_FOUNDRY_NON_OPERATIONAL=1` attestation is missing; `409 llm_target_required` / `campaign_not_terminal` / `score_unavailable` / `job_in_flight`, `422 fixture_not_exportable` / `params_out_of_range` / `auth_profile_kind_unsupported`, `404`, `503 queue_unavailable`; the `integration.push` row on the follow-up run's chain with the Foundry host as `target`, a `Run` with scanner `ml.integration_push` and a `Job` of type `integration.push`, the enqueue on `redsim.integration_push` on `default`; `202 {run_id, job_ids, status_url, integration, campaign_run_id, target_ref, kind}`; proven against `tests/ml/fake_foundry_server.py` only) |
| Batch, bulk and capacity (wave B3, `bulk-service-routes`, `bulk-upload-capacity-cli`) | `POST /v1/campaigns/batch` (`project_id` from the body, a form or `?project=`, else `422`; membership, `batch.run`, scanner; body `{project_id, target_ids, campaign: {<attacks body minus target_id>}, max_parallel?}` or flat; write-free pre-checks `422 params_out_of_range` / `batch_too_large` over `REDSIM_ML_BATCH_MAX_MEMBERS` 20 / `404 not_found` / `422 batch_modality_mismatch` with `groups`, each a `success=False` `batch.create` row; then one `batch.create` row, the `ml_batches` row and one `create_attack_campaign` per member through the unchanged single-run boundary with `batch_id` stamped on the member's `ml_campaigns` row, `Run.stage_table` and `Job.detail`; the capacity service consulted per member; per-member refusals collected, `422 batch_member_refused` only when nothing was admitted; `202 {batch_id, kind, project_id, modality, status, status_url, members, run_ids, refused, n_members, n_refused, config_hash}`), `GET /v1/campaigns/batch?project=&limit=` (`{batches, count}`), `GET /v1/campaigns/batch/{id}` (404, membership; the roll-up `queued | running | succeeded | partial | failed | cancelled`, `state` `active | terminal`, members with `score_status` and a `scorecard_url`, never an MRI number), `GET .../{id}/compare` (`200 mode: batch_side_by_side` with one comparability group, `409 incompatible_campaigns` with `groups`, `409 score_unavailable`; no delta, mean or rank), `POST .../{id}/cancel` (`run.cancel`, remediator; one `batch.cancel` row then `cancel_run` per live member; `409 run_terminal`), `POST /v1/findings/{id}/verify/bulk` (404, `verify.replay`; owner decision BULK-16: one `create_verify_campaign` per `(defense, params)` on a primary finding plus one `verify.replay` row per additional selected finding naming the shared run, both written through the boundary's `before_enqueue` hook so the worker never sees the job without `Job.detail.finding_ids`; since wave B4 the worker projects the shared record onto every listed finding from that finding's own attack rows, one `verify.execute` row per finding; body `{defense?, params?, defenses?, finding_ids?, include_fixed?, max_parallel?}`; `202` with `baseline_run_id`, `finding_ids`, `primary_finding_id`, `skipped`), `POST /v1/models/bulk` (`model.register`; several `files` parts plus one `manifest` JSON part `{project_id, items: [{filename, name, modality, dataset_id, license_statement, declared_format, architecture, dataset_split}]}`; `411`, `413 bulk_too_large` over `REDSIM_ML_BULK_UPLOAD_MAX_MB` 1024, `422 bulk_too_many_files` over `REDSIM_ML_BULK_UPLOAD_MAX_FILES` 10, a one-to-one filename match; one `bulk.upload` row and an `ml_batches` row of kind `upload`, then the single-upload admission per file with `bulk_id` stamped; `201` all validating, `207` mixed, `422 batch_member_refused` all refused; no model bytes deserialised in the API), `GET /v1/ml/capacity?project=` (membership on `?project=`, else the accessible projects, `global` for a system principal; `{projects: [...], limits: {max_concurrent_runs_default, daily_run_budget_default, env, bulk_upload, batch}, source}`). Capacity (`services.ml_capacity`): `Project.ml_max_concurrent_runs` (default `REDSIM_ML_MAX_CONCURRENT_RUNS_PER_PROJECT` 2) defers an over-cap admission (queued, `detail.deferred`, the `capacity_deferred` 202 marker, no broker message); `Project.ml_daily_run_budget` (`REDSIM_ML_DAILY_RUN_BUDGET`, unset uncapped) refuses `429 daily_budget_exceeded` with `budget`, `used`, `requested`, `resets_at`, `retry_after` after its `success=False` row; counts from the jobs table; `dispatch_deferred` runs from the beat task `redsim.ml_dispatch_deferred` every 60 s and `ml_campaign_run` enters `deferred_continuation(job_id)` so a finishing run dispatches the project's deferred jobs at once. Since wave B4 the single-run boundaries `create_attack_campaign` and `create_verify_campaign` call `admit_or_defer` before the admission row (a spent budget is `429 daily_budget_exceeded` after its `success=False` row; an over-cap admission is written deferred and not enqueued, the 202 body carries `deferred: true` and the `capacity_deferred` marker); the batch service decides per member and passes `capacity_check=False` |
| Models | `GET /v1/models` (registered targets including `ml_model_endpoint` rows with a credential-free `endpoint` block, unregistered bundled entries, the LLM domain as a `not_implemented` row. Fixture-only targets never listed), `GET /v1/models/{id}` (with `campaign_history` and, for an endpoint, `validation.probe`), `POST /v1/models` (`source: bundled` through `register_bundled_model`, `source: upload` with the static checks of spec 9.3, and since wave B2 `source: endpoint`: gated on `target.manage` (admin) before any field is read, `EndpointRegistration` plus the static egress check, the `model.register` row with `allowlist_check`, a `Target` of kind `ml_model_endpoint` in `status: validating`, then `redsim.ml_model_validate` probes it through the worker-parent broker; `endpoint_kind: llm` hands off to `services.ml_llm.register_llm_target`, which needs a canonical Pythia `model_id`, `persona`, `guardrail_mode` and a bearer `AuthProfile` and writes an `available` LLM target; any other `endpoint_kind` is `501`), `DELETE /v1/models/{id}` (audited soft delete, blob dropped, row kept for history; an endpoint row keeps `status: deleted` with host and profile id in the detail) |
| Campaigns | `POST /v1/models/{id}/attacks` (202 JobHandle, optional `parent_run_id` rerun of a failed or cancelled parent; since wave B2 admitted for `image`, `tabular`, `text` and `detection` through `SUPPORTED_MODALITIES` with per-modality norms and default grids, the adapter norm check, the detection `n_samples` cap of 200, the endpoint query budget and the project scoring weights), `GET /v1/runs/{id}/campaign` (the record plus `project_id`, `reviewer_notes`, `weights`, `non_default_weights` and, since wave B4, `batch_id` overlaid from the `ml_campaigns` row, `null` for a single-run admission; BULK-02), `GET /v1/runs/{id}/compare?with=` (variable-level `409 incompatible_campaigns`, `409 score_unavailable` when `mri` is null, `mode: verify_delta` or `side_by_side`, `non_default_weights` since B2), `GET /v1/runs/compare?ids=a,b,c` (wave B2: 2 to 10 runs, request order, no mean or rank, a delta only on a verify row whose baseline is in the set), `PATCH /v1/runs/{id}/reviewer-notes`, `GET /v1/runs/{id}/artifacts`, `GET /v1/artifacts/{id}`, `GET /v1/runs/{id}/report.{md,json,html,pdf}` (newest non-archived snapshot's artifact, then the newest artifact row, digest-checked; `?snapshot=<id|version>`; since wave B4 the campaign completion path renders the PDF and records the run's first snapshot, so `report.pdf` is `404 report not yet rendered` only when the renderer could not typeset the record, recorded as `pdf_unavailable` on the `report.render` row), `POST /v1/runs/{id}/report.render` (wave B2, `report.render` gate, `{formats?}`, 202, one immutable `report_snapshots` row per render, version 2 onwards after a completion snapshot), `GET /v1/runs/{id}/snapshots`, `GET .../snapshots/{ref}` (`409 snapshot_archived` for a non-admin), `POST .../snapshots/{ref}/archive` and `/restore` (`target.manage`, audited, bytes never deleted) |
| Findings | `GET /v1/findings` (since B2 with `status`, `review_state` and `source_tool` filters and a review summary per row), `GET /v1/findings/{id}`, `POST /v1/findings/{id}/explain`, `POST /v1/findings/{id}/harden`, `POST /v1/findings/{id}/verify` (since B2 also the training defenses on image targets with a torch module), `PATCH /v1/findings/{id}/status` (`false_positive` = dismiss, `open` = reopen, or a `decision`; the Phase A dismissal rules and codes byte for byte), and the wave B2 review workflow: `POST /v1/findings/{id}/review/{transition}` and `POST /v1/findings/{id}/review` with `decision` in the body (`submit`, `confirm`, `request_changes`, `dismiss`, `reopen`, `resolve` over `services.finding_review.TRANSITIONS`; `finding.review` for verdicts, `finding.author` for submit; independence by identity with `403 reviewer_not_independent`; compare-and-set on `expected_status` and `expected_review_state` with `409 review_state_conflict`; `resolve` refused with `409 resolution_blocked` and the unmet list until `poc_passed`, `fixed`, `confirmed` and a linked retest at the baseline's `settings_hash` hold), `GET /v1/findings/{id}/retests`, analyst drafts `POST /v1/findings` (201, `finding.author`, evidence ids checked against the digest-verified run record) and `PATCH /v1/findings/{id}/draft` |
| Runs and platform | `GET /v1/runs`, `GET /v1/runs/{id}`, `POST /v1/runs/{id}/cancel` (`409 run_terminal`), `GET /v1/audit/verify` (`?run=` resolves the project through run access, `?project_id=`, `?all=1` returns `{chains: [...]}`), `GET/POST/DELETE /v1/targets` (ML kinds are refused with `400 use_models_route`), `GET /v1/targets/{id}/verification` and `POST /v1/targets/{id}/verify` (501, pentest-era ownership check), `GET/POST/DELETE /v1/auth-profiles` (since wave B4 a delete while a live endpoint or LLM target of the project names the profile is `409 auth_profile_in_use` with `target_ids`, after a `success=False` `auth_profile.delete` row, ENDPOINT-18), `GET /v1/projects`, `GET /v1/projects/{slug}/membership`, `PUT /v1/projects/{slug}/settings`, `GET /v1/projects/{slug}/ml-scoring` and `PUT /v1/projects/{slug}/ml-scoring` (wave B2: the effective `ScoringConfig` with `source` `project` or `default`; the `PUT` is `target.manage`, takes the full block or `null`, validates through `ScoringConfig` and never renormalises, audited as `project.settings`), `GET /v1/logs`, `GET /v1/orgs/{org_id}/cost`, `GET /v1/scanners` (one adapter, `ml-campaign`, registered when `redsim.scanners` is imported, `3ab9de7`) |
| LLM probes (wave B2, `llm-api`) | `GET /v1/llm/probes` (authenticated; the committed catalog with the `redsim-core` and opt-in `redsim-extended` sets, per-probe `offline` / `extended` / `excluded` status with reasons, the prompt cap; `501` with the reason on a tree without `redsim/ml/llm/catalog.json`), `POST /v1/models/{id}/probes` (membership, `llm.probe.run`; body `probe_set` or `probe_ids`, `max_prompts_per_probe` 1 to 64 default 16, `seed`, `detector_mode` `offline` or `hf`, `finding_hit_threshold` default 0.2; `409 llm_target_required` for a classifier target, `422 probe_key_required`, `422 probe_set_unknown`, `409 job_in_flight`, `429` daily quota with `retry_after`; the `llm.probe.run` row, then a `Run` with `scanner ml.llm_probe` and a `Job` of type `llm.probe`, then the enqueue on `redsim.ml_llm_probe_run`; 202 with `scorecard_url`), `GET /v1/runs/{id}/llm-scorecard` (the digest-checked `ml.llm.scorecard` artifact; `409 score_unavailable` while the run is not terminal). `/campaign` and `/compare` refuse a probe run with `409 llm_target_required` |
| Phase B surface pin (wave B0 `0b0981b` mounted 19 stubs; B2 replaced five, B3 the last 14) | No route answers `501 not_implemented` as a stub. `tests/ml/test_phase_b_stubs.py` (rewritten by the B3 integration, 61 cases) pins the surface instead: every B0 path and method in the OpenAPI document, the same gate order (`viewer` 403 on gated routes, non-member 403 wherever a project resolves, 404 for an unknown run, model, finding, dataset or batch, `422 params_out_of_range` without `project_id`), then the observed typed refusal or read per route on a seeded harness whose finished run retained no slices, record or `ml_campaigns` row (`409 export_unavailable`, `415 unsupported_dataset_format`, `422 params_out_of_range` / `batch_member_refused`, 404 for the manifest, coverage and an unknown batch, 200 for the roster, the batch list and capacity); refusals create no `Run`, `Job`, `Target` or `Finding` and every audit row they write is `success=False` or the `batch.create` admission row. The by-design `501`s that remain are the Phase B answers in `docs/api/v1.md` (the `llm` modality on `/attacks`, `text` and `detection` uploads and consumed slices, the Lattice roster entry) and `integration_disabled` on the Foundry push, a configuration state. Full table in `docs/api/v1.md` |

Every ML refusal carries `{"detail": {"code", "message", ...}}` with a code
from `redsim/api/errors.py`, the single copy of the spec 17.3 table
(`use_models_route`, `already_registered`, `campaign_in_flight`,
`model_load_refused`, `campaign_not_terminal`, `job_in_flight`, `run_terminal`,
`incompatible_campaigns`, `score_unavailable`, `model_too_large`,
`unsupported_model_format`, `pickle_refused`, `architecture_required`,
`architecture_not_allowlisted`, `dataset_incompatible`, `unknown_attack`,
`unknown_defense`, `attack_modality_mismatch`, `defense_modality_mismatch`,
`attack_requires_gradients`, `eps_grid_invalid`, `reference_eps_not_in_grid`,
`params_out_of_range`, `not_implemented` (always with `phase`),
`queue_unavailable`, `db_unavailable`. `forbidden`, `not_found`,
`rate_limited`, `db_unavailable` keep the retained routes' string detail),
plus the 23 codes of the dated Phase B addendum (wave B0, `3cd3362`, spec
17.3 addendum of 2026-09-09: `capacity_deferred` as a `202` marker,
`endpoint_not_allowlisted`, `egress_refused`, `snapshot_not_found`,
`llm_target_required`, `export_in_flight`, `export_unavailable`,
`resolution_blocked`, `review_transition_invalid`, `dataset_too_large`,
`unsupported_dataset_format`, `endpoint_url_invalid`,
`auth_profile_kind_unsupported`, `endpoint_schema_mismatch`,
`probe_set_unknown`, `license_required`, `remote_reference_refused`,
`schema_undeclared`, `batch_modality_mismatch`, `batch_too_large`,
`daily_budget_exceeded`, `integration_disabled`, `endpoint_unreachable`),
plus the 13 codes of the second dated addendum (wave B2, `api: add thirteen
Phase B error codes; dataset.export to remediator`: `reviewer_not_independent`
403; `auth_profile_in_use`, `idempotency_key_reused`, `idempotency_conflict`,
`review_state_conflict`, `snapshot_archived` 409; `bulk_too_large` 413;
`auth_profile_required`, `probe_key_required`, `batch_member_refused`,
`bulk_too_many_files`, `fixture_not_exportable` 422; `query_budget_exceeded`
429, the register's 422 overruled because it is a budget refusal;
`tests/ml/test_error_codes.py` parses the spec table and both addenda and
refuses a code that exists on one side only), plus the 10 codes of the third
dated addendum (wave B4 `fix-api-services`: `attestation_required`,
`scoring_weights_invalid`, `model_id_invalid`, `model_not_chat`,
`gateway_url_required`, `unknown_probe`, `probe_excluded`,
`probe_detector_unavailable` 422; `llm_probe_quota_exceeded` 429;
`endpoint_auth_failed` 502), the codes the B2 routes had resolved with
`getattr` onto documented neighbours; the routes now raise them by name and
keep the `reason` field for one release. The same pass corrected the
`endpoint_schema_mismatch` row to the `endpoint-v1` name. Services raise
`ApiError`, the route converts it. Nothing parses exception text.

`tests/test_api_process_has_no_ml.py` builds the app in a subprocess with
`torch`, `torchvision`, `art`, `onnx`, `onnxruntime`, `shap`, `sklearn`,
`xgboost` and (since wave B0) `garak`, `openai`, `litellm`, `reportlab`,
`pyarrow` and `mlcroissant` blocked and asserts it still serves `/health`; it
also builds the sandbox child environment with low-entropy fake credentials
in the parent and asserts none survives. The catalog registries are imported
lazily. When one cannot be imported the route answers
`503 ml_catalog_unavailable`, never an empty list.

### Worker (`redsim.workers.celery_app`)

Thirteen tasks. `redsim.scan_start`, `redsim.verify_replay`,
`redsim.ml_campaign_run` and `redsim.ml_model_validate` route to the `scans`
queue through `task_routes`, and since wave B3 `redsim.dataset_export` (queue
set at enqueue) and `redsim.ml_dataset_validate` (queue on the decorator) run
on `scans` too. `redsim.report_render`, `redsim.reap_stale_jobs`,
`redsim.verify_tenant_integrity`, `redsim.export_chains_to_worm`, since
wave B2 `redsim.ml_llm_probe_run` (the garak probe run, on the one pool with
Pythia egress) and since wave B3 `redsim.integration_push` (the Foundry push,
the other outbound call, `max_retries=0`) and `redsim.ml_dispatch_deferred`
(the capacity backstop) run on `default`. The B3 tasks are registered through
the Celery `include` list (`redsim.workers.tasks.capacity`, `dataset_export`,
`dataset_validate`, `integration_push`); `task_routes` kept its nine entries
so the `tests/test_worker_hardening.py` pin holds. Beat runs the reaper every
5 minutes (it also rolls the run status up), tenant integrity hourly, WORM
export on `REDSIM_WORM_INTERVAL` and, since wave B3, the deferred-run
dispatcher every 60 s. Soft time limit 1800 s, hard 2100 s. `worker_init` and
`worker_process_init` configure OTel, structlog and the log shipper
(env-gated, idempotent per process).

`redsim/workers/tasks/ml_campaign.py` runs one whole campaign per job (see
"Accepted divergences"): it validates the frozen admission snapshot, runs
`redsim.ml.campaign.run_campaign` inside the credential-free sandbox child
(`redsim.ml.sandbox.run_campaign_sandboxed` spawning
`python -m redsim.ml.sandbox_worker`), then turns the returned envelope into
evidence:

- Artifact rows through `DatabaseArtifactSink` with the spec 5.8 kinds
  (`ml.curve`, `ml.shap.*`, `ml.feature_diff`, `ml.harden.*`, `report.md`,
  `report.json`, `report.html`. A killed child's files become `ml.partial.*`).
  The wave B1 integration adds the text kinds `ml.text.diff` and
  `ml.shap.text`, the detection kinds `ml.detection.boxes` and
  `ml.detection.scorecard` (its drawn images stay `ml.input.clean` /
  `ml.input.adv`) and the training-defense kinds `ml.derived_model` and
  `ml.training_report`; wave B2 adds `ml.clean_slice` and
  `ml.control_slice` for the persisted slices. Since wave B4 the completion
  path renders every format (`REPORT_FORMATS = ("md", "json", "html", "pdf")`),
  lists what it wrote on the `report.render` row and records the run's first
  `report_snapshots` row over those artifact rows
  (`services.reports.record_report_snapshot`; REVIEW_REPORTS-16/-20); a PDF
  the renderer cannot typeset (reportlab `LayoutError` on a wide table)
  degrades to the three text formats with `pdf_unavailable` on the row and
  the job completes. The stage table is closed from the returned record
  (a stage the record lists as done is `succeeded` even when its live frame
  never reached the parent). The text and detection runners write the same
  self-describing `clean_slice.npz`, `adv_slice/<attack>_<eps>.npz` and
  `control_slice/<eps>.npz` the classification runner writes
  (`runners/base.py::slice_bytes`, INTEROP-04), and the parent forwards
  `REDSIM_ML_MAX_ADV_ARTIFACT_MB` to the child when it is set.
- Wave B2 endpoint campaigns: for a `Target` of kind `ml_model_endpoint` the
  task resolves the `AuthProfile` credential at run time
  (`services.auth_profiles.resolve_auth_for_scan`), builds a credential-free
  `target_endpoint` block (the URL read from `Target.value`, host-only detail
  accepted) and calls `run_campaign_sandboxed(..., target_endpoint=,
  endpoint_auth=, endpoint_allowlist=)`; the broker is started in this parent
  and stopped by the sandbox in every exit path, the secret never reaches the
  child, a `job.detail`, a log or an audit row, and the broker tally (rows,
  requests, by purpose, budget, fingerprint) from
  `provenance.model_manifest["endpoint_broker"]` goes on the run record and
  the `attack.execute`, `campaign.score` and `job.complete` rows (the
  `attack.execute` rows of an endpoint run are written after the record, so
  they carry the counts).
- Wave B2 training verifies: after a verify whose `provenance.defense.kind`
  is `training`, the derived weights the child wrote become a NEW `Target`
  (kind `ml_model_artifact`, source `derived`,
  `MLModelManifest.derived_from = DerivedFrom(parent_target_id,
  parent_sha256, defense_id, training_budget)`) through the register-then-
  validate path (`status: validating`, a validate `Run`, a `model.validate`
  `Job`, the `model.register` row before the enqueue, `ml_model_validate`
  enqueued best-effort). No derived weights, no registration; the verify job
  never fails on it. `verify.execute` and the `RemediationAttempt` summary
  carry `derived_sha256`, `derived_target_id`, `parent_sha256` and
  `training_budget`; every verify appends a `FindingVerify` with
  `settings_hash` and `baseline_run_id` to `MLFindingDetail.retests`,
  keeping `verify == retests[-1]`.
- `Run.stage_table` in the spec 6.5 shape (`stages` map with `status` in
  `queued | running | succeeded | failed | skipped | cancelled | timed_out`,
  `started_at`, `finished_at`, `job_id`) and one `{"type": "stage", "name",
  "status"}` frame per transition on the run-events channel.
  `expected_stages` adds `defense_apply` right after `load_target` only when
  the campaign's defense is a `kind: training` row (wave B1 integration); a
  preprocessing defense wraps the target inside `load_target` and has no
  stage.
- Audit rows in the spec 10.5 vocabulary through `redsim.safety.authorize`:
  `model.load`, `attack.execute.<attack_id>`, `explain.execute`,
  `campaign.score`, `harden.execute`, `verify.execute`, `report.render` (with
  `formats`) and `job.complete`, actor `worker:<job type>` with the requesting
  principal in `detail.requested_by`. Refused or failed steps are
  `success=False` rows. Details carry ids, digests and counts only.
- The Pythia narrative in this parent process, after the envelope returns:
  model through `redsim.llm.router.route("ml.harden_narrative")` with
  `DbBudgetChecker`, transport `redsim.llm.pythia.chat_text` inside the
  guardrails, prompt and completion stored as `ml.harden.prompt` /
  `ml.harden.completion` artifacts with digests on the `harden.execute` row,
  one `LLMUsage(task="ml.harden_narrative")` row per call. Every failure keeps
  the rule output with `narrative_source="rules"` and the skip reason.
- Findings: `attack.run` projects threshold crossings per spec 5.7.
  `explain.run` and `harden.recommend` merge the child's observations,
  interpretation and candidates back into the parent finding's
  `schema_blob["ml"]`. `verify.replay` attaches the `MeasuredDelta` to the
  recommendation naming the defense, maps the outcome through
  `verify._STATE_MAP` and spec 6.4 (`inconclusive` -> `open`), writes the
  `RemediationAttempt` row and the `verify.execute` audit row. Since wave
  B4 a bulk verify (owner decision BULK-16) projects the one defended record
  onto every finding in `Job.detail.finding_ids` from that finding's own
  attack rows, one `verify.execute` row per finding, the primary first; a
  child failure leaves every listed finding `inconclusive` / `open`.
- `SandboxTimeout` / `SandboxKilled` / `EnvelopeInvalid` are Job failures with
  the stage `timed_out` / `failed`, completeness `partial`, a `job.complete`
  row with `success=False` and the error class.

`redsim/workers/tasks/ml_model.py` (`redsim.ml_model_validate`) validates
uploads in the sandbox child: typed validate envelope, parent-side sha256
check against the manifest (`ArtifactDigestMismatch`), the spec 5.11 detail
(format, status, gradients, onnx2torch agreement, library versions), blob
delete on refusal, `job.complete`. Since wave B2 it dispatches on
`Target.kind`: the endpoint variant reads the `auth_profile_id` from the
job detail, resolves the credential at pickup and passes it only as the
`endpoint_auth` argument of `redsim.ml.sandbox.probe_endpoint_sandboxed`
(the child sends the seeded 8-row probe over the broker socket), then records
`available` with `gradients: false`, the response fingerprint (remote model
identity, never a weights digest), latency, `tls_mode`, rows, requests and
resolved addresses under `validation.probe`, or `refused` with the frozen
`refusal_reason` (`shape_mismatch` for a contract violation, `load_failed`
for unreachable, auth, egress or budget failures) and the typed class and
code beside it. A deleted profile refuses without probing; a missing
`REDSIM_AUTH_PROFILES_KEY` fails the job with a `success=False` row, never an
anonymous probe.

`redsim/workers/tasks/ml_llm.py` (`redsim.ml_llm_probe_run`, wave B2, on
`default`, `max_retries=0`): in order, `REDSIM_DISABLE_LLM` (job fails
`llm_disabled` with no gateway request), the `load_target` stage,
`enforce_budget_for_run` (`budget_exceeded`), `resolve_auth_for_scan`
(`auth_profile_missing` / `probe_key_required`), the entitlement check
through `redsim.llm.pythia.list_models` with the probe key (an
`llm.probe.entitlement` row, `model_not_entitled` or `gateway_unreachable`),
then `redsim.ml.llm.runner.run_probe_child` in a fresh credential-minimised
subprocess (`python -m redsim.ml.llm.probe_child --spec <json>`, the key in
a 0600 file the child deletes at once, the plugin sandbox's interpreter
allowlist with `PYTHIA_*`, `AWS_*`, `KAGGLE*`, `OPENAI*`, `HF_TOKEN` and
every other `REDSIM_*` swept, `REDSIM_LLM_PROBE_TIMEOUT_S` 1500 s, process-
group kill). Per-probe stages `probe:<short_id>` and
`llm.probe.execute.<short_id>` rows; garak's `report.jsonl`, `hitlog.jsonl`,
digest HTML, the usage ledger and `child_result.json` stored as
`ml.llm.report_jsonl`, `ml.llm.hitlog_jsonl`, `ml.llm.digest_html`,
`ml.llm.usage`, `ml.llm.child_result` (`ml.llm.partial.*` when the child
did not succeed) and never parsed for text, storage failing closed when the
key shape appears; the k/n scorecard validated for forbidden keys and
through `LLMProbeScorecard`, stored as `ml.llm.scorecard` with an
`llm.probe.score` row; one `LLMUsage(task="ml.llm_probe")` row; findings
through `services.ml_findings.project_llm_findings` (severity derived from
hit rate, `>= 0.5` high, `>= 0.2` medium, `> 0` low, labelled so); rule
candidates from `redsim.ml.llm.rules`; `report.{md,json,html}` through
`redsim.ml.llm.reporting.render_probe_reports`; `report.render` and
`job.complete`. A failed or timed-out child keeps the evidence, projects
nothing and fails the job (`probe_child_failed` / `probe_child_timeout`).

The wave B3 tasks (`docs/interop.md`, `docs/api/v1.md`):

- `redsim/workers/tasks/dataset_export.py` (`redsim.dataset_export`, on
  `scans`, `max_retries=2`): loads the source run's persisted slices and
  `ml.flip_matrix`, runs the projection-equality guard
  (`redsim.ml.interop.croissant.check_projection`), builds the content-
  addressed Parquet shards, the Croissant manifest (its own sha256 is the
  dataset version) and the template card, writes them under
  `datasets/<source-run-id>/` as `ml.dataset.parquet`, `ml.dataset.manifest`
  and `ml.dataset.card` rows on the source run, then `dataset.export.execute`
  (manifest sha256, file count, bytes, prefix) and `job.complete` on the
  follow-up run's chain. A mismatch or an invalid manifest is a
  `success=False` execute row and a failed job with nothing written. The
  classification runner writes self-describing `clean_slice.npz`,
  `adv_slice/<attack>_<eps>.npz` and `control_slice/<eps>.npz` with the
  prediction keys (embedded `family` / `attack` / `eps` descriptors, so the
  exporter labels a slice from its bytes on the digest-addressed filesystem
  store), so a live classification export carries all three families
  (INTEROP-04); the text and detection runners' slices are skipped with a
  caveat.
- `redsim/workers/tasks/dataset_validate.py` (`redsim.ml_dataset_validate`,
  on `scans`, `max_retries=2`): materialises the consumed slice's blobs into
  the job work directory, re-hashes them in the parent (a substituted blob is
  `artifact_digest_mismatch` with no child spawned), spawns
  `python -m redsim.ml.interop.consume` under the ML sandbox's allowlisted
  credential-free environment, rlimits, process group and wall clock, reads
  the envelope, marks the `ml_datasets` row `available` or `refused` with
  the child's code (`manifest_digest_mismatch`, `dataset_too_large`,
  `schema_mismatch`, `class_names_mismatch`, `parse_failed`,
  `sandbox_timeout`, `sandbox_killed`), writes one `dataset.validate` audit
  row, the `ml.dataset_validation_report` artifact and `job.complete`. The
  parent never opens a Parquet file (asserted by monkeypatching
  `pyarrow.parquet.ParquetFile` to raise in the test process).
- `redsim/workers/tasks/integration_push.py` (`redsim.integration_push`, on
  `default`, `max_retries=0`): re-reads `FoundrySettings.from_env` on the
  worker (a lost URL or attestation fails the job as `integration_disabled` /
  `integration_misconfigured`), loads the run record with its digest checked
  against the artifact row and the admission-time digest, refuses a
  fixture-flagged record (`fixture_not_exportable`), builds the scorecard
  payload and runs `assert_push_payload` (a bare MRI, a URL string, a
  JWT-shaped or `Bearer` value, a model file name, raw bytes,
  `expected_gain`, `reviewer_notes` or a readiness word is `payload_refused`),
  stores the exact bytes that leave as `ml.integration.payload` and
  `ml.integration.rows` first, resolves the bearer token through
  `resolve_auth_for_scan` only then and drops it after the push, pushes
  through the Foundry Datasets v2 flow (create an `APPEND` transaction,
  upload `scorecard.json` and `rows.jsonl`, commit; abort best-effort),
  stores `ml.integration.receipt` and writes `integration.push.execute` (host,
  rids, digests, HTTP statuses, counts, or `step`, `http_status`,
  `error_class`, `transaction_aborted` with `success=False`, no retry) and
  `job.complete` through the shared `_AuditEmitter`. Stage table over
  `configure`, `load_record`, `build_payload`, `push`, `receipt`.
- `redsim/workers/tasks/capacity.py` (`redsim.ml_dispatch_deferred`, on
  `default`, beat every 60 s): one `dispatch_deferred` pass per project
  (deferred jobs enqueued oldest-first while a slot is free, the flag
  restored on a broker failure) plus a gauge sample through
  `set_capacity_gauges`. `deferred_continuation(job_id)` is a context manager
  around `continue_deferred(project_id, finishing_job_id=)`; `ml_campaign_run`
  enters it outside `task_context`, so every exit path dispatches the
  project's deferred jobs once the terminal status is committed (never
  raises; unknown job or db down is a logged no-op); the beat sweep is the
  backstop.

### Database and policy

`redsim/db` models plus Alembic migrations `0001` to `0011`.
`0010_ml_vertical` adds `targets.detail` JSONB and the `ml_campaigns` table
with full RLS parity (denormalized `org_id`, BEFORE INSERT backfill trigger,
BEFORE UPDATE drift guard, `FORCE ROW LEVEL SECURITY`, the
`redsim_tenant_isolation` policy). `0011_phase_b_platform` (Phase B wave B0,
`7b1f2fa`, the one move of the frozen head, announced in master plan
section 5) adds `report_snapshots`, `idempotency_keys` (primary key
`(project_id, key)`), `ml_batches` and `ml_datasets` with the same RLS
parity token for token, `projects.ml_scoring` / `ml_max_concurrent_runs` /
`ml_daily_run_budget` and `ml_campaigns.batch_id` (nullable, indexed, no
FK). ORM models `ReportSnapshot`, `IdempotencyKey`, `MlBatch`, `MlDataset`;
`ml_campaigns` stays migration-owned (no ORM model; the services reflect it
and the e2e harness, the campaign-route tests and, since B3, the surface pin
keep sqlite mirrors that carry `batch_id`). Since wave B3 `ml_batches` holds
campaign, verify and upload batches (`kind`, the roll-up `status`, `config`
with members and collected refusals, the sha256 of an `Idempotency-Key`),
`ml_datasets` the consumed slices (`status` `validating`, `available`,
`refused`, `manifest_sha256` as the revision, the declared schema and file
digests in `detail`), `ml_campaigns.batch_id` is stamped on batch members,
and `projects.ml_max_concurrent_runs` / `ml_daily_run_budget` are read by the
capacity service. `tests/test_migration_0011.py` and
`tests/test_tenant_rls.py` cover it (Postgres cases skip without
`REDSIM_DB_URL`); the tenant reconciler scans the `0010` and `0011` tables as
well since the B1 integration. Bundled registrations are per project:
`Target.id` is `<bundled_id>-<8 hex>`, `Target.value` is `bundled:<id>`, the
registry id lives in `detail.bundled_id`
(`redsim.services.ml_models.register_bundled_model(session, project_id,
bundled_id, actor, *, audit_writer=None, config=None, blob_store=None,
assets_root=None) -> Target`).

`redsim/api/policy.py`: roles `viewer` (0) < `scanner` < `remediator` <
`approver` < `admin`. `Action` members and minimum roles: `scan.start`
(scanner), `verify.replay` (remediator), `target.manage` (admin),
`auth_profile.manage` (admin), `audit.verify` (admin), `run.cancel`
(remediator), `model.register` (remediator), `attack.run` (scanner),
`explain.run` (scanner), `harden.recommend` (remediator), `finding.review`
(approver), `finding.annotate` (remediator), `report.export` (scanner), and
since wave B0 (`3cd3362`, spec 7.4 addendum) the Phase B members
`llm.probe.run` (remediator), `dataset.register` (remediator),
`dataset.export` (remediator since wave B2; B0 had scanner from the brief's
wording, B2 aligned the three policy files to spec 17.4 and 27.4),
`integration.push` (admin), `batch.run` (scanner), `report.render`
(scanner), `finding.author` (remediator). The table is mirrored in
`deploy/opa/redsim-authz.rego` and `deploy/cedar/redsim-policy.cedar`.
Change all three together; `tests/test_policy_ml_actions.py` parses both
mirrors and asserts equality.

### Platform packages

`redsim/audit` (chain, forensic, redaction), `redsim/api/middleware` (tenant
GUC for RLS, CSRF, rate limit, and since wave B2 `idempotency.py`: a pure
ASGI middleware honouring `Idempotency-Key` on `POST`/`PUT`/`PATCH`/`DELETE`
under `/v1/models`, `/v1/findings`, `/v1/runs`, `/v1/campaigns` and
`/v1/datasets`, keyed by project, principal and `sha256(principal | key)` so
the raw header never lands in `idempotency_keys`, replaying a stored 2xx JSON
body up to 64 KB with `Idempotency-Replayed: true`, `409
idempotency_key_reused` for the same key with a different route or body,
`409 idempotency_conflict` while the original is still reserved, keys
outside 1 to 255 characters `422`, rows older than 24 h a miss, a lookup
failure a logged pass-through), `redsim/llm` (router, budget, pricing with
the environment snapshotted around the `litellm` import so a cost lookup is
never an ambient credential source, guardrails, `pythia.py`,
`pythia_check.py`), `redsim/storage` (filesystem, S3, WORM), `redsim/state`,
`redsim/services` (`ml_models`, `ml_campaigns`, `ml_findings`, `reports`,
`runs`, `scans`, `targets`, `verify`, `auth_profiles`, `evidence`, since
wave B2 `ml_llm` and `finding_review`, and since wave B3 `ml_datasets` (the
consumed-slice admission, stdlib only), `ml_datasets_export` (the export
admission and the manifest read), `ml_batches` (batch and bulk-verify
admission, roll-up, view, cancel) and `ml_capacity` (deferral and the daily
budget, ML-import-free)), `redsim/integrations` (wave B3: `foundry.py` with
the settings, roster block, payload builder, D9 guard, `scrub_detail` and the
Datasets v2 client, and `__init__.py` with the push admission boundary
`create_foundry_push`, the vocabulary and the Lattice text; imported by the
API process for the roster and admission, httpx and pure redsim modules
only), `redsim/scanners` (registry,
`KNOWN_CAPABILITIES`, out-of-process plugin sandbox), `redsim/registry.py`,
`redsim/plugins.py`, `redsim/supply_chain/signing.py`, `redsim/cli`,
`redsim/log_ingest`, `redsim/observability.py`, `redsim/doctor.py`.

### ML vertical (`redsim/ml/`)

`schema.py` is FROZEN by P0 (`TargetInfo`, `AttackInfo`, `ParamSpec`,
`CampaignConfig`, `ScoringConfig`, `MRIWeights`, `DefenseConfig`,
`Provenance`, `Measurement`, `Observation`, `Interpretation`, `Subscores`,
`MeasuredDelta`, `MRIDelta`, `CandidateRecommendation`, `MRIInputRow`,
`MRIRecord`, `MLModelManifest`, `MLFindingDetail`, `AtlasTechnique`,
`RobustnessCurve`, `RunRecord`, `CampaignRecord`, `RunSummary`, `STAGES`,
`STANDING_LIMITATIONS`, `grade_for_mri`, `contains_banned_score_word`) and
was extended once, additively, by Phase B wave B0 (`934838e`, master plan
section 0): `Domain` and `Modality` gain `text` and `detection`, `Norm`
gains `edit` and `patch_area`, `Measurement.edit_fraction_mean` and
`.detection: DetectionMetrics`, `Observation.text: TextObservation` and
`.detection: DetectionObservation`, `MLModelManifest.text`, `.detection`,
`.endpoint: EndpointSpec`, `.derived_from: DerivedFrom` (omitted from dumps
while `None`, so every earlier `manifest_sha256` holds), `ReviewState` with
`draft`, `in_review`, `confirmed`, `resolved`, `FindingReview.history` and
`.revisions`, `MLFindingDetail.retests`, `FindingVerify.settings_hash` and
`.baseline_run_id`, `CampaignRecord.schema_version = "campaign-record-1"`,
`RunSummary.kind` (`RunKind`) and `.probe_ids`, and `STAGES` with
`defense_apply` after `load_target`. `tests/ml/test_schema_compat.py` is the
tripwire: the frozen fixture's sha256, byte-identical round trip under
`exclude_unset`, no P0 property removed or retyped, every later property
default-valued. `targets/base.py` (`Target`, `Sample`) and `attacks/base.py`
(`AttackAdapter`, `AttackOutput`) are the frozen protocols.

Modules: `registry.py`, `artifacts.py`, `errors.py` (spec 10.6 failure
classes: `ModelLoadRefused`, `ArtifactDigestMismatch`, `SandboxTimeout`,
`SandboxKilled`, `EnvelopeInvalid`, `DatasetUnavailable`,
`MlExtraUnavailable`, `ExplainerUnavailable`, each with a `code`; since wave
B1 also `EndpointError`, `EndpointUnreachable`, `EndpointAuthFailed`,
`QueryBudgetExceeded` and the re-exported `EndpointSchemaMismatch`,
`EgressRefused`, `EndpointUrlInvalid`, `EndpointNotAllowlisted`, all rebuilt
by name from the child's envelope), `defenses.py` (every row with `kind`
`preprocessing` or `training` and `phase`; `DEFENSES` stays the
preprocessing tuple the Phase A verify admission treats as runnable,
`TRAINING_DEFENSES` and `ALL_DEFENSES` since wave B1), `harden/` (wave B1:
`apply.apply_training_defense` as the `defense_apply` stage returning a
`DerivedTorchTarget` with a `TrainingRecord`, `adversarial_training` over
ART `AdversarialTrainer`, native torch `distillation`, the tabular tree
ensemble a typed `TrainingDefenseUnavailable`), `eval.py`, `scoring.py`
(`DEFAULT_EPS_GRID_LINF` `(0.01, 0.03, 0.1)`, `DEFAULT_EPS_GRID_L2`
`(0.25, 0.5, 1.0)`, `DEFAULT_REFERENCE_EPS` `0.03`, the binomial
`control_preserves_accuracy` predicate, `FamilyDelta`, typed delta refusal),
`campaign.py` (since wave B1 the shared frame: target and defense
resolution, attack-set resolution with `attack_supports_norm`, stages,
evidence lists, curve and flip-matrix artifacts, the explain gate, score,
interpret, recommend, report, provenance; attacks that cannot run are
recorded `not_run` and removed from the in-scope set, curve PNG, dataset
caveats and the `subject_centered` weak-subject caveat), `runners/` (wave
B1: `base.py` with `CampaignFrame`, `ModalityResult`, the `ModalityRunner`
protocol, `MODALITY_RUNNERS` keyed by every `Modality` literal and resolved
lazily, `ModalityRunnerUnavailable`, the offline `NLTK_DATA` / `TORCH_HOME`
pins; `classification.py` for image and tabular, `text.py`,
`detection.py`), `endpoint_broker.py` and `endpoint_egress.py` (the
worker-parent `PredictBroker`, the only outbound HTTP of the vertical, and
the egress policy; `docs/api/endpoint-contract.md`), `atlas_data.py` (wave
B0: ATLAS `v2026.08` vendored with digests and the 4.x prior names),
`reporting.py` (six sections in the spec 14.8 order: configuration and
provenance, measurements with the MRI scorecard as a derived-summary
sub-block, observations, interpretation, candidate recommendations,
limitations then reviewer notes. `report.json` is
`CampaignRecord.model_dump`. HTML through the escaping helpers in
`redsim.report`. Since wave B2: `schema_version` and a licence line in
section 1, the **Non-default weights** badge with the vector when it differs
from `MRIWeights()`, the derived-model lineage in the delta block of a
training verify, the open-D006 sentence "No export-redaction policy was
applied to this report" in section 6, `render_campaign_reports(formats=)`
with `REPORT_FORMATS_TEXT` / `REPORT_FORMATS_ALL`, and the LLM section hook
`is_llm_probe_record` / `_llm_section` embedding
`redsim.ml.llm.report_section.render_llm_section` between sections 2 and 3),
`pdf.py` (wave B2: `render_pdf(record, generated_at=, markdown=)` typesets
the same Markdown into reportlab platypus flowables, a third projection of the
record and never a recomputation; reportlab imported inside the function
only; `invariant=1` for byte-identical output; DejaVu Sans regular and bold
subsets under `pdf_fonts/` with the Bitstream Vera licence,
`REDSIM_PDF_FONT_DIR` overrides, matplotlib's copy the last fallback, no face
at all a `PdfFontsUnavailable` refusal rather than a Latin-1 fallback),
`compare.py` (wave B2: the pure comparison module, `comparison_table` over 2
to 10 runs in request order with `changed_variables_per_row`,
`unchanged_variables`, `ignored_variables`, `caveats`, a delta only on a
verify row whose baseline is in the set, `assert_no_aggregate_keys` refusing
any mean, rank, average or aggregate key, `is_default_weights` /
`non_default_weights`; since wave B3 `comparability_groups` for the batch
compare, greedy in request order, no aggregate), `interop/` (wave B3, worker
and sandbox child only, pyarrow imported inside functions: `parquet.py` with
the fixed nullable column schema, `eps_tag`, the slice descriptors and the
deterministic shard writer, `croissant.py` with the Croissant 1.0 manifest
builder, `check_projection` (the projection-equality guard against
`ml.flip_matrix`, `ExportMismatch`) and `croissant_validate` (structure,
banned tokens, no bare MRI), `card.py` with the template-only dataset card,
`consume.py` the parse child for a consumed slice with
`load_consumed_slice`, `ConsumeRefused` and the envelope-shaped `main`),
`atlas.py` (wave B3: `STAMP_TECHNIQUE_IDS` checked at import against
`atlas_data.ATTACK_TECHNIQUE_IDS`, `technique_for_attack`,
`techniques_for_attack`, `stamp_reason`, `attack_atlas_row`,
`release_citation`, `coverage` with `numeric_paths` refusing any number in
the view), `llm/` (wave B2, worker and tests only: `catalog.py`
with the committed `catalog.json` regenerated from garak 0.16.0, 103 probes,
the `redsim-core` set of 76 offline-detector probes and the opt-in
`redsim-extended` set of 85, 18 excluded rows with reasons including
`fitd.FITD` for HarmBench (LLM-08); `generator.py` with
`PythiaGenerator(OpenAICompatible)` posting `model`, `messages`,
`temperature`, `max_tokens` only to `{gateway}/v1/`, `X-Pythia-Persona` as a
default header, `redsim.llm.pythia.tls_verify`, `max_retries=0` with a
bounded retry loop, a caller-supplied key never read from the environment,
`assert_no_litellm`; `probe_child.py` and `runner.py`; `scorecard.py` with
`LLMProbeScorecard` whose validator refuses MRI, grade, subscore and weights
keys and requires the D9 sentence; `rules.py` with `r.L1` to `r.L7` and
`NARRATIVE_NOT_OFFERED_REASON`; `report_section.py`, `schema.py`,
`reporting.py` as the register's names), `sandbox.py` and `sandbox_worker.py` (typed
`MlSandboxConfig` from `REDSIM_ML_SANDBOX_*`, defaults 1200 s wall clock,
900 CPU s, 4096 MB, 1024 MB files, 2 threads. Child env is the interpreter
allowlist plus `MPLBACKEND=Agg`, `HF_HUB_OFFLINE`, `HF_DATASETS_OFFLINE`,
thread pins, `REDSIM_ML_ASSETS_DIR`, `REDSIM_ENV_FILE` pinned to the absent
`<work_dir>/no-env` and `REDSIM_DISABLE_LLM=1` (`c3868e5`), with every
secret-bearing and proxy variable removed. Work dir
`REDSIM_ML_WORK_DIR/<job_id>` mode 0700),
`targets/` (`registry`, `architectures` with `small_cnn` (alias `smallcnn`)
and `resnet18`, `bundled`, `tabular`, `artifact` with onnx2torch conversion
and argmax agreement, `unavailable`, and since wave B1 `text`
(`BundledTextTarget` `sms_tfidf_lr`, `joblib.load` only after the digest
matched), `detection` (`BundledDetectionTarget` `assets_frcnn_mnv3`, greedy
IoU matching, recall and `map50` with box denominators), `endpoint`
(`EndpointTarget` over ART `BlackBoxClassifier`, `access`
`black-box-endpoint`, `gradients: false`) and `endpoint_contract` (wave B0,
`endpoint-v1`, pure Python)), `attacks/` (`fgsm`, `pgd` with surrogate
transfer, per-feature eps scaling and ART mask for tabular, `hopskipjump`
with `IMAGE_DEFAULTS` since B1, `noise_control`, and since wave B1 `cw_l2`,
`deepfool`, `zoo`, `word_substitution` with its unregistered
`text_noise_control`, `dpatch` with `patch_noise_control`; `registry.py`
with `KNOWN_NORMS`, `attack_norms`, `attack_supports_norm`,
`apply_domain_defaults` and the `norm:*` tags), `datasets/` (`cifar10`,
`image_hub`, `sampling`, `url_features`, since B1 `sms_spam` and
`military_assets`), `explain/` (`base` with `EXPLAIN_QUERY_CAPS`,
`EXPLAINER_ROSTER` and `explain_caps_for`, `shap_image` with the
`PartitionExplainer` fallback, `shap_tabular` with the `explainer` choice and
`KernelExplainer` for predict-only targets, `shap_text`, `stability`,
`summary`, the explanation cache under `REDSIM_ML_EXPLAIN_CACHE` or the work
dir), `recommend/` (`rules`, `narrative`), `assets/` (`datasets` with the
Phase B dataset loaders and public-repository index, `build`, `train_cnn`,
`train_url_classifier`, `train_text_classifier`, `train_detector`,
`fixture_sample`, `manifest` with `DatasetSource` `uci` / `github` and the
Phase B bundled ids).

`import redsim.ml.targets, redsim.ml.attacks` registers the targets
`assets_frcnn_mnv3` (detection, `not_implemented` until its asset is built),
`cifar10_smallcnn` (fixture only), `endpoint_stub` (`not_implemented`),
`url_trees` (legacy alias `url_classifier`) and `vehicles_cnn`; `sms_tfidf_lr`
and `assets_frcnn_mnv3` register on a bare `import redsim.ml.targets` since
the B2 integration (`redsim/ml/targets/__init__.py` imports `.text` and
`.detection`, still without sklearn, torch or joblib). The attacks are `cw_l2`,
`deepfool`, `dpatch`, `fgsm`, `hopskipjump`, `noise_control`,
`patch_noise_control`, `pgd`, `word_substitution`, `zoo` (checked at import
against the declared list; `adv_patch` recorded as not built). The defenses
are `feature_squeezing`, `spatial_smoothing`, `jpeg_compression`
(preprocessing) and `adversarial_training`, `defensive_distillation`
(training, `phase: "B"`, admitted by the verify route since wave B2 on image
targets whose manifest gradients are not `false`; tabular is
`422 defense_modality_mismatch` with the tree-ensemble reason, a gradient-free
target `422 params_out_of_range` with `training_defense_unavailable`).
`tests/ml/` holds `fakes.py` (`TinyTarget`, `TinyTabularTarget`),
`fakes_text.py` (`TinyTextTarget`), `fakes_detection.py` (`TinyDetector`),
`tiny_endpoint_server.py`, `fake_openai_server.py` (wave B2: a stdlib
`ThreadingHTTPServer` on `127.0.0.1` with `GET /v1/models` and
`POST /v1/chat/completions`, bearer check, persona and body-key recording,
usage blocks, failure switches, a low-entropy fake token),
`fake_foundry_server.py` (wave B3: the Foundry Datasets v2 create, upload,
commit and abort paths on `127.0.0.1` with a bearer check, per-request
records, `fail_at` / `fail_status` switches and a low-entropy JWT-shaped
fake token assembled from three segments so no JWT literal sits in the
source), the wave B3 test files `test_interop_export.py`,
`test_interop_consume.py`, `test_atlas_foundry.py`, `test_batches.py`,
`test_bulk_upload_capacity.py`, `test_cli_matrix.py` and the rewritten
`test_phase_b_stubs.py`, `fixtures/` (`run_record.json`,
`run_record_phase_b.json`, `malicious_urls_sample.csv`,
`cifar10_test_500.npz`, `sms_spam_sample.tsv`, `synonyms_tiny.json`,
`public_index.csv`, `MANIFEST.json`), `_campaign_pre_refactor.py` (the
frozen pre-refactor `run_campaign`, sha256 asserted, for
`test_campaign_golden.py`) and the module, route, task and audit tests. An
autouse fixture in `tests/ml/conftest.py` keeps every ML test away from a
developer's `.env`.

### Web

`@redsim/web` pages: `/`, `/login`, `/dashboard`, `/runs`, `/runs/[id]`,
`/findings`, `/findings/[id]`, `/projects`, `/projects/[slug]/settings`,
`/targets`, `/auth-profiles`, `/logs`, `/audit`, `/cost`, `/models`,
`/models/[id]`, with `MriScorecard`, `DimensionBars`, `RobustnessCurve`,
`MeasurementTable`, `ObservationCard`, `LabelBadge`, `PanelSection` and
`CompatibilityList` in `@redsim/design-system`. The pages render an explicit
`not_implemented` state on 404 or 501. PR #22 aligned the web contract with
the mounted routes. Wiring beyond that alignment has not been exercised in a
browser against a running stack and is listed as open in the README.
`web/src/lib/api.ts` defaults to `http://localhost:8000`, overridable with
`NEXT_PUBLIC_REDSIM_API_URL`.

### Deploy

`deploy/docker-compose.yml`: postgres (5432), redis (6379), keycloak (8080),
minio (9100/9101), redsim-api (8000, runs `alembic upgrade head` on start),
redsim-worker (`-Q scans`), redsim-worker-default (`-Q default`),
redsim-beat, redsim-web (3300), redsim-log-ingest (4319), plus opt-in
profiles `policy` (opa), `obs` (otel-collector, loki, jaeger) and
`obs-search` (elasticsearch, kibana). `Dockerfile.api` installs `.[api,worker]`,
`Dockerfile.worker` installs CPU torch then `.[worker,ml]`.
`deploy/helm/redsim` is the chart. `deploy/terraform/` (#19, on `main`) is
the code-only Fargate foundation (existing-VPC checks, private endpoints, an
ALB with target groups but no listeners, RDS PostgreSQL 16, Redis, two S3
buckets, per-service IAM roles, mocked-plan tests behind `validate.sh`): no
task definitions, no services, nothing applied from this tree. Compose and
Helm have not been brought up as part of the completion pass.

PR #23 (`feat/p7-fargate-runtime`, William, merged as `10650da`) adds
`deploy/bootstrap/` and `deploy/runtime/`: a public HTTPS Fargate demo
runtime at https://redsim.ndia.agiledefense.xyz with ACM and DNS, Keycloak,
separate migration tasks, service-scoped secrets and immutable images. Its
author reports it applied to the AWS account (`140381642432`, `us-east-1`)
with migrations through `0010` (the next rollout has to migrate to `0011`),
`/health`, the login page and OIDC discovery answering 200 and
unauthenticated API calls answering 401. Workers stay at zero tasks until a
pinned asset bundle is supplied, demo users and project memberships and real
model assets are outstanding, and automatic ECS rollout stays disabled.
`deploy/runtime/README.md` is the deployment sequence. Its completion is
package E of `docs/plans/10-remaining-work-brief.md`, outside the Phase B
waves, and no campaign has been run on that runtime.

### Wave 3 (on `main`, `7556b22..58461cc`, verified from this tree)

Ten commits after `bb43bd7`, integrated by `58461cc` (2026-09-09).

- `3ab9de7` `redsim ml attack <target_id>`: offline campaign against a
  bundled target from `REDSIM_ML_ASSETS_DIR` or `./assets`, run in the
  sandbox child, writing `<out>/<run_id>/{run_record.json, report.md,
  report.json, report.html, artifacts/curve/robustness_curve.png,
  audit.jsonl}`. The `attack.run` row is written first through
  `JsonlAuditWriter` (single-file chain `run:<run_id>`), every stage event
  and `job.complete` land in the same chain. `endpoint_stub` refuses with
  `not_implemented`, fixture-only targets with `fixture_only`, both before
  anything is written. `llm_narrative` stays false and the CLI prints
  `narrative_source=rules`. `--out` defaults to the config `output_dir`.
- `3ab9de7` then `98a8733` `redsim ml seed [--project] [--only]
  [--assets-dir] [--actor]`: opens `REDSIM_DB_URL` and calls the real
  `register_bundled_model(session, project_id, bundled_id, actor,
  audit_writer=, config=, blob_store=, assets_root=)` per non-fixture
  manifest model, commits per model, reports `registered` versus `already
  present` (the service's `409 already_registered`), writes the route's
  `success=False` `model.register` row for any other refusal and exits 1
  after trying the remaining models.
- `3ab9de7` `CampaignScannerAdapter` registered as `ml-campaign` with
  capabilities `adversarial_ml` and `explainability` (both in
  `KNOWN_CAPABILITIES`) at `import redsim.scanners`. `health_check` probes
  the `ml` extra by `find_spec` and launches `redsim.ml.sandbox_worker
  --help` under the real child env, never a model.
- `3ab9de7` opt-in `redsim.ml.attacks` entry-point discovery in
  `redsim/plugins.py` (`REDSIM_PLUGINS=1`, `REDSIM_PLUGINS_ALLOW`,
  `AttackAdapter` conformance, capability vocabulary, Ed25519 verifier).
  `load_ml_attack_plugins` registers into `ATTACKS` and never replaces a
  registered id. `c3868e5` makes `GET /v1/attacks` load the plugins once per
  process and return the discovery rows under `plugins`
  (`{"enabled": false}` when the gate is off, else `{"enabled": true,
  "rows": [...]}` with `status` `loaded | rejected | skipped`), and a loader
  failure is `503 ml_plugins_unavailable` with the reason.
- `35e71c7` then `a45a787` `tests/e2e/` harness (`conftest.py`,
  `harness.py`, `README.md`) and `test_harness_smoke.py`: every item under
  the directory is stamped `e2e` and skipped unless `REDSIM_E2E` is set.
  Real API, admission, eager Celery (propagate off), real sandbox child,
  real CLI over one autocommit sqlite connection with a mirror of the
  `ml_campaigns` table. `REDSIM_E2E_SANDBOX=child|inprocess`,
  `REDSIM_E2E_POSTGRES_URL` for the RLS lane, parent-side mocked Pythia
  toggle. The smoke file's 8 cases pass through the real child at
  `58461cc`.
- `7556b22` then `c3868e5` `redsim doctor [--api-mode] [--worker-mode]`
  rewritten around Pythia: no provider key anywhere, an informational
  Pythia block with the key redacted to prefix and length, the `ml` extra,
  sandbox child launch and assets manifest checks (required with
  `--worker-mode` or `REDSIM_DOCTOR_WORKER_MODE=1`, informational
  otherwise), the `ml-campaign` roster check. `--api-mode` keeps the DB,
  blob and OIDC probes. `redsim.yaml` and `redsim init` drop the
  provider-style `model` and write `task_models: {}`. `.env.example` is
  Pythia-only and documents every spec 20.3 ML variable.
- `aa9674e` audit chain timestamps canonicalised to the UTC `+00:00`
  isoformat on write and read (`canonical_ts`), so `PostgresAuditWriter`
  chains verify on sqlite and on Postgres in any session zone with old rows
  still verifiable and no migration. `redsim audit verify --run <id>` falls
  back to `<output_dir>/<id>/audit.jsonl`, and `--run-dir PATH` names an
  offline run directory or `.jsonl` file explicitly.
- `c3868e5` the sandbox child pins `REDSIM_ENV_FILE` to the absent
  `<work_dir>/no-env` and sets `REDSIM_DISABLE_LLM=1`
  (`_ALLOWED_REDSIM_KEYS` is `REDSIM_ML_ASSETS_DIR`, `REDSIM_PLUGINS`,
  `REDSIM_ENV_FILE`, `REDSIM_DISABLE_LLM`).
- `dd2bbd4` admission strips the grid-owned `eps` and `norm_l2` before
  validating and freezes only caller-supplied keys into `attack_params`
  (`_GRID_OWNED_PARAMS`), and decides applicability from the adapter's
  `modality:<domain>` capability tags rather than `AttackInfo.domain`.
  `58461cc` then admits a white-box attack on a gradient-free model when the
  adapter declares `surrogate_transfer` and the target declares a surrogate
  (PGD on `url_trees`), which the e2e smoke test had exposed as
  `422 attack_requires_gradients`.
- `39126ce` the `resnet18` fine-tune recipe: lr 3e-4 with cosine decay,
  random flip and reflect-pad crop augmentation, best-epoch selection on a
  per-class 10 percent validation slice held out of the training split (the
  evaluation split is never used for selection), every choice recorded in
  the manifest `training` block. `small_cnn` keeps its recipe.

### Wave 4 and Phase B waves B0 to B3 (2026-09-09)

- **Wave 4** (`3dda572..e73dea0`, on `main`): the three e2e files
  (`test_ml_campaigns.py`, `test_ml_verify_upload_reports.py`,
  `test_ml_governance.py`; 22 e2e cases with the smoke file), the CI fixes
  (`d8a9f15`: `python-multipart`, the `Sample` move, the `.trivyignore`
  baseline, lazy torch imports behind `build-assets`), `8eb8870` admission
  refuses a control or `fgsm` on the L2 grid and loads plugins idempotently,
  the v2.4 docs. Then `7706950` (the Phase B register and plan), #23
  (`10650da`), #24 (`b93d9a9`), #25 (`6cbb661`).
- **Wave B0** (`934838e..29db42c`, on `main`): the schema additions
  (above), migration `0011`, seven `Action` members and 23 codes,
  `tests/ml/test_schema_compat.py`, the extended API-process import block,
  the `garak` marker and pin with the `e2e-python` and `garak-offline` CI
  jobs, the 19 stubs, `redsim/ml/targets/endpoint_contract.py` and
  `redsim/ml/endpoint_egress.py`, `redsim/ml/atlas_data.py`, and the
  datasets in `redsim/ml/assets/datasets.py` (SMS Spam Collection fetch and
  split, WordNet fetch, the military-assets subset selection, the training
  slice writer, the public-repository index). Integration `29db42c` changed
  three tests only.
- **Wave B1** (eight commits, rebased onto `29db42c`, pushed with this
  pass): the library layer described under "ML vertical" above, plus the
  integration commit that closes the B0 reconciliation list (schema literals
  read directly, the contract and egress modules imported, endpoint errors
  re-exported from `redsim/ml/errors.py`, registration wiring,
  `expected_stages` and artifact kinds in the worker, the tenant reconciler
  over the `0010` and `0011` tables, `DatasetSource` `uci` / `github`,
  `build-assets --dataset text` / `--dataset detection`, `--attach-train-slice`
  and the training slice for the image builds, `redsim ml attack --norm
  edit|patch_area`). Integrated by `1439f92` (default tier 2257 passed, 35
  skipped, 1 deselected; `ml` tier 418 passed, 1 skipped; e2e 22 passed;
  mypy 220 files).
- **Wave B2** (eight track commits plus `fix: integrate Phase B wave B2
  tracks`, rebased onto `1439f92` and pushed with the B2 documentation pass; written in a
  worktree whose base predates the B1 integration): `api: add thirteen
  Phase B error codes; dataset.export to remediator` (`codes-b2`), `feat(ml):
  endpoint registration, validate via broker, projections`
  (`endpoint-admission`: `redsim/api/v1/models.py`,
  `redsim/services/ml_models.py`, `redsim/workers/tasks/ml_model.py`),
  `worker: endpoint broker lifecycle, derived-target registration, retests
  (Phase B B2)` (`worker-campaign-phase-b`: `redsim/workers/tasks/ml_campaign.py`),
  `admission(ml): modality table, norm checks, endpoint budget, project
  scoring` (`admission-phase-b`: `redsim/services/ml_campaigns.py`), `ml(llm):
  garak through Pythia core: catalog, generator, probe child, scorecard`
  (`llm-core`: `redsim/ml/llm/`), `feat(llm): probe routes, admission,
  worker, scorecard and findings` (`llm-api`: `redsim/api/v1/llm.py`,
  `redsim/services/ml_llm.py`, `redsim/workers/tasks/ml_llm.py`,
  `redsim/workers/celery_app.py`, `redsim/services/ml_findings.py`), `review:
  transition table, resolve gates, retest links, analyst drafts`
  (`review-workflow`: `redsim/services/finding_review.py`,
  `redsim/api/v1/ml_findings.py`), `reports: PDF projection, snapshots,
  N-run compare, weights API, idempotency` (`reports-compare-weights`:
  `redsim/ml/pdf.py`, `redsim/ml/pdf_fonts/`, `redsim/ml/compare.py`,
  `redsim/ml/reporting.py`, `redsim/services/reports.py`,
  `redsim/api/v1/{reports,compare,projects,batches}.py`,
  `redsim/api/middleware/idempotency.py`, `redsim/api/app.py`,
  `pyproject.toml`). The integration commit moved six test pins to the B2
  behaviour, taught `_endpoint_request_block` to read the URL from
  `Target.value`, and wrapped the `litellm` import in `redsim/llm/pricing.py`
  with an environment snapshot. Its checks before the rebase (worktree on
  `b404eb8`): ruff and mypy (236 files) clean, 251 passed and 1 xfailed in
  the writers' ten test files, the default tier 2431 passed, 36 skipped, 12
  deselected, 1 xfailed, 17 failed, all 17 present at that base and fixed on
  `main` by the B1 integration. The B2 integration pass (`fix: integrate Phase B wave B2`, pushed with the B2 commits) re-ran every tier on the rebased tree from the venv: ruff (CI selection) and `mypy redsim` (236 files) clean, the default tier 2480 passed, 35 skipped, 13 deselected, the `ml` tier 420 passed, 1 skipped, the 12 `garak`-marked tests green against the fake gateway, the e2e tier 22 passed against Postgres with the sandbox child, `mkdocs build --strict` exit 0.
- **Wave B3** (five track commits plus `fix: integrate Phase B wave B3
  tracks`, written in the worktree `wt/waveb3` on the B2 integration and
  rebased onto it, pushed with the B3 documentation pass): `feat(interop): Croissant/Parquet
  dataset export of a campaign run` (`interop-contribute`:
  `redsim/ml/interop/{__init__,parquet,croissant,card}.py`,
  `redsim/workers/tasks/dataset_export.py`,
  `redsim/services/ml_datasets_export.py`), `interop(consume): POST
  /v1/datasets static admission, sandboxed Parquet parse, binding hook`
  (`interop-consume`: `redsim/api/v1/datasets.py`,
  `redsim/services/ml_datasets.py`, `redsim/ml/interop/consume.py`,
  `redsim/workers/tasks/dataset_validate.py`), `bulk: batch campaigns,
  roll-up, cancel, compare groups, bulk verify` (`bulk-service-routes`:
  `redsim/services/ml_batches.py`, `redsim/api/v1/batches.py`,
  `redsim/ml/compare.py`, the `batch_id` mirror in `tests/e2e/harness.py` and
  `tests/ml/test_campaign_routes.py`), `feat(ml): bulk upload, per-project
  capacity/deferral, CLI attack matrix` (`bulk-upload-capacity-cli`:
  `redsim/api/v1/models_bulk.py`, `redsim/api/app.py`,
  `redsim/services/ml_capacity.py`, `redsim/workers/tasks/capacity.py`,
  `redsim/workers/celery_app.py`, `redsim/cli/ml.py`,
  `redsim/observability.py`), `interop(atlas,foundry): ATLAS stamp and
  coverage, Foundry push, roster` (`atlas-foundry`: `redsim/ml/atlas.py`,
  `redsim/integrations/{__init__,foundry}.py`,
  `redsim/workers/tasks/integration_push.py`,
  `redsim/api/v1/integrations.py`, `redsim/services/ml_findings.py` (one
  line: the stamp), `redsim/api/v1/attacks.py` (the ATLAS block),
  `tests/ml/fake_foundry_server.py`), and the integration commit (the three
  B3 task modules added to the Celery `include` list, the B0 export stub
  removed from `integrations.py` so the datasets router serves the path
  without a duplicate operation id, and `tests/ml/test_phase_b_stubs.py`
  rewritten as the surface pin). No frozen contract, error code, `Action`
  or migration changed. The B3 assembler's checks in its worktree (head
  `a780d88`, before the atlas-foundry and integration commits and the
  rebase): ruff and `mypy redsim` (253 files) clean, the six writers' test
  files 140 passed and 1 skipped, the surface pin 61 passed, the e2e smoke
  file 8 passed through the real child. Final counts at the B3 integration on the rebased tree (the reconcile pass, run from the repository root): `ruff check --select E4,E7,E9,F,I redsim tests` clean, `mypy redsim` clean (253 source files), the default tier `pytest -q -p no:cacheprovider --ignore=tests/e2e` 2634 passed, 35 skipped, 13 deselected (the `test_campaign_golden` artifact pin now excludes the Phase B export slices, `test_cli_ml` pins the `l2` default `pgd`; the `test_campaign` harden-hook and `test_datasets` synonyms failures of the B2 tree are not present), the `ml` tier 433 passed and 1 skipped, the `garak` tier 12 passed, the `e2e` tier against the compose Postgres 22 passed, `mkdocs build --strict` exit 0.
  The public data repository gained the first Croissant
  export sample at `0dababc` (`data/exports/url_trees_sample/`).
- **Wave B4** (four track commits written in `wt/waveb4` on the B3
  integration and rebased onto `703f8f6`, then the fix pass and this
  documentation pass, pushed together): `e2e(endpoint,llm): endpoint
  connector and garak LLM probe evidence on the shared harness`
  (`tests/e2e/test_ml_endpoint.py`, `test_ml_llm.py`), `e2e(text,detection,
  attacks,harden): modality, norm, ZOO and training-defense evidence`
  (`test_ml_text_detection.py`, `test_ml_attacks_harden.py`),
  `e2e(review,reports,interop,bulk): review workflow, PDF/snapshots, compare,
  Croissant, ATLAS, Foundry, batches, capacity, CLI matrix evidence`
  (`test_ml_review_reports.py`, `test_ml_interop.py`, `test_ml_bulk.py`),
  `ci(phase-b-gate): scripts/phase_b_gate.sh, make check-phase-b, CI jobs,
  docs consistency test`. The fix pass (`fix-api-services`: the capabilities
  roster read from the tree, the attacks tag filter, the `batch_id` overlay,
  `409 auth_profile_in_use`, the `FindingType` literals, the ATLAS stamp on
  drafts, the JWT redaction pattern, the third 17.3 addendum, the consumed-
  slice upload binding and loader, `.env.example` and compose;
  `fix-worker-runners`: the BULK-16 projection, single-run capacity, the
  four-format completion render and first snapshot, the text and detection
  export slices with the nullable `text` column, the forwarded artifact cap,
  the record-authoritative stage close, four e2e test-isolation fixes;
  `fix-gate-ci`: the garak step failing on exit 5 and on an all-skipped run,
  the worktree `PYTHONPATH` rule in the e2e step, the `garak` extra in the
  `e2e-python` lane, the docs-consistency test's stale-phrase heuristic). What
  the B4 files left open by attribution is in the README's open items.

## Assets and datasets (built locally, gitignored)

The catalog is decided (spec section 11 and plan 12 section 4): image demo
`leibnitz-lab/military_vehicles` (HF, MIT, coarse 7-class task, ground-level
photographs), image CI fixture `uoft-cs/cifar10`, tabular demo Kaggle
`sid321axn/malicious-urls-dataset` (CC0. URL strings are data and are never
fetched. A committed stratified sample serves CI), tabular fallback
`lacg030175/UNSW-NB15` (CC-BY-4.0, unused), and since Phase B wave B0 the
text demo UCI SMS Spam Collection (`uci:sms-spam-collection`, CC BY 4.0,
5,574 messages, published verbatim under owner default MODALITIES-12, a
300-row committed sample for CI), WordNet 3.0 from `nltk/nltk_data`
`550b6625` (WordNet licence, cached under `<assets>/cache/wordnet`, not
republished, a 47-entry JSON fixture for CI), the detection demo, a capped
seeded 300-image subset of Kaggle
`rawsi18/military-assets-dataset-12-classes-yolo8-format` (CC BY 4.0, four
vehicle and aircraft classes, person and weapon classes excluded by
construction, published for owner review under MODALITIES-27 and removable
in one commit), the `vehicles_cnn` training slice (1,536 rows, for the
training defenses) and ATLAS `v2026.08` (Apache-2.0, vendored constants).
Everything under `assets/` except `assets/README.md` is gitignored, so a
fresh clone has no assets until it runs `redsim ml build-assets`
(`--dataset all` builds image, cifar10, tabular and text; `--dataset
detection` is named explicitly because its input is the published subset). The Kaggle download reads `KAGGLE_API_TOKEN` (or
the older `KAGGLE_USERNAME` / `KAGGLE_KEY` pair) from the environment or the
`.env` file `REDSIM_ENV_FILE` names, and falls back to the committed sample
(marking the result `fixture_only`) when neither is set.

Clean accuracy and per-class counts are recorded in `assets/MANIFEST.json`
and are read from there by the UI and the reports. The local build of
2026-09-09 (illustrative, one laptop, never a product claim): `url_trees`
(scikit-learn HistGradientBoosting) clean accuracy 0.9087 on n=128224 eval
rows, surrogate agreement 0.7891. `vehicles_cnn` is now `resnet18` (ImageNet
init from the local torch hub cache, the `39126ce` recipe: fine-tune lr 3e-4
with cosine schedule, flip and crop augmentation, best epoch by a held-out
validation slice, 12 epochs) at 0.7687 on n=1621 `test_coarse`
images, up from 0.5151 with `small_cnn`. `cifar10_smallcnn` 0.6872 on the
10000-image test split, fixture only. Quote the manifest of the build in
hand, never these numbers, in anything user-facing.

The datasets are also published for other teams at
https://github.com/IntelliBridge/ai-red-teaming-data (public, spec 11.7,
head `4048a209` on 2026-09-09): the Phase A files, the SMS corpus and split,
the military-assets subset, the `data/garak/` copy with a per-subset licence
reference entry, the WordNet reference entry and an ATLAS release record,
with `INDEX.csv` and `MANIFEST.json`. `tests/ml/fixtures/public_index.csv`
snapshots that `INDEX.csv` and `tests/ml/test_datasets.py` checks every
code-named dataset has its rows. Its URL CSVs are redacted copies
(credential-shaped query values replaced with `REDACTED`, 0.36 percent of
rows), so their hashes differ from the manifest and metrics re-derived from
the public copy differ slightly; the SMS copy is verbatim and hashes to the
loader's pin.

## How to run things

- Python 3.12. The venv is `.venv`, created with uv, and has NO `pip`
  module. Run Python as `.venv/bin/python`. Install with
  `uv pip install --native-tls -e ".[api,worker,test,dev,ml]"`. uv is at
  `/opt/homebrew/bin/uv` and needs `--native-tls` behind the corporate TLS
  proxy. Never call `.venv/bin/pip`. Do not install packages while other
  agents share the venv.
- Extras in `pyproject.toml`: `api`, `worker`, `test`, `dev`, `security`,
  `docs`, `ml` (numpy, torch, torchvision, onnx, onnxruntime, scikit-learn,
  ART, onnx2torch, safetensors, SHAP, matplotlib, pillow, pyarrow, httpx),
  `llm` (optional private `pythia-sdk`. `redsim/llm/pythia.py` falls back to
  httpx), `garak` (Phase B only).
- Tests: `.venv/bin/python -m pytest -q -p no:cacheprovider`. The default
  `-m` from `addopts` excludes `docker`, `e2e`, `slow`, `auth_required` and
  (since wave B0) `garak`. `pytest -m ml` runs the tests that need the `ml`
  extra, `pytest -m integration` the sqlite or Postgres-backed ones,
  `pytest -m garak tests` the garak tier (needs the `garak` extra; skips
  without it; 12 tests under `tests/ml` plus the four e2e-gated cases of
  `tests/e2e/test_ml_llm.py`, all against the in-process fake gateway).
  `make check-phase-b` runs every tier in the gate's order. Tiers in
  `docs/dev/testing.md`.
- End-to-end tier: `REDSIM_E2E=1 .venv/bin/python -m pytest -q -m e2e
  tests/e2e` (the `ml`, `api` and `worker` extras, no network, no Docker).
  `REDSIM_E2E_POSTGRES_URL=postgresql+psycopg://...` (a migrated database)
  adds the Postgres RLS lane, which skips when unset and fails when the
  database is not migrated. `REDSIM_E2E_SANDBOX=inprocess` runs the campaign
  in process for debugging instead of in the real child. Files:
  `tests/e2e/test_harness_smoke.py` (wave 3, 8 cases), the
  completion-criteria evidence `tests/e2e/test_ml_campaigns.py`,
  `tests/e2e/test_ml_verify_upload_reports.py` and
  `tests/e2e/test_ml_governance.py` (wave 4, 22 cases with the smoke file) and
  the wave B4 files `test_ml_endpoint.py`, `test_ml_llm.py`,
  `test_ml_text_detection.py`, `test_ml_attacks_harden.py`,
  `test_ml_review_reports.py`, `test_ml_interop.py`, `test_ml_bulk.py`, run on
  every PR by the `e2e-python` CI job. From a git worktree export
  `PYTHONPATH=<worktree>` first (the gate's e2e step does it for you). See
  `tests/e2e/README.md`.
- Lint and types, exactly as CI runs them:
  `.venv/bin/ruff check --select E4,E7,E9,F,I redsim tests` and
  `.venv/bin/mypy redsim`. A bare `ruff check` applies ruff's much larger
  default set and is not the contract.
- Web: pnpm 10 workspace at the repo root. `pnpm --filter @redsim/web dev`
  (:3000), `pnpm --filter @redsim/web typecheck`, `pnpm --filter @redsim/web
  test` (vitest), `pnpm --filter @redsim/design-system typecheck`.
- Make targets: `install`, `require-install`, `dev` (pytest, then `dev-api`
  + `dev-web` under `make -j`), `dev-api` (`uvicorn redsim.api.app:create_app
  --factory --reload --port 8000`, boots without Postgres or Redis but only
  `/health`, `/docs` and `/metrics` work until they are up), `dev-web`,
  `dev-worker` (`celery -A redsim.workers.celery_app worker -Q scans,default`,
  needs Redis, Postgres and the `ml` extra, deliberately not on the `dev`
  line), `test`, `test-cov`, `lint`, `lint-py` (bare `ruff check`, wider than
  CI), `lint-web` (prints a skip line while `web/` has no ESLint config),
  `typecheck`, `typecheck-py`, `typecheck-web`, `check`, `up`, `down`,
  `docs-serve`, `docs-build`, `docs-build-strict`, `docs-clean` (call
  `mkdocs` from `PATH`, so activate the venv or pass
  `MKDOCS=.venv/bin/mkdocs`).
- Full stack: `make up` runs compose. `deploy/Makefile` has the finer helpers
  (`cd deploy && make seed` creates `default-org`, project `default` and user
  `admin`. `token-for`, `whoami`, `psql`, `logs`, `rebuild`, `down`,
  `down-clean`, `up-obs`). `REDSIM_AUTH_MODE=dev` dev tokens
  (`Bearer dev:<email>`, admin on project `default`) are allowed for the demo
  and refused when `REDSIM_ENV=prod`.

### Environment variables

Platform (`.env.example`): `REDSIM_MODE`, `REDSIM_API_URL`, `REDSIM_DB_URL`,
`REDSIM_BLOB_BACKEND` (`fs` | `s3`), `REDSIM_S3_*`, `REDSIM_AUTH_MODE`,
`REDSIM_ENV`, `REDSIM_OIDC_*`, `REDSIM_WORKER_SIGNING_KEY`,
`REDSIM_API_JWKS_CACHE_TTL_SECONDS`, `REDSIM_API_SESSION_PUBLIC_KEY_PREVIOUS`,
`REDSIM_AUTH_PROFILES_KEY_PREVIOUS`, `REDSIM_CORS_ORIGINS`,
`REDSIM_LLM_BUDGET_STRICT`, `REDSIM_BROKER_URL`, `REDSIM_RESULT_BACKEND`,
`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, `REDSIM_PLUGINS_SANDBOX`,
`REDSIM_PLUGIN_SANDBOX_*`, `REDSIM_DISABLE_LLM`, `REDSIM_E2E`,
`REDSIM_E2E_LIVE`, `REDSIM_PLUGINS`. Since `7556b22` `.env.example` holds no
provider key: the only LLM credential it names is `PYTHIA_API_KEY`, and it
documents every spec 20.3 ML variable below with empty values. Read by the
tools but not listed there: `REDSIM_DOCTOR_WORKER_MODE` (doctor),
`REDSIM_E2E_POSTGRES_URL` and `REDSIM_E2E_SANDBOX` (the e2e harness).

Pythia (spec 20.3, read on the worker): `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`,
`PYTHIA_PERSONA`, `PYTHIA_TIMEOUT_S`, `REDSIM_ML_LLM_MODEL` (deprecated
aliases `AEGIS_ML_LLM_MODEL`, `REDSIM_LLM_MODEL`), `REDSIM_ENV_FILE`,
`REDSIM_TLS_TRUSTSTORE`, `REDSIM_CA_BUNDLE`, `SSL_CERT_FILE`.

ML vertical (spec 20.3, all read by the code on this tree):
`REDSIM_ML_ASSETS_DIR` (default `./assets`), `REDSIM_ML_WORK_DIR`,
`REDSIM_ML_KEEP_WORK_DIR`, `REDSIM_ML_SANDBOX_TIMEOUT_S` (1200),
`REDSIM_ML_SANDBOX_CPU_SECONDS` (900), `REDSIM_ML_SANDBOX_MEMORY_MB` (4096),
`REDSIM_ML_SANDBOX_FILESIZE_MB` (1024), `REDSIM_ML_SANDBOX_THREADS` (2),
`REDSIM_ML_DATASET_CACHE`, `REDSIM_ML_UPLOAD_MAX_MB` (API, 512),
`REDSIM_ML_MAX_ADV_ARTIFACT_MB` (64), `REDSIM_ML_EXPLAIN_CACHE`,
`KAGGLE_API_TOKEN` (the one-off `build-assets` run only), and since wave B1
the endpoint broker limits read in the worker parent
`REDSIM_ML_ENDPOINT_RPS` (10), `REDSIM_ML_ENDPOINT_BATCH_ROWS` (32 image /
256 tabular, at most 1024), `REDSIM_ML_ENDPOINT_TIMEOUT_S` (30),
`REDSIM_ML_ENDPOINT_MAX_ROWS` (500000), `REDSIM_ML_ENDPOINT_MAX_REQUESTS`
(20000), and since wave B2 the probe knobs `REDSIM_LLM_PROBE_MAX_PROMPTS_PER_PROBE`
(64, the deployment cap on a request's `max_prompts_per_probe`),
`REDSIM_LLM_PROBE_MAX_RUNS_PER_PROJECT_PER_DAY` (10),
`REDSIM_LLM_PROBE_HF_DETECTORS` (truthy admits `detector_mode=hf`),
`REDSIM_LLM_PROBE_HF_CACHE`, `REDSIM_LLM_PROBE_TIMEOUT_S` (1500, the garak
child's wall clock, below the Celery soft limit) and `REDSIM_PDF_FONT_DIR`
(a directory holding both DejaVu faces, else the bundled subsets), and since
wave B3 the capacity, bulk and consume knobs
`REDSIM_ML_MAX_CONCURRENT_RUNS_PER_PROJECT` (2, the default for
`projects.ml_max_concurrent_runs`), `REDSIM_ML_DAILY_RUN_BUDGET` (alias
`REDSIM_ML_PROJECT_DAILY_RUN_BUDGET`; unset is uncapped),
`REDSIM_ML_BATCH_MAX_MEMBERS` (20), `REDSIM_ML_BULK_UPLOAD_MAX_FILES` (10),
`REDSIM_ML_BULK_UPLOAD_MAX_MB` (1024, buffered whole in the API process),
`REDSIM_ML_DATASET_UPLOAD_MAX_MB` (256), `REDSIM_ML_DATASET_MAX_ROWS`
(200000, enforced in the parse child), and the Foundry settings read from
the process environment only (never `.env`) by the API for presence and by
the default worker pool for the push: `REDSIM_INTEGRATION_FOUNDRY_URL` (unset
is disabled, the default), `REDSIM_INTEGRATION_FOUNDRY_NON_OPERATIONAL=1`
(the spec 27.3 operator attestation, required for `configured`),
`REDSIM_INTEGRATION_FOUNDRY_DATASET_RID` (an optional default target rid,
never a URL) and `REDSIM_INTEGRATION_FOUNDRY_TIMEOUT_S` (30). No Foundry
token variable exists: the bearer token is an `AuthProfile` named at push
time. Since wave B4 `.env.example` documents every endpoint, probe, capacity, bulk,
consume and Foundry variable with empty values and `deploy/docker-compose.yml`
passes the API caps to `redsim-api`, the worker-parent settings to the worker
anchor and the Foundry settings to `redsim-worker-default` only (INTEROP-29,
BULK-23); the sandbox child drops every `REDSIM_INTEGRATION_FOUNDRY_*` name
and receives `REDSIM_ML_MAX_ADV_ARTIFACT_MB` only when it is set to a positive
number. Tests only: `REDSIM_PUBLIC_DATA_CHECK=1`
runs the slow live check of the public data repository. There is no network
switch for the ML child: it
never receives network configuration; the child reaches an endpoint only
through the parent's broker socket, and the campaign frame pins `NLTK_DATA`
and `TORCH_HOME` offline for the run when they are unset.

## CLI (`redsim`, `redsim.cli:main`)

| Command | What it does |
|---|---|
| `redsim doctor [--api-mode] [--worker-mode]` | Environment checks around Pythia (`7556b22`, `c3868e5`): the mode line, an informational Pythia block with the key redacted to prefix and length, the `ml` extra with versions, a launch of `redsim.ml.sandbox_worker --help` under the real child env and rlimits, and the assets manifest verification. The three ML checks are required in worker mode (`--worker-mode` or `REDSIM_DOCTOR_WORKER_MODE=1`) and informational otherwise, and the `ml-campaign` roster is reported. `--api-mode` adds the Postgres, blob and OIDC probes. No provider key anywhere. |
| `redsim init` | Writes a default `redsim.yaml`. |
| `redsim status` | Mode, backends, connectivity. |
| `redsim scan <url> --scanner <name>` | Dispatches through the scanner registry. Exits 1 when no adapter of that name is registered. |
| `redsim findings`, `redsim verify`, `redsim report` | Filesystem run-state commands inherited from the platform. |
| `redsim audit verify [--run ID \| --project ID \| --all] [--run-dir PATH]` | Walks the chain(s) the configured writer holds (Postgres when `REDSIM_DB_URL` is set, else `<output_dir>/audit/*.jsonl`). `--run <id>` falls back to `<output_dir>/<id>/audit.jsonl` when the primary store has no events for that chain, and `--run-dir PATH` names an offline run directory or `.jsonl` file explicitly (`aa9674e`). An explicitly named chain with no events anywhere exits 1. |
| `redsim audit export [--all \| --chain ID] [--no-verify]` | WORM export (`REDSIM_WORM_EXPORT=1`). |
| `redsim tenants verify [--repair]` | Reconciles denormalized `org_id`. |
| `redsim plugins list [--json]`, `redsim plugins sign ...` | Third-party adapter discovery (`REDSIM_PLUGINS=1`) and Ed25519 signing. |
| `redsim ml build-assets [--dataset image\|tabular\|cifar10\|text\|detection\|all] [--only ID] [--epochs N] [--arch small_cnn\|resnet18] [--image-size N] [--seed N] [--out DIR] [--cache-dir DIR] [--max-train N] [--max-eval N] [--workers N] [--xgboost\|--no-xgboost] [--no-train-slice] [--train-slice-n N] [--attach-train-slice ID] [--detection-image-size N] [--detection-subset DIR] [--fixture [--fixture-out] [--fixture-sidecar] [--fixture-synthetic-ok]]` | Fetches the datasets by pinned revision, trains the bundled models on CPU with a fixed seed, writes `assets/MANIFEST.json` on `MLModelManifest` with dataset caveats and `subject_centered`. Since the wave B1 integration: `--dataset text` trains `sms_tfidf_lr`, `--dataset detection` trains `assets_frcnn_mnv3` from the published subset (named explicitly, never part of `all`), the image builds write `bundled/<model>/train_slice.npz` for the training defenses and `--attach-train-slice` records a slice drawn out-of-band. `--fixture` writes `tests/ml/fixtures/cifar10_test_500.npz` from local files only. Network access happens only here. |
| `redsim ml attack <target_id> [<target_id> ...] \| --matrix FILE.yaml [--fail-fast] [--attacks fgsm,pgd] [--eps ...] [--reference-eps] [--n-samples 200] [--seed 0] [--explain-k 8] [--no-control] [--norm linf\|l2\|edit\|patch_area] [--out DIR] [--assets-dir DIR] [--actor]` | Offline campaign for a bundled target with no database, no network and no Pythia, see Wave 3 (`3ab9de7`). Defaults: attacks `fgsm,pgd` with the noise control, the spec 12.3 grid for the norm, reference eps `0.03`, `--out` the config `output_dir`. Since the wave B1 integration a text target defaults to `word_substitution` on the `edit` grid `{0.1, 0.2, 0.3}` (reference 0.2) and a detection target to `dpatch` on the `patch_area` grid `{0.01, 0.03, 0.05}` (reference 0.03), once those assets are built. Since wave B3 several target ids, or `--matrix FILE.yaml` (`models` x `attack_sets` x `eps_grids` x `seeds`, with optional `norm`, `reference_eps`, `n_samples`, `explain_k`, `include_control`, `name`; the flags are the defaults for keys the file omits; the schema is printed by `--help`), run one `run_offline_campaign` per cell with its own run id, directory and hash-chained `audit.jsonl` verified with `verify_chain`, print a per-cell summary table (no mean, rank or aggregate), write `<out>/matrix-<id>/summary.json`, stop at the first refused or failed cell with `--fail-fast` and exit 1 when any cell was refused or failed. The single-target path is unchanged. |
| `redsim ml seed [--project] [--only IDS] [--assets-dir DIR] [--actor]` | Registers the bundled, non-fixture models into a project through `register_bundled_model`, audit-first, one commit per model, `already present` for a live duplicate, exit 1 on any other refusal (`3ab9de7`, `98a8733`). Needs `REDSIM_DB_URL`. |
| `redsim evidence-pack --out DIR [--project ID]` | Bundles audit and controls evidence. |
| `redsim migrate fs->pg --source DIR --project ID` | Filesystem run data into Postgres. |

## LLM access: Pythia only

Every LLM call goes through Pythia (`redsim/llm/pythia.py`). redsim's per-task
router (`redsim.llm.router.route`, task `ml.harden_narrative`) and the budget
checker stay the policy layer, Pythia is the only transport. No litellm, no
direct provider keys anywhere. `docs/ops/pythia.md` is the full runbook.
Since wave B2 there are two consumers: the hardening narrative below, and the
garak probe traffic of `redsim.ml_llm_probe_run`, which reaches
`{gateway}/v1/chat/completions` through `redsim.ml.llm.generator.PythiaGenerator`
with a probe key held in a bearer `AuthProfile` (never `PYTHIA_API_KEY`), a
persona declared per LLM target and a `guardrail_mode` that lands in the
scorecard limitations (owner default LLM-26: a separate persona and key,
never the narrative writer's). `assert_no_litellm` checks that garak's
litellm never enters the generator's MRO.

| Variable | Meaning |
|---|---|
| `PYTHIA_BASE_URL` | Gateway base URL, posts go to `{PYTHIA_BASE_URL}/v1/chat/completions`, the model list to `{PYTHIA_BASE_URL}/v1/models`. |
| `PYTHIA_API_KEY` | `pk_...` key sent as `Authorization: Bearer`. The only LLM secret redsim holds. |
| `PYTHIA_PERSONA` | Optional, sent as `X-Pythia-Persona`. |
| `PYTHIA_TIMEOUT_S` | Optional, default 60. |
| `REDSIM_ML_LLM_MODEL` | Canonical model id (`<vendor>/<model>` or `pythia/auto`). Seeds `config.task_models["ml.harden_narrative"]`. `AEGIS_ML_LLM_MODEL` and `REDSIM_LLM_MODEL` are read as deprecated aliases with a `DeprecationWarning`. |
| `REDSIM_ENV_FILE` | Path of the `.env` to read (default `./.env`, then the repo root). The client parses it itself. A process variable always wins over the file. |
| `REDSIM_TLS_TRUSTSTORE` | Default on: verify TLS against the OS trust store through `truststore`. `0` falls back to `REDSIM_CA_BUNDLE` or `SSL_CERT_FILE`, then certifi. |
| `REDSIM_DISABLE_LLM` | Truthy skips the narrative entirely (rules only). |

If any required variable is missing, `PythiaSettings.from_env()` returns
`None`, the recommendation keeps `narrative = None` and
`narrative_source = "rules"`, and the UI says "Narrative unavailable". Never
fake a narrative. The writer receives metrics and a SHAP text summary only,
never images, model bytes or dataset rows. The narrative runs in the worker
parent, never in the sandbox child, which holds no Pythia variables. `.env`
is gitignored and dockerignored, and the key is never logged
(`PythiaSettings.redacted()` is the only view that reaches provenance).

Behind the corporate TLS proxy (Zscaler) a plain httpx client fails with
`CERTIFICATE_VERIFY_FAILED`. The client's default truststore mode handles it
on a laptop, containers get the proxy root from `deploy/certs/`. Prove the
gateway before debugging narrative code:

```bash
.venv/bin/python -m redsim.llm.pythia_check              # reads ./.env
.venv/bin/python -m redsim.llm.pythia_check --skip-chat  # only GET /v1/models
```

Compose passes the Pythia variables through to `redsim-api` and the worker
pool with `${VAR:-}`. The worker anchor also sets `REDSIM_DISABLE_LLM: "1"`,
which has to be unset on `redsim-worker-default` before a compose stack can
produce a narrative.

## Accepted divergences from the spec

Recorded per the change protocol in `docs/plans/01-p0-contracts-api-skeleton.md`
section 8. Each is a knowing choice of the completion pass, not an oversight.

- One Celery job per campaign (`redsim.ml_campaign_run` runs load, sample,
  attacks, control, explain, score, recommend and report in one sandbox
  child) instead of the per-attack Celery chain of spec 10.3. The stage table
  and the audit vocabulary are unchanged.
- Shipped task names are `redsim.ml_campaign_run` and
  `redsim.ml_model_validate`. The spec's `attack.run`, `explain.run`,
  `harden.recommend`, `verify.replay` and `model.validate` remain the Job
  types and audit actions, not the Celery task names.
- Report artifacts are written with kinds `report.md` / `report.json` /
  `report.html` (the sink's spec 5.8 names). The legacy `ml.report_<ext>`
  kinds are still read by the report route.
- The `harden.execute` audit detail records token usage as
  `usage.prompt` / `usage.completion` rather than `prompt_tokens` /
  `completion_tokens`, because audit redaction blanks any key containing
  `token`.
- Worker audit rows carry actor `worker:<job.type>` with the requesting
  principal in `detail.requested_by`, instead of the admitting human as actor.
- A verify campaign whose score is partial is `inconclusive` and leaves the
  finding `open` (spec 6.4), rather than failing the job.
- Phase B (waves B0 to B4, recorded in `docs/architecture/ml-vertical.md`
  "Accepted divergences"): `defense_apply` sits after `load_target`, not at
  the end of `STAGES`; the endpoint contract is `endpoint-v1` with
  `{contract, input_format, inputs}`, not the register's
  `redsim-predict-proba/1` with an `encoding` key (the spec 17.3 addendum
  row for `endpoint_schema_mismatch` was corrected in wave B4); five stub
  paths follow the brief rather than the register; `DetectionMetrics` uses
  the brief's field names; image HopSkipJump is served by the Phase A adapter
  with `IMAGE_DEFAULTS` (spec 12.2); KernelSHAP for images is not built (spec
  13.2); distillation is native torch with ART's class cited (spec 16.5); the
  broker does not pin the connection to the resolved address (ENDPOINT-07
  risk note); no DNS-TXT ownership check for endpoints (spec 21.7, owner
  default ENDPOINT-26). Wave B2 closed the `dataset.export` divergence
  (`remediator` in all three policy files) and added: `query_budget_exceeded`
  is `429` (register ENDPOINT-06 wrote 422), `idempotency_key_reused` is
  `409` (REVIEW_REPORTS-32 wrote 422), `fixture_not_exportable` is `422`
  (INTEROP-03 wrote 409), REVIEW_REPORTS-32's `idempotency_in_flight` is
  `idempotency_conflict`; `PATCH /v1/findings/{id}/status` keeps the Phase A
  plain-string `forbidden` for the independence refusal while the
  `POST .../review` decisions emit the structured `reviewer_not_independent`;
  the detection `n_samples` cap is 200 (`DETECTION_N_SAMPLES_CAP`) rather
  than the register's wording. Wave B4 closed the B2 code and `FindingType`
  divergences (the third 17.3 addendum; `adversarial_llm` and
  `adversarial_ml_manual` in `redsim/schema.py`) and added: the `batch_id` of
  a run is an overlay on `GET /v1/runs/{id}/campaign` rather than a schema
  field (BULK-02); the export schema gained a nullable `text` column for
  text-modality slices (27.1); a PDF the renderer cannot typeset degrades to
  the text formats with `pdf_unavailable` recorded rather than failing the
  evidence job; the completion snapshot is version 1 and an on-demand render
  version 2 onwards (REVIEW_REPORTS-20); a training defense the child cannot
  apply is recorded unavailable with the score withheld and the verify run
  succeeds on the undefended model (spec 15.6 / 16.4, honest state until the
  bundled targets expose a training slice).

## Verified state (2026-09-09, `main` at `703f8f6` plus wave B4)

The counts of record are the B3 integration's on `main` at `703f8f6`, run
from the repository root with the venv interpreter and the `ml` extra:
`pytest -q -p no:cacheprovider --ignore=tests/e2e` 2634 passed, 35 skipped,
13 deselected; `pytest -q -m ml tests/ml` 433 passed, 1 skipped; `pytest -q
-m garak tests` 12 passed; the e2e tier against the compose Postgres 22
passed; `ruff check --select E4,E7,E9,F,I redsim tests` clean; `mypy redsim`
clean (253 files); `mkdocs build --strict` exit 0. The wave B4 tree adds the
seven e2e files and the gate; its counts are the B4 assembler's to record
with its commit. At the B4 push, read from the tree: ruff and `mypy redsim`
clean; `tests/test_docs_phase_b_consistency.py` passes after this
documentation pass; the default tier carries one stale pin
(`tests/ml/test_audit_campaign.py:113`, `formats` now includes `pdf`); the
e2e tier carries the attributed failures listed under Open items and two
stale report pins, so it is not green; `make check-phase-b` has not been run
against `make up`. The earlier counts below are kept as dated history. Re-run
before quoting anything.

- At `1439f92` (wave B1 integration, the last full run recorded on `main`):
  `.venv/bin/python -m pytest -q -x -p no:cacheprovider --ignore=tests/e2e`
  2257 passed, 35 skipped, 1 deselected (2:03); `pytest -q -m ml tests/ml`
  418 passed, 1 skipped; `REDSIM_E2E=1 REDSIM_E2E_POSTGRES_URL=... pytest -q
  -m e2e tests/e2e` 22 passed (2:30, Postgres at `localhost:5433`);
  `ruff check --select E4,E7,E9,F,I redsim tests` clean; `mypy redsim` clean
  (220 source files); `mkdocs build --strict` exit 0; the frozen fixture
  `tests/ml/fixtures/run_record.json` unchanged (sha256 `e5266f18…`, the
  tripwire pin). The Postgres-gated cases of `tests/test_migration_0011.py`
  and `tests/test_tenant_rls.py` skip without `REDSIM_DB_URL` and were not run
  locally.
- Wave B2 before its rebase (worktree on `b404eb8`, a base that predates the
  B1 integration commit): ruff clean, `mypy redsim` clean (236 source files),
  the writers' ten test files 251 passed and 1 xfailed (the endpoint
  real-child test, xfailed on the B1 broker defect the B1 integration fixed),
  the default tier without `-x` 2431 passed, 36 skipped, 12 deselected,
  1 xfailed, 17 failed, every one of the 17 present at that base
  (`tests/ml/test_endpoint_target.py` x10, `test_campaign`,
  `test_campaign_golden`, `test_datasets`, `test_detection_modality` x2,
  `test_text_modality` x2) and none added by B2; the 11 `garak`-marked tests
  passed with garak 0.16.0 against the fake gateway. The B2 integration pass (`fix: integrate Phase B wave B2`, pushed with the B2 commits) re-ran every tier on the rebased tree from the venv: ruff (CI selection) and `mypy redsim` (236 files) clean, the default tier 2480 passed, 35 skipped, 13 deselected, the `ml` tier 420 passed, 1 skipped, the 12 `garak`-marked tests green against the fake gateway, the e2e tier 22 passed against Postgres with the sandbox child, `mkdocs build --strict` exit 0.
- Wave B3 (the assembler's worktree `wt/waveb3` on the B2 integration, head
  `a780d88` before the atlas-foundry and integration commits and the rebase):
  `ruff check --select E4,E7,E9,F,I redsim tests` clean, `mypy redsim` clean
  (253 source files), the six writers' test files together 140 passed and 1
  skipped (the consume ld+json round trip, which needs a run with persisted
  slices), `tests/ml/test_phase_b_stubs.py` rewritten 61 passed, the
  `bulk-service-routes` writer's `REDSIM_E2E=1 tests/e2e/test_harness_smoke.py`
  8 passed through the real child with the `batch_id` mirror. The full
  default tier was run with `-x`: 395 passed then
  `tests/ml/test_campaign.py::test_training_defense_is_applied_through_the_harden_hook`
  failed (`defense_apply` in `stages_done`, the B1 runner-refactor `STAGES`
  pin; present at the base, no B3 diff on its files); with it deselected 402
  passed then
  `tests/ml/test_campaign_golden.py::test_refactored_campaign_matches_the_pre_refactor_record[image_verify_feature_squeezing]`
  failed (the same pin, the golden also lacks `report`); the top-level and
  route suites run as a targeted subset 426 passed, 8 subtests passed, 2
  deselected, 1 failed
  (`tests/ml/test_datasets.py::test_committed_synonyms_fixture_is_well_formed_and_cited`,
  `KeyError: 'schema_version'`). The three are pre-existing on the B2 tree
  and open: re-pin or regenerate them before the default tier can go green.
  No full-tier, `ml`, `garak` or `e2e` count exists for the rebased B3 tree,
  and `mkdocs build --strict` was run by this documentation pass only. The
  Aikido pre-commit hook passed every B3 commit: the JWT-shaped fake token of
  `tests/ml/fake_foundry_server.py` is assembled from three segments at
  import so no JWT literal sits in the source.
- Web vitest: last recorded 274 passed at `7240220`. Not re-run for this
  revision.
- Redsim CI: no run on `main` after `58461cc` has been read: not `e73dea0`
  (wave 4, which landed the three fixes for the `58461cc` failures), not
  `29db42c` (the first with the `e2e-python` and `garak-offline` jobs), not
  `1439f92`, `57da31f`, `703f8f6`, nor the wave B4 push (the first with the
  gate script in the two lanes, the `garak` extra in `e2e-python`, the 30
  minute e2e timeout and the exit-5 rule gone). The last run this file has
  read is `58461cc` (run 34307513075): red on the Coverage gate, Unit tests
  (py3.13) and Dependency CVEs, green on the rest. Do not claim green CI
  until a run on `main` is read; `docs/dev/ci.md` has the details. The last
  fully green run was `ea39f97` (#21).
- `Deploy to AWS` built and pushed the api, worker and web images to ECR
  under GitHub OIDC on the `58461cc` push and skips its deploy job while the
  repo variable `ECS_CLUSTER` is unset. `Docs` builds with `mkdocs build
  --strict`. Pages deploy is dormant behind the repo variable `ENABLE_PAGES`.
- Still stale outside the docs refresh: `docs/architecture/overview.md`
  (pentest sections), `CHANGELOG.md` (aegis release history),
  `web/components.json` (its `registry` points at the deleted
  `project_repos/shadcn-ui`), ADRs 0001, 0002 and 0004 (history, keep), and
  the v2 bodies of `docs/plans/06` and `08` under their banners.
  `docs/plans/EXECUTION-CONTEXT.md` and `docs/plans/07` were refreshed for
  the B4 tree; `docs/security/supply-chain.md` and `SECURITY.md` carry the
  garak paragraph.

## CI contract (`.github/workflows/redsim-ci.yml`)

- Lint: `ruff check --select E4,E7,E9,F,I redsim tests`. `pyproject.toml`
  only says `extend-select = ["I"]`. Ruff's default set is not the contract.
- Types: `mypy redsim` with the strict settings in `pyproject.toml`.
- Tests: 3.12 installs the `ml` extra (CPU torch first) and runs
  `-m "not integration and not docker and not e2e and not slow and not
  auth_required and not garak"`, 3.13 runs without the extra and adds
  `and not ml`. ML test modules must `pytest.importorskip` their heavy
  imports so collection survives on 3.13; `garak`-marked modules likewise.
- `E2E tier (python, eager Celery)` (job `e2e-python`, wave B0; through
  `scripts/phase_b_gate.sh --only e2e` then `--only docs-consistency` since
  wave B4): `REDSIM_E2E=1 pytest -q -p no:cacheprovider -rs -m e2e tests/e2e`
  against a migrated service Postgres passed as `REDSIM_E2E_POSTGRES_URL`, so
  the RLS lane runs and the step fails if the harness still reports the lane
  off; the `garak` extra installed for `tests/e2e/test_ml_llm.py`; 30 minute
  timeout, the harness directory uploaded on failure.
- `garak offline` (job `garak-offline`, wave B0): installs `.[garak]`
  (`garak>=0.16,<0.17`) on CPU torch, `import garak`, then
  `scripts/phase_b_gate.sh --only garak` (`pytest -q -p no:cacheprovider -m
  garak tests`) with no `PYTHIA_*` variable and the XDG dirs under the runner
  temp. Since wave B4 the step fails on pytest exit 5 (nothing collected), on
  a run in which no test passed and on a missing extra; the wave B0 rule that
  mapped exit 5 to success is gone from the script and the workflow. The lane
  collects the 12 tests of `tests/ml/test_llm_core.py` and
  `tests/ml/test_llm_routes.py`; `tests/e2e/test_ml_llm.py` is e2e-gated and
  runs in `e2e-python`, which installs the `garak` extra for it. Whether they
  pass on the runner is proven by a run after the B4 push, which has not
  been read.
- The default tier's wave B2 tests need `reportlab` (worker extra) and
  `pypdf` (test extra), both declared in B2; every lane installs those
  extras.
- Coverage gate: the full default suite against Postgres 16 and Redis 7 with
  `--cov-fail-under=81` (`COV_FAIL_UNDER`). Raise it in the PR that merges
  each ML phase, never lower it without recording why in `docs/dev/ci.md`.
- Also: API integration (Postgres + Redis, `not ml`), SAST (semgrep
  `p/python` + `p/security-audit` plus `.semgrep.yml`, bandit `-ll -ii`),
  dependency CVEs (`pip-audit --skip-editable`, trivy at HIGH,CRITICAL with
  `.trivyignore`), Helm lint plus template renders including the prod-secret
  guard, OTel config validation, trufflehog (verified secrets only),
  `redsim_output` not committed, the Next.js build (frozen lockfile,
  design-system and web typecheck, vitest, `next build`), the image builds
  (no push), and a Playwright stack E2E behind `workflow_dispatch` with
  `run_e2e=true` (never run as part of the completion pass).
- `docs.yml`: `mkdocs build --strict` on docs changes. Pages deploy off.
- `deploy-aws.yml`: builds api, worker and web images for ECR under GitHub
  OIDC on pushes to `main` that touch runtime paths, and rolls whichever
  `ECS_SERVICE_*` variables are set once `ECS_CLUSTER` is set (the deploy job
  is skipped until then). It does not run the test gates.

## Working rules for this codebase

- Read a file immediately before editing it and make surgical edits. Another
  agent may have touched it since your last read.
- Nothing under `redsim/ml/` may be presented as working until it runs. Show
  unimplemented paths as `not_implemented` with a reason and a `phase`, never
  with placeholder results. Fixture data (the CIFAR-10 slice, `TinyTarget`,
  `TinyTabularTarget`, the committed URL sample) is for tests only. Fixture-only
  targets are never listed, registered or attacked.
- The API process never imports torch, ART, onnxruntime or SHAP. Model bytes
  are opened only on the worker inside the sandbox child. The child receives
  no secrets, no proxy variables and no Pythia settings. The narrative runs in
  the worker parent.
- Every mutating route appends its audit event before writing `Run` / `Job`
  rows and before touching Celery (`tests/test_admission_audit_before_enqueue.py`
  asserts the order). Refusals write `success=False` rows first. Audit detail
  carries ids, digests and counts, never payloads, prompts or model bytes.
- Refusals use the codes in `redsim/api/errors.py`. Do not invent a code or
  spell one inline. Add it to the table with its HTTP status if the spec
  gains one.
- Measurements, observations, interpretation and candidate recommendations
  stay separate fields and separate panels. The `Literal` labels in
  `redsim/ml/schema.py` (`candidate`, `not evaluated`, `measured`,
  `inferred`, `heuristic`) are part of the contract.
- The MRI is per campaign and never shown without its subscores, the
  per-family table with denominators and the epsilon curve. No expected gain
  on a recommendation until verify measures it. No readiness, fielding,
  deployment or certification wording in any reading, label or doc.
- Numbers in docs are illustrative unless they come from the manifest or
  record in hand, and are labelled so. Never claim a completed run, a
  measured improvement or a validated fix that did not happen.
- P0 froze `redsim/ml/schema.py` (every field name and type), the migration
  head and the `ml_campaigns` column set, the `Action` values and minimum
  roles, the `GET /v1/runs/{id}/campaign` shape in
  `tests/ml/fixtures/run_record.json`, and the name `REDSIM_ML_LLM_MODEL`.
  Change protocol (`docs/plans/01`, section 8): never rename a field, column,
  `Action` or response key silently, announce a change as a one-line note in
  master plan section 5 plus a heads-up to the team, prefer an additive
  default-valued field over changing an existing one, and record accepted
  divergences (see above). Phase B wave B0 used the protocol once: additive
  default-valued schema fields, the head moved `0010_ml_vertical` to
  `0011_phase_b_platform`, seven new `Action` members, all announced in
  master plan sections 0 and 5, and `tests/ml/test_schema_compat.py` must
  stay green after any further schema change.

## Pre-commit hook (Aikido)

`git config core.hooksPath` points at `~/.git-hooks`, whose `pre-commit` runs
`aikido-local-scanner pre-commit-scan` on the repo. The restored aegis
redaction and guardrail test fixtures (for example `tests/test_otel_redaction.py`,
`tests/test_llm_guardrails.py`, `tests/test_audit_chain.py`,
`tests/test_evidence_pack.py`) contain deliberately fake secrets and trip the
scanner. Use `AIKIDO_SKIP_PRE_COMMIT=1 git commit ...` only for commits that
touch those fixtures, and say so in the commit message. Do not skip the hook
for anything else, and never add a real credential to make a test pass. A
new fake that has to match a token shape at runtime (the JWT-shaped
`DEFAULT_TOKEN` of `tests/ml/fake_foundry_server.py`, wave B3) is assembled
from segments at import so no literal trips the scanner and the hook passes
without a skip.

## Conventions

Commits are `type(topic): description` with the trailer
`Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Branch before
committing, never commit to `main` directly. The repository allows squash
merges only and deletes the branch on merge. Prose in docs and comments
avoids em dashes and semicolons. `docs/spec-driven-workflow.md` is the
spec-first process.

## Open items

The README section "Open items and not implemented" is the single list: the
web UI (the Phase B plan's one deferral, browser e2e included); the Phase B
items the wave B4 e2e files found and left open by attribution (the unscaled
endpoint probe in `redsim/ml/targets/endpoint.py`, no training slice exposed
to the child by the bundled targets so every training verify records the
defense unavailable, the worker-parent `materialize_consumed_slice` call for
consumed-bound models, `architecture_kwargs` not derived from the dataset
binding for `state_dict` uploads, the reportlab `LayoutError` on wide tables,
the three stale report pins, the recorded endpoint seams, INTEROP-07, -23,
-26 and the public-index fixture snapshot); the owner decisions of
`docs/plans/12-phase-b-plan.md` section 2 with their defaults; the
remaining-work brief's packages A to F (compose operations and the gate
against `make up`, CI parity, the process-gate documents that need named
human reviewers, residual Phase A rows, the Fargate runtime follow-ups, the
data-poisoning module); the recorded non-builds; and the unread CI runs.
Keep it and this file in step.
