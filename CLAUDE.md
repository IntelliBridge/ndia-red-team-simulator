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
It describes `main` at `1439f92` (2026-09-09: the four Phase A completion
waves, Phase B wave B0 and Phase B wave B1, the library layer) plus Phase B
wave B2, the services, workers and routes over that library, pushed to
`main` together with this documentation pass, verified from this tree and
marked "wave B2" where it is named. Phase B is planned in
`docs/plans/12-phase-b-plan.md` (five waves; B0, B1 and B2 landed, B3 and B4
not started, the 14 wave B3 routes still `501` stubs until B3 replaces them).

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

## What is on the tree (`main` at `1439f92` plus wave B2)

Verified by importing the app and reading its OpenAPI document, importing the
ML registries and reading the routers, services, tasks and tests of the wave
B2 commits.

### API process (`redsim.api.app:create_app()`)

`create_app()` mounts `health`, `ml_capabilities`, `attacks`, `datasets`,
`defenses`, `models`, `artifacts`, `compare`, `ml_findings`, `runs`,
`runs_cancel`, `findings`, `audit`, `reports`, `scanners`, `verify`,
`targets`, `auth_profiles`, `projects`, `logs`, `org_cost`, the Phase B
routers `batches`, `llm`, `integrations` (plus two rows in `datasets`), and
the WebSocket router, with the `IdempotencyMiddleware` (wave B2) added
innermost inside the tenant scope: 69 HTTP routes under `/v1` (39 Phase A,
16 built by wave B2 of which five replaced B0 stubs and eleven are new paths,
14 Phase B stubs left for wave B3), plus `GET /health`, `/metrics`,
`GET /v1/__settings` and `/docs` outside prod, and `WS /v1/runs/{id}/events`.
`POST /v1/scans` was unmounted by P0 and answers 404.

| Group | Routes |
|---|---|
| ML catalog | `GET /v1/ml/capabilities` (secret-free roster, `sandbox_enabled` always true; at the B2 push it still reports `text`, `detection`, `llm` and `endpoint_connector` as `not_implemented`, which admission no longer is: open item), `GET /v1/attacks` (`?modality=` filters on `AttackInfo.domain`, plus a `plugins` block with the opt-in `redsim.ml.attacks` discovery rows, `c3868e5`), `GET /v1/datasets` (rows from `assets/MANIFEST.json`, says so when no manifest is built), `GET /v1/defenses` (five rows; since the B2 integration each row's `phase` and `status` come from its catalog entry, so the training defenses say `phase: "B"`) |
| Models | `GET /v1/models` (registered targets including `ml_model_endpoint` rows with a credential-free `endpoint` block, unregistered bundled entries, the LLM domain as a `not_implemented` row. Fixture-only targets never listed), `GET /v1/models/{id}` (with `campaign_history` and, for an endpoint, `validation.probe`), `POST /v1/models` (`source: bundled` through `register_bundled_model`, `source: upload` with the static checks of spec 9.3, and since wave B2 `source: endpoint`: gated on `target.manage` (admin) before any field is read, `EndpointRegistration` plus the static egress check, the `model.register` row with `allowlist_check`, a `Target` of kind `ml_model_endpoint` in `status: validating`, then `redsim.ml_model_validate` probes it through the worker-parent broker; `endpoint_kind: llm` hands off to `services.ml_llm.register_llm_target`, which needs a canonical Pythia `model_id`, `persona`, `guardrail_mode` and a bearer `AuthProfile` and writes an `available` LLM target; any other `endpoint_kind` is `501`), `DELETE /v1/models/{id}` (audited soft delete, blob dropped, row kept for history; an endpoint row keeps `status: deleted` with host and profile id in the detail) |
| Campaigns | `POST /v1/models/{id}/attacks` (202 JobHandle, optional `parent_run_id` rerun of a failed or cancelled parent; since wave B2 admitted for `image`, `tabular`, `text` and `detection` through `SUPPORTED_MODALITIES` with per-modality norms and default grids, the adapter norm check, the detection `n_samples` cap of 200, the endpoint query budget and the project scoring weights), `GET /v1/runs/{id}/campaign`, `GET /v1/runs/{id}/compare?with=` (variable-level `409 incompatible_campaigns`, `409 score_unavailable` when `mri` is null, `mode: verify_delta` or `side_by_side`, `non_default_weights` since B2), `GET /v1/runs/compare?ids=a,b,c` (wave B2: 2 to 10 runs, request order, no mean or rank, a delta only on a verify row whose baseline is in the set), `PATCH /v1/runs/{id}/reviewer-notes`, `GET /v1/runs/{id}/artifacts`, `GET /v1/artifacts/{id}`, `GET /v1/runs/{id}/report.{md,json,html,pdf}` (newest non-archived snapshot's artifact, then the newest artifact row, digest-checked; `?snapshot=<id|version>`; `report.pdf` is `404 report not yet rendered` until a `report.render` produced it), `POST /v1/runs/{id}/report.render` (wave B2, `report.render` gate, `{formats?}`, 202, one immutable `report_snapshots` row per render), `GET /v1/runs/{id}/snapshots`, `GET .../snapshots/{ref}` (`409 snapshot_archived` for a non-admin), `POST .../snapshots/{ref}/archive` and `/restore` (`target.manage`, audited, bytes never deleted) |
| Findings | `GET /v1/findings` (since B2 with `status`, `review_state` and `source_tool` filters and a review summary per row), `GET /v1/findings/{id}`, `POST /v1/findings/{id}/explain`, `POST /v1/findings/{id}/harden`, `POST /v1/findings/{id}/verify` (since B2 also the training defenses on image targets with a torch module), `PATCH /v1/findings/{id}/status` (`false_positive` = dismiss, `open` = reopen, or a `decision`; the Phase A dismissal rules and codes byte for byte), and the wave B2 review workflow: `POST /v1/findings/{id}/review/{transition}` and `POST /v1/findings/{id}/review` with `decision` in the body (`submit`, `confirm`, `request_changes`, `dismiss`, `reopen`, `resolve` over `services.finding_review.TRANSITIONS`; `finding.review` for verdicts, `finding.author` for submit; independence by identity with `403 reviewer_not_independent`; compare-and-set on `expected_status` and `expected_review_state` with `409 review_state_conflict`; `resolve` refused with `409 resolution_blocked` and the unmet list until `poc_passed`, `fixed`, `confirmed` and a linked retest at the baseline's `settings_hash` hold), `GET /v1/findings/{id}/retests`, analyst drafts `POST /v1/findings` (201, `finding.author`, evidence ids checked against the digest-verified run record) and `PATCH /v1/findings/{id}/draft` |
| Runs and platform | `GET /v1/runs`, `GET /v1/runs/{id}`, `POST /v1/runs/{id}/cancel` (`409 run_terminal`), `GET /v1/audit/verify` (`?run=` resolves the project through run access, `?project_id=`, `?all=1` returns `{chains: [...]}`), `GET/POST/DELETE /v1/targets` (ML kinds are refused with `400 use_models_route`), `GET /v1/targets/{id}/verification` and `POST /v1/targets/{id}/verify` (501, pentest-era ownership check), `GET/POST/DELETE /v1/auth-profiles`, `GET /v1/projects`, `GET /v1/projects/{slug}/membership`, `PUT /v1/projects/{slug}/settings`, `GET /v1/projects/{slug}/ml-scoring` and `PUT /v1/projects/{slug}/ml-scoring` (wave B2: the effective `ScoringConfig` with `source` `project` or `default`; the `PUT` is `target.manage`, takes the full block or `null`, validates through `ScoringConfig` and never renormalises, audited as `project.settings`), `GET /v1/logs`, `GET /v1/orgs/{org_id}/cost`, `GET /v1/scanners` (one adapter, `ml-campaign`, registered when `redsim.scanners` is imported, `3ab9de7`) |
| LLM probes (wave B2, `llm-api`) | `GET /v1/llm/probes` (authenticated; the committed catalog with the `redsim-core` and opt-in `redsim-extended` sets, per-probe `offline` / `extended` / `excluded` status with reasons, the prompt cap; `501` with the reason on a tree without `redsim/ml/llm/catalog.json`), `POST /v1/models/{id}/probes` (membership, `llm.probe.run`; body `probe_set` or `probe_ids`, `max_prompts_per_probe` 1 to 64 default 16, `seed`, `detector_mode` `offline` or `hf`, `finding_hit_threshold` default 0.2; `409 llm_target_required` for a classifier target, `422 probe_key_required`, `422 probe_set_unknown`, `409 job_in_flight`, `429` daily quota with `retry_after`; the `llm.probe.run` row, then a `Run` with `scanner ml.llm_probe` and a `Job` of type `llm.probe`, then the enqueue on `redsim.ml_llm_probe_run`; 202 with `scorecard_url`), `GET /v1/runs/{id}/llm-scorecard` (the digest-checked `ml.llm.scorecard` artifact; `409 score_unavailable` while the run is not terminal). `/campaign` and `/compare` refuse a probe run with `409 llm_target_required` |
| Phase B, 501 until built (wave B0, `0b0981b`; 14 rows left after wave B2) | Routes mounted behind the lookup, membership and role gates their real handlers will run, then `501 not_implemented` with `phase: "B"` and a `reason` naming the wave and track that builds them; no row, audit event, job or artifact is written. `POST /v1/runs/{id}/dataset`, `GET /v1/datasets/{id}`, `POST /v1/datasets` (B3 interop), `GET /v1/runs/{id}/atlas-coverage`, `POST /v1/runs/{id}/integrations/foundry`, `GET /v1/integrations` (B3 atlas-foundry), `POST/GET /v1/campaigns/batch`, `GET /v1/campaigns/batch/{id}`, `GET .../{id}/compare`, `POST .../{id}/cancel`, `POST /v1/models/bulk`, `POST /v1/findings/{id}/verify/bulk`, `GET /v1/ml/capacity` (B3 bulk). The five B2 rows (`GET /v1/llm/probes`, `POST /v1/models/{id}/probes`, `GET /v1/runs/{id}/llm-scorecard`, `POST /v1/runs/{id}/report.render`, `GET /v1/runs/{id}/snapshots`) left `STUBS` in `tests/ml/test_phase_b_stubs.py` and stay in its `OPENAPI_PATHS`. Full table in `docs/api/v1.md` |

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
refuses a code that exists on one side only). Codes the wave B2 routes need
but the table lacks (`attestation_required`, `scoring_weights_invalid`, the
LLM-12 set `unknown_probe`, `probe_excluded`, `probe_detector_unavailable`,
`model_id_invalid`, `model_not_chat`, `gateway_url_required`,
`llm_probe_quota_exceeded`) are resolved with `getattr` and fall back to a
documented neighbour (`license_required`, `params_out_of_range`,
`probe_set_unknown`, `rate_limited`). Services raise `ApiError`, the route
converts it. Nothing parses exception text.

`tests/test_api_process_has_no_ml.py` builds the app in a subprocess with
`torch`, `torchvision`, `art`, `onnx`, `onnxruntime`, `shap`, `sklearn`,
`xgboost` and (since wave B0) `garak`, `openai`, `litellm`, `reportlab`,
`pyarrow` and `mlcroissant` blocked and asserts it still serves `/health`; it
also builds the sandbox child environment with low-entropy fake credentials
in the parent and asserts none survives. The catalog registries are imported
lazily. When one cannot be imported the route answers
`503 ml_catalog_unavailable`, never an empty list.

### Worker (`redsim.workers.celery_app`)

Nine tasks. `redsim.scan_start`, `redsim.verify_replay`,
`redsim.ml_campaign_run` and `redsim.ml_model_validate` route to the `scans`
queue. `redsim.report_render`, `redsim.reap_stale_jobs`,
`redsim.verify_tenant_integrity`, `redsim.export_chains_to_worm` and, since
wave B2, `redsim.ml_llm_probe_run` (the garak probe run, on the one pool with
Pythia egress) to `default`. Beat runs the reaper every 5 minutes (it also rolls the run status
up), tenant integrity hourly, WORM export on `REDSIM_WORM_INTERVAL`. Soft time
limit 1800 s, hard 2100 s. `worker_init` and `worker_process_init` configure
OTel, structlog and the log shipper (env-gated, idempotent per process).

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
  `ml.control_slice` for the persisted slices. The completion path still
  renders `report.md`, `report.json` and `report.html` and writes no
  `report_snapshots` row (the PDF and the first snapshot come from
  `POST /v1/runs/{id}/report.render`, open item).
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
  `RemediationAttempt` row and the `verify.execute` audit row.
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
and the e2e harness and campaign-route tests keep sqlite mirrors that still
need `batch_id`, a wave B3 item). `tests/test_migration_0011.py` and
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
`runs`, `scans`, `targets`, `verify`, `auth_profiles`, `evidence`, and since
wave B2 `ml_llm` and `finding_review`), `redsim/scanners` (registry,
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
`non_default_weights`), `llm/` (wave B2, worker and tests only: `catalog.py`
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
usage blocks, failure switches, a low-entropy fake token), `fixtures/` (`run_record.json`,
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

### Wave 4 and Phase B waves B0 to B2 (2026-09-09)

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
  tracks`, rebased onto `1439f92` and pushed with this pass; written in a
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
  without it; since wave B2 it holds 11 tests that run garak 0.16.0 against
  the in-process fake gateway). Tiers in `docs/dev/testing.md`.
- End-to-end tier: `REDSIM_E2E=1 .venv/bin/python -m pytest -q -m e2e
  tests/e2e` (the `ml`, `api` and `worker` extras, no network, no Docker).
  `REDSIM_E2E_POSTGRES_URL=postgresql+psycopg://...` (a migrated database)
  adds the Postgres RLS lane, which skips when unset and fails when the
  database is not migrated. `REDSIM_E2E_SANDBOX=inprocess` runs the campaign
  in process for debugging instead of in the real child. Files:
  `tests/e2e/test_harness_smoke.py` (wave 3, 8 cases) and the
  completion-criteria evidence `tests/e2e/test_ml_campaigns.py`,
  `tests/e2e/test_ml_verify_upload_reports.py` and
  `tests/e2e/test_ml_governance.py` (wave 4), 22 cases in all, run on every
  PR by the `e2e-python` CI job since wave B0. See `tests/e2e/README.md`.
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
(a directory holding both DejaVu faces, else the bundled subsets). Tests
only: `REDSIM_PUBLIC_DATA_CHECK=1` runs the slow live check of the public
data repository. There is no network switch for the ML child: it
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
| `redsim ml attack <target_id> [--attacks fgsm,pgd] [--eps ...] [--reference-eps] [--n-samples 200] [--seed 0] [--explain-k 8] [--no-control] [--norm linf\|l2\|edit\|patch_area] [--out DIR] [--assets-dir DIR] [--actor]` | Offline campaign for a bundled target with no database, no network and no Pythia, see Wave 3 (`3ab9de7`). Defaults: attacks `fgsm,pgd` with the noise control, the spec 12.3 grid for the norm, reference eps `0.03`, `--out` the config `output_dir`. Since the wave B1 integration a text target defaults to `word_substitution` on the `edit` grid `{0.1, 0.2, 0.3}` (reference 0.2) and a detection target to `dpatch` on the `patch_area` grid `{0.01, 0.03, 0.05}` (reference 0.03), once those assets are built. |
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
- Phase B (waves B0 to B2, recorded in `docs/architecture/ml-vertical.md`
  "Accepted divergences"): `defense_apply` sits after `load_target`, not at
  the end of `STAGES`; the endpoint contract is `endpoint-v1` with
  `{contract, input_format, inputs}`, not the register's
  `redsim-predict-proba/1` with an `encoding` key (the spec 17.3 addendum
  row for `endpoint_schema_mismatch` still says the old name); five stub
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
  than the register's wording; `SCORING_WEIGHTS_INVALID` and
  `ATTESTATION_REQUIRED` have no table row, so the weights `PUT` refuses
  with `params_out_of_range` (`field: ml_scoring.weights`) and a missing
  attestation with `license_required` (`field:
  evaluation_instance_attestation`).

## Verified state (2026-09-09, `main` at `1439f92` plus wave B2)

Counts come from the wave B1 integration run on `main` and the wave B2
assembler's worktree run, both with the venv interpreter and the `ml` extra.
Re-run them before quoting them.

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
- Web vitest: last recorded 274 passed at `7240220`. Not re-run for this
  revision.
- Redsim CI: the runs for the `29db42c` push (the first with the
  `e2e-python` and `garak-offline` jobs) and the `1439f92` push (wave B1) had
  not been read when this file was written, the B2 push had not happened, and
  neither had the runs for `e73dea0` (wave 4, which landed the three fixes for
  the `58461cc` failures: `python-multipart`, the import cycle, the trivy
  baseline and the lazy torch imports), `7706950`, `6cbb661` been read. The
  last run this file has read is `58461cc` (run 34307513075): red on the
  Coverage gate, Unit tests (py3.13) and Dependency CVEs, green on the rest,
  with API integration, the Next.js build and the image builds skipped behind
  the unit lane. Do not claim green CI until a run on `main` is read; the
  details of each failure and fix are in `docs/dev/ci.md`. The last fully
  green run was `ea39f97` (#21).
- `Deploy to AWS` built and pushed the api, worker and web images to ECR
  under GitHub OIDC on the `58461cc` push and skips its deploy job while the
  repo variable `ECS_CLUSTER` is unset. `Docs` builds with `mkdocs build
  --strict`. Pages deploy is dormant behind the repo variable `ENABLE_PAGES`.
- Still stale outside the docs refresh: `docs/architecture/overview.md`
  (pentest sections), `CHANGELOG.md` (aegis release history),
  `docs/security/supply-chain.md` (points at `examples/redsim-plugin-example`,
  not in this tree; the garak supply-chain paragraph is a wave B4 item),
  `web/components.json` (its `registry` points at the deleted
  `project_repos/shadcn-ui`), ADRs 0001, 0002 and 0004 (history, keep), and
  `docs/plans/EXECUTION-CONTEXT.md` (refreshed for wave 3, not for Phase B).

## CI contract (`.github/workflows/redsim-ci.yml`)

- Lint: `ruff check --select E4,E7,E9,F,I redsim tests`. `pyproject.toml`
  only says `extend-select = ["I"]`. Ruff's default set is not the contract.
- Types: `mypy redsim` with the strict settings in `pyproject.toml`.
- Tests: 3.12 installs the `ml` extra (CPU torch first) and runs
  `-m "not integration and not docker and not e2e and not slow and not
  auth_required and not garak"`, 3.13 runs without the extra and adds
  `and not ml`. ML test modules must `pytest.importorskip` their heavy
  imports so collection survives on 3.13; `garak`-marked modules likewise.
- `E2E tier (python, eager Celery)` (job `e2e-python`, wave B0): `REDSIM_E2E=1
  pytest -q -p no:cacheprovider -m e2e tests/e2e --durations=15` against a
  migrated service Postgres passed as `REDSIM_E2E_POSTGRES_URL`, so the RLS
  lane runs; 20 minute timeout, the harness directory uploaded on failure.
- `garak offline` (job `garak-offline`, wave B0): installs `.[garak]`
  (`garak>=0.16,<0.17`) on CPU torch, `import garak`, then `pytest -q -p
  no:cacheprovider -m garak tests` with no `PYTHIA_*` variable and the XDG
  dirs under the runner temp. The workflow still maps exit 5 (nothing
  collected) to success with a `::notice::` line; since wave B2 the lane
  collects 12 tests (`tests/ml/test_llm_core.py`, `tests/ml/test_llm_routes.py`)
  that drive garak against an in-process fake gateway, and whether they pass
  on the runner is proven by the first run after the B2 push. Any other
  non-zero exit fails.
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
for anything else, and never add a real credential to make a test pass.

## Conventions

Commits are `type(topic): description` with the trailer
`Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Branch before
committing, never commit to `main` directly. The repository allows squash
merges only and deletes the branch on merge. Prose in docs and comments
avoids em dashes and semicolons. `docs/spec-driven-workflow.md` is the
spec-first process.

## Open items

The README section "Open items and not implemented" is the single list: the
web UI (the Phase B plan's one deferral, browser e2e included), Phase B
waves B3 and B4 (the 14 remaining `501` stubs, no e2e evidence for anything
B2 built, no `make check-phase-b` gate), the wave B2 follow-ups read from the
tree (the capabilities roster and the attacks filter not updated, the
defenses route stamping `phase: "A"`, the campaign completion path writing
three formats and no snapshot, the codes still off the 17.3 table,
`FindingType` without the LLM and manual literals, `auth_profile_in_use` not
emitted, ENDPOINT-30), the owner decisions of
`docs/plans/12-phase-b-plan.md` section 2 with their defaults, the
remaining-work brief's packages A to F (compose operations, CI parity, the
process-gate documents that need named human reviewers, residual Phase A
rows, the Fargate runtime follow-ups, the data-poisoning module), the
recorded non-builds, and the unread CI runs for `29db42c` and `1439f92`.
Keep it and this file in step.
