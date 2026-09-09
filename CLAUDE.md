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
It describes `main` at `bb43bd7` (2026-09-08, waves 1 and 2 of the completion
plan merged). Wave 3 is landing on `main` in parallel. Its items are marked
"(wave 3, landing 2026-09-09)" and were read from the wave-3 branch, not from
this tree. Re-verify anything marked that way before building on it.

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
   corrected shared contracts) plus the phase files `docs/plans/01-…` to
   `08-…` and `docs/plans/09-gap-register-2026-09-08.md`, the 560-item
   spec-versus-tree register that drives the four completion waves. Section 8
   of `docs/plans/01-p0-contracts-api-skeleton.md` is the change protocol for
   everything P0 froze and the place divergences are recorded.
5. `docs/architecture/*`. `auth.md`, `audit-chain.md`, `multi-tenancy.md`,
   `observability.md` describe the platform, `ml-vertical.md` the vertical,
   `diagrams/` the current pictures. `overview.md` still carries pentest-era
   sections that no longer exist.
6. `docs/ops/pythia.md` for the LLM gateway, `docs/dev/ci.md` for the CI
   contract, `docs/api/v1.md` for the mounted routes.

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

## What is on the tree (`main` at `bb43bd7`)

Verified by importing the app and listing the router objects, importing the ML
registries and running the suite with the venv interpreter.

### API process (`redsim.api.app:create_app()`)

`create_app()` mounts `health`, `ml_capabilities`, `attacks`, `datasets`,
`defenses`, `models`, `artifacts`, `compare`, `ml_findings`, `runs`,
`runs_cancel`, `findings`, `audit`, `reports`, `scanners`, `verify`,
`targets`, `auth_profiles`, `projects`, `logs`, `org_cost` and the WebSocket
router: 39 HTTP routes under `/v1`, plus `GET /health`, `/metrics`,
`GET /v1/__settings` and `/docs` outside prod, and `WS /v1/runs/{id}/events`.
`POST /v1/scans` was unmounted by P0 and answers 404.

| Group | Routes |
|---|---|
| ML catalog | `GET /v1/ml/capabilities` (secret-free roster, `sandbox_enabled` always true), `GET /v1/attacks` (`?modality=`), `GET /v1/datasets` (rows from `assets/MANIFEST.json`, says so when no manifest is built), `GET /v1/defenses` |
| Models | `GET /v1/models` (registered targets, unregistered bundled entries, the LLM domain as a `not_implemented` row. Fixture-only targets never listed), `GET /v1/models/{id}` (with `campaign_history`), `POST /v1/models` (`source: bundled` through `register_bundled_model`, `source: upload` with the static checks of spec 9.3, `source: endpoint` answers `501 not_implemented` with `phase`), `DELETE /v1/models/{id}` (audited soft delete, blob dropped, row kept for history) |
| Campaigns | `POST /v1/models/{id}/attacks` (202 JobHandle, optional `parent_run_id` rerun of a failed or cancelled parent), `GET /v1/runs/{id}/campaign`, `GET /v1/runs/{id}/compare?with=` (variable-level `409 incompatible_campaigns`, `409 score_unavailable` when `mri` is null, `mode: verify_delta` or `side_by_side`), `PATCH /v1/runs/{id}/reviewer-notes`, `GET /v1/runs/{id}/artifacts`, `GET /v1/artifacts/{id}`, `GET /v1/runs/{id}/report.{md,json,html}` (newest Artifact row, digest-checked. `report.pdf` answers `501 not_implemented`, Phase B) |
| Findings | `GET /v1/findings`, `GET /v1/findings/{id}`, `POST /v1/findings/{id}/explain`, `POST /v1/findings/{id}/harden`, `POST /v1/findings/{id}/verify`, `PATCH /v1/findings/{id}/status` (dismissal only: `finding.review`, approver tier, campaign creator and system principals refused with 403, source status `open` or `failed` only, non-empty reason, audit row before the write) |
| Runs and platform | `GET /v1/runs`, `GET /v1/runs/{id}`, `POST /v1/runs/{id}/cancel` (`409 run_terminal`), `GET /v1/audit/verify` (`?run=` resolves the project through run access, `?project_id=`, `?all=1` returns `{chains: [...]}`), `GET/POST/DELETE /v1/targets` (ML kinds are refused with `400 use_models_route`), `GET /v1/targets/{id}/verification` and `POST /v1/targets/{id}/verify` (501, pentest-era ownership check), `GET/POST/DELETE /v1/auth-profiles`, `GET /v1/projects`, `GET /v1/projects/{slug}/membership`, `PUT /v1/projects/{slug}/settings`, `GET /v1/logs`, `GET /v1/orgs/{org_id}/cost`, `GET /v1/scanners` (empty roster at `bb43bd7`. Wave 3 registers `ml-campaign`) |

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
`rate_limited`, `db_unavailable` keep the retained routes' string detail).
Services raise `ApiError`, the route converts it. Nothing parses exception
text.

`tests/test_api_process_has_no_ml.py` builds the app in a subprocess with
`torch`, `torchvision`, `art`, `onnx`, `onnxruntime`, `shap`, `sklearn` and
`xgboost` blocked and asserts it still serves `/health`. The catalog
registries are imported lazily. When one cannot be imported the route answers
`503 ml_catalog_unavailable`, never an empty list.

### Worker (`redsim.workers.celery_app`)

Eight tasks. `redsim.scan_start`, `redsim.verify_replay`,
`redsim.ml_campaign_run` and `redsim.ml_model_validate` route to the `scans`
queue. `redsim.report_render`, `redsim.reap_stale_jobs`,
`redsim.verify_tenant_integrity` and `redsim.export_chains_to_worm` to
`default`. Beat runs the reaper every 5 minutes (it also rolls the run status
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
- `Run.stage_table` in the spec 6.5 shape (`stages` map with `status` in
  `queued | running | succeeded | failed | skipped | cancelled | timed_out`,
  `started_at`, `finished_at`, `job_id`) and one `{"type": "stage", "name",
  "status"}` frame per transition on the run-events channel.
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
delete on refusal, `job.complete`.

### Database and policy

`redsim/db` models plus Alembic migrations `0001` to `0010`.
`0010_ml_vertical` adds `targets.detail` JSONB and the `ml_campaigns` table
with full RLS parity (denormalized `org_id`, BEFORE INSERT backfill trigger,
BEFORE UPDATE drift guard, `FORCE ROW LEVEL SECURITY`, the
`redsim_tenant_isolation` policy). Bundled registrations are per project:
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
(approver), `finding.annotate` (remediator), `report.export` (scanner). The
table is mirrored in `deploy/opa/redsim-authz.rego` and
`deploy/cedar/redsim-policy.cedar`. Change all three together.

### Platform packages

`redsim/audit` (chain, forensic, redaction), `redsim/api/middleware` (tenant
GUC for RLS, CSRF, rate limit), `redsim/llm` (router, budget, pricing,
guardrails, `pythia.py`, `pythia_check.py`), `redsim/storage` (filesystem,
S3, WORM), `redsim/state`, `redsim/services` (`ml_models`, `ml_campaigns`,
`ml_findings`, `reports`, `runs`, `scans`, `targets`, `verify`,
`auth_profiles`, `evidence`), `redsim/scanners` (registry,
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
`STANDING_LIMITATIONS`, `grade_for_mri`, `contains_banned_score_word`).
`targets/base.py` (`Target`, `Sample`) and `attacks/base.py`
(`AttackAdapter`, `AttackOutput`) are the frozen protocols.

Modules: `registry.py`, `artifacts.py`, `errors.py` (spec 10.6 failure
classes: `ModelLoadRefused`, `ArtifactDigestMismatch`, `SandboxTimeout`,
`SandboxKilled`, `EnvelopeInvalid`, `DatasetUnavailable`,
`MlExtraUnavailable`, `ExplainerUnavailable`, each with a `code`),
`defenses.py`, `eval.py`, `scoring.py` (`DEFAULT_EPS_GRID_LINF`
`(0.01, 0.03, 0.1)`, `DEFAULT_EPS_GRID_L2` `(0.25, 0.5, 1.0)`,
`DEFAULT_REFERENCE_EPS` `0.03`, the binomial `control_preserves_accuracy`
predicate, `FamilyDelta`, typed delta refusal), `campaign.py` (attacks that
cannot run are recorded `not_run` and removed from the in-scope set, curve
PNG, dataset caveats and the `subject_centered` weak-subject caveat),
`reporting.py` (six sections in the spec 14.8 order: configuration and
provenance, measurements with the MRI scorecard as a derived-summary
sub-block, observations, interpretation, candidate recommendations,
limitations then reviewer notes. `report.json` is
`CampaignRecord.model_dump`. HTML through the escaping helpers in
`redsim.report`), `sandbox.py` and `sandbox_worker.py` (typed
`MlSandboxConfig` from `REDSIM_ML_SANDBOX_*`, defaults 1200 s wall clock,
900 CPU s, 4096 MB, 1024 MB files, 2 threads. Child env is the interpreter
allowlist plus `MPLBACKEND=Agg`, `HF_HUB_OFFLINE`, `HF_DATASETS_OFFLINE`,
thread pins and `REDSIM_ML_ASSETS_DIR`, with every secret-bearing and proxy
variable removed. Work dir `REDSIM_ML_WORK_DIR/<job_id>` mode 0700),
`targets/` (`registry`, `architectures` with `small_cnn` (alias `smallcnn`)
and `resnet18`, `bundled`, `tabular`, `artifact` with onnx2torch conversion
and argmax agreement, `unavailable`), `attacks/` (`fgsm`, `pgd` with
surrogate transfer, per-feature eps scaling and ART mask for tabular,
`hopskipjump`, `noise_control`), `datasets/` (`cifar10`, `image_hub`,
`sampling`, `url_features`), `explain/` (`shap_image` with the
`PartitionExplainer` fallback, `shap_tabular`, `stability`, `summary`, the
explanation cache under `REDSIM_ML_EXPLAIN_CACHE` or the work dir),
`recommend/` (`rules`, `narrative`), `assets/` (`datasets`, `build`,
`train_cnn`, `train_url_classifier`, `fixture_sample`, `manifest`).

`import redsim.ml.targets, redsim.ml.attacks` registers the targets
`cifar10_smallcnn` (fixture only), `endpoint_stub` (`not_implemented`),
`url_trees` (legacy alias `url_classifier`) and `vehicles_cnn`, and the
attacks `fgsm`, `pgd`, `hopskipjump`, `noise_control`. The defenses are
`feature_squeezing`, `spatial_smoothing`, `jpeg_compression`. `tests/ml/`
holds `fakes.py` (`TinyTarget`, `TinyTabularTarget`), `fixtures/`
(`run_record.json`, `malicious_urls_sample.csv`, `cifar10_test_500.npz`,
`MANIFEST.json`) and the module, route, task and audit tests. An autouse
fixture in `tests/ml/conftest.py` keeps every ML test away from a developer's
`.env`.

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
`deploy/helm/redsim` is the chart. `deploy/terraform/` is the code-only
Fargate foundation (existing-VPC checks, private endpoints, an ALB with target
groups but no listeners, RDS PostgreSQL 16, Redis, two S3 buckets,
per-service IAM roles, mocked-plan tests behind `validate.sh`): no task
definitions, no services, nothing applied. Compose and Helm have not been
brought up as part of the completion pass.

### Wave 3 (landing on `main` 2026-09-09)

Absent from `bb43bd7`. Described from the wave-3 branch and reports.

- `redsim ml attack <target_id>`: offline campaign against a bundled target
  from `REDSIM_ML_ASSETS_DIR` or `./assets`, run in the sandbox child, writing
  `<out>/<run_id>/{run_record.json, report.md, report.json, report.html,
  artifacts/curve/robustness_curve.png, audit.jsonl}`. The `attack.run` row is
  written first through `JsonlAuditWriter` (single-file chain `run:<run_id>`),
  every stage event and `job.complete` land in the same chain. `endpoint_stub`
  refuses with `not_implemented`, fixture-only targets with `fixture_only`,
  both before anything is written. `llm_narrative` stays false and the CLI
  prints `narrative_source=rules`. (wave 3, landing 2026-09-09)
- `redsim ml seed [--project] [--only] [--assets-dir] [--actor]`: opens
  `REDSIM_DB_URL` and calls `register_bundled_model` per non-fixture manifest
  model, reporting registered versus already present. (wave 3, landing
  2026-09-09)
- `CampaignScannerAdapter` registered as `ml-campaign` with capabilities
  `adversarial_ml` and `explainability` (both added to `KNOWN_CAPABILITIES`).
  `health_check` probes the `ml` extra and launches
  `redsim.ml.sandbox_worker --help` under the real child env, never a model.
  (wave 3, landing 2026-09-09)
- Opt-in `redsim.ml.attacks` entry-point discovery in `redsim/plugins.py`
  (`REDSIM_PLUGINS=1`, `REDSIM_PLUGINS_ALLOW`, `AttackAdapter` conformance,
  Ed25519 verifier). `GET /v1/attacks` loads the plugins. (wave 3, landing
  2026-09-09)
- `tests/e2e/` harness (`conftest.py`, `harness.py`, `README.md`): every item
  under it is stamped `e2e` and skipped unless `REDSIM_E2E` is set. Real API,
  admission, eager Celery, real sandbox child, real CLI over sqlite with a
  mirror of the `ml_campaigns` table. `REDSIM_E2E_SANDBOX=child|inprocess`.
  `REDSIM_E2E_POSTGRES_URL` for the RLS lane. Mocked Pythia toggle. (wave 3,
  landing 2026-09-09)
- `redsim doctor` rewritten around Pythia: no provider key anywhere, an
  informational Pythia block with the key redacted to prefix and length, the
  `ml` extra / sandbox child / assets manifest checks (required with
  `--worker-mode` or `REDSIM_DOCTOR_WORKER_MODE=1`, informational otherwise),
  the `ml-campaign` roster check. `--api-mode` keeps the DB / blob / OIDC
  probes. `redsim.yaml` and `.env.example` are Pythia-only and document every
  spec 20.3 ML variable. (wave 3, landing 2026-09-09)
- `redsim audit verify --run <id>` falls back to
  `<output_dir>/<id>/audit.jsonl`, and `--run-dir PATH` names an offline run
  directory or `.jsonl` file explicitly. (wave 3, landing 2026-09-09)
- Six defect fixes: admission no longer freezes `eps` into `attack_params`.
  `pgd` is admitted on tabular by capability tags (`modality:tabular`). The
  audit chain persists `ts` canonically so sqlite chains verify. The sandbox
  child pins `REDSIM_ENV_FILE` to an absent path and sets
  `REDSIM_DISABLE_LLM`. The `--run-dir` fallback above. `GET /v1/attacks`
  loads attack plugins. (wave 3, landing 2026-09-09)

## Assets and datasets (built locally, gitignored)

The catalog is decided (spec section 11): image demo
`leibnitz-lab/military_vehicles` (HF, MIT, coarse 7-class task, ground-level
photographs), image CI fixture `uoft-cs/cifar10`, tabular demo Kaggle
`sid321axn/malicious-urls-dataset` (CC0. URL strings are data and are never
fetched. A committed stratified sample serves CI), tabular fallback
`lacg030175/UNSW-NB15` (CC-BY-4.0, unused). Everything under `assets/` except
`assets/README.md` is gitignored, so a fresh clone has no assets until it runs
`redsim ml build-assets`. The Kaggle download reads `KAGGLE_API_TOKEN` (or
the older `KAGGLE_USERNAME` / `KAGGLE_KEY` pair) from the environment or the
`.env` file `REDSIM_ENV_FILE` names, and falls back to the committed sample
(marking the result `fixture_only`) when neither is set.

Clean accuracy and per-class counts are recorded in `assets/MANIFEST.json`
and are read from there by the UI and the reports. The local build of
2026-09-09 (illustrative, one laptop, never a product claim): `url_trees`
(scikit-learn HistGradientBoosting) clean accuracy 0.9087 on n=128224 eval
rows, surrogate agreement 0.7891. `vehicles_cnn` is now `resnet18` (ImageNet
init from the local torch hub cache, fine-tune lr 3e-4 with cosine schedule,
flip and crop augmentation, 12 epochs) at 0.7687 on n=1621 `test_coarse`
images, up from 0.5151 with `small_cnn`. `cifar10_smallcnn` 0.6872 on the
10000-image test split, fixture only. Quote the manifest of the build in
hand, never these numbers, in anything user-facing.

The Phase A datasets are also published for other teams at
https://github.com/IntelliBridge/ai-red-teaming-data (public, spec 11.7).
Its URL CSVs are redacted copies (credential-shaped query values replaced
with `REDACTED`, 0.36 percent of rows), so their hashes differ from the
manifest and metrics re-derived from the public copy differ slightly.

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
- Tests: `.venv/bin/python -m pytest -q`. The default `-m` from `addopts`
  excludes `docker`, `e2e`, `slow` and `auth_required`. `pytest -m ml` runs
  the tests that need the `ml` extra, `pytest -m integration` the sqlite or
  Postgres-backed ones. `REDSIM_E2E=1 pytest -q -m e2e tests/e2e` runs the
  end-to-end tier (wave 3, landing 2026-09-09).
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
`REDSIM_PLUGIN_SANDBOX_*`, `REDSIM_DISABLE_LLM`, `REDSIM_E2E`, `REDSIM_PLUGINS`.
At `bb43bd7` `.env.example` still lists `OPENAI_API_KEY`-style provider keys
from aegis. Nothing reads them, and wave 3 removes them (wave 3, landing
2026-09-09).

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
`KAGGLE_API_TOKEN` (the one-off `build-assets` run only). There is no network
switch for the ML child: it never receives network configuration.

## CLI (`redsim`, `redsim.cli:main`)

| Command | What it does |
|---|---|
| `redsim doctor [--api-mode]` | Environment checks. At `bb43bd7` it still derives a provider key from `redsim.yaml`'s `model`. The Pythia-aware rewrite with `--worker-mode` is wave 3 (landing 2026-09-09). |
| `redsim init` | Writes a default `redsim.yaml`. |
| `redsim status` | Mode, backends, connectivity. |
| `redsim scan <url> --scanner <name>` | Dispatches through the scanner registry. Exits 1 when no adapter of that name is registered. |
| `redsim findings`, `redsim verify`, `redsim report` | Filesystem run-state commands inherited from the platform. |
| `redsim audit verify [--run ID \| --project ID \| --all]` | Walks the chain(s) the configured writer holds (Postgres when `REDSIM_DB_URL` is set, else `<output_dir>/audit/*.jsonl`). `--run-dir PATH` and the `<output_dir>/<id>/audit.jsonl` fallback are wave 3 (landing 2026-09-09). |
| `redsim audit export [--all \| --chain ID] [--no-verify]` | WORM export (`REDSIM_WORM_EXPORT=1`). |
| `redsim tenants verify [--repair]` | Reconciles denormalized `org_id`. |
| `redsim plugins list [--json]`, `redsim plugins sign ...` | Third-party adapter discovery (`REDSIM_PLUGINS=1`) and Ed25519 signing. |
| `redsim ml build-assets [--dataset image\|tabular\|cifar10\|all] [--only ID] [--epochs N] [--arch small_cnn\|resnet18] [--image-size N] [--seed N] [--out DIR] [--cache-dir DIR] [--max-train N] [--max-eval N] [--workers N] [--xgboost\|--no-xgboost] [--fixture [--fixture-out] [--fixture-sidecar] [--fixture-synthetic-ok]]` | Fetches the datasets by pinned revision, trains the bundled models on CPU with a fixed seed, writes `assets/MANIFEST.json` on `MLModelManifest` with dataset caveats and `subject_centered`. `--fixture` writes `tests/ml/fixtures/cifar10_test_500.npz` from local files only. Network access happens only here. |
| `redsim ml attack <target_id> [--attacks fgsm,pgd] [--eps ...] [--reference-eps] [--n-samples 200] [--seed 0] [--explain-k 8] [--no-control] [--norm linf\|l2] [--out DIR] [--assets-dir DIR] [--actor]` | Offline campaign, see Wave 3. (wave 3, landing 2026-09-09) |
| `redsim ml seed [--project] [--only IDS] [--assets-dir DIR] [--actor]` | Registers the bundled, non-fixture models into a project through `register_bundled_model`. (wave 3, landing 2026-09-09) |
| `redsim evidence-pack --out DIR [--project ID]` | Bundles audit and controls evidence. |
| `redsim migrate fs->pg --source DIR --project ID` | Filesystem run data into Postgres. |

## LLM access: Pythia only

Every LLM call goes through Pythia (`redsim/llm/pythia.py`). redsim's per-task
router (`redsim.llm.router.route`, task `ml.harden_narrative`) and the budget
checker stay the policy layer, Pythia is the only transport. No litellm, no
direct provider keys anywhere. `docs/ops/pythia.md` is the full runbook.

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

## Verified state (2026-09-08, `main` at `bb43bd7`)

Counts come from running the commands from this tree with the venv
interpreter. Re-run them before quoting them.

- `.venv/bin/python -m pytest -q`: 1594 passed, 30 skipped (about 107 s).
- `.venv/bin/ruff check --select E4,E7,E9,F,I redsim tests`: clean.
- `.venv/bin/mypy redsim`: clean, 189 source files, from a venv that has
  `truststore` and `torch` installed.
- Web vitest: last recorded 274 passed at `7240220`. Not re-run for this
  revision.
- Redsim CI on `main` is red at the time of writing and is being
  investigated. Do not claim green CI. The last fully green run was
  `ea39f97` (#21). Through `7240220` the recorded cause was the unit lanes'
  mypy step: `no-any-return` in `redsim/ml/datasets/image_hub.py`
  (`truststore` is in no pyproject extra, so CI types it as `Any`) and, on
  3.13 only, `redsim/ml/assets/train_cnn.py` without the `ml` extra. Local
  mypy passes because the venv has both packages. Whether the same cause
  applies at `bb43bd7` has not been confirmed.
- `Deploy to AWS` fails at "Configure AWS credentials" (OIDC AssumeRole,
  account-side). `Docs` builds with `mkdocs build --strict`. Pages deploy is
  dormant behind the repo variable `ENABLE_PAGES`.
- Still stale outside the docs refresh: `docs/architecture/overview.md`
  (pentest sections), `CHANGELOG.md` (aegis release history),
  `docs/security/supply-chain.md` (points at `examples/redsim-plugin-example`,
  not in this tree), `web/components.json` (its `registry` points at the
  deleted `project_repos/shadcn-ui`), ADRs 0001, 0002 and 0004 (history,
  keep).

## CI contract (`.github/workflows/redsim-ci.yml`)

- Lint: `ruff check --select E4,E7,E9,F,I redsim tests`. `pyproject.toml`
  only says `extend-select = ["I"]`. Ruff's default set is not the contract.
- Types: `mypy redsim` with the strict settings in `pyproject.toml`.
- Tests: 3.12 installs the `ml` extra (CPU torch first) and runs
  `-m "not integration and not docker and not e2e and not slow and not
  auth_required"`, 3.13 runs without the extra and adds `and not ml`. ML
  test modules must `pytest.importorskip` their heavy imports so collection
  survives on 3.13.
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
  OIDC and rolls whichever `ECS_SERVICE_*` variables are set. It does not run
  the test gates.

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
- P0 froze `redsim/ml/schema.py` (every field name and type), migration head
  `0010_ml_vertical` and the `ml_campaigns` column set, the `Action` values
  and minimum roles, the `GET /v1/runs/{id}/campaign` shape in
  `tests/ml/fixtures/run_record.json`, and the name `REDSIM_ML_LLM_MODEL`.
  Change protocol (`docs/plans/01`, section 8): never rename a field, column,
  `Action` or response key silently, announce a change as a one-line note in
  master plan section 5 plus a heads-up to the team, prefer an additive
  default-valued field over changing an existing one, and record accepted
  divergences (see above).

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

The README section "Open items and not implemented" is the single list of
what this completion pass does not do (web UI wiring beyond the #22 contract
alignment, browser e2e, Fargate / Terraform / Helm apply and compose
operations, Phase B, fallback datasets, and every spec 26 criterion that needs
a named human reviewer). Keep it and this file in step.
