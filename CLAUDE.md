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
It describes `main` at `29db42c` (2026-09-09: the four Phase A completion
waves and Phase B wave B0, verified from this tree) plus Phase B wave B1, the
library layer, pushed to `main` together with this documentation pass and
marked "wave B1" where it is named. Phase B is planned in
`docs/plans/12-phase-b-plan.md` (five waves; B0 and B1 landed, B2 to B4 not
started, every Phase B route a `501` stub until its wave replaces it).

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

## What is on the tree (`main` at `29db42c` plus wave B1)

Verified by importing the app and reading its OpenAPI document, importing the
ML registries and running the suite with the venv interpreter.

### API process (`redsim.api.app:create_app()`)

`create_app()` mounts `health`, `ml_capabilities`, `attacks`, `datasets`,
`defenses`, `models`, `artifacts`, `compare`, `ml_findings`, `runs`,
`runs_cancel`, `findings`, `audit`, `reports`, `scanners`, `verify`,
`targets`, `auth_profiles`, `projects`, `logs`, `org_cost`, since wave B0 the
Phase B stub routers `batches`, `llm`, `integrations` (plus two rows in
`datasets`), and the WebSocket router: 58 HTTP routes under `/v1` (39 Phase
A, 19 Phase B stubs), plus `GET /health`, `/metrics`, `GET /v1/__settings`
and `/docs` outside prod, and `WS /v1/runs/{id}/events`. `POST /v1/scans`
was unmounted by P0 and answers 404.

| Group | Routes |
|---|---|
| ML catalog | `GET /v1/ml/capabilities` (secret-free roster, `sandbox_enabled` always true), `GET /v1/attacks` (`?modality=`, plus a `plugins` block with the opt-in `redsim.ml.attacks` discovery rows, `c3868e5`), `GET /v1/datasets` (rows from `assets/MANIFEST.json`, says so when no manifest is built), `GET /v1/defenses` |
| Models | `GET /v1/models` (registered targets, unregistered bundled entries, the LLM domain as a `not_implemented` row. Fixture-only targets never listed), `GET /v1/models/{id}` (with `campaign_history`), `POST /v1/models` (`source: bundled` through `register_bundled_model`, `source: upload` with the static checks of spec 9.3, `source: endpoint` answers `501 not_implemented` with `phase`), `DELETE /v1/models/{id}` (audited soft delete, blob dropped, row kept for history) |
| Campaigns | `POST /v1/models/{id}/attacks` (202 JobHandle, optional `parent_run_id` rerun of a failed or cancelled parent), `GET /v1/runs/{id}/campaign`, `GET /v1/runs/{id}/compare?with=` (variable-level `409 incompatible_campaigns`, `409 score_unavailable` when `mri` is null, `mode: verify_delta` or `side_by_side`), `PATCH /v1/runs/{id}/reviewer-notes`, `GET /v1/runs/{id}/artifacts`, `GET /v1/artifacts/{id}`, `GET /v1/runs/{id}/report.{md,json,html}` (newest Artifact row, digest-checked. `report.pdf` answers `501 not_implemented`, Phase B) |
| Findings | `GET /v1/findings`, `GET /v1/findings/{id}`, `POST /v1/findings/{id}/explain`, `POST /v1/findings/{id}/harden`, `POST /v1/findings/{id}/verify`, `PATCH /v1/findings/{id}/status` (dismissal only: `finding.review`, approver tier, campaign creator and system principals refused with 403, source status `open` or `failed` only, non-empty reason, audit row before the write) |
| Runs and platform | `GET /v1/runs`, `GET /v1/runs/{id}`, `POST /v1/runs/{id}/cancel` (`409 run_terminal`), `GET /v1/audit/verify` (`?run=` resolves the project through run access, `?project_id=`, `?all=1` returns `{chains: [...]}`), `GET/POST/DELETE /v1/targets` (ML kinds are refused with `400 use_models_route`), `GET /v1/targets/{id}/verification` and `POST /v1/targets/{id}/verify` (501, pentest-era ownership check), `GET/POST/DELETE /v1/auth-profiles`, `GET /v1/projects`, `GET /v1/projects/{slug}/membership`, `PUT /v1/projects/{slug}/settings`, `GET /v1/logs`, `GET /v1/orgs/{org_id}/cost`, `GET /v1/scanners` (one adapter, `ml-campaign`, registered when `redsim.scanners` is imported, `3ab9de7`) |
| Phase B, 501 until built (wave B0, `0b0981b`) | 19 routes mounted behind the lookup, membership and role gates their real handlers will run, then `501 not_implemented` with `phase: "B"` and a `reason` naming the wave and track that builds them; no row, audit event, job or artifact is written. `POST /v1/runs/{id}/dataset`, `GET /v1/datasets/{id}`, `POST /v1/datasets` (B3 interop), `GET /v1/runs/{id}/atlas-coverage`, `POST /v1/runs/{id}/integrations/foundry`, `GET /v1/integrations` (B3 atlas-foundry), `GET /v1/llm/probes`, `POST /v1/models/{id}/probes`, `GET /v1/runs/{id}/llm-scorecard` (B2 llm-api), `POST/GET /v1/campaigns/batch`, `GET /v1/campaigns/batch/{id}`, `GET .../{id}/compare`, `POST .../{id}/cancel`, `POST /v1/models/bulk`, `POST /v1/findings/{id}/verify/bulk`, `GET /v1/ml/capacity` (B3 bulk), `POST /v1/runs/{id}/report.render`, `GET /v1/runs/{id}/snapshots` (B2 reports). The stubs resolve the Phase B `Action` members by name and gate on them (`tests/ml/test_phase_b_stubs.py`). Full table in `docs/api/v1.md` |

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
`daily_budget_exceeded`, `integration_disabled`, `endpoint_unreachable`;
`tests/ml/test_error_codes.py` parses the spec table and the addendum and
refuses a code that exists on one side only). Services raise `ApiError`, the
route converts it. Nothing parses exception text.

`tests/test_api_process_has_no_ml.py` builds the app in a subprocess with
`torch`, `torchvision`, `art`, `onnx`, `onnxruntime`, `shap`, `sklearn`,
`xgboost` and (since wave B0) `garak`, `openai`, `litellm`, `reportlab`,
`pyarrow` and `mlcroissant` blocked and asserts it still serves `/health`; it
also builds the sandbox child environment with low-entropy fake credentials
in the parent and asserts none survives. The catalog registries are imported
lazily. When one cannot be imported the route answers
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
  The wave B1 integration adds the text kinds `ml.text.diff` and
  `ml.shap.text`, the detection kinds `ml.detection.boxes` and
  `ml.detection.scorecard` (its drawn images stay `ml.input.clean` /
  `ml.input.adv`) and the training-defense kinds `ml.derived_model` and
  `ml.training_report`.
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
delete on refusal, `job.complete`.

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
`dataset.export` (scanner; the register said remediator, recorded for the
owner to confirm), `integration.push` (admin), `batch.run` (scanner),
`report.render` (scanner), `finding.author` (remediator). The
table is mirrored in `deploy/opa/redsim-authz.rego` and
`deploy/cedar/redsim-policy.cedar`. Change all three together;
`tests/test_policy_ml_actions.py` parses both mirrors and asserts equality.

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
`redsim.report`), `sandbox.py` and `sandbox_worker.py` (typed
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
registers when `redsim.ml.targets.text` is imported. The attacks are `cw_l2`,
`deepfool`, `dpatch`, `fgsm`, `hopskipjump`, `noise_control`,
`patch_noise_control`, `pgd`, `word_substitution`, `zoo` (checked at import
against the declared list; `adv_patch` recorded as not built). The defenses
are `feature_squeezing`, `spatial_smoothing`, `jpeg_compression`
(preprocessing) and `adversarial_training`, `defensive_distillation`
(training, `phase: "B"`, not yet admitted by the verify route). `tests/ml/`
holds `fakes.py` (`TinyTarget`, `TinyTabularTarget`), `fakes_text.py`
(`TinyTextTarget`), `fakes_detection.py` (`TinyDetector`),
`tiny_endpoint_server.py`, `fixtures/` (`run_record.json`,
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

### Wave 4 and Phase B waves B0 and B1 (2026-09-09)

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
  edit|patch_area`). Nothing of B1 is admitted through the API until wave
  B2.

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
  without it; exits 5 with nothing collected until a `garak`-marked test
  exists). Tiers in `docs/dev/testing.md`.
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
(20000). Tests only: `REDSIM_PUBLIC_DATA_CHECK=1` runs the slow live check of
the public data repository. There is no network switch for the ML child: it
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
- Phase B (waves B0 and B1, recorded in `docs/architecture/ml-vertical.md`
  "Accepted divergences"): `defense_apply` sits after `load_target`, not at
  the end of `STAGES`; the endpoint contract is `endpoint-v1` with
  `{contract, input_format, inputs}`, not the register's
  `redsim-predict-proba/1` with an `encoding` key; `dataset.export` gates at
  `scanner` (the brief), not `remediator` (register INTEROP-02, spec 17.4);
  five stub paths follow the brief rather than the register;
  `DetectionMetrics` uses the brief's field names; image HopSkipJump is served
  by the Phase A adapter with `IMAGE_DEFAULTS` (spec 12.2); KernelSHAP for
  images is not built (spec 13.2); distillation is native torch with ART's
  class cited (spec 16.5); the broker does not pin the connection to the
  resolved address (ENDPOINT-07 risk note); no DNS-TXT ownership check for
  endpoints (spec 21.7, owner default ENDPOINT-26).

## Verified state (2026-09-09, `main` at `29db42c` plus wave B1)

Counts come from the wave B0 and B1 integration runs with the venv
interpreter and the `ml` extra. Re-run them before quoting them.

- At `29db42c` (wave B0 integration): `.venv/bin/python -m pytest -q -p
  no:cacheprovider --ignore=tests/e2e` 2081 passed, 35 skipped, 1 deselected
  (106 s); `REDSIM_E2E=1 REDSIM_E2E_POSTGRES_URL=... pytest -q -m e2e
  tests/e2e` 22 passed (136 s, Postgres at `localhost:5433`);
  `ruff check --select E4,E7,E9,F,I redsim tests` clean; `mypy redsim` clean
  (197 source files); `mkdocs build --strict` exit 0; the frozen fixture
  `tests/ml/fixtures/run_record.json` unchanged (sha256 `e5266f18…`, the
  tripwire pin). The Postgres-gated cases of `tests/test_migration_0011.py`
  and `tests/test_tenant_rls.py` skip without `REDSIM_DB_URL` and were not run
  locally.
- Wave B1 before its rebase (worktree on `7706950`): ruff clean, `mypy
  redsim` clean (213 source files), the seven writers' test files 206 passed
  (31 s), the default tier 1840 passed and 31 skipped (that worktree lacked
  B0's tests). The rebased tree's counts are in the B1 integration commit
  message.
- Web vitest: last recorded 274 passed at `7240220`. Not re-run for this
  revision.
- Redsim CI: the run for the `29db42c` push, the first with the `e2e-python`
  and `garak-offline` jobs, had not been read when this file was written, and
  neither had the runs for `e73dea0` (wave 4, which landed the three fixes for
  the `58461cc` failures: `python-multipart`, the import cycle, the trivy
  baseline and the lazy torch imports), `7706950`, `6cbb661`. The last run
  this file has read is `58461cc` (run 34307513075): red on the Coverage gate,
  Unit tests (py3.13) and Dependency CVEs, green on the rest, with API
  integration, the Next.js build and the image builds skipped behind the unit
  lane. Do not claim green CI until a run on `main` is read; the details of
  each failure and fix are in `docs/dev/ci.md`. The last fully green run was
  `ea39f97` (#21).
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
  dirs under the runner temp. Exit 5 (nothing collected) is mapped to success
  with a `::notice::` line until the LLM tracks land `garak`-marked tests;
  any other non-zero exit fails.
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
waves B2 to B4 (every Phase B route a `501` stub, no admission of the Phase B
modalities, norms, training defenses or endpoint targets), the owner
decisions of `docs/plans/12-phase-b-plan.md` section 2 with their defaults,
the remaining-work brief's packages A to F (compose operations, CI parity,
the process-gate documents that need named human reviewers, residual Phase A
rows, the Fargate runtime follow-ups, the data-poisoning module), the
recorded non-builds, and the unread CI run for `29db42c`. Keep it and this
file in step.
