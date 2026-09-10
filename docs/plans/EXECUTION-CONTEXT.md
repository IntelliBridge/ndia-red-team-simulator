# Execution context: cold-start guide

Read this before touching the tree in a fresh session. It carries the
operational facts that are not in the phase files, and the order to read
things.

Refreshed 2026-09-09 against `main` at `703f8f6` (the Phase A completion waves
1 to 4 and Phase B waves B0 to B3) plus Phase B wave B4 (the end-to-end
evidence, the `make check-phase-b` gate, the fix pass and the documentation
pass, pushed together). Everything below was read from that tree.

## Read order

1. **This file.**
2. **Canonical spec**, `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`.
   Decisions D1 to D14 (section 4) are final. Sections 10 (job and worker
   flow, 10.5 audit vocabulary, 10.6 failure classes), 17.3 (error codes with
   the three dated Phase B addenda), 20.3 (environment variables), 22.6 (the
   Phase B testing addendum), 26 with 26.7 (Phase B completion criteria) and
   27 (interoperability) are the ones the tree is measured against most.
3. **Master plan**, `docs/plans/00-master-plan.md`. Section 0 (v2.5 to v2.8)
   records what each Phase B wave landed and the divergences the tree keeps,
   section 4.1 the workstream, wave and CI status, section 5 the shared
   contracts, section 8 where the definition of done stands.
4. **Phase B plan and register**, `docs/plans/12-phase-b-plan.md` (waves B0 to
   B4 with a dated status line each, the owner decisions with their applied
   defaults) over `docs/plans/11-phase-b-register-2026-09-09.md` (309 rows as
   found; its header paragraph says which ids landed in which wave).
   `docs/plans/10-remaining-work-brief.md` (packages A to F) carries what runs
   outside the waves; `docs/plans/09-gap-register-2026-09-08.md` is the Phase
   A register.
5. **Your phase file**, `docs/plans/0N-*.md`. `01` closes with a dated Landed
   note and its section 8 is the change protocol; `02` to `05` open with a
   dated Landed block written at `bb43bd7` (their wave-3 items landed at
   `58461cc`); `06` and `08` carry v2 bodies under a status banner; `07` was
   rewritten in wave B4 onto the spec 27 vocabulary as built.
6. **Feature detail**, `specs/F001` to `F008`. Where a feature file conflicts
   with the canonical spec, the spec wins. D006 and D007 stay open with no
   owner invented.
7. **The narrative pages**, `docs/architecture/ml-vertical.md` (the vertical
   as it runs, the accepted divergences), `docs/interop.md` (what leaves and
   what enters), `docs/api/v1.md` (every route from the OpenAPI document),
   `docs/api/endpoint-contract.md` (`endpoint-v1`), `docs/ops/pythia.md`,
   `docs/dev/testing.md`, `docs/dev/ci.md`.
8. **The code you will touch**: `redsim/ml/`, `redsim/api/v1/`,
   `redsim/services/`, `redsim/workers/tasks/`, `redsim/integrations/`,
   `redsim/db/`.

## Repo ground truth

- The package is `redsim-platform` (the aegis security platform renamed to the
  `redsim` namespace on 2026-09-08 with the pentest domain removed). The ML
  vertical `redsim/ml/` is on `main` end to end: `schema.py` (frozen by P0,
  extended once additively by wave B0), `registry.py`, `artifacts.py`,
  `errors.py`, `eval.py`, `scoring.py`, `campaign.py` (the
  frame), `runners/` (`base`, `classification`, `text`, `detection`),
  `reporting.py`, `pdf.py`, `compare.py`, `atlas.py`, `atlas_data.py`,
  `endpoint_broker.py`, `endpoint_egress.py`, `sandbox.py` and
  `sandbox_worker.py` (the ML child), `targets/` (`base`, `registry`,
  `architectures`, `bundled`, `tabular`, `artifact`, `unavailable`, `text`,
  `detection`, `endpoint`, `endpoint_contract`), `attacks/` (`base`,
  `registry`, `fgsm`, `pgd`, `hopskipjump`, `noise_control`, `cw_l2`,
  `deepfool`, `zoo`, `word_substitution`, `dpatch`), `datasets/` (`cifar10`,
  `image_hub`, `sampling`, `url_features`, `sms_spam`, `military_assets`),
  `explain/` (`base`, `shap_image`, `shap_tabular`, `shap_text`, `stability`,
  `summary`), `recommend/` (`rules`, `narrative`), `llm/` (garak through Pythia:
  `catalog`, `generator`, `probe_child`, `runner`, `scorecard`, `rules`,
  `report_section`, `schema`, `reporting`), `interop/` (`parquet`, `croissant`,
  `card`, `consume`) and `assets/` (`datasets`, `build`, `train_cnn`,
  `train_url_classifier`, `train_text_classifier`, `train_detector`,
  `fixture_sample`, `manifest`). `import redsim.ml.targets, redsim.ml.attacks`
  registers the targets `assets_frcnn_mnv3`, `cifar10_smallcnn` (fixture only),
  `endpoint_stub`, `sms_tfidf_lr`, `url_trees` (alias `url_classifier`),
  `vehicles_cnn` and the attacks `cw_l2`, `deepfool`, `dpatch`, `fgsm`,
  `hopskipjump`, `noise_control`, `patch_noise_control`, `pgd`,
  `word_substitution`, `zoo`.
- The platform side: 66 HTTP routes under `/v1` on
  `redsim/api/app.py:create_app` (routers `health`, `ml_capabilities`,
  `attacks`, `datasets`, `models`, `models_bulk`, `artifacts`,
  `compare`, `ml_findings`, `runs`, `runs_cancel`, `findings`, `audit`,
  `reports`, `scanners`, `targets`, `auth_profiles`, `projects`,
  `logs`, `org_cost`, `batches`, `llm`, `integrations`, the WebSocket), the
  `IdempotencyMiddleware`, `redsim/api/errors.py` (the spec 17.3 table plus
  three dated addenda, 23 + 13 + 10 codes), the services
  `redsim/services/{ml_models,ml_campaigns,ml_findings,ml_llm,finding_review,reports,ml_datasets,ml_datasets_export,ml_batches,ml_capacity}.py`,
  `redsim/integrations/`, and twelve Celery tasks in `redsim/workers/tasks/`
  (`ml_campaign`, `ml_model`, `ml_llm`, `dataset_export`, `dataset_validate`,
  `integration_push`, `capacity`, `report`, `reaper`, the platform tasks).
  `redsim.ml_campaign_run`, `redsim.ml_model_validate`, `redsim.dataset_export`
  and `redsim.ml_dataset_validate` run on `scans`; `redsim.ml_llm_probe_run`,
  `redsim.integration_push` and the beat task `redsim.ml_dispatch_deferred`
  run on `default`, the only pool with egress. There is no per-attack Celery
  chain (master plan section 0, v2.3).
- No route is a `501 not_implemented` stub (`tests/ml/test_phase_b_stubs.py`
  pins the Phase B surface). The `501`s that remain are by decision with a
  reason (`docs/api/v1.md` "Phase B answers").
- The API process never imports torch, ART, onnxruntime, SHAP, scikit-learn,
  garak, openai, litellm, reportlab, pyarrow or mlcroissant
  (`tests/test_api_process_has_no_ml.py`). Model bytes, inference calls and
  Parquet parsing happen only on the worker: in the sandbox child, or in the
  worker parent for the endpoint predict broker and the Foundry push.
- Python 3.12 (torch and ART wheels). The venv is `.venv`, created with uv and
  without a `pip` module: run `.venv/bin/python`, install with
  `uv pip install --native-tls -e ".[api,worker,test,dev,ml]"` (add `docs` and
  `garak` for a full `make check-phase-b`).
- Dev flow: `make install`, then `make dev`. `make check` runs lint, typecheck
  and tests (Phase A meaning); `make check-phase-b` runs
  `scripts/phase_b_gate.sh`, the Phase B definition of done (nine steps, the
  first failure naming its spec 26 criterion). CI is
  `.github/workflows/redsim-ci.yml` (state in master plan section 4.1 and
  `docs/dev/ci.md`); `docs.yml` runs `mkdocs build --strict`.
- Migrations `0001` to `0012`. `0011_phase_b_platform` (wave B0) added
  `report_snapshots`, `idempotency_keys`, `ml_batches`, `ml_datasets` with RLS
  parity, `projects.ml_scoring` / `ml_max_concurrent_runs` /
  `ml_daily_run_budget`, `ml_campaigns.batch_id`. `0012_remove_verify_paradigm`
  (2026-09-09) is the head: it drops three verify-era columns, two on
  `findings` and one on `ml_campaigns`, and adds no table. Waves B1 to B4 added no
  migration.
- Corporate TLS proxy (Zscaler): Python clients need the OS trust store.
  `redsim/llm/pythia.py` defaults to `truststore` (`REDSIM_TLS_TRUSTSTORE`),
  `uv` needs `--native-tls`, `deploy/certs/README.md` covers containers.
  `docs/ops/pythia.md` is the gateway runbook.
- Git worktrees: the editable install points at the main checkout, so the e2e
  tier's subprocesses (the sandbox child, the CLI) run the main tree unless
  `PYTHONPATH=<worktree>` is set. `scripts/phase_b_gate.sh --only e2e` detects
  the mismatch and sets it; by hand, export it yourself (`tests/e2e/README.md`
  "Running from a git worktree").

## CLI surface

On `main` at `703f8f6` (`redsim/cli/main.py`, `redsim/cli/ml.py`):

- `redsim ml build-assets [--dataset image|tabular|cifar10|text|detection|all]
  [--only ID] [--epochs N] [--arch small_cnn|resnet18] [--image-size N]
  [--seed N] [--out DIR] [--cache-dir DIR] [--max-train N] [--max-eval N]
  [--xgboost|--no-xgboost] [--detection-image-size N]
  [--detection-subset DIR] [--fixture ...]`. Network access happens only here
  (HuggingFace hub by pinned revision, Kaggle with `KAGGLE_API_TOKEN` or the
  older `KAGGLE_USERNAME` / `KAGGLE_KEY` pair, else the committed CI sample;
  the SMS corpus from UCI by pinned sha256; WordNet from `nltk_data`).
  `--dataset all` builds image, cifar10, tabular and text; `--dataset
  detection` is named explicitly because its input is the published subset.
- `redsim ml attack <target_id> [<target_id> ...] | --matrix FILE.yaml
  [--fail-fast] [--attacks IDS] [--eps GRID] [--reference-eps E]
  [--n-samples N] [--seed N] [--explain-k K] [--no-control]
  [--norm linf|l2|edit|patch_area] [--out DIR] [--assets-dir DIR]
  [--actor A]`: an offline campaign per bundled target in the sandbox child
  with no database, no network and no Pythia, the `attack.run` row first on a
  `JsonlAuditWriter` chain, `<out>/<run_id>/{run_record.json, report.md,
  report.json, report.html, artifacts/..., audit.jsonl}`. Defaults: attacks
  `fgsm,pgd` (linf), `pgd` (l2), `word_substitution` (edit), `dpatch`
  (patch_area), the spec 12.3 grid for the norm. Since wave B3 several ids or
  a YAML matrix run one campaign per cell with its own chain, a summary table
  with no aggregate, `summary.json`, exit 1 on any refused or failed cell.
  `endpoint_stub` and fixture-only targets are refused before anything is
  written.
- `redsim ml seed [--project ID] [--only IDS] [--assets-dir DIR] [--actor A]`:
  registers every non-fixture manifest model through
  `register_bundled_model`, one commit per model. Needs `REDSIM_DB_URL`.
- `redsim audit verify [--run ID | --project ID | --all] [--run-dir PATH]` and
  `redsim audit export [--all | --chain ID]`.
- `redsim doctor [--api-mode] [--worker-mode]`: the Pythia block (key redacted),
  the `ml` extra, the sandbox child launch and the assets manifest (required in
  worker mode), the `ml-campaign` roster check. No provider key is checked.
- `redsim init`, `redsim status`, `redsim tenants verify`,
  `redsim plugins list|sign`, `redsim evidence-pack`, `redsim migrate`, and the
  pentest-era `redsim scan`, `findings`, `report` (`redsim scan
  --scanner X` exits 1 unless the adapter is `ml-campaign`).

## Environment variables (spec 20.3, all read by code on the tree)

| Group | Variables | Read by |
|---|---|---|
| Pythia | `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `PYTHIA_PERSONA`, `PYTHIA_TIMEOUT_S`, `REDSIM_ML_LLM_MODEL` (deprecated aliases `REDSIM_LLM_MODEL`, `AEGIS_ML_LLM_MODEL`), `REDSIM_DISABLE_LLM`, `REDSIM_ENV_FILE`, `REDSIM_TLS_TRUSTSTORE`, `REDSIM_CA_BUNDLE`, `SSL_CERT_FILE` | the worker parent (narrative); `PYTHIA_BASE_URL` is also the default gateway of an LLM target that names none. The probe key is never an environment variable: it lives in a bearer `AuthProfile` |
| ML sandbox | `REDSIM_ML_ASSETS_DIR`, `REDSIM_ML_WORK_DIR`, `REDSIM_ML_KEEP_WORK_DIR`, `REDSIM_ML_SANDBOX_TIMEOUT_S` (1200), `_CPU_SECONDS` (900), `_MEMORY_MB` (4096), `_FILESIZE_MB` (1024), `_THREADS` (2), `REDSIM_ML_DATASET_CACHE`, `REDSIM_ML_EXPLAIN_CACHE`, `REDSIM_ML_MAX_ADV_ARTIFACT_MB` (64, forwarded to the child since wave B4 when set to a positive number) | worker, sandbox child |
| API caps | `REDSIM_ML_UPLOAD_MAX_MB` (512), `REDSIM_ML_BULK_UPLOAD_MAX_FILES` (10), `REDSIM_ML_BULK_UPLOAD_MAX_MB` (1024), `REDSIM_ML_DATASET_UPLOAD_MAX_MB` (256), `REDSIM_ML_BATCH_MAX_MEMBERS` (20), `REDSIM_ML_ENDPOINT_MAX_ROWS` (500000), `REDSIM_ML_ENDPOINT_MAX_REQUESTS` (20000), `REDSIM_LLM_PROBE_MAX_PROMPTS_PER_PROBE` (64), `REDSIM_LLM_PROBE_MAX_RUNS_PER_PROJECT_PER_DAY` (10), `REDSIM_LLM_PROBE_HF_DETECTORS` | api (admission) |
| Capacity | `REDSIM_ML_MAX_CONCURRENT_RUNS_PER_PROJECT` (2, the default for `projects.ml_max_concurrent_runs`), `REDSIM_ML_DAILY_RUN_BUDGET` (unset is uncapped) | api (every attack, batch and bulk-upload admission since wave B4), the beat dispatcher |
| Endpoint broker | `REDSIM_ML_ENDPOINT_RPS` (10), `REDSIM_ML_ENDPOINT_BATCH_ROWS` (32 image / 256 tabular, at most 1024), `REDSIM_ML_ENDPOINT_TIMEOUT_S` (30) | worker parent |
| Probe child | `REDSIM_LLM_PROBE_HF_CACHE`, `REDSIM_LLM_PROBE_TIMEOUT_S` (1500), `REDSIM_LLM_PROBE_CPU_SECONDS`, `_MEMORY_MB`, `_FILESIZE_MB`, `_MAX_PROCESSES` | worker (default pool) |
| Consume | `REDSIM_ML_DATASET_MAX_ROWS` (200000) | the parse child |
| Foundry | `REDSIM_INTEGRATION_FOUNDRY_URL` (unset is disabled), `REDSIM_INTEGRATION_FOUNDRY_NON_OPERATIONAL=1` (the attestation), `REDSIM_INTEGRATION_FOUNDRY_DATASET_RID`, `REDSIM_INTEGRATION_FOUNDRY_TIMEOUT_S` (30); no token variable exists | api (presence, `GET /v1/integrations`), the default worker pool (the push); the sandbox child drops every one |
| Build and tests | `KAGGLE_API_TOKEN` (the one-off `build-assets` run only), `REDSIM_E2E`, `REDSIM_E2E_POSTGRES_URL`, `REDSIM_E2E_SANDBOX`, `REDSIM_E2E_LIVE`, `REDSIM_PUBLIC_DATA_CHECK`, `REDSIM_DOCTOR_WORKER_MODE`, `REDSIM_PLUGINS`, `REDSIM_PDF_FONT_DIR` | the tooling |

`.env.example` documents every one of these with empty values and carries no
provider key (since wave B4 it also carries the endpoint, probe, capacity,
bulk, consume and Foundry groups; INTEROP-29, BULK-23), and
`deploy/docker-compose.yml` passes the API caps to `redsim-api`, the worker
parent settings to the worker anchor and the Foundry settings to
`redsim-worker-default` only. The sandbox child receives `REDSIM_ML_ASSETS_DIR`,
`REDSIM_PLUGINS`, `REDSIM_ENV_FILE=<work_dir>/no-env`, `REDSIM_DISABLE_LLM=1`
and, when set, `REDSIM_ML_MAX_ADV_ARTIFACT_MB`; nothing else under a
secret-bearing prefix crosses.

## Local assets (illustrative, never results)

`redsim ml build-assets` output is gitignored under `assets/` (only
`assets/README.md` is tracked); a fresh clone has no assets until it runs the
build. `assets/MANIFEST.json` is the only source of clean-accuracy numbers.
The build in hand on 2026-09-09 recorded: `url_trees`
(`sklearn_hist_gradient_boosting` on the Kaggle malicious-URLs set) clean
accuracy 0.9087 on n=128224, surrogate agreement 0.7891; `vehicles_cnn` as
`resnet18` (the `39126ce` recipe) 0.7687 on n=1621 `test_coarse`;
`cifar10_smallcnn` 0.6872, `fixture_only`. The text and detection builds
(`sms_tfidf_lr`, `assets_frcnn_mnv3`) record their own numbers in the same
manifest. Quote the manifest of the build you have, never these.

## Conventions

- Branch before committing. Do not commit to `main` directly. The repository
  allows squash merges only.
- Commit messages are `type(topic): description` with the
  `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` trailer.
- Prose in docs and comments avoids em dashes and semicolons.
- Lint and types exactly as CI runs them:
  `.venv/bin/ruff check --select E4,E7,E9,F,I redsim tests` and
  `.venv/bin/mypy redsim`. Tests: `.venv/bin/python -m pytest -q` (the
  `addopts` marker expression deselects `docker`, `e2e`, `slow`,
  `auth_required` and `garak`); `-m ml`, `-m garak tests` and
  `REDSIM_E2E=1 -m e2e tests/e2e` for the other tiers (`docs/dev/testing.md`).
- Nothing under `redsim/ml/` is presented as working until it runs; a test
  that meets a product defect fails with an attribution naming the module,
  never with a weakened assertion (the wave B4 e2e files do this).
- `redsim/ml/schema.py`, the migration head, the `Action` set and the error
  table change only through the plan 01 section 8 protocol
  (`tests/ml/test_schema_compat.py`, `tests/ml/test_error_codes.py`,
  `tests/test_policy_ml_actions.py` are the tripwires).

## AWS and CI already provisioned

Account `140381642432`, region `us-east-1`:

- A GitHub OIDC provider and IAM role `ndia-red-team-gha-deploy` (ECR push,
  ECS deploy, PassRole to `ndia-red-team-*` task roles); ECR repositories
  `ndia-red-team/{api,web,worker}`; repo variables `AWS_ACCOUNT_ID`,
  `AWS_REGION`, `AWS_DEPLOY_ROLE_ARN`, `ECR_REGISTRY`.
- `.github/workflows/deploy-aws.yml` builds the api, worker and web images on
  push to `main` via OIDC. The `58461cc` push built and pushed all three (the
  AssumeRole step had failed on the `bb43bd7` push). Its deploy job is
  skipped until `ECS_CLUSTER` is set, and it fails loudly rather than
  reporting a false green.
- `deploy/terraform/` (#19, `b40f7e1`) is the code-only Fargate foundation: no
  listeners, task definitions or services, nothing applied from this tree.
  PR #23 (`feat/p7-fargate-runtime`, William, merged as `10650da` with two
  review fixes) added `deploy/bootstrap/` and `deploy/runtime/`, a public HTTPS
  demo runtime at https://redsim.ndia.agiledefense.xyz that its author reports
  applied to this account (migrations through `0010`, health, login and OIDC
  discovery 200, unauthenticated API 401, workers at zero until a pinned asset
  bundle exists, demo users and memberships and real assets outstanding,
  automatic rollout disabled). Its completion is package E of the remaining-work
  brief (PR #29 reports the bundle, workers and demo users supplied);
  `deploy/runtime/README.md` on `main` is the sequence. Fargate, Terraform and
  Helm apply and compose operations stay outside the completion pass (master
  plan section 8). No campaign has been run on the runtime from this tree.
- Redsim CI: every run from the wave B0 push (`934838e`) to the B3 push
  (`703f8f6`) failed at workflow parse (`runner.temp` in a job-level `env`,
  fixed by #27). The first run that executed, #27's, is red on the Postgres
  migration test, the SAST `use-defused-xml` finding in `redsim/ml/pdf.py`
  and the coverage gate (which fails only on that migration test); every
  other lane passed. The fixes are queued. Nothing is claimed green.
- **Action: rotate the bootstrap AWS access keys.** Keys were pasted in
  plaintext during setup and must be treated as compromised. The pipeline uses
  OIDC, not static keys.

## Scope decisions that bite

- The substrate is redsim: Postgres with RLS, Celery on Redis, Keycloak auth,
  the hash-chained audit log, S3 (no EFS). Master plan section 2.
- Interoperability (spec 27) is built (wave B3) and proven end to end where it
  can be (wave B4): Croissant export and consume, ATLAS tagging and coverage,
  the Foundry push off by default and proven against a fake server only,
  Lattice text only by D3. `docs/plans/07-p6-interoperability.md` is rewritten
  onto the tree; `docs/interop.md` is the narrative.
- Demo data is `leibnitz-lab/military_vehicles` (image, `vehicles_cnn`),
  Kaggle `sid321axn/malicious-urls-dataset` (tabular, `url_trees`), the UCI
  SMS Spam Collection (text, `sms_tfidf_lr`) and the capped military-assets
  subset (detection, `assets_frcnn_mnv3`, published for owner review). URL
  strings are inert data and are never fetched, resolved or rendered.
  `lacg030175/UNSW-NB15` is the tabular fallback and has not been built.
  CIFAR-10 is a CI fixture only.
- The MRI is per campaign and per modality only. Detection campaigns and LLM
  probe runs never carry one. Never show it without its five subscores, the
  per-family table and the eps curve. A recommendation is a candidate and
  carries no gain figure.
- One job runs a whole campaign (`redsim.ml_campaign_run`). Do not build
  against the per-attack chain of spec 10.3.
- Every LLM call goes through Pythia: the narrative from the worker parent,
  the garak probes through `PythiaGenerator` with a probe key from an
  `AuthProfile`. No provider key exists anywhere; garak's litellm never enters
  the generator (`assert_no_litellm`).

## Known live bugs and gaps (at the wave B4 push)

Attributed by the wave B4 e2e files and left open (the README "Open items and
not implemented" is the single list):

- `redsim/ml/targets/endpoint.py:228`: `EndpointTarget.load` sends the 8-row
  probe as unscaled uint8 values, refused by the `float32_nchw` rule, so no
  endpoint reaches `available` through the tiny server (three cases of
  `tests/e2e/test_ml_endpoint.py`).
- The worker parent does not call `materialize_consumed_slice` when it builds
  the target detail, so a campaign on a consumed-bound model does not run end
  to end (`tests/e2e/test_ml_interop.py`; INTEROP-16 remainder).
- No route derives `architecture_kwargs` from the dataset binding, so a
  `small_cnn` `state_dict` for a dataset with other than 10 classes is refused
  at validation (`tests/e2e/test_ml_bulk.py`; spec 9.2).
- `redsim/ml/pdf.py` raises reportlab's `LayoutError` on a 13-column
  measurement table; the completion path degrades to the text formats with
  `pdf_unavailable` recorded, `POST /v1/runs/{id}/report.render` still raises
  on such a record.
- Three stale pins the completion render made stale, to be moved by their
  owners: `tests/ml/test_audit_campaign.py:113` (`formats` now includes
  `pdf`), `tests/e2e/test_ml_verify_upload_reports.py` (uploads and report
  formats: `report.pdf` is no longer `404` after a campaign),
  `tests/e2e/test_ml_review_reports.py` (the
  completion snapshot is version 1, the on-demand render version 2).

Platform gaps unchanged from earlier passes: the `audit_events` table is not
under RLS (only `0004_audit_append_only` touches it); `make lint-py` runs a
bare `ruff check` wider than CI; `redsim scan` and `redsim/cli/api_client.py`
still post to `/v1/scans` (404 since P0); `docs/architecture/overview.md`
carries pentest-era sections.

## Test doubles

- `tests/ml/fakes.py`: `TinyTarget` (id `tiny`, 8x8x3, three classes) and
  `TinyTabularTarget`; `tests/ml/fakes_text.py`: `TinyTextTarget`;
  `tests/ml/fakes_detection.py`: `TinyDetector`;
  `tests/ml/tiny_endpoint_server.py`: `TinyEndpointServer` (`endpoint-v1`
  over `TinyTarget`); `tests/ml/fake_openai_server.py` (the fake gateway);
  `tests/ml/fake_foundry_server.py` (Foundry Datasets v2, a JWT-shaped fake
  token assembled from segments). There is no attack fake: the tests run the
  real adapters on the tiny targets.
- `tests/ml/fixtures/`: `run_record.json` (the frozen campaign response shape,
  sha256 `25be404f…`), `run_record_phase_b.json`, `MANIFEST.json`,
  `malicious_urls_sample.csv`, `cifar10_test_500.npz`, `sms_spam_sample.tsv`,
  `synonyms_tiny.json`, `public_index.csv`. `tests/ml/_campaign_pre_refactor.py`
  is the frozen pre-refactor `run_campaign` for the golden test. Fixture data
  is never served as a result.
- `tests/ml/conftest.py` has an autouse fixture that isolates every ML test
  from a developer's `.env`; `tests/conftest.py` skips `garak`-marked items
  at collection when the extra is absent.
- `tests/e2e/`: `conftest.py` and `harness.py` stamp every item `e2e` and skip
  unless `REDSIM_E2E` is set; the fixtures build a tiny synthetic asset tree
  with the real builders, run FastAPI over one autocommit sqlite connection
  with eager Celery and the real sandbox child, provide one dev-token client
  per role, a parent-side mocked Pythia transport, the real `redsim audit
  verify --all` as a subprocess and `REDSIM_E2E_POSTGRES_URL` for the RLS
  lane. Files: `test_harness_smoke.py` (wave 3), `test_ml_campaigns.py`,
  `test_ml_verify_upload_reports.py`, `test_ml_governance.py` (wave 4),
  `test_ml_endpoint.py`, `test_ml_llm.py`, `test_ml_text_detection.py`,
  `test_ml_attacks_harden.py`, `test_ml_review_reports.py`,
  `test_ml_interop.py`, `test_ml_bulk.py` (wave B4). `tests/e2e/README.md`
  describes every fixture and the worktree rule.
