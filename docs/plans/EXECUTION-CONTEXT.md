# Execution context — cold-start guide

Read this before executing any phase plan in a fresh session. It carries the
operational facts that are not in the phase files, and the order to read things.

Refreshed 2026-09-09 against `main` at `58461cc` (completion waves 1 to 3
merged, wave 3 being `7556b22..58461cc`). Items marked "added in wave 4" are
being written in parallel and are not in that tree yet.

## Read order

1. **This file.**
2. **Canonical spec** — `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`.
   It is authoritative. Decisions D1-D13 (section 4) are final and override every
   other source. Sections 10 (job and worker flow, 10.5 audit vocabulary, 10.6
   failure classes), 17.3 (error codes) and 20.3 (environment variables) are
   the ones the tree is measured against most often.
3. **Master plan** — `docs/plans/00-master-plan.md`. Section 0 (v2.3 and
   v2.4) records what landed and the six divergences the tree keeps, section
   4.1 the workstream and CI status with the wave-3 shas, section 5 the
   shared contracts, section 8 where the definition of done stands.
4. **Gap register** — `docs/plans/09-gap-register-2026-09-08.md`, the
   spec-vs-tree register the completion waves work from. Its header paragraph
   gives the status after waves 1 to 3.
5. **Your phase file** — `docs/plans/0N-*.md`. `02`–`05` open with a dated
   Landed status block written at `bb43bd7` (what is on `main`, what lands
   with wave 3, what is open). Wave 3 is on `main` since `58461cc`, so read
   those wave-3 items as landed. The bodies below the blocks are the
   pre-merge plans.
6. **Feature detail** — `specs/F001`-`F008` (`spec.md`, `plan.md`, `tasks.md`).
   Where a feature file conflicts with the canonical spec, the spec wins.
7. **The code you will touch** — `redsim/ml/`, `redsim/api/v1/`, `redsim/workers/`,
   `redsim/services/`, `redsim/db/`.

## Repo ground truth

- The package is `redsim-platform` (formerly the `aegis` security platform,
  renamed to the `redsim` namespace on 2026-09-08). The ML vertical
  `redsim/ml/` is implemented on `main`: `schema.py` (frozen by P0),
  `registry.py`, `artifacts.py`, `errors.py` (with the spec 10.6 classes),
  `defenses.py`, `eval.py`, `scoring.py`, `campaign.py`, `reporting.py`,
  `sandbox.py` and `sandbox_worker.py` (the ML child), `targets/` (`base`,
  `registry`, `architectures`, `bundled`, `tabular`, `artifact`,
  `unavailable`), `attacks/` (`base`, `registry`, `fgsm`, `pgd`,
  `hopskipjump`, `noise_control`), `datasets/` (`cifar10`, `image_hub`,
  `sampling`, `url_features`), `explain/` (`base`, `shap_image`,
  `shap_tabular`, `stability`, `summary`), `recommend/` (`rules`,
  `narrative`) and `assets/` (`datasets`, `build`, `train_cnn`,
  `train_url_classifier`, `fixture_sample`, `manifest`).
  `import redsim.ml.targets, redsim.ml.attacks` registers the targets
  `cifar10_smallcnn`, `endpoint_stub`, `url_trees`, `vehicles_cnn` and the
  attacks `fgsm`, `hopskipjump`, `noise_control`, `pgd`.
- The platform side of the vertical: routes
  `redsim/api/v1/{ml_capabilities,attacks,datasets,defenses,models,artifacts,compare,ml_findings,reports,audit,verify,runs_cancel}.py`
  mounted under `/v1` on `redsim/api/app.py:create_app`, `redsim/api/errors.py`
  (the spec 17.3 code table), the services
  `redsim/services/{ml_models,ml_campaigns,ml_findings,reports}.py`, the
  tasks `redsim/workers/tasks/{ml_campaign,ml_model}.py`
  (`redsim.ml_campaign_run`, `redsim.ml_model_validate`, both on the `scans`
  queue) and the ML branch of `redsim.report_render`. There is no separate ML
  app and no per-attack Celery chain (master plan section 0, v2.3).
- The console script is `redsim = redsim.cli:main`. The earlier stripped-down
  standalone `redsim/` package is gone. This `redsim/` is the full platform
  under its new name.
- The API process never imports torch, ART, onnxruntime or SHAP
  (`tests/test_api_process_has_no_ml.py`). Model bytes are opened only in the
  sandbox child on the worker.
- Python is pinned to 3.12 (torch and ART have no 3.14 wheels). The venv is
  `.venv`, created with uv and without a `pip` module: run
  `.venv/bin/python`, install with
  `uv pip install --native-tls -e ".[api,worker,test,dev,ml]"`.
- Dev flow: `make install`, then `make dev`. `make check` runs lint, typecheck
  and tests. CI is `.github/workflows/redsim-ci.yml` (its state is in master
  plan section 4.1) and `docs.yml` runs `mkdocs build --strict`.
- Migrations `0001` to `0010`. `0010_ml_vertical` is the head. Neither PR #22
  nor the completion waves added a migration.
- Corporate TLS proxy (Zscaler): Python clients need the OS trust store.
  `redsim/llm/pythia.py` defaults to `truststore` (`REDSIM_TLS_TRUSTSTORE`),
  `uv` needs `--native-tls`, and `deploy/certs/README.md` covers containers.
  `docs/ops/pythia.md` is the gateway runbook. Do not hard-code one
  operator's certificate path.

## CLI surface

On `main` at `58461cc` (`redsim/cli/main.py`, `redsim/cli/ml.py`):

- `redsim ml build-assets [--dataset {image,tabular,cifar10,all}] [--only MODEL_ID ...]
  [--epochs N] [--out DIR] [--cache-dir DIR] [--seed N] [--arch {small_cnn,resnet18}]
  [--image-size N] [--max-train N] [--max-eval N] [--xgboost | --no-xgboost]
  [--fixture [--fixture-out PATH] [--fixture-sidecar PATH] [--fixture-synthetic-ok]]`.
  Network access happens only here (HuggingFace hub by pinned revision, Kaggle
  with `KAGGLE_API_TOKEN` or the older `KAGGLE_USERNAME` / `KAGGLE_KEY` pair,
  else the committed CI sample). `--fixture` writes
  `tests/ml/fixtures/cifar10_test_500.npz` and its sidecar from local files
  and downloads nothing. `--cache-dir` wins over `REDSIM_ML_DATASET_CACHE`.
- `redsim ml attack <target_id> [--attacks IDS] [--eps GRID] [--reference-eps E]
  [--n-samples N] [--seed N] [--explain-k K] [--no-control] [--norm linf|l2]
  [--out DIR] [--assets-dir DIR] [--actor A]` (`3ab9de7`): an offline
  campaign for a bundled target (assets from `REDSIM_ML_ASSETS_DIR` or
  `./assets`) that writes the `attack.run` audit row first on a
  `JsonlAuditWriter` chain, runs the sandbox child, and leaves
  `<out>/<run_id>/{run_record.json, report.md, report.json, report.html,
  artifacts/curve/robustness_curve.png, audit.jsonl}`. `endpoint_stub` is
  refused with `not_implemented` and fixture-only targets with
  `fixture_only` before anything is written. No LLM call offline:
  `narrative_source = "rules"`. `--out` defaults to the config
  `output_dir`, which is where `redsim audit verify --run <run_id>` looks.
- `redsim ml seed [--project ID] [--only IDS] [--assets-dir DIR] [--actor A]`
  (`3ab9de7`, `98a8733`): registers every non-fixture manifest model through
  `redsim.services.ml_models.register_bundled_model`, one commit per model,
  and reports registered versus already present. Needs `REDSIM_DB_URL`.
- `redsim audit verify [--run RUN_ID | --project ID | --all] [--run-dir PATH]`
  (`aa9674e`): `--run` falls back to `<output_dir>/<run_id>/audit.jsonl`
  when the primary store has no events for the chain, `--run-dir` names a
  run directory or `.jsonl` file directly. `redsim audit export
  [--all | --chain ID]` is unchanged.
- `redsim doctor [--api-mode] [--worker-mode]` (`7556b22`, `c3868e5`):
  worker mode (`--worker-mode` or `REDSIM_DOCTOR_WORKER_MODE=1`) treats the
  `ml` extra, the sandbox child launch and the assets manifest as required.
  The Pythia block is informational with the key redacted, and no provider
  key is checked.
- `redsim init`, `redsim status`, `redsim tenants verify`,
  `redsim plugins list|sign`, `redsim evidence-pack`, `redsim migrate`, and
  the pentest-era `redsim scan`, `findings`, `verify`, `report`.
  `redsim scan --scanner X` exits 1 when no adapter of that name is
  registered, and `ml-campaign` is the only registered name (`3ab9de7`).
  `redsim/cli/api_client.py` still posts to the unmounted `/v1/scans` and
  gets 404.

## Environment variables (spec 20.3)

Read by code on `main` at `58461cc`:

| Variable | Read by | Meaning |
|---|---|---|
| `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `PYTHIA_PERSONA`, `PYTHIA_TIMEOUT_S` | worker (`redsim/llm/pythia.py`) | The gateway. Missing required values skip the narrative (`narrative_source = "rules"`), never fake it. |
| `REDSIM_ML_LLM_MODEL` | worker | Canonical model id for `ml.harden_narrative`, seeded into `config.task_models`. `REDSIM_LLM_MODEL` and `AEGIS_ML_LLM_MODEL` are deprecated aliases. |
| `REDSIM_DISABLE_LLM` | worker | Truthy disables the narrative. Compose sets it on the worker anchor. |
| `REDSIM_ENV_FILE` | any process using `redsim.llm.pythia` | Path of the `.env` to read (default `./.env`, then the repo root). Tests pin it to a nonexistent path. |
| `REDSIM_TLS_TRUSTSTORE` | any Pythia client | Default on: verify TLS against the OS trust store. |
| `REDSIM_ML_ASSETS_DIR` | worker, sandbox child, `redsim ml` | Assets root (default `./assets`). Forwarded to the child. |
| `REDSIM_ML_DATASET_CACHE` | `redsim ml build-assets`, loaders | Dataset download cache. |
| `REDSIM_ML_WORK_DIR`, `REDSIM_ML_KEEP_WORK_DIR` | worker (`redsim/ml/sandbox.py`) | Root of the per-job work directories (mode 0700) and the keep-for-debugging switch. |
| `REDSIM_ML_SANDBOX_TIMEOUT_S`, `REDSIM_ML_SANDBOX_CPU_SECONDS`, `REDSIM_ML_SANDBOX_MEMORY_MB`, `REDSIM_ML_SANDBOX_FILESIZE_MB`, `REDSIM_ML_SANDBOX_THREADS` | worker (`MlSandboxConfig.from_env`) | Child ceilings (spec defaults 1200 s, 900 s, 4096 MB, 1024 MB, 2). Malformed values keep the default. |
| `REDSIM_ML_UPLOAD_MAX_MB` | api (`redsim/api/v1/models.py`) | Upload cap, enforced while the stream is read, `413 model_too_large`. |
| `REDSIM_ML_MAX_ADV_ARTIFACT_MB` | worker | Size above which the full adversarial slice is not retained. |
| `REDSIM_ML_EXPLAIN_CACHE` | sandbox child (`redsim/ml/explain/base.py`) | Explanation cache directory. Not in the spec 20.3 table, read by code. |
| `KAGGLE_API_TOKEN` (or `KAGGLE_USERNAME` / `KAGGLE_KEY`) | `redsim ml build-assets` only | Kaggle download credential. Never on the API, web or steady-state worker. |

`.env.example` (`7556b22`) documents the four Pythia variables,
`REDSIM_ML_LLM_MODEL`, `REDSIM_DISABLE_LLM`, `REDSIM_ENV_FILE`, every
`REDSIM_ML_*` knob above, `KAGGLE_API_TOKEN`, `REDSIM_E2E`, `REDSIM_E2E_LIVE`
and `REDSIM_PLUGINS`, all with empty values, and carries no provider-key
placeholder. `redsim.yaml` and `redsim init` write no provider-style `model`
and carry `task_models: {}`. The sandbox child additionally receives
`REDSIM_ENV_FILE=<work_dir>/no-env` (an absent file) and
`REDSIM_DISABLE_LLM=1` (`c3868e5`). Read by the tooling but not in the
file: `REDSIM_DOCTOR_WORKER_MODE`, and the e2e harness's
`REDSIM_E2E_POSTGRES_URL` and `REDSIM_E2E_SANDBOX`.

## Local assets (illustrative, never results)

`redsim ml build-assets` output is gitignored under `assets/` (only
`assets/README.md` is tracked), so a fresh clone has no assets until it runs
the build. `assets/MANIFEST.json` is the only source of clean-accuracy
numbers. The build in hand on 2026-09-09 recorded: `url_trees`
(`sklearn_hist_gradient_boosting` on the full Kaggle malicious-URLs set) clean
accuracy 0.9087 on n=128224, surrogate agreement 0.7891. `vehicles_cnn` as
`resnet18` (the `39126ce` recipe: ImageNet init from the local torch hub cache, 12 epochs, lr 3e-4
with cosine annealing, flip and crop augmentation, best epoch by a 10 percent
validation slice held out of the training split) clean accuracy 0.7687 on
n=1621 `test_coarse`. `cifar10_smallcnn` 0.6872, `fixture_only`, never a demo
target. These are illustrative numbers from one local build. Quote the
manifest of the build you have, never these.

## Conventions

- Branch before committing. Do not commit to `main` directly. The repository
  allows squash merges only.
- Commit messages are `type(topic): description`.
- Prose in docs and comments avoids em dashes and semicolons.
- Lint and types exactly as CI runs them:
  `.venv/bin/ruff check --select E4,E7,E9,F,I redsim tests` and
  `.venv/bin/mypy redsim`. Tests: `.venv/bin/python -m pytest -q` (the
  `addopts` marker expression deselects `docker`, `e2e`, `slow` and
  `auth_required`).

## AWS and CI already provisioned

Account `140381642432`, region `us-east-1`:

- A GitHub OIDC provider and IAM role `ndia-red-team-gha-deploy` (ECR push, ECS
  deploy, and PassRole to `ndia-red-team-*` task roles).
- ECR repositories `ndia-red-team/{api,web,worker}`.
- Repo variables set: `AWS_ACCOUNT_ID`, `AWS_REGION`, `AWS_DEPLOY_ROLE_ARN`,
  `ECR_REGISTRY`.
- `.github/workflows/deploy-aws.yml` builds the api, worker and web images on
  push to `main` via OIDC. The `58461cc` push built and pushed all three (the
  AssumeRole step had failed on the `bb43bd7` push). Its deploy job is
  skipped until `ECS_CLUSTER` is set, and it fails loudly rather than
  reporting a false-positive green deploy.
- `deploy/terraform/` (#19, `b40f7e1`) is the code-only Fargate foundation: no
  listeners, task definitions or services, nothing applied from this tree.
  Open PR #23 (`feat/p7-fargate-runtime`, William) adds `deploy/bootstrap/`
  and `deploy/runtime/` and reports a public HTTPS demo runtime at
  https://redsim.ndia.agiledefense.xyz applied to this account (migrations
  through `0010`, health, login and OIDC discovery 200, unauthenticated API
  401, workers at zero until a pinned asset bundle exists, demo users and
  memberships and real assets outstanding, automatic rollout disabled).
  `deploy/runtime/README.md` on that branch is the sequence. Fargate,
  Terraform and Helm apply and compose operations stay outside the
  completion pass (master plan section 8).
- **Action: rotate the bootstrap AWS access keys.** Keys were pasted in
  plaintext during setup and must be treated as compromised. The pipeline uses
  OIDC, not static keys.

## Scope decisions that bite

- The substrate is redsim: Postgres with RLS, Celery on Redis, Keycloak auth, the
  hash-chained audit log, and S3 (no EFS). See master plan section 2.
- **Interoperability is Phase B2, not Phase A.** Croissant dataset export, its
  consume side, MITRE ATLAS tagging, and Palantir/Lattice are specified in
  canonical section 27, off by default and not built. Routes return `501` until
  B2. `docs/plans/07-p6-interoperability.md` maps to Phase B2, off the Phase A
  critical path.
- Demo data is `leibnitz-lab/military_vehicles` (image, `vehicles_cnn`) and
  Kaggle `sid321axn/malicious-urls-dataset` (tabular, `url_trees` on lexical
  URL features, a Kaggle token at build time else the committed sample). URL
  strings are inert data and are never fetched, resolved or rendered.
  `lacg030175/UNSW-NB15` is the tabular fallback and has not been built.
  CIFAR-10 is a CI fixture only.
- The MRI is per-campaign only. Never show it without its five subscores, the
  per-family accuracy table, and the ε curve. The words "hardened",
  "deployment-ready", "certified", and "safe" are banned in score text. A
  recommendation carries no numeric gain until a verify run measures it.
- One job runs a whole campaign (`redsim.ml_campaign_run`). Do not build
  against the per-attack chain of spec 10.3. The divergence is recorded in
  master plan section 0 (v2.3).

## Known live bugs and gaps

- The `/audit` web page reads `GET /v1/audit/verify?all=1` and the API answers
  `{"chains": [...]}` since wave 2. The earlier shape mismatch is closed.
- The `audit_events` table is still not under RLS (only `0004_audit_append_only`
  touches it).
- `make lint-py` runs a bare `ruff check redsim tests`, a larger rule set than
  the CI selection. `make lint-web` skips with a visible line because `web/`
  has no ESLint config.
- `redsim scan` and `redsim/cli/api_client.py` still post to `/v1/scans` (404
  since P0).
- Fixed on `main` by wave 3, found by the offline CLI and the e2e harness:
  admission freezing `eps` (and PGD's `norm_l2`) into `attack_params` so the
  child refused every API-launched campaign, and `pgd` refused on tabular
  targets by `AttackInfo.domain` (`dd2bbd4`, applicability now by
  `modality:<domain>` capability tag), PGD by surrogate transfer refused by
  the `requires_gradients` check on `url_trees` (`58461cc`), the audit chain
  `ts` re-derived on read so a sqlite chain failed to verify (`aa9674e`,
  `canonical_ts`), the sandbox child able to read a checkout's `.env`
  (`c3868e5`), `redsim audit verify --run` unable to see the offline chain
  (`aa9674e`, `--run-dir`), and `GET /v1/attacks` not loading attack plugins
  (`c3868e5`).
- Known caveat in `GET /v1/attacks` (recorded in the route's docstring at
  `c3868e5`): when `redsim.scanners` was imported earlier in the same process
  with `REDSIM_PLUGINS=1`, its import already registered the group and the
  route's rows read `rejected: already registered` while the adapters are in
  the catalog. An idempotent loader is a wave-4 admission follow-up.
- CI on `main` is red at `58461cc` on the Coverage gate (`python-multipart`
  missing from the `api` extra), Unit tests (py3.13) and Dependency CVEs
  (`next` 14.2.35 advisory), the same three jobs as at `bb43bd7` (master plan
  section 4.1). Wave 4 lands the `python-multipart`, import-cycle and
  trivy-baseline fixes and records the 3.13 lane's eager torch import
  (`redsim/cli/ml.py` importing `redsim.ml.assets.build`) as still open in
  `docs/dev/ci.md`. Local checks at `58461cc`: 1663 passed and 30 skipped, 8
  e2e passed, ruff and mypy clean (190 files).

## Test doubles

- `tests/ml/fakes.py` holds `TinyTarget` (id `tiny`, a random-weight one-conv
  net on 8x8x3 inputs with three synthetic classes) and `TinyTabularTarget`
  (id `tiny_tabular`). There is no attack fake: the tests run the real
  adapters on the tiny targets. `AttackOutput` carries no predictions, so the
  pipeline computes adversarial predictions itself.
- `tests/ml/fixtures/`: `run_record.json` (the frozen campaign response
  shape), `MANIFEST.json` (the fixture sidecar), `malicious_urls_sample.csv`
  (the committed CI sample) and `cifar10_test_500.npz` (50 per class, seed 0,
  written by `build-assets --fixture`). Fixture data is never served as a
  result.
- `tests/ml/conftest.py` has an autouse fixture that isolates every ML test
  from a developer's `.env`.
- `tests/e2e/` (`35e71c7`, `a45a787`): `conftest.py` and `harness.py` stamp
  every item `e2e` and skip unless `REDSIM_E2E` is set. Fixtures build a tiny
  synthetic asset tree with the real builders, run FastAPI over one
  autocommit sqlite connection with eager Celery and the real sandbox child
  (`REDSIM_E2E_SANDBOX=child|inprocess`), provide one dev-token client per
  role, a parent-side mocked Pythia transport, the real `redsim audit verify
  --all` as a subprocess, and `REDSIM_E2E_POSTGRES_URL` for the RLS lane
  (skipped when unset, failing when unmigrated). `test_harness_smoke.py` (8
  cases, passing at `58461cc`) is the harness's own check. The
  completion-criteria files `test_ml_campaigns.py`,
  `test_ml_verify_upload_reports.py` and `test_ml_governance.py` are added
  in wave 4. `tests/e2e/README.md` describes every fixture.
