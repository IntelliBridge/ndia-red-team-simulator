# Execution context — cold-start guide

Read this before executing any phase plan in a fresh session. It carries the
operational facts that are not in the phase files, and the order to read things.

Refreshed 2026-09-08 (night) against `main` at `bb43bd7` (completion waves 1
and 2 merged). Facts marked "(wave 3, landing 2026-09-09)" come from the wave 3
writers' reports and are not in that tree. Re-verify them before building on
them.

## Read order

1. **This file.**
2. **Canonical spec** — `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`.
   It is authoritative. Decisions D1-D13 (section 4) are final and override every
   other source. Sections 10 (job and worker flow, 10.5 audit vocabulary, 10.6
   failure classes), 17.3 (error codes) and 20.3 (environment variables) are
   the ones the tree is measured against most often.
3. **Master plan** — `docs/plans/00-master-plan.md`. Section 0 (v2.3) records
   what landed and the six divergences the tree keeps, section 4.1 the
   workstream and CI status, section 5 the shared contracts, section 8 where
   the definition of done stands.
4. **Gap register** — `docs/plans/09-gap-register-2026-09-08.md`, the
   spec-vs-tree register the completion waves work from. Its header paragraph
   gives the status after waves 1 to 3.
5. **Your phase file** — `docs/plans/0N-*.md`. `02`–`05` open with a dated
   Landed status block (what is on `main`, what lands with wave 3, what is
   open). The bodies below the blocks are the pre-merge plans.
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

On `main` at `bb43bd7` (`redsim/cli/main.py`):

- `redsim ml build-assets [--dataset {image,tabular,cifar10,all}] [--only MODEL_ID ...]
  [--epochs N] [--out DIR] [--cache-dir DIR] [--seed N] [--arch {small_cnn,resnet18}]
  [--image-size N] [--max-train N] [--max-eval N] [--xgboost | --no-xgboost]
  [--fixture [--fixture-out PATH] [--fixture-sidecar PATH] [--fixture-synthetic-ok]]`.
  Network access happens only here (HuggingFace hub by pinned revision, Kaggle
  with `KAGGLE_API_TOKEN` or the older `KAGGLE_USERNAME` / `KAGGLE_KEY` pair,
  else the committed CI sample). `--fixture` writes
  `tests/ml/fixtures/cifar10_test_500.npz` and its sidecar from local files
  and downloads nothing. `--cache-dir` wins over `REDSIM_ML_DATASET_CACHE`.
- `redsim audit verify [--run RUN_ID | --all]` and
  `redsim audit export [--all | --chain ID]`.
- `redsim doctor [--api-mode]`, `redsim init`, `redsim status`,
  `redsim tenants verify`, `redsim plugins list|sign`, `redsim evidence-pack`,
  `redsim migrate`, and the pentest-era `redsim scan`, `findings`, `verify`,
  `report`. `redsim scan` and `redsim/cli/api_client.py` still post to the
  unmounted `/v1/scans` and get 404.

Wave 3, landing 2026-09-09:

- `redsim ml attack <target_id>`: an offline campaign for a bundled target
  (assets from `REDSIM_ML_ASSETS_DIR` or `./assets`) that writes the
  `attack.run` audit row first on a `JsonlAuditWriter` chain, runs the
  sandbox child, and leaves `<out>/<run_id>/{run_record.json, report.md,
  report.json, report.html, robustness curve, audit.jsonl}`. `endpoint_stub`
  is refused with `not_implemented` and fixture-only targets with
  `fixture_only` before anything is written. No LLM call offline:
  `narrative_source = "rules"`. `redsim audit verify --run <run_id>` verifies
  the chain through the new `--run-dir` fallback.
- `redsim ml seed [--project ID] [--only MODEL_ID ...]`: registers every
  non-fixture manifest model through
  `redsim.services.ml_models.register_bundled_model` and reports registered
  versus already present.
- `redsim doctor` in worker mode (`--worker-mode`, or
  `REDSIM_DOCTOR_WORKER_MODE=1`) treats the `ml` extra, the sandbox child
  launch and the assets manifest as required. The Pythia block is
  informational with the key redacted, and no provider key is checked.

## Environment variables (spec 20.3)

Read by code on `main` at `bb43bd7`:

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

`.env.example` at `bb43bd7` documents the four Pythia variables,
`REDSIM_ML_LLM_MODEL` and `REDSIM_DISABLE_LLM` but none of the `REDSIM_ML_*`
knobs, and still carries provider-key placeholders (`GOOGLE_API_KEY`,
`OPENAI_API_KEY` and friends) that nothing in the ML vertical reads.
`redsim.yaml` still writes a provider-style `model`. Wave 3 (landing
2026-09-09) replaces both: `.env.example` documents every spec 20.3 variable
with empty values, drops the provider keys, and adds `REDSIM_ENV_FILE` and
`KAGGLE_API_TOKEN`. `redsim.yaml` and `redsim init` drop the provider model
and write `task_models: {}`.

## Local assets (illustrative, never results)

`redsim ml build-assets` output is gitignored under `assets/` (only
`assets/README.md` is tracked), so a fresh clone has no assets until it runs
the build. `assets/MANIFEST.json` is the only source of clean-accuracy
numbers. The build in hand on 2026-09-09 recorded: `url_trees`
(`sklearn_hist_gradient_boosting` on the full Kaggle malicious-URLs set) clean
accuracy 0.9087 on n=128224, surrogate agreement 0.7891. `vehicles_cnn` as
`resnet18` (ImageNet init from the local torch hub cache, 12 epochs, lr 3e-4
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
  push to `main` via OIDC. Its deploy job is dormant until the `ECS_*`
  variables are set, and it fails loudly rather than reporting a
  false-positive green deploy.
- `deploy/terraform/` (#19, `b40f7e1`) is the code-only Fargate foundation: no
  listeners, task definitions or services, nothing applied. Fargate, Terraform
  and Helm apply and compose operations are outside the completion pass
  (master plan section 8).
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
- Wave 3 (landing 2026-09-09) fixes six defects found by the offline CLI and
  the e2e harness: admission freezing `eps` (and PGD's `norm_l2`) into
  `attack_params` so the child refused every API-launched campaign, `pgd`
  refused on tabular targets by `AttackInfo.domain`, the audit chain `ts`
  re-derived on read so a sqlite chain failed to verify, the sandbox child
  able to read a checkout's `.env`, `redsim audit verify --run` unable to see
  the offline chain, and `GET /v1/attacks` not loading attack plugins. Until
  wave 3 is on `main`, an API-launched campaign against a bundled target fails
  at the child's config check.
- CI on `main` is red at the time of writing and under investigation (master
  plan section 4.1). Local checks at `bb43bd7`: 1594 passed and 30 skipped,
  ruff and mypy clean.

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
- `tests/e2e/` (wave 3, landing 2026-09-09): `conftest.py` and `harness.py`
  stamp every item `e2e` and skip unless `REDSIM_E2E` is set. Fixtures build a
  tiny synthetic asset tree, run FastAPI over sqlite with an eager Celery,
  provide one dev-token client per role, a mocked Pythia transport, and
  `REDSIM_E2E_POSTGRES_URL` for the RLS lane (skipped when unset). The test
  files themselves are wave 4.
