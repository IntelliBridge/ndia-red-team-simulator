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
The earlier lean "strip aegis down to a `redsim` package" design is retired.

## Authoritative docs, in order

1. `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`. The
   consolidated product spec, 27 sections. Section 8 is the architecture,
   section 9 model loading and isolation, section 11 the datasets, section 17
   the API surface, section 18 the web UI, section 20 deployment, section 22
   testing, section 23 milestones, section 26 completion criteria.
2. `docs/project-brief.md`. Governance brief. Its reporting principles are
   design constraints. "Decisions taken (2026-09-08)" records every decision
   and every knowing divergence from the brief and the constitution.
3. `specs/README.md` and `specs/00N-*/` (F001 to F008) with
   `specs/_shared/` (decision register, shared architecture, readiness
   checklist). Feature layer beneath the product spec. Where a feature file
   and the product spec conflict, the product spec wins.
4. `docs/plans/00-master-plan.md`, John Sasser's coordination plan
   (workstreams WS0 to WS7, integration waves, corrected shared contracts,
   workstream status), plus the phase files `docs/plans/01-…` to `08-…`.
   Section 8 of `docs/plans/01-p0-contracts-api-skeleton.md` is the change
   protocol for everything P0 froze.
5. `docs/architecture/*`. Platform docs inherited from aegis. `auth.md`,
   `audit-chain.md`, `multi-tenancy.md` and `observability.md` still describe
   the platform. `overview.md` still carries pentest-era sections (scanner
   adapters, CAI agents, Kali toolbelt, tool catalog) that no longer exist.
   The current pictures are the diagrams under `docs/architecture/diagrams/`.
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
  `b39d933`): the earlier "Python stays aegis" position is superseded, and
  `aegis` survives only as the name of the upstream fork.
- Web workspace packages: `@redsim/web` (in `web/`) and
  `@redsim/design-system` (in `packages/design-system/`). Web environment
  variables are `NEXT_PUBLIC_REDSIM_*`.
- Compose services and images are `redsim-*`, the Helm chart is
  `deploy/helm/redsim`, the CI workflow is `.github/workflows/redsim-ci.yml`.
- Mentions of `aegis` that refer to the upstream project or to history (fork
  provenance, "restored from the aegis head", the ADRs) are correct and stay.
  Anything that describes this package, its paths, env vars, CLI, services,
  cookies or chart says redsim.

## What exists and what is not written yet

Verified on `main` at `7240220` (2026-09-08, late evening) by importing the
app, listing the router objects, importing the ML registries and running
the suite with `.venv/bin/python`.

### On main

- `redsim.api.app:create_app()` mounts the routers `health`, `runs`,
  `runs_cancel`, `findings`, `audit`, `reports`, `scanners`, `verify`,
  `targets`, `auth_profiles`, `projects`, `logs`, `org_cost` and the
  WebSocket router: 23 HTTP routes under `/v1`, `GET /health`,
  `WS /v1/runs/{id}/events`, `GET /v1/__settings` (non-prod), `/metrics`,
  `/docs`. `POST /v1/scans` was unmounted by P0 and answers 404.
  `tests/test_api_process_has_no_ml.py` builds the app in a subprocess with
  `torch`, `torchvision`, `art`, `onnx`, `onnxruntime`, `shap`, `sklearn`
  and `xgboost` blocked and asserts it still serves `/health`.
- `redsim.workers.celery_app` loads six tasks: `redsim.scan_start` and
  `redsim.verify_replay` on the `scans` queue, `redsim.report_render`,
  `redsim.reap_stale_jobs`, `redsim.verify_tenant_integrity` and
  `redsim.export_chains_to_worm` on `default`. Beat runs the reaper every
  5 minutes, tenant integrity hourly, WORM export on `REDSIM_WORM_INTERVAL`.
- `redsim/db` models plus Alembic migrations `0001` to `0010`.
  `0010_ml_vertical` (P0) adds `targets.detail` JSONB and the `ml_campaigns`
  table with full RLS parity (denormalized `org_id`, BEFORE INSERT backfill
  trigger, BEFORE UPDATE drift guard, `FORCE ROW LEVEL SECURITY`, the
  `redsim_tenant_isolation` policy).
- `redsim/api/policy.py`: roles `viewer` (0) < `scanner` < `remediator` <
  `approver` < `admin`. `Action` members `scan.start`, `verify.replay`,
  `target.manage`, `auth_profile.manage`, `audit.verify`, `run.cancel` and
  the seven P0 additions `model.register` (remediator), `attack.run`
  (scanner), `explain.run` (scanner), `harden.recommend` (remediator),
  `finding.review` (approver), `finding.annotate` (remediator),
  `report.export` (scanner). `redsim/policy` holds the static, OPA and Cedar
  engines.
- `redsim/audit` (chain, forensic, redaction), `redsim/api/middleware`
  (tenant GUC for RLS, CSRF, rate limit), `redsim/llm` (router, budget,
  pricing, guardrails, `pythia.py`, `pythia_check.py`), `redsim/storage`
  (filesystem, S3, WORM), `redsim/state`, `redsim/services`,
  `redsim/scanners` (registry, `KNOWN_CAPABILITIES`, out-of-process plugin
  sandbox, no adapters registered), `redsim/registry.py`, `redsim/plugins.py`,
  `redsim/supply_chain/signing.py`, `redsim/cli` (`doctor`, `init`, `scan`,
  `findings`, `verify`, `report`, `status`, `audit verify|export`,
  `tenants verify`, `plugins list|sign`, `ml build-assets`, `evidence-pack`,
  `migrate`), `redsim/log_ingest`, `redsim/observability.py`.
- `redsim/ml/`: `schema.py` is FROZEN by P0 (`TargetInfo`, `AttackInfo`,
  `ParamSpec`, `CampaignConfig`, `ScoringConfig`, `MRIWeights`,
  `DefenseConfig`, `Provenance`, `Measurement`, `Observation`,
  `Interpretation`, `Subscores`, `MeasuredDelta`, `MRIDelta`,
  `CandidateRecommendation`, `MRIInputRow`, `MRIRecord`, `MLModelManifest`,
  `MLFindingDetail`, `AtlasTechnique`, `RobustnessCurve`, `RunRecord`,
  `CampaignRecord`, `RunSummary`, `STAGES` including `score`,
  `STANDING_LIMITATIONS` and `standing_limitations()`, `grade_for_mri`,
  `contains_banned_score_word`). `targets/base.py` (`Target` protocol,
  `Sample`) and `attacks/base.py` (`AttackAdapter`, `AttackOutput`) are the
  frozen protocols.
- `redsim/ml/` implementation, merged on 2026-09-08 from #8 `feat/ml-core`
  (`ce33d21`) and #9 `feat/ml-assets` (`1725728`): `registry.py`,
  `artifacts.py`, `errors.py`, `defenses.py`, `eval.py`, `scoring.py`,
  `campaign.py`, `targets/` (`registry.py`, `architectures.py` with
  `SmallCNN`, `bundled.py`, `tabular.py`, `artifact.py`, `unavailable.py`),
  `attacks/` (`registry.py`, `fgsm.py`, `pgd.py`, `hopskipjump.py`,
  `noise_control.py`), `datasets/` (`cifar10.py`, `image_hub.py`,
  `sampling.py`, `url_features.py`), `explain/` (`base.py`, `shap_image.py`,
  `shap_tabular.py`, `stability.py`, `summary.py`), `recommend/` (`rules.py`,
  `narrative.py`) and `assets/` (`datasets.py`, `build.py`, `train_cnn.py`,
  `train_url_classifier.py`, `fixture_sample.py`, `manifest.py`).
  `import redsim.ml.targets, redsim.ml.attacks` registers the targets
  `cifar10_smallcnn`, `endpoint_stub`, `url_trees`, `vehicles_cnn` and the
  attacks `fgsm`, `hopskipjump`, `noise_control`, `pgd`. `redsim ml
  build-assets` is implemented (`redsim/cli/ml.py` over
  `redsim/ml/assets/build.py`): it fetches the datasets by pinned revision,
  trains the bundled models on CPU with a fixed seed and writes
  `assets/MANIFEST.json` on `MLModelManifest`. `tests/ml/` holds `fakes.py`
  (`TinyTarget`), `fixtures/` (`run_record.json`, `malicious_urls_sample.csv`,
  `MANIFEST.json`), the schema, fixture and CLI tests and the module tests,
  with an autouse fixture in `tests/ml/conftest.py` that isolates every ML
  test from a developer's `.env`. The sandbox child `redsim/ml/sandbox.py`
  is not written (WS4).
- Web `@redsim/web` pages: `/`, `/login`, `/dashboard`, `/runs`,
  `/runs/[id]`, `/findings`, `/findings/[id]`, `/projects`,
  `/projects/[slug]/settings`, `/targets`, `/auth-profiles`, `/logs`,
  `/audit`, `/cost`, and since #16 merged as `1a9204e` (2026-09-08) the P5
  pages `/models` and `/models/[id]` plus the MRI panels on `/runs/[id]` and
  the three-pane `/findings/[id]`, with `MriScorecard`, `DimensionBars`,
  `RobustnessCurve`, `MeasurementTable`, `ObservationCard`, `LabelBadge`,
  `PanelSection` and `CompatibilityList` in `@redsim/design-system`. The P5
  pages call the WS4 routes (`/v1/models`, `/v1/models/{id}/attacks`, the
  campaign, artifacts and compare routes), which are not mounted, and render
  an explicit `not_implemented` state on 404 or 501 (`7240220` tightened
  that wording). `web/src/lib/api.ts` defaults to `http://localhost:8000`,
  overridable with `NEXT_PUBLIC_REDSIM_API_URL`.
- `deploy/docker-compose.yml`: postgres, redis, keycloak, minio, redsim-api,
  redsim-worker (`-Q scans`), redsim-worker-default (`-Q default`),
  redsim-beat, redsim-web, redsim-log-ingest, plus opt-in profiles `policy`
  (opa), `obs` (otel-collector, loki, jaeger) and `obs-search`
  (elasticsearch, kibana). `deploy/Dockerfile.api` installs `.[api,worker]`
  and runs `alembic upgrade head` before uvicorn, `deploy/Dockerfile.worker`
  installs CPU torch then `.[worker,ml]`. `deploy/helm/redsim` is the chart.
  `deploy-aws.yml` builds api, worker and web images for ECR.
  `deploy/terraform/` (#19, merged as `b40f7e1` on 2026-09-08) is the
  code-only Fargate foundation: existing-VPC selection with checks, private
  endpoints, an ALB with target groups but no listeners, RDS PostgreSQL 16,
  Redis, two S3 buckets, per-service IAM roles, and mocked-plan tests run by
  `deploy/terraform/validate.sh`. No task definitions, no services, nothing
  applied.

### Merged late on 2026-09-08, after the ML PRs

No pull request is open. The last two merges of the evening:

- #16 `feat/replit-redsim-migration` (Metz, P5 v2 web UI, WS5) as
  `1a9204e`: the P5 pages and design-system components listed above.
  codex-pr-review verdict blocking with 10 confirmed findings, one fix
  commit per finding landed on the branch before the squash merge, and
  `7240220` (product owner) tightened the `not_implemented` and
  compatibility wording on the model pages afterwards. The web CI lanes have
  not run on `main` since `ea39f97` (skipped downstream of the failing unit
  job, see Verified state), so nothing from #16 has been built by CI on
  `main` yet.
- #19 `feat/p7-fargate-foundation` (William, WS7) as `b40f7e1`: the 26 new
  files under `deploy/terraform/`. codex-pr-review verdict needs-changes
  with 2 confirmed findings, both fixed on the branch before merge.

### Datasets and assets: built locally, not committed

The catalog is decided (spec section 11): image demo
`leibnitz-lab/military_vehicles` (HF, MIT, coarse 7-class task, ground-level
photographs), image CI fixture `uoft-cs/cifar10`, tabular demo Kaggle
`sid321axn/malicious-urls-dataset` (CC0, URL strings are data and are never
fetched, committed stratified sample for CI), tabular fallback
`lacg030175/UNSW-NB15` (CC-BY-4.0, unused so far). On 2026-09-08
`redsim ml build-assets --dataset all` fetched the three used datasets by
pinned revision and trained `vehicles_cnn`, `cifar10_smallcnn` (1-epoch
fixture, never a demo target) and `url_classifier` (the asset behind the
`url_trees` target, trained on the full Kaggle set) on CPU. Everything
under `assets/` except `assets/README.md` is gitignored, so a fresh clone
has no assets until it runs the build. The Kaggle download reads
`KAGGLE_API_TOKEN` (sent as a bearer token) from the environment or from
`.env` (`REDSIM_ENV_FILE`), or the older `KAGGLE_USERNAME` / `KAGGLE_KEY`
pair, and falls back to the committed CI sample when neither is set. Clean
accuracy per model and the per-class counts are recorded in
`assets/MANIFEST.json`. Quote them from the manifest of the build in hand,
never as a product claim in docs.
The Phase A datasets are also published for other teams at
https://github.com/IntelliBridge/ai-red-teaming-data (public, commit `ff6a36b`,
spec 11.7). Its URL CSVs are redacted copies (credential-shaped query
values replaced with `REDACTED` in 0.36 percent of rows, so their hashes
differ from the manifest) while the local build trains on the unredacted
Kaggle file, so metrics re-derived from the public copy differ slightly.

### Not started

- WS4: Celery tasks `redsim.model_validate`, `redsim.attack_run`,
  `redsim.explain_run`, `redsim.harden_recommend` and the ML branch of
  `redsim.verify_replay` (`redsim/workers/tasks/{model_validate,attack,
  explain,harden}.py`), the ML sandbox child (`redsim/ml/sandbox.py`,
  `redsim/ml/sandbox_worker.py`), the admission services
  `redsim/services/{ml_models,ml_campaigns,ml_findings}.py` and the routes
  `redsim/api/v1/{models,attacks,datasets,defenses,ml_capabilities,
  artifacts,compare,ml_findings}.py` (`/v1/models`, `/v1/models/{id}/attacks`,
  `/v1/attacks`, `/v1/datasets`, `/v1/defenses`, `/v1/ml/capabilities`,
  `/v1/runs/{id}/campaign`, `/v1/runs/{id}/artifacts`, `/v1/artifacts/{id}`,
  `/v1/runs/{id}/compare`, `/v1/runs/{id}/reviewer-notes`, explain and harden
  on findings).
- WS5 remainder: the P5 pages are on main (#16) but every ML call they make
  goes to an unmounted WS4 route, so no page shows real campaign data until
  WS4 lands. CI has not built them on main yet.
- WS6 reports and compare. WS7 services: the Terraform foundation (#19) has
  no listeners, task definitions or services, and nothing has been applied.

## How to run things

- Python 3.12 only. The venv is `.venv`, created with uv, and it has NO `pip`
  module. Run Python as `.venv/bin/python`. Install with uv:
  `uv pip install --native-tls -e ".[api,worker,test,dev,ml]"`. uv is at
  `/opt/homebrew/bin/uv` and needs `--native-tls` behind the corporate TLS
  proxy. Never call `.venv/bin/pip`. Do not install packages while other
  agents share the venv.
- Extras in `pyproject.toml`: `api`, `worker`, `test`, `dev`, `security`,
  `docs`, `ml` (numpy, torch, torchvision, onnx, onnxruntime, scikit-learn,
  ART, onnx2torch, safetensors, SHAP, matplotlib, pillow, pyarrow, httpx),
  `llm` (optional private `pythia-sdk`, `redsim/llm/pythia.py` falls back to
  httpx), `garak` (Phase B only).
- Tests: `.venv/bin/python -m pytest -q`. The default `-m` from `addopts`
  excludes `docker`, `e2e`, `slow` and `auth_required`. `pytest -m ml` runs
  the tests that need the `ml` extra, `pytest -m integration` the sqlite or
  Postgres-backed ones.
- Lint and types, exactly as CI runs them:
  `.venv/bin/ruff check --select E4,E7,E9,F,I redsim tests` and
  `.venv/bin/mypy redsim`. A bare `ruff check` applies ruff's much larger
  default set and is not the contract.
- Web: pnpm 10 workspace at the repo root. `pnpm --filter @redsim/web dev`
  (:3000), `pnpm --filter @redsim/web typecheck`, `pnpm --filter @redsim/web
  test` (vitest), `pnpm --filter @redsim/design-system typecheck`.
- Make targets: `install` (venv, then `uv pip install --native-tls
  --python .venv/bin/python -e ".[$(EXTRAS)]"` with `EXTRAS` defaulting to
  `api,worker,test,dev,ml`, pip fallback, `pnpm install`),
  `require-install`, `dev` (pytest, then `dev-api` + `dev-web` under
  `make -j`), `dev-api` (`uvicorn redsim.api.app:create_app --factory
  --reload --port 8000`, boots without Postgres or Redis but only `/health`,
  `/docs` and `/metrics` work until they are up), `dev-web`, `dev-worker`
  (`celery -A redsim.workers.celery_app worker -Q scans,default`, needs Redis,
  Postgres and the `ml` extra, deliberately not on the `dev` line), `test`,
  `test-cov` (`--cov=redsim`), `lint`, `lint-py`, `lint-web`, `typecheck`,
  `typecheck-py`, `typecheck-web`, `check` (lint, typecheck, test), `up`
  (`docker compose -f deploy/docker-compose.yml up -d --build`), `down`,
  `docs-serve`, `docs-build`, `docs-build-strict`, `docs-clean` (call
  `mkdocs` from `PATH`, so activate the venv or pass
  `MKDOCS=.venv/bin/mkdocs`).
- Full stack: `make up` at the root runs compose directly. `deploy/Makefile`
  has the finer helpers (`cd deploy && make seed`, `token-for`, `whoami`,
  `psql`, `logs`, `rebuild`, `down`, `down-clean`, `up-obs`). `redsim-api`
  runs `alembic upgrade head` on start. Ports: web 3300, API 8000, Keycloak
  8080, Postgres 5432, Redis 6379, MinIO 9100/9101, log ingest 4319.
  `REDSIM_AUTH_MODE=dev` dev tokens (`Bearer dev:<email>`) are allowed for
  the demo.
- Environment names are in `.env.example` (`REDSIM_DB_URL`, `REDSIM_BROKER_URL`,
  `REDSIM_RESULT_BACKEND`, `REDSIM_BLOB_BACKEND`, `REDSIM_S3_*`,
  `REDSIM_AUTH_MODE`, `REDSIM_OIDC_*`, `REDSIM_CORS_ORIGINS`,
  `REDSIM_PLUGINS_SANDBOX`, `REDSIM_DISABLE_LLM`, `REDSIM_LLM_BUDGET_STRICT`,
  the four Pythia variables). The `OPENAI_API_KEY`-style entries there are
  aegis leftovers and are read by nothing in the ML vertical.

## LLM access: Pythia only

Every LLM call goes through Pythia (`redsim/llm/pythia.py`, merged in PR
#11). redsim's per-task router and budget caps stay the policy layer, Pythia
is the only transport. No litellm, no direct provider keys anywhere.
`docs/ops/pythia.md` is the full runbook.

| Variable | Meaning |
|---|---|
| `PYTHIA_BASE_URL` | Gateway base URL, posts go to `{PYTHIA_BASE_URL}/v1/chat/completions`, the model list to `{PYTHIA_BASE_URL}/v1/models`. |
| `PYTHIA_API_KEY` | `pk_...` key sent as `Authorization: Bearer`. The only LLM secret redsim holds. |
| `PYTHIA_PERSONA` | Optional, sent as `X-Pythia-Persona`. |
| `PYTHIA_TIMEOUT_S` | Optional, default 60. |
| `REDSIM_ML_LLM_MODEL` | Canonical model id (`<vendor>/<model>` or `pythia/auto`). `AEGIS_ML_LLM_MODEL` and the scaffold name `REDSIM_LLM_MODEL` are read as deprecated aliases with a `DeprecationWarning`. |
| `REDSIM_ENV_FILE` | Path of the `.env` to read (default `./.env`, then the repo root). The client parses it itself, no python-dotenv. A process variable always wins over the file. |
| `REDSIM_TLS_TRUSTSTORE` | Default on: verify TLS against the OS trust store through `truststore`. `0` falls back to `REDSIM_CA_BUNDLE` or `SSL_CERT_FILE`, then certifi. |

If any required variable is missing, `PythiaSettings.from_env()` returns
`None`, the recommendation keeps `narrative = None` and
`narrative_source = "rules"`, and the UI says "Narrative unavailable". Never
fake a narrative. The writer receives metrics and a SHAP text summary only,
never images, model bytes or dataset rows. `.env` is gitignored and
dockerignored, and the key is never logged (`PythiaSettings.redacted()` is the
only view that reaches provenance).

Behind the corporate TLS proxy (Zscaler) the gateway is reached through an
inspecting proxy. `curl` succeeds because it uses the macOS keychain, a plain
httpx client fails with `CERTIFICATE_VERIFY_FAILED`. The client's default
truststore mode handles this on a laptop, containers get the proxy root from
`deploy/certs/`. Prove the gateway before debugging narrative code:

```bash
.venv/bin/python -m redsim.llm.pythia_check              # reads ./.env
.venv/bin/python -m redsim.llm.pythia_check --skip-chat  # only GET /v1/models
```

Verified 2026-09-08 from a laptop behind Zscaler with persona `default`: 27
entitled models listed, one chat completion OK (`pythia/auto` resolved to
`amazon/nova-micro-v1:0`). Compose passes the four Pythia variables through to
`redsim-api` and the worker pool with `${VAR:-}`. The worker anchor also sets
`REDSIM_DISABLE_LLM: "1"`, which has to be unset on `redsim-worker-default`
before a compose stack can produce a narrative.

## Pre-commit hook (Aikido)

`git config core.hooksPath` points at `~/.git-hooks`, whose `pre-commit` runs
`aikido-local-scanner pre-commit-scan` on the repo. The restored aegis
redaction and guardrail test fixtures (for example `tests/test_otel_redaction.py`,
`tests/test_llm_guardrails.py`, `tests/test_audit_chain.py`,
`tests/test_evidence_pack.py`) contain deliberately fake secrets and trip the
scanner. Use `AIKIDO_SKIP_PRE_COMMIT=1 git commit ...` only for commits that
touch those fixtures, and say so in the commit message. Do not skip the hook
for anything else, and never add a real credential to make a test pass.

## Verified state (2026-09-08 late evening, main 7240220)

Counts come from running the commands from this tree with the venv
interpreter, not from memory. Re-run them before quoting them.

- `.venv/bin/python -m pytest -q`: 1198 passed, 30 skipped.
- `pnpm --filter @redsim/web test` (vitest): 274 passed in 41 files.
- `.venv/bin/ruff check --select E4,E7,E9,F,I redsim tests`: clean. A bare
  `ruff check redsim tests` reports three RUF100 findings (unused
  `noqa: E402` in `redsim/cli/main.py` and `redsim/ml/attacks/__init__.py`)
  that are outside the CI selection.
- `.venv/bin/mypy redsim`: clean, 172 source files, from a venv that has
  `truststore` and `torch` installed. CI's mypy step does not (next bullet).
- `make -n lint-web` shows the guard: `web/` has no `.eslintrc*` or
  `eslint.config.*`, so `lint-web` prints
  `skip: lint-web (web/ has no ESLint config yet, ...)` and exits 0. `make
  lint` and `make check` pass through the skip. The real fix is `eslint`
  plus `eslint-config-next` and a config in `web/`.
- Redsim CI on `main`: fully green at `ea39f97` (#21 restored the web
  toolchain, so `Next.js build` and `Build images` pass again, E2E skipped
  by design). Red on every run from `1725728` (#9) through `7240220`:
  both unit lanes fail at their mypy step with `no-any-return` in
  `redsim/ml/datasets/image_hub.py:55` (`truststore.SSLContext(...)` types
  as `Any` because `truststore` is in no pyproject extra and CI does not
  install it) and, on the 3.13 lane only, `redsim/ml/assets/train_cnn.py:172`
  (`model.eval()` is `Any` without the `ml` extra). Local mypy passes
  because the venv has both packages. `API integration`, `Next.js build`
  and `Build images` are skipped downstream of the failing `unit` job, so no
  commit after `ea39f97` has had the web lanes run on `main`, #16's pages
  included. The fix is a typed return in each function, or `truststore` in
  the extras, and is not on any branch yet.
- `Deploy to AWS` fails at "Configure AWS credentials" (OIDC AssumeRole,
  account-side). `Docs` is green, and the Pages deploy is dormant behind the
  repo variable `ENABLE_PAGES` (Pages is off, the plan has no private
  Pages).
- `mkdocs` 1.6.1 and Material are installed in `.venv` now.
  `.venv/bin/python -m mkdocs build --strict` passes in about 2 s.
  `docs/ops/pythia.md` and `docs/workstreams/pythia-access.md` are not in
  the `mkdocs.yml` nav (INFO only, readers cannot find them from the sidebar).
- Still stale outside this docs refresh: `docs/architecture/overview.md`
  (pentest sections), `CHANGELOG.md` (aegis release history),
  `docs/security/supply-chain.md` (points at `examples/redsim-plugin-example`,
  which is not in this tree), `web/components.json` (its `registry` points
  at the deleted `project_repos/shadcn-ui`), ADRs 0001, 0002 and 0004
  (history, keep).

## CI contract (`.github/workflows/redsim-ci.yml`)

- Lint: `ruff check --select E4,E7,E9,F,I redsim tests`. The explicit
  selection is deliberate, `pyproject.toml` only says `extend-select = ["I"]`
  and ruff 0.16's default set would report hundreds of findings that were
  never part of the contract.
- Types: `mypy redsim` with the strict settings in `pyproject.toml`
  (`disallow_untyped_defs`, `warn_return_any`, `warn_unused_ignores`,
  `ignore_missing_imports`).
- Tests: 3.12 installs the `ml` extra (CPU torch first) and runs
  `-m "not integration and not docker and not e2e and not slow and not
  auth_required"`, 3.13 runs without the extra and adds `and not ml`. ML
  test modules must `pytest.importorskip` their heavy imports so collection
  survives on 3.13.
- Coverage gate: the full default suite against Postgres 16 and Redis 7 with
  `--cov-fail-under=81` (`COV_FAIL_UNDER` in the job env). The floor is the
  local measurement minus 2. Raise it in the PR that merges each ML phase,
  never lower it without recording why in `docs/dev/ci.md`.
- Also: API integration (Postgres + Redis, `not ml`), SAST (semgrep
  `p/python` + `p/security-audit` at ERROR plus `.semgrep.yml`, bandit
  `-ll -ii`), dependency CVEs (`pip-audit --skip-editable`, trivy `v0.74.0`
  at HIGH,CRITICAL with `.trivyignore`), Helm lint plus six template renders
  including the prod-secret guard, OTel config validation, trufflehog
  (verified secrets only), `redsim_output` not committed, the Next.js build
  (frozen lockfile, design-system and web typecheck, vitest, `next build`),
  the four image builds (no push), and a Playwright stack E2E behind
  `workflow_dispatch` with `run_e2e=true`.
- `docs.yml`: `mkdocs build --strict` on docs changes. Pages deploy off.
- `deploy-aws.yml`: builds api, worker and web images for ECR under GitHub
  OIDC and rolls whichever `ECS_SERVICE_*` variables are set. It does not run
  the test gates.

## Working rules for this codebase

- Read a file immediately before editing it and make surgical edits. Another
  agent may have touched it since your last read.
- Nothing under `redsim/ml/` may be presented as working until it runs. Show
  unimplemented paths as `not_implemented` with a reason, never with
  placeholder results. Fixture data (CIFAR-10 slice, `TinyTarget`, the
  committed URL sample) is for tests only.
- The API process never imports torch, ART, onnxruntime or SHAP. Model bytes
  are opened only on the worker inside the sandbox child.
- Every mutating route appends its audit event before writing `Run`/`Job`
  rows and before touching Celery (`tests/test_admission_audit_before_enqueue.py`
  asserts the order).
- Measurements, observations, interpretation and candidate recommendations
  stay separate fields and separate panels. The `Literal` labels in
  `redsim/ml/schema.py` (`candidate`, `not evaluated`, `inferred`,
  `heuristic`) are part of the contract.
- The MRI is per campaign and never shown without its subscores, the
  per-family table with denominators and the epsilon curve. No expected gain
  on a recommendation until verify measures it.
- P0 froze `redsim/ml/schema.py` (every field name and type), migration head
  `0010_ml_vertical` and the `ml_campaigns` column set, the `Action` values
  and minimum roles, the `GET /v1/runs/{id}/campaign` shape in
  `tests/ml/fixtures/run_record.json`, and the name `REDSIM_ML_LLM_MODEL`.
  Change protocol (`docs/plans/01`, section 8): never rename a field, column,
  `Action` or response key silently, announce a change as a one-line note in
  master plan section 5 plus a heads-up to the team, and prefer an additive
  default-valued field over changing an existing one.

## Conventions

Commits are `type(topic): description` with the trailer
`Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Branch before
committing, never commit to `main` directly. The repository allows squash
merges only and deletes the branch on merge. Prose in docs and comments
avoids em dashes and semicolons. `docs/spec-driven-workflow.md` is the
spec-first process.
