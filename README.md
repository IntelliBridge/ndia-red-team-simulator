# redsim (Adversarial ML Red-Team Simulator)

redsim stress-tests a machine-learning classifier under adversarial evasion
attacks before anyone relies on it. A user picks a model (a bundled sample or
an uploaded ONNX or PyTorch `state_dict` artifact), launches an attack campaign
(ART attacks such as FGSM, PGD and HopSkipJump across an epsilon sweep, each
paired with a benign random-noise control), and reads the SHAP explanation and
the candidate hardening recommendations side by side, with every step recorded
on a hash-chained audit log. It is a non-operational proof of concept on open,
unclassified, public data. It evaluates and hardens the robustness of a
classifier and nothing else: it never trains, optimizes or deploys targeting or
weapons models, it connects to no mission system, it applies defenses only to
an evaluation copy inside a campaign, and no score or grade it produces is a
safety, readiness or certification statement. Measurements, per-sample
observations, inferred interpretation and candidate recommendations are kept
in separate fields and separate UI panels, and every succeeded run carries its
limitations.

The product is built as one new vertical, `redsim/ml/`, inside the redsim
platform. This repository is a fork of IntelliBridge's aegis security platform
with the penetration-testing domain removed and, since 2026-09-08, every
identifier renamed to redsim (see Provenance).

## Status

As of 2026-09-08 (late evening), `main` at `7240220`. The decisions behind this
table are in [`docs/project-brief.md`](docs/project-brief.md) under
"Decisions taken", the target design is the
[product spec](docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md),
and the workstream status is section 4.1 of the
[master plan](docs/plans/00-master-plan.md). Anything that does not hold on
the deployed stack is listed here as not implemented, never simulated in the
UI.

| Area | State on `main` |
|---|---|
| redsim platform (inherited from aegis): FastAPI `/v1` API (`redsim.api.app:create_app`), Celery workers (`redsim.workers.celery_app`), Postgres with Alembic migrations `0001` to `0010`, Redis, S3/MinIO blob store, Keycloak/NextAuth auth, RBAC and Postgres RLS, hash-chained audit log with WORM export, per-task LLM routing and budgets, OTel observability and `redsim-log-ingest` | Restored and green. `create_app()` mounts 23 HTTP routes under `/v1` plus `/health` and the run-events WebSocket. `pytest -q` = 1198 passed, 30 skipped, and the web vitest suite is 274 passed. ruff (CI selection) and mypy are clean from the venv. Counts, commands and the CI state on `main` are in [`CLAUDE.md`](CLAUDE.md). |
| Pentest domain (14 scanner adapters, Kali, CAI agents, GitHub remediation, ticketing, CI gate) | Deleted for good. The seams it filled fail explicitly rather than pretend: `GET /v1/scanners` returns an empty roster, `POST /v1/scans` is unmounted (404), `redsim scan --scanner X` exits 1 without writing a findings file, the web Start scan button is disabled behind a notice, target ownership verification answers 501, and `redsim doctor` lists the adapter roster as information only. |
| ML vertical contracts (milestone M0 / plan P0, merged as #18) | On main: `redsim/ml/schema.py` frozen (`CampaignConfig`, `ScoringConfig`, `MRIRecord`, `MLModelManifest`, `MLFindingDetail`, `RunRecord`, `CampaignRecord`, `STAGES` with `score`, `standing_limitations()`), the `Target` and `AttackAdapter` protocols, migration `0010_ml_vertical` (`targets.detail`, `ml_campaigns` with RLS parity), the seven ML `Action` members and the `viewer` role, the `redsim ml build-assets` CLI entry point (real since #9, next row), and a test that the API process imports no ML library. |
| ML vertical implementation: model loaders, sandboxed loader child, FGSM / PGD / HopSkipJump adapters, noise control, epsilon sweep, evaluation, MRI scoring, SHAP explainers, recommendation rules and Pythia narrative, bundled `SmallCNN` and URL feature extractor, real `build-assets` | On main since 2026-09-08. #8 `feat/ml-core` merged as `ce33d21`: targets, defenses, datasets, the ART adapters `fgsm`, `pgd`, `hopskipjump` and the `noise_control` control, the epsilon sweep, evaluation, MRI scoring, the campaign runner, SHAP explainers, the interpretation and recommendation rules and the Pythia narrative. #9 `feat/ml-assets` merged as `1725728`: `SmallCNN`, `url_features`, the real `redsim ml build-assets` and `MANIFEST.json` on `MLModelManifest`. `import redsim.ml.targets, redsim.ml.attacks` registers the targets `cifar10_smallcnn`, `endpoint_stub`, `url_trees`, `vehicles_cnn` and the attacks `fgsm`, `hopskipjump`, `noise_control`, `pgd`. The sandboxed loader child is WS4 work. Attacks run from Python and the tests only, no task or route drives them yet (next row). |
| ML orchestration and API (WS4): Celery tasks `model.validate`, `attack.run`, `explain.run`, `harden.recommend`, the ML branch of `verify.replay`, the admission services, `/v1/models`, `/v1/attacks`, `/v1/datasets`, `/v1/defenses`, `/v1/ml/capabilities`, `/v1/runs/{id}/campaign`, `/v1/runs/{id}/artifacts`, `/v1/artifacts/{id}`, `/v1/runs/{id}/compare` | Not started. Listed as planned in [`docs/api/v1.md`](docs/api/v1.md). |
| Pythia LLM transport (`redsim/llm/pythia.py`, `python -m redsim.llm.pythia_check`) | Merged (#11) and verified on 2026-09-08 behind the corporate proxy: 27 entitled models listed, one chat completion OK. Reads `REDSIM_ML_LLM_MODEL`. See [`docs/ops/pythia.md`](docs/ops/pythia.md). |
| Web app `@redsim/web` (Next.js 14) and `@redsim/design-system` | Platform pages present: `/`, `/login`, `/dashboard`, `/runs`, `/runs/[id]`, `/findings`, `/findings/[id]`, `/projects`, `/projects/[slug]/settings`, `/targets`, `/auth-profiles`, `/logs`, `/audit`, `/cost`. The P5 pages landed with #16 (`1a9204e`, 2026-09-08): `/models`, `/models/[id]`, the MRI scorecard and panels on `/runs/[id]`, the three-pane `/findings/[id]`, and `MriScorecard`, `DimensionBars`, `RobustnessCurve`, `MeasurementTable`, `ObservationCard` in the design system. They call the WS4 routes, which are not mounted, and show an explicit `not_implemented` state on 404 or 501. #16's ten review findings were fixed before merge. #21 (`ea39f97`) restored the web toolchain: the dependabot #15 bump is reverted (Next 14, React 18, TypeScript 5), `deploy/Dockerfile.web` installs pnpm with `npm install -g` on `node:26`, and the `viewer` role is in the Keycloak realm export and in the design-system `ROLES` with 0-based ranks. Both web CI jobs were green at `ea39f97` and have not run on main since (skipped behind the failing unit job, see [`CLAUDE.md`](CLAUDE.md)). |
| Deployment: `deploy/docker-compose.yml`, `deploy/helm/redsim`, `deploy/Dockerfile.*`, `deploy-aws.yml` | Compose (postgres, redis, keycloak, minio, redsim-api, redsim-worker, redsim-worker-default, redsim-beat, redsim-web, redsim-log-ingest, optional opa / otel-collector / loki / jaeger / elasticsearch / kibana) and the Helm chart are named `redsim-*`. `Dockerfile.api` installs `.[api,worker]` and runs `alembic upgrade head`, `Dockerfile.worker` installs CPU torch then `.[worker,ml]`. `deploy-aws.yml` fails at the OIDC AssumeRole step (account-side). ECS Fargate (WS7): #19 merged as `b40f7e1` (2026-09-08) with the code-only Terraform foundation under `deploy/terraform/` (existing-VPC checks, private endpoints, an ALB with target groups but no listeners, RDS PostgreSQL 16, Redis, two S3 buckets, per-service IAM roles, mocked-plan tests behind `validate.sh`). No task definitions, no services, nothing applied. |
| Demo data | Decided and buildable. `redsim ml build-assets --dataset all` fetches the datasets by pinned revision and trains the bundled models on CPU. Everything it writes under `assets/` is gitignored, so a fresh clone has none until it runs the build (see Get started). Clean accuracy per model is recorded in the asset manifest. |
| Docs site (`mkdocs.yml`, `make docs-*`) | `mkdocs build --strict` passes locally and in the Docs workflow. GitHub Pages publishing is off (the plan has no private Pages). |

## Architecture at a glance

Three layers, described in full in
[section 8 of the product spec](docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md#8-architecture).
The interactive diagrams live under `docs/architecture/diagrams/` and open as
pages on the docs site:

- [`redsim-platform.architecture.html`](docs/architecture/diagrams/redsim-platform.architecture.html):
  the deployed services and the data plane.
- [`attack-campaign.sequence.html`](docs/architecture/diagrams/attack-campaign.sequence.html):
  one campaign from `POST /v1/models/{id}/attacks` through the worker, the
  sandbox child and Pythia.
- [`campaign-run.lifecycle.html`](docs/architecture/diagrams/campaign-run.lifecycle.html):
  run, job and finding states and the stage progression.

1. **redsim platform.** Browser to `@redsim/web` (Next.js, NextAuth against
   Keycloak, dev-token mode allowed for the demo) to `redsim-api` (FastAPI
   `/v1`, RBAC through `redsim/api/policy.py`, tenant GUC for Postgres RLS,
   CSRF, rate limit, request-id correlation). Every mutating call appends a
   hash-chained audit event before it writes `Run` and `Job` rows and before it
   touches Celery. Postgres holds runs, jobs, findings, artifacts, campaign
   records and the audit chain, S3/MinIO holds bytes, Redis is the Celery
   broker and the live-event channel behind `/v1/runs/{id}/events`.
2. **`redsim/ml/` vertical.** Runs only on the worker. `attack.run`,
   `explain.run`, `harden.recommend` and the ML branch of `verify.replay` load
   the model inside a sandboxed child process (separate process, rlimits,
   wall-clock kill, no network), run ART attacks and SHAP, compute the MRI per
   campaign, and write `Measurement`, `Observation`, `Interpretation` and
   `CandidateRecommendation` records plus `Artifact` rows. The API process
   never imports torch, ART, onnxruntime or SHAP (a test enforces it).
3. **Pythia.** The only LLM transport. The `harden.recommend` task sends
   metrics and a SHAP text summary, never images or model bytes, to
   `{PYTHIA_BASE_URL}/v1/chat/completions` under redsim's per-task routing and
   budget caps. No provider key exists anywhere in the deployment.

## Get started

### Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Python | 3.12.x | `pyproject.toml` requires 3.12 or newer. `torch` and `adversarial-robustness-toolbox` wheels lag newer interpreters, so 3.12 is the working choice and the one the images pin. |
| uv | any recent | `/opt/homebrew/bin/uv` on the team laptops. The local `.venv` is created by uv and has no `pip` module, so use `uv pip ...` or `.venv/bin/python -m ...`, never `.venv/bin/pip`. |
| Node.js | 20 or newer | |
| pnpm | 10 | Workspaces are declared in `pnpm-workspace.yaml` (`web`, `packages/design-system`). The lockfile is the root `pnpm-lock.yaml`. |
| Docker | 24 or newer, Compose v2 | Only for the full stack (`make up`). |

Behind a corporate TLS proxy (Zscaler and similar), uv needs the system trust
store: pass `--native-tls` to every `uv` command, for example
`uv pip install --native-tls -e ".[api,worker,test,dev,ml]"`. The Dockerfiles
under `deploy/` copy any `.pem` / `.crt` files from `deploy/certs/` into the
image trust store for the same reason, and the Pythia client trusts the OS
store by default (see Pythia below).

### Install

```bash
make install
```

Creates `.venv` when it is missing (pyenv's newest 3.12.x, then `python3.12`
on `PATH`, then `python3`), installs the Python package with the extras in
`EXTRAS` (default `api,worker,test,dev,ml`, override with
`EXTRAS=api,worker,test,dev,ml,docs make install`), and runs `pnpm install`
for the two workspaces. It uses `uv pip install --native-tls` when uv is on
`PATH` and falls back to `ensurepip` plus pip otherwise. Re-running it is
safe. To do the same by hand:

```bash
uv venv --python 3.12 .venv
uv pip install --native-tls -e ".[api,worker,test,dev,ml]"
pnpm install
```

The extras are `api`, `worker`, `test`, `dev`, `security`, `docs`, `ml`
(numpy, torch, torchvision, onnx, onnxruntime, scikit-learn, ART, onnx2torch,
safetensors, SHAP, matplotlib, pillow, pyarrow, httpx), `llm` (the optional
private `pythia-sdk`, not needed because `redsim/llm/pythia.py` falls back to
an in-repo httpx client) and `garak` (Phase B only).

### Build the bundled ML assets

```bash
.venv/bin/redsim ml build-assets --dataset all
```

Fetches the datasets of spec section 11 by pinned revision, trains the
bundled `SmallCNN` models and the URL classifier on CPU with a fixed seed,
and writes `assets/MANIFEST.json`. Everything under `assets/` except its
README is gitignored, so each clone builds its own. The Kaggle download
reads `KAGGLE_API_TOKEN` from the environment or from `.env`
(`REDSIM_ENV_FILE`), or the older `KAGGLE_USERNAME` / `KAGGLE_KEY` pair,
and falls back to the committed CI sample when neither is set.
`--dataset cifar10` needs no token. `--epochs` (default 3), `--only
<model_id>`, `--out` and `--cache-dir` are the other knobs. Clean accuracy
per model is recorded in the manifest.

### Run

```bash
make dev
```

Runs the Python tests once as a sanity check, then serves the API and the web
app together under `make -j` in the foreground. The web app is at
<http://localhost:3000>, the API at <http://localhost:8000> (`/docs` and
`/health` outside prod). With no `REDSIM_DB_URL` set the API still boots and
`/health` reports `db_configured=false`, but every database-backed route
raises until Postgres and Redis are up and the `REDSIM_*` variables from
`.env.example` are exported (`cp .env.example .env`, then
`set -a; source .env; set +a` in the shell that runs `make dev`).

The Celery worker is a separate target, `make dev-worker`, because it needs
Redis, Postgres and the `ml` extra up front. Run it in a second terminal once
the stack is up, or `make -j dev-api dev-web dev-worker`.

Full stack in containers:

```bash
make up          # docker compose -f deploy/docker-compose.yml up -d --build
make down        # docker compose ... down
```

`redsim-api` runs `alembic upgrade head` on start. The finer helpers live in
`deploy/Makefile` (`cd deploy && make seed` creates `default-org`, project
`default` and user `admin`, `make token-for` mints a dev bearer token when
`REDSIM_AUTH_MODE=dev`, plus `logs`, `psql`, `rebuild`, `down-clean`, `up-obs`).
Ports: web `3300`, API `8000`, Keycloak `8080`, Postgres `5432`, Redis `6379`,
MinIO `9100` / `9101`, log ingest `4319`. `docker compose --profile obs up -d`
adds OTel Collector, Loki and Jaeger. The worker image installs
`.[worker,ml]` (CPU-only torch wheels first), so expect it to be the slowest
to build.

### Pythia

Every LLM call goes through Pythia. Set these on the worker that runs
`harden.recommend` (the `default` queue) when the narrative should run:

| Variable | Meaning |
|---|---|
| `PYTHIA_BASE_URL` | Gateway base URL. The client posts to `{PYTHIA_BASE_URL}/v1/chat/completions`. |
| `PYTHIA_API_KEY` | `pk_...` gateway key, sent as `Authorization: Bearer`. The only LLM credential anywhere. |
| `PYTHIA_PERSONA` | Optional, sent as `X-Pythia-Persona`. |
| `PYTHIA_TIMEOUT_S` | Optional request timeout, default 60. |
| `REDSIM_ML_LLM_MODEL` | Canonical model id, `<vendor>/<model>` or `pythia/auto`, for the hardening narrative. `AEGIS_ML_LLM_MODEL` and `REDSIM_LLM_MODEL` are read as deprecated aliases. |

When any required variable is missing the narrative is skipped, not faked:
recommendations render from the rule layer with `narrative_source = "rules"`
and the UI says so. Do not set provider keys (`OPENAI_API_KEY` and friends
still appear in `.env.example` from aegis and are unused by this vertical).
The values live in `.env` at the repo root, which is gitignored and
dockerignored, and the Aikido pre-commit hook scans staged files for secrets.

Behind the corporate TLS proxy the client verifies against the OS trust store
by default (`REDSIM_TLS_TRUSTSTORE=1` through the `truststore` package), or
against `REDSIM_CA_BUNDLE` / `SSL_CERT_FILE` when that is turned off. Prove
the gateway is reachable before debugging narrative code:

```bash
.venv/bin/python -m redsim.llm.pythia_check              # lists /v1/models, runs one chat completion
.venv/bin/python -m redsim.llm.pythia_check --skip-chat  # only GET /v1/models
```

The full runbook, including what the check printed on 2026-09-08 and the
entitled model list, is [`docs/ops/pythia.md`](docs/ops/pythia.md).

### Datasets

Every dataset is open, unclassified, publicly available and carries a license
stated on its distribution page (spec section 11). Nothing is committed: the
one-off `redsim ml build-assets` run (see Get started) fetches them and
trains the bundled models locally.

Other teams obtain the Phase A data from the public GitHub repository
[IntelliBridge/ai-red-teaming-data](https://github.com/IntelliBridge/ai-red-teaming-data)
(commit `ff6a36b`, CC BY 4.0 for the repository's own contents, upstream
licenses kept per file): the military vehicles parquet (9,444 JPEGs as
bytes, MIT), the full malicious-URLs CSV (651,191 rows, CC0) and its
128,224-row seeded eval split, with `INDEX.csv` hashes and a
`MANIFEST.json`. No models and no CIFAR-10 are published. The public URL
CSVs are redacted copies: credential-shaped query-parameter values are
replaced with the literal `REDACTED` in 2,346 of 651,191 rows (406 of
128,224 in the eval split), with row count, order and labels unchanged.
The private build trains on the unredacted Kaggle file, so metrics
re-derived from the public copy differ slightly on those 0.36 percent of
rows (spec section 11.7).

| Role | Dataset | Modality | License | Notes |
|---|---|---|---|---|
| Demo image dataset | `leibnitz-lab/military_vehicles` (HuggingFace), coarse 7-class task | image | MIT (dataset card) | Ground-level photographs, not aerial imagery. Photo copyright is not cleared by the MIT tag, so images are not redistributed in public releases or reports. |
| Image CI fixture | `uoft-cs/cifar10` (HuggingFace), test split, pinned 500-image subset | image | CIFAR-10 terms | Tests only, never a demo dataset or a result. |
| Demo tabular dataset | Kaggle `sid321axn/malicious-urls-dataset` (`malicious_phish.csv`) | tabular | CC0 (Kaggle metadata API) | Lexical URL features only. URL strings are data and are never fetched, resolved or rendered as links. The download needs a Kaggle API token for the one `redsim ml build-assets` run (`KAGGLE_API_TOKEN`, or the older `KAGGLE_USERNAME` / `KAGGLE_KEY` pair), never on the API, web, steady-state worker or CI. A committed stratified sample under `tests/ml/fixtures/` serves CI. |
| Tabular fallback | `lacg030175/UNSW-NB15` (HuggingFace), config `standard` | tabular | CC-BY-4.0 | Used only if the Kaggle download cannot be completed on the day. |
| Unit-test double | `TinyTarget` in `tests/ml/fakes.py` | image | in-repo | Random-weight 1-conv net, no download. |

### Make targets

| Target | What it runs |
|---|---|
| `make install` | Venv, `uv pip install --native-tls -e ".[$(EXTRAS)]"` (or pip), `pnpm install` |
| `make require-install` | Fails fast with one clear line when `.venv` or `node_modules` is missing. Every dev, test, lint and typecheck target depends on it. |
| `make dev` | pytest, then `dev-api` and `dev-web` under `make -j` |
| `make dev-api` | `uvicorn redsim.api.app:create_app --factory --reload --port 8000` |
| `make dev-web` | `pnpm --filter @redsim/web dev` on :3000 |
| `make dev-worker` | `celery -A redsim.workers.celery_app worker -Q scans,default`. Not on the `dev` line, needs Redis and Postgres first. |
| `make test` | `pytest -q` plus `pnpm --filter @redsim/web test` |
| `make test-cov` | pytest with `--cov=redsim --cov-report=term-missing` |
| `make lint` | `lint-py` (`ruff check redsim tests`) then `lint-web` (`next lint`, printed as a skip line while `web/` has no ESLint config) |
| `make typecheck` | `typecheck-py` (`mypy redsim`) then `typecheck-web` (`tsc --noEmit`) |
| `make check` | lint, typecheck, test |
| `make up` / `make down` | `docker compose -f deploy/docker-compose.yml up -d --build` / `down` |
| `make docs-serve` / `docs-build` / `docs-build-strict` / `docs-clean` | MkDocs Material on :8001. The recipes call `mkdocs` from `PATH`, so activate the venv or pass `MKDOCS=.venv/bin/mkdocs`. |

Recipes call the venv interpreter by path, so no target needs an activated
shell. `make check` mirrors the lint, typecheck and test jobs of
`.github/workflows/redsim-ci.yml`, with one difference: CI runs ruff with
`--select E4,E7,E9,F,I`, and `make lint-py` runs the bare `ruff check`. The
CI contract is in [`docs/dev/ci.md`](docs/dev/ci.md).

### Tests

```bash
.venv/bin/python -m pytest -q                                   # 1198 passed, 30 skipped on main 7240220
.venv/bin/ruff check --select E4,E7,E9,F,I redsim tests         # lint, exactly as CI
.venv/bin/mypy redsim                                           # types
pnpm --filter @redsim/web typecheck                             # tsc --noEmit
pnpm --filter @redsim/web test                                  # vitest, 274 passed on main 7240220
```

Markers are declared in `pyproject.toml`. `unit` and `integration` run by
default. The `integration` tests use the shared sqlite harness in
`tests/conftest.py` and need no running services. `docker`, `e2e`, `slow` and
`auth_required` are opt-in with `-m` (they need Docker, a live stack, or the
Keycloak cookie flow), and `pytest -m ml` selects the tests that need the `ml`
extra. The engine-unavailable paths listed under Status are pinned by tests
(`tests/test_cli_commands_coverage.py`, `tests/test_m6_dispatch.py`,
`tests/test_api_routes_coverage.py`, `tests/test_doctor.py`), so a faked empty
result fails the suite rather than passing as a clean run.

## Layout

```
redsim/                 Python package (renamed from aegis on 2026-09-08)
  api/                  FastAPI app factory, /v1 routers, middleware, auth, policy
  audit/                hash-chained audit log: chain, writers, forensic export, redaction
  cli/                  `redsim` console script: doctor, audit verify/export, plugins, ml build-assets, ...
  db/                   SQLAlchemy models, session, Alembic migrations 0001-0010
  llm/                  per-task routing, budgets, pricing, guardrails, Pythia transport and check
  log_ingest/           OTLP logs to Postgres mirror service
  migrate/              filesystem to Postgres migration helpers
  ml/                   the adversarial-ML vertical: frozen schema, Target and AttackAdapter protocols
  policy/               static / OPA / Cedar policy engines behind the RBAC check
  scanners/             registry, capability vocabulary, out-of-process plugin sandbox
  services/             admission services (audit event, Run/Job rows, enqueue)
  state/                run-state facade: filesystem and Postgres backends
  storage/              blob store: filesystem, S3/MinIO, WORM export
  supply_chain/         plugin signing
  workers/              Celery app, bootstrap, job state machine, tasks/
web/                    Next.js 14 app (@redsim/web): app router pages, NextAuth, api() client
packages/design-system/ @redsim/design-system: curated components over shadcn primitives
tests/                  pytest suite (unit and integration markers), tests/ml/ for the vertical
deploy/                 docker-compose.yml, Dockerfile.{api,worker,web,postgres,log_ingest}, helm, keycloak, opa, cedar, otel, loki, certs
docs/                   product spec, project brief, plans, platform architecture docs and diagrams, ADRs, ops and dev guides
specs/                  Spec Kit feature layer: F001-F008 plus _shared/ (decisions, architecture, readiness)
.specify/               Spec Kit constitution and templates
.github/                redsim-ci.yml, deploy-aws.yml, docs.yml, release-sign.yml, dependabot
hooks/                  mkdocs build hooks (README as the docs index, cross-tree links)
exports/                ai-assurance-spec-pack.zip (spec pack export)
alembic.ini             Alembic entry point for redsim/db/migrations
redsim.yaml             default runtime configuration read by redsim/config.py
mkdocs.yml              docs site configuration
pyproject.toml          package metadata, extras, pytest markers, ruff and mypy settings
pnpm-workspace.yaml     web and packages/design-system workspaces
```

## Documentation

Read in this order. Where two documents disagree, the earlier one in this list
wins.

| Doc | What it is |
|---|---|
| [`docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`](docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md) | The consolidated product spec, 27 sections: scope and phasing, domain model, architecture, model loading and isolation, datasets, attacks, SHAP, MRI scoring, recommendations, API surface, web UI, deployment, testing, milestones, completion criteria. |
| [`docs/project-brief.md`](docs/project-brief.md) | Governance brief. Its reporting principles are design constraints, and its "Decisions taken (2026-09-08)" section records the product owner's decisions and every knowing divergence. |
| [`specs/README.md`](specs/README.md) and `specs/00N-*/` | Spec Kit feature layer beneath the product spec: F001 project access through F008 audit and governance, each with `spec.md`, `plan.md`, `tasks.md`. `specs/_shared/` holds the decision register, the shared architecture and the readiness checklist. |
| [`docs/plans/00-master-plan.md`](docs/plans/00-master-plan.md) and `docs/plans/01` to `08` | The coordination plan: workstreams WS0 to WS7 and their status, corrected shared contracts, integration waves, and one phase file per plan step. Section 8 of [`01-p0-contracts-api-skeleton.md`](docs/plans/01-p0-contracts-api-skeleton.md) is the change protocol for everything P0 froze. |
| [`docs/spec-driven-workflow.md`](docs/spec-driven-workflow.md) | How the team works spec-first with Spec Kit's stages. The Spec Kit CLI is not installed. |
| [`docs/architecture/diagrams/`](docs/architecture/diagrams/README.md) | The current pictures: platform architecture, attack-campaign sequence, campaign-run lifecycle. |
| [`docs/architecture/overview.md`](docs/architecture/overview.md), [`auth.md`](docs/architecture/auth.md), [`audit-chain.md`](docs/architecture/audit-chain.md), [`multi-tenancy.md`](docs/architecture/multi-tenancy.md), [`observability.md`](docs/architecture/observability.md) | Platform architecture inherited from aegis. `auth`, `audit-chain`, `multi-tenancy` and `observability` still hold. `overview.md` still carries pentest-era sections (scanner adapters, CAI agents, Kali toolbelt) that no longer exist. |
| [`docs/api/v1.md`](docs/api/v1.md) | The mounted `/v1` routes with their gates, and the planned ML routes marked as such. |
| [`docs/dev/local-stack.md`](docs/dev/local-stack.md), [`testing.md`](docs/dev/testing.md), [`ci.md`](docs/dev/ci.md), [`frontend.md`](docs/dev/frontend.md), [`extending.md`](docs/dev/extending.md), [`docs.md`](docs/dev/docs.md) | Developer guides: the compose stack, test plumbing, the CI contract, the web workspace, the extension points (registries, `Target` and `AttackAdapter`, defenses, plugins), the docs build. |
| [`docs/ops/deploy.md`](docs/ops/deploy.md), [`kubernetes.md`](docs/ops/kubernetes.md), [`pythia.md`](docs/ops/pythia.md), [`compliance-evidence.md`](docs/ops/compliance-evidence.md) | Operator guides: production env vars, keys and rotation, the Helm chart, the LLM gateway, the evidence pack. |
| [`docs/adr/0002-registry-seam-and-runners.md`](docs/adr/0002-registry-seam-and-runners.md), [`docs/adr/0004-unified-effect-class-gate.md`](docs/adr/0004-unified-effect-class-gate.md) | The two seams the ML attack adapters reuse: the registry that `redsim.ml.attacks` registers into (dispatch by name or capability, entry-point plugins, signing, sandbox) and the effect-class gate (`redsim/effects.py`). Written for the pentest domain, kept as history. The other ADRs ([`0001`](docs/adr/0001-vendored-submodules.md), [`0005`](docs/adr/0005-worker-autoscaling-and-dr.md), [`0008`](docs/adr/0008-nix-reproducible-builds.md)) record platform decisions. |
| [`SECURITY.md`](SECURITY.md), [`CONTRIBUTING.md`](CONTRIBUTING.md), [`CHANGELOG.md`](CHANGELOG.md) | Security model and boundaries, contribution rules and gates. `CHANGELOG.md` is the aegis release history up to the fork. |

Superseded and kept for history only: `docs/adversarial-ml-redteam-spec.md`
(and its `.html`) and `docs/superpowers/specs/2026-09-08-redsim-design.md`.

## Team conventions

- Commits are `type(topic): description` with the trailer
  `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Branch before committing. Never commit to `main` directly. The repository
  allows squash merges only and deletes the branch on merge.
- Work spec-first: a changed requirement updates the spec before
  implementation continues. See
  [`docs/spec-driven-workflow.md`](docs/spec-driven-workflow.md) and the
  readiness checklist in `specs/_shared/`.
- Anything P0 froze (schema fields, migration head, `Action` values, the
  campaign response shape, `REDSIM_ML_LLM_MODEL`) changes only through the
  protocol in section 8 of `docs/plans/01-p0-contracts-api-skeleton.md`.
- Prose in docs and comments avoids em dashes and semicolons.
- No fixture data is ever presented as a result, and unimplemented paths are
  shown as unavailable with a reason, never faked.

## Provenance

This repository is `IntelliBridge/ndia-red-team-simulator`, forked from
`IntelliBridge/aegis` (restored from aegis head `5eb24ca` and then pruned).

Removed for good: the 14 pentest scanner adapters, `aegis/agents`,
`aegis/tools`, `aegis/integrations`, `aegis/remediate`, `aegis/runners`, the
Kali image, the CAI agents, the GitHub App and webhooks, ticketing, the CI
gate, demo and vendor tooling, every git submodule, and the `agents` and
`tools` web pages.

Names: on 2026-09-08 the product owner amended decision D7 and every
identifier was renamed to redsim (commit `b39d933`). The Python namespace is
`redsim` (`import redsim...`), the console script is `redsim`, environment
variables are `REDSIM_*`, the API title is "Redsim API", the session and CSRF
cookies are `redsim_api_session` and `redsim_csrf` with the `X-Redsim-CSRF`
header, the compose services, images and Helm chart are `redsim-*` and
`deploy/helm/redsim`, the web workspace packages are `@redsim/web` and
`@redsim/design-system`, the config file is `redsim.yaml`, and the product and
UI name is redsim. `aegis` survives only as the name of the upstream fork.

License: Apache-2.0.
