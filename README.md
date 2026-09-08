# redsim — Adversarial ML Red-Team Simulator

redsim stress-tests a machine-learning classifier under adversarial evasion
attacks before anyone relies on it. A user picks a model (a bundled sample or
an uploaded ONNX / PyTorch `state_dict` artifact), launches an attack campaign
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

The product is built as one new vertical, `aegis/ml/`, inside IntelliBridge's
aegis security platform. This repository is a fork of that platform with the
penetration-testing domain removed.

## Status

As of 2026-09-08. The decisions behind this table are in
[`docs/project-brief.md`](docs/project-brief.md) under "Decisions taken", and
the target design is the
[product spec](docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md).
Anything that does not hold on the deployed stack is listed here as not
implemented, never simulated in the UI.

| Area | State |
|---|---|
| aegis platform: FastAPI `/v1` API (`aegis.api.app:create_app`), Celery workers (`aegis.workers.celery_app`), Postgres with Alembic migrations (`alembic.ini`, `aegis/db/migrations`), Redis, S3/MinIO blob store, Keycloak/NextAuth auth, RBAC and Postgres RLS, hash-chained audit log, per-task LLM routing and budgets, OTel observability and `aegis-log-ingest` | Restored from aegis and importable: `create_app()` builds and the Celery app loads. A code fix-up is bringing the test suite back to green after the pentest removal. Current counts are in [`CLAUDE.md`](CLAUDE.md). |
| Pentest domain (14 scanner adapters, Kali, CAI agents, GitHub remediation, ticketing, CI gate) | Deleted for good. The seams it filled fail explicitly rather than pretend: `GET /v1/scanners` returns an empty roster, `POST /v1/scans` rejects every scanner name with 400, `aegis scan --scanner X` exits 1 without writing a findings file, the web Start scan button is disabled behind a notice, target ownership verification answers 501, dependency re-scan verification reports its engine unavailable, and `aegis doctor` lists the adapter roster as information only. `POST /v1/scans` stays mounted for the ML adapters and is scheduled for review at milestone M0. |
| ML vertical `aegis/ml/`: evidence schema (`schema.py`), `Target` and `AttackAdapter` protocols (`targets/base.py`, `attacks/base.py`), `explain/` and `recommend/` packages | Contracts only. The packages `explain/` and `recommend/` exist and are empty. |
| ML vertical: model loaders, sandboxed loader subprocess, FGSM / PGD / HopSkipJump adapters, noise control, epsilon sweep, SHAP explainers, Model Robustness Index (MRI) scoring, recommendation rules, Celery tasks (`model.validate`, `attack.run`, `explain.run`, `harden.recommend`, ML branch of `verify.replay`), `/v1/models`, `/v1/attacks`, `/v1/datasets`, `/v1/defenses`, `/v1/ml/capabilities`, `/v1/artifacts/{id}`, campaign and compare routes, `aegis ml build-assets` CLI, dataset catalog | Not implemented. Nothing under `aegis/ml/` runs an attack today. |
| Pythia LLM transport (`aegis/llm/pythia.py`, `tests/test_llm_pythia.py`) | Exists and tested. It reads `REDSIM_LLM_MODEL` today. The spec renames that variable to `AEGIS_ML_LLM_MODEL` at M0. |
| Web app `@redsim/web` (Next.js 14) and `@redsim/design-system` | Platform pages present: `/login`, `/dashboard`, `/runs`, `/runs/[id]`, `/findings`, `/findings/[id]`, `/projects`, `/projects/[slug]/settings`, `/targets`, `/auth-profiles`, `/logs`, `/audit`, `/cost`. ML pages (`/models`, `/models/[id]`, the MRI scorecard on `/runs/[id]`, the three-pane `/findings/[id]`) are not written. |
| Deployment: `deploy/docker-compose.yml` (postgres, redis, keycloak, minio, aegis-api, aegis-worker, aegis-worker-default, aegis-beat, aegis-web, aegis-log-ingest, optional opa / otel-collector / loki / jaeger / elasticsearch / kibana), `deploy/helm`, `deploy/Dockerfile.*` | Compose topology and Helm chart are the aegis ones and stay named `aegis-*`. `deploy/Dockerfile.api` copies `aegis/` and `alembic.ini`, installs `.[api,worker,ml]` and runs `alembic upgrade head` before uvicorn. `deploy/Dockerfile.web` builds `@redsim/web`. `deploy-aws.yml` builds api, worker and web images and rolls whichever ECS services are configured. Not yet exercised end to end on the restored tree. |
| Demo data | Decided, not fetched: open, unclassified aerial / military-vehicle imagery for the image classifier and the Kaggle malicious-URLs dataset (lexical features only, URLs are never fetched) for the tabular classifier. CIFAR-10 is the CI fixture, not a demo dataset. |
| Docs site (`mkdocs.yml`, `make docs-*`) | Config exists. Requires the `docs` extra, which the local venv does not install by default. |

## Architecture at a glance

Three layers, described in full in
[section 8 of the product spec](docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md#8-architecture).

1. **aegis platform.** Browser to `@redsim/web` (Next.js, NextAuth against
   Keycloak, dev-token mode allowed for the demo) to `aegis-api` (FastAPI
   `/v1`, RBAC through `aegis/api/policy.py`, tenant GUC for Postgres RLS,
   CSRF, rate limit, request-id correlation). Every mutating call appends a
   hash-chained audit event before it writes `Run` and `Job` rows and before it
   touches Celery. Postgres holds runs, jobs, findings, artifacts and the audit
   chain, S3/MinIO holds bytes, Redis is the Celery broker and the live-event
   channel behind `/v1/runs/{id}/events`.
2. **`aegis/ml/` vertical.** Runs only on the worker. `attack.run`,
   `explain.run`, `harden.recommend` and the ML branch of `verify.replay` load
   the model inside a sandboxed child process (separate process, rlimits,
   wall-clock kill, no network), run ART attacks and SHAP, compute the MRI per
   campaign, and write `Measurement`, `Observation`, `Interpretation` and
   `CandidateRecommendation` records plus `Artifact` rows. The API process
   never imports torch, ART, onnxruntime or SHAP.
3. **Pythia.** The only LLM transport. The `harden.recommend` task sends
   metrics and a SHAP text summary, never images or model bytes, to
   `{PYTHIA_BASE_URL}/v1/chat/completions` under aegis's per-task routing and
   budget caps. No provider key exists anywhere in the deployment.

## Get started

### Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Python | 3.12.x | `pyproject.toml` requires 3.12 or newer. `torch` and `adversarial-robustness-toolbox` do not publish wheels for newer interpreters yet, so 3.12 is the working choice. |
| uv | any recent | `/opt/homebrew/bin/uv` on the team laptops. The local `.venv` is created by uv and has no `pip` module, so use `uv pip ...` or `.venv/bin/python -m ...`, never `.venv/bin/pip`. |
| Node.js | 20 or newer | |
| pnpm | 10 | Workspaces are declared in `pnpm-workspace.yaml` (`web`, `packages/design-system`). |
| Docker | 24 or newer, Compose v2 | Only for the full stack (`make up`). |

Behind a corporate TLS proxy (Zscaler and similar), uv needs the system trust
store: pass `--native-tls` to every `uv` command, for example
`uv pip install --native-tls -e ".[api,worker,test,dev,ml]"`. The Dockerfiles
under `deploy/` copy any `.pem` / `.crt` files from `deploy/certs/` into the
image trust store for the same reason.

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
(torch, torchvision, onnx, onnxruntime, scikit-learn, ART, SHAP, matplotlib,
pyarrow, httpx), `llm` (the optional private `pythia-sdk`, not needed because
`aegis/llm/pythia.py` falls back to an in-repo httpx client) and `garak`
(Phase B only).

### Run

```bash
make dev
```

Runs the Python tests once as a sanity check, then serves the API and the web
app together under `make -j` in the foreground. The web app is at
<http://localhost:3000>, the API at <http://localhost:8000> (`/docs` and
`/health` outside prod). With no `AEGIS_DB_URL` set the API still boots and
`/health` reports `db_configured=false`, but every database-backed route
raises until Postgres and Redis are up and the `AEGIS_*` variables from
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

`aegis-api` runs `alembic upgrade head` on start. The finer helpers live in
`deploy/Makefile` (`cd deploy && make seed` creates `default-org`, project
`default` and user `admin`, `make token-for` mints a dev bearer token when
`AEGIS_AUTH_MODE=dev`, plus `logs`, `psql`, `rebuild`, `down-clean`, `up-obs`).
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
| `AEGIS_ML_LLM_MODEL` | Canonical model id, `<vendor>/<model>` or `pythia/auto`. The code still reads `REDSIM_LLM_MODEL` until the M0 rename lands. |

When any required variable is missing the narrative is skipped, not faked:
recommendations render from the rule layer with `narrative_source = "rules"`
and the UI says so. Do not set provider keys (`OPENAI_API_KEY` and friends
still appear in `.env.example` from aegis and are unused by this vertical).

### Make targets

| Target | What it runs |
|---|---|
| `make install` | Venv, `uv pip install --native-tls -e ".[$(EXTRAS)]"` (or pip), `pnpm install` |
| `make require-install` | Fails fast with one clear line when `.venv` or `node_modules` is missing. Every dev, test, lint and typecheck target depends on it. |
| `make dev` | pytest, then `dev-api` and `dev-web` under `make -j` |
| `make dev-api` | `uvicorn aegis.api.app:create_app --factory --reload --port 8000` |
| `make dev-web` | `pnpm --filter @redsim/web dev` on :3000 |
| `make dev-worker` | `celery -A aegis.workers.celery_app worker -Q scans,default`. Not on the `dev` line, needs Redis and Postgres first. |
| `make test` | `pytest -q` plus `pnpm --filter @redsim/web test` |
| `make test-cov` | pytest with `--cov=aegis --cov-report=term-missing` |
| `make lint` | `lint-py` (`ruff check aegis tests`) then `lint-web` (`next lint`, printed as a skip line while `web/` has no ESLint config) |
| `make typecheck` | `typecheck-py` (`mypy aegis`) then `typecheck-web` (`tsc --noEmit`) |
| `make check` | lint, typecheck, test |
| `make up` / `make down` | `docker compose -f deploy/docker-compose.yml up -d --build` / `down` |
| `make docs-serve` / `docs-build` / `docs-build-strict` / `docs-clean` | MkDocs Material on :8001. Needs `uv pip install --native-tls -e ".[docs]"` first. |

Recipes call the venv interpreter by path, so no target needs an activated
shell. `make check` is the only gate today: `.github/workflows/aegis-ci.yml`
carries the aegis lint, mypy, pytest, coverage, SAST and web-build jobs, and
`deploy-aws.yml` only builds images and rolls ECS services.

### Tests

```bash
.venv/bin/python -m pytest -q                  # Python suite (unit + sqlite-backed integration)
.venv/bin/python -m ruff check aegis tests     # lint
pnpm --filter @redsim/web typecheck            # tsc --noEmit
pnpm --filter @redsim/web test                 # vitest
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
aegis/                  Python package (namespace kept from aegis)
  api/                  FastAPI app factory, /v1 routers, middleware, auth, policy
  audit/                hash-chained audit log: chain, writers, forensic export, redaction
  cli/                  `aegis` console script: audit verify, migrate, doctor, plugins, ...
  db/                   SQLAlchemy models, session, Alembic migrations 0001-0009
  llm/                  per-task routing, budgets, pricing, guardrails, Pythia transport
  log_ingest/           OTLP logs to Postgres mirror service
  migrate/              filesystem to Postgres migration helpers
  ml/                   the adversarial-ML vertical: schema, target and attack protocols
  policy/               static / OPA / Cedar policy engines behind the RBAC check
  scanners/             registry, capability vocabulary, out-of-process plugin sandbox
  services/             admission services (audit event, Run/Job rows, enqueue)
  state/                run-state facade: filesystem and Postgres backends
  storage/              blob store: filesystem, S3/MinIO, WORM export
  supply_chain/         plugin signing and marketplace checks
  workers/              Celery app, bootstrap, job state machine, tasks/
web/                    Next.js 14 app (@redsim/web): app router pages, NextAuth, api() client
packages/design-system/ @redsim/design-system: curated components over shadcn primitives
tests/                  pytest suite (unit and integration markers), tests/ml/fakes.py TinyTarget
deploy/                 docker-compose.yml, Dockerfile.{api,worker,web,postgres,log_ingest}, helm, keycloak, opa, cedar, otel, loki
docs/                   product spec, project brief, platform architecture docs, ADRs, ops and dev guides
specs/                  Spec Kit feature layer: F001-F008 plus _shared/ (decisions, architecture, readiness)
.specify/               Spec Kit constitution and templates
.github/                aegis-ci.yml, deploy-aws.yml, docs.yml, release-sign.yml, dependabot
hooks/                  mkdocs build hook that renders this README as the docs index
exports/                ai-assurance-spec-pack.zip (spec pack export)
alembic.ini             Alembic entry point for aegis/db/migrations
aegis.yaml              default runtime configuration read by aegis/config.py
mkdocs.yml              docs site configuration
pyproject.toml          package metadata, extras, pytest markers, ruff and mypy settings
pnpm-workspace.yaml     web and packages/design-system workspaces
```

## Documentation

Read in this order. Where two documents disagree, the earlier one in this list
wins.

| Doc | What it is |
|---|---|
| [`docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`](docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md) | The consolidated product spec, 27 sections: scope and phasing, domain model, architecture, attacks, SHAP, MRI scoring, recommendations, API surface, web UI, deployment, testing, milestones, completion criteria. |
| [`docs/project-brief.md`](docs/project-brief.md) | Governance brief. Its reporting principles are design constraints, and its "Decisions taken (2026-09-08)" section records the product owner's decisions and every knowing divergence. |
| [`specs/README.md`](specs/README.md) and `specs/00N-*/` | Spec Kit feature layer beneath the product spec: F001 project access through F008 audit and governance, each with `spec.md`, `plan.md`, `tasks.md`. `specs/_shared/` holds the decision register, the shared architecture and the readiness checklist. |
| [`docs/spec-driven-workflow.md`](docs/spec-driven-workflow.md) | How the team works spec-first with Spec Kit's stages. The Spec Kit CLI is not installed. |
| [`docs/architecture/overview.md`](docs/architecture/overview.md), [`auth.md`](docs/architecture/auth.md), [`audit-chain.md`](docs/architecture/audit-chain.md), [`multi-tenancy.md`](docs/architecture/multi-tenancy.md), [`observability.md`](docs/architecture/observability.md) | aegis platform architecture. Still accurate for the platform. |
| [`docs/dev/local-stack.md`](docs/dev/local-stack.md), [`docs/dev/frontend.md`](docs/dev/frontend.md), [`docs/dev/testing.md`](docs/dev/testing.md), [`docs/ops/deploy.md`](docs/ops/deploy.md), [`docs/ops/kubernetes.md`](docs/ops/kubernetes.md), [`docs/api/v1.md`](docs/api/v1.md) | Platform dev and ops guides. Some still mention submodules, Kali or routes that were removed with the pentest domain. The spec schedules the `docs/api/v1.md` prune for M0. |
| [`docs/adr/0002-registry-seam-and-runners.md`](docs/adr/0002-registry-seam-and-runners.md), [`docs/adr/0004-unified-effect-class-gate.md`](docs/adr/0004-unified-effect-class-gate.md) | The two seams the ML attack adapters reuse: the scanner registry that `aegis.ml.attacks` registers into (dispatch by name or capability, entry-point plugins, signing, sandbox) and the effect-class gate (`aegis/effects.py`) that classifies every adapter action as read, active or external. The other ADRs ([`0001`](docs/adr/0001-vendored-submodules.md), [`0005`](docs/adr/0005-worker-autoscaling-and-dr.md), [`0008`](docs/adr/0008-nix-reproducible-builds.md)) record platform decisions. |
| [`SECURITY.md`](SECURITY.md), [`CONTRIBUTING.md`](CONTRIBUTING.md), [`CHANGELOG.md`](CHANGELOG.md) | Inherited from aegis. `CONTRIBUTING.md` still describes the aegis submodule checkout and `CHANGELOG.md` is the aegis release history. |

Superseded and kept for history only: `docs/adversarial-ml-redteam-spec.md`
(and its `.html`) and `docs/superpowers/specs/2026-09-08-redsim-design.md`.

## Team conventions

- Commits are `type(topic): description`.
- Branch before committing. Never commit to `main` directly.
- Work spec-first: a changed requirement updates the spec before
  implementation continues. See
  [`docs/spec-driven-workflow.md`](docs/spec-driven-workflow.md) and the
  readiness checklist in `specs/_shared/`.
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

Names that remain: the Python namespace is `aegis` (`import aegis...`), the
console script is `aegis`, environment variables are `AEGIS_*`, the API title
is "Aegis API", the session cookie is `aegis_api_session`, and the compose
services, images and Helm chart are `aegis-*`. The web workspace packages are
`@redsim/web` and `@redsim/design-system`, and the product and UI name is
redsim.

License: Apache-2.0.
