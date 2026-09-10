# Running the redsim stack locally

For the architecture this stack instantiates, see
[`docs/architecture/overview.md`](../architecture/overview.md), the ML flow in
[`docs/architecture/ml-vertical.md`](../architecture/ml-vertical.md) and the
diagrams under `docs/architecture/diagrams/`. For production deployment, see
[`docs/ops/deploy.md`](../ops/deploy.md). For the Python-only path (API and
web without Docker, tests, lint) see the root `Makefile` and
[`CONTRIBUTING.md`](https://github.com/IntelliBridge/ndia-red-team-simulator/blob/main/CONTRIBUTING.md).
State described here is `main` at `58461cc` (2026-09-09, waves 1 to 3 of the
completion plan merged). The three e2e files of wave 4 are marked "added in
wave 4".

## Prerequisites

- Docker 24+ running (Compose v2), for the full stack.
- Free ports: `:8000` API, `:3300` web, `:8080` Keycloak, `:5432` Postgres,
  `:6379` Redis, `:9100` / `:9101` MinIO, `:4319` redsim-log-ingest.
- Python 3.12 and the `.venv` (`make install`, extras `api,worker,test,dev,ml`
  by default). The venv is created with uv and has no `pip`, so run tools as
  `.venv/bin/python -m …` and install with `uv pip install --native-tls`.
- Behind the corporate TLS proxy: the Zscaler root exported into
  `deploy/certs/` as a `.pem` or `.crt` (see
  [`deploy/certs/README.md`](https://github.com/IntelliBridge/ndia-red-team-simulator/blob/main/deploy/certs/README.md)),
  so the images can reach PyPI, the torch index and Pythia.

## Build the bundled assets first

A fresh clone has no models to attack. `assets/` is gitignored except its
README, so build the datasets and the bundled models once:

```bash
.venv/bin/redsim ml build-assets --dataset all              # fetch by pinned revision, train on CPU
.venv/bin/redsim ml build-assets --dataset cifar10 --fixture # only the CI fixture slice (no token needed)
.venv/bin/redsim ml build-assets --only vehicles_cnn --arch resnet18 --epochs 3
```

The Kaggle download reads `KAGGLE_API_TOKEN` from the environment or from
`.env` (`REDSIM_ENV_FILE`), or the older `KAGGLE_USERNAME` / `KAGGLE_KEY`
pair, and falls back to the committed CI sample when neither is set. The
writer records dataset ids, revisions, splits, weight digests, clean
accuracy with `n`, dataset caveats and `subject_centered` in
`assets/MANIFEST.json`. `GET /v1/datasets` and `GET /v1/models` read that
manifest from `REDSIM_ML_ASSETS_DIR` (default `./assets`), so the API and the
worker must both see the same directory. Quote clean accuracy from the
manifest of the build in hand, never as a product claim.

## Compose services and profiles

`deploy/docker-compose.yml` brings up, in the default profile: `postgres`
(postgres 16 with pgaudit), `redis`, `keycloak`, `minio`, `redsim-api`,
`redsim-worker` (`-Q scans`: campaigns, model validation),
`redsim-worker-default` (`-Q default`: report rendering, the reaper, tenant
integrity, WORM export), `redsim-beat`, `redsim-web` and `redsim-log-ingest`.

```bash
make up                                                          # from the repo root
cd deploy && docker compose --profile obs up -d                  # + OTel Collector, Loki, Jaeger
cd deploy && docker compose --profile obs-search up -d           # + Elasticsearch, Kibana
cd deploy && docker compose --profile policy up -d opa           # + OPA for REDSIM_POLICY_ENGINE=opa
```

| Profile | Brings up additionally |
|---|---|
| (default) | api, the two worker pools, beat, web, postgres, redis, keycloak, minio, redsim-log-ingest |
| `obs` | otel-collector, loki, jaeger |
| `obs-search` | elasticsearch, kibana |
| `policy` | opa |

`redsim-log-ingest` runs in the default profile so
`SELECT * FROM application_logs WHERE run_id = '…'` works even without Loki
or Elasticsearch.

## Bring it up

```bash
make up                  # docker compose -f deploy/docker-compose.yml up -d --build
cd deploy && make seed   # default-org, project `default`, user `admin` with the admin role
```

`redsim-api` runs `alembic upgrade head` on start (migrations `0001` to
`0010`). The worker image installs the CPU torch wheels and then
`.[worker,ml]`, so it is the slowest image to build. The API image installs
`.[api,worker]` only and never carries torch, ART, onnxruntime or SHAP.

Two things the compose file does not do for you at `58461cc`:

- **Assets.** No service mounts `assets/` and none sets
  `REDSIM_ML_ASSETS_DIR`, so a compose worker has no bundled models until you
  mount the built tree (a `docker-compose.override.yml` adding
  `./../assets:/app/assets:ro` and `REDSIM_ML_ASSETS_DIR=/app/assets` to
  `redsim-api` and the worker anchor is the least invasive way). Without it
  `GET /v1/datasets` answers `assets.status: "missing"` and registering a
  bundled model answers `409 model_load_refused` with
  `refusal_reason: bundled_assets_missing`.
- **Narrative.** The worker anchor sets `REDSIM_DISABLE_LLM: "1"`, so no
  compose worker calls Pythia until that is unset (see
  [Pythia in compose](#pythia-in-compose)).

Because `make up` runs compose from the repo root, compose reads its own
`.env` in `deploy/`, not the repo-root `.env`. Export the values first, or
point compose at the file:

```bash
set -a; source .env; set +a; make up
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
```

## Sign in

Open `http://localhost:3300`. The login page is the app's own email and
password form; the web server checks the credentials against the realm from
`deploy/keycloak/realm-export.json` (Keycloak on `http://localhost:8080`,
`redsim-web` client with direct access grants). The seeded admin is
`admin@redsim.local` / `adminpass`. The dev bearer below is for the CLI and
scripts only: the web app has no dev login.

For programmatic or CLI access in dev mode:

```bash
export REDSIM_MODE=api
export REDSIM_API_URL=http://localhost:8000
export REDSIM_TOKEN=dev:admin@redsim.local        # REDSIM_AUTH_MODE=dev only

.venv/bin/redsim --api status                     # mode=api, healthy
.venv/bin/redsim --api audit verify --all
```

The dev token works only when `REDSIM_AUTH_MODE=dev` **and** `REDSIM_ENV` is
not `prod`. The API refuses dev tokens in prod.

## Run a campaign against the stack

With the assets visible to the API and the worker, the whole demo path is
four calls. `H` below is the bearer header. Add `X-Redsim-CSRF` only for
cookie sessions.

```bash
H='Authorization: Bearer dev:admin@redsim.local'
API=http://localhost:8000

# 1. What this deployment can do, and which bundled models exist
curl -s -H "$H" $API/v1/ml/capabilities | jq '.modalities, .bundled_models, .llm_narrative'
curl -s -H "$H" "$API/v1/models?project=default" | jq '.models[] | {id, registered, status, modality}'

# 2. Register a bundled model in the project (model.register, remediator+)
curl -s -H "$H" -H 'Content-Type: application/json' -X POST $API/v1/models \
  -d '{"source":"bundled","project_id":"default","bundled_id":"vehicles_cnn"}' | jq '{id, status}'
# -> {"id": "vehicles_cnn-<8 hex>", "status": "available"}; a second call answers 409 already_registered

# 3. Start a campaign (attack.run, scanner+); defaults fill norm, grid, reference eps and dataset
curl -s -H "$H" -H 'Content-Type: application/json' -X POST $API/v1/models/<model_id>/attacks \
  -d '{"attack_ids":["fgsm","pgd"],"n_samples":50,"explain_k":4}' | jq
# -> 202 {"run_id": "run-…", "job_ids": ["job-…"], "status_url": "/v1/runs/run-…"}

# 4. Watch the stage table, then read the record and the report
curl -s -H "$H" $API/v1/runs/<run_id> | jq '.stage_table | {stage, stages_done, completeness}'
curl -s -H "$H" $API/v1/runs/<run_id>/campaign | jq '{status, completeness, score: .score.mri, score_status, findings: (.findings|length)}'
curl -s -H "$H" $API/v1/runs/<run_id>/report.md
curl -s -H "$H" "$API/v1/audit/verify?run=<run_id>" | jq '{verified, count}'
```

Follow-ups on a finding: `POST /v1/findings/{id}/explain`,
`POST /v1/findings/{id}/harden` (`{"llm_narrative": true}` only produces prose
when Pythia is configured on the worker), then
`GET /v1/runs/{run_a}/compare?with={run_b}`, which reads two campaign runs
side by side (`mode: side_by_side`). The tabular path is
the same with `bundled_id: "url_trees"` and `attack_ids: ["pgd",
"hopskipjump"]`: `pgd` runs by surrogate transfer and is admitted since
`dd2bbd4` (applicability by capability tag) and `58461cc` (the gradients
check waived for a `surrogate_transfer` adapter on a target with a declared
surrogate). Every route and code is in the [API reference](../api/v1.md).

A small `n_samples` and `explain_k` keep a laptop run short. On a small
slice the MRI may legitimately be partial (`score` absent, `score_status`
present) and a campaign may produce no finding. That is the honest state per
spec 15.4, not an error.

`redsim ml seed [--project default] [--only <bundled_id>]` (`3ab9de7`,
`98a8733`) registers every non-fixture bundled model through the same service
from the CLI, audit-first and one commit per model, and `redsim ml attack
<target_id> --out <dir>` (`3ab9de7`) runs a campaign offline with no database,
writing `<out>/<run_id>/{run_record.json, report.md, report.json,
report.html, artifacts/curve/robustness_curve.png, audit.jsonl}` with
`narrative_source=rules`. `redsim audit verify --run <run_id>` walks that
chain through the `<output_dir>/<run_id>/audit.jsonl` fallback, or
`--run-dir <out>/<run_id>` names it (`aa9674e`).

## Pythia in compose

The four Pythia variables (`PYTHIA_BASE_URL`, `PYTHIA_API_KEY`,
`PYTHIA_PERSONA`, `REDSIM_ML_LLM_MODEL`) pass through to `redsim-api` and
the worker pool as `${VAR:-}`. When they are not exported the container sees
an empty string and the narrative stays off (`GET /v1/ml/capabilities`
reports `llm_narrative.configured: false`). The worker anchor also sets
`REDSIM_DISABLE_LLM: "1"`. Since wave 2 the narrative runs in the parent of
the `scans` worker (`redsim-worker`), so that is the service on which the
variable has to be unset (a `docker-compose.override.yml` is the least
invasive way) before a compose stack can produce a narrative. The sandbox
child never receives the Pythia variables in either case. Containers get the
proxy CA from `deploy/certs/`, not from a keychain. See
[`docs/ops/pythia.md`](../ops/pythia.md).

## Without Docker

`make dev-api` (uvicorn on `:8000`) boots without Postgres or Redis, but only
`/health`, `/docs`, `/metrics` and the catalog routes that read the asset
manifest work until `REDSIM_DB_URL` and `REDSIM_BROKER_URL` point at running
services. `make dev-worker` runs
`celery -A redsim.workers.celery_app worker -Q scans,default` from the venv and
needs Redis, Postgres and the `ml` extra. `make dev-web` serves the Next.js app
on `:3000`. Export the variables from `.env.example` (`cp .env.example .env`,
then `set -a; source .env; set +a`) in the shell that runs them.

## Tests, including the e2e tier

```bash
.venv/bin/python -m pytest -q                                   # default suite: 1663 passed, 30 skipped at 58461cc (with the ml extra)
.venv/bin/python -m pytest -q -m ml                             # only the tests that need the ml extra
.venv/bin/ruff check --select E4,E7,E9,F,I redsim tests         # lint, exactly as CI
.venv/bin/mypy redsim
```

The default `-m` from `addopts` deselects `docker`, `e2e`, `slow` and
`auth_required`. The ML tests never touch the network: `tests/ml/fakes.py`
provides `TinyTarget` and `TinyTabularTarget`, `tests/ml/fixtures/` holds the
CIFAR-10 slice, the URL sample, a `MANIFEST.json` and the frozen
`run_record.json`, and an autouse fixture in `tests/ml/conftest.py` isolates
every ML test from a developer's `.env`. The route and task tests
(`tests/ml/test_*_routes.py`, `test_admission.py`, `test_tasks.py`,
`test_audit_campaign.py`, `test_model_validate.py`, `test_compare.py`,
`test_cancel_terminal.py`) run on the shared sqlite harness with eager Celery.

The e2e tier (`35e71c7`, `a45a787`) lives under `tests/e2e/`. Its
`conftest.py` stamps every item there `e2e` and skips it unless `REDSIM_E2E`
is set, so `pytest -q` never runs it by accident. The harness builds a tiny
synthetic asset tree with the real builders, runs the FastAPI app over one
autocommit sqlite connection in WAL mode with a filesystem blob store and
eager Celery, launches the real sandbox child by default
(`REDSIM_E2E_SANDBOX=inprocess` selects the in-process mode for debugging),
provides one dev-token client per role, a mocked Pythia transport in the
worker parent, and runs the real `redsim audit verify --all` as a
subprocess. Every number it produces is a harness measurement on a test
double, never a demo result.

```bash
REDSIM_E2E=1 .venv/bin/python -m pytest -q -m e2e tests/e2e                       # sqlite lane (8 passed at 58461cc)
REDSIM_E2E=1 REDSIM_E2E_POSTGRES_URL=postgresql+psycopg://redsim:redsim@localhost:5432/redsim_e2e \
  .venv/bin/python -m pytest -q -m e2e tests/e2e                                  # adds the RLS lane
REDSIM_E2E=1 REDSIM_E2E_SANDBOX=inprocess .venv/bin/python -m pytest -q -m e2e tests/e2e   # debugging only
```

The files: `tests/e2e/test_harness_smoke.py` (wave 3, 8 cases through the
real child) and, added in wave 4 as the completion-criteria evidence,
`tests/e2e/test_ml_campaigns.py` (an image and a tabular campaign to
`succeeded` with scorecard, findings, limitations and the narrative on and
off), `tests/e2e/test_ml_verify_upload_reports.py` (an ONNX upload accepted and
a pickle refused, the report sections and the report formats) and
`tests/e2e/test_ml_governance.py` (the RBAC negative matrix, the RLS
negatives on the Postgres lane, `audit verify --all` clean then broken, no
Pythia secret in `/v1/ml/capabilities`).

The Postgres lane runs the tenant-isolation cases that sqlite cannot (RLS,
`FORCE ROW LEVEL SECURITY`, the append-only audit trigger). It skips when
`REDSIM_E2E_POSTGRES_URL` is unset and fails when the database is not
migrated (`REDSIM_DB_URL="$REDSIM_E2E_POSTGRES_URL" alembic upgrade head`
first). The compose Postgres from `make up` works as its target after that.
A Postgres superuser bypasses RLS, so the policy is observable only through a
non-superuser, non-owner role. The Playwright browser e2e behind
`workflow_dispatch` in CI is excluded from this completion pass.

## Inspect

| Surface | How |
|---|---|
| Postgres | `cd deploy && make psql` (drops into the `redsim` DB) |
| Application logs | `SELECT * FROM application_logs WHERE …`, or the web `/logs` page |
| MinIO console | `http://localhost:9101` |
| Audit chain | `redsim audit verify --all`, `GET /v1/audit/verify?all=1`, or the web `/audit` page |
| Campaign evidence | `GET /v1/runs/{id}/campaign`, `GET /v1/runs/{id}/artifacts`, `GET /v1/runs/{id}/report.md` |
| Health | `curl -s http://localhost:8000/health` (`cd deploy && make whoami`) |
| Metrics | `curl -s http://localhost:8000/metrics | grep redsim_ml_` |
| Loki (obs) | `http://localhost:3100/loki/api/v1/query?query={service="redsim-api"}` |
| Jaeger (obs) | `http://localhost:16686` (the worker opens a `job.run` span per job and one span per campaign stage) |
| Kibana (obs-search) | `http://localhost:5601` |
| Web Storybook | `pnpm --filter @redsim/web storybook` then `http://localhost:6006` |

`cd deploy && make logs svc=redsim-worker` tails one service,
`make rebuild svc=redsim-worker` rebuilds and restarts it.
`REDSIM_ML_KEEP_WORK_DIR=1` on the worker keeps each job's sandbox work
directory (`REDSIM_ML_WORK_DIR/<job_id>`, default under `$TMPDIR/redsim-ml`)
for debugging.

## Tear down

```bash
make down                        # stop and remove containers, keep volumes
cd deploy && make down-clean     # also drop volumes (wipes Postgres and MinIO data)
```

## Auth modes for development

| Mode | Activates |
|---|---|
| `REDSIM_AUTH_MODE=dev` | `dev:<email>` bearer tokens (default in the compose env) |
| `REDSIM_AUTH_MODE=oidc` | Keycloak-issued bearers and the session cookie only |
| Cookie auth (browser) | NextAuth via the web UI (works regardless of dev mode) |

The redsim API session cookie is keyed by `REDSIM_API_SESSION_PRIVATE_KEY`
(web side) and `REDSIM_API_SESSION_PUBLIC_KEY` (api side). The compose stack
auto-generates a dev keypair on first boot under `deploy/certs/`. In
production you supply your own (see [`docs/ops/deploy.md`](../ops/deploy.md)).

## Doctor

`redsim doctor` (`7556b22`, `c3868e5`) checks the environment. It prints the
mode (dev, api or worker), an informational Pythia block (key redacted to its
prefix and length, the routed model, a note when the model came from a
deprecated alias, never a failure), checks the `ml` extra with versions,
launches the sandbox child with `--help` under the real child environment and
rlimits, verifies the asset manifest under `REDSIM_ML_ASSETS_DIR` or
`./assets` (all three required with `--worker-mode` or
`REDSIM_DOCTOR_WORKER_MODE=1`, informational otherwise), and reports whether
the `ml-campaign` adapter is on the roster. `--api-mode` keeps the Postgres,
blob and OIDC probes. No provider key is derived from `redsim.yaml` any more.

## Troubleshooting

- **API returns 401**: confirm `REDSIM_TOKEN` is set. If Keycloak is still
  booting, `make logs svc=keycloak` shows the realm import. Dev tokens work
  immediately, the OIDC path needs the realm fully loaded.
- **`POST /v1/models` answers 409 `model_load_refused` with
  `bundled_assets_missing`**: the API process cannot see a built
  `MANIFEST.json` at `REDSIM_ML_ASSETS_DIR`. Build the assets and mount them.
- **`POST /v1/models/{id}/attacks` answers 409 `model_load_refused`**: the
  target is not `available` (an upload still `validating` or `refused`, or a
  deleted target). `GET /v1/models/{id}` shows `status` and `refusal_reason`.
- **Campaign fails with `SandboxTimeout`**: raise
  `REDSIM_ML_SANDBOX_TIMEOUT_S` on the worker (default 1200, and it must stay
  below the Celery soft limit) or lower `n_samples`. The partial files are
  kept as `ml.partial.*` artifacts.
- **Worker idle or restarting**: `make logs svc=redsim-worker`. Check
  `REDSIM_BROKER_URL` and that the `ml` extra built (the torch wheel download
  is the usual failure behind a proxy without `deploy/certs/`).
- **`/v1/logs` returns 503**: `redsim-log-ingest` is not up. Check
  `docker compose ps redsim-log-ingest` and `http://localhost:4319/health`.
- **WebSocket closes 1008 immediately**: check the browser console for the
  close reason. Usually a stale `redsim_api_session` cookie (sign in again)
  or a misconfigured `REDSIM_WEB_ORIGIN`.
- **`CERTIFICATE_VERIFY_FAILED` from Python on the host**: the Pythia client
  trusts the OS store through `truststore` by default. Set
  `REDSIM_TLS_TRUSTSTORE=1` (the default) or point `REDSIM_CA_BUNDLE` at a
  bundle containing the proxy root.
- **`pnpm install` fails on TLS behind the proxy**: set
  `NODE_EXTRA_CA_CERTS=/path/to/zscaler.pem`.
- **`uv` fails on TLS**: pass `--native-tls`.
