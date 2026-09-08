# Running the redsim stack locally

For the architecture this stack instantiates, see
[`docs/architecture/overview.md`](../architecture/overview.md) and the
diagrams under `docs/architecture/diagrams/`. For production deployment, see
[`docs/ops/deploy.md`](../ops/deploy.md). For the Python-only path (API and
web without Docker, tests, lint) see the root `Makefile` and
[`CONTRIBUTING.md`](https://github.com/IntelliBridge/ndia-red-team-simulator/blob/main/CONTRIBUTING.md).

## Prerequisites

- Docker 24+ running (Compose v2).
- Free ports: `:8000` API, `:3300` web, `:8080` Keycloak, `:5432` Postgres,
  `:6379` Redis, `:9100` / `:9101` MinIO, `:4319` redsim-log-ingest.
- Python 3.12 and the `.venv` (`make install`) if you want to run the CLI
  from your host against the stack.
- Behind the corporate TLS proxy: the Zscaler root exported into
  `deploy/certs/` as a `.pem` or `.crt` (see
  [`deploy/certs/README.md`](https://github.com/IntelliBridge/ndia-red-team-simulator/blob/main/deploy/certs/README.md)),
  so the images can reach PyPI, the torch index and Pythia.

## Compose services and profiles

`deploy/docker-compose.yml` brings up, in the default profile: `postgres`
(postgres 16 with pgaudit), `redis`, `keycloak`, `minio`, `redsim-api`,
`redsim-worker` (`-Q scans`), `redsim-worker-default` (`-Q default`),
`redsim-beat`, `redsim-web` and `redsim-log-ingest`.

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

Because `make up` runs compose from the repo root, compose reads its own
`.env` in `deploy/`, not the repo-root `.env`. Export the values first, or
point compose at the file:

```bash
set -a; source .env; set +a; make up
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
```

## Sign in

Open `http://localhost:3300` and click **Login**. You are redirected to
Keycloak (`http://localhost:8080`, realm from
`deploy/keycloak/realm-export.json`). The seeded admin is
`admin@redsim.local` / `adminpass`.

For programmatic or CLI access in dev mode:

```bash
export REDSIM_MODE=api
export REDSIM_API_URL=http://localhost:8000
export REDSIM_TOKEN=dev:admin@redsim.local        # REDSIM_AUTH_MODE=dev only

.venv/bin/redsim --api status                     # mode=api, healthy
.venv/bin/redsim --api audit verify --all
```

The dev token works only when `REDSIM_AUTH_MODE=dev` **and** `REDSIM_ENV` is
not `prod`. The API refuses dev tokens in prod, so deploying the compose file
unchanged to production is a footgun the runtime catches.

## What you can do on `main`

The platform is up but the ML vertical is contracts only, so a fresh stack
has nothing to attack:

- `GET /v1/scanners` returns an empty roster and `POST /v1/scans` answers
  404. The web Start scan control is disabled behind a notice.
- `redsim ml build-assets` prints `not_implemented` with a reason and
  writes nothing.
- `/models` and the campaign routes do not exist yet
  ([API reference](../api/v1.md), "Planned ML routes").

What does work: sign-in, projects and memberships, `/audit` and
`redsim audit verify`, `/logs` through `redsim-log-ingest`, `/cost`, the
run-events WebSocket, the Helm-equivalent hardening of the API (CSRF, rate
limit, RLS), and the Pythia connectivity check from the host
(`.venv/bin/python -m redsim.llm.pythia_check`, see
[`docs/ops/pythia.md`](../ops/pythia.md)).

## Pythia in compose

The four Pythia variables (`PYTHIA_BASE_URL`, `PYTHIA_API_KEY`,
`PYTHIA_PERSONA`, `REDSIM_ML_LLM_MODEL`) pass through to `redsim-api` and
the worker pool as `${VAR:-}`. When they are not exported the container sees
an empty string and the narrative stays off. The worker anchor also sets
`REDSIM_DISABLE_LLM: "1"`, which has to be unset on `redsim-worker-default`
(a `docker-compose.override.yml` is the least invasive way) before a compose
stack can produce a narrative. Containers get the proxy CA from
`deploy/certs/`, not from a keychain.

## Inspect

| Surface | How |
|---|---|
| Postgres | `cd deploy && make psql` (drops into the `redsim` DB) |
| Application logs | `SELECT * FROM application_logs WHERE …`, or the web `/logs` page |
| MinIO console | `http://localhost:9101` |
| Audit chain | `redsim audit verify --all`, or the web `/audit` page |
| Health | `curl -s http://localhost:8000/health` (`cd deploy && make whoami`) |
| Loki (obs) | `http://localhost:3100/loki/api/v1/query?query={service="redsim-api"}` |
| Jaeger (obs) | `http://localhost:16686` |
| Kibana (obs-search) | `http://localhost:5601` |
| Web Storybook | `pnpm --filter @redsim/web storybook` then `http://localhost:6006` |

`cd deploy && make logs svc=redsim-worker` tails one service,
`make rebuild svc=redsim-worker` rebuilds and restarts it.

## Tear down

```bash
make down                        # stop and remove containers, keep volumes
cd deploy && make down-clean     # also drop volumes (wipes Postgres and MinIO data)
```

## Auth modes for development

| Mode | Activates |
|---|---|
| `REDSIM_AUTH_MODE=dev` | `dev:<email>` bearer tokens (default in the compose env) |
| `REDSIM_AUTH_MODE=oidc` | Keycloak / NextAuth path only |
| Cookie auth (browser) | NextAuth via the web UI (works regardless of dev mode) |

The redsim API session cookie is keyed by `REDSIM_API_SESSION_PRIVATE_KEY`
(web side) and `REDSIM_API_SESSION_PUBLIC_KEY` (api side). The compose stack
auto-generates a dev keypair on first boot under `deploy/certs/`. In
production you supply your own (see [`docs/ops/deploy.md`](../ops/deploy.md)).

## Common smoke checks

```bash
make up
.venv/bin/redsim --api status                # mode=api, api health = healthy
.venv/bin/redsim --api audit verify --all    # every chain verifies
docker compose -f deploy/docker-compose.yml exec postgres \
  psql -U redsim -d redsim -c "SELECT count(*) FROM application_logs;"
```

## Troubleshooting

- **API returns 401**: confirm `REDSIM_TOKEN` is set. If Keycloak is still
  booting, `make logs svc=keycloak` shows the realm import. Dev tokens work
  immediately, the OIDC path needs the realm fully loaded.
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
