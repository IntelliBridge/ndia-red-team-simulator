# Running the Aegis stack locally

For the architecture this stack instantiates, see
[`docs/architecture/overview.md`](../architecture/overview.md). For
production deployment, see [`docs/ops/deploy.md`](../ops/deploy.md).

For Phase 2 offline workflows, see
[`CONTRIBUTING.md`](https://github.com/example/aegis/blob/main/CONTRIBUTING.md)
— the CLI runs without Docker.

## Prerequisites

- Docker 24+ running (Compose v2).
- `git submodule update --init --recursive` has been run.
- Free ports:
  - `:8000` API · `:3300` web · `:8080` Keycloak
  - `:5432` Postgres · `:6379` Redis
  - `:9100` / `:9101` MinIO (remapped from the upstream `:9000`)
  - `:5000` mcp-kali · `:4319` aegis-log-ingest
- Python 3.12+ in `PATH` if you want to run the CLI from your host
  against the stack.

## Compose profiles

Three opt-in tiers (see
[`docs/architecture/observability.md`](../architecture/observability.md)):

```bash
cd deploy
make up                                  # default — full app, Postgres mirror
docker compose --profile obs up -d       # + OTel Collector + Loki + Jaeger
docker compose --profile obs-search up -d  # + Elasticsearch + Kibana
```

| Profile      | Brings up additionally                                                          |
|--------------|---------------------------------------------------------------------------------|
| (default)    | api, worker, web, postgres, redis, keycloak, minio, kali, **aegis-log-ingest**  |
| `obs`        | otel-collector, loki, jaeger                                                    |
| `obs-search` | elasticsearch, kibana                                                           |

The `aegis-log-ingest` service runs in the default profile so
`SELECT * FROM application_logs WHERE run_id = '…'` works even
without Loki / Elasticsearch.

## Bring it up

```bash
cd deploy
make up
make seed       # creates a demo org/project + seeded admin + Juice Shop target
```

`make up` runs `docker compose up -d --build`. The first build is
slow because `aegis-worker` initialises the cai / strix /
vulnerability-fixer submodules into the image. Subsequent builds
are cached.

## Sign in

Open `http://localhost:3300` and click **Login**. You'll be
redirected to Keycloak (`http://localhost:8080`). The seeded admin
is `admin@aegis.local` / `adminpass`.

For programmatic / CLI access:

```bash
export AEGIS_MODE=api
export AEGIS_API_URL=http://localhost:8000
export AEGIS_TOKEN=dev:admin@aegis.local        # dev auth mode

aegis --api status              # mode=api, healthy
aegis --api scan http://juice-shop:3000 --use-strix
```

The dev token works only when `AEGIS_AUTH_MODE=dev` **and**
`AEGIS_ENV` is not `prod`. The API hard-fails dev tokens in prod —
deploying the compose file unchanged to production is a deliberate
footgun the runtime catches.

## Inspect

| Surface                     | How                                                              |
|-----------------------------|------------------------------------------------------------------|
| Postgres                    | `make psql` (drops into the `aegis` DB)                          |
| Application logs            | `SELECT * FROM application_logs WHERE …` or `aegis --api …` + web `/logs` |
| MinIO console               | `http://localhost:9101` (creds in `deploy/.env`)                 |
| Audit chain                 | `aegis audit verify --all`                                       |
| Loki (obs)                  | `http://localhost:3100/loki/api/v1/query?query={service="aegis-api"}` |
| Jaeger (obs)                | `http://localhost:16686`                                         |
| Kibana (obs-search)         | `http://localhost:5601`                                          |
| Web Storybook               | `pnpm --filter @aegis/web storybook` then `http://localhost:6006` |

## Tear down

```bash
make down                # stop + remove containers, keep volumes
make down-clean          # also drop volumes (wipes Postgres + MinIO data)
```

## Auth modes for development

| Mode                                                           | Activates                                                |
|----------------------------------------------------------------|----------------------------------------------------------|
| `AEGIS_AUTH_MODE=dev`                                          | `dev:<email>` bearer tokens (default in the compose env) |
| `AEGIS_AUTH_MODE=oidc`                                         | Keycloak / NextAuth path only                            |
| Cookie auth (browser)                                          | NextAuth via the web UI (works regardless of dev mode)   |

The Aegis API session cookie (F14a) is keyed by
`AEGIS_API_SESSION_PRIVATE_KEY` (web side) and
`AEGIS_API_SESSION_PUBLIC_KEY` (api side). The compose stack
auto-generates a dev keypair on first boot under `deploy/certs/`;
in production you supply your own (see
[`docs/ops/deploy.md`](../ops/deploy.md)).

## Common smoke checks

```bash
# Full stack reachable
make up
aegis --api status                 # mode=api, api health = healthy

# Audit chain intact
aegis --api audit verify --all     # ✓ across all chains

# Postgres log mirror populated
docker compose exec postgres \
  psql -U aegis -d aegis -c "SELECT count(*) FROM application_logs;"
```

## Troubleshooting

- **API returns 401**: confirm `AEGIS_TOKEN` is set. If Keycloak is
  still booting, `make logs keycloak` will show the realm import
  step. The OIDC path needs the realm fully loaded; dev tokens work
  immediately.
- **Worker idle**: `make logs worker`. The most common cause is a
  submodule pin mismatch — rerun
  `git submodule update --init --recursive` and rebuild
  (`make rebuild worker`).
- **`/v1/logs` returns 503**: `aegis-log-ingest` not up. Check
  `docker compose ps aegis-log-ingest` and the service's
  `/health` endpoint at `http://localhost:4319/health`.
- **WebSocket immediately closes 1008**: check the browser console
  for the close reason. Most common: stale `aegis_api_session`
  cookie (re-sign in) or a misconfigured `AEGIS_WEB_ORIGIN`.
- **Stack E2E flakes locally**: increase Docker memory to ≥6 GB.
  Strix's sandbox image alone needs ~3 GB at runtime.
- **`pnpm install` fails on TLS in a corporate proxy**: set
  `NODE_EXTRA_CA_CERTS=/path/to/zscaler.pem` (see
  [`deploy/certs/README.md`](https://github.com/example/aegis/blob/main/deploy/certs/README.md)).
