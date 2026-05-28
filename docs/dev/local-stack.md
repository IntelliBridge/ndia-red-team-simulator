# Running the Aegis stack locally

> Phase 3 only. For Phase 2 offline workflows, see `CONTRIBUTING.md` and `PLAN.md`.

## Prerequisites

- Docker 24+ running.
- `git submodule update --init --recursive` has been run.
- A free `localhost:8000` (API), `localhost:3000` (web), `localhost:8080` (Keycloak), `localhost:5432` (Postgres), `localhost:6379` (Redis), `localhost:9000` (MinIO).
- Python 3.12+ in your `PATH` (only needed if you want to run the CLI against the stack from your host).

## Bring it up

```bash
cd deploy
make up
make seed   # creates a demo org/project, seeded admin user, and a Juice Shop target
```

`make up` runs `docker compose up -d --build`. The first build is slow because
`aegis-worker` initialises the four submodules into the image.

## Log in

Open `http://localhost:3000` and click **Login**. You'll be redirected to
Keycloak (`http://localhost:8080`). The seeded admin is `admin@aegis.local` /
`adminpass` — change this before any non-local deployment.

## Trigger a scan from the CLI

```bash
export AEGIS_MODE=api
export AEGIS_API_URL=http://localhost:8000
export AEGIS_AUTH_TOKEN=$(make -s token-for admin@aegis.local)

aegis status                           # confirms API mode + connected
aegis scan http://juice-shop:3000 --use-strix --project demo
```

The same scan is also triggerable from the web UI dashboard.

## Inspect

- **Postgres**: `make psql` (drops you into the `aegis` DB).
- **MinIO**: `http://localhost:9001` console (creds in `.env`).
- **Audit chain**: `aegis audit verify --all`.
- **Jaeger** (optional, profile `obs`): `docker compose --profile obs up -d jaeger`; UI at `http://localhost:16686`.

## Tear down

```bash
make down                # stop and remove containers, keep volumes
make down-clean          # also drop volumes (wipes Postgres + MinIO data)
```

## Auth mode for development

`AEGIS_AUTH_MODE=dev` is enabled by default in the compose stack. It accepts
`Authorization: Bearer dev:<email>` mapped to a seeded admin. **This mode hard-
fails when `AEGIS_ENV=prod`**, so deploying the compose file unchanged to
production is a deliberate footgun the runtime catches.

## Troubleshooting

- **API returns 401**: confirm the token via `make whoami`. If Keycloak is
  still booting, `make logs keycloak` will show the realm import step.
- **Worker is idle**: `make logs worker`. The most common cause is the
  submodule pin mismatch — rerun `git submodule update --init --recursive`
  and rebuild (`make rebuild worker`).
- **Stack E2E flakes locally**: increase Docker memory to ≥6GB. The Strix
  sandbox image alone needs ~3GB at runtime.
