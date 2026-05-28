# Production deployment

This doc is the canonical reference for running Aegis outside a
developer laptop. For day-1 local development see
[`docs/dev/local-stack.md`](../dev/local-stack.md); this file focuses
on the production posture: env vars that must be set, keys that must
be generated, the deployment topology, and the rotation runbook.

---

## Topology

```mermaid
flowchart LR
  subgraph internet["Internet"]
    users["Users"]
    ghext["github.com"]
  end

  subgraph edge["Edge"]
    lb["Load balancer + TLS"]
  end

  subgraph cluster["Cluster / hosts"]
    web["@aegis/web"]
    api["aegis-api"]
    worker["aegis-worker"]
    li["aegis-log-ingest"]
    col["otel-collector"]
  end

  subgraph data["Data plane"]
    pg[("Postgres")]
    redis[("Redis")]
    blob[("S3")]
    kc["Keycloak"]
    loki[("Loki")]
    es[("Elasticsearch (optional)")]
  end

  users --> lb
  ghext --> lb
  lb --> web
  lb --> api
  web --> api
  api --> redis
  worker --> redis
  api --> pg
  worker --> pg
  api --> blob
  worker --> blob
  api --> kc
  worker --> col
  api --> col
  col --> loki
  col --> li
  col --> es
  li --> pg
```

The four Aegis services (`aegis-api`, `aegis-worker`,
`aegis-log-ingest`, `@aegis/web`) all build from `deploy/Dockerfile.*`
in this repo. The data-plane services are the standard upstream
images.

---

## Required env vars

### Identity

| Var                              | Required where        | Notes                                                                                  |
|----------------------------------|-----------------------|----------------------------------------------------------------------------------------|
| `AEGIS_ENV`                      | api, worker, web      | `prod` disables dev tokens and asserts secure cookies                                  |
| `AEGIS_AUTH_MODE`                | api                   | `oidc` in prod (`dev` only for local development)                                       |
| `AEGIS_OIDC_ISSUER`              | api                   | Keycloak realm URL                                                                     |
| `AEGIS_OIDC_AUDIENCE`            | api                   | Default `aegis`                                                                        |
| `AEGIS_OIDC_JWKS_URL`            | api                   | Keycloak realm's `/protocol/openid-connect/certs`                                       |
| `KEYCLOAK_CLIENT_ID`             | web                   | NextAuth Keycloak provider                                                             |
| `KEYCLOAK_CLIENT_SECRET`         | web                   | NextAuth Keycloak provider                                                             |
| `KEYCLOAK_ISSUER`                | web                   | Same as `AEGIS_OIDC_ISSUER` (web-side name)                                            |
| `NEXTAUTH_SECRET`                | web                   | NextAuth's own session JWT key — opaque to Aegis                                       |
| `NEXTAUTH_URL`                   | web                   | Public web URL (e.g. `https://aegis.example.com`)                                       |

### Aegis-signed cookie (F14a)

These are the v0.4.0 cookie auth keys. The NextAuth callback signs
with the private key; FastAPI verifies with the public key.

| Var                                  | Where set | Value                                                  |
|--------------------------------------|-----------|--------------------------------------------------------|
| `AEGIS_API_SESSION_PRIVATE_KEY`      | web       | PKCS8 PEM, 2048-bit RSA                                |
| `AEGIS_API_SESSION_PUBLIC_KEY`       | api       | SubjectPublicKeyInfo PEM, matching public half         |
| `AEGIS_API_SESSION_KEY_ID`           | both      | Default `aegis-api-session-v1` — increment on rotation |
| `AEGIS_API_SESSION_TTL_SECONDS`      | both      | Default `900` (15 min)                                 |
| `AEGIS_API_SESSION_COOKIE`           | both      | Default `aegis_api_session`                            |
| `AEGIS_CSRF_COOKIE`                  | both      | Default `aegis_csrf`                                   |
| `AEGIS_CSRF_HEADER`                  | both      | Default `X-Aegis-CSRF`                                 |
| `AEGIS_WEB_ORIGIN`                   | api       | The web origin allowed for credentialed CORS           |

To generate a fresh keypair:

```python
from aegis.api.session_cookie import generate_keypair
private_pem, public_pem = generate_keypair()
print(private_pem)
print(public_pem)
```

Store the private key in the web side's secret store; ship the public
key as plain config on the API side — there is no value in it being
secret.

### Worker SA (FW)

| Var                                  | Where     | Notes                                                       |
|--------------------------------------|-----------|-------------------------------------------------------------|
| `AEGIS_WORKER_SIGNING_KEY`           | api, worker | Current shared HMAC key                                    |
| `AEGIS_WORKER_SIGNING_KEY_PREVIOUS`  | api       | Previous key accepted during rotation overlap                |
| `AEGIS_WORKER_SIGNING_KEY_VERSION`   | api, worker | Integer, default `1`. Workers increment when rotating.     |
| `AEGIS_WORKER_KEY_OVERLAP_SECONDS`   | api       | Default `300`                                                |
| `AEGIS_WORKER_TOKEN_TTL_SECONDS`     | worker    | Default `300`                                                |

### Data plane

| Var                          | Where           | Value                                                  |
|------------------------------|-----------------|--------------------------------------------------------|
| `AEGIS_DB_URL`               | api, worker, log-ingest | `postgresql+psycopg://user:pass@host:5432/aegis`  |
| `AEGIS_BROKER_URL`           | api, worker     | `redis://host:6379/0`                                  |
| `AEGIS_RESULT_BACKEND`       | worker          | `redis://host:6379/1`                                  |
| `AEGIS_BLOB_BACKEND`         | api, worker     | `s3`                                                   |
| `AEGIS_S3_ENDPOINT`          | api, worker     | S3-compatible endpoint                                 |
| `AEGIS_S3_BUCKET`            | api, worker     | Default `aegis`                                        |
| `AEGIS_S3_ACCESS_KEY_ID` / `…SECRET_ACCESS_KEY` | api, worker | Bucket credentials                       |

### CORS / Network

| Var                          | Where | Value                                              |
|------------------------------|-------|----------------------------------------------------|
| `AEGIS_CORS_ORIGINS`         | api   | Comma-separated, **explicit** origin list           |
| `AEGIS_WEB_ORIGIN`           | api   | Always added to the CORS allowlist                  |
| `AEGIS_RL_USER_PER_MIN`      | api   | Per-user rate limit (default `30`)                  |
| `AEGIS_RL_PROJECT_PER_MIN`   | api   | Per-project rate limit (default `120`)              |

### GitHub App (F23)

| Var                                | Where    | Value                                                |
|------------------------------------|----------|------------------------------------------------------|
| `AEGIS_GITHUB_WEBHOOK_SECRET`      | api      | HMAC verification secret from the App installation   |
| `AEGIS_GITHUB_APP_ID`              | api, worker | Installation app id                               |
| `AEGIS_GITHUB_PRIVATE_KEY`         | api, worker | App private key (PEM)                             |

### Observability

| Var                                | Where               | Notes                                                       |
|------------------------------------|---------------------|-------------------------------------------------------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT`      | api, worker         | Activates the OTel SDK. Without it, logs go to stdout only. |
| `OTEL_RESOURCE_ATTRIBUTES`         | api, worker         | `service.name=...` etc.                                     |
| `AEGIS_LOG_INGEST_URL`             | api, worker         | Default path that bypasses the Collector (default profile)  |

---

## Build pipeline

```bash
# Backend services
docker build -t aegis-api -f deploy/Dockerfile.api .
docker build -t aegis-worker -f deploy/Dockerfile.worker .
docker build -t aegis-log-ingest -f deploy/Dockerfile.log_ingest .

# Frontend
docker build -t aegis-web -f deploy/Dockerfile.web .

# Kali (only if you're hosting the scanner; usually external)
docker build -t aegis-kali -f deploy/Dockerfile.kali .
```

All four Dockerfiles install from the repo root, so the build context
must be the repo root (`docker build … .`). The web image consumes
the pnpm workspace at the same root path.

---

## First-deploy checklist

1. **Database**: provision Postgres, apply Alembic migrations end to
   end:
   ```bash
   AEGIS_DB_URL=… alembic -c aegis/db/alembic.ini upgrade head
   ```
   Through v0.4.1 the head is `0003_application_logs`.
2. **Blob store**: create the bucket; grant the api + worker IAM the
   read/write needed.
3. **Keycloak**: realm + client per `deploy/keycloak/realm-export.json`.
   The client must carry `aegis_project_roles` in the id_token.
4. **API session keypair**: run `generate_keypair()` (see above);
   stash the private key in web's secret store, set the public key as
   API env.
5. **Worker SA key**: generate a strong shared secret; set
   `AEGIS_WORKER_SIGNING_KEY` on both sides.
6. **GitHub App**: create + install; set webhook secret + private key
   env vars.
7. **CORS allowlist**: `AEGIS_CORS_ORIGINS` and `AEGIS_WEB_ORIGIN`.
8. **Smoke**: deploy api + worker + log-ingest + web; from the CLI:
   ```bash
   aegis --api status
   aegis --api scan https://target/health   # should refuse with 403 unless allowlisted
   ```
9. **Audit verify**: `aegis audit verify --all` — should print ✓.

---

## Rotation runbook

### Aegis API session keypair (F14a)

The web side mints with the private key; the API verifies with the
public key. A rotation is a controlled bump of both.

```
Day 0:  generate new keypair (v2)
Day 0:  set AEGIS_API_SESSION_KEY_ID=aegis-api-session-v2 + new
        public key on the API (still accepts v1 via the JWKS-style
        helper; v0.5 will add explicit dual-public-key acceptance).
Day 0:  set new private key on the web side. NextAuth callbacks now
        mint v2 cookies.
Day 0 + TTL window:
        all v1 cookies have expired (15 min default).
Day 0 + TTL window: drop the v1 public key.
```

For v0.4.1 the API still verifies against a single public key; the
graceful rotation pattern lands in v0.5. Until then, plan for a
~15-minute window of fresh sign-ins during the cutover.

### Worker SA key (FW)

The verifier accepts current + previous keys within an overlap
window. Pattern:

```
Step 1:  Set AEGIS_WORKER_SIGNING_KEY=newkey (current)
         Set AEGIS_WORKER_SIGNING_KEY_PREVIOUS=oldkey
         Set AEGIS_WORKER_SIGNING_KEY_VERSION=2
         Restart the API.
Step 2:  Set AEGIS_WORKER_SIGNING_KEY=newkey on the workers,
         AEGIS_WORKER_SIGNING_KEY_VERSION=2. Rolling restart.
Step 3:  AEGIS_WORKER_KEY_OVERLAP_SECONDS later, drop
         AEGIS_WORKER_SIGNING_KEY_PREVIOUS.
```

In-flight worker tokens minted with v1 keep working through the
overlap. See `aegis/api/auth.py::_verify_worker_token` for the
acceptance logic; see `tests/test_worker_sa_auth.py` for the
guarantees the test suite enforces.

### Keycloak realm signing key

Aegis fetches Keycloak's JWKS via `AEGIS_OIDC_JWKS_URL` and caches
for the process lifetime. After a Keycloak signing key rotation:

- Aegis API: restart so the JWKS cache picks up the new key.
- Aegis worker: same.

NextAuth refreshes JWKS on demand and doesn't need a restart.

---

## What `aegis audit verify --all` should look like at deploy time

```
chain run:run-abc123  ok (42 events)
chain project:proj-a  ok (7 events)
chain system          ok (3 events)

verified 3 chains, 52 events total
```

If you see any chain marked `BROKEN at seq=N`, that's a structural
issue — likely a manual database mutation, a partial restore, or a
clock-skew issue on the writer. The verifier reports the first broken
event; reconcile from there.

---

## Health checks

Each service exposes a unauthenticated `/health` endpoint:

| Service             | Path                          | What it returns                                       |
|---------------------|-------------------------------|-------------------------------------------------------|
| aegis-api           | `/health`                     | `{"status":"ok"}`                                      |
| aegis-worker        | (Celery beat / ping)          | `celery -A aegis.workers.celery_app inspect ping`     |
| aegis-log-ingest    | `/health`                     | `{"status":"ok","buffered":N,"inserted_total":N}`     |
| aegis-web           | `/api/health` (next route, optional) | NextAuth surface; check `/api/auth/session`     |

Compose health checks are configured in `deploy/docker-compose.yml`
for `postgres` and `redis`; add equivalents at the k8s layer when you
get there.

---

## Out of scope for this doc

- HA / multi-region: documented when v0.5 lands the topology changes
  the platform needs (PostgresAuditWriter sharing semantics, Redis
  cluster shape).
- Backup / restore: any standard Postgres backup tool works; the
  audit chain is hash-verifiable so a partial restore is detectable
  via `aegis audit verify`.
- Cost management: per-tenant chargeback dashboards are in the
  deferred list (see [`overview.md`](../architecture/overview.md)).
