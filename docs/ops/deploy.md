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

**Scheduled cleanup (`celery beat`).** Run one `celery -A aegis.workers.celery_app
beat` process alongside the workers. It drives the periodic `aegis.reap_stale_jobs`
task (every 5 min) that marks jobs stuck `running` past
`job_max_runtime_seconds` (default 3600s, set via `aegis.yaml`) as `failed` —
the complement to the worker's redelivery guard. Without a `beat` process,
crashed jobs stay `running` indefinitely.

**LLM budget caps.** Per-project daily spend caps come from
`Project.daily_llm_budget_cents` (unset = unlimited). The fix path records
`llm_usage` rows and `route()` blocks once the day's spend reaches the cap.
Per-call cost is computed from a researched per-model price table
(`aegis/llm/pricing.py`), with litellm's price map as a fallback.

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
| `AEGIS_DB_URL`               | api, worker, log-ingest | Restricted **app** role DSN: `postgresql+psycopg://aegis_app:pass@host:5432/aegis` |
| `AEGIS_DB_OWNER_URL`         | migrations only | **Owner** role DSN used to run Alembic (DDL + GRANTs): `postgresql+psycopg://aegis_owner:pass@host:5432/aegis`. Optional — falls back to `AEGIS_DB_URL` for single-role/dev. |
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

### Policy engine (optional)

The route-level role gate is pluggable (see
[`auth.md`](../architecture/auth.md) § "Policy engine"). Unset, it stays
on the built-in static rule table. Set these only to delegate to an
external decision point; see the runbook below.

| Var                          | Where         | Value                                                  |
|------------------------------|---------------|--------------------------------------------------------|
| `AEGIS_POLICY_ENGINE`        | api, worker   | `static` (default) \| `opa` \| `cedar`                  |
| `AEGIS_OPA_URL`              | api, worker   | OPA base URL (default `http://localhost:8181`)          |
| `AEGIS_OPA_PATH`             | api, worker   | OPA data path (default `/v1/data/aegis/authz`)          |
| `AEGIS_CEDAR_URL`            | api, worker   | cedar-agent base URL (default `http://localhost:8180`)  |

### GitHub App (F23)

| Var                                | Where    | Value                                                |
|------------------------------------|----------|------------------------------------------------------|
| `AEGIS_GITHUB_WEBHOOK_SECRET`      | api      | HMAC verification secret from the App installation   |
| `AEGIS_GITHUB_APP_ID`              | api, worker | Installation app id                               |
| `AEGIS_GITHUB_PRIVATE_KEY`         | api, worker | App private key (PEM)                             |

### Authenticated DAST (optional)

| Var                          | Where       | Notes                                                                 |
|------------------------------|-------------|-----------------------------------------------------------------------|
| `AEGIS_AUTH_PROFILES_KEY`    | api, worker | Fernet key encrypting auth-profile secrets at rest. Required only when using authenticated DAST — see [`authenticated-dast.md`](authenticated-dast.md). |

### Observability

| Var                                | Where               | Notes                                                       |
|------------------------------------|---------------------|-------------------------------------------------------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT`      | api, worker         | Activates the OTel SDK. Without it, logs go to stdout only. |
| `OTEL_RESOURCE_ATTRIBUTES`         | api, worker         | `service.name=...` etc.                                     |
| `AEGIS_LOG_INGEST_URL`             | api, worker         | Default path that bypasses the Collector (default profile)  |

### Third-party plugin signatures

Opt-in Ed25519 signature enforcement for marketplace plugins (off by
default). Set on every process that discovers plugins (`AEGIS_PLUGINS=1`):
the api, worker, and CLI. See
[supply-chain integrity](../security/supply-chain.md#signed-third-party-plugins)
and [Extending Aegis](../dev/extending.md#signature-enforcement-aegis_plugins_require_signature).

| Var                                | Where             | Notes                                                                                   |
|------------------------------------|-------------------|-----------------------------------------------------------------------------------------|
| `AEGIS_PLUGINS_REQUIRE_SIGNATURE`  | api, worker, cli  | `1`/truthy requires a valid signature before any plugin loads. Unset = no signature check. |
| `AEGIS_PLUGINS_TRUSTED_KEYS`       | api, worker, cli  | Colon/comma-separated `*.pem` **public-key** files and/or directories of them.          |
| `AEGIS_PLUGINS_SIG_DIR`            | api, worker, cli  | Dirs holding `<dist>-<version>.sig` files (falls back to trusted-key dirs + the plugin's module dir). |

### LLM guardrails

Two fail-safe layers (secret scrubbing of generated diffs/LLM output +
prompt-injection detection on untrusted input) wrap every LLM chokepoint.
All default **on**; leave them on in production. See `SECURITY.md`
§ "LLM guardrails" and [`overview.md`](../architecture/overview.md)
§ "LLM guardrails".

| Var                              | Where        | Notes                                                                 |
|----------------------------------|--------------|-----------------------------------------------------------------------|
| `AEGIS_LLM_GUARDRAILS`           | api, worker  | Master switch for both layers. Default **on**; `0`/`off` disables all. |
| `AEGIS_LLM_SCRUB_DIFF`           | api, worker  | Secret-scrub generated diffs/patches (`***REDACTED***`). Default **on**. |
| `AEGIS_LLM_DETECT_INJECTION`     | api, worker  | Prompt-injection detection on untrusted finding fields + prompts. Default **on**. |
| `AEGIS_LLM_FILTER_OUTPUT`        | api, worker  | Secret-scrub LLM output at the remediation/agent chokepoints. Default **on**. |
| `AEGIS_LLM_INJECTION_BLOCK_RISK` | api, worker  | Block threshold: `none`/`low`/`medium`/`high` (default `high`); `off` = detect-and-log only. |

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

# Postgres with pgaudit (or use a managed PG with pgaudit enabled)
docker build -t aegis-postgres -f deploy/Dockerfile.postgres .
```

All Dockerfiles install from the repo root, so the build context must
be the repo root (`docker build … .`). The web image consumes the pnpm
workspace at the same root path.

---

## Verify release images before deploy

Release builds (on `v*` tags) are pushed to GHCR, **keyless-signed** with
cosign, and carry a CycloneDX SBOM + SLSA provenance attestation — see
[`.github/workflows/release-sign.yml`](https://github.com/IntelliBridge/aegis/blob/main/.github/workflows/release-sign.yml)
and the [supply-chain integrity](../security/supply-chain.md#signed-attested-release-images)
page. **Verify each image by digest before `docker compose up` / `kubectl
apply`** so a tampered or unsigned image fails the gate. Wire this into the
deploy pipeline; do not deploy an image that fails verification.

```bash
# Per image: api | worker | web | log_ingest, pinned by digest.
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/IntelliBridge/aegis/' \
  ghcr.io/intellibridge/aegis/<service>@<DIGEST>

# Optional but recommended: also verify the SBOM + SLSA provenance.
cosign verify-attestation --type cyclonedx \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/IntelliBridge/aegis/' \
  ghcr.io/intellibridge/aegis/<service>@<DIGEST>
```

`scripts/verify-release.sh` wraps the full set (signature + SBOM +
provenance, the last under the slsa-github-generator identity). Always
verify and deploy the `@sha256:…` digest, not a floating tag — cosign signs
the digest, and a tag can be re-pointed after verification.

---

## First-deploy checklist

1. **Database**: provision Postgres with two roles so the audit log is
   append-only at the DB (migration `0004`). The owner holds DDL; the app
   role the api/worker connect as cannot `UPDATE`/`DELETE` `audit_events`:
   ```sql
   CREATE ROLE aegis_owner LOGIN PASSWORD '…';          -- owns the schema, runs migrations
   CREATE ROLE aegis_app   LOGIN PASSWORD '…';           -- restricted runtime role
   ALTER DATABASE aegis OWNER TO aegis_owner;
   GRANT aegis_app TO aegis_owner;                        -- so the owner can hand out grants
   ```
   Apply migrations **as the owner** (the migration also issues the
   guarded `REVOKE`/`GRANT`s and `CREATE EXTENSION pgaudit`):
   ```bash
   AEGIS_DB_OWNER_URL=postgresql+psycopg://aegis_owner:…@host:5432/aegis \
     alembic -c alembic.ini upgrade head
   ```
   Then point the runtime `AEGIS_DB_URL` at `aegis_app`. The current
   migration head is `0005_auth_profiles`. Single-role/dev may skip the
   roles entirely — the migration's role/grant steps no-op when the roles
   are absent, and Alembic falls back to `AEGIS_DB_URL`.

   **pgaudit** (out-of-band logging of DDL + role/GRANT changes, so disabling
   the controls is recorded) needs the extension preloaded *before*
   `CREATE EXTENSION` can succeed — a server-level setting that can't live in
   a migration transaction. Run Postgres from `deploy/Dockerfile.postgres`
   (installs `postgresql-16-pgaudit`, sets `shared_preload_libraries=pgaudit`
   and `pgaudit.log='ddl, role'`), or on a managed/self-hosted server set the
   equivalent and reload:
   ```sql
   ALTER SYSTEM SET shared_preload_libraries = 'pgaudit';   -- needs a restart
   ALTER SYSTEM SET pgaudit.log = 'ddl, role';              -- SELECT pg_reload_conf();
   ```
   Migration `0004` additionally sets `pgaudit.log` per-role (`ALTER ROLE`).
   Where pgaudit is unavailable (e.g. stock image) the migration logs a
   notice and skips it; the trigger-based append-only guarantee still holds.
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
        helper; explicit dual-public-key acceptance is not yet shipped).
Day 0:  set new private key on the web side. NextAuth callbacks now
        mint v2 cookies.
Day 0 + TTL window:
        all v1 cookies have expired (15 min default).
Day 0 + TTL window: drop the v1 public key.
```

The API still verifies against a single public key; graceful dual-key
rotation is not yet shipped. Until then, plan for a ~15-minute window
of fresh sign-ins during the cutover.

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

### Database role passwords (`aegis_app` / `aegis_owner`)

Rotate the role passwords on your normal secret cadence:

```
aegis_app:    ALTER ROLE aegis_app PASSWORD '…';  then update AEGIS_DB_URL
              on api + worker + log-ingest and rolling-restart.
aegis_owner:  ALTER ROLE aegis_owner PASSWORD '…'; update AEGIS_DB_OWNER_URL
              wherever migrations run (CI/CD secret, ops shell).
```

Do **not** run the app as `aegis_owner` to "simplify" — that hands the
runtime the privileges (DDL, `DROP TRIGGER`) that the split exists to
withhold. The owner role is only for migrations.

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

## External policy engine (optional)

By default the role gate uses the built-in static rule table — no extra
service. To delegate the role-rank decision to OPA or Cedar instead,
stand up the decision point, load the example policy (which replicates
the static table, so it's a behaviour-identical drop-in), and point the
API + worker at it via `AEGIS_POLICY_ENGINE`. Both external engines
**fail closed**: if the engine is unreachable, slow, or returns a bad
answer, the gate denies (`403`) — so a misconfigured sidecar locks the
platform down, it never opens it up.

**OPA.** Bring up the bundled `opa` service (it lives under a non-default
`policy` compose profile, so a plain `docker compose up` never starts it):

```bash
docker compose --profile policy up opa
# or, without compose, run OPA directly over the example policy dir:
opa run --server --addr 0.0.0.0:8181 deploy/opa/
```

The example policy ships at `deploy/opa/aegis-authz.rego` (package
`aegis.authz`); the compose service mounts `deploy/opa/` read-only. Then
point Aegis at it on the API + worker:

```bash
export AEGIS_POLICY_ENGINE=opa
export AEGIS_OPA_URL=http://opa:8181        # http://localhost:8181 outside compose
export AEGIS_OPA_PATH=/v1/data/aegis/authz  # default
```

**Cedar.** Cedar runs as a `cedar-agent` sidecar (not bundled in the
compose stack) loaded with `deploy/cedar/aegis-policy.cedar` plus the
schema/entity notes in `deploy/cedar/aegis-entities.md`. The agent host
resolves the caller's role for the request's project before evaluation.
Point Aegis at it:

```bash
export AEGIS_POLICY_ENGINE=cedar
export AEGIS_CEDAR_URL=http://cedar-agent:8180
```

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
