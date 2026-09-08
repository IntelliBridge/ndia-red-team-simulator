# Production deployment

This doc is the canonical reference for running Aegis outside a
developer laptop. For day-1 local development see
[`docs/dev/local-stack.md`](../dev/local-stack.md); this file focuses
on the production posture: env vars that must be set, keys that must
be generated, the deployment topology, and the rotation runbook.

For a Kubernetes deploy via the Helm chart (hardened pod specs,
sandbox isolation, HA Keycloak), see [Kubernetes (Helm)](kubernetes.md).
For the auditor-facing evidence bundle, see
[Compliance evidence pack](compliance-evidence.md).

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
(`aegis/llm/pricing.py`), with litellm's price map as a fallback. Per-org
**monthly** caps and per-tenant LLM routing land in the Multi-tenancy
runbook below.

---

## Multi-tenancy / RLS

Cross-org isolation is enforced **at the database** as defense-in-depth on
top of the app-layer project checks. The full design is in
[`docs/architecture/multi-tenancy.md`](../architecture/multi-tenancy.md);
this is the operator-facing runbook.

**RLS is forced at the DB.** Migration `0006_tenant_rls` runs
`ENABLE` + **`FORCE ROW LEVEL SECURITY`** on `projects` and the eight
project-scoped tables (`targets`, `runs`, `jobs`, `findings`, `llm_usage`,
`artifacts`, `remediation_attempts`, `application_logs`), each carrying a
denormalized `org_id` (backfilled, then maintained by a `BEFORE INSERT`
trigger). The `aegis_tenant_isolation` policy filters rows by `org_id`.
`FORCE` is deliberate: it binds the table owner / superuser too, so a
privileged connection can't bypass the boundary. Nothing operator-side
needs to "turn it on" — the migration enables it.

**The GUC is set per request.** The policy reads a per-transaction GUC
`app.current_tenants` (a comma-separated org-id list). The API's tenant
middleware resolves the caller's accessible org ids and
`aegis.db.session.get_session` sets the GUC (via `set_config(…, is_local)`)
for the transaction. An **empty / unset GUC means full access** — there is
nothing for an operator to configure here.

**Workers run as system.** Workers, migrations, and any path that doesn't
set the GUC run with full access (empty GUC). That is intentional:
background execution and `alembic upgrade` need to read/write across orgs.
Do **not** add the tenant middleware to the worker.

**Per-tenant config** lives on the `organizations` row (migration
`0007_org_cost_routing`):

| Column                       | Type    | Meaning                                                  |
|------------------------------|---------|----------------------------------------------------------|
| `monthly_llm_budget_cents`   | INTEGER | Org's monthly LLM spend cap in cents; `NULL` = uncapped. |
| `llm_model_overrides`        | JSONB   | `{task: model}` per-tenant routing overrides; wins over the config default. |

```sql
-- cap an org at $500/month and pin its report-summarize task to a cheaper model
UPDATE organizations
   SET monthly_llm_budget_cents = 50000,
       llm_model_overrides = '{"report_summarize": "gpt-4o-mini"}'::jsonb
 WHERE id = 'org-1';
```

`route()` enforces **both** the project daily cap and the org monthly cap;
`GET /v1/orgs/{org_id}/cost` and the web **/cost** dashboard surface the
spend (see the [API reference](../api/v1.md#orgs-cost)).

**CI exercises it.** RLS enforcement runs in the **Postgres CI jobs** — the
`FORCE` is what makes that test real (the superuser CI connection is bound
by the policy), so a regression that drops or weakens the isolation fails
CI rather than shipping silently.

**Enabling a ticket provider.** Set `AEGIS_TICKET_PROVIDER` to `jira`,
`servicenow`, or `linear` on the api **and** worker, plus the matching
creds (table below). Migration `0008_finding_tickets` must be applied
first. Smoke-test with `POST /v1/findings/{id}/ticket` (needs
`remediator+`): a `201` returns the external id and URL; a `409` means the
provider is still `none` or its creds are missing. Leave it unset and
nothing reaches a tracker.

**Verifying a target.** Register the target, then `GET
/v1/targets/{id}/verification` for the proof to publish — a DNS TXT record
(`url` kind) or a GitHub App installation (`github_repo` kind). Publish it,
then `POST /v1/targets/{id}/verify` (`admin`): `200 {verified:true,…}` on
success, `422` until the proof resolves. Set a strong `AEGIS_VERIFY_SECRET`
in prod so the per-target TXT token can't be forged.

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

!!! warning "Breaking change"
    The legacy non-expiring `worker:<hex>` token has been **removed** — only
    versioned, time-bound worker tokens are accepted now. `AEGIS_WORKER_SIGNING_KEY`
    is therefore **mandatory** for worker auth: without it, workers cannot
    authenticate to the API.

| Var                                  | Where     | Notes                                                       |
|--------------------------------------|-----------|-------------------------------------------------------------|
| `AEGIS_WORKER_SIGNING_KEY`           | api, worker | **Required.** Current shared HMAC key                      |
| `AEGIS_WORKER_SIGNING_KEY_PREVIOUS`  | api       | Previous key accepted during rotation overlap                |
| `AEGIS_WORKER_SIGNING_KEY_VERSION`   | api, worker | Integer, default `1`. Workers increment when rotating.     |
| `AEGIS_WORKER_KEY_OVERLAP_SECONDS`   | api       | Default `300`                                                |
| `AEGIS_WORKER_TOKEN_TTL_SECONDS`     | worker    | Default `300`                                                |

### Key rotation

Pick up rotated/revoked keys without a restart, and ride a graceful dual-key
window during cookie / Fernet rotation. See the
[Rotation runbook](#rotation-runbook) below for the cutover procedures.

| Var                                    | Where       | Notes                                                                                                       |
|----------------------------------------|-------------|-------------------------------------------------------------------------------------------------------------|
| `AEGIS_API_JWKS_CACHE_TTL_SECONDS`     | api, worker | Default `300`. The IdP JWKS is a time-boxed cache, not pinned for the process lifetime — a rotated/revoked Keycloak key is picked up after at most one TTL, no restart. |
| `AEGIS_API_SESSION_PUBLIC_KEY_PREVIOUS`| api         | Previous session public key, accepted **alongside** the current one during a cookie-signing-key rotation. Unset outside rotation. |
| `AEGIS_AUTH_PROFILES_KEY_PREVIOUS`     | api, worker | Previous DAST auth-profile Fernet key. Accepted via **MultiFernet** so existing profiles decrypt without re-creation. Unset outside rotation. |

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

### Vendoring

| Var                          | Where           | Value                                                  |
|------------------------------|-----------------|--------------------------------------------------------|
| `AEGIS_OFFLINE_VENDOR_HOST`  | build / vendoring | Internal git mirror host for air-gapped submodule fetches (e.g. `git.internal.example.com`). See [Air-gapped / offline vendor mirror](#air-gapped-offline-vendor-mirror). |

### WORM audit archive

Off-DB tamper-resistant export of the audit chain (see the
[WORM audit archive runbook](#worm-audit-archive-runbook) below). All
default off / safe; the export beat task self-gates on `AEGIS_WORM_EXPORT`.
S3 endpoint + credentials reuse the `AEGIS_S3_*` vars above.

| Var                          | Where  | Value                                                                |
|------------------------------|--------|----------------------------------------------------------------------|
| `AEGIS_WORM_EXPORT`          | worker | Enable the export (default off `0`). Set `1` to turn WORM on.        |
| `AEGIS_WORM_BUCKET`          | worker | Object-Lock bucket name (default `aegis-worm`).                      |
| `AEGIS_WORM_RETENTION_DAYS`  | worker | Object Lock retention in days (default `2555` ≈ 7y).                 |
| `AEGIS_WORM_LOCK_MODE`       | worker | `COMPLIANCE` (default) or `GOVERNANCE`.                              |
| `AEGIS_WORM_INTERVAL`        | worker | Beat export interval, seconds (default `86400` = daily).            |

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
| `AEGIS_AUTH_PROFILES_KEY`    | api, worker | Fernet key encrypting auth-profile secrets at rest. Required only when using authenticated DAST — see `docs/ops/authenticated-dast.md` upstream (not carried in this fork; the authenticated DAST adapters are removed). |

### Observability

| Var                                | Where               | Notes                                                       |
|------------------------------------|---------------------|-------------------------------------------------------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT`      | api, worker         | Activates the OTel SDK. Without it, logs go to stdout only. |
| `OTEL_RESOURCE_ATTRIBUTES`         | api, worker         | `service.name=...` etc.                                     |
| `AEGIS_LOG_INGEST_URL`             | api, worker         | Default path that bypasses the Collector (default profile)  |

### Integrations (ticket sync, target verification, backports)

All optional and **default-off**. The upstream aegis Integrations guide
(`docs/integrations/index.md`) described the full behaviour; it is not carried in this fork, where ticketing and GitHub App integrations are removed.

| Var                              | Where       | Notes                                                                                          |
|----------------------------------|-------------|------------------------------------------------------------------------------------------------|
| `AEGIS_TICKET_PROVIDER`          | api, worker | `none` \| `jira` \| `servicenow` \| `linear`. Default `none` = no-op (nothing reaches a tracker). |
| `AEGIS_JIRA_URL` / `…_USER` / `…_TOKEN` / `…_PROJECT_KEY` | api, worker | Jira Cloud/Server creds (Basic auth + issue project). Required when provider = `jira`.          |
| `AEGIS_SERVICENOW_INSTANCE` / `…_TOKEN` | api, worker | ServiceNow instance URL + OAuth bearer. Required when provider = `servicenow`.            |
| `AEGIS_LINEAR_API_KEY` / `…_TEAM_ID` | api, worker | Linear API key + team. Required when provider = `linear`.                                  |
| `AEGIS_VERIFY_SECRET`            | api, worker | Server-side salt mixed into the per-target DNS TXT token so it can't be forged. A dev default is used when unset — **set a strong value in prod**. Never logged. |
| `AEGIS_RELEASE_TRAINS`           | api, worker | Release-train → branch map for fix-PR base selection. JSON (`{"2024.1":"release/2024.1"}`) or `name=branch,…`. Unset = every fix PR targets `main`. |

The ticket creds and `AEGIS_VERIFY_SECRET` are read from the environment
only — never from an API body, never persisted to a row, never written to
an audit detail. DNS verification needs `dnspython` (shipped in the `api`
extra).

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

### LLM budget (fail-closed)

| Var                       | Where       | Notes                                                                                                                              |
|---------------------------|-------------|------------------------------------------------------------------------------------------------------------------------------------|
| `AEGIS_LLM_BUDGET_STRICT` | api, worker | Fail-closed budget enforcement. Default **on in prod** (`AEGIS_ENV=prod`). A DB-backed run that reaches an LLM call **without** a budget checker is **denied**; the agent-run worker path is budget-enforced. Set `0` to allow ungoverned LLM calls (not recommended outside dev). |

### Plugin sandbox

Third-party plugin scanners run **out-of-process by default**. This is
defense-in-depth — process isolation + a minimal allowlisted env (parent
secrets never reach plugin code) + POSIX rlimits + own process group with
group-kill on timeout + the Ed25519 signature/allowlist gate. It is **not** a
network or filesystem jail: a hostile plugin can still open sockets / touch
files the worker UID can reach. Kernel-level isolation is upstream ADR-0006 (Firecracker microVM isolation; not carried in this fork).
See `SECURITY.md` § "Plugin sandbox".

| Var                               | Where  | Notes                                                                             |
|-----------------------------------|--------|-----------------------------------------------------------------------------------|
| `AEGIS_PLUGINS_SANDBOX`           | worker | Run plugin scanners out-of-process (default `1`). `0` runs them in-process.        |
| `AEGIS_PLUGIN_SANDBOX_NETWORK`    | worker | Default `0`.                                                                       |
| `AEGIS_PLUGIN_SANDBOX_CPU_SECONDS`| worker | `RLIMIT_CPU` for the plugin child, seconds (default `300`).                         |
| `AEGIS_PLUGIN_SANDBOX_MEMORY_MB`  | worker | `RLIMIT_AS` memory cap, MB (default `1024`).                                        |
| `AEGIS_PLUGIN_SANDBOX_FILESIZE_MB`| worker | `RLIMIT_FSIZE` write cap, MB (default `256`).                                       |

### Iterative remediation (opt-in)

The fix→test→retry loop. Default off (no test command = no loop). The loop
**refuses a dirty working tree** (so it can't destroy operator changes) and
**scrubs fed-back test output for secrets** before it reaches the LLM.

| Var                            | Where  | Notes                                                                                  |
|--------------------------------|--------|----------------------------------------------------------------------------------------|
| `AEGIS_REMEDIATION_TEST_COMMAND` | worker | Command run to validate a generated fix (e.g. `pytest -q`). Unset disables the loop.   |
| `AEGIS_REMEDIATION_MAX_ITERS`  | worker | Max fix→test→retry iterations (default `3`).                                            |

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

## Air-gapped / offline vendor mirror

Aegis vendors several upstream repos as git submodules (CAI, Strix, the
MCP Kali server, …). Behind an air-gap those can't be fetched from
`github.com` / `gitlab.com`. Set **`AEGIS_OFFLINE_VENDOR_HOST`** to an
internal git mirror that serves the same `<org>/<repo>.git` paths, and
the submodule URLs are rewritten to that host (the `<org>/<repo>` path is
preserved):

```
https://github.com/aliasrobotics/cai.git  ->  https://<host>/aliasrobotics/cai.git
git@github.com:usestrix/strix.git          ->  https://<host>/usestrix/strix.git
```

Run the helper from the repo root — it rewrites every URL in
`.gitmodules` (via `git submodule set-url` + `git submodule sync`) and
then fetches:

```bash
AEGIS_OFFLINE_VENDOR_HOST=git.internal.example.com \
  ./scripts/vendor-submodules.sh
```

The script is idempotent (re-running re-applies the same set-url and
re-syncs). With the var unset it leaves URLs untouched and only runs
`git submodule update --init`. The pure rewrite rules live in
`aegis/vendor.py` (`mirror_url`, `submodule_mirror_map`); the shell
helper mirrors them exactly.

`config.offline_vendor_host` (the `AEGIS_OFFLINE_VENDOR_HOST` overlay)
surfaces in **`aegis doctor`**: when set, it prints the mirror host plus
the rewritten URL for each submodule so an operator can confirm the
mapping *before* running the script; when unset it leaves a one-line note
pointing at the env var.

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

## WORM audit archive runbook

The audit chain is append-only at the database and hash-verifiable
(migration `0004`); WORM export adds the third layer — an immutable off-DB
copy. Each chain is exported to an S3 / MinIO bucket with **Object Lock**,
so an attacker who fully owns the database (or the bucket credentials)
still can't alter or delete the sealed copy before its retention expires.
See [`docs/architecture/audit-chain.md`](../architecture/audit-chain.md)
§ "WORM archival (Object Lock)" for the object layout and re-verification.

### 1. Create the Object-Lock bucket

Object Lock is a **bucket-creation-time** property — it cannot be enabled on
an existing bucket. Provision the WORM bucket separately from the main
`AEGIS_S3_BUCKET`.

MinIO (via `mc`):

```bash
mc mb --with-lock myalias/aegis-worm
```

AWS S3: create the bucket with Object Lock enabled (the console's "Object
Lock" toggle at create time, or `aws s3api create-bucket
--object-lock-enabled-for-bucket`). Aegis sets retention **per object** on
each put, so a bucket-level default retention is optional; if you set one,
make it ≤ `AEGIS_WORM_RETENTION_DAYS`.

Grant the worker IAM the `s3:PutObject` + `s3:PutObjectRetention` +
`s3:GetObject` / `s3:ListBucket` it needs on the WORM bucket.

### 2. Enable the daily export

Set the env (worker side) and turn the flag on:

```bash
AEGIS_WORM_EXPORT=1
AEGIS_WORM_BUCKET=aegis-worm
AEGIS_WORM_RETENTION_DAYS=2555      # ≈ 7 years; match your compliance regime
AEGIS_WORM_LOCK_MODE=COMPLIANCE
AEGIS_WORM_INTERVAL=86400           # seconds; daily
```

The `aegis.export_chains_to_worm` beat task is already registered in
`celery beat` (interval = `AEGIS_WORM_INTERVAL`). It **self-gates**: with
`AEGIS_WORM_EXPORT` unset/off it no-ops on every tick, so leaving the task
scheduled costs nothing until you opt in. Each run emits an
`audit.worm_export` event (summary counts only) back onto the chain.

### 3. Export on demand

```bash
aegis audit export --all                 # every chain, now
aegis audit export --chain run:run-abc   # one chain
```

Re-exporting an unchanged chain is a no-op (the object key is derived from
the chain head + content sha). A broken chain is still archived but flagged
`verified=false` in its manifest.

### Retention is immutable until expiry

Pick `AEGIS_WORM_RETENTION_DAYS` to match your compliance regime — once an
object is written, its retention **cannot be shortened**. In `COMPLIANCE`
mode that holds even for the account root; `GOVERNANCE` mode allows a
specially-privileged principal to lift retention (use it only if your
regime permits operator override). Storage costs accrue for the full
retention window, so size the regime deliberately.

---

## Rotation runbook

### Aegis API session keypair (F14a)

The web side mints with the private key; the API verifies with the
public key. A rotation is a controlled bump of both, with a graceful
dual-key window so live sessions don't break at the cutover.

```
Day 0:  generate new keypair (v2).
Day 0:  on the API, set the new public key as AEGIS_API_SESSION_PUBLIC_KEY,
        move the old one to AEGIS_API_SESSION_PUBLIC_KEY_PREVIOUS, and
        bump AEGIS_API_SESSION_KEY_ID=aegis-api-session-v2. The API now
        accepts cookies signed by either key.
Day 0:  set the new private key on the web side. NextAuth callbacks now
        mint v2 cookies.
Day 0 + TTL window:
        all v1 cookies have expired (15 min default).
Day 0 + TTL window: drop AEGIS_API_SESSION_PUBLIC_KEY_PREVIOUS.
```

The API now accepts a **previous** public key
(`AEGIS_API_SESSION_PUBLIC_KEY_PREVIOUS`) alongside the current one, so
in-flight cookies keep validating across the cutover — no forced wave of
fresh sign-ins.

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

Aegis fetches Keycloak's JWKS via `AEGIS_OIDC_JWKS_URL` and caches it for
`AEGIS_API_JWKS_CACHE_TTL_SECONDS` (default `300`) — a time-boxed cache,
**not** pinned for the process lifetime. After a Keycloak signing-key
rotation (or a key revocation), the API and worker pick up the change after
at most one TTL with **no restart**. Lower the TTL if you need a faster
pickup; restart only if you want the change immediately.

NextAuth refreshes JWKS on demand and doesn't need a restart.

### DAST auth-profile Fernet key (`AEGIS_AUTH_PROFILES_KEY`)

Rotating the auth-profile encryption key no longer requires re-creating
profiles. Set the new key as `AEGIS_AUTH_PROFILES_KEY` and the old one as
`AEGIS_AUTH_PROFILES_KEY_PREVIOUS` on the api + worker; decryption tries both
via **MultiFernet** while new writes use the current key. Once profiles have
been re-saved (or you accept that only current-key ciphertext remains), drop
`AEGIS_AUTH_PROFILES_KEY_PREVIOUS`. See
`docs/ops/authenticated-dast.md` § "Key rotation" upstream (not carried in this fork).

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
- Cost management: per-tenant monthly budgets + the chargeback dashboard
  have shipped — see the "Multi-tenancy / RLS" runbook above and
  [`docs/architecture/multi-tenancy.md`](../architecture/multi-tenancy.md).
