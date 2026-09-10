# Production deployment

This doc is the canonical reference for running redsim outside a developer
laptop. For day-1 local development see
[`docs/dev/local-stack.md`](../dev/local-stack.md). This page covers the
production posture: env vars that must be set, keys that must be generated,
the deployment topology, image boundaries, and the rotation runbook.

For a Kubernetes deploy via the Helm chart (hardened pod specs, gVisor
sandbox, HA Keycloak), see [Kubernetes (Helm)](kubernetes.md). For the LLM
gateway see [Pythia access](pythia.md). For the auditor-facing evidence
bundle, see [Compliance evidence pack](compliance-evidence.md). The ECS
Fargate target is section 20.4 of the
[product spec](../superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md)
and is not built yet (WS7, PR #19 is an open draft).

---

## Topology

```mermaid
flowchart LR
  subgraph internet["Internet"]
    users["Users"]
    pythia["Pythia gateway"]
  end

  subgraph edge["Edge"]
    lb["Load balancer + TLS"]
  end

  subgraph cluster["Cluster / hosts"]
    web["redsim-web"]
    api["redsim-api"]
    worker["redsim-worker (-Q scans)"]
    workerd["redsim-worker-default (-Q default)"]
    beat["redsim-beat"]
    li["redsim-log-ingest"]
    col["otel-collector (optional)"]
  end

  subgraph data["Data plane"]
    pg[("Postgres")]
    redis[("Redis")]
    blob[("S3 artifacts")]
    worm[("S3 WORM (Object Lock)")]
    kc["Keycloak"]
    loki[("Loki (optional)")]
  end

  users --> lb
  lb --> web
  lb --> api
  web --> api
  api --> redis
  worker --> redis
  workerd --> redis
  beat --> redis
  api --> pg
  worker --> pg
  workerd --> pg
  api --> blob
  worker --> blob
  workerd --> worm
  api --> kc
  workerd --> pythia
  worker --> col
  api --> col
  col --> loki
  col --> li
  li --> pg
```

The four application images (`redsim-api`, `redsim-worker`, `redsim-web`,
`redsim-log-ingest`) all build from `deploy/Dockerfile.*` in this repo. The
worker image runs the `scans` pool, the `default` pool and `beat`. The
data-plane services are the standard upstream images (Postgres from
`deploy/Dockerfile.postgres`, which adds pgaudit).

**Image boundaries.** `deploy/Dockerfile.api` installs `.[api,worker]` and
never carries the `ml` extra. `tests/test_api_process_has_no_ml.py` enforces
that the API process imports no torch, ART, onnxruntime or SHAP.
`deploy/Dockerfile.worker` installs the CPU torch wheels first, then
`.[worker,ml]`, and is the only process that loads a model, inside the
sandboxed child. Both Dockerfiles copy any `.pem` / `.crt` under
`deploy/certs/` into the system trust store for proxied networks.

**Queues.** `redsim-worker` consumes `scans` (long-running: today
`redsim.scan_start` and `redsim.verify_replay`, later `model.validate`,
`attack.run`, `explain.run`). `redsim-worker-default` consumes `default`
(`redsim.report_render`, `redsim.reap_stale_jobs`,
`redsim.verify_tenant_integrity`, `redsim.export_chains_to_worm`, later
`harden.recommend` with the Pythia writer). The split keeps a 30-minute
attack from starving a report or the LLM call.

**Scheduled work (`celery beat`).** Run exactly one `celery -A
redsim.workers.celery_app beat` process. It drives `redsim.reap_stale_jobs`
(every 5 min, marks jobs stuck `running` past `job_max_runtime_seconds`,
default 3600 s in `redsim.yaml`, as `failed`), `redsim.verify_tenant_integrity`
(hourly) and `redsim.export_chains_to_worm` (`REDSIM_WORM_INTERVAL`). Compose
runs it as `redsim-beat`. The Helm chart has no beat Deployment yet (see
[Kubernetes](kubernetes.md#replicas)), and the Fargate plan runs it as a
single-task service.

**LLM budget caps.** Per-project daily caps come from
`Project.daily_llm_budget_cents` (unset = unlimited), per-org monthly caps
from `organizations.monthly_llm_budget_cents`. `route()` records `llm_usage`
rows and blocks once a cap is reached. Per-call cost comes from the price
table in `redsim/llm/pricing.py`. Pythia is the only transport (D5), so every
row is a Pythia call under task `ml.harden_narrative`.

---

## Multi-tenancy / RLS

Cross-org isolation is enforced **at the database** as defense in depth on
top of the app-layer project checks. The design is
[`docs/architecture/multi-tenancy.md`](../architecture/multi-tenancy.md).
This is the operator-facing runbook.

**RLS is forced at the DB.** Migration `0006_tenant_rls` runs `ENABLE` plus
`FORCE ROW LEVEL SECURITY` on `projects` and the eight project-scoped tables
(`targets`, `runs`, `jobs`, `findings`, `llm_usage`, `artifacts`,
`remediation_attempts`, `application_logs`), and `0010_ml_vertical` adds
`ml_campaigns` with the same denormalized `org_id`, backfill trigger, drift
guard and `redsim_tenant_isolation` policy. `FORCE` binds the table owner and
superuser too. Nothing operator-side needs to turn it on.

**The GUC is set per request.** The policy reads `app.current_tenants` (a
comma-separated org-id list). The API's tenant middleware resolves the
caller's org ids and `redsim.db.session.get_session` sets the GUC for the
transaction. An empty or unset GUC means full access.

**Workers run as system.** Workers, migrations and `alembic upgrade` run
with the empty GUC. Do **not** add the tenant middleware to the worker.

**Per-tenant config** lives on the `organizations` row (migration
`0007_org_cost_routing`):

| Column | Type | Meaning |
|---|---|---|
| `monthly_llm_budget_cents` | INTEGER | Org's monthly LLM spend cap in cents, `NULL` = uncapped. |
| `llm_model_overrides` | JSONB | `{task: model}` per-tenant routing overrides. With Pythia as transport the values are Pythia model ids (`<vendor>/<model>` or `pythia/auto`). |

```sql
UPDATE organizations
   SET monthly_llm_budget_cents = 50000,
       llm_model_overrides = '{"ml.harden_narrative": "amazon/nova-lite-v1:0"}'::jsonb
 WHERE id = 'org-1';
```

`GET /v1/orgs/{org_id}/cost` and the web **/cost** page surface the spend
(see the [API reference](../api/v1.md#orgs-cost)). RLS enforcement runs in
the Postgres CI jobs, so a regression fails CI.

---

## Required env vars

### Identity

| Var | Required where | Notes |
|---|---|---|
| `REDSIM_ENV` | api, worker, web | `prod` disables dev tokens and asserts secure cookies |
| `REDSIM_AUTH_MODE` | api | `oidc` in prod (`dev` only for local development and the demo behind a restricted listener) |
| `REDSIM_OIDC_ISSUER` | api | Keycloak realm URL |
| `REDSIM_OIDC_AUDIENCE` | api | Default `redsim` |
| `REDSIM_OIDC_JWKS_URL` | api | Keycloak realm's `/protocol/openid-connect/certs` |
| `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET`, `KEYCLOAK_ISSUER`, `KEYCLOAK_PUBLIC_ISSUER` | web | The realm the login route runs the password grant against (`KEYCLOAK_ISSUER` equals `REDSIM_OIDC_ISSUER`; the public issuer is accepted as a token issuer too). The `redsim-web` client needs direct access grants on. The compose realm's client is public (empty secret); the EC2 realm's is confidential and carries one |
| `REDSIM_WEB_SESSION_SECRET` | web | Seals the refresh cookie and signs the sign-out hop token. At least 32 characters; rotating it signs every browser out. The web process refuses to boot without it. The retired `BETTER_AUTH_SECRET` is read as a fallback |
| `REDSIM_WEB_ORIGIN` | web | Public web URL, the same-origin check on the auth routes. The web process refuses to boot without it. The retired `BETTER_AUTH_URL` is read as a fallback |

### redsim-signed cookie

The login route signs with the private key after the realm accepted the
credentials, FastAPI verifies with the public key. Both halves are required. Supply
only the private half and the login completes, then every API call answers 401.

| Var | Where set | Value |
|---|---|---|
| `REDSIM_API_SESSION_PRIVATE_KEY` | web | PKCS8 PEM, 2048-bit RSA |
| `REDSIM_API_SESSION_PUBLIC_KEY` | api | SubjectPublicKeyInfo PEM, matching public half |
| `REDSIM_API_SESSION_KEY_ID` | both | Default `redsim-api-session-v1`, increment on rotation |
| `REDSIM_API_SESSION_TTL_SECONDS` | both | Default `900` |
| `REDSIM_API_SESSION_COOKIE` | both | Default `redsim_api_session` |
| `REDSIM_CSRF_COOKIE` / `REDSIM_CSRF_HEADER` | both | Defaults `redsim_csrf` / `X-Redsim-CSRF` |
| `REDSIM_WEB_ORIGIN` | api | The web origin allowed for credentialed CORS |

```python
from redsim.api.session_cookie import generate_keypair
private_pem, public_pem = generate_keypair()
```

Store both halves in the secret store: the private half for the web side, the
public half for the API side. The Helm chart carries them as
`config.secret.apiSessionPrivateKey` and `config.secret.apiSessionPublicKey`,
and refuses to render a `config.env=prod` release while either is empty.

### Worker service account

The legacy non-expiring `worker:<hex>` token was removed upstream. Only
versioned, time-bound worker tokens are accepted, so
`REDSIM_WORKER_SIGNING_KEY` is mandatory.

| Var | Where | Notes |
|---|---|---|
| `REDSIM_WORKER_SIGNING_KEY` | api, worker | **Required.** Current shared HMAC key |
| `REDSIM_WORKER_SIGNING_KEY_PREVIOUS` | api | Previous key accepted during rotation overlap |
| `REDSIM_WORKER_SIGNING_KEY_VERSION` | api, worker | Integer, default `1` |
| `REDSIM_WORKER_KEY_OVERLAP_SECONDS` | api | Default `300` |
| `REDSIM_WORKER_TOKEN_TTL_SECONDS` | worker | Default `300` |

### Key rotation

| Var | Where | Notes |
|---|---|---|
| `REDSIM_API_JWKS_CACHE_TTL_SECONDS` | api, worker | Default `300`. The IdP JWKS is a time-boxed cache, so a rotated or revoked Keycloak key is picked up within one TTL. |
| `REDSIM_API_SESSION_PUBLIC_KEY_PREVIOUS` | api | Previous session public key, accepted alongside the current one during rotation. Unset outside rotation. |
| `REDSIM_AUTH_PROFILES_KEY_PREVIOUS` | api, worker | Previous auth-profile Fernet key (MultiFernet). Unset outside rotation. |

### Data plane

| Var | Where | Value |
|---|---|---|
| `REDSIM_DB_URL` | api, worker, log-ingest | Restricted **app** role DSN: `postgresql+psycopg://redsim_app:pass@host:5432/redsim` |
| `REDSIM_DB_OWNER_URL` | migrations only | **Owner** role DSN for Alembic (DDL plus GRANTs). Optional, falls back to `REDSIM_DB_URL` for single-role or dev. |
| `REDSIM_BROKER_URL` | api, worker | `redis://host:6379/0` |
| `REDSIM_RESULT_BACKEND` | worker | `redis://host:6379/1` |
| `REDSIM_BLOB_BACKEND` | api, worker | `s3` |
| `REDSIM_S3_ENDPOINT`, `REDSIM_S3_BUCKET`, `REDSIM_S3_REGION` | api, worker | S3-compatible endpoint, bucket (default `redsim`), region |
| `REDSIM_S3_ACCESS_KEY_ID` / `REDSIM_S3_SECRET_ACCESS_KEY` | api, worker | Bucket credentials. Prefer an IAM task role on AWS. |

### WORM audit archive

Off-DB tamper-resistant export of the audit chain (runbook below). All
default off. S3 endpoint and credentials reuse the `REDSIM_S3_*` vars.

| Var | Where | Value |
|---|---|---|
| `REDSIM_WORM_EXPORT` | worker | `1` enables the export (default `0`). |
| `REDSIM_WORM_BUCKET` | worker | Object-Lock bucket name (default `redsim-worm`). |
| `REDSIM_WORM_RETENTION_DAYS` | worker | Object Lock retention in days (default `2555`, about 7 years). |
| `REDSIM_WORM_LOCK_MODE` | worker | `COMPLIANCE` (default) or `GOVERNANCE`. |
| `REDSIM_WORM_INTERVAL` | worker | Beat export interval in seconds (default `86400`). |

### CORS / network

| Var | Where | Value |
|---|---|---|
| `REDSIM_CORS_ORIGINS` | api | Comma-separated, explicit origin list |
| `REDSIM_WEB_ORIGIN` | api | Always added to the CORS allowlist |
| `REDSIM_RL_USER_PER_MIN` | api | Per-user rate limit on write routes (default `30`) |
| `REDSIM_RL_PROJECT_PER_MIN` | api | Per-project rate limit (default `120`) |

### Policy engine (optional)

| Var | Where | Value |
|---|---|---|
| `REDSIM_POLICY_ENGINE` | api, worker | `static` (default), `opa` or `cedar` |
| `REDSIM_OPA_URL` / `REDSIM_OPA_PATH` | api, worker | OPA base URL (default `http://localhost:8181`) and data path (default `/v1/data/redsim/authz`) |
| `REDSIM_CEDAR_URL` | api, worker | cedar-agent base URL (default `http://localhost:8180`) |

### Auth profiles

| Var | Where | Notes |
|---|---|---|
| `REDSIM_AUTH_PROFILES_KEY` | api, worker | Fernet key encrypting auth-profile secrets at rest. Required to create a profile. Profiles are kept for the Phase B black-box endpoint connector and are unused in Phase A. |

### Pythia (LLM gateway)

Full runbook in [Pythia access](pythia.md). Set on the worker that runs the
`default` queue when the hardening narrative should run. No provider key
exists anywhere in the deployment.

| Var | Where | Notes |
|---|---|---|
| `PYTHIA_BASE_URL` | worker (`default` pool) | Gateway base URL |
| `PYTHIA_API_KEY` | worker (secret) | `pk_…` gateway key, the only LLM credential |
| `PYTHIA_PERSONA` | worker, optional | Sent as `X-Pythia-Persona` |
| `PYTHIA_TIMEOUT_S` | worker, optional | Default `60` |
| `REDSIM_ML_LLM_MODEL` | worker | `<vendor>/<model>` or `pythia/auto` |
| `REDSIM_TLS_TRUSTSTORE`, `REDSIM_CA_BUNDLE` | worker | TLS trust for the gateway behind an inspecting proxy (default: OS store via `truststore`) |
| `REDSIM_DISABLE_LLM` | worker | Compose sets `1` on the worker anchor. Unset it on `redsim-worker-default` for the narrative. |

### LLM guardrails and budget

All default on. Config lives in `redsim/config.py`. See `SECURITY.md`.

| Var | Where | Notes |
|---|---|---|
| `REDSIM_LLM_GUARDRAILS` | api, worker | Master switch. `0` disables all. |
| `REDSIM_LLM_SCRUB_DIFF`, `REDSIM_LLM_DETECT_INJECTION`, `REDSIM_LLM_FILTER_OUTPUT` | api, worker | Secret scrubbing of LLM I/O and prompt-injection detection on untrusted input. |
| `REDSIM_LLM_INJECTION_BLOCK_RISK` | api, worker | Block threshold `none`/`low`/`medium`/`high` (default `high`), `off` = detect and log. |
| `REDSIM_LLM_BUDGET_STRICT` | api, worker | Fail-closed budget enforcement, default on in prod. A DB-backed run that reaches an LLM call without a budget checker is denied. |

### Plugin sandbox

Third-party adapters discovered from the entry-point groups run
out-of-process by default. This is process isolation plus rlimits plus a
wall-clock kill plus a minimal environment, gated by the allowlist and
signature check. It is not a network or filesystem jail. See `SECURITY.md`.

| Var | Where | Notes |
|---|---|---|
| `REDSIM_PLUGINS` | api, worker, cli | `1` enables third-party discovery (default off). |
| `REDSIM_PLUGINS_ALLOW` | api, worker, cli | Distribution allowlist. Set it in production. |
| `REDSIM_PLUGINS_REQUIRE_SIGNATURE`, `REDSIM_PLUGINS_TRUSTED_KEYS`, `REDSIM_PLUGINS_SIG_DIR` | api, worker, cli | Ed25519 signature enforcement, see [supply-chain integrity](../security/supply-chain.md#signed-third-party-plugins). |
| `REDSIM_PLUGINS_SANDBOX` | worker | Run plugin `scan()` out-of-process (default `1`). |
| `REDSIM_PLUGIN_SANDBOX_NETWORK` | worker | Default `0`. |
| `REDSIM_PLUGIN_SANDBOX_CPU_SECONDS` / `_MEMORY_MB` / `_FILESIZE_MB` | worker | `RLIMIT_CPU` (default `300`), `RLIMIT_AS` (`1024`), `RLIMIT_FSIZE` (`256`). |

### ML vertical (planned, spec section 20.3)

These are named by the spec for the code in the open ML PRs and WS4. Nothing
on `main` reads them yet except `REDSIM_ML_DATASET_CACHE` (the default
`--out` of the `build-assets` skeleton).

| Var | Where | Meaning |
|---|---|---|
| `REDSIM_ML_UPLOAD_MAX_MB` | api | Hard cap on uploaded model size (default 512), `413` above it. |
| `REDSIM_ML_DATASET_CACHE` | worker | Volume for the dataset cache used by `build-assets` and the loaders. Mount it so the dataset fetch happens once. |
| `REDSIM_ML_WORK_DIR`, `REDSIM_ML_KEEP_WORK_DIR` | worker | Per-job work directories the sandbox parent populates (default `$TMPDIR/redsim-ml/<job_id>`, mode 0700, removed after the job). |
| `REDSIM_ML_SANDBOX_TIMEOUT_S`, `_CPU_SECONDS`, `_MEMORY_MB`, `_FILESIZE_MB`, `_THREADS` | worker | Ceilings of the ML sandbox child (defaults 1200 s, 900 s, 4096 MB, 1024 MB, 2 threads). No network switch exists. The wall clock must stay below the Celery soft limit (1800 s) and the reaper TTL. |
| `REDSIM_ML_MAX_ADV_ARTIFACT_MB` | worker | Size above which the full adversarial slice is not retained (default 64). |
| `KAGGLE_USERNAME`, `KAGGLE_KEY` | the one-off `redsim ml build-assets` run only | Download the malicious-URLs CSV. Never on the API, web, steady-state worker or beat, never in the sandbox child, never logged. |

### Observability

| Var | Where | Notes |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | api, worker | Activates the OTel SDK. Without it, logs go to stdout only. |
| `OTEL_RESOURCE_ATTRIBUTES` | api, worker | `service.name=...` |
| `REDSIM_LOG_INGEST_URL` | api, worker | Direct path to `redsim-log-ingest`, bypassing the Collector (default profile) |

### Air-gapped installs

`REDSIM_OFFLINE_VENDOR_HOST` names an internal package or artifact mirror and
surfaces in `redsim doctor` and the evidence pack. The submodule URL-rewrite
helper that used it upstream was removed with the pentest domain. For the ML
vertical the equivalent concern is the dataset hosts (HuggingFace hub and the
Kaggle API), which are reached only by the one-off `build-assets` run.

---

## Build pipeline

```bash
docker build -t redsim-api        -f deploy/Dockerfile.api .
docker build -t redsim-worker     -f deploy/Dockerfile.worker .
docker build -t redsim-log-ingest -f deploy/Dockerfile.log_ingest .
docker build -t redsim-web        -f deploy/Dockerfile.web .
docker build -t redsim-postgres   -f deploy/Dockerfile.postgres .   # postgres 16 + pgaudit
```

All Dockerfiles install from the repo root, so the build context must be the
repo root. The web image consumes the pnpm workspace at the same root path.
CI builds the four application images without pushing (`Build images` job).
On 2026-09-08 the web image build is red on `main`: `deploy/Dockerfile.web`
runs `corepack prepare pnpm` on the `node:26` base image, which no longer
ships corepack.

`deploy-aws.yml` builds the api, worker and web images and pushes them to ECR
under `ndia-red-team/<name>:<sha>` using GitHub OIDC, then rolls whichever
`ECS_SERVICE_*` repo variables are set. It currently fails at "Configure AWS
credentials" (the AssumeRole is refused account-side).

---

## Verify release images before deploy

Release builds (on `v*` tags) are pushed to GHCR, keyless-signed with cosign,
and carry a CycloneDX SBOM plus SLSA provenance (`release-sign.yml`, see
[supply-chain integrity](../security/supply-chain.md#signed-attested-release-images)).
Verify each image by digest before `docker compose up` or `kubectl apply`:

```bash
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/IntelliBridge/ndia-red-team-simulator/' \
  ghcr.io/intellibridge/ndia-red-team-simulator/<service>@<DIGEST>

cosign verify-attestation --type cyclonedx \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/IntelliBridge/ndia-red-team-simulator/' \
  ghcr.io/intellibridge/ndia-red-team-simulator/<service>@<DIGEST>
```

`scripts/verify-release.sh` wraps the full set. Always deploy the
`@sha256:…` digest, not a floating tag.

---

## First-deploy checklist

1. **Database**: provision Postgres with two roles so the audit log is
   append-only at the DB (migration `0004`):
   ```sql
   CREATE ROLE redsim_owner LOGIN PASSWORD '…';   -- owns the schema, runs migrations
   CREATE ROLE redsim_app   LOGIN PASSWORD '…';   -- restricted runtime role
   ALTER DATABASE redsim OWNER TO redsim_owner;
   GRANT redsim_app TO redsim_owner;
   ```
   Apply migrations **as the owner**:
   ```bash
   REDSIM_DB_OWNER_URL=postgresql+psycopg://redsim_owner:…@host:5432/redsim \
     alembic -c alembic.ini upgrade head
   ```
   The current head is `0010_ml_vertical`. Then point the runtime
   `REDSIM_DB_URL` at `redsim_app`. Single-role or dev installs may skip the
   roles, the migration's grant steps no-op when they are absent.

   **pgaudit** needs the extension preloaded before `CREATE EXTENSION`. Run
   Postgres from `deploy/Dockerfile.postgres`, or set
   `shared_preload_libraries = 'pgaudit'` and `pgaudit.log = 'ddl, role'` on
   the managed server. Where pgaudit is unavailable the migration logs a
   notice and skips it, the trigger-based append-only guarantee still holds.
2. **Blob store**: create the artifacts bucket, grant the api and worker the
   read and write they need. Create the WORM bucket with Object Lock enabled
   (below) if you enable the export.
3. **Keycloak**: realm and client per `deploy/keycloak/realm-export.json`.
   The client must carry `redsim_project_roles` in the id_token. Add the
   `viewer` realm role (spec section 7.2).
4. **API session keypair**: run `generate_keypair()`, stash the private key in
   the web secret store, set the public key as API env.
5. **Worker SA key**: generate a strong shared secret, set
   `REDSIM_WORKER_SIGNING_KEY` on both sides.
6. **Pythia**: set `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `REDSIM_ML_LLM_MODEL`
   (and `PYTHIA_PERSONA`) on the `default` worker pool, unset
   `REDSIM_DISABLE_LLM` there, and run
   `python -m redsim.llm.pythia_check` from the worker image to prove the
   gateway is reachable through the proxy.
7. **CORS allowlist**: `REDSIM_CORS_ORIGINS` and `REDSIM_WEB_ORIGIN`.
8. **Smoke**: deploy api, worker pools, beat, log-ingest and web, then
   `redsim --api status` and `GET /health`.
9. **Audit verify**: `redsim audit verify --all` prints every chain as ok.
10. **Assets** (once PR #9 lands): run `redsim ml build-assets` once on the
    worker image with `KAGGLE_USERNAME` / `KAGGLE_KEY` in that run's
    environment only, so the bundled models, datasets and `MANIFEST.json`
    land in the blob store. The manifests are the only source of
    clean-accuracy numbers.

---

## WORM audit archive runbook

The audit chain is append-only at the database and hash-verifiable
(migration `0004`). WORM export adds an immutable off-DB copy in an S3 or
MinIO bucket with **Object Lock**, so an attacker who owns the database or
the bucket credentials still cannot alter the sealed copy before retention
expires. See [`docs/architecture/audit-chain.md`](../architecture/audit-chain.md).

### 1. Create the Object-Lock bucket

Object Lock is a bucket-creation-time property. Provision the WORM bucket
separately from `REDSIM_S3_BUCKET`.

```bash
mc mb --with-lock myalias/redsim-worm                        # MinIO
aws s3api create-bucket --bucket redsim-worm --object-lock-enabled-for-bucket   # AWS
```

redsim sets retention per object on each put. Grant the worker
`s3:PutObject`, `s3:PutObjectRetention`, `s3:GetObject` and `s3:ListBucket`
on the WORM bucket.

### 2. Enable the daily export

```bash
REDSIM_WORM_EXPORT=1
REDSIM_WORM_BUCKET=redsim-worm
REDSIM_WORM_RETENTION_DAYS=2555
REDSIM_WORM_LOCK_MODE=COMPLIANCE
REDSIM_WORM_INTERVAL=86400
```

The `redsim.export_chains_to_worm` beat task self-gates on
`REDSIM_WORM_EXPORT`, so leaving it scheduled costs nothing until you opt in.
Each run emits an `audit.worm_export` event (summary counts only).

### 3. Export on demand

```bash
redsim audit export --all
redsim audit export --chain run:run-abc
```

Re-exporting an unchanged chain is a no-op (the key derives from the chain
head plus content sha). A broken chain is still archived and flagged
`verified=false` in its manifest.

### Retention is immutable until expiry

Once an object is written its retention cannot be shortened. In `COMPLIANCE`
mode that holds even for the account root. `GOVERNANCE` allows a
specially-privileged principal to lift retention. Storage costs accrue for
the full window, so size the regime deliberately.

---

## Rotation runbook

### API session keypair

```
Day 0:  generate new keypair (v2).
Day 0:  on the API, set the new public key as REDSIM_API_SESSION_PUBLIC_KEY,
        move the old one to REDSIM_API_SESSION_PUBLIC_KEY_PREVIOUS, and
        bump REDSIM_API_SESSION_KEY_ID=redsim-api-session-v2.
Day 0:  set the new private key on the web side. Better Auth now mints v2 cookies.
Day 0 + TTL window (15 min default): drop REDSIM_API_SESSION_PUBLIC_KEY_PREVIOUS.
```

### Worker SA key

```
Step 1:  Set REDSIM_WORKER_SIGNING_KEY=newkey, REDSIM_WORKER_SIGNING_KEY_PREVIOUS=oldkey,
         REDSIM_WORKER_SIGNING_KEY_VERSION=2. Restart the API.
Step 2:  Set REDSIM_WORKER_SIGNING_KEY=newkey and VERSION=2 on the workers. Rolling restart.
Step 3:  REDSIM_WORKER_KEY_OVERLAP_SECONDS later, drop REDSIM_WORKER_SIGNING_KEY_PREVIOUS.
```

See `redsim/api/auth.py::_verify_worker_token` and
`tests/test_worker_sa_auth.py`.

### Keycloak realm signing key

redsim fetches the JWKS from `REDSIM_OIDC_JWKS_URL` and caches it for
`REDSIM_API_JWKS_CACHE_TTL_SECONDS` (default `300`). After a rotation or
revocation the API and worker pick up the change within one TTL with no
restart. Better Auth resolves the realm through OIDC discovery at startup.

### Auth-profile Fernet key

Set the new key as `REDSIM_AUTH_PROFILES_KEY` and the old one as
`REDSIM_AUTH_PROFILES_KEY_PREVIOUS` on api and worker. Decryption tries both
(MultiFernet), new writes use the current key. Drop the previous key once
profiles have been re-saved.

### Pythia key

Provisioned by the Pythia operators per team and persona. Replace
`PYTHIA_API_KEY` in the worker's secret store, roll the `default` pool, and
re-run `python -m redsim.llm.pythia_check`. Entitlements are a property of
the key and persona, so re-check the model list after a change.

### Database role passwords

```
redsim_app:    ALTER ROLE redsim_app PASSWORD '…', then update REDSIM_DB_URL
               on api, workers and log-ingest and rolling-restart.
redsim_owner:  ALTER ROLE redsim_owner PASSWORD '…', update REDSIM_DB_OWNER_URL
               wherever migrations run.
```

Do **not** run the app as `redsim_owner`. The owner role is only for
migrations.

---

## What `redsim audit verify --all` should look like at deploy time

```
chain run:run-abc123  ok (42 events)
chain project:proj-a  ok (7 events)
chain system          ok (3 events)

verified 3 chains, 52 events total
```

A chain marked `BROKEN at seq=N` is a structural issue (a manual mutation, a
partial restore, clock skew on the writer). The verifier reports the first
broken event, reconcile from there.

---

## External policy engine (optional)

By default the role gate uses the built-in static table. To delegate to OPA
or Cedar, stand up the decision point, load the example policy (a
behaviour-identical drop-in), and point the API and worker at it. Both
external engines fail closed: unreachable, slow or malformed answers deny.

**OPA.** The bundled `opa` service lives under the `policy` compose profile:

```bash
docker compose -f deploy/docker-compose.yml --profile policy up -d opa
# or: opa run --server --addr 0.0.0.0:8181 deploy/opa/
export REDSIM_POLICY_ENGINE=opa
export REDSIM_OPA_URL=http://opa:8181
export REDSIM_OPA_PATH=/v1/data/redsim/authz
```

The example policy is `deploy/opa/redsim-authz.rego` (package
`redsim.authz`). The seven ML `Action` rows have to be present in the bundle
before the ML routes are used with this engine.

**Cedar.** Run a `cedar-agent` sidecar loaded with
`deploy/cedar/redsim-policy.cedar` and the entity notes in
`deploy/cedar/redsim-entities.md`, then `REDSIM_POLICY_ENGINE=cedar` and
`REDSIM_CEDAR_URL=http://cedar-agent:8180`.

---

## Health checks

| Service | Path | What it returns |
|---|---|---|
| redsim-api | `/health` | `{"status":"ok","env":"…","db_configured":true}` |
| redsim-worker | Celery ping | `celery -A redsim.workers.celery_app inspect ping` |
| redsim-log-ingest | `/health` | `{"status":"ok","buffered":N,"inserted_total":N}` |
| redsim-web | `/` | Next.js app root, the path the chart probes |

Compose health checks are configured in `deploy/docker-compose.yml` for
`postgres` and `redis`. The Helm chart adds probes on every service.

---

## Out of scope for this doc

- ECS Fargate specifics (task sizing for torch on CPU, ephemeral storage for
  the dataset cache, the one-off migration task, Secrets Manager wiring):
  spec section 20.4, built by WS7.
- HA and multi-region: [ADR-0005](../adr/0005-worker-autoscaling-and-dr.md).
- Backup and restore: any standard Postgres backup tool works. The audit
  chain is hash-verifiable, so a partial restore is detectable via
  `redsim audit verify`.
