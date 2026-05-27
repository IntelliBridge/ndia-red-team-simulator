# Aegis — Phase 3 Development Plan

> Status entering Phase 3: Phase 2 scaffold complete. 121 unit/integration tests
> passing on Python 3.12. The deterministic E2E demo runs end-to-end. Patch
> workflow is safe (branch-first + rollback). Safety gate, stage provenance,
> dep verification via Trivy rescan, and `aegis targets` CLI are all in place.
>
> Goal of Phase 3: turn the single-user CLI into a **multi-user, API-backed,
> auditable platform** that an org can deploy and adopt. Not yet full
> production — that's Phase 4. This phase establishes the spine: persistence,
> auth, API, workers, GitHub App, scanner plugin abstraction, and a minimal
> read-only web dashboard.

---

## Executive Summary — What Changes in Phase 3

1. **Server-shaped, not CLI-shaped.** A FastAPI service wraps the existing
   Python modules. The CLI becomes one of two clients (the other is the web
   UI). All state lives in Postgres; `aegis_output/` becomes a transient
   working dir for workers, not the source of truth.
2. **Auth, not anonymous.** Keycloak (or any OIDC provider) gates every API
   call. RBAC distinguishes *scanner*, *remediator*, *approver*, *admin*.
3. **Async, not blocking.** Long-running operations (Strix scan, CAI patch,
   verification) run in worker processes against a durable queue.
4. **GitHub App, not local gh.** Org-installable app with webhook-driven
   scans replaces the shell-out to `gh pr create`.
5. **Pluggable scanners, not hard-coded ones.** A `ScannerAdapter` interface
   lets us add Semgrep, ZAP, CodeQL, etc., without touching `cmd_scan`.
6. **Audit log becomes tamper-evident.** A hash-chained audit table replaces
   the flat JSONL — a modest change with a large compliance unlock.
7. **A minimal read-only web UI.** Not the final product UI; enough that a
   non-CLI user can see runs, findings, and reports. Full write-side UI is
   **deferred**.

What Phase 3 explicitly does **not** do is called out in §1.3.

---

## 1. Phase Objectives

### 1.1 Exact outcome
A running deployment of:

- **`aegis-api`** — FastAPI service exposing `/runs`, `/findings`, `/scans`,
  `/fix-attempts`, `/audit`, `/health`, with OIDC bearer-token auth.
- **`aegis-worker`** — Celery/Temporal worker that consumes `scan.start`,
  `fix.generate`, `verify.replay` jobs and writes results back through the
  same persistence layer.
- **Postgres** with a versioned schema (migrations via Alembic).
- **`aegis-web`** — a minimal Next.js dashboard (read-only) that lists runs,
  shows finding tables, renders the same report content, and links to PRs.
- **GitHub App** installed against a demo org — opens PRs and posts back
  scan-result check-runs.
- **Keycloak** (or any OIDC provider) issuing tokens; ngrok/Tailscale-style
  hostname is fine for the demo.
- All current CLI surfaces continue to work and talk to the API instead of
  the filesystem when `AEGIS_API_URL` is set; the local filesystem mode
  remains available for offline / CI scenarios.

### 1.2 Definition of "done"
- `make up` (docker-compose or k8s/kind manifest) starts Postgres + Keycloak
  + api + worker + web on a clean Mac/Linux box.
- A user logs into the web UI via OIDC, triggers a scan against a registered
  target (Juice Shop image), waits for it to finish, sees findings, and
  follows the link to the auto-opened PR.
- The CLI talks to the API by default when `AEGIS_API_URL` is set; the
  existing fixture-assisted offline path still works.
- Audit log is hash-chained and verifiable via `aegis audit verify`.
- `pytest -q` is green; new integration tests exercise: API auth, RBAC,
  worker enqueue/consume, scanner-adapter dispatch, GitHub-App PR opening
  (against a fake GitHub).
- E2E test: deterministic fixture-assisted run through the API + worker,
  not just the in-process function call.

### 1.3 Out of scope for Phase 3 (deferred to Phase 4+)
- **Full multi-tenancy.** Phase 3 supports multiple users but a single
  tenant; no row-level isolation across orgs. (Phase 4)
- **Strict sandbox isolation per scan** (gVisor / Firecracker). Workers
  still run in shared k8s pods; cross-job isolation is best-effort. (Phase 4)
- **Production-grade observability.** OpenTelemetry traces + Prometheus
  metrics are added at the call-site level but no SLO dashboards or paging
  integration yet. (Phase 4)
- **SOC 2 / ISO 27001 / FedRAMP** evidence pack. (Phase 4+)
- **PII / secret scrubbing pipeline.** We rely on the diff/report being
  reviewable; redaction is a Phase 4 workstream. (Phase 4)
- **LLM prompt-injection / output-filtering guards.** (Phase 4)
- **Full write-side web UI.** Phase 3 UI is read-only plus "trigger scan"
  and "open PR" buttons; bulk triage / suppression workflows are Phase 4.
- **Multi-region deployment / DR / RPO-RTO.** (Phase 5)
- **Backports / release-train awareness for generated PRs.** (Phase 4)
- **Cost accounting per tenant.** Hooks land in Phase 3 (request IDs,
  span attributes); aggregation/dashboards are Phase 4.
- **Bidirectional Jira / ServiceNow / Linear sync.** GitHub Issues only in
  Phase 3 via the GitHub App. (Phase 4)
- **Native MCP protocol.** We keep the REST shim for `mcp-kali-server`.
  (Phase 4)
- **Iterative agent loops with test execution.** Patch generation remains
  single-shot in Phase 3. (Phase 4)
- **Authenticated DAST flows.** Stay on unauthenticated routes. (Phase 4)
- **Cloud-target ownership verification** (DNS TXT, GitHub repo linkage).
  (Phase 4)
- **Image / IaC / SBOM scanning beyond `trivy fs`.** (Phase 4)
- **Reproducible-build provenance (SLSA-3+) for Aegis itself.** (Phase 4)
- **Worker autoscaling / Karpenter / HPA tuning.** Fixed worker count in
  Phase 3. (Phase 4)
- **Web UI design polish.** Phase 3 UI is functional, not branded.

---

## 2. Technical Workstreams

### 2.1 Persistence — Postgres + Alembic
- New module: `aegis/db/` with SQLAlchemy 2.x models and Alembic migrations.
- Tables (initial set):
  - `runs(id uuid pk, created_at, created_by, mode, status, target_pack,
    repo_url, stage_table jsonb)`
  - `findings(id uuid pk, run_id fk, source_finding_id, schema_blob jsonb,
    status, severity, source_tool, ...)` — `schema_blob` is the existing
    `AegisFinding.to_dict()`; we index the hot columns.
  - `artifacts(id uuid pk, run_id, kind, path_or_blob_ref, sha256)`
  - `remediation_attempts(id uuid pk, finding_id, action, branch,
    commit_hash, ref_before, diff_sha256, pr_url, success, error,
    created_at)`
  - `audit_events(id bigserial pk, run_id, action, target, allowlist_check,
    override, success, detail jsonb, prev_hash bytea, this_hash bytea,
    created_at, actor)`
  - `targets(id, owner, kind, url_or_repo, verified, allowlist_until)`
  - `users(id, sub, email, display_name, roles[])`
- Migrations via Alembic; `aegis-api` runs `alembic upgrade head` on boot.
- The existing `RunState` class becomes a *back-end-agnostic* facade with
  two implementations: `FilesystemRunState` (today) and `PostgresRunState`
  (new). The API uses Postgres; the offline CLI uses the filesystem one.
- Object storage for large artifacts (patches, evidence): S3-compatible
  backend (MinIO in dev). Blobs are referenced by sha256 from
  `artifacts.path_or_blob_ref`.

### 2.2 Identity, authN/Z, audit chain
- **Keycloak** in docker-compose for dev; production deploy assumes any
  OIDC issuer with PKCE support.
- API uses FastAPI's `Depends(get_current_user)` to verify JWT signature
  against the JWKS endpoint; user upserted into `users` on first login.
- **RBAC** roles seeded at boot:
  - `scanner` — start scans, view findings.
  - `remediator` — same plus produce patches and (dry-run) bumps.
  - `approver` — same plus `--apply` and `--open-pr`.
  - `admin` — manage targets, users, allowlist, system config.
- Authorization is a thin policy layer (`aegis.auth.policy.check(user,
  action, resource)`) backed by a static rule table in Phase 3. (OPA/Cedar
  is **deferred**.)
- **Hash-chained audit**: every insert into `audit_events` computes
  `this_hash = sha256(prev_hash || canonical_json(record))`. A
  `aegis audit verify` CLI subcommand walks the chain and reports any
  break.
- Tokens for `aegis-worker` → `aegis-api` use a service account.
- All existing `aegis.safety.authorize` callers now also pass the actor's
  user id; on the CLI side a local-only "cli-actor" is used when offline.

### 2.3 API service — `aegis-api`
- Stack: FastAPI + Uvicorn + Pydantic 2 + SQLAlchemy 2 async.
- Surface (versioned at `/v1`):
  - `POST /v1/scans` → `{ target, mode, instruction? }` → enqueues job,
    returns `run_id`.
  - `GET  /v1/runs/{id}` and `GET /v1/runs` (paginated).
  - `GET  /v1/runs/{id}/findings`.
  - `GET  /v1/findings/{id}`.
  - `POST /v1/findings/{id}/fix` — body says `{ strategy: patch|live|deps,
    apply: bool, open_pr: bool, repo? }` → enqueues a `fix.generate` job.
  - `POST /v1/findings/{id}/verify` → enqueues `verify.replay`.
  - `GET  /v1/runs/{id}/report.{md|json|html}` — proxies the rendered
    report from the worker's artifact storage.
  - `GET  /v1/audit/verify` (admin) — server-side hash-chain check.
- OpenAPI / Swagger UI served at `/docs` (gated by `admin` role in prod,
  open in dev).
- WebSocket `/v1/runs/{id}/events` streams stage transitions and new
  findings as they happen. (Used by the web UI.)

### 2.4 Workers — `aegis-worker`
- Celery 5 with Redis broker (Phase 3 default). Migration path to Temporal
  is documented but **deferred**.
- Tasks: `scan.start`, `fix.generate`, `verify.replay`, `report.render`.
- Each task takes a `run_id` and uses `PostgresRunState` to read/write
  state. Existing functions (`run_demo`, `run_strix`, `run_code_fix`,
  `verify_finding`) become the task bodies — no business logic moves.
- Idempotency: task keys are `(run_id, task_name)`; retries are safe
  (writes go through `INSERT ... ON CONFLICT DO NOTHING` where applicable).
- Concurrency limits: per-target rate limit (one active scan per target),
  global Strix concurrency cap.
- Cancellation: `DELETE /v1/runs/{id}` revokes the task and marks the run
  `cancelled`.

### 2.5 GitHub App
- New module: `aegis/integrations/github_app.py`.
- App permissions (minimum): Contents (read/write), Pull requests
  (read/write), Checks (write), Metadata (read).
- Webhooks consumed:
  - `pull_request.synchronize` — if the PR is on an Aegis branch, post a
    Checks summary linking back to the run.
  - `push` to default branch — optional auto-scan trigger (config flag).
- Replaces the `gh pr create` shell-out in `patch_workflow.open_pull_request`
  with a typed HTTP call; the existing function gains a `client` parameter
  so the CLI offline mode can still use `gh`.
- Installation IDs live in `targets.kind="github_repo"` rows with the org
  → installation_id mapping cached.

### 2.6 Pluggable scanner abstraction
- New module: `aegis/scanners/` with:
  ```python
  class ScannerAdapter(Protocol):
      name: str
      capabilities: set[Literal["dast", "sast", "dependency", "iac", "secret"]]
      def scan(self, target: ScanTarget, run_state: RunStateAPI,
               options: ScanOptions) -> ScanResult: ...
  ```
- Registered via entry points (`[project.entry-points."aegis.scanners"]`)
  so third parties can ship adapters as separate packages.
- Phase 3 ships: `StrixAdapter` (today's `strix_runner`), `TrivyAdapter`
  (today's `trivy_runner`). A third stub adapter (`Semgrep`) lands as
  proof of the extension point but is wired only to validate the registry.
- `cmd_scan` becomes a dispatcher that picks adapters by `--scanner` flag
  (or by target capability matrix).
- **Deferred**: ZAP, CodeQL, Bandit, Grype, Checkov, Trufflehog.

### 2.7 Minimal web UI — `aegis-web`
- Next.js 14 app. Pages:
  - `/login` — OIDC redirect.
  - `/dashboard` — list of recent runs with status, severity histogram.
  - `/runs/[id]` — stage table, finding table, links to artifacts.
  - `/findings/[id]` — full finding detail, before/after evidence,
    remediation timeline, PR link.
  - `/targets` (admin) — register/edit targets.
- "Trigger scan" button is the only write action in Phase 3 UI. Approval
  workflows, bulk operations, suppression are **deferred**.
- Auth: NextAuth.js / Auth.js with OIDC provider config.
- Real-time: subscribes to `/v1/runs/{id}/events` WebSocket.
- Build artifact: a single Docker image.

### 2.8 Observability hooks (foundations only)
- OpenTelemetry SDK on `aegis-api` and `aegis-worker`. Spans for: HTTP
  request, DB query, scan/fix/verify task, scanner-adapter call.
- Logs: structured JSON via `structlog`; correlation id from incoming
  request.
- Metrics: a small `/metrics` Prometheus endpoint counts scans-by-status,
  fix-success-rate, verify-status-distribution.
- **Deferred**: SLO definitions, dashboards, paging routes.

### 2.9 Packaging & deployment
- Three Docker images: `aegis-api`, `aegis-worker`, `aegis-web`. Built
  reproducibly via a single Dockerfile per target with multi-stage builds.
- `make up` runs docker-compose with Postgres, Redis, Keycloak, MinIO,
  api, worker, web. `make seed` populates a demo target + a sample user.
- A kind-based (Kubernetes-in-Docker) variant lands as `make k8s-up` for
  validation; production manifests (helm) are **deferred**.
- Dependency lock files: `uv.lock` (Python) and `pnpm-lock.yaml` (web).

### 2.10 CI/CD evolution
- Existing `.github/workflows/aegis-ci.yml` keeps the Python matrix +
  leak-check.
- New jobs:
  - `api-integration` — spins up Postgres + Redis as services, runs
    integration tests against the API.
  - `web-build` — Next.js typecheck + build.
  - `docker-images` — buildx + sbom + sigstore signing of all three
    images. (Signing infra is staged but the actual keys land in Phase 4.)
- E2E job (workflow_dispatch): full docker-compose stack + Playwright
  test that logs in, triggers a scan, and asserts on the report URL.

---

## 3. Concrete Implementation Tasks

### 3.1 Files to create
| Path | Purpose |
|---|---|
| `aegis/db/__init__.py`, `aegis/db/models.py`, `aegis/db/session.py` | SQLAlchemy models + async session |
| `aegis/db/migrations/` (Alembic) | Versioned schema |
| `aegis/state_pg.py` | `PostgresRunState` implementing the shared RunState facade |
| `aegis/state_facade.py` | Abstract `RunStateAPI` + factory selecting fs vs pg |
| `aegis/api/__init__.py` | FastAPI app factory |
| `aegis/api/v1/{runs,findings,scans,fix,verify,audit,reports,health}.py` | Route handlers |
| `aegis/api/auth.py` | OIDC JWT verification + `get_current_user` dep |
| `aegis/api/policy.py` | RBAC policy table + `check()` |
| `aegis/api/ws.py` | `/v1/runs/{id}/events` WebSocket |
| `aegis/workers/celery_app.py` | Celery app + task definitions |
| `aegis/workers/tasks/{scan,fix,verify,report}.py` | Task bodies |
| `aegis/integrations/github_app.py` | App-installation HTTP client; replaces `gh` shell-out |
| `aegis/integrations/github_webhooks.py` | FastAPI webhook receiver |
| `aegis/scanners/__init__.py`, `aegis/scanners/registry.py` | Adapter registry + Protocol |
| `aegis/scanners/strix_adapter.py`, `aegis/scanners/trivy_adapter.py` | Adapters wrapping existing runners |
| `aegis/scanners/semgrep_adapter.py` | Stub adapter validating the extension point |
| `aegis/audit/chain.py` | Hash-chained audit insert + verify |
| `aegis/cli/audit.py` | `aegis audit verify` subcommand |
| `web/` | Next.js app (pages, components, OIDC config) |
| `deploy/docker-compose.yml`, `deploy/Makefile`, `deploy/kind.yaml` | Dev orchestration |
| `deploy/Dockerfile.{api,worker,web}` | Image builds |
| `deploy/keycloak/realm-export.json` | Seeded realm with roles |
| `tests/integration/test_api_auth.py` | OIDC + RBAC happy/sad paths |
| `tests/integration/test_worker_enqueue.py` | Celery task contract |
| `tests/integration/test_scanner_registry.py` | Adapter dispatch |
| `tests/integration/test_github_app_pr.py` | Mock GitHub App PR open |
| `tests/integration/test_audit_chain.py` | Chain integrity (positive + tamper) |
| `tests/e2e/test_full_stack.py` | Playwright login → scan → report |

### 3.2 Files to modify
| Path | Change |
|---|---|
| `aegis/cli.py` | Switch default backend to API when `AEGIS_API_URL` is set; keep offline filesystem mode |
| `aegis/safety.py` | `authorize()` gains `actor: str`; audit insert routes through `aegis.audit.chain` |
| `aegis/remediate/patch_workflow.py::open_pull_request` | Optional `client` parameter; default still `gh` for offline |
| `aegis/state.py` (existing `RunState`) | Implement the `RunStateAPI` facade so it stays usable in offline mode |
| `pyproject.toml` | Add `fastapi`, `uvicorn`, `sqlalchemy[asyncio]`, `asyncpg`, `alembic`, `celery[redis]`, `structlog`, `opentelemetry-sdk`, `httpx`, `authlib`, `boto3` (S3), `prometheus-client` |
| `.github/workflows/aegis-ci.yml` | Add `api-integration`, `web-build`, `docker-images`, `e2e-stack` jobs |

### 3.3 API contracts (initial cut)

**Trigger a scan**
```http
POST /v1/scans
{ "target": "github:owner/repo", "scanner": "strix",
  "instruction": "focus on auth flows" }
→ 202 { "run_id": "...", "status_url": "/v1/runs/<id>" }
```

**Open a PR for a finding**
```http
POST /v1/findings/{id}/fix
{ "strategy": "patch", "apply": true, "open_pr": true }
→ 202 { "task_id": "...", "run_id": "..." }
```

**Audit verification**
```http
GET /v1/audit/verify?since=2026-01-01
→ 200 { "verified": true, "events": 12345, "broken_at": null }
```

### 3.4 Expected artifacts in object storage (replacing the local run dir)
```
s3://aegis/<run_id>/findings.json
s3://aegis/<run_id>/report.{md,json,html}
s3://aegis/<run_id>/artifacts/patches/<finding_id>.diff
s3://aegis/<run_id>/artifacts/evidence/<finding_id>/before.json
s3://aegis/<run_id>/artifacts/evidence/<finding_id>/after.json
s3://aegis/<run_id>/strix/{events.jsonl,strix.log}
```
Pointers (`sha256` + `s3 path`) live in the `artifacts` table. Local
filesystem mode keeps writing under `aegis_output/runs/<run_id>/`.

---

## 4. Architecture Decisions

### 4.1 SQLAlchemy + Alembic vs. raw SQL
**Decision:** SQLAlchemy 2.x async + Alembic. Mature, schema migrations are
non-negotiable for a server, and we get JSONB out of the box for the
`schema_blob`. Trade-off accepted: heavier dependency than `asyncpg` alone.

### 4.2 Celery vs. Temporal vs. arq
**Decision:** Celery + Redis broker for Phase 3. Familiar, simple,
well-documented. Temporal is more powerful (durable workflows, retries,
saga-style compensations) but adds operational complexity we don't yet
need. Document the migration shape; **defer** the migration itself.

### 4.3 Keycloak vs. cloud IdP
**Decision:** Keycloak for dev. The auth code is provider-agnostic (any
OIDC issuer works); Keycloak gives us a local, deterministic dev
environment. Production deployments swap in their own IdP via env var.

### 4.4 GitHub App vs. PAT-only
**Decision:** GitHub App. PATs don't scale to org-wide adoption, can't
post Check Runs without expanding scope, and require manual per-repo
configuration. The App formalizes the trust boundary and unlocks
webhook-driven scans.

### 4.5 Scanner registry shape
**Decision:** Entry-point-based plugin registration (Python's standard
mechanism). Adapters can ship as separate packages and don't need to be
forks of Aegis. The `Protocol` is intentionally small (`scan()` returns
`ScanResult`) — capability flags rather than inheritance.

### 4.6 Hash-chained audit
**Decision:** SHA-256 chain inserted via DB trigger or app-level
transaction (start with app-level for portability). Each event references
the previous event's hash; tamper detection is a single linear scan. WORM
storage is **deferred**; the chain is the cheap upgrade we take now.

### 4.7 Web UI scope discipline
**Decision:** Read-mostly UI in Phase 3. The only write actions are
"trigger scan" and "open PR for finding." Bulk triage, suppression, custom
queries are explicitly **deferred** to Phase 4 to keep this phase from
ballooning.

---

## 5. Testing Strategy

### 5.1 Unit
- Existing 121 tests stay green and continue to run on Python 3.12.
- New unit tests for: `state_pg`, hash-chain integrity, OIDC token
  validation (with a fake JWKS), RBAC policy table.

### 5.2 Integration
- Postgres + Redis as `services:` in CI. Tests spin up `aegis-api` in-process.
- Celery tasks tested via `task.apply()` (eager mode) and via a real worker
  in a separate integration job.
- Scanner-adapter dispatch tested with two mock adapters and the real
  Strix/Trivy adapters in subprocess mode.
- GitHub App tested against `httpx_mock` / `responses` fakes; the live
  variant runs on `workflow_dispatch` with a sacrificial demo repo.

### 5.3 E2E (Playwright)
- docker-compose stack up.
- Login → trigger scan against the bundled Juice Shop image target →
  poll until `runs/<id>` is `completed` → click into a finding → assert
  the report link works → assert the PR link exists.
- Gated on `AEGIS_E2E_STACK=1`; manual `workflow_dispatch` only.

### 5.4 Mocking strategy (additions)
| Dependency | Mock |
|---|---|
| Postgres | testcontainers in CI; sqlite-in-memory is **not** acceptable (jsonb behaviour differs) |
| Redis / Celery broker | Eager mode for unit; real Redis for integration |
| Keycloak | A `JWKSStub` that signs tokens with a known key |
| GitHub App | `httpx_mock` library; webhook receiver tested with replayed payloads |
| S3 / MinIO | `moto` library or a real MinIO container |

---

## 6. Risks and Mitigations

| Risk | L | I | Mitigation |
|---|---|---|---|
| Postgres adoption silently breaks offline CLI | M | H | The `RunStateAPI` facade keeps both backends; integration tests run the CLI against both. |
| OIDC misconfig locks operators out | M | C | First-boot bootstrap admin token printed to logs; rotate after first login; docs cover IdP recovery. |
| Worker queue saturation under burst | M | H | Per-target rate limits; explicit concurrency caps; admission control on `/v1/scans`. |
| GitHub App permissions creep | L | H | Lock to least-privilege scopes in the App manifest; CI fails if the manifest diverges. |
| Hash-chain breaks under restore | L | C | Document restore procedure: chain is verified after restore; broken chain is a P0 alert, not a silent state. |
| Plugin registry imports a hostile adapter | L | C | Adapter loading happens once at startup, signed entry points only in Phase 4 (**deferred**); meanwhile, Phase 3 ships only built-in adapters and refuses unknown names. |
| Web UI scope creep eats the phase | H | M | Hard cap: read-only + 2 write actions. Any other request is a Phase 4 backlog ticket; reviewed weekly. |
| LLM cost balloons under multi-user | M | H | Per-user rate limit; per-org daily budget (alert at 80%, hard-stop at 100%); `AEGIS_DISABLE_LLM=1` worker mode for tenants that prefer the golden-patch fallback. |
| Migration from filesystem to Postgres on existing data | M | M | `aegis migrate fs->pg` one-shot script reads `aegis_output/runs/*` and inserts; documented and idempotent. |
| FastAPI async + sync subprocess interplay | M | M | Workers (Celery) own subprocess invocation; the API is fully async and never calls Strix/Trivy directly. |
| Keycloak operational burden in prod | M | M | Document the swap to managed IdP (Auth0, Okta, Cognito); env-var-only config so swap is one deployment. |

---

## 7. Prioritized Backlog

### Must-have (Phase 3 gate)
1. Postgres + Alembic + `RunStateAPI` facade.
2. FastAPI service (read + write endpoints listed in §2.3).
3. OIDC auth + RBAC table + `actor` threaded through the audit log.
4. Hash-chained audit log + `aegis audit verify`.
5. Celery worker + the four canonical tasks.
6. GitHub App + webhook receiver + PR opening through the app.
7. Scanner registry + Strix/Trivy adapters refactored onto it.
8. Minimal Next.js dashboard (login, runs, findings, report).
9. docker-compose stack with Postgres, Redis, Keycloak, MinIO, api,
    worker, web.
10. CI jobs for api-integration, web-build, and the stack E2E (manual).

### Should-have
11. Semgrep stub adapter (validates the extension point).
12. WebSocket event stream for live UI updates.
13. `aegis migrate fs->pg` one-shot importer for Phase 2 runs.
14. Prometheus `/metrics` on api + worker.
15. OpenTelemetry SDK wired (no dashboards yet).
16. Demo Helm chart skeleton (no production hardening).

### Nice-to-have
17. Coverage delta gate in CI.
18. Asciinema recording of the full stack demo, embedded in README.
19. CLI command `aegis status` showing API health + queue depth +
    last-run summary.

### Explicit defer (Phase 4)
- Multi-tenant row-level isolation.
- Sandbox isolation per scan (gVisor / Firecracker).
- Full UI write-side (triage, bulk ops, suppression).
- LLM prompt-injection / output filtering.
- PII / secret scrubbing pipeline.
- ZAP / CodeQL / Bandit / Grype / Checkov / Trufflehog adapters.
- ServiceNow / Jira / Linear / Slack-as-a-system-of-record.
- Native MCP protocol.
- Cost accounting & per-tenant chargeback.
- Reproducible build / SLSA-3+ supply chain.
- Authenticated DAST.
- Cloud target ownership verification (DNS TXT, etc.).
- Backports / release-train awareness.
- Iterative patch agent loops with test execution.
- SOC 2 / ISO 27001 / FedRAMP evidence pack.
- Multi-region DR.

### Explicit defer (Phase 5+)
- HA Keycloak / IdP hardening.
- Per-tenant LLM model routing.
- Marketplace for community scanner adapters.
- On-prem air-gapped distribution.

---

## 8. Suggested Implementation Order (Milestones)

Each milestone is a PR-sized chunk you could merge independently. Total
budget: ~8 working weeks for one engineer; 6 weeks for two working in
parallel along the natural seam at M5 vs M6.

### M0 — Repo hygiene + initial commit (½ day)
- `git add . && git commit -m "Phase 2 scaffold"` — unblocks remote
  tooling (e.g. `/ultraplan`).
- Add `CONTRIBUTING.md` skeleton, `SECURITY.md`, `CHANGELOG.md`.

**Validate:** `git log --oneline -3` shows the initial commit; the
existing 121-test suite still passes.

### M1 — RunState facade + Postgres (3 days)
- Introduce `RunStateAPI` Protocol; refactor existing code to use it.
- Add SQLAlchemy models + Alembic migration `0001_initial.sql`.
- Implement `PostgresRunState` with parity tests against `FilesystemRunState`.

**Validate:** existing tests still pass; new `tests/integration/test_state_pg.py`
runs against a real Postgres in testcontainers.

### M2 — Hash-chained audit (2 days)
- New `aegis.audit.chain` module; replace `_append_audit` writes.
- `aegis audit verify` CLI.

**Validate:** `pytest tests/integration/test_audit_chain.py`; tamper-injection
test breaks the chain at the expected point.

### M3 — FastAPI service skeleton + OIDC (4 days)
- Bare API with `/health`, `/runs`, `/findings` (read-only).
- OIDC via `authlib`; Keycloak realm export checked in.

**Validate:** `pytest tests/integration/test_api_auth.py`; manual login
via Swagger.

### M4 — RBAC + write endpoints (3 days)
- Policy table; `check()` dep on each write route.
- `POST /v1/scans`, `POST /v1/findings/{id}/fix`, `POST /v1/findings/{id}/verify`.

**Validate:** RBAC happy/sad-path tests; bare role can't `--apply`.

### M5 — Celery workers (4 days)
- Worker app + four tasks reusing existing function bodies.
- Move `run_demo`/`run_strix`/`run_code_fix`/`verify_finding` behind the
  task interface; API enqueues tasks via Redis.

**Validate:** `pytest tests/integration/test_worker_enqueue.py`; manual
`celery worker` consumes a scan and writes findings.

### M6 — Scanner registry (3 days)
- Entry-point-based registry + `StrixAdapter` + `TrivyAdapter`.
- Semgrep stub adapter; CLI/API `--scanner` flag selects.

**Validate:** `pytest tests/integration/test_scanner_registry.py`;
`aegis scan --scanner trivy --repo /tmp/...` produces dep findings.

### M7 — GitHub App (4 days)
- App manifest; installation flow documented.
- `aegis/integrations/github_app.py` replaces `gh` shell-out.
- Webhook receiver posts Check Runs.

**Validate:** `pytest tests/integration/test_github_app_pr.py`;
manual install against a sacrificial repo; PR opens, Check appears.

### M8 — Minimal web UI (5 days)
- Next.js app with the four pages from §2.7.
- NextAuth.js OIDC; reads the same Keycloak realm.
- WebSocket subscription for live stage updates.

**Validate:** Playwright test logs in, triggers a scan, sees findings,
follows the report link. Manual demo recorded.

### M9 — Object storage for artifacts (2 days)
- MinIO in compose; `aegis/blobs.py` puts/gets artifacts.
- Workers write artifacts to MinIO; API streams them out.

**Validate:** `pytest tests/integration/test_blobs.py`; full-stack
report.html renders from MinIO.

### M10 — Observability hooks (2 days)
- OpenTelemetry on api + worker.
- Prometheus `/metrics`.

**Validate:** spans visible in a local Jaeger; `/metrics` returns the
expected counter set.

### M11 — fs→pg migration tool + docs (2 days)
- `aegis migrate fs->pg --source aegis_output/`.
- README + ADRs for Phase 3 architecture.

**Validate:** migrating a real Phase 2 run yields identical
`/v1/runs/{id}` responses.

### M12 — CI + stack E2E (2 days)
- New CI jobs; Playwright job under `workflow_dispatch`.
- Tag a `v0.3.0` release.

**Validate:** PR opened against `main` has all CI checks green; manual
E2E dispatch passes.

---

## 9. Success Criteria for the Phase 3 Demo

### 9.1 The narrative
A new engineer onboards to a fresh deployment in under 30 minutes:

```bash
git clone <aegis repo> && cd Pentest
make up                              # Postgres, Redis, Keycloak, MinIO, api, worker, web
# Wait for compose health; visit http://localhost:8080
# Log in via Keycloak (seeded admin); see the empty dashboard.
# Register a target (Juice Shop image) via the targets page.
# Click "Trigger scan" → live stage updates appear over WebSocket.
# When complete: click into the SQLi finding → see before/after evidence,
# the diff, and a link to the auto-opened PR in the seeded demo repo.
# Approver role: click "Apply + open PR"; PR appears with a Check posted by Aegis.
```

### 9.2 Expected outputs (per scan)
- A `runs/{id}` row in Postgres with `status="completed"`, `stage_table`
  showing live-vs-fixture provenance.
- Findings rows with the existing schema_blob preserved.
- Artifacts in MinIO under `aegis/<run_id>/...` (patches, evidence, report).
- `audit_events` rows hash-chained back to the install root; `aegis audit verify`
  passes.
- A real GitHub PR with an Aegis Check Run linking back to the run page.

### 9.3 Evidence chain (Phase 3 extension of the Phase 2 chain)
The six links from PLAN.md §9.3 still apply per-run. Phase 3 adds:

7. **Attributed** — every action in `audit_events` has an authenticated
   `actor`; no anonymous operations exist.
8. **Integrity-checked** — `aegis audit verify` succeeds against the
   entire audit chain.
9. **Reproducible** — the same Postgres dump + MinIO bucket replayed
   through `aegis migrate` yields byte-identical reports.

If any of links 1–6 break per-run, the run fails (as before). If links
7–9 break, the *deployment* is suspect — alert, do not silently continue.

---

## 10. Resolved Defaults (change explicitly before coding if disagreeing)

- **Stack choice:** FastAPI + SQLAlchemy async + Celery + Redis + Postgres +
  MinIO + Keycloak + Next.js. Each replaceable via env var, but the
  in-tree adapters target this set.
- **OIDC:** any provider; Keycloak in dev for reproducibility.
- **Queue:** Celery in Phase 3; Temporal evaluated in Phase 4.
- **UI scope:** read-only + trigger-scan + open-pr only. Suppression /
  bulk triage / custom views are **deferred** without exception.
- **Container orchestration:** docker-compose in Phase 3; kind/helm
  scaffolding lands but production manifests are **deferred** to Phase 4.
- **API versioning:** `/v1` with explicit version in the path. Future
  versions land beside it; no auto-redirects.

---

## 11. Implementation Guardrails

- The CLI must continue to work offline (filesystem-mode) for the
  fixture-assisted demo. No Phase 3 commit may break that path.
- No write endpoint may bypass the safety + audit layer.
- The web UI never holds long-running operations; all writes go to
  `aegis-api` which enqueues to `aegis-worker`.
- The hash chain is *not* a substitute for tamper-evident storage — it is
  a step toward it. Phase 4 will move the chain into WORM storage.
- Scanner adapters must declare their capabilities upfront; the dispatcher
  refuses to run a SAST adapter against a DAST-only target.
- The schema_blob in `findings` is the contract for downstream consumers.
  Adding columns is fine; removing or renaming them is a schema
  migration with a deprecation cycle.

---

## 12. Verification — How to Know Phase 3 Is Executed Correctly

```bash
# Phase 2 path still works (offline mode)
.venv/bin/pytest -q
AEGIS_E2E=1 AEGIS_DISABLE_LLM=1 .venv/bin/pytest -q tests/e2e/

# Phase 3 stack
make up
make seed
curl -sf http://localhost:8000/health | jq .         # api healthy
curl -sf -H "Authorization: Bearer $TOKEN" http://localhost:8000/v1/runs   # auth works
# Trigger a scan via the UI; wait; verify Postgres has the run + findings.
# Verify MinIO has artifacts/<run_id>/report.html.
# Verify github webhook posted a Check.
aegis audit verify                                    # hash chain holds

# CI
gh pr create ... ; gh pr checks                       # api-integration + web-build green
gh workflow run aegis-ci.yml --field run_e2e=true     # stack E2E green
```

Phase 3 is correctly executed when:
- All Phase 2 evidence-chain links (1–6) hold for every run.
- New Phase 3 links (7–9) hold for the deployment.
- The deferred list in §1.3 is unchanged — i.e. no Phase 4 scope crept in.
- `pytest -q` + integration + stack E2E all pass.

---

## Critical Files to Modify / Create (Quick Reference)

**New top-level surfaces**
- `aegis/api/` (FastAPI service)
- `aegis/workers/` (Celery tasks)
- `aegis/db/` (SQLAlchemy + Alembic)
- `aegis/scanners/` (registry + adapters)
- `aegis/integrations/github_app.py` + `github_webhooks.py`
- `aegis/audit/chain.py`
- `web/` (Next.js)
- `deploy/` (compose, Dockerfiles, kind config)

**Existing primitives still load-bearing (do not rewrite)**
- `aegis.schema.AegisFinding`, `CodeLocation` — schema_blob
- `aegis.safety.{authorize, is_target_allowed, is_loopback}` — gains
  `actor` and `audit_chain` wiring, otherwise unchanged
- `aegis.remediate.patch_workflow.{commit_patch, apply_patch, rollback,
  open_pull_request, deterministic_branch}` — repo-side primitives
- `aegis.remediate.deps_workflow.build_version_bump_diff` — npm/Python bumps
- `aegis.adapters.{strix_runner, trivy_runner}` — wrapped by adapters,
  not replaced
- `aegis.verify.{verify_finding, runtime_proves_post_patch, parse_curl,
  is_dast_remediated, is_sast_remediated, _verify_dependency}` — task body
- `aegis.targets.{TargetPack, JuiceShopPack, DvwaPack, get_target_pack}` —
  used by workers
- `aegis.report.save_reports` — task body, output lands in object storage

The Phase 2 codebase is the foundation; Phase 3 wraps and connects it.
