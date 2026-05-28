# Changelog

All notable changes to Aegis are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
SemVer.

## [0.3.1] — Phase 4 stabilization

Phase 3 shipped the platform but left ~15 architectural guarantees only
half-enforced. v0.3.1 makes them true at runtime — no UI changes, no
new auth model, no observability changes. Pure correctness + safety
wiring. The Phase 2 offline path remained green at every commit.

### Added
- `aegis/policy/{__init__,ci_gate}.py` — pure CIGatePolicy + evaluate;
  Celery import chain detached from the default `pytest -q` (F1).
- `uv.lock`, `web/pnpm-lock.yaml` committed; pytest markers (`unit`,
  `integration`, `docker`, `e2e`, `slow`, `auth_required`) declared;
  CI gates re-derive both lock files and fail on drift (F2).
- `aegis/audit/forensic.py::tool_detail` — canonical detail dict for
  per-tool audit rows. stdout/stderr reduced to sha256 + length; raw
  output stays in the blob store and the row carries `{sha256,
  location, kind}` refs (F8).
- `aegis/audit/writers.py::open_writer(mode=...)` + `InMemoryAuditWriter`
  for tests (F7).
- `aegis/cli/api_client.py` — stdlib-only HTTP wrapper; `--api` /
  `AEGIS_MODE=api` routes `scan` / `fix` / `verify` through the API
  with bearer auth from `AEGIS_TOKEN` or `~/.config/aegis/token` (F4).
- `aegis/services/runs.py::cancel_run`, `aegis/services/targets.py::
  create_target/delete_target`, `services/{scans,fixes,verify}.create_*_job`
  — admission services emit audit-before-enqueue (F6).
- `aegis/api/v1/projects.py` — `GET /v1/projects`, `GET
  /v1/projects/{slug}/membership`, `PUT /v1/projects/{slug}/settings`.
  Prereq for v0.4.0 UI role gating (FP).
- `aegis/api/v1/findings_by_scanner_id.py` — `GET
  /v1/findings/by-scanner-id?run=&scanner_id=` compat lookup
  (deprecated; sunset after v0.5) (F9).
- `aegis/db/migrations/versions/0002_findings_pk_uuid.py` — Alembic
  migration: Finding PK becomes UUID; scanner identifier moves to
  `scanner_finding_id`; `UNIQUE(run_id, scanner_finding_id)`. FK
  fan-out `ON UPDATE CASCADE` (F9).
- `aegis/api/auth.py::issue_worker_token` — time-bound versioned
  worker SA tokens; rotation overlap window; actor surface
  `service:worker:<worker_id>` (FW).
- `aegis/api/policy.py::ensure_project_access` /
  `ensure_run_access` — F12 read-side gates.
- Integration tests: `tests/test_admission_audit_before_enqueue.py`,
  `tests/test_finding_pk_collision.py`,
  `tests/test_worker_status_persistence.py`,
  `tests/test_project_access_read.py`,
  `tests/test_projects_api.py`,
  `tests/test_worker_sa_auth.py`,
  `tests/test_cai_runner_routing.py`,
  `tests/test_api_client.py`.

### Changed
- `safety.authorize()` requires an explicit `AuditWriter` writer (F7).
  Offline path supplies `JsonlAuditWriter(single_file="audit.jsonl")`
  via the safety layer's compat shim; api/worker supply
  `PostgresAuditWriter`.
- `aegis/tools/kali_client.py`: `audit_path` kwarg removed. Every
  Kali tool invocation lands on the canonical audit chain via the
  injected writer; the forensic detail shape comes from
  `aegis.audit.forensic.tool_detail` (F8).
- `aegis/services/tools.py`: threads `audit_writer` / `run_id` /
  `project_id` into KaliClient (F8).
- `aegis/cli/main.py`: `cmd_scan` / `cmd_fix` / `cmd_verify` /
  `cmd_report` reduced to thin shells that delegate to the service
  layer (F3). `--api` sets `AEGIS_MODE=api` and dispatches via
  `aegis.cli.api_client` (F4).
- `aegis/cli/migrate.py`: `cmd_migrate` reads `summary.to_dict().items()`
  (was `summary.items()`); exits non-zero on failures (F5).
- `aegis/cli/status.py`: probes `/health` against `AEGIS_API_URL`
  when in api mode (F4).
- `aegis/api/v1/{scans,fix,verify,runs_cancel,targets}.py`: rewritten
  as thin RBAC + lookup + delegate shells over the admission
  services. `AuthorizationError` surfaces as 403; `LookupError` as
  404. No route constructs Run/Job rows directly any more (F6).
- `aegis/api/v1/{reports,exports}.py`: serve from blob store first,
  filesystem fallback. Every read passes through
  `ensure_run_access` (F12).
- `aegis/api/ws.py`: `/v1/runs/{id}/events` resolves bearer
  header → `?token=…` query parameter → close 1008 if missing /
  unauthorised (F12).
- `aegis/api/auth.py`: factored `_resolve_from_token` for the WS
  handler to reuse the bearer resolution; worker token verification
  now supports v1+ time-bound tokens with key rotation overlap
  (FW).
- `aegis/db/models.py::Finding`: `id` is now a UUID;
  `scanner_finding_id String(256) NOT NULL`;
  `UNIQUE(run_id, scanner_finding_id)`. `schema_blob["id"]` keeps
  the scanner identifier so downstream consumers see the contract
  they expect (F9).
- `aegis/state_pg.py`: `save_findings` allocates UUIDs and writes
  `scanner_finding_id` separately; `update_finding_status` accepts
  either UUID or scanner_finding_id (F9).
- `aegis/workers/tasks/{scan,fix,verify}.py`: no manual audit
  writes; pass through `safety.authorize` with the bootstrap-
  supplied PostgresAuditWriter; fix worker persists
  `Finding.status`, verify worker maps to `validation_state` and
  stamps `validated_at` (F11).
- `aegis/remediate/cai_runner.py`: sys.path injection moved to
  `cai_loader.load_cai`; per-task LLM selection via
  `aegis.llm.router.route` with `project_id` + `BudgetChecker`
  hook (F10).

### Removed
- `aegis/safety._append_audit` flat-JSONL helper (F7).
- `tool-calls.jsonl` side-channel; the legacy `audit_path` kwarg on
  `KaliClient` (F8).
- The Phase 3 `_minimal markdown report` fallback in `cmd_report`
  (F3 — unreachable: `aegis.report` has always been present).

### Migration notes
- Run Alembic migration `0002_findings_pk_uuid` against your existing
  database before serving v0.3.1. The migration is wrapped in a single
  transaction; create a backup table first if you want a manual
  rollback path. Downstream consumers continue to see
  `schema_blob["id"]` carrying the scanner-side identifier.
- `AEGIS_WORKER_SIGNING_KEY` is still required. Optional new env vars:
  `AEGIS_WORKER_SIGNING_KEY_PREVIOUS` (for the rotation overlap),
  `AEGIS_WORKER_SIGNING_KEY_VERSION` (defaults to `1`),
  `AEGIS_WORKER_KEY_OVERLAP_SECONDS` (defaults to 300),
  `AEGIS_WORKER_TOKEN_TTL_SECONDS` (defaults to 300).

### Verification
- `pytest -q` — 194 passed, 3 skipped on Python 3.12.
- `make up` stack remains operational; `aegis --api status` reports
  `mode=api` + healthy/unreachable.
- `aegis audit verify --all` walks every chain and returns ✓.

## [0.3.0] — Phase 3 — Multi-user platform

Phase 3 turns the Phase 2 CLI scaffold into a multi-user, API-backed,
auditable platform. Twelve milestones (M0 – M12) landed across four
waves; the offline CLI remained green at every commit.

### Added
- **Wave 1 — Foundation**
  - `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `CODEOWNERS`, `.env.example`, `docs/architecture/phase3.md`, `docs/dev/local-stack.md`.
  - `aegis/services/` — extracted `start_scan`, `generate_fix`, `verify`, `render_reports`, `run_kali_tool` from `cmd_*` so API + workers reuse the same code.
  - `aegis/integrations/cai_loader.py::load_cai` — single sys.path injection for CAI; replaces the duplicated dance in `cai_runner`.
  - `aegis/llm/router.py` — per-task model selection with `task_models` + per-project budget hook.
  - `aegis/cli/` — package; new subcommands `status`, `audit verify`, `migrate fs->pg`, `ci-gate`. Legacy `cli.py` promoted to `cli/main.py`.
  - `aegis/state_facade.py` — `RunStateAPI` Protocol; `state.py::RunState` renamed to `FilesystemRunState` with back-compat alias.
  - `aegis/db/` — sync SQLAlchemy 2.x models (orgs, projects, users, memberships, targets, runs, jobs, findings, llm_usage, artifacts, remediation_attempts, audit_events, audit_chain_heads, github_installations); Alembic migration `0001_initial`.
  - `aegis/state_pg.py::PostgresRunState`, `aegis/state_factory.py`.
  - `aegis/blobs.py` — `BlobStore` Protocol + `FilesystemBlobStore`; `aegis/blobs_s3.py` adds the S3/MinIO backend (M9).
  - `aegis/audit/chain.py` — hash-chained audit (`JsonlAuditWriter`, `PostgresAuditWriter`, `verify_chain`); `aegis/audit/redact.py` for centralized secret scrubbing. `KaliClient._audit` now routes through the injected writer.
- **Wave 2 — Backend services**
  - `aegis/api/` — FastAPI app factory, settings, auth (OIDC JWKS + dev fallback + worker service-account), policy (Action enum + project-scoped `check`), routers (`runs`, `findings`, `audit`, `reports`, `exports`, `tools`, `health`).
  - `aegis doctor --api-mode` probes Postgres, blob backend, OIDC issuer.
  - `aegis/scanners/` — registry + `StrixAdapter`, `TrivyAdapter`, `SemgrepAdapter`, `NucleiAdapter`. Entry-point discovery gated by `AEGIS_PLUGINS=1`.
  - `aegis/agents/` — CAI-agent registry with 8 wired (`codeagent`, `blueteam_agent`, `bug_bounter`, `red_teamer`, `dfir`, `retester`, `reporter`, `web_pentester`) and 7 registered-but-unwired (Phase 4).
  - `aegis/migrate/fs_to_pg.py` — idempotent importer for Phase 2 runs.
- **Wave 3 — Execution platform**
  - Write endpoints: `POST /v1/scans`, `POST /v1/findings/{id}/fix`, `POST /v1/findings/{id}/verify`, `POST /v1/runs/{id}/cancel`, `POST/DELETE /v1/targets`. Audit event before enqueue.
  - Rate-limit middleware: per-user + per-project token-bucket on write routes.
  - `aegis/workers/` — Celery + Redis; tasks for `scan_start`, `fix_generate`, `verify_replay`, `report_render`, `vulnfixer_render`, `ci_gate`, `parallel_fix`; bootstrap manages authoritative `jobs` row.
  - `aegis/observability.py` — OTel SDK, structlog JSON renderer, correlation-id middleware (`X-Aegis-Request-ID` flows API → worker → audit), Prometheus `/metrics`.
- **Wave 4 — Collaboration surface**
  - `aegis/integrations/github_app.py` — App JWT + installation tokens + PR + Check Run.
  - `aegis/integrations/github_webhooks.py` — HMAC verify + replay protection (10-min TTL set of delivery IDs).
  - `aegis/api/ws.py` — WebSocket `/v1/runs/{id}/events` backed by Redis pub/sub.
  - `web/` — Next.js 14 dashboard with `login`, `dashboard`, `runs/[id]`, `findings/[id]`, `targets` pages; role-gated action buttons.
  - `deploy/docker-compose.yml`, `Dockerfile.{api,worker,web}`, `Makefile`, `kind.yaml`, `keycloak/realm-export.json`.
  - `.github/actions/aegis-ci-gate/action.yml` + `aegis ci-gate` CLI subcommand (severity threshold, max findings, validation gate, JUnit XML output).
  - `.github/workflows/aegis-ci.yml` extended with `api-integration` (Postgres + Redis services), `web-build`, `docker-images`, and manual `e2e-stack` (Playwright) jobs.

### Tests
- 154+ unit/integration tests across the new surfaces (services parity, schema imports, audit chain integrity & redaction, Kali writer injection, scanner / agent registries, API auth + dev-fallback + prod-disabled, GitHub webhook signature + replay, blob round-trip, correlation-id propagation, metrics endpoint, CI-gate policy).

### Notes
- The offline CLI path (Phase 2 fixture-assisted demo) remains green at every Phase 3 commit.
- vulnerability-fixer remains an export-only integration; agentic invocation is deferred to Phase 4 (`strategy="deps_vulnfixer"` reserved in the API enum, returns 501 today).
- Native MCP protocol stays deferred; `mcp-kali-server` is consumed via REST.

## [0.2.0] — 2026-05-27 — Phase 2

### Added
- `aegis.safety` central allowlist + audit log; every active operation routed through `authorize()`.
- Provider-aware `aegis doctor` (Gemini / OpenAI / Anthropic / Azure).
- `aegis/targets.py`: source-bound Juice Shop / DVWA Docker lifecycle (`up`, `up_from_repo`, `rebuild`, `restart`, `wait_ready`, `down`).
- `aegis/remediate/patch_workflow.py`: branch-first patch lifecycle with auto-rollback on apply / commit failure.
- `aegis/adapters/strix_runner.py`: subprocess + live events.jsonl tailing with partial-success handling.
- `aegis/adapters/trivy_runner.py`: dependency vulnerability scanning.
- `aegis/remediate/deps_workflow.py`: deterministic version-bump diffs (npm / Python).
- `aegis/verify.py`: PoC replay + SAST grep fallback + dependency rescan; image-mode rejected for code-patch validation.
- `aegis/demo.py`: opinionated end-to-end demo command (dry-run default; `--apply` opts in).
- `aegis/report.py`: HTML emission + stage provenance table + before/after panel.
- `aegis fix --open-pr` via `gh pr create`; deterministic branch names `aegis/fix/<finding_id>`.
- `aegis fix --deps` with synthesized version-bump patches.
- `aegis targets up/down/list` CLI subcommands.
- Global `--dry-run` / `--verbose` / `--i-understand-this-target-is-authorized` flags.
- CI workflow with leak-check; deterministic E2E variant.
- 121 unit/integration tests + 1 deterministic E2E.

### Fixed
- `cai_runner.run_code_fix` invoked the wrong CAI API (`codeagent.run(messages, context_variables=...)`); now uses `Runner.run_sync(starting_agent=codeagent, input=prompt, context=...)`.
- `cmd_fix --patch` dry-run no longer marks a finding "fixed."
- `cmd_fix --deps` final status is not overwritten by the generic update path.
- `--dry-run` correctly refuses `targets up/down/rebuild`.
- DVWA image pinned away from `:latest`.
- Container names are run-scoped to prevent collisions between concurrent runs.

### Security
- Authorization gate refuses non-loopback targets without `--i-understand-this-target-is-authorized`.
- Patch workflow refuses dirty working trees unless `--allow-dirty`.

## [0.1.0] — Phase 1 (pre-history)

- Initial scaffold: `AegisFinding` schema, `RunState`, Strix event ingestion, vulnfixer JSON export, CAI prompt wiring, 19 unit tests.
