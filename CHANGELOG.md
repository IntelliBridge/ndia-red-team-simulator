# Changelog

All notable changes to Aegis are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
SemVer.

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
