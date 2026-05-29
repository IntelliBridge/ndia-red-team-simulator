# Changelog

All notable changes to Aegis are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
SemVer.

## [0.5.2] — Fix the bumblebee and strix scanner adapters

Two shipped scanner adapters spoke interfaces their tools never exposed; both
are corrected against the vendored source. Execution-layer only — the offline
`pytest -q` path stays green with no scanner binaries (1091 passing, 18 skipped).

### Fixed
- **bumblebee adapter** now invokes the real CLI (`bumblebee scan --root
  <target> --exposure-catalog <dir> --findings-only --output stdout`) and
  parses the real NDJSON schema: records are discriminated by `record_type`
  (was a non-existent `type` field), and `finding` records map their real
  fields (`record_id`, `catalog_id`/`catalog_name`, `severity`, `package_name`,
  `version`, `confidence`). The previous invented `--target`/`--format ndjson`
  flags and `type` filter produced zero findings on real output. The exposure
  catalog defaults to the vendored `threat_intel/*.json`.
- **strix runner** drops the non-existent `--output-dir` flag, runs strix with
  `cwd` set to the per-run directory, and discovers strix's real event stream
  at `strix_runs/*/events.jsonl` (newest by mtime) instead of a fixed path
  strix never wrote.

### Added
- `ScanOptions.scan_mode` (+ `AegisConfig.strix_scan_mode`, default
  `"standard"`) threads strix's `-m/--scan-mode` (quick|standard|deep), so scans
  are no longer hard-pinned to strix's `deep` default.

### Security
- The rewritten bumblebee adapter keeps the credential-never-leaked guarantee:
  only known-safe fields are surfaced and `evidence` stays `None`. The fixture
  uses placeholder catalog ids and no secret-like strings.

## [0.5.1] — Bumblebee supply-chain scanner via the hardened seam

The first tool added through the v0.5.0 registry seam. Adding the
`supply_chain` capability was a one-line `KNOWN_CAPABILITIES` append — the
proof the open vocabulary works without patching core. Execution-layer +
packaging only; the offline `pytest -q` path stays green with no
Postgres/Redis/Keycloak and no scanner binaries.

### Added
- `BumblebeeAdapter` (`aegis/scanners/bumblebee_adapter.py`) — wraps the
  bumblebee CLI's NDJSON output (`package` / `finding` / `scan_summary`
  records) and emits `AegisFinding`s with `finding_type="supply_chain"`.
  Findings carry severity directly, so there is no synthetic-severity
  workaround.
- New `supply_chain` capability in `KNOWN_CAPABILITIES` (a one-line append),
  covered by the bumblebee adapter — the scanner roster is now 13.
- Vendored `perplexityai/bumblebee` as a pinned submodule (Apache-2.0, tag
  v0.1.1) under `project_repos/bumblebee`, recorded in `AEGIS_VENDORED.md`
  and the ADR 0001 bumps log; `bumblebee_path` added to `AegisConfig`.
- `tests/test_bumblebee_adapter.py` + an NDJSON fixture: severity mapping,
  required-field conversion, and a credential-never-leaked guard, all
  offline.

### Security
- bumblebee parses MCP-host configs that may contain credentials; the
  adapter never copies a credential value into a finding (`evidence` is left
  unset), mirroring the trufflehog redaction guarantee. A test asserts no
  sentinel credential reaches the serialized finding.

### Migration
- The scanner needs `bumblebee` on `PATH` (a Go 1.25+ static binary) or a
  build from the vendored source; when absent, `health_check()` returns
  False and the adapter soft-degrades. The Go build dependency touches only
  the `docker-images` image (a multi-stage `golang` builder stage) — never
  the offline test path.

## [0.5.0] — Harden the registry seam

Architecture hardening so new capability arrives through an extension seam
instead of by hand-editing core. Execution-layer + packaging only — no API
write route, Celery enqueue, or audit-chain change. Offline `pytest -q`
stays green with no Postgres/Redis/Keycloak and no scanner binaries.

### Added
- Generic `aegis.registry.Registry[T]` shared by the scanner and agent
  registries (`register` / `get` / `list_names` + a gated
  `maybe_load_entry_points`), collapsing two near-identical registries onto
  one seam.
- Live third-party plugin discovery: `aegis/scanners/__init__.py` and
  `aegis/agents/__init__.py` now call `maybe_load_entry_points()` after the
  built-ins, discovering entry points in groups `aegis.scanners` /
  `aegis.agents`. Gated by `AEGIS_PLUGINS=1` (default off) so it never
  touches the offline path — the previously-dormant hook is now wired.
- `KNOWN_CAPABILITIES` open capability vocabulary in
  `aegis/scanners/registry.py`: adding a capability is a one-line append;
  an unknown declared capability logs a warning but still registers, so a
  plugin can introduce its own without patching core.
- `tests/test_plugin_discovery.py` — gated entry-point discovery for both
  registries (on registers; off is a strict no-op; unknown-capability
  warns-but-registers), fully offline.

### Changed
- Retired the stale `wired_in_phase_3` phase flag → `wired` on the agent
  adapter Protocol, the `list_agents()` output key, and the `AgentResult`
  status string `"not_wired_in_phase_3"` → `"not_wired"`.
- Renamed package `aegis/adapters/` → `aegis/runners/` and the finding
  converter `strix_adapter.py` → `strix_converter.py`, clarifying the
  subprocess-runner / finding-converter / exporter layer and killing the
  name collision with the registered `aegis/scanners/strix_adapter.py`.
- `Capability` is no longer a closed `Literal`; capabilities are plain
  `str` validated against `KNOWN_CAPABILITIES` at registration.

### Migration
- Downstream importers of `aegis.adapters.*` must switch to
  `aegis.runners.*`; the Strix finding converter moved from
  `aegis.adapters.strix_adapter` to `aegis.runners.strix_converter`. The
  registered scanner adapter `aegis.scanners.strix_adapter` is unchanged.
- Third-party scanners/agents may now register via entry-point groups
  `aegis.scanners` / `aegis.agents` (opt-in with `AEGIS_PLUGINS=1`); see
  the "Extending Aegis" docs.
- Public import paths from `aegis.scanners`, `aegis.scanners.registry`,
  `aegis.agents`, and `aegis.agents.registry` are otherwise unchanged.

## [0.4.2] — OnePager gap: forensic/wireless agents + scanner breadth

Narrows the gap between shipped capability and the OnePager promise on two
axes: the seven registered-but-unwired CAI agents (forensics + mobile +
wireless + RF) now dispatch to their real upstream agents, and eight new
scanner adapters land. v0.4.1 and earlier untouched — this is
execution-layer breadth only, with no API write route, Celery enqueue, or
audit-chain change.

### Added
- Seven newly-wired CAI agents in `aegis/agents/cai/builtins.py`, each
  dispatching through `Runner.run_sync` to its upstream `cai.agents.*`
  agent: `memory_analysis`, `network_traffic_analyzer`,
  `reverse_engineering` (forensic) and `android_sast_agent`,
  `subghz_sdr_agent`, `wifi_security_tester`, `replay_attack_agent`
  (offensive). The registry now reports **15 wired** agents, up from 8.
- Eight scanner adapters under `aegis/scanners/`, each following the
  self-contained subprocess + JSON-parse shape (`_convert` →
  `AegisFinding`; graceful `exit_code=-1` on missing binary / timeout /
  decode error; raw output persisted under `run_path/<tool>/`):
  - `zap_adapter.py` (`dast`) — OWASP ZAP JSON report.
  - `codeql_adapter.py` (`sast`) — `codeql database analyze` SARIF.
  - `bandit_adapter.py` (`sast`) — `bandit -r -f json`.
  - `grype_adapter.py` (`dependency`) — `grype -o json`.
  - `checkov_adapter.py` (`iac`) — `checkov -o json`.
  - `trufflehog_adapter.py` (`secret`) — `trufflehog … --json` (JSONL);
    raw secret material is redacted, never persisted.
  - `sonarqube_adapter.py` (`sast`) — `sonar-scanner` +
    `GET /api/issues/search`; an unconfigured server degrades to an
    empty, flagged `ScanResult` rather than raising.
  - `syft_adapter.py` (`sbom`) — `syft -o cyclonedx-json`; persists a
    CycloneDX SBOM to `run_path/syft/sbom.cyclonedx.json` and returns
    `findings=[]` (inventory, not findings).
- New `sbom` capability so Syft's inventory output is a first-class tool
  without faking findings.
- Tests (offline by construction — CAI bundle mocked, scanners parse
  static fixtures, `health_check` exercised with the binary absent):
  - `tests/test_agent_registry.py` — 5 cases (15 registered; the 7 new
    agents dispatch ok; `_NOT_WIRED` empty; `cai_attr`↔`CAIBundle` field
    parity; resilient-import degradation to `status="error"`).
  - `tests/test_{zap,codeql,bandit,grype,checkov,trufflehog,sonarqube,syft}_adapter.py`
    — one per adapter against a minimal real-shape fixture.
  - `tests/test_scanners.py` — registry roster (all 12), capability
    coverage, graceful `health_check`, dispatch-by-capability.

### Changed
- `aegis/integrations/cai_loader.py`: `CAIBundle` gains the seven
  upstream agent fields; `load_cai` imports them in a separate
  `try/except ImportError` so an upstream rename of a new agent cannot
  regress the already-wired codeagent/blueteam path.
- `aegis/scanners/registry.py`: the `Capability` Literal gains `"sbom"`.
- `aegis/scanners/__init__.py`: eager-imports the eight new adapters so
  they self-register on package import.
- `tests/test_scanner_registry.py`: agent-registry assertions now
  reflect that the forensic trio is wired; the `not_wired_in_phase_3`
  path is retired (`_NOT_WIRED` is empty).
- `docs/architecture/overview.md`: the "Additional scanners (ZAP …)"
  deferred bullet is removed (now shipped); `docs/api/v1.md` lists the
  full scanner enum.

### Migration notes
- None — additive. The new scanners need their CLIs on `PATH`
  (SonarQube additionally needs a server via `SONAR_HOST_URL` + token in
  `options.extra` or env); when absent each degrades through
  `health_check` / guarded `scan` rather than raising. The offline
  `pytest -q` path requires none of them.

### Verification
- `pytest -q` — 287 passed, 3 skipped on Python 3.12 (no Postgres /
  Redis / Keycloak, no scanner binaries).
- `python -c "import aegis.scanners as s; print(sorted(s.list_scanners()))"`
  → the 12 adapters; wired-agent count → 15.
- `mkdocs build --strict` clean (the README feeds the docs index).

## [0.4.1] — Phase 4 Observability & GitHub completion

Centralised logs queryable in Loki / Elasticsearch and in-app via a
Postgres mirror; GitHub PR-scoped scans with structured scope and
fork-restricted mode. v0.3.1 + v0.4.0 untouched; v0.4.1 layers
observability + integrations on top.

### Added
- `aegis/log_ingest/` — in-tree FastAPI service that mirrors the OTel
  log stream into Postgres. Two ingress paths converge on the same
  batched writer: ``POST /ingest`` (native JSON, used by api/worker
  when no Collector is up) and ``POST /v1/logs`` (OTLP/Logs over
  HTTP-JSON, what the Collector's ``otlphttp/aegis-ingest`` exporter
  posts). ``/health`` + ``/metrics`` for lag visibility. Severity
  numbers map to text via the OTLP severity table (F20c).
- `application_logs` table + indexes via Alembic
  ``0003_application_logs``. Columns: ts/severity/service/message +
  run_id/job_id/project_id/actor/request_id/trace_id/span_id +
  freeform JSONB attrs. Index set: per-run+ts DESC, per-project+ts
  DESC, request_id, trace_id, severity+ts DESC, service, ts (F20c).
- `aegis/api/v1/logs.py` — `GET /v1/logs` admin endpoint with
  run/project/service/severity/request_id/since filters and id-cursor
  pagination. Every query lands a ``logs.queried`` chained audit
  event so a forensic review can trace who looked at what (F22).
- `aegis/integrations/github_handlers.py`: `PRScope`, `RestrictedMode`,
  `pr_scope_from_payload`, `restricted_mode_for`, `scope_audit_detail`,
  `on_pull_request_event`. Fork detection compares
  ``head.repo.full_name`` vs ``base.repo.full_name`` (the
  ``head.repo.fork`` flag is unreliable on forks-of-forks). Forks
  engage restricted mode (no apply, no open_pr, depth-1 clone, no
  secret mount, path allowlist = `changed_files`) (F23a/c).
- `aegis/integrations/github_webhooks.py`: ``X-GitHub-Event:
  pull_request`` events dispatch into the handler and the structured
  scope + reason surface in the response body (F23b).
- `project_repos/opentelemetry-collector-contrib/` — vendored at SHA
  `d7957a20ce54ab42a87b8f9e91eda73f7b3b48e5`. Apache-2.0; source-of-
  truth for the running ``otel/opentelemetry-collector-contrib`` image
  + the SLSA / fork target (F19).
- Three compose profiles (`default`, `obs`, `obs-search`) and the
  configs they need:
  - `deploy/otel/config.yaml` — receivers (OTLP gRPC + HTTP) →
    `logs/loki`, `logs/aegis-ingest`, traces → Jaeger pipelines.
  - `deploy/loki/config.yaml` — single-binary Loki dev config
    (filesystem storage, tsdb schema v13, 7d retention).
  - `deploy/Dockerfile.log_ingest` — thin python:3.12-slim image for
    aegis-log-ingest (F20a + F20c).
- `web/src/app/logs/page.tsx` — terminal-style log viewer reading
  `/v1/logs` with run/severity/service filter query params (F22).
- `docs/security/fork-prs.md` — policy doc for the fork-restricted
  mode (F23c).
- Tests:
  - `tests/test_log_ingest.py` — 11 cases (tz-aware ts validation,
    truncation, OTLP severity mapping, native + OTLP endpoints,
    metrics, health).
  - `tests/test_logs_api.py` — 3 cases (admin list, non-admin 403,
    filter narrowing).
  - `tests/test_structlog_correlation.py` — 4 cases (correlation
    processor lifts request_id, leaves it alone when caller-set,
    skips trace ids when no span).
  - `tests/test_pr_scope.py` — 6 cases (fork detection, restricted
    mode defaults, audit detail shape, dispatcher).

### Changed
- `aegis/observability.py`:
  - New `_inject_correlation_ids` structlog processor lifting
    `request_id` from the ContextVar and `trace_id` / `span_id` from
    the active OTel span.
  - `_configure_otel_logs(service_name)` — when
    ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set, every log event also
    streams to the Collector via the OTel Logs SDK's
    LoggingHandler. No-op when the env var is unset (Phase 2 path
    untouched).
  - `configure_structlog(service_name="aegis")` runs the OTel setup
    before structlog.configure so every event reaches the handler
    (F21).
- `aegis/db/models.py`: new `ApplicationLog` model (F20c).
- `aegis/api/app.py`: include `/v1/logs` router (F22).

### Migration notes
- Run Alembic migration `0003_application_logs` before serving
  v0.4.1.
- The default compose profile now brings up `aegis-log-ingest`;
  `make up` includes it without changes. The `obs` profile adds the
  Collector + Loki + Jaeger; `obs-search` further adds Elasticsearch
  + Kibana.
- Set ``OTEL_EXPORTER_OTLP_ENDPOINT`` in the API + worker environments
  to route logs through the Collector (the compose obs profile sets
  it via service-name DNS).

### Verification
- `pytest -q` — 237 passed, 3 skipped on Python 3.12.
- Default compose profile: `aegis-log-ingest` writes to
  `application_logs`; `SELECT count(*) FROM application_logs WHERE
  request_id = ...` correlates API + worker rows.
- `obs` profile: Loki shows the same stream via ``{service="aegis-
  api"}``.
- Webhook receiver: a fork PR payload returns
  ``restricted_mode="fork.restricted=true"`` in the response.

## [0.4.0] — Phase 4 Identity & UX

Real browser auth, real CSRF/CSP/XSS defence, production design
system, every web page rebuilt against it. The v0.3.1 backend is
untouched; v0.4.0 layers identity + UX on top.

### Added
- `aegis/api/session_cookie.py` — RS256 mint + verify for the
  Aegis API session cookie. NextAuth signs with the Aegis private
  key; FastAPI verifies with the Aegis public key. iss=
  ``aegis-api-session``, aud=``aegis-api``. ``generate_keypair()``
  helper for tests + ops bootstrap (F14a).
- `aegis/api/middleware/csrf.py` — double-submit CSRF on cookie-
  authenticated mutations; constant-time compare; bearer callers
  exempt (F14b).
- `aegis/api/security_headers.py` — `REPORT_CSP` constant +
  `html_report_headers()` / `non_html_report_headers()`. HTML
  reports carry `default-src 'none'` (F14d).
- New env knobs in `aegis/api/settings.py`:
  `AEGIS_API_SESSION_PRIVATE_KEY` /
  `AEGIS_API_SESSION_PUBLIC_KEY`,
  `AEGIS_API_SESSION_KEY_ID`,
  `AEGIS_API_SESSION_TTL_SECONDS`,
  `AEGIS_API_SESSION_COOKIE`,
  `AEGIS_CSRF_COOKIE`,
  `AEGIS_CSRF_HEADER`,
  `AEGIS_WEB_ORIGIN`.
- `web/src/app/api/auth/[...nextauth]/route.ts` — Keycloak provider;
  session callback mints `aegis_api_session` + `aegis_csrf` cookies
  via `jose` RS256 (F13).
- `web/src/app/api/auth/refresh-api-session/route.ts` — POST endpoint
  re-mints both cookies for the active NextAuth session, no
  Keycloak round trip.
- `web/src/app/api/auth/signout-aegis/route.ts` — clears the Aegis
  cookies during logout.
- `web/src/server/aegis-session.ts` — server-only jose-based minter
  + CSRF token generator + cookie-name helpers (F13).
- `pnpm-workspace.yaml` at the repo root — packages: `web`,
  `project_repos/design-system`.
- `project_repos/design-system/` — new workspace package
  `@aegis/design-system`. First component batch (each with a
  Storybook story): `SeverityChip`, `RunStatusBadge`,
  `AuditChainBadge`, `FindingCard`, `StageTimeline`, `EvidenceDiff`,
  `ToastList`, `RoleGated`. `cn()` Tailwind class merger in
  `src/lib/utils.ts` (F16).
- `web/.storybook/{main,preview}.ts` — Storybook 8 +
  `@storybook/addon-essentials` + `@storybook/addon-a11y`. CI gate
  is OFF for v0.4.0 (incremental; flips on in v0.4.2 once the
  second component batch lands).
- `project_repos/shadcn-ui/` — vendored submodule at SHA
  `360e8a19c3ee13ac78b656027462007c8bdaa6d5`. License (MIT)
  preserved. `web/components.json` points the shadcn registry at
  the local clone (F15).
- `project_repos/AEGIS_VENDORED.md` — pin manifest + license
  summary + rebase policy for every project_repos/ submodule.
- `web/src/hooks/useRoles.ts` — SWR-backed reader for `/v1/projects`;
  returns the caller's per-project roles for `<RoleGated>` and any
  page-level conditional rendering (F18).
- New pages: `/projects`, `/projects/[slug]/settings`, `/audit`
  (F17).
- Integration tests:
  - `tests/test_cookie_and_bearer_auth_parity.py` — 7 cases.
  - `tests/test_csrf.py` — 6 cases (double-submit + CORS).
  - `tests/test_ws_origin_and_auth.py` — 3 cases (Origin,
    subprotocol bearer).
  - `tests/test_report_xss.py` — 3 cases (renderer escapes +
    response headers).

### Changed
- `aegis/api/auth.py`: `get_current_user` resolves
  `Authorization: Bearer …` first, then the configured
  `aegis_api_session` cookie. `_resolve_from_cookie` /
  `_resolve_from_token` factored out for the WebSocket handler
  to reuse (F14a/F14c).
- `aegis/api/app.py`: CORS hardened —
  `allow_credentials=True` only against an explicit
  origin list (`cors_origins` + `web_origin`), methods
  enumerated, headers scoped to
  `Authorization` / `Content-Type` / `X-Aegis-CSRF` /
  `X-Aegis-Request-ID`. CSRF middleware wired (F14b).
- `aegis/api/ws.py`: `/v1/runs/{id}/events` upgrade now closes
  1008 on bad Origin; accepts bearer via
  `Sec-WebSocket-Protocol: aegis.bearer.<token>` (RFC 6455)
  with subprotocol echo; cookie path also honoured; legacy
  `?token=` preserved one release (F14c).
- `aegis/api/v1/reports.py`: HTML responses now carry the
  strict CSP + `X-Content-Type-Options: nosniff` +
  `Referrer-Policy: no-referrer` + `X-Frame-Options: DENY` +
  `Content-Disposition: inline`. JSON/Markdown carry nosniff +
  `Content-Disposition: attachment` with a stable filename (F14d).
- `web/src/lib/api.ts` rewritten — cookie + bearer parity,
  auto-attached CSRF header on mutations, auto
  `X-Aegis-Request-ID` per call (F18).
- `web/src/lib/auth.ts`: `requireAuth` now accepts cookie-only
  sessions (presence of the non-httpOnly `aegis_csrf` cookie);
  `logout()` clears the Aegis cookies via
  `/api/auth/signout-aegis` (F18).
- `web/src/app/{layout,dashboard,runs,findings}/*.tsx`: rewritten
  against `@aegis/design-system`. Inline styles + per-page badges
  gone in favour of `RunStatusBadge`, `SeverityChip`,
  `FindingCard`, `StageTimeline`, `RoleGated`, `AuditChainBadge`
  (F17).
- `web/package.json` renamed to `@aegis/web`; added `jose`,
  `class-variance-authority`, `clsx`, `tailwind-merge`,
  `lucide-react`, `@aegis/design-system` (workspace), Storybook
  8 + addons.

### Migration notes
- Generate an Aegis API session keypair and set
  `AEGIS_API_SESSION_PRIVATE_KEY` (on the web/NextAuth side) and
  `AEGIS_API_SESSION_PUBLIC_KEY` (on the API side). The
  `generate_keypair()` helper in `aegis.api.session_cookie` is the
  reference implementation. Both must be PKCS8-PEM (private) and
  SubjectPublicKeyInfo-PEM (public).
- Set `AEGIS_WEB_ORIGIN` to the production web origin; CORS
  enforces `allow_credentials=True` only against it.
- `pnpm install` at the repo root picks up the new workspace
  pointer (`@aegis/design-system`) and the v0.4.0 dependencies
  (`jose`, `clsx`, etc.).

### Verification
- `pytest -q` — 213 passed, 3 skipped on Python 3.12.
- Backend security suite (`test_cookie_and_bearer_auth_parity`,
  `test_csrf`, `test_ws_origin_and_auth`, `test_report_xss`) — 19
  total cases, all green.

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
