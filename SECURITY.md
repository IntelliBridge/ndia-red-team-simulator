# Security policy

## Supported versions

| Version           | Supported                          |
|-------------------|------------------------------------|
| 0.12.x (current)  | yes                                |
| 0.5.x – 0.11.x    | yes — security fixes only          |
| 0.3.x – 0.4.x     | yes — security fixes only          |
| < 0.3             | no                                 |

## Reporting a vulnerability

Email **security@agiledefense.com** (or open a private security
advisory on GitHub if the repo is hosted there). Do **not** open a
public issue.

Include:

1. Affected version / commit.
2. Reproduction steps or PoC.
3. Impact assessment.
4. Suggested remediation if you have one.

We will acknowledge within 3 business days and aim for triage within
10 business days. Coordinated disclosure preferred; we will credit
reporters who request it.

## Hardening posture (current — v0.12.0)

### Auth + authorization

- Browser sessions: NextAuth + Keycloak code flow; the Aegis-signed
  `aegis_api_session` cookie (RS256) is the only token FastAPI
  trusts on the cookie path.
- CLI / CI: bearer tokens only; bearer wins when both are present.
- Worker → API: time-bound versioned tokens with key rotation
  overlap; static-HMAC legacy format still accepted for one rolling
  restart.
- Every protected route runs `aegis.api.policy.check` server-side;
  the web `<RoleGated>` component is **UX only**.
- Project-access enforced on read endpoints (reports / exports /
  WebSocket) via `ensure_project_access` /
  `ensure_run_access`.

See [`docs/architecture/auth.md`](docs/architecture/auth.md).

### CSRF, CORS, WebSocket

- Cookie-authenticated mutations require an `X-Aegis-CSRF` header
  matching the `aegis_csrf` cookie (double-submit pattern).
  Bearer-only callers are exempt.
- CORS exposes `allow_credentials=True` only against an explicit
  origin list (`AEGIS_CORS_ORIGINS` + `AEGIS_WEB_ORIGIN`); methods +
  headers are enumerated.
- WebSocket upgrades validate `Origin` and resolve auth from
  subprotocol → header → cookie; policy
  failures close with `1008`.

### HTML report XSS defence

- Strict `html.escape(..., quote=True)` for every finding /
  evidence interpolation in the report renderer.
- Every HTML response carries
  `Content-Security-Policy: default-src 'none'; style-src 'self'
  'unsafe-inline'; img-src data:; base-uri 'none'; frame-ancestors
  'none'; form-action 'none'`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`.
- No inline `<script>` tags anywhere in the templates.

### Audit chain

- Every active operation runs through `aegis.safety.authorize` and
  lands a hash-chained event via the configured `AuditWriter`
  (`PostgresAuditWriter` in api/worker mode; `JsonlAuditWriter`
  offline; `InMemoryAuditWriter` for tests).
- Audit-before-enqueue: the chain row exists before Celery is
  touched. Worker crashes can't produce a half-state.
- Tool invocations land forensic detail (digests + blob refs) — raw
  scanner stdout / stderr never appears in audit rows.

See [`docs/architecture/audit-chain.md`](docs/architecture/audit-chain.md).

### Patch workflow

- Patches generated in a temporary branch with automatic rollback on
  `git apply --check` failure (`aegis/remediate/patch_workflow.py`).
- `--apply` requires explicit approver-role consent. Dry-run by
  default.

### Target allowlist

- Active scans against non-allowlisted hosts require an explicit
  `--i-understand-this-target-is-authorized` flag (CLI) /
  `override_authorized=true` (API). Either path also emits an
  audit event with `override=true` so it shows up forensically.
- CIDR ranges supported (`aegis.safety.is_target_allowed`).

### Fork-PR safety

- Webhook payloads from GitHub trigger `PRScope` admission. Fork PRs
  engage restricted mode: no `--apply`, no `--open-pr`, depth-1
  clone, no secret mount, path allowlist scoped to `changed_files`.
- See [`docs/security/fork-prs.md`](docs/security/fork-prs.md).

### Secrets handling

- Three distinct secret materials:
  - `AEGIS_API_SESSION_PRIVATE_KEY` (NextAuth side, RS256).
  - `AEGIS_WORKER_SIGNING_KEY` (shared HMAC, rotation overlap).
  - `AEGIS_GITHUB_PRIVATE_KEY` (GitHub App).
- `NEXTAUTH_SECRET` is opaque to Aegis (NextAuth's own).
- Rotation procedure for each is documented in
  [`docs/ops/deploy.md`](docs/ops/deploy.md) § "Rotation runbook".

## Out of scope

- Findings produced **by** Aegis against deliberately-vulnerable
  targets (Juice Shop, DVWA, etc.). Those are by design.
- The fixture-assisted demo mode's lack of a live LLM / scanner —
  documented and intentional.
- Submodule vulnerabilities. Report those to the respective upstream
  projects (`cai`, `strix`, `mcp-kali-server`, `vulnerability-fixer`,
  `bumblebee`, `deepsec`, `shadcn-ui`,
  `opentelemetry-collector-contrib`).
- DoS / resource exhaustion against the offline CLI when supplied a
  malicious finding fixture (the CLI is single-process; trust the
  fixture source).
- Cost / budget exhaustion via LLM-routed agents — see the
  `BudgetChecker` hook in `aegis/llm/router.py`.

## Known gaps (tracked, not shipping in v0.12.0)

- Database-side append-only enforcement on `audit_events` (Postgres
  `pg_audit` + role separation). Today, a privileged DB operator
  could re-sign a chain end to end.
- PII / content scrubbing inside diffs and patches.
- LLM prompt-injection / output filtering guards.
- Sandbox isolation per scan (gVisor / Firecracker).
- SOC 2 / ISO 27001 / FedRAMP evidence pack.

These are documented in `docs/architecture/overview.md` under "What's
deferred."
