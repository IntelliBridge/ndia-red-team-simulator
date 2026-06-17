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
- The role-gate decision is **pluggable** (`AEGIS_POLICY_ENGINE`):
  the default `static` engine is the built-in role-rank table, while
  `opa` / `cedar` delegate to an external policy service. External
  engines **fail closed** — any error or timeout denies.
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
- **Append-only at the database** (migration `0004`): a row-immutability
  trigger `RAISE EXCEPTION`s on `UPDATE`/`DELETE`/`TRUNCATE` of
  `audit_events` for everyone (owner + superuser included), so the chain
  can't be re-signed by editing rows. The runtime `aegis_app` role is
  granted only `INSERT, SELECT` on it; DDL (dropping the trigger) needs the
  separate `aegis_owner` role, and `pgaudit` logs such changes out-of-band.

See [`docs/architecture/audit-chain.md`](docs/architecture/audit-chain.md)
and [`docs/ops/deploy.md`](docs/ops/deploy.md) for role provisioning.

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

### LLM guardrails

Two fail-safe layers sit at every point where untrusted text reaches an
LLM or where model output leaves the platform (`aegis/llm/guardrails.py`).
Both are config-gated and default **on**; logs and raised exceptions are
secret-free (a blocked input surfaces a clean error, never the offending
text or any matched secret).

- **Diff / output secret scrubbing.** The canonical unified diff (in
  `extract_unified_diff`) and LLM outputs at the remediation + agent
  chokepoints are passed through the same secret/token regex set used by
  the audit redactor (`aegis/audit/redact.py`), with matches replaced by
  `***REDACTED***`. Because scrubbing happens on the *canonical* diff,
  every downstream consumer — the persisted `.diff`, the PR body, and the
  remediation log — inherits the scrub.
- **Prompt-injection detection.** Untrusted finding fields (title,
  description, remediation steps, PoC, code snippets) and agent prompts are
  scored for injection before they reach the model: a tiered risk
  (`none` / `low` / `medium` / `high`) with categories
  (`instruction_override`, `role_switch`, `exfiltration`, …). At or above a
  configurable risk threshold (`AEGIS_LLM_INJECTION_BLOCK_RISK`, default
  `high`) the input is **blocked** — a failed `FixOutcome` in the fix flow,
  a blocked `AgentResult` in the agent flow. `off` detects + logs only.
- Wired at three chokepoints: the remediation LLM boundary
  (`aegis/remediate/cai_runner.py`), the diff-extraction point
  (`aegis/remediate/patch_workflow.py`), and the agent-API boundary
  (`aegis/agents/cai/builtins.py` / `patterns.py`).
- Config (env vars): `AEGIS_LLM_GUARDRAILS` (master, default on),
  `AEGIS_LLM_SCRUB_DIFF`, `AEGIS_LLM_DETECT_INJECTION`,
  `AEGIS_LLM_FILTER_OUTPUT` (all default on), and
  `AEGIS_LLM_INJECTION_BLOCK_RISK` (default `high`; `off` = detect-and-log).

See [`docs/architecture/overview.md`](docs/architecture/overview.md)
§ "LLM guardrails" and [`docs/ops/deploy.md`](docs/ops/deploy.md) for the
env knobs.

### Secrets handling

- Three distinct secret materials:
  - `AEGIS_API_SESSION_PRIVATE_KEY` (NextAuth side, RS256).
  - `AEGIS_WORKER_SIGNING_KEY` (shared HMAC, rotation overlap).
  - `AEGIS_GITHUB_PRIVATE_KEY` (GitHub App).
- `NEXTAUTH_SECRET` is opaque to Aegis (NextAuth's own).
- Generated **diffs / patches and LLM I/O** are secret-scrubbed before
  they are persisted, surfaced in a PR, or logged — see § "LLM guardrails"
  above. Secrets that leak into a model-authored diff or a model response
  are redacted to `***REDACTED***` on the canonical path.
- Rotation procedure for each is documented in
  [`docs/ops/deploy.md`](docs/ops/deploy.md) § "Rotation runbook".

### Supply-chain integrity

- **Signed third-party plugins.** Marketplace plugin discovery supports
  opt-in **Ed25519** signature enforcement (`AEGIS_PLUGINS_REQUIRE_SIGNATURE`
  + `AEGIS_PLUGINS_TRUSTED_KEYS`). The signature binds to the SHA-256 of the
  factory module's source — it authorises only the code that runs. When
  enforcement is on, an unsigned or invalid plugin is **rejected** before
  registration; `aegis plugins sign` produces the detached signature.
- **Signed + attested release images.** Release builds (on `v*` tags) push
  the four service images to GHCR and **keyless cosign-sign** each by digest
  (GitHub OIDC, no stored keys), attaching a **CycloneDX SBOM** (Syft) and
  **SLSA-3 provenance** attestation. Operators verify with `cosign verify` /
  `cosign verify-attestation` before deploy.
- Remaining: **Nix reproducible builds** (bit-for-bit independent rebuild)
  are still deferred (tracked on the roadmap).
- See [`docs/security/supply-chain.md`](docs/security/supply-chain.md) for
  the trust model, env vars, and the operator verification runbook.

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

- Sandbox isolation per scan (gVisor / Firecracker).
- SOC 2 / ISO 27001 / FedRAMP evidence pack.

These are documented in `docs/architecture/overview.md` under "What's
deferred."
