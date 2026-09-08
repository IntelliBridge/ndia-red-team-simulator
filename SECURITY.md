# Security policy

## Supported versions

| Version           | Supported                          |
|-------------------|------------------------------------|
| 0.14.x (current)  | yes                                |
| 0.5.x – 0.13.x    | yes — security fixes only          |
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

## Hardening posture (current — v0.14.0)

### Auth + authorization

- Browser sessions: NextAuth + Keycloak code flow; the Aegis-signed
  `aegis_api_session` cookie (RS256) is the only token FastAPI
  trusts on the cookie path.
- CLI / CI: bearer tokens only; bearer wins when both are present.
- Worker → API: **only** time-bound, versioned tokens with key-rotation
  overlap. **Breaking change:** the legacy non-expiring `worker:<hex>`
  token has been **removed** — it is no longer accepted, and
  `AEGIS_WORKER_SIGNING_KEY` is now **mandatory** for worker auth (a
  worker can't authenticate without it).
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

### Key rotation

Rotated or revoked keys are picked up without a forced restart or a
re-create, and rotations get a graceful overlap window:

- **IdP keys (JWKS).** The Keycloak JWKS is now a **time-boxed cache**
  (`AEGIS_API_JWKS_CACHE_TTL_SECONDS`, default `300`) rather than pinned
  for the process lifetime, so a rotated or revoked IdP signing key is
  picked up after at most one TTL with no restart.
- **API session cookie.** During a cookie-signing-key rotation the API
  accepts a **previous** public key
  (`AEGIS_API_SESSION_PUBLIC_KEY_PREVIOUS`) alongside the current one, so
  in-flight sessions keep validating across the cutover.
- **DAST auth-profile secrets.** The Fernet key supports **MultiFernet**
  rotation (`AEGIS_AUTH_PROFILES_KEY_PREVIOUS`): the previous key still
  decrypts existing profiles while new writes use the current key, so
  rotation no longer requires re-creating every profile.

See [`docs/ops/deploy.md`](docs/ops/deploy.md) § "Rotation runbook".

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
- **WORM / Object-Lock archival** (`aegis/storage/worm.py`): chains export
  off-DB to an S3 / MinIO bucket with **Object Lock** (`COMPLIANCE` mode,
  default 7-year retention) — a daily `celery beat` task (self-gated on
  `AEGIS_WORM_EXPORT`) plus on-demand `aegis audit export`. The sealed copy
  can't be overwritten or deleted before retention expires, even by an
  attacker who owns the database or the bucket credentials, so the chain is
  tamper-*resistant* off-DB and not merely tamper-*evident*. Re-verify by
  downloading the archived JSONL into `verify_chain`.

See [`docs/architecture/audit-chain.md`](docs/architecture/audit-chain.md)
and [`docs/ops/deploy.md`](docs/ops/deploy.md) for role provisioning and the
WORM bucket runbook.

### Multi-tenancy / data isolation

- The tenant is the **Organization**; every project belongs to one org.
- **Layered isolation.** The app layer scopes reads to the caller's
  project memberships (`ensure_project_access` / `ensure_run_access`); the
  database layer adds **Postgres Row-Level Security** keyed on `org_id` as
  **defense-in-depth**, so a forgotten `WHERE` clause can't leak rows
  across orgs.
- **`FORCE` on the tenant tables** (migration `0005`): `projects` and the
  eight project-scoped tables (denormalized `org_id` + `BEFORE INSERT`
  trigger) run with `ENABLE` + `FORCE ROW LEVEL SECURITY`, so the policy
  binds even the table owner / superuser. A per-request GUC
  `app.current_tenants` carries the caller's org ids; an empty/unset GUC
  is the system / worker path (full access). RLS enforcement is exercised
  in the Postgres CI jobs.

See [`docs/architecture/multi-tenancy.md`](docs/architecture/multi-tenancy.md).

### Target allowlist

- Active scans against non-allowlisted hosts require an explicit
  `--i-understand-this-target-is-authorized` flag (CLI) /
  `override_authorized=true` (API). Either path also emits an
  audit event with `override=true` so it shows up forensically.
- CIDR ranges supported (`aegis.safety.is_target_allowed`).

### Target ownership verification

- The DNS-TXT / GitHub-App ownership-verification engine was removed
  with the pentest domain. Targets are gated by the project allowlist
  (and the explicit override flag above) alone; a target's `verified`
  flag is never set in this build.
- `GET /v1/targets/{id}/verification` and `POST /v1/targets/{id}/verify`
  keep their 404 / project-membership / `admin` gates and then return
  **`501 Not Implemented`** with an explicit message — an honest
  "unavailable" path rather than a faked verification. `verified` is
  left untouched.

### Deployment hardening (Helm / k8s)

- The Helm chart (`deploy/helm/aegis/`) renders every Aegis pod
  hardened by default: non-root `securityContext`
  (`runAsNonRoot`, uid/gid 1000), all Linux capabilities dropped,
  `allowPrivilegeEscalation: false`, and `seccompProfile:
  RuntimeDefault` at the pod and container level. Resource
  requests/limits and liveness/readiness probes ship on every service.
- **Optional gVisor sandbox** for the untrusted scan/tool workloads.
  With `sandbox.enabled=true` a `runsc` `RuntimeClass` is wired onto
  the worker pods (the attack-adapter executors), so a compromised
  adapter is contained from the node kernel. gVisor must be installed on the
  scheduling nodes. See [`docs/ops/kubernetes.md`](docs/ops/kubernetes.md).

### Air-gapped installs

- `AEGIS_OFFLINE_VENDOR_HOST` names the internal package / artifact
  mirror for air-gapped installs and surfaces in `aegis doctor` and the
  evidence pack. (The vendored pentest submodules and the URL-rewrite
  helper that used this setting were removed with the pentest domain.)
  See [`docs/ops/deploy.md`](docs/ops/deploy.md#air-gapped-offline-vendor-mirror).

### Compliance evidence

- `aegis evidence-pack --out DIR` produces a self-contained,
  **secret-free** bundle for auditors: exported audit chains + their
  `verify_chain` integrity verdicts, a SOC 2 / ISO 27001 / FedRAMP
  controls crosswalk (partial coverage flagged honestly), a system
  summary, and a hashed manifest. See
  [`docs/ops/compliance-evidence.md`](docs/ops/compliance-evidence.md).

### LLM guardrails

Two fail-safe layers sit at every point where untrusted text reaches an
LLM or where model output leaves the platform (`aegis/llm/guardrails.py`).
Both are config-gated and default **on**; logs and raised exceptions are
secret-free (a blocked input surfaces a clean error, never the offending
text or any matched secret).

- **Diff / output secret scrubbing.** Unified diffs (`extract_unified_diff`)
  and LLM outputs are passed through the same secret/token regex set used
  by the audit redactor (`aegis/audit/redact.py`), with matches replaced by
  `***REDACTED***`, so every downstream consumer of a scrubbed text
  inherits the scrub.
- **Prompt-injection detection.** Untrusted finding fields (title,
  description, remediation steps, PoC, code snippets) and free-text prompts
  are scored for injection before they reach the model: a tiered risk
  (`none` / `low` / `medium` / `high`) with categories
  (`instruction_override`, `role_switch`, `exfiltration`, …). At or above a
  configurable risk threshold (`AEGIS_LLM_INJECTION_BLOCK_RISK`, default
  `high`) the input is **blocked** with a clean error. `off` detects + logs
  only.
- The guardrail surface is `aegis/llm/guardrails.py` alone in this fork.
  The pentest remediation / agent chokepoints that wired it were removed
  with the pentest domain; the adversarial-ML explain / recommend stages
  (`aegis/ml/`) call the same functions at their LLM boundary.
- Config (env vars): `AEGIS_LLM_GUARDRAILS` (master, default on),
  `AEGIS_LLM_SCRUB_DIFF`, `AEGIS_LLM_DETECT_INJECTION`,
  `AEGIS_LLM_FILTER_OUTPUT` (all default on), and
  `AEGIS_LLM_INJECTION_BLOCK_RISK` (default `high`; `off` = detect-and-log).

See [`docs/architecture/overview.md`](docs/architecture/overview.md)
§ "LLM guardrails" and [`docs/ops/deploy.md`](docs/ops/deploy.md) for the
env knobs.

### LLM budget (fail-closed)

Budget enforcement is now **fail-closed** (`AEGIS_LLM_BUDGET_STRICT`,
default **on** in prod). A DB-backed run that reaches an LLM call
**without** a budget checker is **denied** rather than billed silently, so
a missing or misconfigured budget hook can no longer let an ungoverned run
spend. Set the knob off only in dev where cost isn't a concern.

### Secrets handling

- Four distinct secret materials:
  - `AEGIS_API_SESSION_PRIVATE_KEY` (NextAuth side, RS256); the API
    verifies with `AEGIS_API_SESSION_PUBLIC_KEY` and accepts
    `AEGIS_API_SESSION_PUBLIC_KEY_PREVIOUS` during rotation.
  - `AEGIS_WORKER_SIGNING_KEY` (shared HMAC, rotation overlap) — now
    **mandatory** for worker auth (the legacy static token is gone).
  - `AEGIS_GITHUB_PRIVATE_KEY` (GitHub App).
  - `AEGIS_AUTH_PROFILES_KEY` (Fernet, api + worker) — encrypts DAST
    auth-profile secrets at rest; `AEGIS_AUTH_PROFILES_KEY_PREVIOUS`
    enables MultiFernet rotation.
- DAST auth-profile secrets (`auth_profiles.secret_ciphertext`) are
  Fernet-encrypted before any row or audit event is written, never
  returned by any endpoint, and redacted (`***`) from recorded command
  strings; a missing key fails closed. The key supports **MultiFernet**
  rotation via `AEGIS_AUTH_PROFILES_KEY_PREVIOUS` (the previous key still
  decrypts existing profiles during the overlap), so rotation no longer
  requires re-creating profiles — see
  [`docs/ops/authenticated-dast.md`](docs/ops/authenticated-dast.md).
- `NEXTAUTH_SECRET` is opaque to Aegis (NextAuth's own).
- Generated **diffs / patches and LLM I/O** are secret-scrubbed before
  they are persisted, surfaced in a PR, or logged — see § "LLM guardrails"
  above. Secrets that leak into a model-authored diff or a model response
  are redacted to `***REDACTED***` on the canonical path.
- Rotation procedure for each is documented in
  [`docs/ops/deploy.md`](docs/ops/deploy.md) § "Rotation runbook" and
  [`docs/ops/authenticated-dast.md`](docs/ops/authenticated-dast.md)
  § "Key rotation".
- Integration secrets — the ticket-provider credentials
  (`AEGIS_JIRA_*` / `AEGIS_SERVICENOW_*` / `AEGIS_LINEAR_*`) and the
  target-verification salt `AEGIS_VERIFY_SECRET` — are env-configured
  only. They are never accepted in an API body, persisted to a row, or
  written to an audit detail; provider HTTP errors are wrapped to carry
  only the provider name + status code, never the body or auth header.

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
  are still deferred — see
  [ADR-0008](docs/adr/0008-nix-reproducible-builds.md) (tracked on the
  roadmap).
- See [`docs/security/supply-chain.md`](docs/security/supply-chain.md) for
  the trust model, env vars, and the operator verification runbook.

### Plugin sandbox

Third-party plugin scanners run **out-of-process by default**
(`AEGIS_PLUGINS_SANDBOX=1`). The child process gets a **minimal allowlisted
environment** — the parent's secrets are **never** passed to plugin code —
plus **POSIX rlimits** (CPU, address space, file size, and `RLIMIT_NPROC`),
its **own process group** with a **group-kill on timeout** (so a fork-bomb
or a stuck child can't outlive the deadline), and a **private fd result
channel** for handing findings back without a shared file.

**Be honest about what this is and isn't.** It is **defense-in-depth** —
process isolation + rlimits + a hard timeout + a minimal env, gated by the
Ed25519 **signature / allowlist** check (see "Supply-chain integrity"
above). It is **not** a network or filesystem jail: a hostile plugin can
still open sockets and touch files that the worker UID can reach. Kernel-
level isolation (a microVM per plugin) is the upgrade path in
[ADR-0006](docs/adr/0006-firecracker-microvm-isolation.md), not something
this sandbox provides.

There is also a **pre-existing load-then-verify limitation**: the plugin
signature is verified **after** the factory module is imported, so importing
a malicious module already executes its top-level code before the signature
gate runs. The sandbox does not close that gap. **Only run vetted, signed
plugins**, and keep `AEGIS_PLUGINS_ALLOW` / signature enforcement on. See
[`docs/ops/deploy.md`](docs/ops/deploy.md) § "Plugin sandbox" for the env
knobs.

### Tenant integrity (org_id drift)

Beyond Row-Level Security (above), the tenant key itself is now guarded
against drift. A **`BEFORE UPDATE` trigger** (migration `0009`) **rejects**
any change to `org_id` on the eight org-scoped tables, so a row can't be
silently re-homed into another tenant by an `UPDATE`. An hourly
`verify_tenant_integrity` reconciliation task and an
`aegis tenants verify` CLI command **detect** drift (a row whose `org_id`
disagrees with its parent project's) out of band, so a gap is caught even
if a future code path bypasses the trigger.

### Iterative remediation

The opt-in fix→test→retry loop is constrained so it can't damage an
operator's workspace or leak through fed-back output:

- It **requires a clean working tree** and **refuses to run against a dirty
  one**, so the loop never overwrites or discards uncommitted operator
  changes.
- The test output fed back to the LLM between iterations is **scrubbed for
  secrets** (the same redactor as the audit path) before it reaches the
  model.

See [`docs/ops/deploy.md`](docs/ops/deploy.md) § "Iterative remediation".

### CI security gates

Security scanning now **gates CI** (a failing scan fails the build), not
just advisory:

- **SAST.** `semgrep` (`p/python` + `p/security-audit` + repo-specific
  banned-pattern rules) and `bandit` run on every PR.
- **Dependency CVEs.** `pip-audit` (Python deps) and `trivy fs` (filesystem
  / lockfiles) run on every PR; **dependabot** is enabled for ongoing bumps.
- **Documented baselines.** The gates ship with explicit, reviewable
  baselines so they fail on *new* issues, not legacy noise: `.bandit`
  (`B310`), `.semgrepignore` (migrations), and intentionally **empty**
  `pip-audit` / `trivy` ignore files (nothing suppressed yet).

### WORM secrets in Helm

Production Helm installs **hard-fail on shipped dev secret placeholders** —
a deploy that still carries the in-chart development secret values is
rejected rather than quietly running with a known credential. Wire real
secrets (e.g. via the chart's `ExternalSecret` support) before installing to
prod. See [`docs/ops/kubernetes.md`](docs/ops/kubernetes.md).

## Out of scope

- Findings produced **by** Aegis against deliberately-vulnerable or
  deliberately-weak targets (test models, reference datasets). Those are
  by design.
- Vulnerabilities in bundled upstream components. Report those to the
  respective upstream projects (`shadcn-ui`,
  `opentelemetry-collector-contrib`, and the adversarial-robustness
  libraries the ML vertical builds on).
- DoS / resource exhaustion against the offline CLI when supplied a
  malicious finding fixture (the CLI is single-process; trust the
  fixture source).
- Cost / budget exhaustion via LLM-routed stages — now mitigated by
  fail-closed budget enforcement (`AEGIS_LLM_BUDGET_STRICT`; see § "LLM
  budget" above and the `BudgetChecker` hook in `aegis/llm/router.py`).

## Known gaps (tracked)

- Kernel-level (microVM) isolation for attack-adapter runs. The gVisor
  `RuntimeClass` sandbox for the worker pods has shipped — see
  "Deployment hardening" above — and third-party plugins run
  out-of-process; a microVM boundary is not yet in place.
- Worker autoscaling + multi-region DR (spike in
  [ADR-0005](docs/adr/0005-worker-autoscaling-and-dr.md)).
- Nix reproducible builds (spike in
  [ADR-0008](docs/adr/0008-nix-reproducible-builds.md)).

PII / content scrubbing and LLM prompt-injection / output filtering —
previously listed here — have shipped (see § "LLM guardrails" above).
Sandbox isolation (gVisor) and the SOC 2 / ISO 27001 / FedRAMP evidence
pack — also previously listed here — have shipped (see the sections above
and `CHANGELOG.md`). The remaining gaps are documented in
`docs/architecture/overview.md` under "What's deferred."
