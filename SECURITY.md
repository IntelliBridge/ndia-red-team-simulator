# Security policy

redsim is a non-operational proof of concept. There is no supported release
line: `main` is the only line, and the platform it inherits from aegis is
described below together with the boundaries the adversarial-ML vertical adds.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository
(`IntelliBridge/ndia-red-team-simulator`, Security tab) or contact the
repository owner listed in `CODEOWNERS` directly. Do **not** open a public
issue.

Include:

1. Affected commit.
2. Reproduction steps or PoC.
3. Impact assessment.
4. Suggested remediation if you have one.

We acknowledge within 3 business days and aim for triage within 10 business
days. Coordinated disclosure is preferred.

## Platform security model

### Auth and authorization

- Browser sessions: the app's own login page runs the OAuth 2 password grant
  against Keycloak from the Next server, verifies the ID token and mints the
  cookies; the realm's refresh token is sealed in an httpOnly cookie. The
  redsim-signed `redsim_api_session` cookie (RS256) is the only token FastAPI
  trusts on the cookie path. The web tier has no dev login.
- CLI / CI: bearer tokens only. Bearer wins when both are present.
  `REDSIM_AUTH_MODE=dev` accepts `dev:<email>` bearers and is refused when
  `REDSIM_ENV=prod`.
- Worker to API: only time-bound, versioned tokens with key-rotation overlap.
  `REDSIM_WORKER_SIGNING_KEY` is mandatory for worker auth.
- Every protected route runs `redsim.api.policy.check` server-side. The web
  `<RoleGated>` component is UX only.
- Roles rank `viewer` < `scanner` < `remediator` < `approver` < `admin`.
  `viewer` passes every membership (read) gate and fails every gated action.
  The ML actions gate as `model.register` (remediator), `attack.run`
  (scanner), `explain.run` (scanner), `harden.recommend` (remediator),
  `finding.review` (approver, plus an independence check so a campaign's
  creator cannot dismiss its own findings), `finding.annotate` (remediator),
  `report.export` (scanner), and since Phase B wave B0 `llm.probe.run`
  (remediator), `dataset.register` (remediator), `dataset.export`
  (remediator), `integration.push` (admin), `batch.run` (scanner),
  `report.render` (scanner), `finding.author` (remediator), mirrored in the
  OPA and Cedar bundles.
- The role-gate decision is pluggable (`REDSIM_POLICY_ENGINE`): the default
  `static` engine is the built-in role-rank table, `opa` and `cedar` delegate
  to an external policy service. External engines fail closed.
- Project access is enforced on read endpoints (reports, WebSocket) via
  `ensure_project_access` / `ensure_run_access`.

See [`docs/architecture/auth.md`](docs/architecture/auth.md).

### Key rotation

- **IdP keys (JWKS).** The Keycloak JWKS is a time-boxed cache
  (`REDSIM_API_JWKS_CACHE_TTL_SECONDS`, default `300`), so a rotated or
  revoked signing key is picked up within one TTL with no restart.
- **API session cookie.** During a rotation the API accepts a previous public
  key (`REDSIM_API_SESSION_PUBLIC_KEY_PREVIOUS`) alongside the current one.
- **Auth-profile secrets.** The Fernet key supports MultiFernet rotation
  (`REDSIM_AUTH_PROFILES_KEY_PREVIOUS`).

See [`docs/ops/deploy.md`](docs/ops/deploy.md) under "Rotation runbook".

### CSRF, CORS, WebSocket

- Cookie-authenticated mutations require an `X-Redsim-CSRF` header matching
  the `redsim_csrf` cookie (double-submit). Bearer-only callers are exempt.
- CORS exposes `allow_credentials=True` only against an explicit origin list
  (`REDSIM_CORS_ORIGINS` plus `REDSIM_WEB_ORIGIN`).
- WebSocket upgrades validate `Origin` and resolve auth from subprotocol,
  then header, then cookie. Policy failures close with `1008`.

### HTML report defence

- Strict `html.escape(..., quote=True)` for every finding and evidence
  interpolation in the report renderer.
- Every HTML report carries `Content-Security-Policy: default-src 'none'`
  (with `style-src 'self' 'unsafe-inline'`, `img-src data:`, `base-uri
  'none'`, `frame-ancestors 'none'`, `form-action 'none'`),
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and
  `X-Frame-Options: DENY`. No inline `<script>` anywhere in the templates.
  The planned `/v1/artifacts/{id}` route serves SHAP PNGs and JSON under the
  same headers.

### Audit chain

- Every active operation runs through `redsim.safety.authorize` and lands a
  hash-chained event via the configured `AuditWriter` (`PostgresAuditWriter`
  in api/worker mode, `JsonlAuditWriter` offline, `InMemoryAuditWriter` in
  tests).
- Audit-before-enqueue: the chain row exists before the `Run` and `Job` rows
  and before Celery is touched.
- Forensic detail is digests plus blob refs. Raw tool output, model bytes,
  dataset rows and prompt text never appear in audit rows.
- Append-only at the database (migration `0004`): a row-immutability trigger
  rejects `UPDATE`, `DELETE` and `TRUNCATE` on `audit_events` for everyone,
  owner and superuser included. The runtime `redsim_app` role has only
  `INSERT, SELECT`. DDL needs the separate `redsim_owner` role, and
  `pgaudit` logs such changes out of band.
- WORM archival (`redsim/storage/worm.py`): chains export to an S3 / MinIO
  bucket with Object Lock (`COMPLIANCE` mode, default 7-year retention) from
  a daily beat task self-gated on `REDSIM_WORM_EXPORT`, and on demand with
  `redsim audit export`. The sealed copy cannot be altered before retention
  expires, even by an attacker who owns the database.

See [`docs/architecture/audit-chain.md`](docs/architecture/audit-chain.md).

### Multi-tenancy and data isolation

- The tenant is the Organization. Every project belongs to one org.
- The app layer scopes reads to the caller's project memberships, and the
  database adds Postgres Row-Level Security keyed on `org_id` as defence in
  depth. `ENABLE` plus `FORCE ROW LEVEL SECURITY` on `projects`, the eight
  project-scoped tables (migration `0006`) and `ml_campaigns` (migration
  `0010`), so the policy binds the table owner too. A per-request GUC
  `app.current_tenants` carries the caller's org ids. An empty GUC is the
  system / worker path.
- Tenant integrity: a `BEFORE UPDATE` trigger (migration `0009`, extended to
  `ml_campaigns` by `0010`) rejects any change to `org_id`, so a row cannot be
  re-homed into another tenant. An hourly `verify_tenant_integrity` task and
  `redsim tenants verify` detect drift out of band.

See [`docs/architecture/multi-tenancy.md`](docs/architecture/multi-tenancy.md).

### Targets

- Targets are gated by the project allowlist in `redsim.yaml`
  (`redsim.safety.is_target_allowed`, exact host or CIDR). An override
  (`override_authorized=true`) emits an audit event with `override=true`.
- The DNS-TXT / GitHub-App ownership-verification engine was removed with the
  pentest domain. `GET /v1/targets/{id}/verification` and
  `POST /v1/targets/{id}/verify` keep their 404, membership and `admin` gates
  and then return `501 Not Implemented`. A target's `verified` flag is never
  set in this build.
- ML model targets (`Target.kind` of `ml_model_artifact` and
  `ml_model_endpoint`) are created only through the `/v1/models` routes so
  the upload rules below cannot be bypassed. `POST /v1/targets` with an ML
  kind answers `400 use_models_route`. A black-box endpoint (Phase B wave B2)
  registers at `target.manage` (admin) with its credential in an
  `AuthProfile`, passes the egress allowlist and the D3 attestation
  (`attestation_required` otherwise), is queried only from the worker-parent
  predict broker (never the API, never the sandbox child), and its profile
  cannot be deleted while the target is live (`409 auth_profile_in_use`).
  No DNS-TXT ownership check exists for endpoints (owner default
  ENDPOINT-26).

### Deployment hardening (Helm / k8s)

- The chart (`deploy/helm/redsim/`) renders every pod non-root (uid/gid
  1000), all Linux capabilities dropped, `allowPrivilegeEscalation: false`,
  `seccompProfile: RuntimeDefault`, with resource limits and probes on every
  service.
- Optional gVisor sandbox: with `sandbox.enabled=true` a `runsc`
  `RuntimeClass` is wired onto the worker pods, which are the only pods that
  load models and run attacks. gVisor must be installed on the scheduling
  nodes. The ECS Fargate target has no equivalent, which the spec records as
  a risk. See [`docs/ops/kubernetes.md`](docs/ops/kubernetes.md).
- Production Helm installs hard-fail on shipped dev secret placeholders. Wire
  real secrets (for example via the chart's `ExternalSecret` support) before
  installing to prod.

### Compliance evidence

`redsim evidence-pack --out DIR` produces a self-contained, secret-free
bundle for auditors: exported audit chains with their `verify_chain`
verdicts, a SOC 2 / ISO 27001 / FedRAMP controls crosswalk with partial
coverage flagged, a system summary and a hashed manifest. See
[`docs/ops/compliance-evidence.md`](docs/ops/compliance-evidence.md).

### Plugin sandbox

Third-party adapters discovered from the `redsim.scanners` entry-point group
run out-of-process by default (`REDSIM_PLUGINS_SANDBOX=1`). The child gets a
minimal allowlisted environment (the parent's secrets, including
`PYTHIA_API_KEY`, are never passed), POSIX rlimits (CPU, address space, file
size, open files, processes), its own process group with a group-kill on
timeout, and a private fd result channel.

This is defence in depth, not a jail: process isolation plus rlimits plus a
hard timeout plus a minimal env, gated by the Ed25519 signature / allowlist
check. It is not a network namespace or a filesystem jail. Plugin signatures
are verified after the factory module is imported, so importing a malicious
module already runs its top-level code. Only run vetted, signed plugins with
`REDSIM_PLUGINS_ALLOW` and signature enforcement on. See
[`docs/ops/deploy.md`](docs/ops/deploy.md) under "Plugin sandbox".

### Supply-chain integrity

- Signed third-party plugins: opt-in Ed25519 signature enforcement
  (`REDSIM_PLUGINS_REQUIRE_SIGNATURE` plus `REDSIM_PLUGINS_TRUSTED_KEYS`)
  bound to the SHA-256 of the factory module's source. `redsim plugins sign`
  produces the detached signature. The upstream example plugin directory is
  not carried in this fork.
- Signed and attested release images: `release-sign.yml` builds on `v*` tags,
  pushes to GHCR, keyless cosign-signs each image by digest and attaches a
  CycloneDX SBOM and SLSA provenance. Verify with `cosign verify` before
  deploy (`scripts/verify-release.sh`).
- Dependency CVEs (`pip-audit`, `trivy`), SAST (`semgrep`, `bandit`) and a
  verified-secrets scan (`trufflehog`) gate CI with documented baselines
  (`.bandit`, `.semgrepignore`, `.github/pip-audit-ignores.txt`,
  `.trivyignore`). The `.trivyignore` baseline at the wave B4 push holds
  Next.js 14.2.35 advisories whose fix is only in Next 15 or 16 (a
  web-workstream migration): `CVE-2026-44573`, `CVE-2026-44578`,
  `GHSA-8h8q-6873-q5fj`, `GHSA-h25m-26qc-wcjf`, `GHSA-q4gf-8mx6-v5v3`,
  `CVE-2026-64641`, `CVE-2026-64645`, `CVE-2026-64649`, `CVE-2026-75604` and
  its alias `GHSA-2xp9-vwfh-vxw4` (an Image Optimization RCE on
  windows-hosted servers; `deploy/Dockerfile.web` is a Linux container, so
  the path is not reachable as deployed), and the `postcss` 8.4.31 entries
  `CVE-2026-45623` and `CVE-2026-73646` (pinned exactly by `next@14.2.35`).
  Each entry carries its reason in the file; the web UI is auth-gated
  internal admin.
- **garak (Phase B LLM domain, decision D5).** The `garak` extra
  (`garak>=0.16,<0.17`) installs the `openai` and `litellm` client libraries
  as transitive dependencies. No deploy image installs the extra
  (`deploy/Dockerfile.worker` installs `.[worker,ml]`, `Dockerfile.api`
  `.[api,worker]`); it is installed in the `garak offline` and `e2e-python` CI
  lanes and on a developer venv that opts in, so those clients exist only
  where a probe run can happen, the worker's `default` pool when an operator
  installs the extra there. No configuration path reaches them: no provider
  key variable exists anywhere (`.env.example` names `PYTHIA_API_KEY` as the
  only LLM credential), garak's generator is `PythiaGenerator`, which posts
  only to the configured gateway with a probe key held in a bearer
  `AuthProfile` and never read from the environment, `assert_no_litellm`
  checks that litellm never enters the generator's class hierarchy, the API
  process blocks `garak`, `openai` and `litellm` in
  `tests/test_api_process_has_no_ml.py`, the probe child runs with the
  interpreter allowlist (every `PYTHIA_*`, `AWS_*`, `KAGGLE*`, `OPENAI*`,
  `HF_TOKEN` and `REDSIM_*` secret swept) and the key in a 0600 file it
  deletes at once, and `redsim/llm/pricing.py` snapshots the environment
  around its own `litellm` import so a cost lookup is never an ambient
  credential source. The probe corpora garak ships are loaded by garak from
  the installed package; the public data repository carries a copy with the
  licence per subset (spec 11.6 addendum). See
  [`docs/security/supply-chain.md`](docs/security/supply-chain.md) and
  [`docs/ops/pythia.md`](docs/ops/pythia.md).
- See [`docs/security/supply-chain.md`](docs/security/supply-chain.md).

### LLM: Pythia holds the provider keys

- Every LLM call goes through Pythia (`redsim/llm/pythia.py`). redsim holds
  one `pk_…` gateway key (`PYTHIA_API_KEY`) and no model-provider key
  anywhere. The gateway applies persona, guardrails, metering and audit before
  a request reaches a model. Since `7556b22` `.env.example` is Pythia-only:
  no provider-key placeholder remains. Since Phase B wave B2 the garak probe
  traffic is the second consumer, with its own probe key in an `AuthProfile`
  and its own persona (owner default LLM-26), never `PYTHIA_API_KEY`.
- The key lives in `.env` at the repo root, which is gitignored and
  dockerignored. The Aikido pre-commit hook scans staged files for secrets.
  Nothing logs the key: `PythiaSettings.redacted()` is the only view that
  reaches provenance, and the connectivity check prints at most a
  three-character prefix.
- The hardening writer receives metrics, scorecard numbers, rule outputs,
  limitations and a SHAP text summary. It never receives images, model bytes,
  dataset rows or URL strings. When Pythia is not configured the narrative is
  skipped, never faked (`narrative_source = "rules"`).
- TLS to the gateway is verified against the OS trust store by default
  (`REDSIM_TLS_TRUSTSTORE=1`) or a PEM bundle (`REDSIM_CA_BUNDLE`,
  `SSL_CERT_FILE`). Verification is never disabled.
- Guardrails (`redsim/llm/guardrails.py`, config in `redsim/config.py`) sit at
  the LLM boundary: secret scrubbing of LLM output and prompt-injection
  scoring of untrusted input with a configurable block threshold
  (`REDSIM_LLM_GUARDRAILS`, `REDSIM_LLM_SCRUB_DIFF`,
  `REDSIM_LLM_DETECT_INJECTION`, `REDSIM_LLM_FILTER_OUTPUT`,
  `REDSIM_LLM_INJECTION_BLOCK_RISK`, all default on).
- Budget enforcement is fail-closed (`REDSIM_LLM_BUDGET_STRICT`, default on
  in prod): a DB-backed run that reaches an LLM call without a budget checker
  is denied, and per-project daily and per-org monthly caps apply.

### Secrets handling

- Secret materials: `REDSIM_API_SESSION_PRIVATE_KEY` (web, RS256) with
  `REDSIM_API_SESSION_PUBLIC_KEY` and `…_PREVIOUS` on the API,
  `REDSIM_WORKER_SIGNING_KEY` (shared HMAC, rotation overlap),
  `REDSIM_AUTH_PROFILES_KEY` (Fernet, encrypts auth-profile secrets at rest:
  the endpoint credentials and the LLM probe keys of Phase B), `PYTHIA_API_KEY`, the database
  role passwords, `BETTER_AUTH_SECRET` (Better Auth's own), and the S3
  credentials when an IAM role is not used.
- Auth-profile secrets are encrypted before any row or audit event is written,
  are never returned by any endpoint, and a missing key fails closed.
- `KAGGLE_USERNAME` / `KAGGLE_KEY` are used by the one-off
  `redsim ml build-assets` run only, never on the API, web, steady-state
  worker or beat services, never in the sandbox child, never logged or written
  to a manifest.
- Secrets are read from the environment (or `.env` for the Pythia settings)
  only. They are never accepted in an API body, persisted to a row, or
  written to an audit detail.

## ML vertical boundaries

These rules come from sections 9, 11, 14 and 21 of the product spec and the
project brief. Every rule below is enforced on `main` (the ML vertical landed
through the Phase A completion waves and Phase B waves B0 to B4, 2026-09-09)
and tested (the unit and `ml` tiers, and end to end by `tests/e2e/`). The
tests named here are the evidence. Re-run them before quoting them.

Platform boundaries:

- **The API process never loads a model or imports an ML library.**
  `tests/test_api_process_has_no_ml.py` builds the app with `torch`,
  `torchvision`, `art`, `onnx`, `onnxruntime`, `shap`, `sklearn`, `xgboost`
  and, since Phase B, `garak`, `openai`, `litellm`, `reportlab`, `pyarrow`
  and `mlcroissant` blocked and asserts it still serves. `deploy/Dockerfile.api`
  installs `.[api,worker]` without the `ml` extra. Only the worker image
  carries torch, ART, onnxruntime and SHAP.
- **No pentest execution path remains.** `POST /v1/scans` is unmounted, the
  scanner roster holds only `ml-campaign`, and `redsim scan` exits non-zero
  instead of writing an empty findings file.
- **Open data only.** Every dataset is open, unclassified and publicly
  licensed (spec section 11 and its 11.6 and 11.7 addenda). The only dataset
  input path is `POST /v1/datasets` (Phase B wave B3): a Parquet slice with
  an optional Croissant manifest, refused without a licence statement,
  statically checked in the API and parsed only in the sandbox child. There
  is no connection to any operational or mission data source (Lattice is
  text only by D3; the Foundry push is opt-in, off by default and proven
  against a fake server only), and no fixture is ever presented as a result.

ML sandbox and upload rules (`redsim/ml/sandbox.py`,
`redsim/ml/sandbox_worker.py`, `redsim/api/v1/models.py`,
`redsim/workers/tasks/ml_model.py`):

- **Models are loaded only on the worker inside a sandboxed child process.**
  `redsim.ml.sandbox.run_campaign_sandboxed` spawns
  `python -m redsim.ml.sandbox_worker` in its own process group. The typed
  `MlSandboxConfig` (from `REDSIM_ML_SANDBOX_*`) sets the parent's wall clock
  (1200 s), `RLIMIT_CPU` (900 s), `RLIMIT_AS` (4096 MB), `RLIMIT_FSIZE`
  (1024 MB) and the thread pins (2). The child environment is the interpreter
  allowlist plus `MPLBACKEND=Agg`, the offline HF flags and four `REDSIM_*`
  names only: `REDSIM_ML_ASSETS_DIR`, `REDSIM_PLUGINS`, `REDSIM_ENV_FILE`
  pinned to an absent file and `REDSIM_DISABLE_LLM=1`. Every secret-bearing,
  cloud, Pythia and proxy variable is removed, and the child receives no
  network configuration. A timeout or cancel kills the process group. There
  is no switch to run in process. The parent populates a per-job work
  directory (mode 0700) with the digest-checked model file and the
  evaluation slice. The child never reaches S3, Postgres, Redis or the
  dataset source, and an endpoint target is reached only through the parent's
  broker socket. Bundled models take the same path on every run
  (`tests/test_ml_sandbox.py`, `tests/ml/test_sandbox_loader.py`,
  `tests/test_api_process_has_no_ml.py`).
- **Accepted formats are ONNX and pickle-free state dicts only.** ONNX is
  preferred (`onnx.checker` plus an onnxruntime session without custom-op
  libraries, `onnx2torch` for gradients). PyTorch `state_dict` uploads are
  accepted only as `torch.load(..., weights_only=True)` or `safetensors`,
  and only with an `architecture_id` from the in-tree catalog
  (`redsim/ml/targets/architectures.py`). Free-form model code is never
  accepted. TensorFlow SavedModel is not accepted in Phase A.
- **Pickles are refused.** The API sniffs the first bytes and rejects a
  pickle opcode, a `.pkl` / `.joblib` name, a full `torch.save` object or a
  signature that contradicts the declared format with `415 pickle_refused` /
  `415 unsupported_model_format`, retains no bytes, and writes a
  `model.register` audit row with `success=false`. There is no trust override
  in Phase A. The only pickle the loader ever opens is a bundled sklearn
  asset whose sha256 matches the manifest written at build time.
- **Static checks in the API, deep validation in the child.** Size cap while
  streaming (`REDSIM_ML_UPLOAD_MAX_MB`, default 512, `413` above it), magic
  bytes, sha256, content-addressed blob key. Format parse, architecture
  instantiation, shape and class-count checks happen in `model.validate`
  inside the sandbox and are written back as `available` or `refused` with a
  reason.
- **URL strings are data.** The tabular pipeline never fetches, resolves or
  renders a URL from the malicious-URLs dataset, not in the worker, the
  child, the UI or the reports. The feature extractor is a pure string
  function. A URL that is displayed is escaped, non-clickable text labelled
  as dataset content, and it never enters the LLM payload. A test asserts
  the no-network property.
- **Hardening recommendations are text.** A candidate recommendation cites
  ART classes and papers as plain text. The worker never applies a defense
  to the target, never modifies or persists a defended model and never
  changes the target.
- **Attack ids are declarative references** to registered, bounded ART
  adapters. The repository stores no attack recipes, tactical instructions or
  executable payloads. LLM probe ids reference garak's catalogued probes; no
  prompt text is committed to the repository.
- **Endpoint queries leave only from the worker-parent predict broker**
  (Phase B): over a unix socket in the 0700 work directory, under the egress
  allowlist with private-address refusal, a rate limit and a per-job query
  budget, with the credential decrypted at pickup and held in memory only.
  The sandbox child holds no URL and no credential.
- **Nothing that leaves for another system carries a bare score.** The
  Croissant manifest validator and the Foundry payload guard refuse a bare
  MRI, a URL string, a JWT-shaped or `pk_` value, model file names and raw
  bytes before anything is written or sent (D9).

## Out of scope

- Findings produced **by** redsim against deliberately weak targets (test
  models, reference datasets). Those are by design.
- Vulnerabilities in bundled upstream components. Report those to the
  respective upstream projects (`shadcn-ui`, `opentelemetry-collector-contrib`,
  ART, SHAP, torch, onnxruntime).
- DoS or resource exhaustion against the offline CLI when supplied a malicious
  finding fixture (the CLI is single-process, trust the fixture source).

## Known gaps (tracked)

Current on 2026-09-09.

- **Kernel-level (microVM) isolation** for model loading and attack runs. The
  gVisor `RuntimeClass` for worker pods exists in the Helm chart. The plugin
  sandbox and the ML sandbox child (`redsim/ml/sandbox.py`) are process
  isolation plus rlimits: a separate process group, `RLIMIT_CPU`,
  `RLIMIT_AS`, `RLIMIT_FSIZE`, a wall-clock kill and an allowlisted
  environment. Neither is a network namespace or a filesystem jail. The
  child is never handed network configuration, but nothing stops a process
  that already has a socket API from opening one. ECS Fargate has no gVisor
  equivalent.
- **Next.js advisories baselined in `.trivyignore`.** The web app pins
  `next@14.2.35`. Every fix below lands only on the Next 15.x or 16.x line,
  so the twelve ids are ignored in the `deps` CI job until the tracked Next
  14 to 15 (or 16 plus React 19, dependabot PR #15) upgrade is done as a
  tested frontend migration. The web UI is an auth-gated internal admin
  surface, which lowers exposure but does not remove it. Ids: `CVE-2026-44573`
  (information disclosure via middleware), `CVE-2026-44578` (SSRF),
  `GHSA-8h8q-6873-q5fj` (Server Actions DoS), `GHSA-h25m-26qc-wcjf` (request
  deserialisation DoS), `GHSA-q4gf-8mx6-v5v3` (Server Components DoS),
  `CVE-2026-64641` (App Router DoS), `CVE-2026-64645` (SSRF),
  `CVE-2026-64649` (SSRF via host redirection in Server Actions),
  `CVE-2026-75604` and its alias `GHSA-2xp9-vwfh-vxw4` (unauthenticated RCE
  in the Image Optimization API on Windows-hosted servers, not reachable from
  the Linux `deploy/Dockerfile.web` image), and the two `postcss@8.4.31` ids
  `CVE-2026-45623` (information disclosure or DoS via crafted CSS) and
  `CVE-2026-73646` (path traversal in source-map loading), which cannot move
  independently because `next@14.2.35` pins that exact postcss. Remove each
  id from `.trivyignore` in the upgrade PR.
- **Audit redaction** blanks keys containing `token` and known key shapes and,
  since Phase B wave B4 (INTEROP-28), scrubs JWT-shaped values by shape in
  `redsim/audit/redact.py`.
- Worker autoscaling and multi-region DR
  ([ADR-0005](docs/adr/0005-worker-autoscaling-and-dr.md)) and Nix
  reproducible builds ([ADR-0008](docs/adr/0008-nix-reproducible-builds.md))
  are deferred spikes.
