# Roadmap

Where Aegis is heading. This is the forward-looking complement to the
[Changelog](https://github.com/IntelliBridge/aegis/blob/main/CHANGELOG.md)
(which records what has shipped). Items here are **directional, not dated** —
priorities shift; nothing below is a commitment to a release.

**Current release:** v0.12.0 (Python 3.12 / 3.13).

How to read it: **Now / Next** is the immediate focus; the later sections are
grouped by theme, roughly in priority order.

---

## Recently shipped — "Finish the seams" (v0.12.0)

Closed in v0.12.0 (see the [Changelog](https://github.com/IntelliBridge/aegis/blob/main/CHANGELOG.md)):
multi-scanner dispatch so all 14 adapters run through the registry (M6); removal
of the two overdue v0.5 API sunsets (`by-scanner-id`, WebSocket `?token=`);
`override_authorized` on the async fix API; the stale-job reaper; LLM budget
enforcement with a per-model price table; and four review-surfaced cleanups.

## Now / Next

With the seams closed — DB-side append-only audit enforcement
(row-immutability trigger + `aegis_app`/`aegis_owner` role separation + pgaudit;
see `SECURITY.md` and `docs/ops/deploy.md`), the LLM guardrail layers
(diff/output secret scrubbing + prompt-injection detection; see
`SECURITY.md` § "LLM guardrails"), the plugin entry-point seam now a
documented, validated, allowlist-gated **scanner-adapter marketplace** (see
[Extending Aegis](dev/extending.md)), a pluggable authorization **`PolicyEngine`**
(static default + opt-in OPA / Cedar), **supply-chain integrity** mostly
shipped (keyless cosign image signing + SBOM + SLSA-3 provenance, and opt-in
signed plugins; see [Supply-chain integrity](security/supply-chain.md)),
**authenticated DAST flows** (encrypted auth-profile store + ZAP/Nuclei auth
injection; see `docs/ops/authenticated-dast.md`), **cross-org row-level
multi-tenancy** (Postgres RLS `FORCE` on the tenant tables + per-tenant
cost/routing; see [`multi-tenancy.md`](architecture/multi-tenancy.md)), and the
**workflow integrations** (bidirectional Jira / ServiceNow / Linear ticket
sync, cloud-target ownership verification, and backport / release-train
awareness for fix PRs; see [Integrations](integrations/index.md)) all
landed — the focus has been **capability breadth** and the remaining
**security / compliance hardening** (below). On breadth, the tool roster has
now reached the 35+ target (42 effect-classified tools) and the agent roster
has grown to 36 wired agents + 5 multi-agent patterns — substantial progress
toward the 60+ OnePager target. The next highest-leverage candidates:
continuing toward 60+ agents, and iterative agent loops with test execution.

## Capability breadth

Closing the gap to the OnePager promise.

- **60+ specialized agents** (36 wired + 5 multi-agent patterns today —
  substantial progress toward the OnePager target, not yet at 60+). The roster
  now spans the 16 original CAI agents, 8 newly-wired breadth CAI agents, and
  12 Aegis-native authored specialists (`cloud_recon`, `osint_collector`,
  `threat_intel`, `api_security_tester`, `web_surface_mapper`,
  `ssl_tls_auditor`, `dns_enumerator`, `secrets_hunter`, `iac_auditor`,
  `container_security`, `crypto_analyst`, `log_triage`).
- ~~**35+ security tools** (24 today: 10 Kali + 14 scanner adapters).~~
  **Shipped** — the unified tool catalog (`aegis/tools/catalog.py`) now exposes
  **42** effect-classified tools (10 Kali + 14 scanner adapters + 17 CAI
  function-tools + the Camoufox OSINT search), past the 35+ target.
- ~~**Authenticated DAST flows.**~~ **Shipped** (migration `0005`):
  encrypted auth-profile store (form / bearer / header / cookie kinds),
  admin-gated `/v1/auth-profiles` API + web page, `auth_profile_id` on
  `POST /v1/scans`, ZAP/Nuclei header injection with secret redaction.
  See `docs/ops/authenticated-dast.md`.
- ~~**Community scanner-adapter marketplace** — third-party adapters via the
  plugin entry-point seam.~~ **Shipped**: the `aegis.scanners` / `aegis.agents`
  entry-point seam is now a documented marketplace — Protocol-conformance
  validation (a bad plugin is rejected, never fatal), the `AEGIS_PLUGINS_ALLOW`
  distribution allowlist, an `aegis plugins list [--json]` inspector, and a
  reference plugin at `examples/aegis-plugin-example/`. See
  [Extending Aegis](dev/extending.md) § "Third-party plugins (marketplace)".

## Security, audit & compliance

- ~~**DB-side append-only audit enforcement** — Postgres pgaudit + role
  separation.~~ **Shipped** (migration `0004`): row-immutability trigger blocks
  `UPDATE`/`DELETE`/`TRUNCATE` on `audit_events`, `aegis_app`/`aegis_owner` role
  split, pgaudit logging. See `SECURITY.md` § "Audit chain".
- **WORM / tamper-evident audit storage.**
- ~~**PII / content scrubbing inside diffs and patches.**~~ **Shipped**:
  the canonical unified diff (in `extract_unified_diff`) and LLM outputs are
  scrubbed through the audit redactor's secret/token regex (`***REDACTED***`),
  so the persisted `.diff`, PR body, and remediation log all inherit it. See
  `SECURITY.md` § "LLM guardrails".
- ~~**LLM prompt-injection / output filtering.**~~ **Shipped**: untrusted
  finding fields and agent prompts are scored for injection (tiered risk +
  categories) before the model call and blocked at/above
  `AEGIS_LLM_INJECTION_BLOCK_RISK` (default `high`); fail-safe, secret-free
  logs. See `docs/architecture/overview.md` § "LLM guardrails".
- ~~**Supply-chain integrity** — sigstore image signing, signed plugin entry
  points, SLSA-3 provenance.~~ **Shipped**: release images are keyless
  cosign-signed by digest with a CycloneDX SBOM + SLSA-3 provenance
  attestation (`.github/workflows/release-sign.yml`, on `v*` tags), and
  third-party plugins support opt-in Ed25519 signature enforcement
  (`AEGIS_PLUGINS_REQUIRE_SIGNATURE` + trusted keys, `aegis plugins sign`).
  See [Supply-chain integrity](security/supply-chain.md) and `SECURITY.md`.
    - **Nix reproducible builds** — bit-for-bit reproducible builds so the
      published image can be independently rebuilt and compared. Still
      deferred.
- **Per-scan sandbox isolation** (gVisor / Firecracker).
- **SOC 2 / ISO 27001 / FedRAMP evidence pack.**

## Scale, multi-tenancy & infra

- ~~**Cross-org row-level multi-tenancy.**~~ **Shipped** (migration `0006`):
  Postgres RLS with `FORCE ROW LEVEL SECURITY` on `projects` + the eight
  project-scoped tables (denormalized `org_id` + `BEFORE INSERT` trigger),
  filtered by the per-request `app.current_tenants` GUC — defense-in-depth
  behind the app-layer project checks. See
  [`architecture/multi-tenancy.md`](architecture/multi-tenancy.md) and
  `SECURITY.md` § "Multi-tenancy".
- ~~**Per-tenant cost dashboards / chargeback**; per-tenant LLM model
  routing.~~ **Shipped** (migration `0007`): `organizations.monthly_llm_budget_cents`
  (enforced alongside the project daily cap) + `llm_model_overrides`
  per-tenant routing; `GET /v1/orgs/{org_id}/cost` and a web **/cost**
  dashboard.
- **Worker autoscaling / multi-region DR.**
- **Celery → Temporal** queue migration (migration shape documented; deferred).
- **Production Helm / k8s manifests** (kind scaffolding only today).
- ~~**OPA / Cedar policy engine** (static rule table today).~~ **Shipped**:
  the route-level role gate is now a pluggable `PolicyEngine`
  (`aegis/policy/engine.py`). `static` stays the default and is
  behaviour-identical; opt into `opa` or `cedar` via `AEGIS_POLICY_ENGINE`
  to delegate to an external decision point (fail-closed). Example policies
  ship at `deploy/opa/` and `deploy/cedar/`. See `docs/architecture/auth.md`
  § "Policy engine".
- **HA Keycloak / IdP hardening.**
- **Native MCP protocol** (mcp-kali consumed over REST today).
- **`AEGIS_OFFLINE_VENDOR_HOST`** — air-gapped vendor mirror for submodules.

## Integrations & workflow

- ~~**Bidirectional Jira / ServiceNow / Linear sync.**~~ **Shipped**
  (migration `0005`): a pluggable `TicketProvider` (env-selected via
  `AEGIS_TICKET_PROVIDER`, default `none`) pushes a finding to the tracker
  and pulls status back; `FindingTicket` records the external id/url/status
  per `(finding, provider)`. See
  [Integrations](integrations/index.md#bidirectional-ticket-sync).
- ~~**Cloud-target ownership verification** (DNS TXT / GitHub repo
  linkage).~~ **Shipped**: a target's `verified` flag now requires proof of
  control — a per-target DNS TXT token (`url`) or GitHub App installation
  linkage (`github_repo`). See
  [Integrations](integrations/index.md#cloud-target-ownership-verification).
- ~~**Backport / release-train awareness** for generated fix PRs.~~
  **Shipped**: `select_base_branch()` resolves a fix-PR base from a
  release-train map (`AEGIS_RELEASE_TRAINS`); default `main`, all existing
  callers unchanged. See
  [Integrations](integrations/index.md#backport-release-train-awareness).
- **Iterative agent loops with test execution.** *(Still pending —* the
  remaining sub-item of this line: run the generated patch through the
  project's tests and loop the agent on failures.*)*

## Frontend

- **Radix-based shadcn primitives** (`alert-dialog`, `tooltip`, `command`) —
  gated on adding `radix-ui` / `cmdk` to the offline build lockfile.
- Dark mode; audit-chain visualization page; per-finding HTML report;
  Storybook test-runner + a11y CI gates.

## Observability

- **`osquery` receiver + `isolationforest` anomaly processor** — not standard
  collector-contrib components; kept commented in `deploy/otel/config.yaml`
  until a custom/community collector distro ships them.

---

## Sources

This roadmap consolidates: [`architecture/overview.md`](architecture/overview.md)
§ "What's deferred", the per-release **Deferred** sections of the Changelog,
`SECURITY.md` § "Known gaps", the ADR consequences, the legacy Phase-3 plan, and
forward-looking seams in the code.
