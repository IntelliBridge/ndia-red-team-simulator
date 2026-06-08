# Roadmap

Where Aegis is heading. This is the forward-looking complement to the
[Changelog](https://github.com/IntelliBridge/aegis/blob/main/CHANGELOG.md)
(which records what has shipped). Items here are **directional, not dated** —
priorities shift; nothing below is a commitment to a release.

**Current release:** v0.11.0 (Python 3.12 / 3.13).

How to read it: the **Now / Next** milestone is the immediate focus — work that
is already half-built in code (reserved parameters, no-op hooks, deprecations
that outlived their target). The later sections are grouped by theme, roughly in
priority order.

---

## Now / Next — "Finish the seams"

The highest-leverage milestone: the scaffolding already exists in the codebase,
so these are completions rather than greenfield builds.

| Item | What's left | Where it's scaffolded |
|---|---|---|
| **Multi-scanner dispatch (M6)** | The worker task already dispatches by scanner name through the registry, but the synchronous service path (`run_scan`) and the CLI still hard-code Strix. Route all 14 adapters through one dispatch path so the platform's full scanner roster is reachable everywhere. | `aegis/services/scans.py` (`scanner` reserved for M6), `aegis/scanners/registry.py` (`dispatch`), `aegis/workers/tasks/scan.py` |
| **v0.5 API sunsets (overdue)** | Remove the deprecated `GET /v1/findings/by-scanner-id` and the legacy WebSocket `?token=` query-param auth. Both were slated for v0.5 and have been carried to v0.11.0. | `aegis/api/v1/findings_by_scanner_id.py`, `aegis/api/ws.py` |
| **LLM budget enforcement** | The `BudgetChecker` hook is a no-op until the real `llm_usage`-table check is wired — per-project / per-org cost caps. | `aegis/llm/router.py` |
| **Stale-job reaper** | A periodic Celery-beat job that marks jobs stuck `running` past a TTL as `failed`. Referenced in docstrings; not implemented. (The cancel/redelivery guard in `task_context` is the complementary half and already exists.) | `aegis/workers/bootstrap.py` |
| **`override_authorized` in the async fix API** | The flag threads through the agent and scan async paths and the synchronous CLI fix path, but the async `POST /v1/findings/{id}/fix` never exposes it. Add it to `FixBody` → `create_fix_job` → worker so off-allowlist remediation is possible via the API. | `aegis/api/v1/fix.py`, `aegis/services/fixes.py`, `aegis/workers/tasks/fix.py` |
| **Review-surfaced cleanups** | Four low-severity items deferred from the v0.5.2→v0.11.0 review: gate `open_pr` at approver role (defense-in-depth), make `record_artifact` idempotent on the Postgres backend, honor per-adapter `default_timeout`, and filter by `chain_id` in single-file audit mode. | `aegis/api/v1/fix.py`, `aegis/state/postgres.py`, `aegis/scanners/registry.py`, `aegis/audit/chain.py` |

## Capability breadth

Closing the gap to the OnePager promise.

- **60+ specialized agents** (16 wired + 3 multi-agent patterns today).
- **35+ security tools** (24 today: 10 Kali + 14 scanner adapters).
- **Authenticated DAST flows.**
- **Community scanner-adapter marketplace** (third-party adapters via the plugin
  entry-point seam).

## Security, audit & compliance

- **DB-side append-only audit enforcement** — Postgres `pg_audit` + role
  separation. Today a privileged DB operator could re-sign a chain end to end
  (tracked in `SECURITY.md`).
- **WORM / tamper-evident audit storage.**
- **PII / content scrubbing inside diffs and patches.**
- **LLM prompt-injection / output filtering.**
- **Supply-chain integrity** — sigstore image signing, signed plugin
  entry points, SLSA-3 / Nix reproducible builds.
- **Per-scan sandbox isolation** (gVisor / Firecracker).
- **SOC 2 / ISO 27001 / FedRAMP evidence pack.**

## Scale, multi-tenancy & infra

- **Cross-org row-level multi-tenancy.**
- **Per-tenant cost dashboards / chargeback**; per-tenant LLM model routing.
- **Worker autoscaling / multi-region DR.**
- **Celery → Temporal** queue migration (migration shape documented; deferred).
- **Production Helm / k8s manifests** (kind scaffolding only today).
- **OPA / Cedar policy engine** (static rule table today).
- **HA Keycloak / IdP hardening.**
- **Native MCP protocol** (mcp-kali consumed over REST today).
- **`AEGIS_OFFLINE_VENDOR_HOST`** — air-gapped vendor mirror for submodules.

## Integrations & workflow

- **Bidirectional Jira / ServiceNow / Linear sync.**
- **Cloud-target ownership verification** (DNS TXT / GitHub repo linkage).
- **Backport / release-train awareness** for generated fix PRs.
- **Iterative agent loops with test execution.**

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
