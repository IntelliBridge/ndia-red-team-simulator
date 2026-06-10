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

With the seams closed — and DB-side append-only audit enforcement
(row-immutability trigger + `aegis_app`/`aegis_owner` role separation + pgaudit;
see `SECURITY.md` and `docs/ops/deploy.md`) plus the LLM guardrail layers
(diff/output secret scrubbing + prompt-injection detection; see
`SECURITY.md` § "LLM guardrails") now landed — the next focus is **capability
breadth** and the remaining **security / compliance hardening** (below). The
highest-leverage candidates: broadening the agent/tool roster toward the
OnePager promise, and authenticated DAST flows.

## Capability breadth

Closing the gap to the OnePager promise.

- **60+ specialized agents** (16 wired + 3 multi-agent patterns today).
- **35+ security tools** (24 today: 10 Kali + 14 scanner adapters).
- **Authenticated DAST flows.**
- **Community scanner-adapter marketplace** (third-party adapters via the plugin
  entry-point seam).

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
