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

With the seams closed — DB-side append-only audit enforcement landed
(row-immutability trigger + `aegis_app`/`aegis_owner` role separation + pgaudit;
see `SECURITY.md` and `docs/ops/deploy.md`), and the workflow integrations now
shipped (bidirectional Jira / ServiceNow / Linear ticket sync, cloud-target
ownership verification, and backport / release-train awareness for fix PRs; see
[Integrations](integrations/index.md)) — the next focus is **capability
breadth** and the remaining **security / compliance hardening** (below). The
highest-leverage candidates: broadening the agent/tool roster toward the
OnePager promise, authenticated DAST flows, and closing the last integrations
sub-item, iterative agent loops with test execution.

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
