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
see `SECURITY.md` and `docs/ops/deploy.md`) and the **production infra
hardening** now landed (a hardened Helm chart, gVisor sandbox isolation, HA
Keycloak, an air-gapped vendor mirror, and a compliance evidence pack — see
[Kubernetes (Helm)](ops/kubernetes.md) and
[Compliance evidence pack](ops/compliance-evidence.md)) — the next focus is
**capability breadth**: broadening the agent/tool roster toward the OnePager
promise, authenticated DAST flows, and the remaining deferred infra item, the
**native MCP protocol** (mcp-kali is consumed over REST today).

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
- **Per-scan sandbox isolation** (gVisor / Firecracker). *(gVisor
  `RuntimeClass` shipped — see "Scale, multi-tenancy & infra".)*
- ~~**SOC 2 / ISO 27001 / FedRAMP evidence pack.**~~ **Shipped**:
  `aegis evidence-pack --out DIR` bundles per-chain audit JSONL +
  verification verdicts, a controls crosswalk (partials flagged), a
  secret-free system summary, and a hashed manifest. See
  [`docs/ops/compliance-evidence.md`](ops/compliance-evidence.md).

## Scale, multi-tenancy & infra

- **Cross-org row-level multi-tenancy.**
- **Per-tenant cost dashboards / chargeback**; per-tenant LLM model routing.
- **Worker autoscaling / multi-region DR.**
- **Celery → Temporal** queue migration (migration shape documented; deferred).
- ~~**Production Helm / k8s manifests** (kind scaffolding only today).~~
  **Shipped**: `deploy/helm/aegis/` deploys the full stack with hardened
  pod specs (non-root, dropped caps, seccomp, resource limits,
  liveness/readiness probes); optional deps gated by `*.enabled`; a
  `helm-lint` CI job runs `helm lint` + `helm template`. See
  [`docs/ops/kubernetes.md`](ops/kubernetes.md).
- **OPA / Cedar policy engine** (static rule table today).
- ~~**Per-scan sandbox isolation** (gVisor / Firecracker).~~ **Shipped
  (gVisor)**: a `runsc` `RuntimeClass` gated by `sandbox.enabled`, wired
  onto the untrusted worker + kali pods (gVisor must be installed on the
  nodes). Firecracker is still out.
- ~~**HA Keycloak / IdP hardening.**~~ **Shipped**: `keycloak.replicas`
  (default 2), with the shared-DB + distributed-cache requirement for
  real HA documented in-chart and in
  [`docs/ops/kubernetes.md`](ops/kubernetes.md).
- **Native MCP protocol** (mcp-kali consumed over REST today).
- ~~**`AEGIS_OFFLINE_VENDOR_HOST`** — air-gapped vendor mirror for
  submodules.~~ **Shipped**: `scripts/vendor-submodules.sh` rewrites the
  submodule URLs to an internal mirror (`aegis/vendor.py` rewrite rules);
  surfaced in `aegis doctor`. See
  [`docs/ops/deploy.md`](ops/deploy.md#air-gapped-offline-vendor-mirror).

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
