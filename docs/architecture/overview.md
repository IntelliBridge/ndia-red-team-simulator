# Architecture overview

This doc is the entry point to "how does Aegis fit together." For the
auth flow, audit chain, observability pipeline, and HTTP API each get
their own dedicated doc; this file is the shared mental model.

- [Auth flows](auth.md)
- [Audit chain](audit-chain.md)
- [Observability](observability.md)
- [`/v1/*` HTTP API](../api/v1.md)

---

## System context

```mermaid
flowchart LR
  subgraph callers["Callers"]
    dev["Developer<br/>CLI user"]
    approver["Approver<br/>web UI"]
    gh["GitHub<br/>PR webhooks"]
  end

  subgraph aegis["Aegis"]
    api["aegis-api<br/>FastAPI: RBAC, admission,<br/>audit, read/stream"]
    worker["aegis-worker<br/>Celery: scanner and CAI<br/>execution + status"]
    web["@aegis/web<br/>Next.js 14 dashboard"]
    li["aegis-log-ingest<br/>OTLP/Logs to Postgres"]
  end

  subgraph ext["External systems"]
    kc["Keycloak<br/>OIDC identity"]
    llm["LLM providers<br/>via CAI"]
  end

  subgraph data["Data plane"]
    pg[("Postgres<br/>runs / jobs / findings<br/>audit_events<br/>application_logs")]
    s3[("MinIO / S3<br/>artifacts + reports")]
    redis[("Redis<br/>broker + pub/sub")]
    kali["MCP Kali Server<br/>nmap / nikto / sqlmap"]
  end

  dev -- "bearer" --> api
  approver -- "browser" --> web
  web -- "cookie + CSRF" --> api
  gh -- "HMAC webhook" --> api
  api -- "JWKS" --> kc
  api -- "enqueue" --> redis
  worker -- "consume" --> redis
  worker -- "REST" --> kali
  worker -- "via CAI" --> llm
  api -- "read/write" --> pg
  worker -- "read/write" --> pg
  worker -- "artifacts" --> s3
  api -- "stream reports" --> s3
  worker -- "OTel logs" --> li
  li -- "batched INSERT" --> pg
```

## Deployment topology

Three compose profiles ship out of the box:

```mermaid
flowchart TB
  subgraph p_default["compose profile: default"]
    direction LR
    api[aegis-api]
    worker[aegis-worker]
    web[aegis-web]
    li[aegis-log-ingest]
    pg[(Postgres)]
    redis[(Redis)]
    kc[Keycloak]
    minio[(MinIO)]
    kali[mcp-kali]
    api --- pg
    worker --- pg
    li --- pg
    api --- redis
    worker --- redis
    web --- api
    api --- minio
    api --- kc
    worker --- kali
    api -. "POST /ingest" .-> li
    worker -. "POST /ingest" .-> li
  end

  subgraph p_obs["+ profile: obs"]
    col[otel-collector]
    loki[(Loki)]
    jaeger[Jaeger]
    api2[aegis-api]
    worker2[aegis-worker]
    api2 -. "OTLP" .-> col
    worker2 -. "OTLP" .-> col
    col -. "logs" .-> loki
    col -. "logs" .-> li
    col -. "traces" .-> jaeger
  end

  subgraph p_search["+ profile: obs-search"]
    es[(Elasticsearch)]
    kibana[Kibana]
    col2[otel-collector]
    col2 -. "logs" .-> es
    kibana --- es
  end

  p_default --> p_obs --> p_search
```

- **default** — everything you need to demo the platform locally.
  `aegis-log-ingest` runs in this profile so
  `SELECT * FROM application_logs WHERE run_id = '…'` works even
  without Loki up.
- **`obs`** — adds the OTel Collector + Loki + Jaeger. Logs fan out:
  Loki for ad-hoc kibana-style queries, `aegis-log-ingest` for the
  Postgres mirror, Jaeger for traces.
- **`obs-search`** — adds Elasticsearch + Kibana on top of `obs`.

For a per-service walkthrough of the compose stack, see
[`docs/dev/local-stack.md`](../dev/local-stack.md). For the production
deployment runbook (env vars, key rotation, image build), see
[`docs/ops/deploy.md`](../ops/deploy.md).

## Service shapes

| Service             | Language | What it owns                                                   |
|---------------------|----------|----------------------------------------------------------------|
| `aegis-api`         | Python   | FastAPI app: RBAC, admission services, read/stream routes      |
| `aegis-worker`      | Python   | Celery: scanner + CAI execution; persists `Finding.status` etc. |
| `aegis-log-ingest`  | Python   | OTLP/Logs receiver → `application_logs` Postgres rows           |
| `@aegis/web`        | TS/Next  | App-router UI; cookie-aware `api()` helper                     |
| `@aegis/design-system` | TS    | Workspace package with shadcn-derived primitives + Aegis-branded compositions |
| `mcp-kali`          | (image)  | nmap / nikto / sqlmap host                                     |

The Python services share `aegis/services/` so the same admission +
execution code paths run regardless of which entry point invoked them
(CLI, API, worker).

## Request flow: `aegis scan` (admission + execution)

```mermaid
sequenceDiagram
    autonumber
    participant U as Caller (CLI / UI / GitHub)
    participant API as aegis-api
    participant Wr as PostgresAuditWriter
    participant DB as Postgres
    participant Q as Redis broker
    participant W as aegis-worker
    participant S as Scanner (Strix)

    U->>API: POST /v1/scans
    API->>API: policy.check SCAN_START
    API->>Wr: authorize scan.start
    Wr->>DB: INSERT audit_events (chained)
    API->>DB: INSERT runs, INSERT jobs
    API->>Q: scan_start.delay(job_id)
    API-->>U: run_id, job_id, status_url

    W->>Q: pull task
    W->>DB: UPDATE jobs status running
    W->>Wr: authorize scan.execute.strix
    Wr->>DB: INSERT audit_events (run-scoped)
    W->>S: dispatch strix
    S-->>W: findings + exit_code
    W->>DB: INSERT findings
    W->>DB: UPDATE jobs status succeeded
```

The load-bearing invariant: the audit row for `scan.start` is on the
chain **before** Redis is touched. A worker crash mid-enqueue leaves a
chained audit event plus a `queued` job — never a half-state where the
job ran without a matching audit trail.

## Data model (Postgres)

```mermaid
erDiagram
    organizations ||--o{ projects : has
    projects ||--o{ project_memberships : grants
    users ||--o{ project_memberships : member_of
    projects ||--o{ targets : registers
    projects ||--o{ runs : owns
    runs ||--o{ jobs : tracks
    runs ||--o{ findings : produces
    findings ||--o{ remediation_attempts : has
    runs ||--o{ artifacts : emits
    audit_chain_heads ||--o{ audit_events : tracks
    application_logs }o--|| projects : project_id
    application_logs }o--|| runs : run_id

    findings {
        UUID id PK
        STRING scanner_finding_id "uniq per run"
        STRING run_id FK
        JSONB schema_blob
        STRING status
        STRING validation_state
    }
    audit_events {
        STRING chain_id "run-scoped or project-scoped"
        INT seq
        BYTEA prev_hash
        BYTEA this_hash
        STRING action
        STRING actor
        STRING target
        BOOLEAN success
        JSONB detail
    }
    application_logs {
        BIGINT id PK
        TIMESTAMPTZ ts
        STRING severity
        STRING service
        STRING run_id
        STRING request_id
        STRING trace_id
        JSONB attrs
    }
```

Two design choices worth highlighting:

- **Finding PK is an internal UUID** (since v0.3.1 F9). The scanner's
  upstream identifier lives in `scanner_finding_id`, uniquely
  constrained per-run. Two parallel runs can both emit
  `vuln-0001` from Strix without colliding.
- **`audit_events.chain_id` is the partition key**, not a project id.
  Chains are tracked at the run level (most common), the project
  level (admission), and a single `system` chain for global events.
  This makes verification a per-chain walk; no global lock is needed.

## Layered service architecture

```mermaid
flowchart TB
  subgraph Entry["Entry points"]
    cli["aegis CLI"]
    api["/v1/* HTTP routes"]
    worker["Celery tasks"]
  end

  subgraph Services["aegis/services/ — admission + execution"]
    direction LR
    create["create_*_job<br/>admission"]
    execute["start_scan / generate_fix /<br/>verify / render_reports<br/>execution"]
  end

  subgraph Primitives["Primitives"]
    direction LR
    safety["safety.authorize<br/>emits audit"]
    chain["audit/chain.py<br/>JsonlAuditWriter,<br/>PostgresAuditWriter"]
    state["state, state_pg<br/>RunState"]
    schema["schema.AegisFinding"]
    scanners["scanners/<br/>Strix, Trivy, ..."]
    remediate["remediate/<br/>cai_runner, patch_workflow"]
  end

  cli --> create
  cli --> execute
  api --> create
  worker --> execute
  create --> safety
  execute --> safety
  safety --> chain
  create --> state
  execute --> state
  execute --> schema
  execute --> scanners
  execute --> remediate
```

The split is the v0.3.1 F6 contract: **API routes call admission
only**; **Celery tasks call execution only**. Admission is cheap and
request-scoped; execution is the long-running scanner / CAI work.

## Execution surface: scanners, capabilities, and agents

Aegis discovers two kinds of pluggable component at startup, both backed
by the same generic `aegis.registry.Registry[T]` (see
[ADR 0002](../adr/0002-registry-seam-and-runners.md) and
[Extending Aegis](../dev/extending.md)): **scanner adapters** wrap a
security tool and emit `AegisFinding`s; **agent adapters** wrap a CAI
agent. First-party adapters register eagerly at import; third-party
adapters register through the entry-point groups `aegis.scanners` /
`aegis.agents`, discovered only when `AEGIS_PLUGINS=1` (off by default,
so the offline test path stays deterministic).

### Scanner adapters (13)

Each adapter declares one or more **capabilities**; `dispatch` accepts
either an adapter name or a capability tag.

| Adapter | Capability | Wraps |
|---------|------------|-------|
| `strix` | `dast` | AI-driven pentester (the reference adapter) |
| `nuclei` | `dast` | Template-based vulnerability scanner |
| `zap` | `dast` | OWASP ZAP web-app scanner |
| `semgrep` | `sast` | Pattern-based static analysis |
| `codeql` | `sast` | Semantic code analysis (SARIF) |
| `bandit` | `sast` | Python security linter |
| `sonarqube` | `sast` | Code-quality + security analysis |
| `trivy` | `dependency` | Vulnerability + dependency scanner |
| `grype` | `dependency` | Dependency vulnerability scanner |
| `checkov` | `iac` | IaC misconfiguration scanner |
| `trufflehog` | `secret` | Secret scanner (raw material redacted) |
| `syft` | `sbom` | SBOM generator (CycloneDX; inventory, not findings) |
| `bumblebee` | `supply_chain` | Supply-chain / MCP-host exposure scanner |
| `deepsec` | `code_audit` | AI whole-repo code auditor (owner PII stripped) |

The reference `strix` adapter surfaces the vendored CLI's deeper code-scan
controls as optional `ScanOptions` fields: `targets` (a multi-target sweep
alongside the single `target`), `instruction_file` (read in lieu of an inline
`instruction`), and `scope_mode` (`auto | diff | full`) + `diff_base` for
PR-diff-scoped review. White-box source review needs no flag — strix derives
it from local-path targets. All are optional and soft-degrade; the
single-target default path is unchanged. These knobs live on `ScanOptions`
(programmatic / registry-dispatch callers); the HTTP `POST /v1/scans` body
forwards only `target` + `instruction`, as it does for `scan_mode`.

### Capabilities (8)

`KNOWN_CAPABILITIES` is an **open vocabulary** validated at
registration: `dast`, `sast`, `dependency`, `iac`, `secret`, `sbom`,
`supply_chain`, `code_audit`. A declared capability outside the set logs
a warning but still registers, so a third-party plugin can add its own
without patching core. Promoting one to first-party is a one-line append
— how `supply_chain` landed in v0.5.1 and `code_audit` in v0.7.0.

### CAI agents (16 wired + 3 multi-agent patterns)

Agent adapters wrap upstream `cai.agents.*` agents and dispatch by name.
Every registered agent is **wired** (executable, not a stub), spanning
all six `Domain` values:

| Domain | Agents |
|--------|--------|
| `offensive` | `bug_bounter`, `red_teamer`, `web_pentester`, `android_sast_agent`, `subghz_sdr_agent`, `wifi_security_tester`, `replay_attack_agent` |
| `forensic` | `dfir`, `memory_analysis`, `network_traffic_analyzer`, `reverse_engineering` |
| `audit` | `retester`, `reporter` |
| `defensive` | `blueteam_agent` |
| `remediation` | `codeagent` |
| `recon` | `recon` (read-only: nmap, shodan, curl, netcat, netstat) |

Beyond the 16 single agents, three **multi-agent patterns** join the
registry as explicitly-dispatchable entries — `offsec_pattern` (a parallel
offensive sweep) and the `redteam_swarm` / `bb_triage_swarm` handoff swarms
— for **19** dispatchable entries in all. A pattern runs **only when
dispatched by name**; a normal single-agent run never triggers one (no
auto-swarm). All three are `active`-effect, so they clear the same gate as
any offensive agent. When executed (post-approval), the active offensive
specialists (`bug_bounter`, `red_teamer`, `web_pentester`) reach the live
Kali tool belt over an SSE MCP connection to `config.mcp_kali_url`; the
read-only `recon` agent is excluded by design (the belt carries active
tools, and recon stays read-only).

### Kali toolbelt (10, via MCP)

Beyond the registered scanners, the worker reaches a Kali host over MCP
for classic offensive tooling: `nmap`, `sqlmap`, `nikto`, `hydra`,
`gobuster`, `dirb`, `john`, `wpscan`, `enum4linux`, `metasploit`. Every
invocation lands on the audit chain at the service boundary (see
[Audit chain](audit-chain.md)). Each tool carries an effect class (below):
the `read` recon tools run at `remediator`, while the `active` ones
(`sqlmap`, `hydra`, `metasploit`, `wpscan`) are gated behind
`execute=true` + `approver`. Counting both surfaces, Aegis ships
**24 tools today: 10 Kali + 14 scanner adapters**, on the way to the 35+
OnePager target.

Each wrapper sends the exact parameter keys the vendored mcp-kali server
reads (gobuster/dirb use `url`; hydra uses `username_file`/`password_file`;
metasploit folds `RHOSTS` into `options`) and exposes structured subcommand
controls — gobuster `mode` (`dir | dns | vhost | fuzz`), hydra user/password
values and list files, metasploit `module` + `options`, john `format`. Every
value still passes the allowlist `_check`, and no wrapper exposes a freeform
argument passthrough: the generic `command` surface stays closed (403, all
roles).

### Capability matrix

The three seams above each reach the runtime through a different dispatch
path. This matrix is the single view of *what exists*, *what consumes
it*, and *where the wiring is still thin* — the map a new capability
slots into without diverging from the architecture (most recently the
`code_audit` adapter `deepsec`, added through this seam in v0.7.0).

| Seam | Vocabulary | Registered | Runtime consumer | Dispatch |
|------|-----------|-----------|------------------|----------|
| Scanners | 8 capabilities | 14 adapters | `scan_start` Celery task | one adapter per job via `dispatch(name \| capability)`; defaults to `strix` |
| Agents | 6 `Domain`s | 19 adapters (16 agents + 3 patterns) | `agent_run` Celery task | `POST /v1/agents/{name}/run` → admission → task → `dispatch(name)`; remediation may still call `cai.Runner` directly for `codeagent` / `blueteam_agent` |
| Kali tools | 10 named tools | 10 (over MCP) | `run_kali_tool` service | per-tool REST call, audited at the service boundary |

One interconnection fact the matrix still makes explicit, tracked as a
gap rather than intent: scanners run **one adapter per job** (there is
no capability-sweep that fans a target across every adapter claiming a
capability). The former agent-registry gap is now **closed** — as of
v0.6.0 the registry has a runtime dispatch path: `POST
/v1/agents/{name}/run` admits the job (authorize → audit-before-enqueue
→ Run/Job rows → enqueue) and the `agent_run` Celery task re-authorizes
and calls `dispatch(name)`, so every registered adapter is reachable.

### The human-in-the-loop gate (effect classes)

Aegis's purpose is the full loop — **scan → pentest → remediate** — with
a human in the loop on anything that changes the world. Since v0.8.0 that
gate is **one** abstraction, the *effect class* (`aegis/effects.py`,
[ADR 0004](../adr/0004-unified-effect-class-gate.md)), applied at every
seam above rather than re-invented per adapter:

| Effect | Meaning | Gate |
|--------|---------|------|
| `read` | recon, enumeration, static analysis, SBOM, generating a diff/plan, dry-run | none beyond the target allowlist — runs freely |
| `active` | attack / state-changing against a live system: exploitation, brute-force, an exploit module, live hardening | gated |
| `external` | leaves the sandbox: pushing a branch, opening a PR, egress | gated |

The gate is one rule: an `active` / `external` capability performs its
irreversible step **only** when the caller explicitly opts in
(`execute=true` / `apply=true` / `open_pr=true`) **and** holds the
`approver` role; otherwise it returns a reviewable **proposal** (an attack
plan, a hardening plan, or a diff) and the underlying agent/tool is never
run. It is enforced at the **chokepoints** — `agents.registry.dispatch()`
(covers built-ins *and* plugins), the Kali tool route, and the fix
service — so a new adapter inherits the gate for free.

**Effect is not a function of domain.** An `android_sast_agent` is
offensive-by-domain but only reads bytecode → `read`; a `retester` is
audit-by-domain but re-fires exploits → `active`. So effect is an explicit
per-agent column in the wiring table, with `domain_default_effect()` as
the fallback; an unknown domain or unlisted Kali tool defaults to `active`
— it fails **safe** (gated), never open.

**Remediation engines, all behind the same gate:** `codeagent` produces
code-fix diffs (`patch`/`deps` strategies); `blueteam_agent` applies live
hardening (`live` strategy, gated on `apply`); the vendored
vulnerability-fixer drives the `agentic` strategy — propose → diff, then
`apply` for a rollback-safe local commit, then `apply + open_pr` to let the
engine open the **human-reviewed PR itself** (the PR review *is* the gate).

## Release map

```mermaid
flowchart TD
    subgraph v031["v0.3.1 — Stabilization"]
      f1["F1 detach CIGate"]
      f2["F2 lock files + markers"]
      f5["F5 cmd_migrate fix"]
      f9["F9 Finding PK UUID"]
      f7["F7 retire _append_audit"]
      f8["F8 retire tool-calls.jsonl"]
      f3["F3 CLI thru services"]
      f6["F6 admission + audit-before-enqueue"]
      f11["F11 worker persists status"]
      f4["F4 --api dispatch"]
      f12["F12 project-access on read"]
      f10["F10 cai_loader + llm.router"]
      fw["FW worker SA + rotation"]
      fp["FP membership endpoints"]
    end

    subgraph v040["v0.4.0 — Identity & UX"]
      f14a["F14a session cookie"]
      f14b["F14b CSRF + CORS"]
      f14c["F14c WS Origin + subproto"]
      f14d["F14d report CSP"]
      f13["F13 NextAuth"]
      f15["F15 vendor shadcn/ui"]
      f16["F16 design-system + Storybook"]
      f17["F17 pages rebuilt"]
      f18["F18 api() helper + useRoles"]
    end

    subgraph v041["v0.4.1 — Observability & GitHub"]
      f19["F19 vendor OTel contrib"]
      f20a["F20a obs profile"]
      f20c["F20c log-ingest"]
      f21["F21 structlog to OTel"]
      f22["F22 /v1/logs"]
      f23a["F23a PRScope"]
      f23b["F23b PR scans"]
      f23c["F23c fork restricted"]
    end

    subgraph v042["v0.4.2 — Agent + scanner breadth"]
      a1["7 agents wired (8 → 15)"]
      a2["8 scanner adapters: zap, codeql,<br/>bandit, grype, checkov,<br/>trufflehog, sonarqube, syft"]
      a3["sbom capability"]
    end

    subgraph v050["v0.5.0 — Registry seam hardening"]
      r1["generic Registry[T]"]
      r2["entry-point plugin discovery<br/>(AEGIS_PLUGINS=1)"]
      r3["KNOWN_CAPABILITIES open vocab"]
      r4["wired_in_phase_3 → wired"]
      r5["adapters/ → runners/"]
    end

    subgraph v051["v0.5.1 — Supply chain"]
      b1["bumblebee adapter (13th)"]
      b2["supply_chain capability"]
    end

    subgraph v052["v0.5.2 — Scanner bug fixes"]
      c1["bumblebee speaks real CLI/NDJSON"]
      c2["strix reads strix_runs/ events<br/>+ scan_mode"]
    end

    subgraph v060["v0.6.0 — Agent seam end-to-end"]
      d1["6 specialists un-fallbacked<br/>+ recon agent (16th)"]
      d2["POST /agents/{name}/run<br/>(admission-only)"]
      d3["agent_run task (execution-only)"]
      d4["Kali wrappers 3 → 10"]
    end

    subgraph v070["v0.7.0 — AI code audit"]
      e1["deepsec adapter (14th)"]
      e2["code_audit capability"]
      e3["owner PII stripped<br/>+ AI process opt-in"]
    end

    subgraph v080["v0.8.0 — Unified human gate"]
      g1["effect-class gate spine<br/>(read/active/external)"]
      g2["agent + Kali tool gate<br/>(execute=true + approver)"]
      g3["agentic remediation strategy<br/>(vuln-fixer opens the PR)"]
      g4["multi-format finding ingestion<br/>(Snyk/Veracode/Trivy/SARIF)"]
    end

    subgraph v090["v0.9.0 — Live belt + multi-agent"]
      h1["live Kali belt over MCP<br/>(active specialists)"]
      h2["3 multi-agent patterns<br/>(16 → 19, no auto-swarm)"]
    end

    subgraph v0100["v0.10.0 — Deeper scan surfaces"]
      i1["strix code-scope depth<br/>(multi-target / scope-mode / diff-base)"]
      i2["Kali wrappers speak real<br/>mcp-kali args (gobuster/hydra/msf)"]
    end

    v031 --> v040 --> v041 --> v042 --> v050 --> v051 --> v052 --> v060 --> v070 --> v080 --> v090 --> v0100
```

## What's deferred

The Phase-4 plan called out items intentionally pushed past v0.4.1.
Live-current list:

- Cross-org row-level multi-tenancy.
- Per-tenant cost dashboards / chargeback.
- Sandbox isolation per scan (gVisor / Firecracker).
- SOC 2 / ISO 27001 / FedRAMP evidence pack.
- PII / content scrubbing inside diffs and patches.
- LLM prompt-injection / output filtering.
- Iterative agent loops with test execution.
- Native MCP protocol.
- Authenticated DAST flows.
- Worker autoscaling / multi-region DR.

The CHANGELOG entry for each release also enumerates its deferred
items if they were called out at the time.
