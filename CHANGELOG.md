# Changelog

All notable changes to Aegis are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
SemVer.

## [Unreleased]

### Added
- **Frontend completion — UI for the previously-unexposed endpoints.** New and
  extended web surfaces close the gap to the backend:
  - **Run detail**: a **Cancel run** button (`POST /v1/runs/{id}/cancel`,
    `remediator`, confirm dialog), `report.json` / `report.md` download links,
    and a **Vulnfixer export** link (`GET /v1/runs/{id}/exports/vulnfixer`).
  - **`/targets`**: a **Delete target** action (`DELETE /v1/targets/{id}`,
    `admin`, confirm dialog).
  - **`/agents`**: invoke a wired agent with a prompt (`POST
    /v1/agents/{name}/run`) — `read` agents gated at `remediator`,
    active/offensive agents at `approver` with an explicit confirm.
  - **`/tools`**: run a Kali tool (`POST /v1/tools/kali/{tool}`) — `read` tools
    at `remediator`, active tools (`sqlmap`/`hydra`/`metasploit`/`wpscan`) at
    `approver` behind an **Execute** toggle + confirm.
  - **`/audit`**: an audit-chain visualization page rendering each chain as
    linked blocks with valid/broken status and per-event hashes.
- **UX polish.** A class-strategy **dark mode** with a header theme toggle
  persisted to `localStorage`, and a **Cmd/Ctrl-K command palette** for quick
  navigation.
- **`@aegis/design-system` Radix / `cmdk` primitives.** `AlertDialog`,
  `Tooltip`, and `Command` ship (backing the confirm dialogs, tooltips, and the
  command palette). `@radix-ui/react-alert-dialog`, `@radix-ui/react-dialog`,
  `@radix-ui/react-tooltip`, and `cmdk` are added to `web/pnpm-lock.yaml`,
  lifting the offline-build lockfile gate.

### Security
- **DB-side append-only audit log (migration `0004`).** `audit_events` is now
  insert-only *at the database*: a row-immutability trigger `RAISE EXCEPTION`s
  on `UPDATE`/`DELETE`/`TRUNCATE` for everyone — table owner and superuser
  included — so a privileged operator can no longer rewrite rows and re-sign a
  chain end to end (the gap `verify_chain` could detect but not prevent).
  `audit_chain_heads` stays mutable so appends still update the head pointer.
- **Least-privilege role separation (guarded).** The migration grants the
  runtime `aegis_app` role only `INSERT, SELECT` on `audit_events` (full DML
  elsewhere) and reserves DDL for `aegis_owner`; Alembic connects via the new
  optional `AEGIS_DB_OWNER_URL`. The role/grant steps no-op when the roles are
  absent, so CI and single-role dev are unaffected.
- **pgaudit logging (guarded).** Out-of-band logging of DDL + role/GRANT
  changes records any attempt to disable the controls above; `CREATE EXTENSION`
  and `pgaudit.log` are guarded on availability and skip cleanly where the
  extension isn't loaded. New `deploy/Dockerfile.postgres` ships a
  pgaudit-enabled Postgres for the compose stack.

## [0.12.0] — 2026-06-08 — finish the seams: multi-scanner dispatch, budget caps, API sunsets

Post-0.11.0 hardening, the **"finish the seams"** milestone, and tooling
work. Completes scaffolded-but-unfinished seams (multi-scanner dispatch,
the job reaper, budget enforcement) and removes two long-deprecated API
surfaces; the offline `pytest` path and `mkdocs --strict` build stay green.

### Fixed
- **Unit CI matrix unblocked.** `aegis.state` no longer eagerly imports
  the Postgres backend (PEP 562 lazy `PostgresRunState`), so
  `from aegis.state import RunState` — the filesystem default — works
  without the `api`/`worker` extras installed.
- **Postgres / worker correctness.** `append_remediation_log` resolves a
  scanner finding id to the internal row UUID before the FK insert
  (previously raised `IntegrityError`); `task_context` skips cancelled or
  redelivered jobs (an at-least-once guard under `task_acks_late`) so a
  revoked or crashed task never re-executes; `override_authorized` now
  threads from admission into the worker re-authorization on the agent
  and scan paths.
- **`record_artifact` is idempotent on the Postgres backend** — re-recording
  identical content (same `run_id`/`kind`/`sha256`) returns the existing
  ref instead of raising `IntegrityError` on the unique constraint.
- **Single-file audit mode filters by `chain_id`** — `_last`/`read_chain`
  no longer mix interleaved chains in one `audit.jsonl`, so per-chain
  `seq`/`prev_hash` continuity holds.

### Security
- **OTel security pipeline** gains a `transform/redact_body` processor so
  secrets in the raw host-log *body* (`filelog`/`journald`/`syslog`) are
  scrubbed — the `redaction` processor only masked attribute values —
  before export to Loki and the Postgres mirror.
- **Rate limiting**: the per-project token bucket is keyed by principal so
  a client-supplied `?project` can't drain another tenant's bucket;
  log-ingest endpoints require a valid worker token when a signing key is
  configured.
- **deepsec** persists a PII-sanitized export artifact instead of the raw
  CLI stdout (owner identities never reach disk).

### Changed
- Run-state and blob-storage internals refactored into the
  `aegis/state/` and `aegis/storage/` packages (public
  `from aegis.state import …` / `from aegis.storage import …` imports
  unchanged); the CLI was split into per-subcommand modules and the audit
  writers consolidated.
- **Per-adapter `default_timeout` now applies.** `run_cli_scan` falls back
  to the adapter's declared `default_timeout` (e.g. codeql 3600s, semgrep
  600s) when the caller didn't override it, instead of the flat 1800s.
- **Opening a fix PR requires the `approver` role.** `POST
  /v1/findings/{id}/fix` with `open_pr=true` is now gated like `apply`
  (was `remediator`).

### Added
- A web unit suite (`vitest`) for `@aegis/web`, plus CI gates that
  validate the OTel collector config and enforce a blocking
  `@aegis/design-system` typecheck.
- **Multi-scanner dispatch (M6).** The synchronous scan service, the API,
  and the CLI route all 14 registered scanner adapters through the
  registry (`dispatch`), not just Strix; `POST /v1/scans` rejects an
  unknown `scanner` with HTTP 400 and the CLI gains `--scanner`.
- **`override_authorized` on the async fix API.** `FixBody` carries the
  flag through `create_fix_job` → worker → `generate_fix`, so an
  off-allowlist target authorized at admission stays authorized.
- **Stale-job reaper.** A Celery-beat task (`aegis.reap_stale_jobs`, every
  5 min) marks jobs stuck `running` past `job_max_runtime_seconds`
  (default 3600s) as `failed` — the complement to the redelivery guard.
- **LLM budget enforcement.** A `DbBudgetChecker` reads
  `Project.daily_llm_budget_cents`, subtracts the day's `llm_usage`, and
  `route()` blocks when exhausted; the fix path records usage rows with
  per-call cost from a researched per-model price table
  (`aegis/llm/pricing.py`), with litellm's price map as a fallback.

### Removed
- **`GET /v1/findings/by-scanner-id`** (deprecated since v0.3.1) — use
  `GET /v1/findings?run=<run>` or `GET /v1/findings/{uuid}`.
- **WebSocket `?token=<token>` query-param auth** — use the
  `aegis.bearer.<token>` subprotocol, the `Authorization` header, or the
  session cookie.

## [0.11.0] — security telemetry pipeline + design-system base primitives

Two additive, file-disjoint surfaces land here — observability infra and the
frontend component layer — neither of which touches the Python core or the
offline test path. The collector gains a dedicated security-log pipeline that
scrubs secrets before anything leaves the host, and `@aegis/design-system`
gains its first batch of base UI primitives ported from the vendored shadcn
registry. Python suite unchanged at 1253 passing, 18 skipped.

### Added
- **OTel security log pipeline** (`deploy/otel/config.yaml`). A new
  `logs/security` pipeline ingests host/OS audit sources — `filelog`
  (`/var/log/auth.log`, `/var/log/secure`), `journald` (sshd/sudo/kernel),
  rfc5424 `syslog` over tcp, and the `k8sobjects` events receiver — runs them
  through the `redaction` processor (token/password/apikey/bearer-style values
  masked **before** batch or export) and a `filter` denoise stage, then fans
  the result out to the existing Postgres mirror (`otlphttp/aegis-ingest`) and
  Loki. Redaction always precedes export, so secrets never leave the collector.
- **`@aegis/design-system` base primitives** (`project_repos/design-system/`).
  A new `src/primitives/` directory holds six base components ported from the
  vendored shadcn `new-york-v4` registry — `table`, `card`, `skeleton`,
  `alert`, `input`, `textarea` — each with a Storybook story and a barrel
  export. They populate the package's pre-declared `./primitives/*` export
  subpath, layering shadcn base components under the existing Aegis-curated
  domain components.

### Changed
- The collector header comment documents the security pipeline; the three
  pre-existing pipelines (`logs/loki`, `logs/aegis-ingest`, `traces`) are
  byte-for-byte unchanged.

### Deferred
- **`osquery` and `isolationforest`** are referenced only in a commented,
  forward-looking block in the collector config. Neither is a standard
  opentelemetry-collector-contrib component, so an active reference would fail
  collector startup; they require a custom/community distro to activate.
- **The Radix-based shadcn primitives** (`alert-dialog`, `tooltip`, `command`)
  were **not** ported: they depend on the `radix-ui` / `cmdk` packages, which
  are not installed and cannot be added in the offline build. Porting them is a
  follow-up gated on adding those dependencies.

### Migration
- **No runtime or API change.** The security pipeline is deploy-only config; an
  operator opts in by deploying the obs profile. The design-system primitives
  are a frontend package addition with no Python or HTTP-surface impact. The
  offline `pytest` path and `mkdocs --strict` build are unaffected.

## [0.10.0] — deeper scan surfaces: strix code-scope + real Kali tool args

This release deepens two existing subprocess surfaces without changing any
default behaviour. The strix adapter gains the vendored CLI's richer
code-scan controls, and the Kali tool wrappers are corrected to speak the
parameter shape the vendored mcp-kali server actually reads — several deep
scans were silently no-op'ing on mismatched keys. Both are additive and
soft-degrade; the single-target / default-arg paths are byte-identical to
0.9.0. 1253 passing, 18 skipped.

### Added
- **Strix code-scope depth** (`aegis/runners/strix_runner.py`,
  `aegis/scanners/strix_adapter.py`, `aegis/scanners/registry.py`). Four new
  optional `ScanOptions` fields surface strix's deeper controls: `targets`
  (a multi-target sweep that augments the single `target`), `instruction_file`
  (a path read in lieu of an inline `instruction` — the two are mutually
  exclusive, file wins), and `scope_mode` (`auto | diff | full`) + `diff_base`
  for PR-diff-scoped code review. White-box source review needs no flag —
  strix auto-derives it from local-path targets. A `strix_scope_mode` config
  default mirrors the `ScanOptions` default, matching how `strix_scan_mode`
  was introduced in 0.5.2. An out-of-range `scope_mode` falls back to `auto`.
- **Real mcp-kali tool arguments** (`aegis/tools/cai_tools.py`). The
  `gobuster` / `dirb` / `hydra` / `metasploit` / `john` wrappers now send the
  exact parameter keys the vendored server reads, and expose structured
  subcommand controls: gobuster `mode` (`dir | dns | vhost | fuzz`), hydra
  user / password values and list files, metasploit `module` + `options`
  (with `RHOSTS` folded in), and john `format`.

### Fixed
- **Kali deep-scan wrappers were sending keys the server ignored.** gobuster
  and dirb sent `target` where mcp-kali reads `url`; hydra sent `userlist` /
  `passlist` instead of `username_file` / `password_file`; metasploit put
  `rhosts` at the top level instead of inside `options.RHOSTS`. Those scans
  reached the server but ran with empty arguments. The wrappers now match the
  server's request schema, and every value still passes through the
  allowlist `_check`. **No** freeform `additional_args` passthrough was added
  — the generic-command surface stays closed (`command` → 403, all roles).

### Migration
- **No behaviour change on the default path.** Every new strix field is
  optional and defaults to today's behaviour; a scan that sets none of them
  builds the identical command line as 0.9.0. The new strix knobs are
  `ScanOptions`-level (programmatic / registry-dispatch callers); the HTTP
  `POST /v1/scans` body is unchanged and still forwards only `target` +
  `instruction`, exactly as it did for `scan_mode`.
- **Kali callers that relied on the old (ignored) keys** were already
  no-op'ing those arguments; after this fix the same calls run with the
  arguments actually applied. Review any saved gobuster/dirb/hydra/metasploit
  invocations against the corrected parameter names above.

## [0.9.0] — live Kali tool belt over MCP + CAI multi-agent patterns

Building on the unified gate from 0.8.0, this release lets the wired offensive
specialists reach the **live Kali tool belt at run time** over an MCP connection,
and exposes CAI's **multi-agent patterns** as ordinary, explicitly-dispatchable
registry entries. Both are bound by the same effect-class gate — every pattern is
`active`, so nothing fires without `execute=true` and the `approver` role — and
nothing auto-swarms: a pattern runs only when a caller dispatches it by name.
1233 passing, 18 skipped.

### Added
- **CAI multi-agent patterns** (`aegis/agents/cai/patterns.py`). Three composite
  entries join the agent registry: `offsec_pattern` (a parallel offensive sweep)
  and the `redteam_swarm` / `bb_triage_swarm` handoff swarms. Each resolves and
  runs its CAI agent(s) through `Runner.run_sync` — a swarm via its entry agent;
  a parallel pattern by resolving each configured agent by name and concatenating
  their outputs. All three are `active`-effect and flow through the same
  `dispatch()` gate: without `execute=true` they return a `pending_approval`
  proposal and **no** agent runs. The registry roster grows 16 → **19**.
- **Live Kali tool belt over MCP** (`aegis/integrations/cai_loader.py`). When CAI
  is available, `load_cai` attaches an SSE MCP server (`MCPServerSse` pointed at
  `config.mcp_kali_url`) to the active offensive specialists — `bug_bounter`,
  `red_teamer`, `web_pentester` — so they can call the live nmap/sqlmap/hydra/…
  belt when executed (post-approval). The read-only `recon` agent is **deliberately
  excluded**: the belt carries active tools and recon stays read-only. `CAIBundle`
  gains `kali_mcp_attached` (count of specialists wired; `0` offline).
- **Loader resolvers** `load_cai_pattern()` / `resolve_cai_agent()` funnel the
  `cai.agents.patterns.get_pattern` / `cai.agents.get_agent_by_name` lookups
  through the one CAI loader, so the rest of the codebase never imports CAI directly.

### Changed
- `load_cai` now attaches the Kali MCP belt to the active specialists at
  bundle-build time. **No-op offline** — CAI isn't importable, so `load_cai`
  returns `None` long before the attach, and the attach itself degrades to zero
  when the MCP endpoint is unset, the client classes can't be imported, or the
  server object can't be built.

### Migration
- **Patterns are gated exactly like offensive agents.** `dispatch("redteam_swarm",
  …)` (or `offsec_pattern` / `bb_triage_swarm`) without `execute=true` returns a
  `pending_approval` plan; flip `execute=true` (requires the `approver` role) to
  actually run the pattern. Nothing auto-swarms from a normal single-agent run.
- **The MCP attach is a live-runtime feature only.** It connects nothing offline
  and never runs in the test path; the server object is attached but not connected
  until a live agent run wires it up. Existing offline callers see no change.

## [0.8.0] — unified human-in-the-loop gate + agentic remediation + finding ingestion

Aegis's purpose is the full loop — **scan code + infra → pentest → remediate** —
with a human in the loop on anything that changes the world. Before this release
that gate existed only for *code fixes*. This release introduces one abstraction
— the **effect class** — and gates on it everywhere: offensive agents, defensive
agents, active Kali tools, and the new agentic remediation strategy all now go
through the same propose→approve→act path. The remediation loop is completed
here: the vendored vulnerability-fixer becomes a first-class **gated** strategy
that can open its own human-reviewed pull request. See
[ADR 0004](docs/adr/0004-unified-effect-class-gate.md). 1211 passing, 18 skipped.

### Added
- **Effect-class gate spine** (`aegis/effects.py`, dependency-free). Classifies
  every capability as `read` (recon/enumeration/static analysis/diff/plan/dry-run
  — runs freely, allowlist is the only gate), `active` (attack or state-changing
  against a live system — gated), or `external` (leaves the sandbox: push/PR/egress
  — gated). `requires_approval(effect)` is the single testable answer to "is this
  gated?". `domain_default_effect()` and `kali_tool_effect()` both fail **safe** —
  an unknown domain or unlisted tool defaults to `active` (gated, never open).
  `build_action_plan()` produces the reviewable proposal returned in lieu of acting.
- **Agent execution gate.** `agents.registry.dispatch()` — the single path
  covering built-ins *and* plugins — now enforces the gate. An `active` agent
  dispatched without `context.execute` returns
  `AgentResult(status="pending_approval", plan=…)` and the underlying agent is
  **never** invoked. New `Action.AGENT_EXECUTE` sits at the `approver` role
  (mirroring `FIX_APPLY`); `AGENT_RUN` stays `remediator`. The route selects the
  action by the `execute` flag; the worker re-authorizes
  `agent.execute.{name}` vs `agent.run.{name}` accordingly.
- **Kali tool gate.** `aegis/api/v1/tools.py` classifies each tool via
  `kali_tool_effect()`. `active` tools (`sqlmap`/`hydra`/`metasploit`/`wpscan`)
  without `execute=true` return `pending_approval`; with it they require the
  `approver` role. `read` tools (`nmap`/`nikto`/`gobuster`/…) keep
  `tool.invoke` at `remediator`. The generic `command` shell stays hard-blocked
  (403) for every role.
- **Agentic remediation strategy** (`aegis/runners/vulnfixer_runner.py`,
  `Strategy="agentic"`). Drives the vendored vulnerability-fixer engine:
  propose → unified diff (`pending_apply`); `apply` → local rollback-safe commit;
  `apply + open_pr` → **the engine opens the human-reviewed PR itself** (the PR
  review *is* the gate). In PR mode the GitHub token flows only through the
  subprocess *environment*, never argv.
- **Live-hardening gate.** The `live` fix strategy now gates on `apply`: a propose
  call returns a hardening **plan** (`pending_approval`) and never invokes the
  blue-team agent; `apply=True` runs the hardening.
- **Multi-format finding ingestion** (`aegis/integrations/finding_ingest.py`).
  Normalizes Snyk / Veracode / Trivy / SARIF reports into `AegisFinding`s.
  Pure-Python, fixture-driven, fully offline.

### Changed
- `Strategy` literal in `aegis/services/fixes.py` extended with `agentic`.
- `AgentContext` gains an `execute` flag (default `False`); `AgentResult` gains a
  `plan` field carrying the proposal when a gated capability is not executed.
- `list_agents()` now surfaces each agent's effect class; `builtins._WIRED` carries
  an explicit per-agent effect column (effect is **not** a function of domain).

### Migration
- **Active agents and tools now need `execute=true` *and* the `approver` role to
  run.** Callers that previously got an immediate exploit/hardening run now get a
  `pending_approval` proposal instead — this is the intended behavior change. Flip
  `execute=true` (agents/tools) or `apply=true` (fixes) to act.
- **Agentic PR mode depends on `GITHUB_TOKEN` in the worker environment.** Absent
  it, the agentic engine soft-degrades to a failed outcome rather than opening a
  PR; `apply` without `open_pr` still produces a local rollback-safe commit.

## [0.7.0] — deepsec AI code-audit scanner (new `code_audit` capability)

Adds [deepsec](https://github.com/vercel-labs/deepsec) (Apache-2.0, pinned at
`9e3832d`) as the 14th scanner adapter and Aegis's 8th scanner capability,
`code_audit` — whole-repo AI SAST. Dropped through the same hardened registry
seam as every other adapter: the offline `pytest -q` path stays green with no
Node/pnpm and no deepsec checkout (the adapter soft-degrades via `health_check`).
1145 passing, 18 skipped.

### Added
- **deepsec scanner adapter** (`aegis/scanners/deepsec_adapter.py`, capability
  `code_audit`). Drives deepsec's three-stage pipeline as subprocesses — `scan`
  (regex candidate discovery) → `process` (AI investigation) → `export --format
  json` (a bare JSON array of findings on stdout) — and converts each
  `ExportedFinding` to an `AegisFinding`. Severity maps
  `CRITICAL/HIGH/HIGH_BUG/MEDIUM/BUG/LOW` → Aegis severities (`HIGH_BUG`→`high`,
  `BUG`→`low`, unknown→`low`); `metadata.filePath`/`lineNumbers` become a
  `CodeLocation`; `vulnSlug` and `confidence` carry through. Findings whose
  `revalidation.verdict` is `false-positive`, `fixed`, or `duplicate` are dropped.
- **`code_audit` capability** added to `KNOWN_CAPABILITIES`; the adapter
  eager-registers in `aegis.scanners` alongside the other 13. Roster: 14 scanner
  adapters covering 8 capabilities.
- **Config knobs** (`aegis/config.py`): `deepsec_path`, `deepsec_ai_process`
  (default `False`), `deepsec_budget_usd` (default `5.0`).

### Security
- **Owner identities are never emitted.** deepsec enriches each finding with
  code-owner PII — `metadata.owners` (on-call/manager/contributor names, emails,
  GitHub handles, Slack ids), a top-level `assignee` email, owning-team `labels`,
  a `githubUrl`, and a pre-built `description` that embeds those same names and
  emails as markdown. The adapter copies **none** of them: it synthesizes its own
  PII-free description from the technical fields only (file, line, slug) and drops
  `owners`/`assignee`/`labels`/`githubUrl`/deepsec's `description` entirely.
  `evidence` is always `None`. A fixture seeded with owner PII asserts that no
  value survives into any serialized finding. (Mirrors the bumblebee/trufflehog
  redaction guarantee.)
- **The paid AI stage is opt-in.** `process` runs only when
  `deepsec_ai_process=True` **and** `deepsec_budget_usd > 0` **and** an AI Gateway
  / model key is present in the environment. Otherwise the adapter runs `scan` +
  `export` only (regex candidates) and never spends money.

### Migration
- deepsec is a Node/pnpm monorepo vendored as a git submodule at
  `project_repos/deepsec`. To run the adapter the submodule must be checked out
  and built (`pnpm install` in the deepsec workspace) with `pnpm` on `PATH`. With
  neither present, `health_check()` returns `False` and the adapter is skipped —
  the offline test path requires nothing. The docker-images build is the only
  place the Node/pnpm toolchain (and any AI-stage cost) is introduced.

## [0.6.0] — Wire the agent seam end-to-end + a read-only recon agent

The agent registry was wired but **orphaned**: `dispatch` existed and 15
adapters were registered, yet no running code reached them. This release gives
the registry a runtime path, un-fallbacks six specialist agents, composes a
read-only recon agent (16th), and widens the agent-facing Kali toolbelt from 3
to 10. Admission-layer + wiring only — the offline `pytest -q` path stays green
with no Postgres/Redis/Keycloak and no scanner binaries (1115 passing, 18
skipped).

### Added
- **Agent execution path** (F6 admission/execution split, mirroring the scan
  path). `POST /v1/agents/{agent_name}/run` does admission only — RBAC
  (`agent.run`, `remediator+`) → `create_agent_job(...)` emits a chained
  `agent.run` audit row **before** the Run/Job rows and **before** Celery is
  touched, then enqueues. The new `agent_run` Celery task does execution only:
  re-authorize `agent.execute.{name}` against the worker-side allowlist, then
  `dispatch(name, prompt, AgentContext(...))`. No business logic in the route;
  no admission in the task. (`aegis/api/v1/agents.py`,
  `aegis/services/agents.py`, `aegis/workers/tasks/agent.py`,
  `Action.AGENT_RUN` in `aegis/api/policy.py`.) See [ADR
  0003](docs/adr/0003-agent-execution-path.md).
- **Read-only recon agent (16th)** composed from CAI reconnaissance tools
  (`nmap`, `shodan_search`, `shodan_host_info`, `curl`, `netcat`, `netstat`)
  and registered in the `recon` domain — the domain was previously empty. The
  agent gets observation tools only; never `generic_linux_command` / `exec_code`.
- **Agent-facing Kali toolbelt 3 → 10.** Thin typed `@function_tool` wrappers
  for `gobuster`, `dirb`, `hydra`, `wpscan`, `enum4linux`, `metasploit`, and
  `john`, each routed through `KaliClient` with the same allowlist enforcement
  at the service boundary. No generic-command surface was added.

### Fixed
- **Six specialist slots no longer resolve to fallbacks.** The CAI loader now
  imports `bug_bounter_agent`, `redteam_agent`, `dfir_agent`, `retester_agent`,
  `reporting_agent`, and `web_pentester_agent` (degrading the whole group to
  `None` offline), and `_WIRED` maps each slot to its real CAI agent instead of
  a generic stand-in.

### Security
- The recon agent and the new Kali wrappers add **no** arbitrary-command
  surface: `KaliClient.execute_command` stays gated by `allow_generic_command`
  (default `False`), and target-bearing tools remain allowlist-checked.
- The worker re-authorizes every agent run (`agent.execute.{name}`) rather than
  trusting the admission-time allowlist decision, so allowlist drift surfaces
  before the agent executes.

## [0.5.2] — Fix the bumblebee and strix scanner adapters

Two shipped scanner adapters spoke interfaces their tools never exposed; both
are corrected against the vendored source. Execution-layer only — the offline
`pytest -q` path stays green with no scanner binaries (1091 passing, 18 skipped).

### Fixed
- **bumblebee adapter** now invokes the real CLI (`bumblebee scan --root
  <target> --exposure-catalog <dir> --findings-only --output stdout`) and
  parses the real NDJSON schema: records are discriminated by `record_type`
  (was a non-existent `type` field), and `finding` records map their real
  fields (`record_id`, `catalog_id`/`catalog_name`, `severity`, `package_name`,
  `version`, `confidence`). The previous invented `--target`/`--format ndjson`
  flags and `type` filter produced zero findings on real output. The exposure
  catalog defaults to the vendored `threat_intel/*.json`.
- **strix runner** drops the non-existent `--output-dir` flag, runs strix with
  `cwd` set to the per-run directory, and discovers strix's real event stream
  at `strix_runs/*/events.jsonl` (newest by mtime) instead of a fixed path
  strix never wrote.

### Added
- `ScanOptions.scan_mode` (+ `AegisConfig.strix_scan_mode`, default
  `"standard"`) threads strix's `-m/--scan-mode` (quick|standard|deep), so scans
  are no longer hard-pinned to strix's `deep` default.

### Security
- The rewritten bumblebee adapter keeps the credential-never-leaked guarantee:
  only known-safe fields are surfaced and `evidence` stays `None`. The fixture
  uses placeholder catalog ids and no secret-like strings.

## [0.5.1] — Bumblebee supply-chain scanner via the hardened seam

The first tool added through the v0.5.0 registry seam. Adding the
`supply_chain` capability was a one-line `KNOWN_CAPABILITIES` append — the
proof the open vocabulary works without patching core. Execution-layer +
packaging only; the offline `pytest -q` path stays green with no
Postgres/Redis/Keycloak and no scanner binaries.

### Added
- `BumblebeeAdapter` (`aegis/scanners/bumblebee_adapter.py`) — wraps the
  bumblebee CLI's NDJSON output (`package` / `finding` / `scan_summary`
  records) and emits `AegisFinding`s with `finding_type="supply_chain"`.
  Findings carry severity directly, so there is no synthetic-severity
  workaround.
- New `supply_chain` capability in `KNOWN_CAPABILITIES` (a one-line append),
  covered by the bumblebee adapter — the scanner roster is now 13.
- Vendored `perplexityai/bumblebee` as a pinned submodule (Apache-2.0, tag
  v0.1.1) under `project_repos/bumblebee`, recorded in `AEGIS_VENDORED.md`
  and the ADR 0001 bumps log; `bumblebee_path` added to `AegisConfig`.
- `tests/test_bumblebee_adapter.py` + an NDJSON fixture: severity mapping,
  required-field conversion, and a credential-never-leaked guard, all
  offline.

### Security
- bumblebee parses MCP-host configs that may contain credentials; the
  adapter never copies a credential value into a finding (`evidence` is left
  unset), mirroring the trufflehog redaction guarantee. A test asserts no
  sentinel credential reaches the serialized finding.

### Migration
- The scanner needs `bumblebee` on `PATH` (a Go 1.25+ static binary) or a
  build from the vendored source; when absent, `health_check()` returns
  False and the adapter soft-degrades. The Go build dependency touches only
  the `docker-images` image (a multi-stage `golang` builder stage) — never
  the offline test path.

## [0.5.0] — Harden the registry seam

Architecture hardening so new capability arrives through an extension seam
instead of by hand-editing core. Execution-layer + packaging only — no API
write route, Celery enqueue, or audit-chain change. Offline `pytest -q`
stays green with no Postgres/Redis/Keycloak and no scanner binaries.

### Added
- Generic `aegis.registry.Registry[T]` shared by the scanner and agent
  registries (`register` / `get` / `list_names` + a gated
  `maybe_load_entry_points`), collapsing two near-identical registries onto
  one seam.
- Live third-party plugin discovery: `aegis/scanners/__init__.py` and
  `aegis/agents/__init__.py` now call `maybe_load_entry_points()` after the
  built-ins, discovering entry points in groups `aegis.scanners` /
  `aegis.agents`. Gated by `AEGIS_PLUGINS=1` (default off) so it never
  touches the offline path — the previously-dormant hook is now wired.
- `KNOWN_CAPABILITIES` open capability vocabulary in
  `aegis/scanners/registry.py`: adding a capability is a one-line append;
  an unknown declared capability logs a warning but still registers, so a
  plugin can introduce its own without patching core.
- `tests/test_plugin_discovery.py` — gated entry-point discovery for both
  registries (on registers; off is a strict no-op; unknown-capability
  warns-but-registers), fully offline.

### Changed
- Retired the stale `wired_in_phase_3` phase flag → `wired` on the agent
  adapter Protocol, the `list_agents()` output key, and the `AgentResult`
  status string `"not_wired_in_phase_3"` → `"not_wired"`.
- Renamed package `aegis/adapters/` → `aegis/runners/` and the finding
  converter `strix_adapter.py` → `strix_converter.py`, clarifying the
  subprocess-runner / finding-converter / exporter layer and killing the
  name collision with the registered `aegis/scanners/strix_adapter.py`.
- `Capability` is no longer a closed `Literal`; capabilities are plain
  `str` validated against `KNOWN_CAPABILITIES` at registration.

### Migration
- Downstream importers of `aegis.adapters.*` must switch to
  `aegis.runners.*`; the Strix finding converter moved from
  `aegis.adapters.strix_adapter` to `aegis.runners.strix_converter`. The
  registered scanner adapter `aegis.scanners.strix_adapter` is unchanged.
- Third-party scanners/agents may now register via entry-point groups
  `aegis.scanners` / `aegis.agents` (opt-in with `AEGIS_PLUGINS=1`); see
  the "Extending Aegis" docs.
- Public import paths from `aegis.scanners`, `aegis.scanners.registry`,
  `aegis.agents`, and `aegis.agents.registry` are otherwise unchanged.

## [0.4.2] — OnePager gap: forensic/wireless agents + scanner breadth

Narrows the gap between shipped capability and the OnePager promise on two
axes: the seven registered-but-unwired CAI agents (forensics + mobile +
wireless + RF) now dispatch to their real upstream agents, and eight new
scanner adapters land. v0.4.1 and earlier untouched — this is
execution-layer breadth only, with no API write route, Celery enqueue, or
audit-chain change.

### Added
- Seven newly-wired CAI agents in `aegis/agents/cai/builtins.py`, each
  dispatching through `Runner.run_sync` to its upstream `cai.agents.*`
  agent: `memory_analysis`, `network_traffic_analyzer`,
  `reverse_engineering` (forensic) and `android_sast_agent`,
  `subghz_sdr_agent`, `wifi_security_tester`, `replay_attack_agent`
  (offensive). The registry now reports **15 wired** agents, up from 8.
- Eight scanner adapters under `aegis/scanners/`, each following the
  self-contained subprocess + JSON-parse shape (`_convert` →
  `AegisFinding`; graceful `exit_code=-1` on missing binary / timeout /
  decode error; raw output persisted under `run_path/<tool>/`):
  - `zap_adapter.py` (`dast`) — OWASP ZAP JSON report.
  - `codeql_adapter.py` (`sast`) — `codeql database analyze` SARIF.
  - `bandit_adapter.py` (`sast`) — `bandit -r -f json`.
  - `grype_adapter.py` (`dependency`) — `grype -o json`.
  - `checkov_adapter.py` (`iac`) — `checkov -o json`.
  - `trufflehog_adapter.py` (`secret`) — `trufflehog … --json` (JSONL);
    raw secret material is redacted, never persisted.
  - `sonarqube_adapter.py` (`sast`) — `sonar-scanner` +
    `GET /api/issues/search`; an unconfigured server degrades to an
    empty, flagged `ScanResult` rather than raising.
  - `syft_adapter.py` (`sbom`) — `syft -o cyclonedx-json`; persists a
    CycloneDX SBOM to `run_path/syft/sbom.cyclonedx.json` and returns
    `findings=[]` (inventory, not findings).
- New `sbom` capability so Syft's inventory output is a first-class tool
  without faking findings.
- Tests (offline by construction — CAI bundle mocked, scanners parse
  static fixtures, `health_check` exercised with the binary absent):
  - `tests/test_agent_registry.py` — 5 cases (15 registered; the 7 new
    agents dispatch ok; `_NOT_WIRED` empty; `cai_attr`↔`CAIBundle` field
    parity; resilient-import degradation to `status="error"`).
  - `tests/test_{zap,codeql,bandit,grype,checkov,trufflehog,sonarqube,syft}_adapter.py`
    — one per adapter against a minimal real-shape fixture.
  - `tests/test_scanners.py` — registry roster (all 12), capability
    coverage, graceful `health_check`, dispatch-by-capability.

### Changed
- `aegis/integrations/cai_loader.py`: `CAIBundle` gains the seven
  upstream agent fields; `load_cai` imports them in a separate
  `try/except ImportError` so an upstream rename of a new agent cannot
  regress the already-wired codeagent/blueteam path.
- `aegis/scanners/registry.py`: the `Capability` Literal gains `"sbom"`.
- `aegis/scanners/__init__.py`: eager-imports the eight new adapters so
  they self-register on package import.
- `tests/test_scanner_registry.py`: agent-registry assertions now
  reflect that the forensic trio is wired; the `not_wired_in_phase_3`
  path is retired (`_NOT_WIRED` is empty).
- `docs/architecture/overview.md`: the "Additional scanners (ZAP …)"
  deferred bullet is removed (now shipped); `docs/api/v1.md` lists the
  full scanner enum.

### Migration notes
- None — additive. The new scanners need their CLIs on `PATH`
  (SonarQube additionally needs a server via `SONAR_HOST_URL` + token in
  `options.extra` or env); when absent each degrades through
  `health_check` / guarded `scan` rather than raising. The offline
  `pytest -q` path requires none of them.

### Verification
- `pytest -q` — 287 passed, 3 skipped on Python 3.12 (no Postgres /
  Redis / Keycloak, no scanner binaries).
- `python -c "import aegis.scanners as s; print(sorted(s.list_scanners()))"`
  → the 12 adapters; wired-agent count → 15.
- `mkdocs build --strict` clean (the README feeds the docs index).

## [0.4.1] — Phase 4 Observability & GitHub completion

Centralised logs queryable in Loki / Elasticsearch and in-app via a
Postgres mirror; GitHub PR-scoped scans with structured scope and
fork-restricted mode. v0.3.1 + v0.4.0 untouched; v0.4.1 layers
observability + integrations on top.

### Added
- `aegis/log_ingest/` — in-tree FastAPI service that mirrors the OTel
  log stream into Postgres. Two ingress paths converge on the same
  batched writer: ``POST /ingest`` (native JSON, used by api/worker
  when no Collector is up) and ``POST /v1/logs`` (OTLP/Logs over
  HTTP-JSON, what the Collector's ``otlphttp/aegis-ingest`` exporter
  posts). ``/health`` + ``/metrics`` for lag visibility. Severity
  numbers map to text via the OTLP severity table (F20c).
- `application_logs` table + indexes via Alembic
  ``0003_application_logs``. Columns: ts/severity/service/message +
  run_id/job_id/project_id/actor/request_id/trace_id/span_id +
  freeform JSONB attrs. Index set: per-run+ts DESC, per-project+ts
  DESC, request_id, trace_id, severity+ts DESC, service, ts (F20c).
- `aegis/api/v1/logs.py` — `GET /v1/logs` admin endpoint with
  run/project/service/severity/request_id/since filters and id-cursor
  pagination. Every query lands a ``logs.queried`` chained audit
  event so a forensic review can trace who looked at what (F22).
- `aegis/integrations/github_handlers.py`: `PRScope`, `RestrictedMode`,
  `pr_scope_from_payload`, `restricted_mode_for`, `scope_audit_detail`,
  `on_pull_request_event`. Fork detection compares
  ``head.repo.full_name`` vs ``base.repo.full_name`` (the
  ``head.repo.fork`` flag is unreliable on forks-of-forks). Forks
  engage restricted mode (no apply, no open_pr, depth-1 clone, no
  secret mount, path allowlist = `changed_files`) (F23a/c).
- `aegis/integrations/github_webhooks.py`: ``X-GitHub-Event:
  pull_request`` events dispatch into the handler and the structured
  scope + reason surface in the response body (F23b).
- `project_repos/opentelemetry-collector-contrib/` — vendored at SHA
  `d7957a20ce54ab42a87b8f9e91eda73f7b3b48e5`. Apache-2.0; source-of-
  truth for the running ``otel/opentelemetry-collector-contrib`` image
  + the SLSA / fork target (F19).
- Three compose profiles (`default`, `obs`, `obs-search`) and the
  configs they need:
  - `deploy/otel/config.yaml` — receivers (OTLP gRPC + HTTP) →
    `logs/loki`, `logs/aegis-ingest`, traces → Jaeger pipelines.
  - `deploy/loki/config.yaml` — single-binary Loki dev config
    (filesystem storage, tsdb schema v13, 7d retention).
  - `deploy/Dockerfile.log_ingest` — thin python:3.12-slim image for
    aegis-log-ingest (F20a + F20c).
- `web/src/app/logs/page.tsx` — terminal-style log viewer reading
  `/v1/logs` with run/severity/service filter query params (F22).
- `docs/security/fork-prs.md` — policy doc for the fork-restricted
  mode (F23c).
- Tests:
  - `tests/test_log_ingest.py` — 11 cases (tz-aware ts validation,
    truncation, OTLP severity mapping, native + OTLP endpoints,
    metrics, health).
  - `tests/test_logs_api.py` — 3 cases (admin list, non-admin 403,
    filter narrowing).
  - `tests/test_structlog_correlation.py` — 4 cases (correlation
    processor lifts request_id, leaves it alone when caller-set,
    skips trace ids when no span).
  - `tests/test_pr_scope.py` — 6 cases (fork detection, restricted
    mode defaults, audit detail shape, dispatcher).

### Changed
- `aegis/observability.py`:
  - New `_inject_correlation_ids` structlog processor lifting
    `request_id` from the ContextVar and `trace_id` / `span_id` from
    the active OTel span.
  - `_configure_otel_logs(service_name)` — when
    ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set, every log event also
    streams to the Collector via the OTel Logs SDK's
    LoggingHandler. No-op when the env var is unset (Phase 2 path
    untouched).
  - `configure_structlog(service_name="aegis")` runs the OTel setup
    before structlog.configure so every event reaches the handler
    (F21).
- `aegis/db/models.py`: new `ApplicationLog` model (F20c).
- `aegis/api/app.py`: include `/v1/logs` router (F22).

### Migration notes
- Run Alembic migration `0003_application_logs` before serving
  v0.4.1.
- The default compose profile now brings up `aegis-log-ingest`;
  `make up` includes it without changes. The `obs` profile adds the
  Collector + Loki + Jaeger; `obs-search` further adds Elasticsearch
  + Kibana.
- Set ``OTEL_EXPORTER_OTLP_ENDPOINT`` in the API + worker environments
  to route logs through the Collector (the compose obs profile sets
  it via service-name DNS).

### Verification
- `pytest -q` — 237 passed, 3 skipped on Python 3.12.
- Default compose profile: `aegis-log-ingest` writes to
  `application_logs`; `SELECT count(*) FROM application_logs WHERE
  request_id = ...` correlates API + worker rows.
- `obs` profile: Loki shows the same stream via ``{service="aegis-
  api"}``.
- Webhook receiver: a fork PR payload returns
  ``restricted_mode="fork.restricted=true"`` in the response.

## [0.4.0] — Phase 4 Identity & UX

Real browser auth, real CSRF/CSP/XSS defence, production design
system, every web page rebuilt against it. The v0.3.1 backend is
untouched; v0.4.0 layers identity + UX on top.

### Added
- `aegis/api/session_cookie.py` — RS256 mint + verify for the
  Aegis API session cookie. NextAuth signs with the Aegis private
  key; FastAPI verifies with the Aegis public key. iss=
  ``aegis-api-session``, aud=``aegis-api``. ``generate_keypair()``
  helper for tests + ops bootstrap (F14a).
- `aegis/api/middleware/csrf.py` — double-submit CSRF on cookie-
  authenticated mutations; constant-time compare; bearer callers
  exempt (F14b).
- `aegis/api/security_headers.py` — `REPORT_CSP` constant +
  `html_report_headers()` / `non_html_report_headers()`. HTML
  reports carry `default-src 'none'` (F14d).
- New env knobs in `aegis/api/settings.py`:
  `AEGIS_API_SESSION_PRIVATE_KEY` /
  `AEGIS_API_SESSION_PUBLIC_KEY`,
  `AEGIS_API_SESSION_KEY_ID`,
  `AEGIS_API_SESSION_TTL_SECONDS`,
  `AEGIS_API_SESSION_COOKIE`,
  `AEGIS_CSRF_COOKIE`,
  `AEGIS_CSRF_HEADER`,
  `AEGIS_WEB_ORIGIN`.
- `web/src/app/api/auth/[...nextauth]/route.ts` — Keycloak provider;
  session callback mints `aegis_api_session` + `aegis_csrf` cookies
  via `jose` RS256 (F13).
- `web/src/app/api/auth/refresh-api-session/route.ts` — POST endpoint
  re-mints both cookies for the active NextAuth session, no
  Keycloak round trip.
- `web/src/app/api/auth/signout-aegis/route.ts` — clears the Aegis
  cookies during logout.
- `web/src/server/aegis-session.ts` — server-only jose-based minter
  + CSRF token generator + cookie-name helpers (F13).
- `pnpm-workspace.yaml` at the repo root — packages: `web`,
  `project_repos/design-system`.
- `project_repos/design-system/` — new workspace package
  `@aegis/design-system`. First component batch (each with a
  Storybook story): `SeverityChip`, `RunStatusBadge`,
  `AuditChainBadge`, `FindingCard`, `StageTimeline`, `EvidenceDiff`,
  `ToastList`, `RoleGated`. `cn()` Tailwind class merger in
  `src/lib/utils.ts` (F16).
- `web/.storybook/{main,preview}.ts` — Storybook 8 +
  `@storybook/addon-essentials` + `@storybook/addon-a11y`. CI gate
  is OFF for v0.4.0 (incremental; flips on in v0.4.2 once the
  second component batch lands).
- `project_repos/shadcn-ui/` — vendored submodule at SHA
  `360e8a19c3ee13ac78b656027462007c8bdaa6d5`. License (MIT)
  preserved. `web/components.json` points the shadcn registry at
  the local clone (F15).
- `project_repos/AEGIS_VENDORED.md` — pin manifest + license
  summary + rebase policy for every project_repos/ submodule.
- `web/src/hooks/useRoles.ts` — SWR-backed reader for `/v1/projects`;
  returns the caller's per-project roles for `<RoleGated>` and any
  page-level conditional rendering (F18).
- New pages: `/projects`, `/projects/[slug]/settings`, `/audit`
  (F17).
- Integration tests:
  - `tests/test_cookie_and_bearer_auth_parity.py` — 7 cases.
  - `tests/test_csrf.py` — 6 cases (double-submit + CORS).
  - `tests/test_ws_origin_and_auth.py` — 3 cases (Origin,
    subprotocol bearer).
  - `tests/test_report_xss.py` — 3 cases (renderer escapes +
    response headers).

### Changed
- `aegis/api/auth.py`: `get_current_user` resolves
  `Authorization: Bearer …` first, then the configured
  `aegis_api_session` cookie. `_resolve_from_cookie` /
  `_resolve_from_token` factored out for the WebSocket handler
  to reuse (F14a/F14c).
- `aegis/api/app.py`: CORS hardened —
  `allow_credentials=True` only against an explicit
  origin list (`cors_origins` + `web_origin`), methods
  enumerated, headers scoped to
  `Authorization` / `Content-Type` / `X-Aegis-CSRF` /
  `X-Aegis-Request-ID`. CSRF middleware wired (F14b).
- `aegis/api/ws.py`: `/v1/runs/{id}/events` upgrade now closes
  1008 on bad Origin; accepts bearer via
  `Sec-WebSocket-Protocol: aegis.bearer.<token>` (RFC 6455)
  with subprotocol echo; cookie path also honoured; legacy
  `?token=` preserved one release (F14c).
- `aegis/api/v1/reports.py`: HTML responses now carry the
  strict CSP + `X-Content-Type-Options: nosniff` +
  `Referrer-Policy: no-referrer` + `X-Frame-Options: DENY` +
  `Content-Disposition: inline`. JSON/Markdown carry nosniff +
  `Content-Disposition: attachment` with a stable filename (F14d).
- `web/src/lib/api.ts` rewritten — cookie + bearer parity,
  auto-attached CSRF header on mutations, auto
  `X-Aegis-Request-ID` per call (F18).
- `web/src/lib/auth.ts`: `requireAuth` now accepts cookie-only
  sessions (presence of the non-httpOnly `aegis_csrf` cookie);
  `logout()` clears the Aegis cookies via
  `/api/auth/signout-aegis` (F18).
- `web/src/app/{layout,dashboard,runs,findings}/*.tsx`: rewritten
  against `@aegis/design-system`. Inline styles + per-page badges
  gone in favour of `RunStatusBadge`, `SeverityChip`,
  `FindingCard`, `StageTimeline`, `RoleGated`, `AuditChainBadge`
  (F17).
- `web/package.json` renamed to `@aegis/web`; added `jose`,
  `class-variance-authority`, `clsx`, `tailwind-merge`,
  `lucide-react`, `@aegis/design-system` (workspace), Storybook
  8 + addons.

### Migration notes
- Generate an Aegis API session keypair and set
  `AEGIS_API_SESSION_PRIVATE_KEY` (on the web/NextAuth side) and
  `AEGIS_API_SESSION_PUBLIC_KEY` (on the API side). The
  `generate_keypair()` helper in `aegis.api.session_cookie` is the
  reference implementation. Both must be PKCS8-PEM (private) and
  SubjectPublicKeyInfo-PEM (public).
- Set `AEGIS_WEB_ORIGIN` to the production web origin; CORS
  enforces `allow_credentials=True` only against it.
- `pnpm install` at the repo root picks up the new workspace
  pointer (`@aegis/design-system`) and the v0.4.0 dependencies
  (`jose`, `clsx`, etc.).

### Verification
- `pytest -q` — 213 passed, 3 skipped on Python 3.12.
- Backend security suite (`test_cookie_and_bearer_auth_parity`,
  `test_csrf`, `test_ws_origin_and_auth`, `test_report_xss`) — 19
  total cases, all green.

## [0.3.1] — Phase 4 stabilization

Phase 3 shipped the platform but left ~15 architectural guarantees only
half-enforced. v0.3.1 makes them true at runtime — no UI changes, no
new auth model, no observability changes. Pure correctness + safety
wiring. The Phase 2 offline path remained green at every commit.

### Added
- `aegis/policy/{__init__,ci_gate}.py` — pure CIGatePolicy + evaluate;
  Celery import chain detached from the default `pytest -q` (F1).
- `uv.lock`, `web/pnpm-lock.yaml` committed; pytest markers (`unit`,
  `integration`, `docker`, `e2e`, `slow`, `auth_required`) declared;
  CI gates re-derive both lock files and fail on drift (F2).
- `aegis/audit/forensic.py::tool_detail` — canonical detail dict for
  per-tool audit rows. stdout/stderr reduced to sha256 + length; raw
  output stays in the blob store and the row carries `{sha256,
  location, kind}` refs (F8).
- `aegis/audit/writers.py::open_writer(mode=...)` + `InMemoryAuditWriter`
  for tests (F7).
- `aegis/cli/api_client.py` — stdlib-only HTTP wrapper; `--api` /
  `AEGIS_MODE=api` routes `scan` / `fix` / `verify` through the API
  with bearer auth from `AEGIS_TOKEN` or `~/.config/aegis/token` (F4).
- `aegis/services/runs.py::cancel_run`, `aegis/services/targets.py::
  create_target/delete_target`, `services/{scans,fixes,verify}.create_*_job`
  — admission services emit audit-before-enqueue (F6).
- `aegis/api/v1/projects.py` — `GET /v1/projects`, `GET
  /v1/projects/{slug}/membership`, `PUT /v1/projects/{slug}/settings`.
  Prereq for v0.4.0 UI role gating (FP).
- `aegis/api/v1/findings_by_scanner_id.py` — `GET
  /v1/findings/by-scanner-id?run=&scanner_id=` compat lookup
  (deprecated; sunset after v0.5) (F9).
- `aegis/db/migrations/versions/0002_findings_pk_uuid.py` — Alembic
  migration: Finding PK becomes UUID; scanner identifier moves to
  `scanner_finding_id`; `UNIQUE(run_id, scanner_finding_id)`. FK
  fan-out `ON UPDATE CASCADE` (F9).
- `aegis/api/auth.py::issue_worker_token` — time-bound versioned
  worker SA tokens; rotation overlap window; actor surface
  `service:worker:<worker_id>` (FW).
- `aegis/api/policy.py::ensure_project_access` /
  `ensure_run_access` — F12 read-side gates.
- Integration tests: `tests/test_admission_audit_before_enqueue.py`,
  `tests/test_finding_pk_collision.py`,
  `tests/test_worker_status_persistence.py`,
  `tests/test_project_access_read.py`,
  `tests/test_projects_api.py`,
  `tests/test_worker_sa_auth.py`,
  `tests/test_cai_runner_routing.py`,
  `tests/test_api_client.py`.

### Changed
- `safety.authorize()` requires an explicit `AuditWriter` writer (F7).
  Offline path supplies `JsonlAuditWriter(single_file="audit.jsonl")`
  via the safety layer's compat shim; api/worker supply
  `PostgresAuditWriter`.
- `aegis/tools/kali_client.py`: `audit_path` kwarg removed. Every
  Kali tool invocation lands on the canonical audit chain via the
  injected writer; the forensic detail shape comes from
  `aegis.audit.forensic.tool_detail` (F8).
- `aegis/services/tools.py`: threads `audit_writer` / `run_id` /
  `project_id` into KaliClient (F8).
- `aegis/cli/main.py`: `cmd_scan` / `cmd_fix` / `cmd_verify` /
  `cmd_report` reduced to thin shells that delegate to the service
  layer (F3). `--api` sets `AEGIS_MODE=api` and dispatches via
  `aegis.cli.api_client` (F4).
- `aegis/cli/migrate.py`: `cmd_migrate` reads `summary.to_dict().items()`
  (was `summary.items()`); exits non-zero on failures (F5).
- `aegis/cli/status.py`: probes `/health` against `AEGIS_API_URL`
  when in api mode (F4).
- `aegis/api/v1/{scans,fix,verify,runs_cancel,targets}.py`: rewritten
  as thin RBAC + lookup + delegate shells over the admission
  services. `AuthorizationError` surfaces as 403; `LookupError` as
  404. No route constructs Run/Job rows directly any more (F6).
- `aegis/api/v1/{reports,exports}.py`: serve from blob store first,
  filesystem fallback. Every read passes through
  `ensure_run_access` (F12).
- `aegis/api/ws.py`: `/v1/runs/{id}/events` resolves bearer
  header → `?token=…` query parameter → close 1008 if missing /
  unauthorised (F12).
- `aegis/api/auth.py`: factored `_resolve_from_token` for the WS
  handler to reuse the bearer resolution; worker token verification
  now supports v1+ time-bound tokens with key rotation overlap
  (FW).
- `aegis/db/models.py::Finding`: `id` is now a UUID;
  `scanner_finding_id String(256) NOT NULL`;
  `UNIQUE(run_id, scanner_finding_id)`. `schema_blob["id"]` keeps
  the scanner identifier so downstream consumers see the contract
  they expect (F9).
- `aegis/state_pg.py`: `save_findings` allocates UUIDs and writes
  `scanner_finding_id` separately; `update_finding_status` accepts
  either UUID or scanner_finding_id (F9).
- `aegis/workers/tasks/{scan,fix,verify}.py`: no manual audit
  writes; pass through `safety.authorize` with the bootstrap-
  supplied PostgresAuditWriter; fix worker persists
  `Finding.status`, verify worker maps to `validation_state` and
  stamps `validated_at` (F11).
- `aegis/remediate/cai_runner.py`: sys.path injection moved to
  `cai_loader.load_cai`; per-task LLM selection via
  `aegis.llm.router.route` with `project_id` + `BudgetChecker`
  hook (F10).

### Removed
- `aegis/safety._append_audit` flat-JSONL helper (F7).
- `tool-calls.jsonl` side-channel; the legacy `audit_path` kwarg on
  `KaliClient` (F8).
- The Phase 3 `_minimal markdown report` fallback in `cmd_report`
  (F3 — unreachable: `aegis.report` has always been present).

### Migration notes
- Run Alembic migration `0002_findings_pk_uuid` against your existing
  database before serving v0.3.1. The migration is wrapped in a single
  transaction; create a backup table first if you want a manual
  rollback path. Downstream consumers continue to see
  `schema_blob["id"]` carrying the scanner-side identifier.
- `AEGIS_WORKER_SIGNING_KEY` is still required. Optional new env vars:
  `AEGIS_WORKER_SIGNING_KEY_PREVIOUS` (for the rotation overlap),
  `AEGIS_WORKER_SIGNING_KEY_VERSION` (defaults to `1`),
  `AEGIS_WORKER_KEY_OVERLAP_SECONDS` (defaults to 300),
  `AEGIS_WORKER_TOKEN_TTL_SECONDS` (defaults to 300).

### Verification
- `pytest -q` — 194 passed, 3 skipped on Python 3.12.
- `make up` stack remains operational; `aegis --api status` reports
  `mode=api` + healthy/unreachable.
- `aegis audit verify --all` walks every chain and returns ✓.

## [0.3.0] — Phase 3 — Multi-user platform

Phase 3 turns the Phase 2 CLI scaffold into a multi-user, API-backed,
auditable platform. Twelve milestones (M0 – M12) landed across four
waves; the offline CLI remained green at every commit.

### Added
- **Wave 1 — Foundation**
  - `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `CODEOWNERS`, `.env.example`, `docs/architecture/phase3.md`, `docs/dev/local-stack.md`.
  - `aegis/services/` — extracted `start_scan`, `generate_fix`, `verify`, `render_reports`, `run_kali_tool` from `cmd_*` so API + workers reuse the same code.
  - `aegis/integrations/cai_loader.py::load_cai` — single sys.path injection for CAI; replaces the duplicated dance in `cai_runner`.
  - `aegis/llm/router.py` — per-task model selection with `task_models` + per-project budget hook.
  - `aegis/cli/` — package; new subcommands `status`, `audit verify`, `migrate fs->pg`, `ci-gate`. Legacy `cli.py` promoted to `cli/main.py`.
  - `aegis/state_facade.py` — `RunStateAPI` Protocol; `state.py::RunState` renamed to `FilesystemRunState` with back-compat alias.
  - `aegis/db/` — sync SQLAlchemy 2.x models (orgs, projects, users, memberships, targets, runs, jobs, findings, llm_usage, artifacts, remediation_attempts, audit_events, audit_chain_heads, github_installations); Alembic migration `0001_initial`.
  - `aegis/state_pg.py::PostgresRunState`, `aegis/state_factory.py`.
  - `aegis/blobs.py` — `BlobStore` Protocol + `FilesystemBlobStore`; `aegis/blobs_s3.py` adds the S3/MinIO backend (M9).
  - `aegis/audit/chain.py` — hash-chained audit (`JsonlAuditWriter`, `PostgresAuditWriter`, `verify_chain`); `aegis/audit/redact.py` for centralized secret scrubbing. `KaliClient._audit` now routes through the injected writer.
- **Wave 2 — Backend services**
  - `aegis/api/` — FastAPI app factory, settings, auth (OIDC JWKS + dev fallback + worker service-account), policy (Action enum + project-scoped `check`), routers (`runs`, `findings`, `audit`, `reports`, `exports`, `tools`, `health`).
  - `aegis doctor --api-mode` probes Postgres, blob backend, OIDC issuer.
  - `aegis/scanners/` — registry + `StrixAdapter`, `TrivyAdapter`, `SemgrepAdapter`, `NucleiAdapter`. Entry-point discovery gated by `AEGIS_PLUGINS=1`.
  - `aegis/agents/` — CAI-agent registry with 8 wired (`codeagent`, `blueteam_agent`, `bug_bounter`, `red_teamer`, `dfir`, `retester`, `reporter`, `web_pentester`) and 7 registered-but-unwired (Phase 4).
  - `aegis/migrate/fs_to_pg.py` — idempotent importer for Phase 2 runs.
- **Wave 3 — Execution platform**
  - Write endpoints: `POST /v1/scans`, `POST /v1/findings/{id}/fix`, `POST /v1/findings/{id}/verify`, `POST /v1/runs/{id}/cancel`, `POST/DELETE /v1/targets`. Audit event before enqueue.
  - Rate-limit middleware: per-user + per-project token-bucket on write routes.
  - `aegis/workers/` — Celery + Redis; tasks for `scan_start`, `fix_generate`, `verify_replay`, `report_render`, `vulnfixer_render`, `ci_gate`, `parallel_fix`; bootstrap manages authoritative `jobs` row.
  - `aegis/observability.py` — OTel SDK, structlog JSON renderer, correlation-id middleware (`X-Aegis-Request-ID` flows API → worker → audit), Prometheus `/metrics`.
- **Wave 4 — Collaboration surface**
  - `aegis/integrations/github_app.py` — App JWT + installation tokens + PR + Check Run.
  - `aegis/integrations/github_webhooks.py` — HMAC verify + replay protection (10-min TTL set of delivery IDs).
  - `aegis/api/ws.py` — WebSocket `/v1/runs/{id}/events` backed by Redis pub/sub.
  - `web/` — Next.js 14 dashboard with `login`, `dashboard`, `runs/[id]`, `findings/[id]`, `targets` pages; role-gated action buttons.
  - `deploy/docker-compose.yml`, `Dockerfile.{api,worker,web}`, `Makefile`, `kind.yaml`, `keycloak/realm-export.json`.
  - `.github/actions/aegis-ci-gate/action.yml` + `aegis ci-gate` CLI subcommand (severity threshold, max findings, validation gate, JUnit XML output).
  - `.github/workflows/aegis-ci.yml` extended with `api-integration` (Postgres + Redis services), `web-build`, `docker-images`, and manual `e2e-stack` (Playwright) jobs.

### Tests
- 154+ unit/integration tests across the new surfaces (services parity, schema imports, audit chain integrity & redaction, Kali writer injection, scanner / agent registries, API auth + dev-fallback + prod-disabled, GitHub webhook signature + replay, blob round-trip, correlation-id propagation, metrics endpoint, CI-gate policy).

### Notes
- The offline CLI path (Phase 2 fixture-assisted demo) remains green at every Phase 3 commit.
- vulnerability-fixer remains an export-only integration; agentic invocation is deferred to Phase 4 (`strategy="deps_vulnfixer"` reserved in the API enum, returns 501 today).
- Native MCP protocol stays deferred; `mcp-kali-server` is consumed via REST.

## [0.2.0] — 2026-05-27 — Phase 2

### Added
- `aegis.safety` central allowlist + audit log; every active operation routed through `authorize()`.
- Provider-aware `aegis doctor` (Gemini / OpenAI / Anthropic / Azure).
- `aegis/targets.py`: source-bound Juice Shop / DVWA Docker lifecycle (`up`, `up_from_repo`, `rebuild`, `restart`, `wait_ready`, `down`).
- `aegis/remediate/patch_workflow.py`: branch-first patch lifecycle with auto-rollback on apply / commit failure.
- `aegis/adapters/strix_runner.py`: subprocess + live events.jsonl tailing with partial-success handling.
- `aegis/adapters/trivy_runner.py`: dependency vulnerability scanning.
- `aegis/remediate/deps_workflow.py`: deterministic version-bump diffs (npm / Python).
- `aegis/verify.py`: PoC replay + SAST grep fallback + dependency rescan; image-mode rejected for code-patch validation.
- `aegis/demo.py`: opinionated end-to-end demo command (dry-run default; `--apply` opts in).
- `aegis/report.py`: HTML emission + stage provenance table + before/after panel.
- `aegis fix --open-pr` via `gh pr create`; deterministic branch names `aegis/fix/<finding_id>`.
- `aegis fix --deps` with synthesized version-bump patches.
- `aegis targets up/down/list` CLI subcommands.
- Global `--dry-run` / `--verbose` / `--i-understand-this-target-is-authorized` flags.
- CI workflow with leak-check; deterministic E2E variant.
- 121 unit/integration tests + 1 deterministic E2E.

### Fixed
- `cai_runner.run_code_fix` invoked the wrong CAI API (`codeagent.run(messages, context_variables=...)`); now uses `Runner.run_sync(starting_agent=codeagent, input=prompt, context=...)`.
- `cmd_fix --patch` dry-run no longer marks a finding "fixed."
- `cmd_fix --deps` final status is not overwritten by the generic update path.
- `--dry-run` correctly refuses `targets up/down/rebuild`.
- DVWA image pinned away from `:latest`.
- Container names are run-scoped to prevent collisions between concurrent runs.

### Security
- Authorization gate refuses non-loopback targets without `--i-understand-this-target-is-authorized`.
- Patch workflow refuses dirty working trees unless `--allow-dirty`.

## [0.1.0] — Phase 1 (pre-history)

- Initial scaffold: `AegisFinding` schema, `RunState`, Strix event ingestion, vulnfixer JSON export, CAI prompt wiring, 19 unit tests.
