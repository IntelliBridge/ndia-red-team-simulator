# Extending Aegis

Aegis discovers two kinds of pluggable component at startup: **scanner
adapters** (wrap a security tool, emit `AegisFinding`s) and **agent
adapters** (wrap a CAI agent). Both are kept in a generic
`name -> item` table — `aegis.registry.Registry[T]` — that backs the
scanner registry ([`aegis/scanners/registry.py`](https://github.com/IntelliBridge/aegis/blob/main/aegis/scanners/registry.py))
and the agent registry ([`aegis/agents/registry.py`](https://github.com/IntelliBridge/aegis/blob/main/aegis/agents/registry.py)).

This page covers how to add your own.

## Two extension paths

| Path | How it registers | When to use |
|------|------------------|-------------|
| **First-party** | Eager `import` in the subsystem `__init__.py`, which runs `register(...)` at module import. Fast, explicit, always present. | Adapters that ship inside the `aegis` package. |
| **Third-party** | A Python **entry point** that Aegis discovers at startup — opt-in via `AEGIS_PLUGINS=1`. | Adapters shipped from a separate downstream package, with no edit to `aegis`. |

### First-party (in-tree)

The built-ins are imported eagerly so callers never have to import each
adapter module by hand. For example,
[`aegis/scanners/__init__.py`](https://github.com/IntelliBridge/aegis/blob/main/aegis/scanners/__init__.py)
imports `strix_adapter`, `trivy_adapter`, and the rest; each module ends
with a top-level `register(MyAdapter())`. Adding a first-party adapter is
two steps: write `aegis/scanners/<tool>_adapter.py` ending in
`register(...)`, then add it to the import list in `__init__.py`.

### Third-party (entry points)

See [Third-party plugins (marketplace)](#third-party-plugins-marketplace)
below for the full authoring guide: the entry-point contract, a
copy-pasteable example plugin, enabling discovery, the security
allowlist, conformance validation, and the inspection CLI.

## The adapter surface

A plugin's `factory()` must return an object that satisfies the
relevant Protocol. The Protocols are the contract — match them exactly;
the registry only checks `.name` at registration, so a missing method
surfaces later at dispatch, not at load.

### `ScannerAdapter`

Defined in [`aegis/scanners/registry.py`](https://github.com/IntelliBridge/aegis/blob/main/aegis/scanners/registry.py):

| Member | Type | Purpose |
|--------|------|---------|
| `name` | `str` | Registry key. Used by `dispatch(name, ...)`. |
| `capabilities` | `set[str]` | Capability tags (e.g. `{"dast"}`). Drives capability-based dispatch. |
| `default_timeout` | `int` | Fallback scan timeout in seconds. |
| `adapter_version()` | `-> str` | Version string for the wrapped tool. |
| `health_check()` | `-> bool` | Whether the tool is usable (e.g. on `PATH`). |
| `scan(run_state, options)` | `-> ScanResult` | Run the scan; return findings + metadata. |

`scan` takes a `RunState` and a `ScanOptions` (`target`, optional
`instruction`, `timeout`, `extra`) and returns a `ScanResult`
(`findings`, `adapter_name`, `adapter_version`, `command_str`,
`env_keys`, `exit_code`, `duration_s`, `error`). The in-tree
`StrixAdapter` in
[`aegis/scanners/strix_adapter.py`](https://github.com/IntelliBridge/aegis/blob/main/aegis/scanners/strix_adapter.py)
is the reference implementation.

## Don't hand-roll `scan()` — pick the right shared helper

Most adapters wrap a CLI tool, and the wrapping boilerplate (start the
timer, `subprocess.run`, the `TimeoutExpired` / `FileNotFoundError`
envelope, persist the raw payload, assemble the `ScanResult`) is
identical from adapter to adapter. [`aegis/scanners/registry.py`](https://github.com/IntelliBridge/aegis/blob/main/aegis/scanners/registry.py)
provides three reuse seams so a new adapter supplies only what genuinely
varies. Reach for them in this order — write a fully custom `scan()`
only when none fits.

### CLI-subprocess helpers: `run_cli_scan` vs. `run_cli_scan_jsonl`

Both own the same lifecycle (timer → `subprocess.run` with the adapter's
`default_timeout` honoured → error envelope → optional raw-payload
persistence → `ScanResult`). They differ only in **how stdout is
parsed**:

| Helper | Tool output shape | Parse callback | Malformed input |
|--------|-------------------|----------------|-----------------|
| `run_cli_scan(...)` | A **single JSON document** on stdout (one object/array for the whole scan). | `parse(proc, run_id) -> list[AegisFinding]` — gets the whole `CompletedProcess`. | May raise `json.JSONDecodeError`; with `parse_error_label` set that becomes a `"failed to parse <label>"` error result. |
| `run_cli_scan_jsonl(...)` | **Line-oriented JSONL / NDJSON** — one JSON object per line. | `convert(record, run_id) -> AegisFinding \| None` — invoked once per parsed line. | A line that isn't valid JSON is **silently skipped**; the scan never fails on a bad line, so there is no parse-error envelope. |

The JSONL helper's per-line `convert` callback returning `None` **filters
that line out**. That is how `bumblebee` keeps only its finding records:
its callback (`_convert_finding` in
[`aegis/scanners/bumblebee_adapter.py`](https://github.com/IntelliBridge/aegis/blob/main/aegis/scanners/bumblebee_adapter.py))
returns `None` for any record whose `record_type != "finding"`, dropping
the interleaved `scan_summary` / `diagnostic` lines. `nuclei`,
`trufflehog`, and `bumblebee` all use `run_cli_scan_jsonl`; the
single-document tools (e.g. grype, sonarqube) use `run_cli_scan`. Both
take `subdir` / `raw_filename` to persist the raw stdout under
`run_state.run_path`, or `None` / `None` to persist nothing.

The companion helpers `cli_version(executable, ...)` (probe a tool's
`--version` banner, or `"unknown"` on any failure) and
`which_available(*executables)` (`shutil.which` OR-probe) cover the
matching `adapter_version()` / `health_check()` boilerplate.

### Runner-backed adapters: `ScanResult.from_runner(...)`

`strix` and `trivy` don't shell out directly from the adapter — they
delegate to a subprocess **runner** in `aegis/runners/` (see below) that
returns a `*RunResult`. Rather than hand-roll the re-wrap, map that
result into a `ScanResult` with the classmethod:

```python
return ScanResult.from_runner(
    result,
    adapter_name=self.name,
    adapter_version=version,
    duration_s=time.monotonic() - started,
    command_str=command_str,   # optional; defaults to " ".join(result.command)
)
```

`findings` / `error` pass straight through and `exit_code` is
`result.return_code or 0`. `command_str` defaults to the joined
`result.command`, but a runner with no `command` attribute passes it
explicitly (the `trivy` adapter passes the literal `"trivy fs"`). Any
runner result satisfying the `RunnerResult` Protocol (`findings`,
`return_code`, `error`) works — the scanner layer never imports the
runner layer, keeping the dependency one-directional.

### When a fully custom adapter is justified

`deepsec` ([`aegis/scanners/deepsec_adapter.py`](https://github.com/IntelliBridge/aegis/blob/main/aegis/scanners/deepsec_adapter.py))
is the worked example of an adapter that *can't* use any of the shared
helpers, and its module docstring spells out why:

- **Multi-step `scan → process → export` flow.** A single deepsec run is
  three sequential subprocess invocations sharing on-disk state, not the
  one `subprocess.run` + one stdout payload that `run_cli_scan` models.
  The AI `process` stage is opt-in (only when `config.deepsec_ai_process`
  is set, `config.deepsec_budget_usd > 0`, and a model key is present),
  so the default path stays free.
- **`pnpm` + config-driven `cwd` invocation.** deepsec isn't on `PATH`;
  it runs as `pnpm deepsec <subcmd>` from `config.deepsec_path`. That
  argv-with-cwd shape is something `cli_version` / `which_available`
  can't express, so `adapter_version()` and `health_check()` stay custom.
- **`_convert(record, run_id) -> AegisFinding | None` verdict filtering.**
  Like the JSONL `convert` callback, `_convert` returns `None` to drop a
  record — here for non-actionable revalidation verdicts
  (`false-positive` / `fixed` / `duplicate`) — but it's wired into the
  hand-written scan loop rather than a shared helper. (deepsec also
  strips code-owner PII before either constructing a finding or persisting
  its raw artifact; see the docstring.)

## Findings are validated at construction (Pydantic v2)

As of the architecture-hardening pass,
[`aegis/schema.py`](https://github.com/IntelliBridge/aegis/blob/main/aegis/schema.py)'s
`AegisFinding` and `CodeLocation` are **Pydantic v2 `BaseModel`s**, not
dataclasses. The fields `severity`, `finding_type`, `status`, and
`confidence` are typed as `Literal` vocabularies, so construction is
validated at runtime: an adapter that emits an out-of-vocabulary
`severity` or omits a required field now **raises at the adapter** (the
source) instead of silently persisting a malformed finding.

For an adapter author this means two things:

- Construct findings with **valid `Literal` values** — `severity` in
  `critical | high | medium | low`, `finding_type` in `dependency | sast
  | dast | runtime | config | code | code_audit | supply_chain`, `status`
  in `open | fixing | fixed | failed | false_positive`, `confidence` in
  `high | medium | low`. Map your tool's native vocabulary onto these
  (deepsec's `_SEVERITY_MAP` / `_canon_severity` is the pattern).
- The public surface is unchanged: `to_dict()` / `from_dict()` keep the
  same signatures, and `from_dict` is deliberately lenient (it falls back
  to an unvalidated construction and logs) so legacy `schema_blob` rows
  still read. New writes are fail-closed; only reads are best-effort.

### `AgentAdapter`

Defined in [`aegis/agents/registry.py`](https://github.com/IntelliBridge/aegis/blob/main/aegis/agents/registry.py):

| Member | Type | Purpose |
|--------|------|---------|
| `name` | `str` | Registry key. Used by `dispatch(name, ...)`. |
| `domain` | `Domain` | One of `offensive`, `defensive`, `forensic`, `recon`, `remediation`, `audit`. |
| `wired` | `bool` | Whether the agent is actually executable (vs. a stub). |
| `invoke(prompt, context)` | `-> AgentResult` | Run the agent; return status + output. |

`invoke` takes a prompt `str` and an `AgentContext` (`finding_id`,
`target`, `repo_path`, `actor`, `extra`) and returns an `AgentResult`
(`status`, `output`, `findings`, `diff`, `agent_version`, `error`).

Each agent also declares an **effect** (`read` / `active` / `external`) — see
"The tool catalog and effect classification" below — which drives the unified
human-in-the-loop gate in `aegis/effects.py`. Effect is a per-agent property,
not a function of domain.

## Authoring a native specialist agent

Beyond wrapping an agent CAI already ships, you can **compose** a brand-new
specialist from the vendored CAI tool catalog. The pattern lives in
[`aegis/agents/cai/authored.py`](https://github.com/IntelliBridge/aegis/blob/main/aegis/agents/cai/authored.py):
each specialist is a declarative `AuthoredSpec` (a scoped system prompt +
a toolbelt + a `domain` and `effect`), turned into a `FunctionAgentAdapter`
and `register()`ed at import. Adding one is a single list entry:

```python
AuthoredSpec(
    name="my_specialist",          # Aegis registry key (dispatch by name)
    cai_name="MySpecialist",       # the CAI Agent's own name
    domain="recon",                # one of the six Domain values
    effect="external",             # read / active / external — drives the gate
    instructions=_ROE + "You are a … specialist. …",  # substantive prompt
    tool_imports=[                 # (module_path, attribute) pairs, lazy-resolved
        ("cai.tools.reconnaissance", "shodan_search"),
        ("cai.tools.reconnaissance", "curl"),
    ],
    use_osint=True,                # append the Camoufox OSINT search tool
),
```

Three properties make this safe:

- **Registration is import-safe.** Specs are plain data; the adapter
  registers `wired=True` at import **without** importing CAI. CAI only
  matters at invocation.
- **Invocation degrades, never raises.** `invoke` loads CAI through the
  central loader; a `None` bundle (submodule missing / offline) surfaces
  `status="error"`. The CAI `Agent` is built lazily and cached, resolving
  each `tool_imports` entry defensively — a tool whose import fails is
  **skipped, not fatal** — and any runtime failure becomes `status="error"`.
- **OSINT search** is wired by setting `use_osint=True`, which appends the
  tool returned by
  [`build_osint_search_tool()`](https://github.com/IntelliBridge/aegis/blob/main/aegis/tools/osint_search.py)
  — the platform's web-search tool (Camoufox + DuckDuckGo, used in place of a
  Google/SerpAPI search). It returns `None` when CAI isn't importable, and
  `None` is filtered out of the toolbelt.

The 12 shipped specialists (`cloud_recon`, `osint_collector`, `threat_intel`,
`api_security_tester`, `web_surface_mapper`, `ssl_tls_auditor`,
`dns_enumerator`, `secrets_hunter`, `iac_auditor`, `container_security`,
`crypto_analyst`, `log_triage`) are the reference implementations.

To wire an *existing* CAI agent instead of composing a new one, add a tuple to
`_WIRED` in [`aegis/agents/cai/builtins.py`](https://github.com/IntelliBridge/aegis/blob/main/aegis/agents/cai/builtins.py)
with `by_name=True`; it resolves generically by its upstream registry key via
`resolve_cai_agent` (CAI's `get_agent_by_name`), so no per-agent `CAIBundle`
field is needed.

## The tool catalog and effect classification

[`aegis/tools/catalog.py`](https://github.com/IntelliBridge/aegis/blob/main/aegis/tools/catalog.py)
(`TOOL_CATALOG` / `list_tools()`) is the single, honest registry of every tool
the platform can expose to agents — **42 today** across four `source`s:
`kali` (10, the mcp-kali allowlist), `scanner` (14 registered adapters),
`cai` (17 vendored `@function_tool`s, namespaced `cai_*`), and `osint` (1, the
Camoufox web search). The module is import-light, so it lists what the platform
*can* expose independent of whether the optional CAI / Camoufox stacks are
installed.

Each `ToolSpec` carries an **effect** that is **authoritative in the catalog**:
`aegis.effects.tool_effect()` consults it (falling back to the Kali map), so
the catalog and the gate never drift. Classify conservatively:

| Effect | Use for | Gate |
|--------|---------|------|
| `read` | enumeration, analysis, third-party-free observation | none beyond the target allowlist |
| `active` | command execution or active probing of a live target | `execute=true` + `approver` |
| `external` | reaches a third party (Shodan API, web search, egress) | `execute=true` + `approver` |

An unclassified name fails **safe** to `active` — never silently treated as
harmless. To add a `cai` tool, append a `_CaiEntry` (catalog name, bare CAI
name, category, effect, description); the bare name is recorded in
`CAI_TOOL_NAMES` for toolbelt wiring.

## Capabilities are an open vocabulary

`aegis/scanners/registry.py` defines the known capability set:

```python
KNOWN_CAPABILITIES: set[str] = {"dast", "sast", "dependency", "iac", "secret", "sbom", "supply_chain", "code_audit"}
```

A scanner's `capabilities` is a `set[str]` validated at `register()`:

- A capability **in** the set registers silently.
- A capability **outside** the set **logs a warning but still
  registers**. Plugins can therefore introduce a new capability without
  patching core.

To promote a capability to first-party (so it no longer warns), it's a
**one-line append** to `KNOWN_CAPABILITIES`.

## Third-party plugins (marketplace)

The entry-point seam is Aegis's **community scanner-adapter marketplace**:
a downstream package ships a scanner (or agent) adapter, declares an entry
point, and an Aegis operator installs and enables it with **no edit to the
`aegis` package**. Discovery is opt-in, validated, and gated behind an
allowlist — the three controls below let an operator run third-party
adapters without surrendering the deterministic offline path or running
arbitrary code unconditionally.

A complete, installable reference plugin lives at
[`examples/aegis-plugin-example/`](https://github.com/IntelliBridge/aegis/tree/main/examples/aegis-plugin-example)
— copy it as your starting point.

### The entry-point contract

A plugin declares an entry point in its own `pyproject.toml`. The
**group** selects the registry (`aegis.scanners` or `aegis.agents`); the
**value** is a module path to a **zero-arg factory callable** that returns
the adapter instance:

```toml
# In the plugin's own pyproject.toml — nothing in aegis changes.
[project.entry-points."aegis.scanners"]
myscanner = "my_pkg:create_scanner"

[project.entry-points."aegis.agents"]
myagent = "my_pkg:create_agent"
```

Aegis imports the value, calls `create_scanner()` with **no arguments**,
and registers the returned object. A class works too (calling it with no
args constructs an instance), but a factory function keeps construction
explicit. The returned object must satisfy the relevant Protocol —
[`ScannerAdapter`](#scanneradapter) or [`AgentAdapter`](#agentadapter)
above.

### A minimal conformant scanner plugin

The factory returns any object with the `ScannerAdapter` surface. Here is
a complete, copy-pasteable `my_pkg/__init__.py` that mirrors the Protocol
exactly:

```python
"""my_pkg — a minimal third-party Aegis scanner adapter."""
from aegis.scanners.registry import ScanOptions, ScanResult


class MyScanner:
    name = "myscanner"
    capabilities = {"dast"}        # from the known set; unknown is allowed (warns)
    default_timeout = 600          # seconds; used when the caller doesn't override

    def adapter_version(self) -> str:
        return "1.0.0"

    def health_check(self) -> bool:
        return True                # e.g. shutil.which("mytool") is not None

    def scan(self, run_state, options: ScanOptions) -> ScanResult:
        # Run your tool against options.target, convert its output to
        # AegisFinding objects, and return them in a ScanResult.
        return ScanResult(
            findings=[],
            adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str=f"mytool {options.target}",
        )


def create_scanner() -> MyScanner:   # the zero-arg factory the entry point names
    return MyScanner()
```

For a real conversion pattern — building `AegisFinding`s from tool output
and the `run_cli_scan` subprocess helper — read the in-tree
[`grype_adapter.py`](https://github.com/IntelliBridge/aegis/blob/main/aegis/scanners/grype_adapter.py),
the simplest registered adapter.

### Enabling discovery: `AEGIS_PLUGINS=1`

Third-party discovery is **off by default**. Built-in adapters always
load; third-party ones load **only** when `AEGIS_PLUGINS=1` is set.

!!! warning "Set `AEGIS_PLUGINS=1` on every process that needs the plugin"
    Discovery is per-process. To use a third-party adapter end to end,
    set `AEGIS_PLUGINS=1` in the environment of **all three**:

    - the **API** (so `POST /v1/scans` accepts the adapter's name),
    - the **worker** (so the scan actually dispatches to it), and
    - the **CLI** (so `aegis scan --scanner …` and `aegis plugins list`
      see it).

    A common failure mode is enabling it on the API but not the worker:
    admission accepts the scan, then the worker — running without the
    flag — can't find the adapter.

This gate is deliberate. The offline test path must stay deterministic:
`pytest` runs without `AEGIS_PLUGINS`, so a plugin installed in the same
environment can never perturb the built-in registry during tests. The
seam is wired in `Registry.maybe_load_entry_points`, which returns
immediately unless the flag is `"1"`. Each subsystem exposes a no-arg
wrapper — `aegis.scanners.maybe_load_entry_points()` and
`aegis.agents.maybe_load_entry_points()` — that the package `__init__`
calls **after** the built-ins are imported, so first-party adapters are
always present and plugins layer on top.

### Security: the `AEGIS_PLUGINS_ALLOW` allowlist

!!! danger "Loading a plugin runs its code in your process"
    A discovered plugin's factory and `scan`/`invoke` methods execute
    **in-process** inside the API and worker — same privileges, same
    secrets, same network. Treat installing an Aegis plugin as installing
    any other dependency: only enable distributions you trust.

`AEGIS_PLUGINS_ALLOW` is a comma-separated list of **distribution** names
(the installed package/project name, not the entry-point name) that acts
as an allowlist:

```bash
# Only load plugins from these two distributions; skip everything else.
export AEGIS_PLUGINS=1
export AEGIS_PLUGINS_ALLOW="aegis-plugin-example,acme-scanners"
```

- **Allowlist set** — only plugins whose providing distribution is named
  in the list load. Every other discovered plugin is **skipped** (status
  `skipped` in `aegis plugins list`), even though discovery is on.
- **Allowlist unset** (with `AEGIS_PLUGINS=1`) — **all** discovered
  plugins load, and Aegis **logs a warning** that an unpinned plugin set
  is active. This is convenient for development but not recommended for
  production: pin the distributions you trust.

Treat the allowlist as a production control. Combined with pinning plugin
versions in your lockfile, it bounds exactly which third-party code runs.

### Signature enforcement: `AEGIS_PLUGINS_REQUIRE_SIGNATURE`

The allowlist bounds *which distributions* may load; **signature
enforcement** adds cryptographic proof of *who authored the code*, bound to
the exact factory module that runs. It is opt-in and **off by default** —
the allowlist behaviour above is unchanged until you turn it on.

When `AEGIS_PLUGINS_REQUIRE_SIGNATURE=1` is set, every discovered plugin
must carry a valid **Ed25519** signature, verifying under a trusted public
key, **before** it is registered. An unsigned or invalid plugin is
**rejected** (status `rejected` in `aegis plugins list`, with the reason in
the detail column); a valid one loads and the new **SIGNED** column shows
`yes:<key_id>` so an operator can see which trusted key vouched for it. One
bad signature never crashes discovery.

| Var | Purpose |
|-----|---------|
| `AEGIS_PLUGINS_REQUIRE_SIGNATURE` | `1`/truthy to require a valid signature; unset = no signature check. |
| `AEGIS_PLUGINS_TRUSTED_KEYS` | Colon/comma-separated `*.pem` **public-key** files and/or dirs. |
| `AEGIS_PLUGINS_SIG_DIR` | Dirs holding `<dist>-<version>.sig` files (falls back to trusted-key dirs + the plugin's module dir). |

A plugin author signs their own distribution with the CLI — it digests the
factory module's source, signs the canonical payload, and writes the
detached `<dist>-<version>.sig`:

```bash
aegis plugins sign \
  --dist aegis-plugin-example --version 0.1.0 \
  --entry-point aegis.scanners:example \
  --key your-ed25519-private-key.pem \
  --out ./signing
```

The reference example at
[`examples/aegis-plugin-example/signing/`](https://github.com/IntelliBridge/aegis/tree/main/examples/aegis-plugin-example/signing)
ships a working trusted public key + signature. For the full trust model,
the payload format, and the operator runbook, see
[Supply-chain integrity](../security/supply-chain.md#signed-third-party-plugins).

### Validation: a bad plugin is rejected, never fatal

Each discovered plugin is validated against its Protocol before it joins
the registry. A plugin is **rejected and skipped** — without crashing
discovery or affecting any other plugin or built-in — when:

- its factory **raises** on construction,
- the returned object **doesn't satisfy the Protocol** (e.g. missing
  `scan`, or no `name`), or
- its `name` is **empty**.

A rejection is logged and surfaces as status `rejected` in `aegis plugins
list` (with the reason in the detail column). One broken plugin can never
take down discovery or sideline a healthy one.

### Inspecting plugins: `aegis plugins list`

`aegis plugins list` prints what discovery found — built-in and
third-party alike — so an operator can confirm a plugin loaded (or see why
it didn't) without reading logs:

```text
$ AEGIS_PLUGINS=1 aegis plugins list
NAME         KIND      DISTRIBUTION           VERSION  STATUS    DETAIL
myscanner    scanner   aegis-plugin-example   1.0.0    loaded
acme-dast    scanner   acme-scanners          2.3.0    skipped   not in AEGIS_PLUGINS_ALLOW
brokenone    scanner   broken-pkg             —        rejected  factory raised: ValueError
```

| Column | Meaning |
|--------|---------|
| `name` | The adapter's registry key (entry-point name). |
| `kind` | `scanner` or `agent`. |
| `distribution` | The installed distribution that provides the plugin. |
| `version` | The distribution version. |
| `status` | `loaded` (registered), `rejected` (failed validation), or `skipped` (not in the allowlist). |
| `detail` | Reason for a non-`loaded` status. |

Add `--json` to emit the same data as a JSON array for scripting:

```bash
AEGIS_PLUGINS=1 aegis plugins list --json
```

With discovery **disabled**, `aegis plugins list` prints a hint to set
`AEGIS_PLUGINS=1` rather than an empty table, so the off-by-default
behaviour is never mistaken for "no plugins installed."

## Runners vs. converters vs. registered adapters

The single most confusing distinction for a new contributor: not
everything named `*_adapter.py` is a registered adapter, and the
`aegis/runners/` package holds none of the registered scanner adapters.

Only the `*_adapter.py` modules under **`aegis/scanners/`** implement
the `ScannerAdapter` Protocol and call `register(...)`. Everything in
**`aegis/runners/`** is plumbing those adapters call into — it is *not*
registered.

| Module | Role | Registered? |
|--------|------|-------------|
| `aegis/scanners/strix_adapter.py` (`StrixAdapter`) | The registered `ScannerAdapter`; `register()`ed into the scanner registry. | **Yes** |
| `aegis/runners/strix_runner.py` | Subprocess **runner** — discovers + launches the Strix CLI, tails `events.jsonl`. | No |
| `aegis/runners/trivy_runner.py` | Subprocess **runner** for Trivy. | No |
| `aegis/runners/strix_converter.py` | **Converter** — turns raw Strix events into `AegisFinding`s (`convert_strix_finding`). | No |
| `aegis/runners/vulnfixer_converter.py` | **Exporter** — maps an `AegisFinding` to the vulnerability-fixer payload. | No |
| `aegis/runners/vulnfixer_runner.py` | **Runner** — drives the vendored vulnerability-fixer engine for the agentic remediation strategy. | No |

!!! note "Why the rename"
    The package `aegis/adapters/` was renamed to `aegis/runners/`, and
    its finding-converter members were renamed with it
    (`strix_adapter.py` → `strix_converter.py`,
    `vulnfixer_adapter.py` → `vulnfixer_converter.py`). The old
    name collided with the genuinely registered
    `aegis/scanners/strix_adapter.py`. The new name says what the
    module is: a runner package whose Strix member is a *converter*, not
    a registered adapter. See
    [ADR 0002](../adr/0002-registry-seam-and-runners.md).

The call path ties them together: `StrixAdapter.scan` (registered
adapter) calls `run_strix` (runner), which calls `convert_strix_finding`
(converter) per event, then wraps the `StrixRunResult` into a
`ScanResult` via `ScanResult.from_runner(...)` (see [Runner-backed
adapters](#runner-backed-adapters-scanresultfrom_runner) above) — so a
registered adapter is the public face and the `runners/` modules are the
implementation behind it.
