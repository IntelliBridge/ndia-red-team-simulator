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

A downstream package registers a plugin by declaring an entry point in
its own `pyproject.toml` — no change to the `aegis` package:

```toml
[project.entry-points."aegis.scanners"]
my_scanner = "my_pkg.my_module:MyScannerAdapter"

[project.entry-points."aegis.agents"]
my_agent = "my_pkg.my_module:MyAgentAdapter"
```

The entry-point **value must be a zero-arg callable** (a class works,
since calling it with no arguments constructs an instance). Aegis calls
`factory()` and registers the result, which must expose a `.name`
attribute (and otherwise satisfy the relevant adapter Protocol — see
below). The groups are `aegis.scanners` and `aegis.agents`.

!!! warning "Discovery is opt-in: `AEGIS_PLUGINS=1`"
    Entry-point discovery only runs when the environment variable
    `AEGIS_PLUGINS=1` is set. It is **off by default**.

    This is deliberate: the offline test path must stay deterministic.
    `pytest` runs without `AEGIS_PLUGINS`, so a third-party plugin
    installed in the same environment can never perturb the built-in
    registry during tests. The seam is wired in
    `Registry.maybe_load_entry_points`, which returns immediately unless
    the flag is `"1"`; a plugin whose `factory()` raises is logged and
    skipped, never propagated.

Each subsystem exposes a no-arg wrapper —
`aegis.scanners.maybe_load_entry_points()` and
`aegis.agents.maybe_load_entry_points()` — that the package `__init__`
calls **after** the built-ins are imported, so first-party adapters are
always present and plugins layer on top.

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
