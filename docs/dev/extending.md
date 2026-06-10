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
(converter) per event — so a registered adapter is the public face and
the `runners/` modules are the implementation behind it.
