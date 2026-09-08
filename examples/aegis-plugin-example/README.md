# aegis-plugin-example

A reference **community scanner adapter** for the Aegis marketplace, and a
*working sandboxed* one: `scan()` walks the target directory and flags any line
containing the demo marker token `AEGIS-EXAMPLE-SECRET` as a low-severity
finding. It is still a copyable template — swap the body of `scan()` for a real
tool — but it now exercises the whole finding pipeline end-to-end.

## What it shows

- An installable package that declares an `aegis.scanners` entry point.
- A factory (`create_scanner`) returning an object that satisfies the
  `ScannerAdapter` Protocol (`name`, `capabilities`, `default_timeout` +
  `adapter_version` / `health_check` / `scan`).
- A `scan()` that returns real `AegisFinding`s and writes an artifact into the
  run **directory** — all from **inside the sandbox subprocess** (see below).
  Findings are the round-tripped result (serialized back to the parent);
  artifacts land on the filesystem run dir. By design the sandboxed child has
  **no database access**, so under the Postgres state backend a plugin's
  artifact is not registered in the `Artifact` table — that ingestion is parent
  responsibility and not yet wired for sandboxed plugins.

## Try it

```bash
# From this directory, into an env that also has aegis installed:
pip install -e .

# Discovery is opt-in. With no allowlist you'll get a warning that
# third-party code is being loaded unrestricted:
AEGIS_PLUGINS=1 aegis plugins list

# Restrict to this distribution only:
AEGIS_PLUGINS=1 AEGIS_PLUGINS_ALLOW=aegis-plugin-example aegis plugins list

# JSON form:
AEGIS_PLUGINS=1 aegis plugins list --json
```

When enabled, the `example` scanner shows up with `status=loaded` and is
registered into the scanner registry (you can `aegis scan ... --scanner example`).

## Sandboxed by default

Third-party plugin code is untrusted, so Aegis runs a discovered scanner's
`scan()` **out-of-process**. The registry wraps the adapter in a
`SandboxedScanner`, which launches `python -m aegis.scanners.sandbox_worker`
with:

- a **list argv** (no shell — the same safe invocation pattern as the built-in
  CLI scanners),
- POSIX `resource` rlimits (CPU seconds, address space, file size, open files,
  processes, no core dump) + a wall-clock timeout that kills the whole process
  group,
- a **minimal allowlisted environment** — the parent's secrets (DB URL,
  signing/encryption keys, cloud creds) are never passed to plugin code, and
- proxy env vars stripped by default.

This is **defense-in-depth**, not a jail: it does not add a network namespace or
a filesystem jail, so a hostile plugin can still open sockets or touch files the
worker's user can reach. Only run plugins you have vetted and signed. Stronger
kernel-level isolation (netns/seccomp, microVM-per-plugin) is a tracked
follow-up.

The run id, run directory, and `ScanOptions` cross the boundary as a JSON
request on stdin; the result returns as a JSON `ScanResult` on stdout. A plugin
that crashes, hangs, or blows a resource limit degrades to a clean
`ScanResult` error (exit code `-1`) instead of taking down the host scan.

You don't write any of this — a conformant scanner gets the isolation for free.
Tunables (all optional):

| Env var | Default | Effect |
|---|---|---|
| `AEGIS_PLUGINS_SANDBOX` | `1` (on) | Set `0` to run trusted plugins in-process. |
| `AEGIS_PLUGIN_SANDBOX_NETWORK` | `0` (off) | Set `1` to keep proxy env (allow network). |
| `AEGIS_PLUGIN_SANDBOX_CPU_SECONDS` | `300` | CPU-time rlimit for the child. |
| `AEGIS_PLUGIN_SANDBOX_MEMORY_MB` | `1024` | Address-space rlimit for the child. |
| `AEGIS_PLUGIN_SANDBOX_FILESIZE_MB` | `256` | Largest file the child may write. |

## Make your own

1. Copy this directory and rename `aegis_plugin_example/` + the package name.
2. Change the `[project.entry-points."aegis.scanners"]` key and target.
3. Replace `ExampleScanner.scan` with a real implementation that returns a
   `ScanResult` of `AegisFinding`s.

For agents, declare an `[project.entry-points."aegis.agents"]` entry point whose
factory returns an object satisfying the `AgentAdapter` Protocol instead.

## Signed plugin (optional supply-chain enforcement)

Aegis can require third-party plugins to carry a valid **Ed25519** signature
before it will register them. Enforcement is off by default; an operator turns
it on with `AEGIS_PLUGINS_REQUIRE_SIGNATURE=1` and points
`AEGIS_PLUGINS_TRUSTED_KEYS` at one or more trusted public-key PEMs.

This example ships a working signed bundle under `signing/`:

- `signing/keys/aegis-plugin-example.pem` — the **trusted public key**.
- `signing/aegis-plugin-example-0.1.0.sig` — the detached signature
  (hex-encoded raw Ed25519 bytes) over the canonical payload
  `aegis-plugin\n<dist>\n<version>\n<sha256-of-factory-module-source>`.

The signature binds to the SHA-256 of the factory module's source, so it only
authorises the code that actually runs. Run it with enforcement on:

```bash
AEGIS_PLUGINS=1 \
AEGIS_PLUGINS_REQUIRE_SIGNATURE=1 \
AEGIS_PLUGINS_TRUSTED_KEYS=examples/aegis-plugin-example/signing/keys \
AEGIS_PLUGINS_SIG_DIR=examples/aegis-plugin-example/signing \
  aegis plugins list
```

The `example` scanner shows `status=loaded` with a `yes:<key_id>` SIGNED cell;
an unsigned plugin would be `rejected` ("no signature found") and never
registered.

### How it was signed

The committed material was produced by `signing/generate_and_sign.py`, which
generates an **ephemeral** keypair, writes only the public key + signature, and
discards the private key (the private key is never committed). A plugin author
signs their own distribution with the CLI:

```bash
aegis plugins sign \
  --dist aegis-plugin-example --version 0.1.0 \
  --entry-point aegis.scanners:example \
  --key your-ed25519-private-key.pem \
  --out examples/aegis-plugin-example/signing
```
