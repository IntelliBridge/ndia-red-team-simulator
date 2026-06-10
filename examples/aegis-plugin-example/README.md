# aegis-plugin-example

A reference **community scanner adapter** for the Aegis marketplace. It is a
copyable template, not a real scanner — `scan()` returns zero findings.

## What it shows

- An installable package that declares an `aegis.scanners` entry point.
- A factory (`create_scanner`) returning an object that satisfies the
  `ScannerAdapter` Protocol (`name`, `capabilities`, `default_timeout` +
  `adapter_version` / `health_check` / `scan`).

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
