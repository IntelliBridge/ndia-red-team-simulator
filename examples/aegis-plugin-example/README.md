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
