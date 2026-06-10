"""Offline-safe tests for the community scanner/agent adapter marketplace.

Exercises the structured discovery report (:func:`aegis.plugins.discover_all`),
the shared load+report path on :class:`aegis.registry.Registry`, the
``AEGIS_PLUGINS_ALLOW`` allowlist gate, the reference example package, and the
``aegis plugins list`` CLI surface.

Everything is monkeypatched: no real package install, no scanner binaries, no
network. Entry points are faked by patching ``importlib.metadata.entry_points``
(resolved fresh inside the registry at call time). Global state is always
restored -- ``os.environ`` via ``patch.dict`` and any fake we register is
popped from the live ``_REGISTRY`` backing dict via ``addCleanup``.
"""

from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import aegis.plugins as plugins
import aegis.scanners.registry as scanner_registry
from aegis.agents.registry import AgentResult

EXAMPLE_DIR = Path(__file__).resolve().parents[1] / "examples" / "aegis-plugin-example"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeScanner:
    """Minimal conformant ScannerAdapter."""

    def __init__(self, name="fake-mp-scanner", capabilities=None):
        self.name = name
        self.capabilities = {"dast"} if capabilities is None else capabilities
        self.default_timeout = 60

    def adapter_version(self):
        return "0.0.0-fake"

    def health_check(self):
        return True

    def scan(self, run_state, options):  # pragma: no cover - never invoked
        raise NotImplementedError


class BadScanner:
    """Non-conformant: missing ``scan`` so isinstance(ScannerAdapter) is False."""

    def __init__(self, name="bad-mp-scanner"):
        self.name = name
        self.capabilities = {"dast"}
        self.default_timeout = 60

    def adapter_version(self):
        return "0.0.0"

    def health_check(self):
        return True


class FakeAgent:
    def __init__(self, name="fake-mp-agent"):
        self.name = name
        self.domain = "offensive"
        self.effect = "active"
        self.wired = True

    def invoke(self, prompt, context):  # pragma: no cover - never invoked
        return AgentResult(status="ok", output="fake")


def _fake_ep(name, factory, *, dist_name=None, version=None):
    """Fake EntryPoint: ``.load()`` returns ``factory``; ``.dist`` mimics 3.12."""
    dist = None
    if dist_name is not None:
        dist = SimpleNamespace(name=dist_name, version=version)
    return SimpleNamespace(name=name, load=lambda: factory, dist=dist)


def _env_without_plugins():
    return {k: v for k, v in os.environ.items() if k != "AEGIS_PLUGINS"}


# ---------------------------------------------------------------------------
# discover_all() — read-only report
# ---------------------------------------------------------------------------

class TestDiscoverAll(unittest.TestCase):
    def test_disabled_when_plugins_unset(self):
        """No AEGIS_PLUGINS -> discover_all() == [] and nothing registered."""
        self.addCleanup(scanner_registry._REGISTRY.pop, "fake-mp-scanner", None)
        before = set(scanner_registry._REGISTRY)
        with patch.dict(os.environ, _env_without_plugins(), clear=True), \
                patch("importlib.metadata.entry_points") as ep_mock:
            self.assertEqual(plugins.discover_all(), [])
        ep_mock.assert_not_called()
        self.assertEqual(set(scanner_registry._REGISTRY), before)

    def test_conformant_scanner_reported_loaded_without_registering(self):
        """discover_all() reports loaded but (register=False) does not mutate."""
        self.addCleanup(scanner_registry._REGISTRY.pop, "fake-mp-scanner", None)
        ep = _fake_ep("example", lambda: FakeScanner(),
                      dist_name="fake-dist", version="1.2.3")
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "aegis.scanners" else []):
            report = plugins.discover_all()
        rows = [r for r in report if r.name == "fake-mp-scanner"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.status, "loaded")
        self.assertEqual(row.kind, "scanner")
        self.assertEqual(row.group, "aegis.scanners")
        self.assertEqual(row.distribution, "fake-dist")
        self.assertEqual(row.version, "1.2.3")
        self.assertEqual(row.detail, "")
        # register=False: the report must not register the plugin.
        self.assertNotIn("fake-mp-scanner", scanner_registry._REGISTRY)


# ---------------------------------------------------------------------------
# maybe_load_entry_points() — real registration via the shared path
# ---------------------------------------------------------------------------

class TestEagerLoad(unittest.TestCase):
    def test_conformant_scanner_loads_and_registers(self):
        self.addCleanup(scanner_registry._REGISTRY.pop, "fake-mp-scanner", None)
        ep = _fake_ep("example", lambda: FakeScanner(), dist_name="d", version="1")
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points", return_value=[ep]):
            scanner_registry.maybe_load_entry_points()
        self.assertIn("fake-mp-scanner", scanner_registry._REGISTRY)

    def test_nonconformant_rejected_sibling_still_loads(self):
        """A bad plugin is rejected + not registered; a sibling still loads."""
        self.addCleanup(scanner_registry._REGISTRY.pop, "fake-mp-scanner", None)
        self.addCleanup(scanner_registry._REGISTRY.pop, "bad-mp-scanner", None)
        eps = [
            _fake_ep("bad", lambda: BadScanner(), dist_name="d", version="1"),
            _fake_ep("good", lambda: FakeScanner(), dist_name="d", version="1"),
        ]
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: eps if group == "aegis.scanners" else []):
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "aegis.scanners", register=True))
        # Rejected rows report the entry-point name (the adapter is untrusted);
        # loaded rows report the adapter's own ``name``.
        by_name = {r.name: r for r in report}
        self.assertEqual(by_name["bad"].status, "rejected")
        self.assertIn("protocol", by_name["bad"].detail.lower())
        self.assertEqual(by_name["fake-mp-scanner"].status, "loaded")
        self.assertNotIn("bad-mp-scanner", scanner_registry._REGISTRY)
        self.assertIn("fake-mp-scanner", scanner_registry._REGISTRY)

    def test_empty_name_rejected(self):
        """A factory yielding an empty ``name`` is rejected, not registered."""
        self.addCleanup(scanner_registry._REGISTRY.pop, "", None)
        ep = _fake_ep("blank", lambda: FakeScanner(name=""),
                      dist_name="d", version="1")
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "aegis.scanners" else []):
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "aegis.scanners", register=True))
        self.assertEqual(report[0].status, "rejected")
        self.assertIn("name", report[0].detail.lower())
        self.assertNotIn("", scanner_registry._REGISTRY)

    def test_factory_that_raises_is_rejected_discovery_continues(self):
        def boom():
            raise RuntimeError("kaboom")

        self.addCleanup(scanner_registry._REGISTRY.pop, "fake-mp-scanner", None)
        eps = [
            _fake_ep("boom", boom, dist_name="d", version="1"),
            _fake_ep("good", lambda: FakeScanner(), dist_name="d", version="1"),
        ]
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: eps if group == "aegis.scanners" else []):
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "aegis.scanners", register=True))
        self.assertEqual(report[0].status, "rejected")
        self.assertIn("kaboom", report[0].detail)
        # Discovery continued to the sibling.
        self.assertEqual(report[1].status, "loaded")
        self.assertIn("fake-mp-scanner", scanner_registry._REGISTRY)

    def test_unknown_capability_warns_but_loads(self):
        """The scanner 'warn but register' semantics survive the refactor."""
        self.addCleanup(scanner_registry._REGISTRY.pop, "fake-mp-scanner", None)
        ep = _fake_ep("cap", lambda: FakeScanner(capabilities={"made-up"}),
                      dist_name="d", version="1")
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points", return_value=[ep]):
            with self.assertLogs("aegis.scanners.registry", level="WARNING") as cm:
                scanner_registry.maybe_load_entry_points()
        self.assertIn("fake-mp-scanner", scanner_registry._REGISTRY)
        self.assertTrue(any("unknown capabilities" in line for line in cm.output))


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

class TestAllowlist(unittest.TestCase):
    def test_distribution_not_in_allow_is_skipped(self):
        self.addCleanup(scanner_registry._REGISTRY.pop, "fake-mp-scanner", None)
        ep = _fake_ep("example", lambda: FakeScanner(),
                      dist_name="not-allowed", version="1")
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1",
                                     "AEGIS_PLUGINS_ALLOW": "some-other-dist"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "aegis.scanners" else []):
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "aegis.scanners", register=True))
        self.assertEqual(report[0].status, "skipped")
        self.assertIn("AEGIS_PLUGINS_ALLOW", report[0].detail)
        self.assertNotIn("fake-mp-scanner", scanner_registry._REGISTRY)

    def test_distribution_in_allow_loads(self):
        self.addCleanup(scanner_registry._REGISTRY.pop, "fake-mp-scanner", None)
        ep = _fake_ep("example", lambda: FakeScanner(),
                      dist_name="allowed-dist", version="1")
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1",
                                     "AEGIS_PLUGINS_ALLOW": "allowed-dist"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "aegis.scanners" else []):
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "aegis.scanners", register=True))
        self.assertEqual(report[0].status, "loaded")
        self.assertIn("fake-mp-scanner", scanner_registry._REGISTRY)

    def test_no_allowlist_warns(self):
        """AEGIS_PLUGINS=1 with no allowlist logs the unrestricted warning."""
        self.addCleanup(scanner_registry._REGISTRY.pop, "fake-mp-scanner", None)
        env = {k: v for k, v in os.environ.items() if k != "AEGIS_PLUGINS_ALLOW"}
        env["AEGIS_PLUGINS"] = "1"
        ep = _fake_ep("example", lambda: FakeScanner(), dist_name="d", version="1")
        with patch.dict(os.environ, env, clear=True), \
                patch("importlib.metadata.entry_points", return_value=[ep]):
            with self.assertLogs("aegis.registry", level="WARNING") as cm:
                list(scanner_registry._scanner_registry.scan_entry_points(
                    "aegis.scanners", register=False))
        self.assertTrue(any("no AEGIS_PLUGINS_ALLOW" in line for line in cm.output))


# ---------------------------------------------------------------------------
# Reference example package
# ---------------------------------------------------------------------------

class TestExamplePackage(unittest.TestCase):
    def test_example_create_scanner_is_protocol_conformant(self):
        inserted = str(EXAMPLE_DIR)
        if inserted not in sys.path:
            sys.path.insert(0, inserted)
            self.addCleanup(sys.path.remove, inserted)
        import importlib
        mod = importlib.import_module("aegis_plugin_example")
        self.addCleanup(sys.modules.pop, "aegis_plugin_example", None)
        scanner = mod.create_scanner()
        self.assertEqual(scanner.name, "example")
        self.assertIsInstance(scanner, scanner_registry.ScannerAdapter)


# ---------------------------------------------------------------------------
# CLI: aegis plugins list
# ---------------------------------------------------------------------------

class TestPluginsCli(unittest.TestCase):
    def test_list_discovery_disabled_prints_hint(self):
        from aegis.cli.main import main
        args_env = _env_without_plugins()
        buf = io.StringIO()
        with patch.dict(os.environ, args_env, clear=True), \
                patch("aegis.config.load_config"), \
                redirect_stdout(buf):
            main(["plugins", "list"])
        out = buf.getvalue()
        self.assertIn("AEGIS_PLUGINS=1", out)
        self.assertIn("disabled", out)

    def test_list_table_renders_loaded_plugin(self):
        """Enabled discovery prints a human-readable table row for the plugin."""
        from aegis.cli.main import main
        ep = _fake_ep("example", lambda: FakeScanner(),
                      dist_name="fake-dist", version="9.9.9")
        buf = io.StringIO()
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("aegis.config.load_config"), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "aegis.scanners" else []), \
                redirect_stdout(buf):
            main(["plugins", "list"])
        out = buf.getvalue()
        self.assertIn("NAME", out)
        self.assertIn("fake-mp-scanner", out)
        self.assertIn("fake-dist", out)
        self.assertIn("loaded", out)
        self.assertNotIn("fake-mp-scanner", scanner_registry._REGISTRY)

    def test_list_table_no_plugins_prints_note(self):
        from aegis.cli.main import main
        buf = io.StringIO()
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("aegis.config.load_config"), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: []), \
                redirect_stdout(buf):
            main(["plugins", "list"])
        self.assertIn("no third-party plugins discovered", buf.getvalue())

    def test_list_json_emits_valid_json_for_loaded_plugin(self):
        from aegis.cli.main import main
        ep = _fake_ep("example", lambda: FakeScanner(),
                      dist_name="fake-dist", version="9.9.9")
        buf = io.StringIO()
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("aegis.config.load_config"), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "aegis.scanners" else []), \
                redirect_stdout(buf):
            main(["plugins", "list", "--json"])
        payload = json.loads(buf.getvalue())
        self.assertIsInstance(payload, list)
        loaded = [r for r in payload if r["name"] == "fake-mp-scanner"]
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["status"], "loaded")
        self.assertEqual(loaded[0]["distribution"], "fake-dist")
        self.assertEqual(loaded[0]["version"], "9.9.9")
        # --json must not register the plugin (discover_all uses register=False).
        self.assertNotIn("fake-mp-scanner", scanner_registry._REGISTRY)


if __name__ == "__main__":
    unittest.main()
