"""Offline-safe tests for the community scanner adapter marketplace.

Exercises the structured discovery report (:func:`redsim.plugins.discover_all`),
the shared load+report path on :class:`redsim.registry.Registry`, the
``REDSIM_PLUGINS_ALLOW`` allowlist gate, the sandbox wrapping/error envelopes,
the reference example package (``examples/redsim-plugin-example``, run for real
through the out-of-process sandbox worker), and the ``redsim plugins list`` CLI
surface. (The pentest agent-registry group that was also exercised here was
removed with the pentest domain.)

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
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import redsim.plugins as plugins
import redsim.scanners.registry as scanner_registry
from redsim.scanners.registry import ScanOptions
from redsim.scanners.sandbox import (
    SandboxConfig,
    SandboxedScanner,
    entry_point_ref,
    sandbox_enabled,
)
from redsim.state import RunState

EXAMPLE_DIR = Path(__file__).resolve().parents[1] / "examples" / "redsim-plugin-example"
EXAMPLE_EP = "redsim_plugin_example:create_scanner"


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


def _fake_ep(name, factory, *, dist_name=None, version=None):
    """Fake EntryPoint: ``.load()`` returns ``factory``; ``.dist`` mimics 3.12."""
    dist = None
    if dist_name is not None:
        dist = SimpleNamespace(name=dist_name, version=version)
    return SimpleNamespace(name=name, load=lambda: factory, dist=dist)


def _env_without_plugins():
    return {k: v for k, v in os.environ.items() if k != "REDSIM_PLUGINS"}


# ---------------------------------------------------------------------------
# discover_all() — read-only report
# ---------------------------------------------------------------------------

class TestDiscoverAll(unittest.TestCase):
    def test_disabled_when_plugins_unset(self):
        """No REDSIM_PLUGINS -> discover_all() == [] and nothing registered."""
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
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "redsim.scanners" else []):
            report = plugins.discover_all()
        rows = [r for r in report if r.name == "fake-mp-scanner"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.status, "loaded")
        self.assertEqual(row.kind, "scanner")
        self.assertEqual(row.group, "redsim.scanners")
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
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1"}), \
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
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: eps if group == "redsim.scanners" else []):
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "redsim.scanners", register=True))
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
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "redsim.scanners" else []):
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "redsim.scanners", register=True))
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
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: eps if group == "redsim.scanners" else []):
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "redsim.scanners", register=True))
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
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points", return_value=[ep]):
            with self.assertLogs("redsim.scanners.registry", level="WARNING") as cm:
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
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1",
                                     "REDSIM_PLUGINS_ALLOW": "some-other-dist"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "redsim.scanners" else []):
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "redsim.scanners", register=True))
        self.assertEqual(report[0].status, "skipped")
        self.assertIn("REDSIM_PLUGINS_ALLOW", report[0].detail)
        self.assertNotIn("fake-mp-scanner", scanner_registry._REGISTRY)

    def test_distribution_in_allow_loads(self):
        self.addCleanup(scanner_registry._REGISTRY.pop, "fake-mp-scanner", None)
        ep = _fake_ep("example", lambda: FakeScanner(),
                      dist_name="allowed-dist", version="1")
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1",
                                     "REDSIM_PLUGINS_ALLOW": "allowed-dist"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "redsim.scanners" else []):
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "redsim.scanners", register=True))
        self.assertEqual(report[0].status, "loaded")
        self.assertIn("fake-mp-scanner", scanner_registry._REGISTRY)

    def test_no_allowlist_warns(self):
        """REDSIM_PLUGINS=1 with no allowlist logs the unrestricted warning."""
        self.addCleanup(scanner_registry._REGISTRY.pop, "fake-mp-scanner", None)
        env = {k: v for k, v in os.environ.items() if k != "REDSIM_PLUGINS_ALLOW"}
        env["REDSIM_PLUGINS"] = "1"
        ep = _fake_ep("example", lambda: FakeScanner(), dist_name="d", version="1")
        with patch.dict(os.environ, env, clear=True), \
                patch("importlib.metadata.entry_points", return_value=[ep]):
            with self.assertLogs("redsim.registry", level="WARNING") as cm:
                list(scanner_registry._scanner_registry.scan_entry_points(
                    "redsim.scanners", register=False))
        self.assertTrue(any("no REDSIM_PLUGINS_ALLOW" in line for line in cm.output))


# ---------------------------------------------------------------------------
# Reference example package
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# CLI: redsim plugins list
# ---------------------------------------------------------------------------

class TestPluginsCli(unittest.TestCase):
    def test_list_discovery_disabled_prints_hint(self):
        from redsim.cli.main import main
        args_env = _env_without_plugins()
        buf = io.StringIO()
        with patch.dict(os.environ, args_env, clear=True), \
                patch("redsim.config.load_config"), \
                redirect_stdout(buf):
            main(["plugins", "list"])
        out = buf.getvalue()
        self.assertIn("REDSIM_PLUGINS=1", out)
        self.assertIn("disabled", out)

    def test_list_table_renders_loaded_plugin(self):
        """Enabled discovery prints a human-readable table row for the plugin."""
        from redsim.cli.main import main
        ep = _fake_ep("example", lambda: FakeScanner(),
                      dist_name="fake-dist", version="9.9.9")
        buf = io.StringIO()
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1"}), \
                patch("redsim.config.load_config"), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "redsim.scanners" else []), \
                redirect_stdout(buf):
            main(["plugins", "list"])
        out = buf.getvalue()
        self.assertIn("NAME", out)
        self.assertIn("fake-mp-scanner", out)
        self.assertIn("fake-dist", out)
        self.assertIn("loaded", out)
        self.assertNotIn("fake-mp-scanner", scanner_registry._REGISTRY)

    def test_list_table_no_plugins_prints_note(self):
        from redsim.cli.main import main
        buf = io.StringIO()
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1"}), \
                patch("redsim.config.load_config"), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: []), \
                redirect_stdout(buf):
            main(["plugins", "list"])
        self.assertIn("no third-party plugins discovered", buf.getvalue())

    def test_list_json_emits_valid_json_for_loaded_plugin(self):
        from redsim.cli.main import main
        ep = _fake_ep("example", lambda: FakeScanner(),
                      dist_name="fake-dist", version="9.9.9")
        buf = io.StringIO()
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1"}), \
                patch("redsim.config.load_config"), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "redsim.scanners" else []), \
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


# ---------------------------------------------------------------------------
# Plugin sandbox: out-of-process scanner execution
# ---------------------------------------------------------------------------

def _example_on_path(case: unittest.TestCase) -> None:
    """Put the reference example package on sys.path *and* PYTHONPATH.

    The sandbox worker is a *fresh* subprocess: it imports the factory from its
    own ``sys.path``, which is seeded from ``PYTHONPATH``. So both the parent
    (for ``create_scanner`` references) and the child (for the actual import)
    must see the example dir.
    """
    inserted = str(EXAMPLE_DIR)
    if inserted not in sys.path:
        sys.path.insert(0, inserted)
        case.addCleanup(sys.path.remove, inserted)
    case.addCleanup(sys.modules.pop, "redsim_plugin_example", None)
    prev = os.environ.get("PYTHONPATH")
    parts = [inserted] + ([prev] if prev else [])
    patcher = patch.dict(os.environ, {"PYTHONPATH": os.pathsep.join(parts)})
    patcher.start()
    case.addCleanup(patcher.stop)


class TestSandboxWrapping(unittest.TestCase):
    """Discovery wraps a conformant plugin scanner in a SandboxedScanner."""

    def _ep(self):
        # A real-ish entry point: carries ``.value`` (module:attr) + ``.load()``.
        return SimpleNamespace(
            name="example", value="somemod:create_scanner",
            load=lambda: (lambda: FakeScanner()),
            dist=SimpleNamespace(name="d", version="1"),
        )

    def test_loaded_plugin_is_sandbox_wrapped_by_default(self):
        self.addCleanup(scanner_registry._REGISTRY.pop, "fake-mp-scanner", None)
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [self._ep()] if group == "redsim.scanners" else []):
            scanner_registry.maybe_load_entry_points()
        reg = scanner_registry._REGISTRY["fake-mp-scanner"]
        self.assertIsInstance(reg, SandboxedScanner)
        # The wrapper mirrors the wrapped adapter's public metadata.
        self.assertEqual(reg.name, "fake-mp-scanner")
        self.assertEqual(reg.capabilities, {"dast"})
        self.assertEqual(reg.default_timeout, 60)

    def test_sandbox_disabled_registers_raw_adapter(self):
        self.addCleanup(scanner_registry._REGISTRY.pop, "fake-mp-scanner", None)
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1", "REDSIM_PLUGINS_SANDBOX": "0"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [self._ep()] if group == "redsim.scanners" else []):
            scanner_registry.maybe_load_entry_points()
        reg = scanner_registry._REGISTRY["fake-mp-scanner"]
        self.assertIsInstance(reg, FakeScanner)
        self.assertNotIsInstance(reg, SandboxedScanner)

    def test_wrapping_does_not_change_the_discovery_report(self):
        """A wrapped plugin still reports loaded under its own name."""
        self.addCleanup(scanner_registry._REGISTRY.pop, "fake-mp-scanner", None)
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [self._ep()] if group == "redsim.scanners" else []):
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "redsim.scanners", register=True,
                wrap=scanner_registry._sandbox_wrap))
        row = [r for r in report if r.name == "fake-mp-scanner"][0]
        self.assertEqual(row.status, "loaded")
        self.assertIsInstance(scanner_registry._REGISTRY["fake-mp-scanner"], SandboxedScanner)


class TestSandboxConfig(unittest.TestCase):
    def test_enabled_by_default(self):
        env = {k: v for k, v in os.environ.items() if k != "REDSIM_PLUGINS_SANDBOX"}
        with patch.dict(os.environ, env, clear=True):
            self.assertTrue(sandbox_enabled())

    def test_env_disables(self):
        with patch.dict(os.environ, {"REDSIM_PLUGINS_SANDBOX": "0"}):
            self.assertFalse(sandbox_enabled())

    def test_config_flag_disables_when_env_absent(self):
        env = {k: v for k, v in os.environ.items() if k != "REDSIM_PLUGINS_SANDBOX"}
        cfg = SimpleNamespace(plugins_sandbox=False)
        with patch.dict(os.environ, env, clear=True):
            self.assertFalse(sandbox_enabled(cfg))

    def test_from_env_overrides_and_tolerates_garbage(self):
        env = {
            "REDSIM_PLUGIN_SANDBOX_MEMORY_MB": "512",
            "REDSIM_PLUGIN_SANDBOX_CPU_SECONDS": "not-a-number",
            "REDSIM_PLUGIN_SANDBOX_NETWORK": "1",
        }
        with patch.dict(os.environ, env):
            cfg = SandboxConfig.from_env(timeout_s=42)
        self.assertEqual(cfg.timeout_s, 42)
        self.assertEqual(cfg.memory_mb, 512)
        self.assertEqual(cfg.cpu_seconds, SandboxConfig().cpu_seconds)  # default on garbage
        self.assertTrue(cfg.allow_network)


class TestEntryPointRef(unittest.TestCase):
    def test_prefers_entry_point_value(self):
        ep = SimpleNamespace(value="pkg.mod:create_scanner")
        self.assertEqual(entry_point_ref(ep, None), "pkg.mod:create_scanner")

    def test_strips_extras_suffix(self):
        ep = SimpleNamespace(value="pkg.mod:create_scanner [extra]")
        self.assertEqual(entry_point_ref(ep, None), "pkg.mod:create_scanner")

    def test_falls_back_to_factory_module_qualname(self):
        ep = SimpleNamespace(value=None)
        ref = entry_point_ref(ep, fake_module_factory)
        self.assertEqual(ref, f"{__name__}:fake_module_factory")

    def test_unresolvable_lambda_returns_none(self):
        ep = SimpleNamespace(value=None)
        self.assertIsNone(entry_point_ref(ep, lambda: None))

    def test_nested_factory_value_rejected(self):
        # A dotted attr (e.g. ``mod:Cls.factory``) is not importable as-is.
        ep = SimpleNamespace(value="pkg.mod:Cls.create")
        self.assertIsNone(entry_point_ref(ep, lambda: None))


def fake_module_factory():  # module-level so it has a stable module:qualname
    return FakeScanner()


class TestSandboxedRunEndToEnd(unittest.TestCase):
    """Spawns the real worker subprocess against the reference example.

    This is the sandbox's *success* path: ``SandboxedScanner.scan`` -> child
    ``python -m redsim.scanners.sandbox_worker`` -> ok envelope -> a rebuilt
    ``ScanResult`` with a real finding and an artifact persisted into the run
    dir. The error-envelope tests below cover the failure paths.
    """

    def setUp(self):
        _example_on_path(self)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def _sandboxed(self) -> SandboxedScanner:
        import redsim_plugin_example as mod
        return SandboxedScanner(mod.create_scanner(), EXAMPLE_EP)

    def test_marker_hit_produces_finding_via_subprocess(self):
        target = self.tmp / "target"
        target.mkdir()
        (target / "a.py").write_text('pw = "REDSIM-EXAMPLE-SECRET"\n')
        (target / "clean.txt").write_text("nothing to see\n")
        run_state = RunState(str(self.tmp / "out"))
        result = self._sandboxed().scan(run_state, ScanOptions(target=str(target)))

        self.assertEqual(result.exit_code, 0, result.error)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.finding_type, "sast")
        self.assertEqual(finding.source_tool, "example")
        self.assertEqual(finding.code_locations[0].start_line, 1)
        # The command recorded is the safe list-argv worker invocation (no shell).
        self.assertIn("redsim.scanners.sandbox_worker", result.command_str)
        # The sandboxed child persisted an artifact into the real run dir.
        self.assertTrue((run_state.run_path / "artifacts" / "example-scanner.txt").is_file())

    def test_clean_target_produces_zero_findings(self):
        target = self.tmp / "clean"
        target.mkdir()
        (target / "ok.py").write_text("x = 1\n")
        run_state = RunState(str(self.tmp / "out"))
        result = self._sandboxed().scan(run_state, ScanOptions(target=str(target)))
        self.assertEqual(result.exit_code, 0, result.error)
        self.assertEqual(result.findings, [])


class TestSandboxedRunChildEnv(unittest.TestCase):
    """Sandbox child-env policy (does not need the reference example package)."""

    def test_network_off_env_strips_proxy_for_child(self):
        """The child env has proxy vars stripped + REDSIM_PLUGINS pinned off."""
        from redsim.scanners.sandbox import _child_env

        with patch.dict(os.environ, {"HTTPS_PROXY": "http://p:8080",
                                     "http_proxy": "http://p:8080"}):
            env_off = _child_env(SandboxConfig(allow_network=False))
            env_on = _child_env(SandboxConfig(allow_network=True))
        self.assertNotIn("HTTPS_PROXY", env_off)
        self.assertNotIn("http_proxy", env_off)
        self.assertEqual(env_off["REDSIM_PLUGINS"], "0")
        self.assertEqual(env_on["HTTPS_PROXY"], "http://p:8080")


class TestSandboxErrorEnvelopes(unittest.TestCase):
    """A misbehaving plugin degrades to a clean error ScanResult, never a crash."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.run_state = RunState(str(Path(self._tmp.name) / "out"))

    def test_unimportable_entry_point_is_clean_error(self):
        sandboxed = SandboxedScanner(FakeScanner(), "no_such_module_xyz:create")
        result = sandboxed.scan(self.run_state, ScanOptions(target="."))
        self.assertEqual(result.exit_code, -1)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.adapter_name, "fake-mp-scanner")

    def test_timeout_is_clean_error(self):
        import subprocess

        from redsim.scanners import sandbox as sandbox_mod

        class _TimeoutProc:
            pid = 4321
            returncode = None

            def communicate(self, *a, **kw):
                raise subprocess.TimeoutExpired(["worker"], 1)

            def kill(self):
                pass

        # The sandbox spawns via Popen + communicate(timeout=) and kills the
        # whole process group on timeout; patch the group-kill so the fake pid
        # is never passed to os.killpg.
        with patch("subprocess.Popen", return_value=_TimeoutProc()), \
                patch.object(sandbox_mod, "_kill_process_group"):
            result = sandbox_mod.run_scanner_sandboxed(
                "x:y", self.run_state, ScanOptions(target="."),
                adapter_name="fake-mp-scanner",
                config=SandboxConfig(timeout_s=1),
            )
        self.assertEqual(result.exit_code, -1)
        self.assertIn("timed out", result.error or "")

    def test_unparseable_worker_output_is_clean_error(self):
        from redsim.scanners import sandbox as sandbox_mod

        proc = SimpleNamespace(
            returncode=0,
            communicate=lambda *a, **kw: ("not json at all", ""))
        with patch("subprocess.Popen", return_value=proc):
            result = sandbox_mod.run_scanner_sandboxed(
                "x:y", self.run_state, ScanOptions(target="."),
                adapter_name="fake-mp-scanner", config=SandboxConfig(),
            )
        self.assertEqual(result.exit_code, -1)
        self.assertIn("unparseable", result.error or "")

    def test_structured_failure_envelope_is_surfaced(self):
        from redsim.scanners import sandbox as sandbox_mod

        proc = SimpleNamespace(
            returncode=0,
            communicate=lambda *a, **kw: (
                json.dumps({"ok": False, "error": "RuntimeError: boom"}), ""))
        with patch("subprocess.Popen", return_value=proc):
            result = sandbox_mod.run_scanner_sandboxed(
                "x:y", self.run_state, ScanOptions(target="."),
                adapter_name="fake-mp-scanner", config=SandboxConfig(),
            )
        self.assertEqual(result.exit_code, -1)
        self.assertIn("boom", result.error or "")


class TestSandboxEnvPolicy(unittest.TestCase):
    """The child env is a minimal allowlist — no parent secrets, network off."""

    def test_child_env_excludes_parent_secrets(self):
        import os

        from redsim.scanners.sandbox import SandboxConfig, _child_env

        with patch.dict(os.environ, {
            "REDSIM_WORKER_SIGNING_KEY": "k",
            "REDSIM_DB_URL": "postgresql://u:secret@h/db",
            "REDSIM_AUTH_PROFILES_KEY": "fernet-key",
            "AWS_SECRET_ACCESS_KEY": "aws-secret",
        }):
            env = _child_env(SandboxConfig())
        for secret in ("REDSIM_WORKER_SIGNING_KEY", "REDSIM_DB_URL",
                       "REDSIM_AUTH_PROFILES_KEY", "AWS_SECRET_ACCESS_KEY"):
            self.assertNotIn(secret, env)
        self.assertEqual(env["REDSIM_PLUGINS"], "0")
        self.assertIn("PATH", env)

    def test_child_env_network_off_by_default(self):
        import os

        from redsim.scanners.sandbox import SandboxConfig, _child_env

        with patch.dict(os.environ, {"HTTP_PROXY": "http://p", "NO_PROXY": "x"}):
            off = _child_env(SandboxConfig(allow_network=False))
            on = _child_env(SandboxConfig(allow_network=True))
        self.assertNotIn("HTTP_PROXY", off)
        self.assertIn("HTTP_PROXY", on)


class TestSandboxWorkerUnit(unittest.TestCase):
    """In-process unit tests of the worker's request/response core."""

    def setUp(self):
        _example_on_path(self)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def test_run_returns_ok_envelope(self):
        from redsim.scanners import sandbox_worker

        target = self.tmp / "t"
        target.mkdir()
        (target / "a.py").write_text('k = "REDSIM-EXAMPLE-SECRET"\n')
        run_path = self.tmp / "out" / "run-1"
        request = {"run_id": "run-1", "run_path": str(run_path),
                   "options": {"target": str(target)}}
        envelope = sandbox_worker.run(EXAMPLE_EP, request)
        self.assertTrue(envelope["ok"])
        self.assertEqual(len(envelope["result"]["findings"]), 1)
        self.assertEqual(envelope["result"]["adapter_name"], "example")

    def test_parse_entry_point_rejects_malformed(self):
        from redsim.scanners.sandbox_worker import _parse_entry_point

        for bad in ("nocolon", ":nofactory", "nomodule:", ""):
            with self.assertRaises(ValueError):
                _parse_entry_point(bad)

    def test_main_emits_error_envelope_on_unimportable(self):
        from redsim.scanners import sandbox_worker

        request = json.dumps({"run_id": "r", "run_path": str(self.tmp / "o"),
                              "options": {"target": "."}})
        buf = io.StringIO()
        with patch.object(sandbox_worker, "_RESULT_STREAM", buf), \
                patch("sys.stdin", io.StringIO(request)):
            rc = sandbox_worker.main(["--entry-point", "no_such_mod_abc:create"])
        self.assertEqual(rc, 0)  # a produced (error) envelope is exit 0
        envelope = json.loads(buf.getvalue())
        self.assertFalse(envelope["ok"])
        self.assertIn("error", envelope)


if __name__ == "__main__":
    unittest.main()
