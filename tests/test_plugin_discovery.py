"""Offline-safe tests for the opt-in third-party plugin-discovery seam.

Both ``aegis.scanners.registry`` and ``aegis.agents.registry`` expose a no-arg
``maybe_load_entry_points()`` that delegates to an entry-point group and is
gated by ``AEGIS_PLUGINS=1``. The discovery does a lazy
``from importlib.metadata import entry_points`` inside the function body, so the
correct patch target is ``importlib.metadata.entry_points`` (resolved fresh at
call time).

Everything here is monkeypatched: no Postgres/Redis/Keycloak, no real package
install, no scanner binaries, no network. Global state is always restored --
``os.environ`` via ``patch.dict`` and any fake we register is popped from the
live ``_REGISTRY`` backing dict via ``addCleanup``.
"""

import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import aegis.agents as agents_pkg
import aegis.agents.registry as agent_registry
import aegis.scanners as scanners_pkg
import aegis.scanners.registry as scanner_registry
from aegis.agents.registry import AgentResult

SCANNER_NAME = "fake-plugin-scanner"
AGENT_NAME = "fake-plugin-agent"


class FakeScanner:
    """Minimal concrete ScannerAdapter; ``.name`` is a real string."""

    def __init__(self, name=SCANNER_NAME, capabilities=None):
        self.name = name
        self.capabilities = {"dast"} if capabilities is None else capabilities
        self.default_timeout = 60

    def adapter_version(self):
        return "0.0.0-fake"

    def health_check(self):
        return True

    def scan(self, run_state, options):  # never called in these tests
        raise NotImplementedError


class FakeAgent:
    """Minimal concrete AgentAdapter with a real string ``.name``."""

    def __init__(self, name=AGENT_NAME):
        self.name = name
        self.domain = "offensive"
        self.wired = True

    def invoke(self, prompt, context):  # never called in these tests
        return AgentResult(status="ok", output="fake")


def _fake_entry_point(name, factory):
    """A stand-in entry point whose ``.load()`` returns a zero-arg factory."""
    return SimpleNamespace(name=name, load=lambda: factory)


def _env_without_plugins():
    """Current environment with AEGIS_PLUGINS removed."""
    return {k: v for k, v in os.environ.items() if k != "AEGIS_PLUGINS"}


class TestScannerPluginDiscovery(unittest.TestCase):
    def test_scanner_discovery_on_registers_plugin(self):
        """AEGIS_PLUGINS=1 + patched entry_points registers the fake scanner."""
        self.addCleanup(scanner_registry._REGISTRY.pop, SCANNER_NAME, None)
        fake_ep = _fake_entry_point(SCANNER_NAME, lambda: FakeScanner())
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points", return_value=[fake_ep]):
            scanner_registry.maybe_load_entry_points()

        self.assertIn(SCANNER_NAME, scanner_registry._REGISTRY)
        self.assertIn(SCANNER_NAME, scanners_pkg.list_scanners())

    def test_scanner_discovery_off_is_noop(self):
        """Unset AEGIS_PLUGINS: no registration and entry_points never called."""
        self.addCleanup(scanner_registry._REGISTRY.pop, SCANNER_NAME, None)
        entry_points_mock = Mock(return_value=[
            _fake_entry_point(SCANNER_NAME, lambda: FakeScanner()),
        ])
        with patch.dict(os.environ, _env_without_plugins(), clear=True), \
                patch("importlib.metadata.entry_points", entry_points_mock):
            scanner_registry.maybe_load_entry_points()

        self.assertNotIn(SCANNER_NAME, scanner_registry._REGISTRY)
        # The gate returns before the lazy import, so entry_points is untouched.
        entry_points_mock.assert_not_called()

    def test_scanner_unknown_capability_still_registers(self):
        """An unknown capability warns but still lands in the registry."""
        self.addCleanup(scanner_registry._REGISTRY.pop, SCANNER_NAME, None)
        factory = lambda: FakeScanner(capabilities={"totally-made-up"})  # noqa: E731
        fake_ep = _fake_entry_point(SCANNER_NAME, factory)
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points", return_value=[fake_ep]):
            with self.assertLogs("aegis.scanners.registry", level="WARNING") as cm:
                scanner_registry.maybe_load_entry_points()

        self.assertIn(SCANNER_NAME, scanner_registry._REGISTRY)
        self.assertTrue(
            any("unknown capabilities" in line for line in cm.output),
            cm.output,
        )


class TestAgentPluginDiscovery(unittest.TestCase):
    def test_agent_discovery_on_registers_plugin(self):
        """AEGIS_PLUGINS=1 + patched entry_points registers the fake agent."""
        self.addCleanup(agent_registry._REGISTRY.pop, AGENT_NAME, None)
        fake_ep = _fake_entry_point(AGENT_NAME, lambda: FakeAgent())
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points", return_value=[fake_ep]):
            agent_registry.maybe_load_entry_points()

        self.assertIn(AGENT_NAME, agent_registry._REGISTRY)
        self.assertIn(AGENT_NAME, [a["name"] for a in agents_pkg.list_agents()])

    def test_agent_discovery_off_is_noop(self):
        """Unset AEGIS_PLUGINS: no registration and entry_points never called."""
        self.addCleanup(agent_registry._REGISTRY.pop, AGENT_NAME, None)
        entry_points_mock = Mock(return_value=[
            _fake_entry_point(AGENT_NAME, lambda: FakeAgent()),
        ])
        with patch.dict(os.environ, _env_without_plugins(), clear=True), \
                patch("importlib.metadata.entry_points", entry_points_mock):
            agent_registry.maybe_load_entry_points()

        self.assertNotIn(AGENT_NAME, agent_registry._REGISTRY)
        entry_points_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
