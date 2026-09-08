"""Offline-safe tests for the opt-in third-party plugin-discovery seam.

``redsim.scanners.registry`` exposes a no-arg ``maybe_load_entry_points()`` that
delegates to the ``redsim.scanners`` entry-point group and is gated by
``REDSIM_PLUGINS=1``. The discovery does a lazy
``from importlib.metadata import entry_points`` inside the function body, so the
correct patch target is ``importlib.metadata.entry_points`` (resolved fresh at
call time). (The pentest agent registry that once shared this seam was removed
with the pentest domain.)

Everything here is monkeypatched: no Postgres/Redis/Keycloak, no real package
install, no scanner binaries, no network. Global state is always restored --
``os.environ`` via ``patch.dict`` and any fake we register is popped from the
live ``_REGISTRY`` backing dict via ``addCleanup``.
"""

import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import redsim.scanners as scanners_pkg
import redsim.scanners.registry as scanner_registry

SCANNER_NAME = "fake-plugin-scanner"


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


def _fake_entry_point(name, factory):
    """A stand-in entry point whose ``.load()`` returns a zero-arg factory."""
    return SimpleNamespace(name=name, load=lambda: factory)


def _env_without_plugins():
    """Current environment with REDSIM_PLUGINS removed."""
    return {k: v for k, v in os.environ.items() if k != "REDSIM_PLUGINS"}


class TestScannerPluginDiscovery(unittest.TestCase):
    def test_scanner_discovery_on_registers_plugin(self):
        """REDSIM_PLUGINS=1 + patched entry_points registers the fake scanner."""
        self.addCleanup(scanner_registry._REGISTRY.pop, SCANNER_NAME, None)
        fake_ep = _fake_entry_point(SCANNER_NAME, lambda: FakeScanner())
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points", return_value=[fake_ep]):
            scanner_registry.maybe_load_entry_points()

        self.assertIn(SCANNER_NAME, scanner_registry._REGISTRY)
        self.assertIn(SCANNER_NAME, scanners_pkg.list_scanners())

    def test_scanner_discovery_off_is_noop(self):
        """Unset REDSIM_PLUGINS: no registration and entry_points never called."""
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
        factory = lambda: FakeScanner(capabilities={"totally-made-up"})
        fake_ep = _fake_entry_point(SCANNER_NAME, factory)
        with patch.dict(os.environ, {"REDSIM_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points", return_value=[fake_ep]), \
                self.assertLogs("redsim.scanners.registry", level="WARNING") as cm:
            scanner_registry.maybe_load_entry_points()

        self.assertIn(SCANNER_NAME, scanner_registry._REGISTRY)
        self.assertTrue(
            any("unknown capabilities" in line for line in cm.output),
            cm.output,
        )


if __name__ == "__main__":
    unittest.main()
