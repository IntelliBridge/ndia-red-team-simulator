"""Registry-level checks for the full scanner roster (offline-safe).

No scanner binary is invoked: dispatch-by-capability is exercised with a
synthetic capability + mock adapter, and ``health_check`` is checked with
``shutil.which`` patched to report every binary absent.
"""

import unittest
from unittest.mock import patch

from aegis.scanners import dispatch, get, list_scanners
from aegis.scanners.registry import _REGISTRY, ScanOptions, ScanResult, register

# The 12 first-party adapters, sorted.
_EXPECTED = [
    "bandit", "checkov", "codeql", "grype", "nuclei", "semgrep",
    "sonarqube", "strix", "syft", "trivy", "trufflehog", "zap",
]
_CAPABILITIES = {"dast", "sast", "dependency", "iac", "secret", "sbom"}


class TestScannerRoster(unittest.TestCase):
    def test_all_twelve_registered(self):
        names = set(list_scanners())
        self.assertTrue(set(_EXPECTED) <= names,
                        f"missing: {set(_EXPECTED) - names}")
        # Ignore transient test-only mocks other tests may have registered.
        real = sorted(n for n in names if not n.startswith("mock"))
        self.assertEqual(real, _EXPECTED)

    def test_name_matches_registry_key(self):
        for n in _EXPECTED:
            self.assertEqual(get(n).name, n)

    def test_capabilities_nonempty_and_known(self):
        for n in _EXPECTED:
            caps = get(n).capabilities
            self.assertTrue(caps, f"{n} declares no capabilities")
            self.assertTrue(
                caps <= _CAPABILITIES,
                f"{n} declares unknown capability {caps - _CAPABILITIES}",
            )

    def test_every_capability_has_an_adapter(self):
        covered = set()
        for n in _EXPECTED:
            covered |= get(n).capabilities
        self.assertEqual(covered, _CAPABILITIES)


class TestHealthCheck(unittest.TestCase):
    def test_health_check_false_when_binary_absent(self):
        # Every adapter resolves its binary via shutil.which; with none on
        # PATH each must return False and never raise.
        with patch("shutil.which", return_value=None):
            for n in _EXPECTED:
                self.assertIs(get(n).health_check(), False, f"{n}")


class TestDispatch(unittest.TestCase):
    def test_dispatch_by_capability_routes_to_adapter(self):
        # Synthetic capability keeps this offline: dispatching a real one
        # (e.g. "sast") would shell out to whatever scanner is on PATH.
        class _Probe:
            name = "mock-cap-probe"
            capabilities = {"__probe__"}
            default_timeout = 60

            def adapter_version(self):
                return "0.0.0-test"

            def health_check(self):
                return True

            def scan(self, run_state, options):
                return ScanResult(
                    findings=[], adapter_name=self.name,
                    adapter_version=self.adapter_version(),
                    command_str="mock",
                )

        register(_Probe())
        self.addCleanup(_REGISTRY.pop, "mock-cap-probe", None)
        res = dispatch("__probe__", run_state=None,
                       options=ScanOptions(target="x"))
        self.assertEqual(res.adapter_name, "mock-cap-probe")

    def test_unknown_capability_raises(self):
        with self.assertRaises(KeyError):
            dispatch("no-such-capability", run_state=None,
                     options=ScanOptions(target="x"))


if __name__ == "__main__":
    unittest.main()
