"""Registry-level checks for the scanner-adapter dispatch (offline-safe).

The 14 first-party pentest scanner adapters were removed with the pentest
domain; the adversarial-ML attack adapters (``aegis.ml.attacks``) register
through this same registry. No scanner binary is invoked: dispatch-by-capability
is exercised with a synthetic capability + mock adapter.
"""

import unittest

from aegis.scanners import dispatch
from aegis.scanners.registry import _REGISTRY, ScanOptions, ScanResult, register


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
