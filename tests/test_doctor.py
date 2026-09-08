import subprocess
import unittest
from unittest.mock import patch

from redsim.config import RedsimConfig
from redsim.doctor import detect_provider, run_doctor


class TestDetectProvider(unittest.TestCase):
    def test_litellm_prefixes(self):
        self.assertEqual(detect_provider("gemini/gemini-2.5-flash"), "gemini")
        self.assertEqual(detect_provider("openai/gpt-4o"), "openai")
        self.assertEqual(detect_provider("anthropic/claude-3-5-sonnet"), "anthropic")

    def test_inference_from_model_name(self):
        self.assertEqual(detect_provider("claude-3-5-sonnet"), "anthropic")
        self.assertEqual(detect_provider("gpt-4o-mini"), "openai")
        self.assertEqual(detect_provider("o1-preview"), "openai")
        self.assertEqual(detect_provider("gemini-1.5-pro"), "gemini")

    def test_unknown(self):
        self.assertEqual(detect_provider(""), "unknown")
        self.assertEqual(detect_provider("llama-3-70b"), "unknown")


def _docker_ok():
    return patch("redsim.doctor.subprocess.run",
                 return_value=subprocess.CompletedProcess(
                     args=[], returncode=0, stdout="Docker version 25"))


class TestDoctorProviderAware(unittest.TestCase):
    def _config(self, model: str, tmp_path: str = "/tmp"):
        # A plain config: the removed pentest engines (Strix / CAI / vuln-fixer
        # paths, the MCP-Kali URL) are no longer config keys, so nothing has to
        # be propped up for doctor to pass.
        return RedsimConfig(model=model, output_dir=tmp_path)

    def test_gemini_requires_gemini_key_only(self):
        cfg = self._config("gemini/gemini-2.5-flash")
        with patch.dict("os.environ", {"GOOGLE_API_KEY": "x"}, clear=True), _docker_ok():
            self.assertTrue(run_doctor(cfg))

    def test_openai_does_not_require_gemini_key(self):
        cfg = self._config("openai/gpt-4o")
        with patch.dict("os.environ", {"OPENAI_API_KEY": "x"}, clear=True), _docker_ok():
            self.assertTrue(run_doctor(cfg))

    def test_openai_fails_without_openai_key(self):
        cfg = self._config("openai/gpt-4o")
        with patch.dict("os.environ", {}, clear=True), _docker_ok():
            self.assertFalse(run_doctor(cfg))

    def test_anthropic_requires_anthropic_key(self):
        cfg = self._config("anthropic/claude-3-5-sonnet")
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "x"}, clear=True), _docker_ok():
            self.assertTrue(run_doctor(cfg))


class TestDoctorNoPentestEngines(unittest.TestCase):
    """`redsim doctor` must not require the removed pentest engines.

    The Strix / CAI submodule directories and the MCP-Kali health probe were
    deleted with the pentest domain. A default config on a fresh checkout has
    to pass, no network probe may run outside --api-mode, and the output must
    not attribute a failure to an engine that no longer exists.
    """

    def _run(self, cfg):
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with patch.dict("os.environ", {"GOOGLE_API_KEY": "x"}, clear=True), \
             _docker_ok(), \
             patch("redsim.doctor.urlopen") as mock_urlopen, \
             redirect_stdout(buf):
            ok = run_doctor(cfg)
        return ok, buf.getvalue(), mock_urlopen

    def test_default_config_passes_and_probes_no_network(self):
        ok, out, mock_urlopen = self._run(RedsimConfig())
        self.assertTrue(ok, out)
        mock_urlopen.assert_not_called()
        self.assertIn("All required checks passed", out)
        for engine in ("Strix", "CAI", "Kali", "--open-pr", "GITHUB_TOKEN"):
            self.assertNotIn(engine, out)

    def test_removed_engine_keys_are_not_config_fields(self):
        for key in ("strix_path", "cai_path", "vulnfixer_path", "mcp_kali_url"):
            self.assertNotIn(key, RedsimConfig.__dataclass_fields__)

    def test_attack_adapter_roster_is_informational(self):
        # No adapter is registered until an ML attack adapter lands; doctor
        # reports that as a warning, never as a failed required check.
        with patch("redsim.scanners.list_scanners", return_value=[]):
            ok, out, _ = self._run(RedsimConfig())
        self.assertTrue(ok, out)
        self.assertIn("Attack adapters", out)
        self.assertIn("redsim.ml.attacks", out)
        self.assertNotIn("Some required checks failed", out)

    def test_registered_adapters_are_listed(self):
        with patch("redsim.scanners.list_scanners", return_value=["fake-evasion"]):
            ok, out, _ = self._run(RedsimConfig())
        self.assertTrue(ok, out)
        self.assertIn("fake-evasion", out)


class TestDoctorOfflineVendor(unittest.TestCase):
    """`redsim doctor` surfaces the air-gapped package mirror host."""

    def test_unset_prints_one_line_note(self):
        import io
        from contextlib import redirect_stdout

        from redsim.cli.doctor import _report_offline_vendor

        cfg = RedsimConfig(offline_vendor_host=None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            _report_offline_vendor(cfg)
        out = buf.getvalue()
        self.assertIn("Offline vendor mirror: not set", out)
        self.assertIn("REDSIM_OFFLINE_VENDOR_HOST", out)

    def test_set_prints_mirror_host(self):
        import io
        from contextlib import redirect_stdout

        from redsim.cli.doctor import _report_offline_vendor

        # The pentest submodule URL-rewrite helper was removed; the doctor now
        # only reports that a mirror host is configured.
        cfg = RedsimConfig(offline_vendor_host="mirror.int")
        buf = io.StringIO()
        with redirect_stdout(buf):
            _report_offline_vendor(cfg)
        out = buf.getvalue()
        self.assertIn("Offline vendor mirror: mirror.int", out)


if __name__ == "__main__":
    unittest.main()
