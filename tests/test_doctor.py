import subprocess
import unittest
from unittest.mock import patch

from aegis.config import AegisConfig
from aegis.doctor import detect_provider, run_doctor


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


class TestDoctorProviderAware(unittest.TestCase):
    def _config(self, model: str, tmp_path: str = "/tmp"):
        return AegisConfig(
            strix_path=tmp_path,
            cai_path=tmp_path,
            vulnfixer_path=tmp_path,
            model=model,
            output_dir=tmp_path,
        )

    def test_gemini_requires_gemini_key_only(self):
        cfg = self._config("gemini/gemini-2.5-flash")
        with patch.dict("os.environ", {"GOOGLE_API_KEY": "x"}, clear=True), \
             patch("aegis.doctor.subprocess.run",
                   return_value=subprocess.CompletedProcess(
                       args=[], returncode=0, stdout="Docker version 25")), \
             patch("aegis.doctor.urlopen", side_effect=OSError("no mcp")):
            self.assertTrue(run_doctor(cfg))

    def test_openai_does_not_require_gemini_key(self):
        cfg = self._config("openai/gpt-4o")
        with patch.dict("os.environ", {"OPENAI_API_KEY": "x"}, clear=True), \
             patch("aegis.doctor.subprocess.run",
                   return_value=subprocess.CompletedProcess(
                       args=[], returncode=0, stdout="Docker version 25")), \
             patch("aegis.doctor.urlopen", side_effect=OSError("no mcp")):
            self.assertTrue(run_doctor(cfg))

    def test_openai_fails_without_openai_key(self):
        cfg = self._config("openai/gpt-4o")
        with patch.dict("os.environ", {}, clear=True), \
             patch("aegis.doctor.subprocess.run",
                   return_value=subprocess.CompletedProcess(
                       args=[], returncode=0, stdout="Docker version 25")), \
             patch("aegis.doctor.urlopen", side_effect=OSError("no mcp")):
            self.assertFalse(run_doctor(cfg))

    def test_anthropic_requires_anthropic_key(self):
        cfg = self._config("anthropic/claude-3-5-sonnet")
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "x"}, clear=True), \
             patch("aegis.doctor.subprocess.run",
                   return_value=subprocess.CompletedProcess(
                       args=[], returncode=0, stdout="Docker version 25")), \
             patch("aegis.doctor.urlopen", side_effect=OSError("no mcp")):
            self.assertTrue(run_doctor(cfg))


class TestDoctorOfflineVendor(unittest.TestCase):
    """`aegis doctor` surfaces the air-gapped submodule mirror."""

    def test_unset_prints_one_line_note(self):
        import io
        from contextlib import redirect_stdout

        from aegis.cli.doctor import _report_offline_vendor

        cfg = AegisConfig(offline_vendor_host=None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            _report_offline_vendor(cfg)
        out = buf.getvalue()
        self.assertIn("Offline vendor mirror: not set", out)
        self.assertIn("AEGIS_OFFLINE_VENDOR_HOST", out)

    def test_set_prints_mirror_and_rewritten_urls(self):
        import io
        import os
        import tempfile
        from contextlib import redirect_stdout
        from pathlib import Path

        from aegis.cli.doctor import _report_offline_vendor

        cfg = AegisConfig(offline_vendor_host="mirror.int")
        # Run from a temp cwd with a known .gitmodules so the rewritten-URL
        # assertion is deterministic regardless of where pytest is invoked.
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".gitmodules").write_text(
                '[submodule "x"]\n\tpath = x\n'
                "\turl = https://github.com/org/repo.git\n"
            )
            try:
                os.chdir(tmp)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    _report_offline_vendor(cfg)
            finally:
                os.chdir(cwd)
        out = buf.getvalue()
        self.assertIn("Offline vendor mirror: mirror.int", out)
        self.assertIn("-> https://mirror.int/org/repo.git", out)

    def test_set_but_no_gitmodules(self):
        import io
        import os
        import tempfile
        from contextlib import redirect_stdout

        from aegis.cli.doctor import _report_offline_vendor

        cfg = AegisConfig(offline_vendor_host="mirror.int")
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.chdir(tmp)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    _report_offline_vendor(cfg)
            finally:
                os.chdir(cwd)
        out = buf.getvalue()
        self.assertIn("Offline vendor mirror: mirror.int", out)
        self.assertIn("no .gitmodules found", out)


if __name__ == "__main__":
    unittest.main()
