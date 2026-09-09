"""`redsim doctor` — Pythia-aware, provider-free (gap register G-DOCTOR, spec 8 / 10.8 / 20.3).

Everything here is offline. Docker, the sandbox child and the ML probes are
patched unless a test says otherwise; the one real child launch runs
``python -m redsim.ml.sandbox_worker --help`` (no request file, no model).
The Pythia tests pin ``REDSIM_ENV_FILE`` to a path that does not exist so the
developer's own ``.env`` is never read, and the key they use is a fake.
"""

from __future__ import annotations

import io
import os
import subprocess
import tempfile
import unittest
from argparse import Namespace
from contextlib import ExitStack, contextmanager, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest

from redsim import doctor
from redsim.config import RedsimConfig
from redsim.doctor import pythia_status, redact_key, run_doctor

REPO_ROOT = Path(__file__).resolve().parents[1]

# Deliberately fake: a recognisable prefix, an unusual length, never a real key.
FAKE_KEY = "pk_" + "test" * 12  # 51 chars
FAKE_URL = "https://pythia.example.invalid"
NO_ENV_FILE = {"REDSIM_ENV_FILE": "/nonexistent/redsim-doctor-test.env"}
CONFIGURED = {**NO_ENV_FILE, "PYTHIA_BASE_URL": FAKE_URL, "PYTHIA_API_KEY": FAKE_KEY,
              "REDSIM_ML_LLM_MODEL": "pythia/auto"}


def _docker_ok():
    return patch("redsim.doctor._cmd_version", return_value="Docker version 25")


@contextmanager
def _ml_checks(*, extra=(True, "torch 2 (test)"), sandbox=(True, "--help exit 0 (test)"),
               assets=(True, "3 bundled model(s) verified (test)")):
    with ExitStack() as stack:
        stack.enter_context(patch("redsim.doctor._check_ml_extra", return_value=extra))
        stack.enter_context(patch("redsim.doctor._check_sandbox_launch", return_value=sandbox))
        stack.enter_context(patch("redsim.doctor._check_assets_manifest", return_value=assets))
        yield


def _run(cfg: RedsimConfig | None = None, env: dict[str, str] | None = None, **kwargs):
    """Run the doctor with a clean environment; returns ``(ok, output, urlopen mock)``."""
    buf = io.StringIO()
    with patch.dict("os.environ", {**NO_ENV_FILE, **(env or {})}, clear=True), \
         _docker_ok(), \
         patch("redsim.doctor.urlopen") as mock_urlopen, \
         redirect_stdout(buf):
        ok = run_doctor(cfg or RedsimConfig(), **kwargs)
    return ok, buf.getvalue(), mock_urlopen


# ---------------------------------------------------------------------------
# The named acceptance test
# ---------------------------------------------------------------------------


def test_doctor_pythia_and_sandbox_checks():
    """Configured vs absent Pythia, key redaction, sandbox report; absence never fails."""
    # Configured: reported as such, key shown as prefix + length only.
    with _ml_checks():
        ok, out, urlopen_mock = _run(env=CONFIGURED)
    assert ok, out
    assert "Pythia gateway" in out
    assert "configured" in out
    assert redact_key(FAKE_KEY) in out
    assert "pk_… (51 chars)" in out
    assert FAKE_KEY not in out
    assert FAKE_KEY[3:] not in out
    assert "model=pythia/auto" in out
    assert FAKE_URL in out
    urlopen_mock.assert_not_called()

    # Absent: informational, never a failed required check.
    with _ml_checks():
        ok, out, _ = _run(env={})
    assert ok, out
    assert "narrative off (rules only)" in out
    assert "PYTHIA_BASE_URL" in out and "PYTHIA_API_KEY" in out and "REDSIM_ML_LLM_MODEL" in out
    assert "All required checks passed" in out
    assert "Some required checks failed" not in out
    assert "API key" not in out.replace("PYTHIA_API_KEY", "")  # no provider-key line survives

    # Sandbox child: reported when it launches ...
    with _ml_checks(sandbox=(True, "python -m redsim.ml.sandbox_worker --help exit 0 under rlimits")):
        ok, out, _ = _run(env=CONFIGURED)
    assert ok
    assert "ML sandbox child" in out and "--help exit 0" in out

    # ... informational in dev mode when it does not, required in worker mode.
    with _ml_checks(sandbox=(False, "child exited 1: boom")):
        ok_dev, out_dev, _ = _run(env=CONFIGURED)
        ok_worker, out_worker, _ = _run(env=CONFIGURED, worker_mode=True)
    assert ok_dev, out_dev
    assert "child exited 1: boom [informational]" in out_dev
    assert not ok_worker
    assert "child exited 1: boom [required]" in out_worker
    assert "Some required checks failed" in out_worker


# ---------------------------------------------------------------------------
# Pythia block details
# ---------------------------------------------------------------------------


class TestRedactKey(unittest.TestCase):
    def test_prefix_and_length_only(self):
        self.assertEqual(redact_key("pk_abcdef"), "pk_… (9 chars)")
        self.assertNotIn("abcdef", redact_key("pk_abcdef"))

    def test_unset(self):
        self.assertEqual(redact_key(""), "(unset)")


class TestPythiaStatus(unittest.TestCase):
    def test_configured(self):
        status = pythia_status(CONFIGURED)
        self.assertTrue(status.configured)
        self.assertEqual(status.key_redacted, "pk_… (51 chars)")
        self.assertEqual(status.model, "pythia/auto")
        self.assertEqual(status.missing, [])
        self.assertNotIn(FAKE_KEY, status.detail())

    def test_missing_lists_every_absent_variable(self):
        status = pythia_status({**NO_ENV_FILE, "PYTHIA_BASE_URL": FAKE_URL})
        self.assertFalse(status.configured)
        self.assertEqual(status.missing, ["PYTHIA_API_KEY", "REDSIM_ML_LLM_MODEL"])
        self.assertIn("narrative off (rules only)", status.detail())

    def test_gateway_without_model_is_not_configured(self):
        status = pythia_status({**NO_ENV_FILE, "PYTHIA_BASE_URL": FAKE_URL, "PYTHIA_API_KEY": FAKE_KEY})
        self.assertFalse(status.configured)
        self.assertEqual(status.missing, ["REDSIM_ML_LLM_MODEL"])

    def test_deprecated_alias_is_accepted_with_a_note(self):
        for alias in ("AEGIS_ML_LLM_MODEL", "REDSIM_LLM_MODEL"):
            env = {**NO_ENV_FILE, "PYTHIA_BASE_URL": FAKE_URL, "PYTHIA_API_KEY": FAKE_KEY,
                   alias: "anthropic/claude-3-haiku"}
            status = pythia_status(env)
            self.assertTrue(status.configured, alias)
            self.assertEqual(status.model, "anthropic/claude-3-haiku")
            self.assertTrue(any(f"deprecated {alias}" in n for n in status.notes), status.notes)
            self.assertIn("REDSIM_ML_LLM_MODEL", status.detail())

    def test_canonical_name_wins_over_alias(self):
        status = pythia_status({**CONFIGURED, "AEGIS_ML_LLM_MODEL": "old/model"})
        self.assertEqual(status.model, "pythia/auto")
        self.assertEqual(status.notes, [])

    def test_persona_reported(self):
        status = pythia_status({**CONFIGURED, "PYTHIA_PERSONA": "default"})
        self.assertIn("persona=default", status.detail())

    def test_disable_llm_flag(self):
        status = pythia_status({**CONFIGURED, "REDSIM_DISABLE_LLM": "1"})
        self.assertTrue(status.configured)
        self.assertTrue(status.llm_disabled)
        self.assertIn("REDSIM_DISABLE_LLM", status.detail())
        self.assertIn("narrative off (rules only)", status.detail())

    def test_without_httpx_only_the_process_env_is_read(self):
        # The lean base install has no httpx, so redsim.llm.pythia cannot import;
        # the doctor still reports from the process environment and says so.
        with patch("redsim.doctor._pythia_module", return_value=None):
            status = pythia_status({**CONFIGURED, "AEGIS_ML_LLM_MODEL": "ignored/model"})
            alias_only = pythia_status({**NO_ENV_FILE, "PYTHIA_BASE_URL": FAKE_URL,
                                        "PYTHIA_API_KEY": FAKE_KEY, "AEGIS_ML_LLM_MODEL": "a/b"})
        self.assertTrue(status.configured)
        self.assertEqual(status.model, "pythia/auto")
        self.assertTrue(any("httpx" in n for n in status.notes), status.notes)
        self.assertEqual(alias_only.model, "a/b")
        self.assertTrue(any("deprecated AEGIS_ML_LLM_MODEL" in n for n in alias_only.notes))

    def test_env_file_is_reported_and_never_the_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text(f"PYTHIA_BASE_URL={FAKE_URL}\nPYTHIA_API_KEY={FAKE_KEY}\n"
                                "REDSIM_ML_LLM_MODEL=pythia/auto\n")
            status = pythia_status({"REDSIM_ENV_FILE": str(env_file)})
        self.assertTrue(status.configured)
        self.assertEqual(status.env_file, str(env_file))
        self.assertIn(str(env_file), status.detail())
        self.assertNotIn(FAKE_KEY, status.detail())


class TestDoctorDisableLlm(unittest.TestCase):
    def test_disabled_is_informational(self):
        with _ml_checks():
            ok, out, _ = _run(env={**CONFIGURED, "REDSIM_DISABLE_LLM": "1"})
        self.assertTrue(ok, out)
        self.assertIn("REDSIM_DISABLE_LLM", out)
        self.assertIn("narrative off (rules only)", out)
        self.assertIn(redact_key(FAKE_KEY), out)
        self.assertNotIn(FAKE_KEY, out)


# ---------------------------------------------------------------------------
# ML environment checks
# ---------------------------------------------------------------------------


class TestMlExtraCheck(unittest.TestCase):
    def test_missing_module_is_named(self):
        real_import = doctor.importlib.import_module

        def fake_import(name):
            if name == "torch":
                raise ImportError("no torch here")
            return real_import(name) if name in ("sklearn",) else type("M", (), {"__version__": "9.9"})()

        with patch("redsim.doctor.importlib.import_module", side_effect=fake_import):
            ok, detail = doctor._check_ml_extra()
        self.assertFalse(ok)
        self.assertIn("missing torch", detail)
        self.assertIn('pip install -e ".[ml]"', detail)

    def test_all_present_lists_versions(self):
        with patch("redsim.doctor.importlib.import_module",
                   return_value=type("M", (), {"__version__": "1.2.3"})()):
            ok, detail = doctor._check_ml_extra()
        self.assertTrue(ok)
        for name in doctor.ML_EXTRA_MODULES:
            self.assertIn(f"{name} 1.2.3", detail)

    def test_required_only_in_worker_mode(self):
        with _ml_checks(extra=(False, "missing torch, art")), \
             patch("redsim.doctor._check_db", return_value=(True, "SELECT 1 ok")), \
             patch("redsim.doctor._check_blob_backend", return_value=(True, "fs at x")):
            ok_dev, out_dev, _ = _run(env=CONFIGURED)
            ok_api, out_api, _ = _run(env={**CONFIGURED, "REDSIM_DB_URL": "postgresql://x"}, api_mode=True)
            ok_worker, out_worker, _ = _run(env=CONFIGURED, worker_mode=True)
        self.assertTrue(ok_dev, out_dev)
        self.assertIn("missing torch, art [informational]", out_dev)
        # api mode: the API image never carries the ml extra, so still informational.
        self.assertTrue(ok_api, out_api)
        self.assertIn("missing torch, art [informational]", out_api)
        self.assertFalse(ok_worker)
        self.assertIn("missing torch, art [required]", out_worker)


class TestSandboxLaunchCheck(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "rlimits and process groups are POSIX-only")
    def test_real_child_launches_with_help_and_loads_nothing(self):
        ok, detail = doctor._check_sandbox_launch(timeout_s=60)
        self.assertTrue(ok, detail)
        self.assertIn("--help exit 0", detail)
        self.assertIn("no model loaded", detail)

    def test_child_env_carries_no_secret(self):
        seen: dict[str, object] = {}

        def fake_run(argv, **kwargs):
            seen["argv"] = argv
            seen["env"] = kwargs["env"]
            return subprocess.CompletedProcess(argv, 0, stdout="usage", stderr="")

        with patch.dict("os.environ", {"PYTHIA_API_KEY": FAKE_KEY, "REDSIM_DB_URL": "postgres://x",
                                       "HTTPS_PROXY": "http://proxy"}), \
             patch("redsim.doctor.subprocess.run", side_effect=fake_run):
            ok, _ = doctor._check_sandbox_launch()
        self.assertTrue(ok)
        argv = seen["argv"]
        self.assertEqual(argv[1:], ["-m", "redsim.ml.sandbox_worker", "--help"])
        env = seen["env"]
        self.assertNotIn("PYTHIA_API_KEY", env)
        self.assertNotIn("REDSIM_DB_URL", env)
        self.assertNotIn("HTTPS_PROXY", env)
        self.assertIn("REDSIM_ML_ASSETS_DIR", env)

    def test_timeout_and_nonzero_exit_are_reported(self):
        with patch("redsim.doctor.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="x", timeout=1)):
            ok, detail = doctor._check_sandbox_launch(timeout_s=1)
        self.assertFalse(ok)
        self.assertIn("did not exit", detail)

        with patch("redsim.doctor.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 1, stdout="", stderr="Traceback\nboom")):
            ok, detail = doctor._check_sandbox_launch()
        self.assertFalse(ok)
        self.assertEqual(detail, "child exited 1: boom")


class TestAssetsManifestCheck(unittest.TestCase):
    def test_absent_manifest_is_informational_in_dev_and_required_in_worker_mode(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.dict("os.environ", {"REDSIM_ML_ASSETS_DIR": tmp}):
            present, detail = doctor._check_assets_manifest()
        self.assertIsNone(present)
        self.assertIn("MANIFEST.json not found", detail)
        self.assertIn("redsim ml build-assets", detail)

        with _ml_checks(assets=(None, "x/MANIFEST.json not found")):
            ok_dev, out_dev, _ = _run(env=CONFIGURED)
            ok_worker, out_worker, _ = _run(env=CONFIGURED, worker_mode=True)
        self.assertTrue(ok_dev, out_dev)
        self.assertIn("not found [informational]", out_dev)
        self.assertFalse(ok_worker)
        self.assertIn("not found [required]", out_worker)

    def test_malformed_manifest_is_a_failure(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.dict("os.environ", {"REDSIM_ML_ASSETS_DIR": tmp}):
            (Path(tmp) / "MANIFEST.json").write_text("{not json")
            present, detail = doctor._check_assets_manifest()
        self.assertFalse(present)
        self.assertIn("unreadable", detail)

    def test_verification_problems_fail_in_every_mode(self):
        with _ml_checks(assets=(False, "1 problem(s): model x: weights sha256 mismatch")):
            ok_dev, out_dev, _ = _run(env=CONFIGURED)
        self.assertFalse(ok_dev)
        self.assertIn("sha256 mismatch", out_dev)
        self.assertNotIn("[informational]", out_dev.split("ML assets manifest", 1)[1].splitlines()[0])

    def test_default_root_is_dot_assets(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(doctor._assets_root(), Path("./assets"))
        with patch.dict("os.environ", {"REDSIM_ML_ASSETS_DIR": "  "}, clear=True):
            self.assertEqual(doctor._assets_root(), Path("./assets"))

    def test_repo_assets_verify_when_built(self):
        manifest = REPO_ROOT / "assets" / "MANIFEST.json"
        if not manifest.is_file():
            pytest.skip("assets not built in this checkout (run redsim ml build-assets)")
        with patch.dict("os.environ", {"REDSIM_ML_ASSETS_DIR": str(manifest.parent)}):
            present, detail = doctor._check_assets_manifest()
        self.assertTrue(present, detail)
        self.assertIn("verified", detail)


# ---------------------------------------------------------------------------
# Attack adapters roster
# ---------------------------------------------------------------------------


class TestDoctorAttackAdapters(unittest.TestCase):
    def test_ml_campaign_registered(self):
        with _ml_checks(), \
             patch("redsim.doctor._ml_campaign_adapter_importable", return_value=(True, "importable")), \
             patch("redsim.scanners.list_scanners", return_value=["ml-campaign", "fake-evasion"]):
            ok, out, _ = _run(env=CONFIGURED)
        self.assertTrue(ok, out)
        self.assertIn("ml-campaign registered", out)
        self.assertIn("fake-evasion", out)

    def test_ml_campaign_importable_but_unregistered_is_a_warning(self):
        with _ml_checks(), \
             patch("redsim.doctor._ml_campaign_adapter_importable", return_value=(True, "importable")), \
             patch("redsim.scanners.list_scanners", return_value=[]):
            ok, out, _ = _run(env=CONFIGURED)
        self.assertTrue(ok, out)
        self.assertIn("ml-campaign is not registered", out)

    def test_no_adapter_is_informational(self):
        with _ml_checks(), \
             patch("redsim.doctor._ml_campaign_adapter_importable",
                   return_value=(False, "redsim.ml.campaign_adapter not present")), \
             patch("redsim.scanners.list_scanners", return_value=[]):
            ok, out, _ = _run(env=CONFIGURED)
        self.assertTrue(ok, out)
        self.assertIn("Attack adapters", out)
        self.assertIn("none registered", out)
        self.assertIn("redsim.ml.attacks", out)
        self.assertNotIn("Some required checks failed", out)

    def test_importable_probe_handles_missing_module(self):
        with patch("redsim.doctor.importlib.util.find_spec", return_value=None):
            importable, note = doctor._ml_campaign_adapter_importable()
        self.assertFalse(importable)
        self.assertIn("not present", note)


# ---------------------------------------------------------------------------
# No pentest engines, no provider keys
# ---------------------------------------------------------------------------


class TestDoctorNoPentestEnginesOrProviderKeys(unittest.TestCase):
    """A default config on a fresh checkout passes with no key and no network."""

    def test_default_config_passes_and_probes_no_network(self):
        with _ml_checks():
            ok, out, mock_urlopen = _run(RedsimConfig(), env={})
        self.assertTrue(ok, out)
        mock_urlopen.assert_not_called()
        self.assertIn("All required checks passed", out)
        for engine in ("Strix", "CAI", "Kali", "--open-pr", "GITHUB_TOKEN"):
            self.assertNotIn(engine, out)
        for provider in ("GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                         "AZURE_API_KEY", "gemini", "litellm"):
            self.assertNotIn(provider, out)

    def test_provider_helpers_are_gone(self):
        self.assertFalse(hasattr(doctor, "detect_provider"))
        self.assertFalse(hasattr(doctor, "_PROVIDER_KEYS"))

    def test_removed_engine_keys_are_not_config_fields(self):
        for key in ("strix_path", "cai_path", "vulnfixer_path", "mcp_kali_url"):
            self.assertNotIn(key, RedsimConfig.__dataclass_fields__)

    def test_api_mode_keeps_db_blob_oidc_probes(self):
        with _ml_checks(), \
             patch("redsim.doctor._check_db", return_value=(True, "SELECT 1 ok")) as db, \
             patch("redsim.doctor._check_blob_backend", return_value=(True, "fs at x")) as blob, \
             patch("redsim.doctor._check_oidc", return_value=(True, "200 from issuer")) as oidc:
            ok, out, _ = _run(env={**CONFIGURED, "REDSIM_DB_URL": "postgresql://x", "REDSIM_BLOB_BACKEND": "fs",
                                   "REDSIM_OIDC_ISSUER": "https://idp.example.invalid"}, api_mode=True)
        self.assertTrue(ok, out)
        db.assert_called_once_with("postgresql://x")
        blob.assert_called_once_with("fs")
        oidc.assert_called_once_with("https://idp.example.invalid")
        self.assertIn("Postgres", out)
        self.assertIn("Blob backend", out)
        self.assertIn("OIDC issuer", out)

    def test_api_mode_without_db_url_fails(self):
        with _ml_checks(), patch("redsim.doctor._check_blob_backend", return_value=(True, "fs at x")):
            ok, out, _ = _run(env=CONFIGURED, api_mode=True)
        self.assertFalse(ok)
        self.assertIn("REDSIM_DB_URL not set", out)

    def test_mode_is_printed(self):
        with _ml_checks():
            _, out_dev, _ = _run(env=CONFIGURED)
            _, out_worker, _ = _run(env=CONFIGURED, worker_mode=True)
        self.assertIn("(dev mode)", out_dev)
        self.assertIn("(worker mode)", out_worker)


# ---------------------------------------------------------------------------
# CLI wrapper
# ---------------------------------------------------------------------------


class TestCmdDoctor(unittest.TestCase):
    def test_worker_mode_from_flag_or_env(self):
        from redsim.cli.doctor import WORKER_MODE_ENV, worker_mode_requested

        self.assertTrue(worker_mode_requested(Namespace(worker_mode=True)))
        with patch.dict("os.environ", {WORKER_MODE_ENV: "1"}):
            self.assertTrue(worker_mode_requested(Namespace()))
        with patch.dict("os.environ", {WORKER_MODE_ENV: "0"}):
            self.assertFalse(worker_mode_requested(Namespace()))
        with patch.dict("os.environ", {}, clear=True):
            self.assertFalse(worker_mode_requested(Namespace(api_mode=True)))

    def test_cmd_doctor_passes_modes_and_exit_status(self):
        from redsim.cli.doctor import cmd_doctor

        cfg = RedsimConfig()
        with patch("redsim.doctor.run_doctor", return_value=True) as run, \
             redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                cmd_doctor(Namespace(api_mode=True, worker_mode=True), cfg)
        self.assertEqual(ctx.exception.code, 0)
        run.assert_called_once_with(cfg, api_mode=True, worker_mode=True)

        with patch("redsim.doctor.run_doctor", return_value=False), redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                cmd_doctor(Namespace(), cfg)
        self.assertEqual(ctx.exception.code, 1)


class TestDoctorOfflineVendor(unittest.TestCase):
    """`redsim doctor` surfaces the air-gapped package mirror host."""

    def test_unset_prints_one_line_note(self):
        from redsim.cli.doctor import _report_offline_vendor

        cfg = RedsimConfig(offline_vendor_host=None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            _report_offline_vendor(cfg)
        out = buf.getvalue()
        self.assertIn("Offline vendor mirror: not set", out)
        self.assertIn("REDSIM_OFFLINE_VENDOR_HOST", out)

    def test_set_prints_mirror_host(self):
        from redsim.cli.doctor import _report_offline_vendor

        cfg = RedsimConfig(offline_vendor_host="mirror.int")
        buf = io.StringIO()
        with redirect_stdout(buf):
            _report_offline_vendor(cfg)
        out = buf.getvalue()
        self.assertIn("Offline vendor mirror: mirror.int", out)


if __name__ == "__main__":
    unittest.main()
