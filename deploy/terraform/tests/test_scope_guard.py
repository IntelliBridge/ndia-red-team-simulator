"""Offline negative regressions for the bounded validation-source guard."""

import contextlib
import importlib.util
import io
from pathlib import Path
import shutil
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("foundation_guard", SOURCE / "check_foundation.py")
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class ScopeGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for pattern in ("*.tf", ".terraform.lock.hcl"):
            for path in SOURCE.glob(pattern):
                shutil.copy2(path, self.root / path.name)
        shutil.copytree(SOURCE / "tests", self.root / "tests", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(SOURCE / "ci", self.root / "ci")
        self.original_root = GUARD.ROOT
        GUARD.ROOT = self.root

    def tearDown(self):
        GUARD.ROOT = self.original_root
        self.temp.cleanup()

    def check_status(self, expected):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(GUARD.main(), expected)

    def test_checked_in_source_is_allowed(self):
        self.check_status(0)

    def test_ecs_activation_is_rejected(self):
        (self.root / "activation.tf").write_text('resource "aws_ecs_service" "no" {}\n')
        self.check_status(1)

    def test_secret_value_source_is_rejected(self):
        (self.root / "value.tf").write_text('data "aws_secretsmanager_secret_version" "no" {}\n')
        self.check_status(1)

    def test_json_configuration_is_rejected(self):
        (self.root / "provider.tf.json").write_text("{}")
        self.check_status(1)

    def test_override_is_rejected(self):
        (self.root / "override.tf").write_text("")
        self.check_status(1)

    def test_local_variable_file_is_rejected_without_reading(self):
        (self.root / "terraform.tfvars").touch()
        self.check_status(1)

    def test_aliased_mock_is_rejected(self):
        path = self.root / "tests/foundation.tftest.hcl"
        path.write_text(path.read_text().replace('mock_provider "aws" {', 'mock_provider "aws" {\n  alias = "not_default"', 1))
        self.check_status(1)

    def test_json_test_is_rejected(self):
        (self.root / "tests/unsafe.tftest.json").write_text("{}")
        self.check_status(1)

    def test_cloud_execution_is_rejected(self):
        (self.root / "remote.tf").write_text('terraform { cloud { organization = "synthetic" } }\n')
        self.check_status(1)

    def test_provider_profile_is_rejected(self):
        (self.root / "provider.tf").write_text('provider "aws" { profile = "synthetic" }\n')
        self.check_status(1)

    def test_apply_test_is_rejected(self):
        path = self.root / "tests/foundation.tftest.hcl"
        path.write_text(path.read_text().replace("command = plan", "command = apply", 1))
        self.check_status(1)


if __name__ == "__main__":
    unittest.main()