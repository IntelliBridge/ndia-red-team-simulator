"""Phase 4 v0.3.1 F4 — CLI --api dispatch via aegis.cli.api_client."""

from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from aegis.cli import api_client


class _StubResponse:
    def __init__(self, body: dict) -> None:
        self._data = json.dumps(body).encode()

    def read(self) -> bytes:
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _stub_urlopen(payload: dict, capture: list[tuple[str, str, bytes | None,
                                                     dict]]):
    def _opener(req, timeout=None):  # noqa: ARG001
        body = req.data
        headers = {k: v for k, v in req.header_items()}
        capture.append((req.get_method(), req.full_url, body, headers))
        return _StubResponse(payload)
    return _opener


class TestApiClient(unittest.TestCase):
    def test_start_scan_posts_to_v1_scans(self):
        captured: list = []
        client = api_client.ApiClient(base_url="http://api.local",
                                       token="t0k3n")
        with patch("urllib.request.urlopen",
                   _stub_urlopen({"run_id": "r1", "job_id": "j1"}, captured)):
            result = client.start_scan(target="http://localhost:3000",
                                       project_id="proj-1")
        self.assertEqual(result["run_id"], "r1")
        method, url, body, headers = captured[0]
        self.assertEqual(method, "POST")
        self.assertEqual(url, "http://api.local/v1/scans")
        self.assertIn("Authorization", headers)
        self.assertEqual(headers["Authorization"], "Bearer t0k3n")
        sent = json.loads(body.decode())
        self.assertEqual(sent["target"], "http://localhost:3000")
        self.assertEqual(sent["project_id"], "proj-1")

    def test_fix_posts_to_correct_route(self):
        captured: list = []
        client = api_client.ApiClient(base_url="http://api.local", token=None)
        with patch("urllib.request.urlopen",
                   _stub_urlopen({"job_id": "j2"}, captured)):
            client.fix(finding_id="f-1", strategy="patch", apply=True)
        method, url, body, _ = captured[0]
        self.assertEqual(method, "POST")
        self.assertEqual(url, "http://api.local/v1/findings/f-1/fix")
        sent = json.loads(body.decode())
        self.assertTrue(sent["apply"])

    def test_verify_posts_with_no_body(self):
        captured: list = []
        client = api_client.ApiClient(base_url="http://api.local", token=None)
        with patch("urllib.request.urlopen",
                   _stub_urlopen({"job_id": "j3"}, captured)):
            client.verify(finding_id="f-1")
        method, url, body, _ = captured[0]
        self.assertEqual(method, "POST")
        self.assertEqual(url, "http://api.local/v1/findings/f-1/verify")
        self.assertIsNone(body)

    def test_http_error_is_surfaced_as_ApiError(self):
        client = api_client.ApiClient(base_url="http://api.local", token=None)

        def _raise(req, timeout=None):  # noqa: ARG001
            raise urllib.error.HTTPError(
                req.full_url, 403, "Forbidden", {},
                io.BytesIO(b'{"detail":"role lacks fix.apply"}'),
            )

        with patch("urllib.request.urlopen", _raise):
            with self.assertRaises(api_client.ApiError) as ctx:
                client.start_scan(target="http://localhost:3000")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("fix.apply", ctx.exception.body)

    def test_health_returns_none_when_unreachable(self):
        client = api_client.ApiClient(base_url="http://nope", token=None)
        def _raise(_req, timeout=None):  # noqa: ARG001
            raise urllib.error.URLError("nope")
        with patch("urllib.request.urlopen", _raise):
            self.assertIsNone(client.health())


class TestIsApiMode(unittest.TestCase):
    def test_flag_takes_precedence(self):
        args = argparse.Namespace(global_api=True)
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AEGIS_MODE", None)
            self.assertTrue(api_client.is_api_mode(args))

    def test_env_var_lower_case(self):
        args = argparse.Namespace(global_api=False)
        with patch.dict(os.environ, {"AEGIS_MODE": "API"}, clear=False):
            self.assertTrue(api_client.is_api_mode(args))


class TestLoadToken(unittest.TestCase):
    def test_env_wins_over_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".config" / "aegis").mkdir(parents=True)
            (home / ".config" / "aegis" / "token").write_text("from-file\n")
            with patch.dict(os.environ, {"AEGIS_TOKEN": "from-env",
                                          "HOME": str(home)}, clear=False):
                self.assertEqual(api_client.load_token(), "from-env")

    def test_file_used_when_env_unset(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".config" / "aegis").mkdir(parents=True)
            (home / ".config" / "aegis" / "token").write_text("file-token\n")
            with patch.dict(os.environ, {"HOME": str(home)}, clear=False):
                os.environ.pop("AEGIS_TOKEN", None)
                self.assertEqual(api_client.load_token(), "file-token")


if __name__ == "__main__":
    unittest.main()
