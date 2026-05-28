"""GitHub webhook signature + replay protection."""

import hashlib
import hmac
import json
import os
import unittest
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from aegis.api.app import create_app
from aegis.api.settings import APISettings


SECRET = "supersecret"


def _signed_body(payload: dict) -> tuple[bytes, str]:
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    return body, sig


class TestWebhookSignature(unittest.TestCase):
    def test_valid_signature_accepted(self):
        with patch.dict(os.environ,
                        {"AEGIS_GITHUB_WEBHOOK_SECRET": SECRET,
                         "AEGIS_ENV": "dev"},
                        clear=False):
            client = TestClient(create_app(APISettings()))
            body, sig = _signed_body({"action": "opened"})
            resp = client.post(
                "/v1/webhooks/github",
                content=body,
                headers={"X-Hub-Signature-256": sig,
                         "X-GitHub-Event": "pull_request",
                         "X-GitHub-Delivery": "evt-1"},
            )
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["event"], "pull_request")

    def test_invalid_signature_rejected(self):
        with patch.dict(os.environ,
                        {"AEGIS_GITHUB_WEBHOOK_SECRET": SECRET,
                         "AEGIS_ENV": "dev"},
                        clear=False):
            client = TestClient(create_app(APISettings()))
            resp = client.post(
                "/v1/webhooks/github",
                content=b"{}",
                headers={"X-Hub-Signature-256": "sha256=deadbeef",
                         "X-GitHub-Event": "ping",
                         "X-GitHub-Delivery": "evt-2"},
            )
            self.assertEqual(resp.status_code, 401)

    def test_replay_is_no_op(self):
        with patch.dict(os.environ,
                        {"AEGIS_GITHUB_WEBHOOK_SECRET": SECRET,
                         "AEGIS_ENV": "dev"},
                        clear=False):
            client = TestClient(create_app(APISettings()))
            body, sig = _signed_body({"action": "synchronize"})
            headers = {"X-Hub-Signature-256": sig,
                       "X-GitHub-Event": "pull_request",
                       "X-GitHub-Delivery": "evt-replay-1"}
            r1 = client.post("/v1/webhooks/github", content=body, headers=headers)
            r2 = client.post("/v1/webhooks/github", content=body, headers=headers)
            self.assertEqual(r1.status_code, 200)
            self.assertEqual(r2.status_code, 200)
            self.assertIn("replay", r2.json()["detail"])


if __name__ == "__main__":
    unittest.main()
