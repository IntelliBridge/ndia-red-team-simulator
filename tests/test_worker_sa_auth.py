"""Phase 4 v0.3.1 FW — worker service-account auth split.

Worker tokens are now time-bound, versioned, and verifiable through a
rotation overlap window. The API accepts the current and the previous
key version; the actor surface is ``service:worker:<worker_id>``.
"""

from __future__ import annotations

import time
import unittest
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")

from aegis.api.auth import (
    _verify_worker_token,
    issue_worker_token,
)
from aegis.api.settings import APISettings


def _settings(**overrides) -> APISettings:
    base = dict(
        env="prod", auth_mode="oidc",
        worker_signing_key="key-v1",
        worker_signing_key_previous=None,
        worker_signing_key_version=1,
        worker_key_overlap_seconds=300,
        worker_token_ttl_seconds=300,
    )
    base.update(overrides)
    return APISettings(**base)


class TestIssueAndVerify(unittest.TestCase):
    def test_round_trip(self):
        settings = _settings()
        token = issue_worker_token("w1", settings=settings)
        self.assertTrue(token.startswith("worker:"))
        user = _verify_worker_token(token, settings)
        self.assertIsNotNone(user)
        self.assertEqual(user.sub, "service:worker:w1")
        self.assertTrue(user.is_system)

    def test_expired_token_rejected(self):
        settings = _settings()
        token = issue_worker_token("w1", settings=settings, ttl_seconds=1)
        # Force the clock forward by stubbing time.time inside auth
        with patch("aegis.api.auth.time.time",
                   return_value=time.time() + 10):
            self.assertIsNone(_verify_worker_token(token, settings))

    def test_tampered_signature_rejected(self):
        settings = _settings()
        token = issue_worker_token("w1", settings=settings)
        # Flip the last char of the signature
        bad = token[:-1] + ("0" if token[-1] != "0" else "1")
        self.assertIsNone(_verify_worker_token(bad, settings))


class TestKeyRotationOverlap(unittest.TestCase):
    def test_token_signed_with_previous_key_accepted_during_overlap(self):
        # Old worker still has v1 key; API has rotated to v2 with v1 as
        # the previous key. Token signed with v1 must verify until the
        # overlap window closes.
        old = _settings(worker_signing_key="key-v1",
                        worker_signing_key_version=1)
        new = _settings(worker_signing_key="key-v2",
                        worker_signing_key_previous="key-v1",
                        worker_signing_key_version=2)
        token = issue_worker_token("w1", settings=old)
        user = _verify_worker_token(token, new)
        self.assertIsNotNone(user)
        self.assertEqual(user.sub, "service:worker:w1")

    def test_token_signed_with_unknown_version_rejected(self):
        # An attacker who learns a key out of sequence (v3 against an API
        # running v2) must not pass — version is part of the signed
        # payload, so the API never even tries v3 keys.
        old = _settings(worker_signing_key="key-v3",
                        worker_signing_key_version=3)
        new = _settings(worker_signing_key="key-v2",
                        worker_signing_key_previous="key-v1",
                        worker_signing_key_version=2)
        token = issue_worker_token("w1", settings=old)
        self.assertIsNone(_verify_worker_token(token, new))


class TestLegacyTokenStillAccepted(unittest.TestCase):
    def test_static_hmac_legacy_path_works_during_transition(self):
        # The Phase 3 demo path: token is just the HMAC of "aegis-worker".
        from hashlib import sha256
        from hmac import new as hmac_new
        secret = "key-v1"
        legacy_sig = hmac_new(secret.encode(), b"aegis-worker", sha256).hexdigest()
        token = f"worker:{legacy_sig}"
        user = _verify_worker_token(token, _settings(worker_signing_key=secret))
        self.assertIsNotNone(user)
        self.assertEqual(user.sub, "service:worker:legacy")


if __name__ == "__main__":
    unittest.main()
