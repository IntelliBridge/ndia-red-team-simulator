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


class TestLegacyTokenRejected(unittest.TestCase):
    """C1: the legacy non-expiring constant-payload token is gone.

    The Phase 3 demo token was ``worker:<HMAC("aegis-worker")>`` — no
    expiry, signed over a fixed string, and it granted ``is_system``.
    That branch was deleted; such a token must now be rejected.
    """

    @staticmethod
    def _legacy_token(secret: str) -> str:
        from hashlib import sha256
        from hmac import new as hmac_new
        legacy_sig = hmac_new(secret.encode(), b"aegis-worker", sha256).hexdigest()
        return f"worker:{legacy_sig}"

    def test_static_hmac_legacy_token_now_rejected(self):
        secret = "key-v1"
        token = self._legacy_token(secret)
        self.assertIsNone(
            _verify_worker_token(token, _settings(worker_signing_key=secret))
        )

    def test_legacy_token_rejected_even_with_matching_previous_key(self):
        # Rotation state should not resurrect the legacy path either.
        secret = "key-v1"
        token = self._legacy_token(secret)
        settings = _settings(
            worker_signing_key="key-v2",
            worker_signing_key_previous=secret,
            worker_signing_key_version=2,
        )
        self.assertIsNone(_verify_worker_token(token, settings))

    def test_legacy_token_does_not_grant_system_actor(self):
        # Guard the specific privilege the deleted branch handed out: a
        # constant-payload token must never resolve to a service:worker
        # / is_system identity.
        token = self._legacy_token("key-v1")
        user = _verify_worker_token(token, _settings(worker_signing_key="key-v1"))
        self.assertIsNone(user)


if __name__ == "__main__":
    unittest.main()
