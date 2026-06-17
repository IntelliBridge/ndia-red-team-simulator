"""Fernet round-trip + key handling for ``aegis.security_utils.secrets``.

The encryption seam under the authenticated-DAST auth profiles: a
missing key must fail closed (no plaintext fallback) and key/secret
material must never leak into the raised error.
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

import pytest

pytest.importorskip("cryptography")

from cryptography.fernet import Fernet, InvalidToken

from aegis.security_utils.secrets import (
    AuthProfilesKeyError,
    decrypt_secret,
    encrypt_secret,
)


def _key_env(key: str | None) -> mock._patch_dict:
    env = dict(os.environ)
    env.pop("AEGIS_AUTH_PROFILES_KEY", None)
    if key is not None:
        env["AEGIS_AUTH_PROFILES_KEY"] = key
    return mock.patch.dict(os.environ, env, clear=True)


class TestFernetRoundTrip(unittest.TestCase):
    def test_round_trip_recovers_plaintext(self):
        key = Fernet.generate_key().decode()
        with _key_env(key):
            token = encrypt_secret("hunter2-super-secret")
            self.assertIsInstance(token, bytes)
            self.assertEqual(decrypt_secret(token), "hunter2-super-secret")

    def test_ciphertext_is_not_plaintext(self):
        key = Fernet.generate_key().decode()
        with _key_env(key):
            plaintext = "hunter2-super-secret"
            token = encrypt_secret(plaintext)
            self.assertNotEqual(token, plaintext.encode())
            self.assertNotIn(plaintext.encode(), token)

    def test_unicode_round_trip(self):
        key = Fernet.generate_key().decode()
        with _key_env(key):
            self.assertEqual(decrypt_secret(encrypt_secret("pässwörd…🔑")),
                             "pässwörd…🔑")

    def test_decrypt_with_wrong_key_raises_invalid_token(self):
        with _key_env(Fernet.generate_key().decode()):
            token = encrypt_secret("s3cret")
        with _key_env(Fernet.generate_key().decode()):
            with self.assertRaises(InvalidToken):
                decrypt_secret(token)


class TestMissingOrInvalidKey(unittest.TestCase):
    def test_encrypt_without_key_raises_clear_error(self):
        with _key_env(None):
            with self.assertRaises(AuthProfilesKeyError) as ctx:
                encrypt_secret("s3cret")
        message = str(ctx.exception)
        self.assertIn("AEGIS_AUTH_PROFILES_KEY", message)
        # No secret material in the error.
        self.assertNotIn("s3cret", message)

    def test_decrypt_without_key_raises_clear_error(self):
        with _key_env(None):
            with self.assertRaises(AuthProfilesKeyError):
                decrypt_secret(b"gAAAAA-not-a-real-token")

    def test_invalid_key_raises_without_echoing_key(self):
        with _key_env("not-a-fernet-key"):
            with self.assertRaises(AuthProfilesKeyError) as ctx:
                encrypt_secret("s3cret")
        message = str(ctx.exception)
        self.assertNotIn("not-a-fernet-key", message)
        self.assertNotIn("s3cret", message)


if __name__ == "__main__":
    unittest.main()
