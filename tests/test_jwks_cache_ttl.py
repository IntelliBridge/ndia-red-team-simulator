"""C1 — time-boxed JWKS cache.

The OIDC JWKS document used to be cached for the whole process lifetime
via ``functools.lru_cache`` and only refreshed on restart, so an IdP
signing key that had been rotated out kept being accepted indefinitely.
The cache is now time-boxed: an entry is reused only while it is younger
than ``api_jwks_cache_ttl_seconds`` (default 300), after which it is
refetched. These tests pin that behaviour without any network.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("httpx")

from redsim.api.auth import _jwks_cache, _JwksCache
from redsim.api.settings import APISettings


def _counting_httpx(payload: dict[str, object]) -> tuple[MagicMock, MagicMock]:
    """Return a (Client-factory, response) pair that counts fetches.

    The factory is suitable for ``patch("httpx.Client", ...)``; each
    ``client.get(...)`` returns the same response whose ``json()`` yields
    ``payload``. ``response.call_count`` (on the underlying ``get``)
    reflects how many network fetches happened.
    """
    resp = MagicMock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    client = MagicMock()
    client.__enter__.return_value = client
    client.get.return_value = resp
    return MagicMock(return_value=client), client


class TestJwksCacheTtl(unittest.TestCase):
    def setUp(self) -> None:
        # Module-level cache is shared; isolate each test.
        _jwks_cache.cache_clear()
        self.addCleanup(_jwks_cache.cache_clear)

    def test_served_from_cache_within_ttl(self):
        cache = _JwksCache()
        factory, client = _counting_httpx({"keys": ["a"]})
        with patch("httpx.Client", factory):
            with patch("redsim.api.auth.time.time", return_value=1000.0):
                first = cache("https://idp/jwks", 300)
                # Well within the 300s window → no refetch.
                with patch("redsim.api.auth.time.time", return_value=1200.0):
                    second = cache("https://idp/jwks", 300)
        self.assertEqual(first, {"keys": ["a"]})
        self.assertEqual(second, {"keys": ["a"]})
        self.assertEqual(client.get.call_count, 1)

    def test_refetched_after_ttl_elapses(self):
        cache = _JwksCache()
        factory, client = _counting_httpx({"keys": ["a"]})
        with patch("httpx.Client", factory):
            with patch("redsim.api.auth.time.time", return_value=1000.0):
                cache("https://idp/jwks", 300)
            # 301s later — strictly past the window → refetch.
            with patch("redsim.api.auth.time.time", return_value=1301.0):
                cache("https://idp/jwks", 300)
        self.assertEqual(client.get.call_count, 2)

    def test_boundary_exactly_at_ttl_refetches(self):
        # now - fetched_at == ttl is NOT < ttl, so it must refetch.
        cache = _JwksCache()
        factory, client = _counting_httpx({"keys": ["a"]})
        with patch("httpx.Client", factory):
            with patch("redsim.api.auth.time.time", return_value=1000.0):
                cache("https://idp/jwks", 300)
            with patch("redsim.api.auth.time.time", return_value=1300.0):
                cache("https://idp/jwks", 300)
        self.assertEqual(client.get.call_count, 2)

    def test_distinct_urls_cached_independently(self):
        cache = _JwksCache()
        factory, client = _counting_httpx({"keys": []})
        with patch("httpx.Client", factory):
            with patch("redsim.api.auth.time.time", return_value=1000.0):
                cache("https://idp-a/jwks", 300)
                cache("https://idp-b/jwks", 300)
                # Re-request A inside its window → still cached.
                cache("https://idp-a/jwks", 300)
        self.assertEqual(client.get.call_count, 2)

    def test_cache_clear_forces_refetch(self):
        cache = _JwksCache()
        factory, client = _counting_httpx({"keys": ["a"]})
        with patch("httpx.Client", factory):
            with patch("redsim.api.auth.time.time", return_value=1000.0):
                cache("https://idp/jwks", 300)
                cache.cache_clear()
                cache("https://idp/jwks", 300)
        self.assertEqual(client.get.call_count, 2)

    def test_verify_jwt_uses_settings_ttl(self):
        # End-to-end: _verify_jwt threads the configured TTL into the
        # shared cache. With a tiny TTL the second decode refetches.
        from authlib.jose import JoseError

        settings = APISettings(
            env="prod", auth_mode="oidc",
            oidc_jwks_url="https://idp/jwks",
            oidc_audience="redsim",
            api_jwks_cache_ttl_seconds=10,
        )
        factory, client = _counting_httpx({"keys": []})
        # jwt.decode raises so we exercise only the fetch/cache path; the
        # token itself never needs to be valid.
        with patch("httpx.Client", factory), \
                patch("authlib.jose.jwt.decode", side_effect=JoseError("x")):
            from fastapi import HTTPException

            from redsim.api.auth import _verify_jwt
            with patch("redsim.api.auth.time.time", return_value=5000.0):
                with self.assertRaises(HTTPException):
                    _verify_jwt("tok", settings)
            # 11s later → past the 10s TTL → refetch.
            with patch("redsim.api.auth.time.time", return_value=5011.0):
                with self.assertRaises(HTTPException):
                    _verify_jwt("tok", settings)
        self.assertEqual(client.get.call_count, 2)


if __name__ == "__main__":
    unittest.main()
