"""Fernet encryption for DAST auth-profile secrets at rest.

The key comes from ``AegisConfig.auth_profiles_key`` (env
``AEGIS_AUTH_PROFILES_KEY``). Encryption is symmetric and process-local:
the API encrypts on admission, the worker decrypts via
``services.auth_profiles.resolve_auth_for_scan`` just before use.

Invariants:

- No plaintext secret and no key material ever appears in an exception
  message or a log line raised from this module.
- A missing/unusable key raises ``AuthProfilesKeyError`` — there is no
  silent plaintext fallback.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from aegis.config import AegisConfig, load_config

if TYPE_CHECKING:
    from cryptography.fernet import Fernet


class AuthProfilesKeyError(RuntimeError):
    """The auth-profile encryption key is missing or not a valid Fernet key."""


def _fernet(config: AegisConfig | None = None) -> Fernet:
    from cryptography.fernet import Fernet

    cfg = config or load_config()
    key = cfg.auth_profiles_key
    if not key:
        raise AuthProfilesKeyError(
            "auth-profile encryption key is not configured: set the "
            "AEGIS_AUTH_PROFILES_KEY environment variable to a Fernet key "
            "(generate one with: python -c \"from cryptography.fernet import "
            "Fernet; print(Fernet.generate_key().decode())\")"
        )
    try:
        return Fernet(key.encode("utf-8") if isinstance(key, str) else key)
    except (ValueError, TypeError) as exc:
        # Deliberately does not echo the key material back.
        raise AuthProfilesKeyError(
            "AEGIS_AUTH_PROFILES_KEY is not a valid Fernet key "
            "(expected 32 url-safe base64-encoded bytes)"
        ) from exc


def encrypt_secret(plaintext: str, *, config: AegisConfig | None = None) -> bytes:
    """Encrypt ``plaintext`` with the configured auth-profiles key.

    Raises ``AuthProfilesKeyError`` if the key is unset or invalid.
    """
    token: bytes = _fernet(config).encrypt(plaintext.encode("utf-8"))
    return token


def decrypt_secret(token: bytes, *, config: AegisConfig | None = None) -> str:
    """Decrypt a ``secret_ciphertext`` token back to the plaintext secret.

    Raises ``AuthProfilesKeyError`` if the key is unset or invalid, and
    ``cryptography.fernet.InvalidToken`` if the token was not produced by
    the configured key (e.g. after an unmanaged key rotation).
    """
    plaintext: str = _fernet(config).decrypt(token).decode("utf-8")
    return plaintext
