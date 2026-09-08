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
    from cryptography.fernet import Fernet, MultiFernet


class AuthProfilesKeyError(RuntimeError):
    """The auth-profile encryption key is missing or not a valid Fernet key."""


def _build_fernet(key: str | bytes, *, env_var: str) -> Fernet:
    """Construct a single ``Fernet`` from a key, with safe errors.

    Raised errors never echo the key material; ``env_var`` names the
    offending environment variable so a misconfigured *previous* key is
    distinguishable from the current one.
    """
    from cryptography.fernet import Fernet

    try:
        return Fernet(key.encode("utf-8") if isinstance(key, str) else key)
    except (ValueError, TypeError) as exc:
        # Deliberately does not echo the key material back.
        raise AuthProfilesKeyError(
            f"{env_var} is not a valid Fernet key "
            "(expected 32 url-safe base64-encoded bytes)"
        ) from exc


def _fernet(config: AegisConfig | None = None) -> MultiFernet:
    """Return the configured Fernet, wrapped for key rotation.

    Always a ``MultiFernet``: the current key first, then the previous
    key (``AEGIS_AUTH_PROFILES_KEY_PREVIOUS``) when configured. Encryption
    uses the first (current) key; decryption tries each in order, so
    ciphertext written under the previous key keeps resolving through a
    rotation overlap. Raises ``AuthProfilesKeyError`` if the current key
    is unset or either key is invalid.
    """
    from cryptography.fernet import MultiFernet

    cfg = config or load_config()
    key = cfg.auth_profiles_key
    if not key:
        raise AuthProfilesKeyError(
            "auth-profile encryption key is not configured: set the "
            "AEGIS_AUTH_PROFILES_KEY environment variable to a Fernet key "
            "(generate one with: python -c \"from cryptography.fernet import "
            "Fernet; print(Fernet.generate_key().decode())\")"
        )
    fernets = [_build_fernet(key, env_var="AEGIS_AUTH_PROFILES_KEY")]
    previous = cfg.auth_profiles_key_previous
    if previous:
        fernets.append(
            _build_fernet(previous, env_var="AEGIS_AUTH_PROFILES_KEY_PREVIOUS")
        )
    return MultiFernet(fernets)


def encrypt_secret(plaintext: str, *, config: AegisConfig | None = None) -> bytes:
    """Encrypt ``plaintext`` with the current auth-profiles key.

    Encryption always uses the current key (the first key of the
    rotation set). Raises ``AuthProfilesKeyError`` if the key is unset
    or invalid.
    """
    token: bytes = _fernet(config).encrypt(plaintext.encode("utf-8"))
    return token


def decrypt_secret(token: bytes, *, config: AegisConfig | None = None) -> str:
    """Decrypt a ``secret_ciphertext`` token back to the plaintext secret.

    Tries the current key then the previous key
    (``AEGIS_AUTH_PROFILES_KEY_PREVIOUS``) when one is configured, so
    ciphertext written before a rotation still decrypts. Raises
    ``AuthProfilesKeyError`` if the key is unset or invalid, and
    ``cryptography.fernet.InvalidToken`` if the token matches none of the
    configured keys.
    """
    plaintext: str = _fernet(config).decrypt(token).decode("utf-8")
    return plaintext
