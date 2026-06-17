"""Optional Ed25519 signature verification for third-party marketplace plugins.

This module layers a *supply-chain* check onto the existing entry-point
marketplace loader (:meth:`aegis.registry.Registry.scan_entry_points`). It is
entirely opt-in: when ``AEGIS_PLUGINS_REQUIRE_SIGNATURE`` is enabled an operator
gets a :class:`KeyringVerifier`; otherwise :func:`load_plugin_verifier` returns
``None`` and the loader behaves exactly as before.

The contract
============

What gets signed
    A deterministic byte string produced by :func:`canonical_plugin_payload`:

    .. code-block:: text

        aegis-plugin\\n<dist_name>\\n<version>\\n<factory_module_sha256_hex>

    The trailing field is the SHA-256 (hex) of the *source file* that defines
    the plugin's factory (:func:`compute_factory_digest`). Binding the signature
    to the factory's module source means a signature can only authorise the code
    that actually runs — swap the implementation and the digest (and therefore
    the required signature) changes.

Signature file format + discovery
    A *detached* raw Ed25519 signature (64 bytes) is stored **hex-encoded** in a
    file named ``<dist_name>-<version>.sig`` (``<dist_name>.sig`` when the
    version is unknown). ``verify()`` searches the directories named by
    ``AEGIS_PLUGINS_SIG_DIR`` (colon/comma-separated), then the trusted-keys
    directories, then the factory module's own directory. The first readable
    ``.sig`` whose bytes decode (hex, with a base64 fallback) is used.

Trusted keys
    Ed25519 **public** keys in PEM form, named by ``AEGIS_PLUGINS_TRUSTED_KEYS``
    — a colon/comma-separated list of ``*.pem`` file paths and/or directories of
    ``*.pem`` files. The signature must verify under at least one of them.

A successful :meth:`KeyringVerifier.verify` returns ``verified=True`` with
``key_id`` set to the SHA-256 (hex) of the matching public key's raw bytes; a
failure returns ``verified=False`` with a concise, material-free ``reason``.
Key bytes and signature bytes are NEVER logged — only ``key_id`` digests and
reasons.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import inspect
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _CRYPTOGRAPHY_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - signing is an optional api-extra feature
    # ``cryptography`` ships in the api/worker extras. With signature
    # enforcement off (the default) the marketplace loader must still work
    # without it, so importing this module never hard-requires cryptography;
    # only actually signing/verifying does.
    _CRYPTOGRAPHY_AVAILABLE = False

logger = logging.getLogger(__name__)

# Env var names (kept in sync with aegis.config for discoverability/docs).
ENV_REQUIRE_SIGNATURE = "AEGIS_PLUGINS_REQUIRE_SIGNATURE"
ENV_TRUSTED_KEYS = "AEGIS_PLUGINS_TRUSTED_KEYS"
ENV_SIG_DIR = "AEGIS_PLUGINS_SIG_DIR"

_PAYLOAD_PREFIX = b"aegis-plugin"


@dataclass(frozen=True)
class SignatureResult:
    """Outcome of verifying one plugin's signature.

    ``verified`` is True only when a detached signature checked out against a
    trusted key. ``key_id`` is the SHA-256 (hex) of the matching public key on
    success, else ``None``. ``reason`` is a short, material-free explanation
    suitable for logs and the ``aegis plugins list`` report.
    """

    verified: bool
    key_id: str | None
    reason: str


@runtime_checkable
class PluginVerifier(Protocol):
    """Verifies that a plugin distribution carries a trusted signature."""

    def verify(self, dist_name: str, version: str | None, factory: object) -> SignatureResult: ...


# ---------------------------------------------------------------------------
# Canonical payload + factory digest
# ---------------------------------------------------------------------------

def canonical_plugin_payload(
    dist_name: str, version: str | None, factory_module_digest: str
) -> bytes:
    """Return the deterministic bytes that a plugin signature covers.

    Format (newline-separated, UTF-8)::

        aegis-plugin\\n<dist_name>\\n<version>\\n<factory_module_digest>

    ``version`` is rendered as the empty string when ``None`` so the layout is
    fixed-arity. ``factory_module_digest`` is the SHA-256 hex of the factory's
    module source (see :func:`compute_factory_digest`).
    """
    parts = [
        _PAYLOAD_PREFIX.decode(),
        dist_name,
        version or "",
        factory_module_digest,
    ]
    return "\n".join(parts).encode("utf-8")


def compute_factory_digest(factory: object) -> str:
    """SHA-256 (hex) over the source file bytes of ``factory``'s module.

    Prefers ``inspect.getsourcefile`` (the on-disk ``.py``); falls back to the
    module's ``__file__`` and finally to ``inspect.getsource`` text. The digest
    binds a signature to the actual code that will run — change the module and
    the digest changes, invalidating any prior signature.
    """
    source_bytes = _factory_source_bytes(factory)
    return hashlib.sha256(source_bytes).hexdigest()


def _factory_source_bytes(factory: object) -> bytes:
    path: str | None = None
    try:
        path = inspect.getsourcefile(factory)  # type: ignore[arg-type]
    except (TypeError, OSError):
        path = None
    if path is None:
        module = inspect.getmodule(factory)
        path = getattr(module, "__file__", None)
    if path:
        try:
            return Path(path).read_bytes()
        except OSError:
            pass
    # Last resort: the textual source of the object itself.
    return inspect.getsource(factory).encode("utf-8")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Path / env parsing helpers
# ---------------------------------------------------------------------------

def _split_paths(raw: str | None) -> list[str]:
    """Split a colon/comma-separated path list, dropping blanks."""
    if not raw:
        return []
    out: list[str] = []
    for chunk in raw.replace(",", ":").split(":"):
        chunk = chunk.strip()
        if chunk:
            out.append(chunk)
    return out


def _key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def _load_trusted_keys(raw: str | None) -> list[tuple[str, Ed25519PublicKey]]:
    """Load ``(key_id, public_key)`` pairs from PEM files/dirs in ``raw``.

    Non-Ed25519 or unparseable PEMs are skipped with a material-free warning so
    one bad key file never aborts discovery.
    """
    pem_files: list[Path] = []
    for entry in _split_paths(raw):
        p = Path(entry)
        if p.is_dir():
            pem_files.extend(sorted(p.glob("*.pem")))
        elif p.is_file():
            pem_files.append(p)
    keys: list[tuple[str, Ed25519PublicKey]] = []
    seen: set[str] = set()
    for pem in pem_files:
        try:
            data = pem.read_bytes()
            key = serialization.load_pem_public_key(data)
        except (OSError, ValueError):
            logger.warning("skipping unreadable/invalid trusted key file %s", pem.name)
            continue
        if not isinstance(key, Ed25519PublicKey):
            logger.warning("skipping non-Ed25519 trusted key file %s", pem.name)
            continue
        kid = _key_id(key)
        if kid in seen:
            continue
        seen.add(kid)
        keys.append((kid, key))
    return keys


def _decode_signature(text: str) -> bytes | None:
    """Decode a ``.sig`` body as hex, falling back to base64. ``None`` on fail."""
    stripped = "".join(text.split())
    if not stripped:
        return None
    try:
        return binascii.unhexlify(stripped)
    except (binascii.Error, ValueError):
        pass
    try:
        return base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return None


def _sig_filename(dist_name: str, version: str | None) -> str:
    return f"{dist_name}-{version}.sig" if version else f"{dist_name}.sig"


def _factory_dir(factory: object) -> Path | None:
    try:
        src = inspect.getsourcefile(factory)  # type: ignore[arg-type]
    except (TypeError, OSError):
        src = None
    if src is None:
        module = inspect.getmodule(factory)
        src = getattr(module, "__file__", None)
    return Path(src).parent if src else None


# ---------------------------------------------------------------------------
# Keyring verifier
# ---------------------------------------------------------------------------

class KeyringVerifier:
    """Verifies detached Ed25519 plugin signatures against trusted public keys.

    ``trusted_keys_raw`` / ``sig_dirs_raw`` default to the
    ``AEGIS_PLUGINS_TRUSTED_KEYS`` / ``AEGIS_PLUGINS_SIG_DIR`` env vars (read at
    construction, mirroring the storage layer). The trusted-key directories are
    always appended to the signature search path so a key+sig pair shipped in
    one directory works without extra configuration.
    """

    def __init__(
        self,
        *,
        trusted_keys_raw: str | None = None,
        sig_dirs_raw: str | None = None,
    ) -> None:
        if trusted_keys_raw is None:
            trusted_keys_raw = os.environ.get(ENV_TRUSTED_KEYS)
        if sig_dirs_raw is None:
            sig_dirs_raw = os.environ.get(ENV_SIG_DIR)
        self._trusted_keys_raw = trusted_keys_raw
        self._sig_dirs_raw = sig_dirs_raw
        self._keys = _load_trusted_keys(trusted_keys_raw)

    def _signature_dirs(self, factory: object) -> list[Path]:
        dirs: list[Path] = [Path(p) for p in _split_paths(self._sig_dirs_raw)]
        # Trusted-key directories (and the parent dir of each key file) are
        # implicit signature locations so a self-contained key+sig dir works.
        for entry in _split_paths(self._trusted_keys_raw):
            p = Path(entry)
            dirs.append(p if p.is_dir() else p.parent)
        fdir = _factory_dir(factory)
        if fdir is not None:
            dirs.append(fdir)
        # De-dupe while preserving order.
        seen: set[str] = set()
        unique: list[Path] = []
        for d in dirs:
            key = str(d)
            if key not in seen:
                seen.add(key)
                unique.append(d)
        return unique

    def _find_signature(
        self, dist_name: str, version: str | None, factory: object
    ) -> bytes | None:
        fname = _sig_filename(dist_name, version)
        for d in self._signature_dirs(factory):
            candidate = d / fname
            try:
                if candidate.is_file():
                    decoded = _decode_signature(candidate.read_text())
                    if decoded is not None:
                        return decoded
            except OSError:
                continue
        return None

    def verify(
        self, dist_name: str, version: str | None, factory: object
    ) -> SignatureResult:
        """Verify the detached signature for ``dist_name``/``version``.

        Recomputes :func:`canonical_plugin_payload` (binding the digest of the
        factory's module source) and checks the discovered signature against
        each trusted key. Returns ``verified=True`` with the matching key_id on
        success, else ``verified=False`` with a concise reason.
        """
        if not self._keys:
            return SignatureResult(False, None, "no trusted keys")

        signature = self._find_signature(dist_name, version, factory)
        if signature is None:
            return SignatureResult(False, None, "no signature found")

        digest = compute_factory_digest(factory)
        payload = canonical_plugin_payload(dist_name, version, digest)

        for kid, key in self._keys:
            try:
                key.verify(signature, payload)
            except InvalidSignature:
                continue
            return SignatureResult(True, kid, "signature verified")
        return SignatureResult(False, None, "signature does not verify")


# ---------------------------------------------------------------------------
# Loader entry point
# ---------------------------------------------------------------------------

def _enforcement_enabled(config: object | None) -> bool:
    env = os.environ.get(ENV_REQUIRE_SIGNATURE)
    if env is not None:
        return env.strip() in ("1", "true", "True", "yes", "on")
    if config is not None:
        return bool(getattr(config, "plugins_require_signature", False))
    return False


def load_plugin_verifier(config: object | None = None) -> PluginVerifier | None:
    """Return a :class:`KeyringVerifier` when enforcement is on, else ``None``.

    Enforcement is enabled by ``AEGIS_PLUGINS_REQUIRE_SIGNATURE`` (``1``/truthy)
    or, when the env var is unset, the ``plugins_require_signature`` config flag.
    When enforcement is off the loader's behaviour is unchanged (no verifier).
    """
    if not _enforcement_enabled(config):
        return None
    if not _CRYPTOGRAPHY_AVAILABLE:  # pragma: no cover - misconfig: enforcement on, no crypto
        raise RuntimeError(
            "plugin signature enforcement is enabled but the 'cryptography' "
            "package is not installed; install the api or worker extra to verify "
            "plugin signatures (or unset AEGIS_PLUGINS_REQUIRE_SIGNATURE)"
        )
    trusted_raw = None
    sig_raw = None
    if config is not None:
        trusted_raw = getattr(config, "plugins_trusted_keys", None)
        sig_raw = getattr(config, "plugins_sig_dir", None)
    return KeyringVerifier(trusted_keys_raw=trusted_raw, sig_dirs_raw=sig_raw)


# ---------------------------------------------------------------------------
# Signer (used by `aegis plugins sign`, tests, and to sign the example)
# ---------------------------------------------------------------------------

def sign_plugin_distribution(
    private_key_pem_path: str | os.PathLike[str],
    dist_name: str,
    version: str | None,
    factory: object,
    out_path: str | os.PathLike[str],
) -> Path:
    """Sign a plugin distribution and write the detached ``.sig`` file.

    Loads the Ed25519 **private** key (PEM) at ``private_key_pem_path``, signs
    :func:`canonical_plugin_payload` for the given dist/version/factory, and
    writes the hex-encoded raw signature. ``out_path`` may be a directory (the
    canonical ``<dist>-<version>.sig`` filename is used) or an explicit file
    path. Returns the path written.
    """
    key_bytes = Path(private_key_pem_path).read_bytes()
    private_key = serialization.load_pem_private_key(key_bytes, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("private key is not an Ed25519 key")

    digest = compute_factory_digest(factory)
    payload = canonical_plugin_payload(dist_name, version, digest)
    signature = private_key.sign(payload)

    out = Path(out_path)
    if out.is_dir() or (not out.suffix and not out.exists()):
        out.mkdir(parents=True, exist_ok=True)
        out = out / _sig_filename(dist_name, version)
    else:
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(binascii.hexlify(signature).decode("ascii") + "\n")
    return out
