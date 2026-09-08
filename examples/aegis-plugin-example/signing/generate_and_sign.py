#!/usr/bin/env python3
"""Regenerate the committed signing material for aegis-plugin-example.

This is the reproducible recipe that produced the checked-in ``keys/`` public
key and ``aegis-plugin-example-0.1.0.sig`` in this directory. It:

1. Generates a fresh Ed25519 keypair.
2. Writes the **public** key PEM into ``signing/keys/`` (committed; this is the
   trusted key an operator points ``AEGIS_PLUGINS_TRUSTED_KEYS`` at).
3. Signs the example's ``create_scanner`` factory with the **private** key via
   :func:`aegis.supply_chain.signing.sign_plugin_distribution`, writing the
   detached ``.sig`` next to the public key (committed).

The private key is written to a temp file and deleted — it is NEVER committed.
Run from the repo root with the example importable, e.g.::

    PYTHONPATH=examples/aegis-plugin-example \\
        python examples/aegis-plugin-example/signing/generate_and_sign.py

Equivalently, an author can sign with the CLI once their dist is installed::

    aegis plugins sign --dist aegis-plugin-example --version 0.1.0 \\
        --entry-point aegis.scanners:example --key privkey.pem \\
        --out examples/aegis-plugin-example/signing
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.supply_chain.signing import _key_id, sign_plugin_distribution

DIST = "aegis-plugin-example"
VERSION = "0.1.0"
HERE = Path(__file__).resolve().parent
KEYS_DIR = HERE / "keys"


def main() -> None:
    import sys

    sys.path.insert(0, str(HERE.parent))
    from aegis_plugin_example import create_scanner

    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    key_id = _key_id(public_key)

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_path = KEYS_DIR / f"{DIST}.pem"
    pub_path.write_bytes(pub_pem)

    with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=True) as tmp:
        tmp.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        tmp.flush()
        sig_path = sign_plugin_distribution(
            tmp.name, DIST, VERSION, create_scanner, HERE,
        )

    print(f"public key : {pub_path}")
    print(f"signature  : {sig_path}")
    print(f"key_id     : {key_id}")


if __name__ == "__main__":
    main()
