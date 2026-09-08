"""Offline-safe tests for optional plugin signature verification.

Mirrors ``tests/test_plugin_marketplace.py``'s fake-EntryPoint + registry-state
isolation harness. Everything is monkeypatched: keypairs are generated in-test,
no real install, no network. Global state is always restored -- ``os.environ``
via ``patch.dict`` and any fake we register is popped from the live
``_REGISTRY`` backing dict via ``addCleanup``.

Exercises:
- ``SignatureResult`` round-trip via ``sign_plugin_distribution`` /
  ``KeyringVerifier`` (verify True; tampered/wrong-key/missing-sig -> False).
- ``compute_factory_digest`` stability + sensitivity to module source.
- Loader enforcement (signed loads + carries key_id; unsigned rejected + not
  registered; one bad plugin doesn't block a signed sibling; enforcement OFF =
  back-compat).
- ``aegis plugins list`` SIGNED column + ``aegis plugins sign`` round-trip.
- The committed example's public key verifies the committed example ``.sig``.
- The signature gate and the sandbox wrapper compose through the real eager
  loader (signed -> registered as a ``SandboxedScanner``; unsigned -> nothing
  registered).
"""

from __future__ import annotations

import importlib
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aegis.scanners.registry as scanner_registry
from aegis.supply_chain.signing import (
    ENV_REQUIRE_SIGNATURE,
    ENV_SIG_DIR,
    ENV_TRUSTED_KEYS,
    KeyringVerifier,
    SignatureResult,
    canonical_plugin_payload,
    compute_factory_digest,
    load_plugin_verifier,
    sign_plugin_distribution,
)

EXAMPLE_DIR = Path(__file__).resolve().parents[1] / "examples" / "aegis-plugin-example"
EXAMPLE_SIGNING = EXAMPLE_DIR / "signing"


# ---------------------------------------------------------------------------
# Fakes (mirrors the marketplace harness)
# ---------------------------------------------------------------------------

class FakeScanner:
    """Minimal conformant ScannerAdapter."""

    def __init__(self, name="fake-sig-scanner"):
        self.name = name
        self.capabilities = {"dast"}
        self.default_timeout = 60

    def adapter_version(self):
        return "0.0.0-fake"

    def health_check(self):
        return True

    def scan(self, run_state, options):  # pragma: no cover - never invoked
        raise NotImplementedError


def fake_scanner_factory():
    """Module-level factory so its source file is stable and signable."""
    return FakeScanner()


def fake_scanner_factory_unsigned():
    return FakeScanner(name="unsigned-sig-scanner")


def _fake_ep(name, factory, *, dist_name=None, version=None):
    dist = None
    if dist_name is not None:
        dist = SimpleNamespace(name=dist_name, version=version)
    return SimpleNamespace(name=name, load=lambda: factory, dist=dist)


def _write_keypair(tmp: Path) -> tuple[Path, Path]:
    """Generate an Ed25519 keypair; write private + public PEM. Return paths."""
    priv = Ed25519PrivateKey.generate()
    priv_path = tmp / "priv.pem"
    pub_path = tmp / "pub.pem"
    priv_path.write_bytes(priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    pub_path.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return priv_path, pub_path


# ---------------------------------------------------------------------------
# SignatureResult round-trip + payload/digest primitives
# ---------------------------------------------------------------------------

class TestSignRoundTrip(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.priv, self.pub = _write_keypair(self.tmp)

    def test_signed_payload_verifies_true(self):
        sig_path = sign_plugin_distribution(
            self.priv, "d", "1.0", fake_scanner_factory, self.tmp)
        self.assertTrue(sig_path.exists())
        verifier = KeyringVerifier(
            trusted_keys_raw=str(self.pub), sig_dirs_raw=str(self.tmp))
        result = verifier.verify("d", "1.0", fake_scanner_factory)
        self.assertIsInstance(result, SignatureResult)
        self.assertTrue(result.verified, result.reason)
        self.assertIsNotNone(result.key_id)
        self.assertEqual(len(result.key_id), 64)  # sha256 hex

    def test_wrong_key_does_not_verify(self):
        sign_plugin_distribution(self.priv, "d", "1.0", fake_scanner_factory, self.tmp)
        # A foreign trusted key (distinct dir) -> signature does not verify.
        with tempfile.TemporaryDirectory() as d2:
            _, foreign_pub = _write_keypair(Path(d2))
            verifier = KeyringVerifier(
                trusted_keys_raw=str(foreign_pub), sig_dirs_raw=str(self.tmp))
            result = verifier.verify("d", "1.0", fake_scanner_factory)
        self.assertFalse(result.verified)
        self.assertIn("does not verify", result.reason)

    def test_tampered_payload_does_not_verify(self):
        # Sign for version 1.0 but verify a different version -> payload differs.
        sign_plugin_distribution(self.priv, "d", "1.0", fake_scanner_factory, self.tmp)
        # Rename so discovery finds it for version 2.0, forcing a payload mismatch.
        (self.tmp / "d-1.0.sig").rename(self.tmp / "d-2.0.sig")
        verifier = KeyringVerifier(
            trusted_keys_raw=str(self.pub), sig_dirs_raw=str(self.tmp))
        result = verifier.verify("d", "2.0", fake_scanner_factory)
        self.assertFalse(result.verified)
        self.assertIn("does not verify", result.reason)

    def test_missing_signature_reason(self):
        verifier = KeyringVerifier(
            trusted_keys_raw=str(self.pub), sig_dirs_raw=str(self.tmp))
        result = verifier.verify("d", "1.0", fake_scanner_factory)
        self.assertFalse(result.verified)
        self.assertEqual(result.reason, "no signature found")

    def test_no_trusted_keys_reason(self):
        verifier = KeyringVerifier(trusted_keys_raw=None, sig_dirs_raw=str(self.tmp))
        result = verifier.verify("d", "1.0", fake_scanner_factory)
        self.assertFalse(result.verified)
        self.assertEqual(result.reason, "no trusted keys")

    def test_trusted_keys_directory_is_searched(self):
        """A directory of *.pem keys (not just file paths) is honoured."""
        sign_plugin_distribution(self.priv, "d", "1.0", fake_scanner_factory, self.tmp)
        # Move the public key into a dedicated keys/ dir and point at the dir.
        keys_dir = self.tmp / "keys"
        keys_dir.mkdir()
        (keys_dir / "trusted.pem").write_bytes(self.pub.read_bytes())
        verifier = KeyringVerifier(
            trusted_keys_raw=str(keys_dir), sig_dirs_raw=str(self.tmp))
        self.assertTrue(verifier.verify("d", "1.0", fake_scanner_factory).verified)


class TestPrimitives(unittest.TestCase):
    def test_canonical_payload_format(self):
        payload = canonical_plugin_payload("mydist", "2.3", "deadbeef")
        self.assertEqual(payload, b"aegis-plugin\nmydist\n2.3\ndeadbeef")

    def test_canonical_payload_none_version(self):
        payload = canonical_plugin_payload("mydist", None, "abc")
        self.assertEqual(payload, b"aegis-plugin\nmydist\n\nabc")

    def test_factory_digest_stable(self):
        d1 = compute_factory_digest(fake_scanner_factory)
        d2 = compute_factory_digest(fake_scanner_factory)
        self.assertEqual(d1, d2)
        self.assertEqual(len(d1), 64)

    def test_factory_digest_differs_for_different_module_source(self):
        """Two factories defined in different module source files differ."""
        # The example's create_scanner lives in a different source file.
        inserted = str(EXAMPLE_DIR)
        if inserted not in sys.path:
            sys.path.insert(0, inserted)
            self.addCleanup(sys.path.remove, inserted)
        mod = importlib.import_module("aegis_plugin_example")
        self.addCleanup(sys.modules.pop, "aegis_plugin_example", None)
        example_digest = compute_factory_digest(mod.create_scanner)
        local_digest = compute_factory_digest(fake_scanner_factory)
        self.assertNotEqual(example_digest, local_digest)


# ---------------------------------------------------------------------------
# load_plugin_verifier — enforcement toggle
# ---------------------------------------------------------------------------

class TestVerifierToggle(unittest.TestCase):
    def test_off_by_default(self):
        env = {k: v for k, v in os.environ.items() if k != ENV_REQUIRE_SIGNATURE}
        with patch.dict(os.environ, env, clear=True):
            self.assertIsNone(load_plugin_verifier())

    def test_env_enables_verifier(self):
        with patch.dict(os.environ, {ENV_REQUIRE_SIGNATURE: "1"}):
            self.assertIsInstance(load_plugin_verifier(), KeyringVerifier)

    def test_config_flag_enables_verifier(self):
        env = {k: v for k, v in os.environ.items() if k != ENV_REQUIRE_SIGNATURE}
        cfg = SimpleNamespace(
            plugins_require_signature=True,
            plugins_trusted_keys=None, plugins_sig_dir=None)
        with patch.dict(os.environ, env, clear=True):
            self.assertIsInstance(load_plugin_verifier(cfg), KeyringVerifier)


# ---------------------------------------------------------------------------
# Loader enforcement via scan_entry_points(verifier=...)
# ---------------------------------------------------------------------------

class TestLoaderEnforcement(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.priv, self.pub = _write_keypair(self.tmp)
        # Sign the signed factory's distribution.
        sign_plugin_distribution(self.priv, "signed-dist", "1", fake_scanner_factory, self.tmp)
        self.addCleanup(scanner_registry._REGISTRY.pop, "fake-sig-scanner", None)
        self.addCleanup(scanner_registry._REGISTRY.pop, "unsigned-sig-scanner", None)

    def _verifier(self):
        return KeyringVerifier(
            trusted_keys_raw=str(self.pub), sig_dirs_raw=str(self.tmp))

    def test_signed_loads_with_key_id(self):
        ep = _fake_ep("signed", fake_scanner_factory,
                      dist_name="signed-dist", version="1")
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "aegis.scanners" else []):
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "aegis.scanners", register=True, verifier=self._verifier()))
        row = report[0]
        self.assertEqual(row.status, "loaded")
        self.assertIsNotNone(row.signature)
        self.assertEqual(len(row.signature), 64)
        self.assertIn("fake-sig-scanner", scanner_registry._REGISTRY)

    def test_unsigned_rejected_and_not_registered(self):
        ep = _fake_ep("unsigned", fake_scanner_factory_unsigned,
                      dist_name="unsigned-dist", version="1")
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "aegis.scanners" else []):
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "aegis.scanners", register=True, verifier=self._verifier()))
        row = report[0]
        self.assertEqual(row.status, "rejected")
        self.assertIn("no signature found", row.detail)
        self.assertNotIn("unsigned-sig-scanner", scanner_registry._REGISTRY)

    def test_one_unsigned_does_not_block_signed_sibling(self):
        eps = [
            _fake_ep("unsigned", fake_scanner_factory_unsigned,
                     dist_name="unsigned-dist", version="1"),
            _fake_ep("signed", fake_scanner_factory,
                     dist_name="signed-dist", version="1"),
        ]
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: eps if group == "aegis.scanners" else []):
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "aegis.scanners", register=True, verifier=self._verifier()))
        by_name = {r.name: r for r in report}
        self.assertEqual(by_name["unsigned"].status, "rejected")
        self.assertEqual(by_name["fake-sig-scanner"].status, "loaded")
        self.assertNotIn("unsigned-sig-scanner", scanner_registry._REGISTRY)
        self.assertIn("fake-sig-scanner", scanner_registry._REGISTRY)

    def test_enforcement_off_both_load(self):
        """With verifier=None (enforcement off) signed + unsigned both load."""
        eps = [
            _fake_ep("unsigned", fake_scanner_factory_unsigned,
                     dist_name="unsigned-dist", version="1"),
            _fake_ep("signed", fake_scanner_factory,
                     dist_name="signed-dist", version="1"),
        ]
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: eps if group == "aegis.scanners" else []):
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "aegis.scanners", register=True, verifier=None))
        # Loaded rows report the adapter's own ``name`` (not the EP name).
        statuses = {r.name: r.status for r in report}
        self.assertEqual(statuses["unsigned-sig-scanner"], "loaded")
        self.assertEqual(statuses["fake-sig-scanner"], "loaded")
        # signature column is None when enforcement is off.
        self.assertTrue(all(r.signature is None for r in report))


# ---------------------------------------------------------------------------
# CLI: `aegis plugins list` SIGNED column + `aegis plugins sign`
# ---------------------------------------------------------------------------

class TestPluginsCli(unittest.TestCase):
    def test_list_shows_signed_column(self):
        from aegis.cli.main import main
        ep = _fake_ep("example", fake_scanner_factory,
                      dist_name="fake-dist", version="9.9.9")
        buf = io.StringIO()
        with patch.dict(os.environ, {"AEGIS_PLUGINS": "1"}), \
                patch("aegis.config.load_config"), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "aegis.scanners" else []), \
                redirect_stdout(buf):
            main(["plugins", "list"])
        out = buf.getvalue()
        self.assertIn("SIGNED", out)
        self.assertIn("fake-sig-scanner", out)

    def test_sign_then_verify_round_trip_via_cli(self):

        from aegis.cli.main import main
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            priv, pub = _write_keypair(tmp)
            ep = _fake_ep("example", fake_scanner_factory,
                          dist_name="cli-dist", version="3.0")
            buf = io.StringIO()
            with patch.dict(os.environ, {}, clear=False), \
                    patch("aegis.config.load_config"), \
                    patch("importlib.metadata.entry_points",
                          side_effect=lambda group: [ep] if group == "aegis.scanners" else []), \
                    redirect_stdout(buf):
                main(["plugins", "sign", "--dist", "cli-dist", "--version", "3.0",
                      "--entry-point", "aegis.scanners:example",
                      "--key", str(priv), "--out", str(tmp)])
            out = buf.getvalue()
            self.assertIn("wrote signature", out)
            self.assertIn("key_id", out)
            # The produced .sig verifies.
            verifier = KeyringVerifier(
                trusted_keys_raw=str(pub), sig_dirs_raw=str(tmp))
            self.assertTrue(
                verifier.verify("cli-dist", "3.0", fake_scanner_factory).verified)


# ---------------------------------------------------------------------------
# Committed example: the shipped public key verifies the shipped .sig
# ---------------------------------------------------------------------------

class TestCommittedExampleSigned(unittest.TestCase):
    def test_example_public_key_verifies_example_signature(self):
        inserted = str(EXAMPLE_DIR)
        if inserted not in sys.path:
            sys.path.insert(0, inserted)
            self.addCleanup(sys.path.remove, inserted)
        mod = importlib.import_module("aegis_plugin_example")
        self.addCleanup(sys.modules.pop, "aegis_plugin_example", None)

        keys_dir = EXAMPLE_SIGNING / "keys"
        verifier = KeyringVerifier(
            trusted_keys_raw=str(keys_dir), sig_dirs_raw=str(EXAMPLE_SIGNING))
        result = verifier.verify("aegis-plugin-example", "0.1.0", mod.create_scanner)
        self.assertTrue(result.verified, result.reason)
        self.assertIsNotNone(result.key_id)

    def test_example_loader_enforcement_loads_it(self):
        """End-to-end: enforcement on + committed key -> example loads signed."""
        self.addCleanup(scanner_registry._REGISTRY.pop, "example", None)
        inserted = str(EXAMPLE_DIR)
        if inserted not in sys.path:
            sys.path.insert(0, inserted)
            self.addCleanup(sys.path.remove, inserted)
        mod = importlib.import_module("aegis_plugin_example")
        self.addCleanup(sys.modules.pop, "aegis_plugin_example", None)
        ep = _fake_ep("example", mod.create_scanner,
                      dist_name="aegis-plugin-example", version="0.1.0")
        env = {
            "AEGIS_PLUGINS": "1",
            ENV_REQUIRE_SIGNATURE: "1",
            ENV_TRUSTED_KEYS: str(EXAMPLE_SIGNING / "keys"),
            ENV_SIG_DIR: str(EXAMPLE_SIGNING),
        }
        with patch.dict(os.environ, env), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "aegis.scanners" else []):
            verifier = load_plugin_verifier()
            report = list(scanner_registry._scanner_registry.scan_entry_points(
                "aegis.scanners", register=True, verifier=verifier))
        row = report[0]
        self.assertEqual(row.status, "loaded", row.detail)
        self.assertIsNotNone(row.signature)
        self.assertIn("example", scanner_registry._REGISTRY)


# ---------------------------------------------------------------------------
# Signature gate + sandbox compose: a signed plugin runs out-of-process
# ---------------------------------------------------------------------------

class TestSignedPluginSandboxed(unittest.TestCase):
    """The signature gate and the sandbox stack compose.

    The signature binds to the plugin's *real* factory source; the sandbox
    wrapper is trusted in-tree code substituted only after verification. So an
    operator who turns enforcement on still gets the verified plugin, and it
    still runs out-of-process.
    """

    def _example_on_path(self) -> None:
        inserted = str(EXAMPLE_DIR)
        if inserted not in sys.path:
            sys.path.insert(0, inserted)
            self.addCleanup(sys.path.remove, inserted)
        self.addCleanup(sys.modules.pop, "aegis_plugin_example", None)

    def test_signed_example_loads_sandbox_wrapped_via_eager_loader(self):
        """End-to-end: enforcement on + committed key -> example loads, signed,
        and wrapped in the sandbox proxy by the real eager loader."""
        from aegis.scanners.registry import maybe_load_entry_points
        from aegis.scanners.sandbox import SandboxedScanner

        self.addCleanup(scanner_registry._REGISTRY.pop, "example", None)
        self._example_on_path()
        import aegis_plugin_example as mod
        ep = SimpleNamespace(
            name="example", value="aegis_plugin_example:create_scanner",
            load=lambda: mod.create_scanner,
            dist=SimpleNamespace(name="aegis-plugin-example", version="0.1.0"),
        )
        env = {
            "AEGIS_PLUGINS": "1",
            ENV_REQUIRE_SIGNATURE: "1",
            ENV_TRUSTED_KEYS: str(EXAMPLE_SIGNING / "keys"),
            ENV_SIG_DIR: str(EXAMPLE_SIGNING),
            # leave AEGIS_PLUGINS_SANDBOX unset -> sandbox on by default
        }
        with patch.dict(os.environ, env), \
                patch("importlib.metadata.entry_points",
                      side_effect=lambda group: [ep] if group == "aegis.scanners" else []):
            maybe_load_entry_points()
        registered = scanner_registry._REGISTRY.get("example")
        self.assertIsInstance(registered, SandboxedScanner)
        self.assertEqual(registered.name, "example")

    def test_unsigned_example_rejected_before_sandbox_wrap(self):
        """Signature failure rejects the plugin; nothing is registered/wrapped."""
        from aegis.scanners.registry import maybe_load_entry_points

        self.addCleanup(scanner_registry._REGISTRY.pop, "example", None)
        self._example_on_path()
        import aegis_plugin_example as mod
        ep = SimpleNamespace(
            name="example", value="aegis_plugin_example:create_scanner",
            load=lambda: mod.create_scanner,
            dist=SimpleNamespace(name="aegis-plugin-example", version="0.1.0"),
        )
        with tempfile.TemporaryDirectory() as d:
            # A trusted key with no matching signature -> rejected.
            _, foreign_pub = _write_keypair(Path(d))
            env = {
                "AEGIS_PLUGINS": "1",
                ENV_REQUIRE_SIGNATURE: "1",
                ENV_TRUSTED_KEYS: str(foreign_pub),
                ENV_SIG_DIR: str(d),
            }
            with patch.dict(os.environ, env), \
                    patch("importlib.metadata.entry_points",
                          side_effect=lambda group: [ep] if group == "aegis.scanners" else []):
                maybe_load_entry_points()
        self.assertNotIn("example", scanner_registry._REGISTRY)


if __name__ == "__main__":
    unittest.main()
