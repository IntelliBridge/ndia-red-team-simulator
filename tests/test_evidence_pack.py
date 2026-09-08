"""Tests for the compliance evidence pack (Feature: evidence pack).

Seeds a filesystem audit writer with a couple of chains (mirroring
tests/test_audit_chain.py), then asserts ``generate_evidence_pack`` writes
the expected files, the manifest hashes match the file contents, the
verification reflects valid (and tampered) chains, no secrets leak, and the
controls matrix spans SOC2 + ISO + FedRAMP. Also a CLI smoke test.
"""

import hashlib
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from redsim.audit.chain import JsonlAuditWriter
from redsim.config import RedsimConfig
from redsim.services.evidence import (
    build_controls_matrix,
    generate_evidence_pack,
)

# A token-shaped string we deliberately feed in so we can assert it never
# lands in the pack.
SECRET_TOKEN = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def _seed_writer(output_dir: Path) -> JsonlAuditWriter:
    """Seed two chains (one per run) under ``<output_dir>/audit``."""
    writer = JsonlAuditWriter(output_dir / "audit")
    for i in range(3):
        writer.append(
            action="scan.start", actor="cli:alice",
            target="http://localhost:3000",
            allowlist_check="pass", override=False, success=True,
            detail={"seq": i, "authorization": f"Bearer {SECRET_TOKEN}"},
            run_id="run-1", project_id="proj-1",
        )
    for i in range(2):
        writer.append(
            action="fix.apply", actor="cli:bob", target="localhost",
            allowlist_check="pass", override=False, success=True,
            detail={"seq": i}, run_id="run-2", project_id="proj-1",
        )
    return writer


class TestEvidencePackContents(unittest.TestCase):
    def _generate(self, tmp: str):
        out_root = Path(tmp) / "redsim_output"
        _seed_writer(out_root)
        config = RedsimConfig(output_dir=str(out_root))
        pack_dir = Path(tmp) / "pack"
        with patch.dict("os.environ", {}, clear=True):
            manifest = generate_evidence_pack(pack_dir, config=config)
        return pack_dir, manifest

    def test_all_expected_files_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack_dir, _ = self._generate(tmp)
            for name in ("verification.json", "controls.json",
                         "system.json", "manifest.json"):
                self.assertTrue((pack_dir / name).exists(), name)
            jsonl = list((pack_dir / "audit").glob("*.jsonl"))
            self.assertEqual(len(jsonl), 2, jsonl)

    def test_audit_chains_exported_with_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack_dir, manifest = self._generate(tmp)
            self.assertEqual(sorted(manifest.chains),
                             ["run:run-1", "run:run-2"])
            run1 = pack_dir / "audit" / "run__run-1.jsonl"
            lines = [ln for ln in run1.read_text().splitlines() if ln.strip()]
            self.assertEqual(len(lines), 3)

    def test_verification_reflects_valid_chains(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack_dir, _ = self._generate(tmp)
            verification = json.loads((pack_dir / "verification.json").read_text())
            self.assertTrue(verification["run:run-1"]["verified"])
            self.assertEqual(verification["run:run-1"]["count"], 3)
            self.assertTrue(verification["run:run-2"]["verified"])
            self.assertIsNone(verification["run:run-1"]["broken_at"])

    def test_verification_detects_tampered_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_root = Path(tmp) / "redsim_output"
            _seed_writer(out_root)
            # Tamper with a record in run-1's chain on disk.
            chain_file = out_root / "audit" / "run__run-1.jsonl"
            lines = chain_file.read_text().splitlines()
            rec = json.loads(lines[1])
            rec["detail"]["seq"] = 999
            lines[1] = json.dumps(rec)
            chain_file.write_text("\n".join(lines) + "\n")

            config = RedsimConfig(output_dir=str(out_root))
            pack_dir = Path(tmp) / "pack"
            with patch.dict("os.environ", {}, clear=True):
                generate_evidence_pack(pack_dir, config=config)
            verification = json.loads((pack_dir / "verification.json").read_text())
            self.assertFalse(verification["run:run-1"]["verified"])
            self.assertEqual(verification["run:run-1"]["broken_at"], 2)
            self.assertTrue(verification["run:run-2"]["verified"])

    def test_manifest_hashes_match_file_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack_dir, manifest = self._generate(tmp)
            stored = json.loads((pack_dir / "manifest.json").read_text())
            self.assertEqual(stored["pack_hash"], manifest.pack_hash)
            # Every listed file's recomputed sha256 must match the manifest,
            # and manifest.json itself must not be in the file list.
            self.assertNotIn("manifest.json", stored["files"])
            for rel, digest in stored["files"].items():
                actual = hashlib.sha256((pack_dir / rel).read_bytes()).hexdigest()
                self.assertEqual(actual, digest, rel)

    def test_pack_hash_changes_if_file_mutated(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack_dir, manifest = self._generate(tmp)
            recomputed = {}
            for rel in manifest.files:
                recomputed[rel] = hashlib.sha256(
                    (pack_dir / rel).read_bytes()
                ).hexdigest()
            # Recompute the pack hash the same way the service does.
            from redsim.services.evidence import _compute_pack_hash
            self.assertEqual(_compute_pack_hash(recomputed), manifest.pack_hash)
            # Mutate one file -> different hash.
            recomputed[next(iter(recomputed))] = "0" * 64
            self.assertNotEqual(_compute_pack_hash(recomputed), manifest.pack_hash)

    def test_no_secret_tokens_in_pack(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack_dir, _ = self._generate(tmp)
            for path in pack_dir.rglob("*"):
                if not path.is_file():
                    continue
                text = path.read_text()
                self.assertNotIn(SECRET_TOKEN, text, f"token leaked in {path}")
                self.assertNotIn("Bearer ", text, f"bearer leaked in {path}")

    def test_system_json_is_secret_free_and_versioned(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack_dir, _ = self._generate(tmp)
            system = json.loads((pack_dir / "system.json").read_text())
            self.assertIn("redsim_version", system)
            self.assertIn("features", system)
            features = system["features"]
            # Backend names + booleans only — no token-ish keys.
            self.assertIn("audit_backend", features)
            self.assertIn("blob_backend", features)
            for key in features:
                self.assertNotIn("token", key.lower())
                self.assertNotIn("secret", key.lower())
                self.assertNotIn("key", key.lower())


class TestControlsMatrix(unittest.TestCase):
    def test_spans_all_three_frameworks(self):
        matrix = build_controls_matrix()
        self.assertIn("soc2", matrix)
        self.assertIn("iso27001", matrix)
        self.assertIn("fedramp", matrix)
        # Representative keys from each framework.
        self.assertIn("CC7.3", matrix["soc2"])
        self.assertIn("A.8.15", matrix["iso27001"])
        self.assertIn("AU-9", matrix["fedramp"])
        self.assertIn("AC-3", matrix["fedramp"])
        self.assertIn("SI-2", matrix["fedramp"])

    def test_partial_controls_carry_a_note(self):
        matrix = build_controls_matrix()
        for framework in matrix.values():
            for control in framework.values():
                self.assertIn(control["status"], ("supported", "partial"))
                if control["status"] == "partial":
                    self.assertIn("note", control)
                self.assertTrue(control["evidence"])


class TestEvidencePackCli(unittest.TestCase):
    def test_cmd_evidence_pack_smoke(self):
        from redsim.cli.evidence import cmd_evidence_pack

        with tempfile.TemporaryDirectory() as tmp:
            out_root = Path(tmp) / "redsim_output"
            _seed_writer(out_root)
            config = RedsimConfig(output_dir=str(out_root))
            pack_dir = Path(tmp) / "pack"
            args = Namespace(out=str(pack_dir), project=None)
            with patch.dict("os.environ", {}, clear=True), self.assertRaises(SystemExit) as cm:
                cmd_evidence_pack(args, config)
            self.assertEqual(cm.exception.code, 0)
            self.assertTrue((pack_dir / "manifest.json").exists())

    def test_cli_requires_out(self):
        from redsim.cli.evidence import cmd_evidence_pack

        args = Namespace(out=None, project=None)
        with self.assertRaises(SystemExit) as cm:
            cmd_evidence_pack(args, RedsimConfig())
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
