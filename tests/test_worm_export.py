"""WORM (Write-Once-Read-Many) audit export tests.

Core serialization / manifest / idempotency logic is exercised offline with
a ``FilesystemBlobStore`` (or a fake) wrapping ``WormArchive`` and a
``JsonlAuditWriter`` — no S3, no network. A separate moto-backed test covers
the S3 Object-Lock path (skipped if moto isn't installed). The CLI + Celery
surfaces get their own focused tests.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from aegis.audit.chain import JsonlAuditWriter, verify_chain
from aegis.config import AegisConfig
from aegis.storage.blobs import BlobRef, FilesystemBlobStore
from aegis.storage.worm import (
    WormArchive,
    canonical_jsonl,
    worm_export_enabled,
    worm_export_interval,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

class _FakeStore:
    """Minimal in-memory BlobStore that records Object-Lock kwargs."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.put_kwargs: list[dict] = []

    def put(self, key, content, *, content_type="application/octet-stream",
            retain_until=None, lock_mode=None):
        import hashlib
        data = content.encode("utf-8") if isinstance(content, str) else content
        digest = hashlib.sha256(data).hexdigest()
        s3_key = f"{key}/{digest}"
        self.objects[s3_key] = data
        self.put_kwargs.append({
            "key": key, "content_type": content_type,
            "retain_until": retain_until, "lock_mode": lock_mode,
        })
        return BlobRef(sha256=digest, location=f"fake://{s3_key}",
                       size_bytes=len(data), content_type=content_type)

    def _exists(self, key):
        return key in self.objects

    def get(self, key):
        return self.objects[key]


def _seed_chain(writer, chain_id_run="run-1", n=4, project="proj-1"):
    for i in range(n):
        writer.append(
            action="scan.start", actor="cli:alice", target="http://localhost:3000",
            allowlist_check="pass", override=False, success=True,
            detail={"i": i}, run_id=chain_id_run, project_id=project,
        )


# ---------------------------------------------------------------------------
# env helpers
# ---------------------------------------------------------------------------

class TestEnvHelpers(unittest.TestCase):

    def test_export_enabled_truthy_variants(self):
        for val in ("1", "true", "YES", "on"):
            with patch.dict("os.environ", {"AEGIS_WORM_EXPORT": val}, clear=True):
                self.assertTrue(worm_export_enabled())
        for val in ("0", "false", "", "no"):
            with patch.dict("os.environ", {"AEGIS_WORM_EXPORT": val}, clear=True):
                self.assertFalse(worm_export_enabled())
        with patch.dict("os.environ", {}, clear=True):
            self.assertFalse(worm_export_enabled())  # default off

    def test_interval_default_and_override_and_bad_value(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(worm_export_interval(), 86400)
        with patch.dict("os.environ", {"AEGIS_WORM_INTERVAL": "3600"}, clear=True):
            self.assertEqual(worm_export_interval(), 3600)
        with patch.dict("os.environ", {"AEGIS_WORM_INTERVAL": "nope"}, clear=True):
            self.assertEqual(worm_export_interval(), 86400)  # falls back


# ---------------------------------------------------------------------------
# canonical_jsonl + manifest correctness
# ---------------------------------------------------------------------------

class TestCanonicalJsonlAndManifest(unittest.TestCase):

    def test_canonical_jsonl_is_deterministic_and_roundtrips(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            _seed_chain(writer)
            events = list(writer.read_chain("run:run-1"))
            blob1 = canonical_jsonl(events)
            blob2 = canonical_jsonl(events)
            self.assertEqual(blob1, blob2)  # deterministic
            # round-trips back to verifiable events
            parsed = [json.loads(line) for line in blob1.decode().splitlines()]
            self.assertEqual(len(parsed), 4)
            self.assertTrue(verify_chain(parsed).verified)

    def test_archive_chain_writes_jsonl_and_manifest_with_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            _seed_chain(writer)
            events = list(writer.read_chain("run:run-1"))
            store = _FakeStore()
            archive = WormArchive(store, retention_days=10, lock_mode="COMPLIANCE",
                                  bucket="aegis-worm")
            ref = archive.archive_chain("run:run-1", events, verified=True)
            self.assertIsNotNone(ref)
            # two objects: jsonl + manifest
            self.assertEqual(len(store.objects), 2)
            manifest_key = next(k for k in store.objects if "manifest.json" in k)
            manifest = json.loads(store.objects[manifest_key])
            self.assertEqual(manifest["chain_id"], "run:run-1")
            self.assertEqual(manifest["event_count"], 4)
            self.assertEqual(manifest["head_seq"], 4)
            self.assertEqual(manifest["head_hash"], events[-1]["this_hash"])
            self.assertTrue(manifest["verified"])
            self.assertEqual(manifest["lock_mode"], "COMPLIANCE")
            self.assertIn("exported_at", manifest)
            self.assertIn("retention_until", manifest)
            self.assertEqual(manifest["jsonl_sha256"], ref.sha256)
            # Object Lock kwargs forwarded for both objects
            for kw in store.put_kwargs:
                self.assertIsInstance(kw["retain_until"], datetime)
                self.assertEqual(kw["lock_mode"], "COMPLIANCE")

    def test_idempotent_reexport_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            _seed_chain(writer)
            events = list(writer.read_chain("run:run-1"))
            store = _FakeStore()
            archive = WormArchive(store, retention_days=10)
            first = archive.archive_chain("run:run-1", events, verified=True)
            self.assertIsNotNone(first)
            second = archive.archive_chain("run:run-1", events, verified=True)
            self.assertIsNone(second)  # no-op
            self.assertEqual(len(store.objects), 2)  # unchanged

    def test_empty_chain_is_noop(self):
        store = _FakeStore()
        archive = WormArchive(store)
        self.assertIsNone(archive.archive_chain("run:none", [], verified=True))
        self.assertEqual(len(store.objects), 0)

    def test_filesystem_store_backend_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp) / "audit")
            _seed_chain(writer)
            events = list(writer.read_chain("run:run-1"))
            fs = FilesystemBlobStore(Path(tmp) / "worm")
            archive = WormArchive(fs, retention_days=5)
            ref = archive.archive_chain("run:run-1", events, verified=True)
            self.assertIsNotNone(ref)
            # round-trip the JSONL back out of the FS store and re-verify
            raw = fs.get(ref.sha256)
            parsed = [json.loads(line) for line in raw.decode().splitlines()]
            self.assertTrue(verify_chain(parsed).verified)


# ---------------------------------------------------------------------------
# export_all
# ---------------------------------------------------------------------------

class TestExportAll(unittest.TestCase):

    def test_export_all_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            _seed_chain(writer, chain_id_run="run-1")
            _seed_chain(writer, chain_id_run="run-2", n=2)
            store = _FakeStore()
            archive = WormArchive(store)
            summary = archive.export_all(writer, verify=True)
            self.assertEqual(summary.chains_total, 2)
            self.assertEqual(summary.chains_archived, 2)
            self.assertEqual(summary.objects_written, 4)
            self.assertGreater(summary.bytes_written, 0)
            self.assertEqual(summary.broken_chains, [])

    def test_broken_chain_flagged_but_archived(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            _seed_chain(writer)
            # Tamper the on-disk chain so verification fails.
            chain_path = next(Path(tmp).glob("*.jsonl"))
            lines = chain_path.read_text().splitlines()
            rec = json.loads(lines[1])
            rec["detail"]["i"] = 999
            lines[1] = json.dumps(rec)
            chain_path.write_text("\n".join(lines) + "\n")

            store = _FakeStore()
            archive = WormArchive(store)
            summary = archive.export_all(writer, verify=True)
            self.assertEqual(summary.chains_archived, 1)
            self.assertEqual(summary.broken_chains, ["run:run-1"])
            manifest_key = next(k for k in store.objects if "manifest.json" in k)
            manifest = json.loads(store.objects[manifest_key])
            self.assertFalse(manifest["verified"])  # archived but flagged


# ---------------------------------------------------------------------------
# S3 Object-Lock path (moto)
# ---------------------------------------------------------------------------

class TestS3ObjectLock(unittest.TestCase):

    def test_object_lock_headers_and_roundtrip(self):
        try:
            from moto import mock_aws
        except ImportError:
            self.skipTest("moto not installed")
        import boto3

        from aegis.storage.s3 import S3BlobStore

        with mock_aws(), tempfile.TemporaryDirectory() as tmp:
            client = boto3.client("s3", region_name="us-east-1")
            client.create_bucket(Bucket="aegis-worm",
                                 ObjectLockEnabledForBucket=True)

            writer = JsonlAuditWriter(Path(tmp))
            _seed_chain(writer)
            events = list(writer.read_chain("run:run-1"))

            store = S3BlobStore(bucket="aegis-worm")
            archive = WormArchive(store, retention_days=7, lock_mode="COMPLIANCE",
                                  bucket="aegis-worm")
            ref = archive.archive_chain("run:run-1", events, verified=True)
            self.assertIsNotNone(ref)

            # The JSONL object carries Object Lock retention metadata.
            s3_key = ref.location.split("/", 3)[3]
            head = client.head_object(Bucket="aegis-worm", Key=s3_key)
            self.assertEqual(head["ObjectLockMode"], "COMPLIANCE")
            self.assertIn("ObjectLockRetainUntilDate", head)

            # Round-trip the JSONL back and re-verify the chain.
            raw = store.get(ref.location)
            parsed = [json.loads(line) for line in raw.decode().splitlines()]
            self.assertTrue(verify_chain(parsed).verified)

    def test_s3_put_without_lock_is_backward_compatible(self):
        try:
            from moto import mock_aws
        except ImportError:
            self.skipTest("moto not installed")
        import boto3

        from aegis.storage.s3 import S3BlobStore

        with mock_aws():
            client = boto3.client("s3", region_name="us-east-1")
            client.create_bucket(Bucket="plain")
            store = S3BlobStore(bucket="plain")
            ref = store.put("blobs", b"hello")  # no lock kwargs
            self.assertEqual(store.get(ref.location), b"hello")

    def test_from_env_builds_s3_backed_archive(self):
        try:
            from moto import mock_aws
        except ImportError:
            self.skipTest("moto not installed")
        import boto3

        env = {
            "AEGIS_WORM_EXPORT": "1",
            "AEGIS_WORM_BUCKET": "worm-from-env",
            "AEGIS_WORM_RETENTION_DAYS": "30",
            "AEGIS_WORM_LOCK_MODE": "GOVERNANCE",
            "AEGIS_S3_REGION": "us-east-1",
            # moto needs *some* creds on the client built by from_env.
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
        }
        with mock_aws(), patch.dict("os.environ", env, clear=True):
            boto3.client("s3", region_name="us-east-1").create_bucket(
                Bucket="worm-from-env", ObjectLockEnabledForBucket=True)
            archive = WormArchive.from_env()
            self.assertEqual(archive.bucket, "worm-from-env")
            self.assertEqual(archive.retention_days, 30)
            self.assertEqual(archive.lock_mode, "GOVERNANCE")
            self.assertEqual(archive.store.bucket, "worm-from-env")

    def test_from_env_bad_retention_falls_back_to_default(self):
        try:
            from moto import mock_aws
        except ImportError:
            self.skipTest("moto not installed")
        with mock_aws(), patch.dict(
            "os.environ",
            {"AEGIS_WORM_RETENTION_DAYS": "not-a-number"}, clear=True,
        ):
            archive = WormArchive.from_env()
            self.assertEqual(archive.retention_days, 2555)


# ---------------------------------------------------------------------------
# CLI: aegis audit export
# ---------------------------------------------------------------------------

class TestCmdAuditExport(unittest.TestCase):

    def test_export_disabled_errors(self):
        from aegis.cli.audit import cmd_audit_export

        args = Namespace(all=True, chain=None, no_verify=False)
        buf = io.StringIO()
        with patch.dict("os.environ", {}, clear=True), redirect_stdout(buf):
            with self.assertRaises(SystemExit) as ctx:
                cmd_audit_export(args, AegisConfig())
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("AEGIS_WORM_EXPORT", buf.getvalue())

    def test_export_all_prints_summary(self):
        from aegis.cli.audit import cmd_audit_export

        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp) / "audit")
            _seed_chain(writer)
            config = AegisConfig(output_dir=tmp)
            store = _FakeStore()
            archive = WormArchive(store, bucket="aegis-worm")

            args = Namespace(all=True, chain=None, no_verify=False)
            buf = io.StringIO()
            with patch.dict("os.environ", {"AEGIS_WORM_EXPORT": "1"}, clear=True), \
                 patch("aegis.storage.worm.WormArchive.from_env", return_value=archive), \
                 patch("aegis.audit.chain.resolve_writer", return_value=writer), \
                 redirect_stdout(buf):
                with self.assertRaises(SystemExit) as ctx:
                    cmd_audit_export(args, config)
            self.assertEqual(ctx.exception.code, 0)
            out = buf.getvalue()
            self.assertIn("WORM export", out)
            self.assertIn("archived", out)

    def test_export_single_chain(self):
        from aegis.cli.audit import cmd_audit_export

        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp) / "audit")
            _seed_chain(writer)
            config = AegisConfig(output_dir=tmp)
            store = _FakeStore()
            archive = WormArchive(store)

            args = Namespace(all=False, chain="run:run-1", no_verify=False)
            buf = io.StringIO()
            with patch.dict("os.environ", {"AEGIS_WORM_EXPORT": "1"}, clear=True), \
                 patch("aegis.storage.worm.WormArchive.from_env", return_value=archive), \
                 patch("aegis.audit.chain.resolve_writer", return_value=writer), \
                 redirect_stdout(buf):
                with self.assertRaises(SystemExit) as ctx:
                    cmd_audit_export(args, config)
            self.assertEqual(ctx.exception.code, 0)
            self.assertIn("archived 4 events", buf.getvalue())


# ---------------------------------------------------------------------------
# Celery task self-gating
# ---------------------------------------------------------------------------

class TestWormExportTask(unittest.TestCase):

    def test_disabled_returns_disabled(self):
        from aegis.workers.tasks.worm_export import export_chains_to_worm

        with patch.dict("os.environ", {}, clear=True):
            result = export_chains_to_worm()
        self.assertEqual(result, {"status": "disabled"})

    def test_enabled_runs_export(self):
        from aegis.workers.tasks.worm_export import export_chains_to_worm

        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp) / "audit")
            _seed_chain(writer)
            store = _FakeStore()
            archive = WormArchive(store, bucket="aegis-worm")

            with patch.dict("os.environ", {"AEGIS_WORM_EXPORT": "1"}, clear=True), \
                 patch("aegis.storage.worm.WormArchive.from_env", return_value=archive), \
                 patch("aegis.audit.chain.resolve_writer", return_value=writer):
                result = export_chains_to_worm()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["chains_archived"], 1)


if __name__ == "__main__":
    unittest.main()
