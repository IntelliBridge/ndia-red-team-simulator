"""Blob-store parity tests (filesystem now; S3 via moto when available)."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from aegis.blobs import BlobRef, FilesystemBlobStore


class TestFilesystemBlobStore(unittest.TestCase):
    def test_put_get_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = FilesystemBlobStore(Path(tmp))
            payload = b"hello world"
            ref = store.put("test/key", payload)
            self.assertEqual(ref.sha256,
                             hashlib.sha256(payload).hexdigest())
            self.assertEqual(store.get(ref.sha256), payload)
            self.assertEqual(b"".join(store.stream(ref.sha256)), payload)

    def test_put_is_idempotent_by_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = FilesystemBlobStore(Path(tmp))
            ref1 = store.put("k1", b"same")
            ref2 = store.put("k2", b"same")
            self.assertEqual(ref1.sha256, ref2.sha256)
            self.assertEqual(ref1.location, ref2.location)


class TestS3BlobStoreSmoke(unittest.TestCase):
    """Optional: only runs when `moto` is installed."""

    def test_round_trip_with_moto(self):
        try:
            from moto import mock_aws
        except ImportError:
            self.skipTest("moto not installed")
        import boto3
        with mock_aws():
            client = boto3.client("s3", region_name="us-east-1")
            client.create_bucket(Bucket="aegis-test")
            from aegis.blobs_s3 import S3BlobStore
            store = S3BlobStore(bucket="aegis-test")
            ref = store.put("blobs", b"hello")
            self.assertTrue(ref.location.startswith("s3://aegis-test/"))
            self.assertEqual(store.get(ref.location), b"hello")


if __name__ == "__main__":
    unittest.main()
