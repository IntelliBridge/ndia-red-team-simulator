"""S3 / MinIO blob backend."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from datetime import datetime
from typing import cast

from redsim.storage.blobs import BlobRef


class S3BlobStore:
    """Content-addressable S3 / MinIO backend.

    Env config (mirrors compose stack):
      - REDSIM_S3_ENDPOINT      e.g. http://minio:9000
      - REDSIM_S3_BUCKET        e.g. redsim
      - REDSIM_S3_REGION        e.g. us-east-1
      - REDSIM_S3_ACCESS_KEY_ID
      - REDSIM_S3_SECRET_ACCESS_KEY

    Object Lock note: ``put`` accepts optional ``retain_until`` +
    ``lock_mode`` kwargs to apply WORM (Write-Once-Read-Many) retention.
    These only take effect when the **bucket was created with Object Lock
    enabled** (``ObjectLockEnabledForBucket=True`` at create time; it can't
    be turned on afterward). The WORM archive (``redsim.storage.worm``)
    points an ``S3BlobStore`` at such a bucket so an archived audit chain
    can't be altered or deleted before its retention expires.
    """

    def __init__(self, *, bucket: str, endpoint_url: str | None = None,
                 region: str = "us-east-1",
                 access_key: str | None = None,
                 secret_key: str | None = None):
        import boto3
        self.bucket = bucket
        self.endpoint_url = endpoint_url
        kwargs: dict = {"region_name": region}
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url
        if access_key:
            kwargs["aws_access_key_id"] = access_key
        if secret_key:
            kwargs["aws_secret_access_key"] = secret_key
        self.client = boto3.client("s3", **kwargs)

    @classmethod
    def from_env(cls) -> S3BlobStore:
        bucket = os.environ.get("REDSIM_S3_BUCKET")
        if not bucket:
            raise RuntimeError("REDSIM_S3_BUCKET not set")
        return cls(
            bucket=bucket,
            endpoint_url=os.environ.get("REDSIM_S3_ENDPOINT"),
            region=os.environ.get("REDSIM_S3_REGION", "us-east-1"),
            access_key=os.environ.get("REDSIM_S3_ACCESS_KEY_ID"),
            secret_key=os.environ.get("REDSIM_S3_SECRET_ACCESS_KEY"),
        )

    def _exists(self, key: str) -> bool:
        from botocore.exceptions import ClientError
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except ClientError:
            return False

    def _assert_object_lock_enabled(self) -> None:
        """Fail loudly when the bucket lacks S3 Object Lock.

        A WORM put to a bucket without Object Lock would otherwise land
        *without* retention — an archive that looks sealed (the manifest
        records ``retention_until``) but isn't. Object Lock can only be
        enabled at bucket-creation time, so we refuse the write rather than
        silently produce a tamper-able copy.
        """
        try:
            conf = self.client.get_object_lock_configuration(Bucket=self.bucket)
            enabled = conf.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled")
        except Exception as exc:
            raise RuntimeError(
                f"bucket {self.bucket!r} does not have S3 Object Lock enabled "
                "(enable it at bucket creation); refusing to write an unsealed "
                f"WORM archive: {type(exc).__name__}"
            ) from exc
        if enabled != "Enabled":
            raise RuntimeError(
                f"bucket {self.bucket!r} does not have S3 Object Lock enabled "
                "(enable it at bucket creation); refusing to write an unsealed "
                "WORM archive"
            )

    def put(self, key: str, content: bytes | str, *,
            content_type: str = "application/octet-stream",
            retain_until: datetime | None = None,
            lock_mode: str | None = None) -> BlobRef:
        """Store ``content`` content-addressed under ``key``.

        ``retain_until`` + ``lock_mode`` apply S3 Object Lock retention to
        the written object (``lock_mode`` is "GOVERNANCE" or "COMPLIANCE").
        Both must be set together; the target bucket must have Object Lock
        enabled at creation time. Existing call sites that omit these kwargs
        are unchanged.
        """
        data = content.encode("utf-8") if isinstance(content, str) else content
        digest = hashlib.sha256(data).hexdigest()
        s3_key = f"{key}/{digest}"
        if not self._exists(s3_key):
            put_kwargs: dict = {
                "Bucket": self.bucket, "Key": s3_key, "Body": data,
                "ContentType": content_type,
            }
            if retain_until is not None and lock_mode is not None:
                self._assert_object_lock_enabled()
                put_kwargs["ObjectLockMode"] = lock_mode
                put_kwargs["ObjectLockRetainUntilDate"] = retain_until
            self.client.put_object(**put_kwargs)
        return BlobRef(
            sha256=digest,
            location=f"s3://{self.bucket}/{s3_key}",
            size_bytes=len(data),
            content_type=content_type,
        )

    def get(self, key: str) -> bytes:
        # key may be the s3 URI or just the key portion
        if key.startswith("s3://"):
            key = key.split("/", 3)[3]
        obj = self.client.get_object(Bucket=self.bucket, Key=key)
        # boto3 is untyped here; StreamingBody.read() returns bytes at runtime.
        return cast(bytes, obj["Body"].read())

    def stream(self, key: str) -> Iterator[bytes]:
        if key.startswith("s3://"):
            key = key.split("/", 3)[3]
        obj = self.client.get_object(Bucket=self.bucket, Key=key)
        body = obj["Body"]
        while chunk := body.read(64 * 1024):
            yield chunk
