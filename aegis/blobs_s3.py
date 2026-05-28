"""S3 / MinIO blob backend."""

from __future__ import annotations

import hashlib
import os
from typing import Iterator

from aegis.blobs import BlobRef


class S3BlobStore:
    """Content-addressable S3 / MinIO backend.

    Env config (mirrors compose stack):
      - AEGIS_S3_ENDPOINT      e.g. http://minio:9000
      - AEGIS_S3_BUCKET        e.g. aegis
      - AEGIS_S3_REGION        e.g. us-east-1
      - AEGIS_S3_ACCESS_KEY_ID
      - AEGIS_S3_SECRET_ACCESS_KEY
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
    def from_env(cls) -> "S3BlobStore":
        bucket = os.environ.get("AEGIS_S3_BUCKET")
        if not bucket:
            raise RuntimeError("AEGIS_S3_BUCKET not set")
        return cls(
            bucket=bucket,
            endpoint_url=os.environ.get("AEGIS_S3_ENDPOINT"),
            region=os.environ.get("AEGIS_S3_REGION", "us-east-1"),
            access_key=os.environ.get("AEGIS_S3_ACCESS_KEY_ID"),
            secret_key=os.environ.get("AEGIS_S3_SECRET_ACCESS_KEY"),
        )

    def _exists(self, key: str) -> bool:
        from botocore.exceptions import ClientError
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except ClientError:
            return False

    def put(self, key: str, content: bytes | str, *,
            content_type: str = "application/octet-stream") -> BlobRef:
        data = content.encode("utf-8") if isinstance(content, str) else content
        digest = hashlib.sha256(data).hexdigest()
        s3_key = f"{key}/{digest}"
        if not self._exists(s3_key):
            self.client.put_object(
                Bucket=self.bucket, Key=s3_key, Body=data,
                ContentType=content_type,
            )
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
        return obj["Body"].read()

    def stream(self, key: str) -> Iterator[bytes]:
        if key.startswith("s3://"):
            key = key.split("/", 3)[3]
        obj = self.client.get_object(Bucket=self.bucket, Key=key)
        body = obj["Body"]
        while chunk := body.read(64 * 1024):
            yield chunk
