"""Pluggable blob storage (Phase 3 M9 shape; FS backend lands here in M1).

Both ``FilesystemBlobStore`` and ``S3BlobStore`` satisfy this Protocol.
Content is addressed by sha256; ``put`` is idempotent by content (a second
put of the same bytes is a no-op).

S3 backend is added in M9 once boto3 is in the venv.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterator, Protocol

if TYPE_CHECKING:
    from redsim.config import RedsimConfig


@dataclass(frozen=True)
class BlobRef:
    sha256: str
    location: str           # absolute path or URI like s3://bucket/key
    size_bytes: int
    content_type: str = "application/octet-stream"


class BlobStore(Protocol):
    def put(self, key: str, content: bytes | str, *,
            content_type: str = "application/octet-stream") -> BlobRef: ...
    def get(self, key: str) -> bytes: ...
    def stream(self, key: str) -> Iterator[bytes]: ...


class FilesystemBlobStore:
    """Content-addressable blob store rooted at ``base``.

    The on-disk key is the sha256, the logical ``key`` is recorded as
    metadata in the returned ``BlobRef.location`` so the API can surface it.
    """

    def __init__(self, base: str | Path):
        self.base = Path(base)
        self.base.mkdir(parents=True, exist_ok=True)

    def _hash(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def put(self, key: str, content: bytes | str, *,
            content_type: str = "application/octet-stream") -> BlobRef:
        data = content.encode("utf-8") if isinstance(content, str) else content
        digest = self._hash(data)
        path = self.base / digest[:2] / digest
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(data)
        return BlobRef(
            sha256=digest,
            location=str(path),
            size_bytes=len(data),
            content_type=content_type,
        )

    def get(self, key: str) -> bytes:
        # ``key`` here is the sha256 or a relative path; both resolve under base.
        digest = Path(key).name
        path = self.base / digest[:2] / digest
        if not path.exists():
            path = self.base / key
        return path.read_bytes()

    def stream(self, key: str) -> Iterator[bytes]:
        digest = Path(key).name
        path = self.base / digest[:2] / digest
        if not path.exists():
            path = self.base / key
        with open(path, "rb") as fh:
            while chunk := fh.read(64 * 1024):
                yield chunk


def open_blob_store(config_or_url: RedsimConfig | str | None = None) -> BlobStore:
    """Factory that selects the configured backend.

    Reads ``REDSIM_BLOB_BACKEND`` (``fs`` | ``s3``) when called without args.
    """
    backend = os.environ.get("REDSIM_BLOB_BACKEND", "fs")
    if backend == "s3":
        try:
            from redsim.storage.s3 import S3BlobStore  # added in M9
            return S3BlobStore.from_env()
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "REDSIM_BLOB_BACKEND=s3 but boto3 isn't installed; "
                "install with `pip install redsim-platform[api]`"
            ) from exc
    base = os.environ.get("REDSIM_BLOB_FS_PATH", "redsim_output/blobs")
    return FilesystemBlobStore(base)
