"""Pluggable blob storage package.

Public surface lives here so call sites keep importing
``from aegis.storage import ...`` regardless of internal layout:

  - ``BlobRef``            content-addressable blob handle
  - ``BlobStore``          shared Protocol both backends implement
  - ``FilesystemBlobStore`` offline default backend
  - ``S3BlobStore``        S3 / MinIO backend (boto3 imported lazily)
  - ``open_blob_store``    per-environment backend selector
"""

from __future__ import annotations

from aegis.storage.blobs import (
    BlobRef,
    BlobStore,
    FilesystemBlobStore,
    open_blob_store,
)
from aegis.storage.s3 import S3BlobStore

__all__ = [
    "BlobRef",
    "BlobStore",
    "FilesystemBlobStore",
    "S3BlobStore",
    "open_blob_store",
]
