"""WORM (Write-Once-Read-Many) archive for the hash-chained audit log.

The append-only audit chain (:mod:`redsim.audit.chain`) is tamper-*evident*:
a DB compromise that rewrites events is detectable, but the events
themselves still live in a mutable store. This module exports each chain to
an S3 / MinIO bucket with **Object Lock** (compliance retention) so the
archived copy can't be altered or deleted before its retention expires —
even by an attacker who owns the database or the bucket credentials.

Settings come from the environment, mirroring ``S3BlobStore.from_env()``
(creds are NOT plumbed through ``RedsimConfig``):

  - ``REDSIM_WORM_EXPORT``          enable flag (default off, ``"0"``)
  - ``REDSIM_WORM_BUCKET``          target bucket (default ``redsim-worm``)
  - ``REDSIM_WORM_RETENTION_DAYS``  Object Lock retention (default 2555 ≈ 7y)
  - ``REDSIM_WORM_LOCK_MODE``       ``COMPLIANCE`` | ``GOVERNANCE`` (default
                                   ``COMPLIANCE``)
  - ``REDSIM_WORM_INTERVAL``        beat export interval seconds (default
                                   86400)

The S3 client itself reuses ``REDSIM_S3_ENDPOINT/REGION/ACCESS_KEY_ID/
SECRET_ACCESS_KEY``.

No secret material is ever logged — only chain ids, counts and object keys.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from redsim.audit.chain import AuditWriter, verify_chain
from redsim.storage.blobs import BlobRef, BlobStore

logger = logging.getLogger("redsim.storage.worm")

_DEFAULT_BUCKET = "redsim-worm"
_DEFAULT_RETENTION_DAYS = 2555
_DEFAULT_LOCK_MODE = "COMPLIANCE"
_DEFAULT_INTERVAL_SECONDS = 86400


def worm_export_enabled() -> bool:
    """True when ``REDSIM_WORM_EXPORT`` is set to a truthy value."""
    return os.environ.get("REDSIM_WORM_EXPORT", "0").lower() in ("1", "true", "yes", "on")


def worm_export_interval() -> int:
    """Beat export interval (seconds) from ``REDSIM_WORM_INTERVAL``."""
    try:
        return int(os.environ.get("REDSIM_WORM_INTERVAL", str(_DEFAULT_INTERVAL_SECONDS)))
    except ValueError:
        return _DEFAULT_INTERVAL_SECONDS


@dataclass
class ExportSummary:
    """Aggregate outcome of an :meth:`WormArchive.export_all` run."""

    chains_total: int = 0
    chains_archived: int = 0
    chains_skipped: int = 0
    objects_written: int = 0
    bytes_written: int = 0
    broken_chains: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chains_total": self.chains_total,
            "chains_archived": self.chains_archived,
            "chains_skipped": self.chains_skipped,
            "objects_written": self.objects_written,
            "bytes_written": self.bytes_written,
            "broken_chains": list(self.broken_chains),
        }


def canonical_jsonl(events: list[dict[str, Any]]) -> bytes:
    """Serialize an ordered chain to deterministic JSONL.

    Each line is the event's full record encoded with the same
    ``sort_keys`` / compact separators as :func:`canonical_json` (but
    *including* ``this_hash``, since the archive must round-trip back into
    ``verify_chain``). One trailing newline per record; deterministic so the
    sha256 is stable across runs of an unchanged chain.
    """
    out = bytearray()
    for ev in events:
        out += json.dumps(ev, sort_keys=True, separators=(",", ":"),
                           default=str).encode("utf-8")
        out += b"\n"
    return bytes(out)


class WormArchive:
    """Exports audit chains to an Object-Lock bucket.

    ``store`` is any :class:`~redsim.storage.blobs.BlobStore`; in production
    it's an ``S3BlobStore`` pointed at the WORM bucket. Tests inject a
    ``FilesystemBlobStore`` (or a fake) to exercise serialization, the
    manifest, and idempotency without S3.
    """

    def __init__(self, store: BlobStore, *,
                 retention_days: int = _DEFAULT_RETENTION_DAYS,
                 lock_mode: str = _DEFAULT_LOCK_MODE,
                 bucket: str = _DEFAULT_BUCKET):
        self.store = store
        self.retention_days = retention_days
        self.lock_mode = lock_mode
        self.bucket = bucket

    @classmethod
    def from_env(cls) -> WormArchive:
        """Build a WORM archive from the ``REDSIM_WORM_*`` env, wrapping an
        ``S3BlobStore`` pointed at the WORM bucket (creds reused from the
        ``REDSIM_S3_*`` env)."""
        from redsim.storage.s3 import S3BlobStore

        bucket = os.environ.get("REDSIM_WORM_BUCKET", _DEFAULT_BUCKET)
        try:
            retention_days = int(os.environ.get(
                "REDSIM_WORM_RETENTION_DAYS", str(_DEFAULT_RETENTION_DAYS)))
        except ValueError:
            retention_days = _DEFAULT_RETENTION_DAYS
        lock_mode = os.environ.get("REDSIM_WORM_LOCK_MODE", _DEFAULT_LOCK_MODE)
        store = S3BlobStore(
            bucket=bucket,
            endpoint_url=os.environ.get("REDSIM_S3_ENDPOINT"),
            region=os.environ.get("REDSIM_S3_REGION", "us-east-1"),
            access_key=os.environ.get("REDSIM_S3_ACCESS_KEY_ID"),
            secret_key=os.environ.get("REDSIM_S3_SECRET_ACCESS_KEY"),
        )
        return cls(store, retention_days=retention_days,
                   lock_mode=lock_mode, bucket=bucket)

    def _put(self, key: str, content: bytes, *, content_type: str,
             retain_until: datetime) -> BlobRef:
        """Put with Object Lock retention when the backend supports it.

        ``S3BlobStore.put`` accepts ``retain_until`` + ``lock_mode`` (not on
        the shared ``BlobStore`` Protocol); the filesystem/fake stores used
        in tests don't, so fall back to a plain put. The retention is still
        recorded in the manifest either way.
        """
        store: Any = self.store
        try:
            ref: BlobRef = store.put(
                key, content, content_type=content_type,
                retain_until=retain_until, lock_mode=self.lock_mode,
            )
            return ref
        except TypeError:
            return self.store.put(key, content, content_type=content_type)

    def archive_chain(self, chain_id: str, events: list[dict[str, Any]], *,
                      verified: bool) -> BlobRef | None:
        """Archive one chain's events as canonical JSONL + a manifest.

        Returns the JSONL ``BlobRef`` when written, or ``None`` when an
        object for this exact ``head_seq`` + content sha already exists
        (idempotent no-op for an unchanged chain).
        """
        if not events:
            return None

        jsonl = canonical_jsonl(events)
        jsonl_sha = hashlib.sha256(jsonl).hexdigest()
        head = events[-1]
        head_seq = head.get("seq", len(events))
        head_hash = head.get("this_hash", "")
        # Stable, content-derived key: re-exporting the same chain head with
        # the same bytes resolves to the same key. The sha8 disambiguates a
        # head_seq whose contents changed (e.g. a tampered re-export).
        key_prefix = f"audit/{chain_id}/{head_seq}-{jsonl_sha[:8]}"
        jsonl_key = f"{key_prefix}.jsonl"

        # Idempotency: skip if this exact object already exists. S3BlobStore
        # content-addresses by sha under the key, so the final object path is
        # ``{key}/{sha}``; probe that. Fakes/FS report via ``get``.
        if self._already_archived(jsonl_key, jsonl_sha):
            logger.info("worm: chain %s head_seq=%s already archived; skipping",
                        chain_id, head_seq)
            return None

        retain_until = datetime.now(UTC) + timedelta(days=self.retention_days)
        jsonl_ref = self._put(jsonl_key, jsonl, content_type="application/x-ndjson",
                              retain_until=retain_until)

        manifest = {
            "chain_id": chain_id,
            "event_count": len(events),
            "head_seq": head_seq,
            "head_hash": head_hash,
            "verified": verified,
            "exported_at": datetime.now(UTC).isoformat(),
            "retention_until": retain_until.isoformat(),
            "lock_mode": self.lock_mode,
            "jsonl_sha256": jsonl_sha,
        }
        manifest_bytes = json.dumps(manifest, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8")
        manifest_key = f"{key_prefix}.manifest.json"
        self._put(manifest_key, manifest_bytes, content_type="application/json",
                  retain_until=retain_until)

        logger.info("worm: archived chain %s head_seq=%s events=%d verified=%s key=%s",
                    chain_id, head_seq, len(events), verified, jsonl_key)
        return jsonl_ref

    def _already_archived(self, key: str, sha: str) -> bool:
        """True when an object for ``key``+``sha`` is already stored.

        ``S3BlobStore`` exposes a private ``_exists`` over ``{key}/{sha}``;
        prefer it. Other stores fall back to a ``get`` probe.
        """
        exists = getattr(self.store, "_exists", None)
        if callable(exists):
            return bool(exists(f"{key}/{sha}"))
        try:
            self.store.get(sha)
            return True
        except Exception:  # noqa: BLE001 - any backend error means not present
            return False

    def export_all(self, writer: AuditWriter, *, verify: bool = True) -> ExportSummary:
        """Iterate every chain known to ``writer`` and archive each.

        Broken chains are still archived (so the evidence is preserved) but
        flagged ``verified=False`` in the manifest and recorded in
        ``summary.broken_chains``.
        """
        summary = ExportSummary()
        for chain_id in writer.iter_chain_ids():
            summary.chains_total += 1
            events = list(writer.read_chain(chain_id))
            if not events:
                summary.chains_skipped += 1
                continue
            verified = True
            if verify:
                result = verify_chain(events)
                verified = result.verified
                if not verified:
                    summary.broken_chains.append(chain_id)
            ref = self.archive_chain(chain_id, events, verified=verified)
            if ref is None:
                summary.chains_skipped += 1
            else:
                summary.chains_archived += 1
                summary.objects_written += 2  # jsonl + manifest
                summary.bytes_written += ref.size_bytes
        logger.info(
            "worm: export_all total=%d archived=%d skipped=%d objects=%d bytes=%d broken=%d",
            summary.chains_total, summary.chains_archived, summary.chains_skipped,
            summary.objects_written, summary.bytes_written, len(summary.broken_chains),
        )
        return summary
