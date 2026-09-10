"""The signed evidence pack of one campaign run.

One zip a reviewer can verify with no redsim server: the digest-checked run
record, every rendered report format, the run's hash-chained audit trail with
its verdict, an index of every artifact digest, and a manifest that hashes all
of it. When the API holds an Ed25519 evidence key the manifest bytes are
signed and the public key travels inside the pack, so the verifier needs
nothing else. ``verify_evidence_pack`` re-checks every file digest, the pack
hash, the record digest, the audit chain and the signature offline, and can
pin the signer to a trusted public key.

The pack copies no number out of the record into its own files: the manifest
names ids, digests, counts and file names only (spec 15.7). The run row is
written as ids and status, never ``Target.value``, so an endpoint URL cannot
leave with the pack. The private key is read from the environment, is never
written, logged or echoed, and only its ``key_id`` (the sha256 of the raw
public key) is ever reported.

Layout, everything under ``redsim-evidence-<run_id>/``::

    run.json                   the run row: ids, scanner, status, timestamps, stage table
    record/run_record.json     the ml.run_record bytes, digest checked before they are copied
    reports/report.<ext>       md, json, html, pdf as they exist (snapshot first, then newest row)
    artifacts/index.json       every Artifact row: id, kind, sha256, size, content type, created
    audit/run.jsonl            the run:<run_id> chain, one event per line
    audit/verification.json    the verify_chain verdict over those events
    manifest.json              format, ids, record digest, chain verdict, file digests, pack hash
    manifest.sig               hex Ed25519 signature over the exact manifest.json bytes (when signed)
    signer.json                algorithm, key_id and public key PEM, or why the pack is unsigned
"""

from __future__ import annotations

import binascii
import hashlib
import io
import json
import logging
import os
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from redsim import __version__
from redsim.audit.chain import canonical_ts, verify_chain

logger = logging.getLogger(__name__)

#: The manifest ``format`` value; bump when the layout changes.
PACK_FORMAT = "redsim-evidence-1"
#: The report formats a pack carries, in the order they are listed.
REPORT_FORMATS: tuple[str, ...] = ("md", "json", "html", "pdf")
#: Environment names for the signing key: a PEM file path, or the PEM text itself.
KEY_FILE_ENV = "REDSIM_EVIDENCE_SIGNING_KEY_FILE"
KEY_PEM_ENV = "REDSIM_EVIDENCE_SIGNING_KEY"
#: Why a pack is unsigned when neither variable is set.
UNSIGNED_REASON = (
    f"no evidence signing key is configured ({KEY_FILE_ENV} or {KEY_PEM_ENV}); "
    "generate one with `redsim evidence keygen`"
)
#: Files the manifest does not hash because they are written after it.
_UNHASHED = frozenset({"manifest.json", "manifest.sig", "signer.json"})
#: A fixed zip timestamp so two packs of one run differ only where the content differs.
_ZIP_TIME = (2026, 1, 1, 0, 0, 0)
_RUN_RECORD_KIND = "ml.run_record"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _dumps(payload: Any) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n").encode("utf-8")


def _iso(value: datetime | None) -> str | None:
    return canonical_ts(value) if value is not None else None


def compute_pack_hash(files: dict[str, str]) -> str:
    """sha256 over the sorted ``path\\0sha256\\n`` lines: order-independent, sensitive to any change."""
    digest = hashlib.sha256()
    for rel in sorted(files):
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(files[rel].encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


# --------------------------------------------------------------------------- signer


def _ed25519_public_key(public_key_pem: str | bytes) -> Any:
    """The parsed Ed25519 public key, or ``TypeError`` for any other key type."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    pem = public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("public key is not an Ed25519 key")
    return key


def public_key_id(public_key_pem: str | bytes) -> str:
    """The key id of an Ed25519 public key: the sha256 of its raw 32 bytes, as ``supply_chain.signing`` does."""
    from cryptography.hazmat.primitives import serialization

    key = _ed25519_public_key(public_key_pem)
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(bytes(raw)).hexdigest()


@dataclass
class EvidenceSigner:
    """An Ed25519 private key that signs manifest bytes. Holds the key object only, never its PEM."""

    _private_key: Any
    key_id: str
    public_key_pem: str
    algorithm: str = "ed25519"

    @classmethod
    def from_pem(cls, pem: bytes) -> EvidenceSigner:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("evidence signing key is not an Ed25519 key")
        public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        return cls(_private_key=key, key_id=public_key_id(public_pem), public_key_pem=public_pem)

    def sign(self, data: bytes) -> bytes:
        return bytes(self._private_key.sign(data))

    def describe(self) -> dict[str, Any]:
        """The secret-free view: algorithm and key id only."""
        return {"configured": True, "algorithm": self.algorithm, "key_id": self.key_id}


def load_evidence_signer(environ: os._Environ[str] | dict[str, str] | None = None) -> EvidenceSigner | None:
    """The signer named by the environment, or ``None`` when no key is configured.

    ``REDSIM_EVIDENCE_SIGNING_KEY_FILE`` names a PEM file; ``REDSIM_EVIDENCE_SIGNING_KEY`` carries the
    PEM text itself (a value pasted into a host's environment often has literal ``\\n`` sequences in
    place of newlines, so those are accepted). A key that cannot be parsed is an error, never a
    silent fall-back to an unsigned pack.
    """
    env = os.environ if environ is None else environ
    path = (env.get(KEY_FILE_ENV) or "").strip()
    inline = env.get(KEY_PEM_ENV) or ""
    if path:
        return EvidenceSigner.from_pem(Path(path).read_bytes())
    if inline.strip():
        return EvidenceSigner.from_pem(inline.replace("\\n", "\n").strip().encode("utf-8") + b"\n")
    return None


def signer_status(signer: EvidenceSigner | None) -> dict[str, Any]:
    """``{configured, algorithm, key_id}`` for the API and the Exports page. Never a PEM."""
    if signer is None:
        return {"configured": False, "algorithm": None, "key_id": None, "reason": UNSIGNED_REASON}
    return signer.describe()


def generate_keypair() -> tuple[bytes, bytes, str]:
    """A fresh Ed25519 keypair as ``(private_pem, public_pem, key_id)`` for ``redsim evidence keygen``."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem, public_key_id(public_pem)


# --------------------------------------------------------------------------- builder


@dataclass
class RunEvidencePack:
    """What :func:`build_run_evidence_pack` returns: the zip bytes and the manifest as written."""

    run_id: str
    project_id: str
    zip_bytes: bytes
    manifest: dict[str, Any]
    signed: bool
    key_id: str | None
    filename: str

    @property
    def pack_hash(self) -> str:
        return str(self.manifest.get("pack_hash", ""))


def _report_ext(kind: str) -> str | None:
    if kind.startswith("ml.report_"):
        return kind[len("ml.report_"):]
    if kind.startswith("report."):
        return kind.split(".", 1)[1]
    return None


def _checked_bytes(blob_store: Any, row: Any) -> bytes:
    data = blob_store.get(str(row.location))
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if _sha256(raw) != str(row.sha256):
        raise ValueError(f"artifact {row.id} ({row.kind}) bytes do not match the recorded digest")
    return raw


def _report_rows(session: Any, run_id: str, artifacts: list[Any]) -> dict[str, Any]:
    """The Artifact row per report format: the newest non-archived snapshot first, then the newest row."""
    from redsim.services.reports import newest_snapshot, snapshot_artifact

    chosen: dict[str, Any] = {}
    snap = newest_snapshot(session, run_id)
    if snap is not None:
        for ext in REPORT_FORMATS:
            row = snapshot_artifact(session, snap[0], ext)
            if row is not None:
                chosen[ext] = row
    for row in artifacts:  # newest first
        row_ext = _report_ext(str(row.kind))
        if row_ext is not None and row_ext in REPORT_FORMATS and row_ext not in chosen:
            chosen[row_ext] = row
    return chosen


def build_run_evidence_pack(
    session: Any,
    run_id: str,
    *,
    config: Any,
    blob_store: Any | None = None,
    signer: EvidenceSigner | None = None,
    audit_writer: Any | None = None,
    generated_at: datetime | None = None,
) -> RunEvidencePack:
    """Assemble, hash and (when a signer is given) sign the evidence pack of ``run_id``.

    Raises ``LookupError`` when the run does not exist or has no ``ml.run_record`` artifact and
    ``ValueError`` when any copied artifact fails its digest check. Reads only: no audit row, no
    database write.
    """
    from sqlalchemy import select

    from redsim.audit.chain import resolve_writer
    from redsim.db.models import Artifact, Run

    run = session.get(Run, run_id)
    if run is None:
        raise LookupError(f"run {run_id} not found")
    if blob_store is None:
        from redsim.storage.blobs import open_blob_store

        blob_store = open_blob_store(config)

    artifacts = list(session.execute(
        select(Artifact).where(Artifact.run_id == run_id)
        .order_by(Artifact.created_at.desc(), Artifact.id.desc())
    ).scalars().all())
    record_row = next((row for row in artifacts if str(row.kind) == _RUN_RECORD_KIND), None)
    if record_row is None:
        raise LookupError(f"run {run_id} has no {_RUN_RECORD_KIND} artifact")
    record_bytes = _checked_bytes(blob_store, record_row)

    files: dict[str, bytes] = {}
    files["run.json"] = _dumps({
        "id": str(run.id),
        "project_id": str(run.project_id),
        "target_id": str(run.target_id) if run.target_id else None,
        "scanner": run.scanner,
        "mode": run.mode,
        "status": str(run.status),
        "created_at": _iso(run.created_at),
        "completed_at": _iso(getattr(run, "completed_at", None)),
        "stage_table": run.stage_table or {},
    })
    files["record/run_record.json"] = record_bytes

    included: list[str] = []
    for ext, row in _report_rows(session, run_id, artifacts).items():
        files[f"reports/report.{ext}"] = _checked_bytes(blob_store, row)
        included.append(ext)
    included = [ext for ext in REPORT_FORMATS if ext in included]
    missing = [ext for ext in REPORT_FORMATS if ext not in included]

    files["artifacts/index.json"] = _dumps({
        "run_id": str(run.id),
        "count": len(artifacts),
        "artifacts": [
            {
                "id": str(row.id), "kind": str(row.kind), "sha256": str(row.sha256),
                "size_bytes": int(row.size_bytes or 0), "content_type": str(row.content_type),
                "created_at": _iso(row.created_at),
            }
            for row in artifacts
        ],
    })

    writer = audit_writer if audit_writer is not None else resolve_writer(config)
    chain_id = f"run:{run_id}"
    events = list(writer.read_chain(chain_id))
    verdict = verify_chain(iter(events))
    files["audit/run.jsonl"] = "".join(json.dumps(e, default=str) + "\n" for e in events).encode("utf-8")
    files["audit/verification.json"] = _dumps({
        "chain_id": chain_id, "verified": verdict.verified, "count": verdict.count,
        "broken_at": verdict.broken_at, "reason": verdict.reason,
    })

    digests = {path: _sha256(data) for path, data in files.items()}
    manifest: dict[str, Any] = {
        "format": PACK_FORMAT,
        "run_id": str(run.id),
        "project_id": str(run.project_id),
        "generated_at": (generated_at or datetime.now(UTC)).isoformat(),
        "redsim_version": __version__,
        "record_sha256": str(record_row.sha256),
        "record_artifact_id": str(record_row.id),
        "chain": {"id": chain_id, "verified": verdict.verified, "count": verdict.count},
        "reports": {"included": included, "missing": missing},
        "artifact_count": len(artifacts),
        "files": digests,
        "pack_hash": compute_pack_hash(digests),
    }
    manifest_bytes = _dumps(manifest)
    files["manifest.json"] = manifest_bytes
    if signer is not None:
        files["manifest.sig"] = (binascii.hexlify(signer.sign(manifest_bytes)).decode("ascii") + "\n").encode("ascii")
        files["signer.json"] = _dumps({
            "algorithm": signer.algorithm, "key_id": signer.key_id,
            "public_key_pem": signer.public_key_pem, "signed": True,
            "signed_file": "manifest.json",
        })
    else:
        files["signer.json"] = _dumps({"algorithm": None, "key_id": None, "signed": False, "reason": UNSIGNED_REASON})

    prefix = f"redsim-evidence-{run_id}"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            info = zipfile.ZipInfo(f"{prefix}/{path}", date_time=_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, files[path])
    logger.info("evidence pack built run_id=%s files=%d signed=%s", run_id, len(files), signer is not None)
    return RunEvidencePack(
        run_id=str(run.id), project_id=str(run.project_id), zip_bytes=buffer.getvalue(), manifest=manifest,
        signed=signer is not None, key_id=signer.key_id if signer is not None else None,
        filename=f"{prefix}.zip",
    )


# --------------------------------------------------------------------------- verifier


@dataclass
class EvidenceVerification:
    """Every check the offline verifier runs, one boolean each, plus what went wrong."""

    run_id: str | None = None
    format: str | None = None
    files_match: bool = False
    pack_hash_matches: bool = False
    record_digest_matches: bool = False
    chain_verified: bool = False
    chain_count: int = 0
    signature_present: bool = False
    signature_valid: bool = False
    key_id: str | None = None
    trusted_key_matches: bool | None = None
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Every check true. An unsigned pack is never ok: the signature is the point."""
        checks = [self.files_match, self.pack_hash_matches, self.record_digest_matches,
                  self.chain_verified, self.signature_present, self.signature_valid]
        if self.trusted_key_matches is not None:
            checks.append(self.trusted_key_matches)
        return all(checks) and not self.problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok, "run_id": self.run_id, "format": self.format,
            "files_match": self.files_match, "pack_hash_matches": self.pack_hash_matches,
            "record_digest_matches": self.record_digest_matches,
            "chain_verified": self.chain_verified, "chain_count": self.chain_count,
            "signature_present": self.signature_present, "signature_valid": self.signature_valid,
            "key_id": self.key_id, "trusted_key_matches": self.trusted_key_matches,
            "problems": list(self.problems),
        }


def _read_pack(source: bytes | str | os.PathLike[str]) -> dict[str, bytes]:
    """The pack's files keyed by their path under the single top-level directory."""
    raw = source if isinstance(source, bytes) else Path(source).read_bytes()
    out: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            parts = info.filename.split("/", 1)
            rel = parts[1] if len(parts) == 2 else parts[0]
            out[rel] = archive.read(info)
    return out


def verify_evidence_pack(
    source: bytes | str | os.PathLike[str],
    *,
    trusted_public_key_pem: str | bytes | None = None,
) -> EvidenceVerification:
    """Re-check a pack offline: digests, pack hash, record digest, audit chain, signature.

    ``trusted_public_key_pem`` pins the signer: the embedded public key must have the same key id
    and the signature must verify under the trusted key too.
    """
    from cryptography.exceptions import InvalidSignature

    result = EvidenceVerification()
    try:
        files = _read_pack(source)
    except (zipfile.BadZipFile, OSError) as exc:
        result.problems.append(f"not a readable zip: {exc}")
        return result

    manifest_bytes = files.get("manifest.json")
    if manifest_bytes is None:
        result.problems.append("manifest.json missing")
        return result
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        result.problems.append(f"manifest.json unreadable: {exc}")
        return result
    result.run_id = manifest.get("run_id")
    result.format = manifest.get("format")
    if result.format != PACK_FORMAT:
        result.problems.append(f"unknown pack format {result.format!r}")

    # Every hashed file present with the recorded digest, and nothing hashed that is absent.
    recorded = manifest.get("files") or {}
    mismatched: list[str] = []
    for rel, expected in sorted(recorded.items()):
        data = files.get(rel)
        if data is None or _sha256(data) != expected:
            mismatched.append(rel)
    extra = sorted(set(files) - set(recorded) - _UNHASHED)
    result.files_match = not mismatched and not extra
    for rel in mismatched:
        result.problems.append(f"digest mismatch or missing file: {rel}")
    for rel in extra:
        result.problems.append(f"file not in manifest: {rel}")

    result.pack_hash_matches = compute_pack_hash(dict(recorded)) == manifest.get("pack_hash")
    if not result.pack_hash_matches:
        result.problems.append("pack_hash does not match the file digests")

    record = files.get("record/run_record.json")
    result.record_digest_matches = record is not None and _sha256(record) == manifest.get("record_sha256")
    if not result.record_digest_matches:
        result.problems.append("run record digest does not match the manifest")

    events: list[dict[str, Any]] = []
    for line in (files.get("audit/run.jsonl") or b"").decode("utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    verdict = verify_chain(iter(events))
    result.chain_count = verdict.count
    chain_manifest = manifest.get("chain") or {}
    result.chain_verified = verdict.verified and verdict.count == chain_manifest.get("count")
    if not result.chain_verified:
        result.problems.append(verdict.reason or "audit chain count differs from the manifest")

    signer_bytes = files.get("signer.json")
    signer_doc = json.loads(signer_bytes) if signer_bytes else {}
    signature_hex = (files.get("manifest.sig") or b"").decode("ascii", "replace").strip()
    result.signature_present = bool(signature_hex) and bool(signer_doc.get("public_key_pem"))
    if not result.signature_present:
        result.problems.append(str(signer_doc.get("reason") or "the pack is not signed"))
        if trusted_public_key_pem is not None:
            result.trusted_key_matches = False
        return result

    try:
        signature = binascii.unhexlify(signature_hex)
        _ed25519_public_key(str(signer_doc["public_key_pem"])).verify(signature, manifest_bytes)
        result.signature_valid = True
        result.key_id = public_key_id(str(signer_doc["public_key_pem"]))
        if result.key_id != signer_doc.get("key_id"):
            result.signature_valid = False
            result.problems.append("signer.json key_id does not match its public key")
    except (InvalidSignature, ValueError, TypeError, binascii.Error) as exc:
        result.signature_valid = False
        result.problems.append(f"signature does not verify: {exc.__class__.__name__}")

    if trusted_public_key_pem is not None:
        try:
            trusted_id = public_key_id(trusted_public_key_pem)
            _ed25519_public_key(trusted_public_key_pem).verify(binascii.unhexlify(signature_hex), manifest_bytes)
            result.trusted_key_matches = trusted_id == result.key_id
        except (InvalidSignature, ValueError, TypeError, binascii.Error):
            result.trusted_key_matches = False
        if not result.trusted_key_matches:
            result.problems.append("the pack was not signed by the trusted key")
    return result


__all__ = [
    "KEY_FILE_ENV",
    "KEY_PEM_ENV",
    "PACK_FORMAT",
    "REPORT_FORMATS",
    "UNSIGNED_REASON",
    "EvidenceSigner",
    "EvidenceVerification",
    "RunEvidencePack",
    "build_run_evidence_pack",
    "compute_pack_hash",
    "generate_keypair",
    "load_evidence_signer",
    "public_key_id",
    "signer_status",
    "verify_evidence_pack",
]
