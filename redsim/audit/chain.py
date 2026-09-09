"""Hash-chained audit log.

Each ``AuditEvent`` carries ``prev_hash`` (the previous event's
``this_hash``) and ``this_hash = sha256(prev_hash || canonical_json(record))``.
Chains are per ``(project, run)`` for per-run integrity, per project for
project-scope events, or global (``system``) for install-wide events.

Two backends:

- ``JsonlAuditWriter`` — filesystem; one ``.jsonl`` per chain under
  ``audit/<chain_id>.jsonl``. The Phase 2 ``audit.jsonl`` lives next to
  this (different filename) so existing tests stay valid.
- ``PostgresAuditWriter`` — locks ``audit_chain_heads`` and writes via the
  ORM. Unique constraints enforce monotonic sequence + no duplicate hashes.

Timestamps. ``ts`` is part of the hashed record, so the verifier must see
the byte-identical string the writer hashed. Every writer renders it with
:func:`canonical_ts` (UTC, ``datetime.isoformat()``, ``+00:00`` suffix)
and ``PostgresAuditWriter.read_chain`` re-derives it from ``created_at``
through the same function, so a naive sqlite ``DateTime`` (offset dropped
in storage) or a Postgres ``timestamptz`` rendered in a non-UTC session
zone both come back as the hashed ``+00:00`` string. Rows written before
this normalisation were hashed over ``datetime.now(UTC).isoformat()``,
which is the same string, so they stay verifiable.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from redsim.audit.redact import redact_audit_detail

if TYPE_CHECKING:
    from contextlib import AbstractContextManager

    from sqlalchemy.orm import Session

    from redsim.config import RedsimConfig

SCHEMA_VERSION = 1


@dataclass
class AuditEvent:
    chain_id: str
    seq: int
    ts: str
    actor: str
    action: str
    target: str | None
    allowlist_check: str
    override: bool
    success: bool
    detail: dict[str, Any]
    schema_version: int = SCHEMA_VERSION
    prev_hash: str | None = None    # hex
    this_hash: str = ""             # hex
    run_id: str | None = None
    project_id: str | None = None

    def to_record(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    verified: bool
    count: int
    broken_at: int | None = None
    reason: str | None = None
    chain_id: str | None = None


def canonical_json(record: dict[str, Any]) -> bytes:
    """Deterministic JSON encoding for hashing.

    Excludes ``this_hash`` (the field we're about to compute) so the
    record's own hash field doesn't influence the hash.
    """
    payload = {k: v for k, v in record.items() if k != "this_hash"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")


def compute_hash(prev_hash_hex: str | None, record: dict[str, Any]) -> str:
    prev_bytes = bytes.fromhex(prev_hash_hex) if prev_hash_hex else b""
    digest = hashlib.sha256(prev_bytes + canonical_json(record)).hexdigest()
    return digest


def canonical_ts(value: datetime) -> str:
    """Render an event timestamp exactly as it is hashed.

    UTC, ``datetime.isoformat()`` (microseconds present unless zero, as
    ``isoformat`` renders them), ``+00:00`` suffix. A naive datetime is
    taken as UTC (the writers only ever store UTC instants, and sqlite's
    ``DateTime`` storage hands them back without the offset) and an aware
    one is converted, which is what a Postgres ``timestamptz`` needs when the
    session ``TimeZone`` is not UTC. Same instant in, same string out on both
    the write and the read side, so the recomputed hash matches.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        value = value.replace(tzinfo=UTC)
    else:
        value = value.astimezone(UTC)
    return value.isoformat()


def _chain_id(project_id: str | None, run_id: str | None) -> str:
    """Resolve an event's hash-chain id: per run, else per project, else the
    install-wide ``system`` chain. Shared by every writer backend so the
    keying can't drift between them."""
    if run_id:
        return f"run:{run_id}"
    if project_id:
        return f"project:{project_id}"
    return "system"


# ----------------------------------------------------------------------------
# Writer Protocol + backends
# ----------------------------------------------------------------------------


class AuditWriter(Protocol):
    def append(self, *, action: str, actor: str, target: str | None,
               allowlist_check: str, override: bool, success: bool,
               detail: dict[str, Any],
               run_id: str | None = None,
               project_id: str | None = None) -> AuditEvent: ...

    def read_chain(self, chain_id: str) -> Iterable[dict[str, Any]]: ...

    def iter_chain_ids(self) -> Iterator[str]: ...


class JsonlAuditWriter:
    """Filesystem chain writer.

    Two on-disk layout modes:

    - **Per-chain files** (``single_file=None``, default): one file per
      chain id under ``directory``, named ``<chain_safe>.jsonl``. This
      is the Phase 4 canonical layout for ``<output_dir>/audit/``.
    - **Single file** (``single_file="audit.jsonl"``): all events from
      every chain land in one file under ``directory``. Used as the
      Phase 2 / Phase 3 compatibility path when ``authorize()`` is
      invoked with only ``run_path`` — the audit ends up at
      ``<run_path>/audit.jsonl`` exactly where the old ``_append_audit``
      helper wrote it. Each event still carries its full chain metadata
      (chain_id, seq, prev_hash, this_hash); only the file naming
      changes. Chains stay logically separate inside the file.
    """

    def __init__(self, directory: Path, *, single_file: str | None = None):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._single_file = single_file
        self._locks: dict[str, threading.Lock] = {}
        self._global_lock = threading.Lock()

    def _path(self, chain_id: str) -> Path:
        if self._single_file is not None:
            return self.directory / self._single_file
        # Filenames can't contain ':' on all filesystems; replace with '__'.
        safe = chain_id.replace(":", "__").replace("/", "_")
        return self.directory / f"{safe}.jsonl"

    def _lock(self, chain_id: str) -> threading.Lock:
        with self._global_lock:
            if chain_id not in self._locks:
                self._locks[chain_id] = threading.Lock()
            return self._locks[chain_id]

    def _last(self, chain_id: str) -> tuple[int, str | None]:
        path = self._path(chain_id)
        if not path.exists():
            return 0, None
        last_seq = 0
        last_hash: str | None = None
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            # Single-file mode interleaves chains in one file; skip foreign
            # ones so each chain keeps its own seq/prev_hash continuity.
            if self._single_file is not None and rec.get("chain_id") != chain_id:
                continue
            last_seq = rec["seq"]
            last_hash = rec["this_hash"]
        return last_seq, last_hash

    def append(self, *, action: str, actor: str, target: str | None,
               allowlist_check: str, override: bool, success: bool,
               detail: dict[str, Any],
               run_id: str | None = None,
               project_id: str | None = None) -> AuditEvent:
        chain_id = _chain_id(project_id, run_id)
        redacted_detail = redact_audit_detail(detail or {})
        with self._lock(chain_id):
            prev_seq, prev_hash = self._last(chain_id)
            seq = prev_seq + 1
            record = {
                "chain_id": chain_id,
                "seq": seq,
                "ts": canonical_ts(datetime.now(UTC)),
                "actor": actor,
                "action": action,
                "target": target,
                "allowlist_check": allowlist_check,
                "override": override,
                "success": success,
                "detail": redacted_detail,
                "schema_version": SCHEMA_VERSION,
                "prev_hash": prev_hash,
                "run_id": run_id,
                "project_id": project_id,
            }
            this_hash = compute_hash(prev_hash, record)
            record["this_hash"] = this_hash
            with open(self._path(chain_id), "a") as fh:
                fh.write(json.dumps(record) + "\n")
        return AuditEvent(**{k: v for k, v in record.items()
                             if k in AuditEvent.__dataclass_fields__})

    def read_chain(self, chain_id: str) -> Iterator[dict[str, Any]]:
        path = self._path(chain_id)
        if not path.exists():
            return iter(())
        single_file = self._single_file is not None
        def _iter() -> Iterator[dict[str, Any]]:
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if single_file and rec.get("chain_id") != chain_id:
                    continue
                yield rec
        return _iter()

    def iter_chain_ids(self) -> Iterator[str]:
        if self._single_file is not None:
            # One file holds every chain: the ids live inside the records,
            # not in the filename. Yield each distinct id once, in order of
            # first appearance, so ``--all`` over an offline run directory
            # verifies exactly the chains the file carries.
            path = self.directory / self._single_file
            if not path.exists():
                return
            seen: set[str] = set()
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                chain_id = json.loads(line).get("chain_id")
                if chain_id and chain_id not in seen:
                    seen.add(chain_id)
                    yield chain_id
            return
        for path in self.directory.glob("*.jsonl"):
            yield path.stem.replace("__", ":")


class PostgresAuditWriter:
    """Postgres chain writer.

    Locks the ``audit_chain_heads`` row for the chain, computes the hash,
    inserts the event, updates the head, commits. UNIQUE constraints on
    ``audit_events`` catch any concurrent fork.
    """

    def __init__(
        self, session_factory: Callable[[], AbstractContextManager[Session]]
    ) -> None:
        # session_factory: callable returning a context manager that yields a Session.
        self.session_factory = session_factory

    def append(self, *, action: str, actor: str, target: str | None,
               allowlist_check: str, override: bool, success: bool,
               detail: dict[str, Any],
               run_id: str | None = None,
               project_id: str | None = None) -> AuditEvent:
        from sqlalchemy import select

        from redsim.db.models import AuditChainHead
        from redsim.db.models import AuditEvent as AEModel

        chain_id = _chain_id(project_id, run_id)
        redacted_detail = redact_audit_detail(detail or {})

        with self.session_factory() as sess:
            head = sess.execute(
                select(AuditChainHead).where(AuditChainHead.chain_id == chain_id)
                .with_for_update()
            ).scalar_one_or_none()
            if head is None:
                head = AuditChainHead(chain_id=chain_id, head_seq=0,
                                      head_hash=None)
                sess.add(head)
                sess.flush()
            seq = head.head_seq + 1
            prev_hash_hex = head.head_hash.hex() if head.head_hash else None
            # ``ts`` is the hashed rendering of the event time and
            # ``created_at`` is the same instant. ``read_chain`` re-derives
            # ``ts`` from ``created_at`` through ``canonical_ts`` so the
            # verifier recomputes the identical hash on any backend / zone.
            now = datetime.now(UTC)
            ts = canonical_ts(now)
            record = {
                "chain_id": chain_id, "seq": seq,
                "ts": ts,
                "actor": actor, "action": action, "target": target,
                "allowlist_check": allowlist_check,
                "override": override, "success": success,
                "detail": redacted_detail,
                "schema_version": SCHEMA_VERSION,
                "prev_hash": prev_hash_hex,
                "run_id": run_id, "project_id": project_id,
            }
            this_hash_hex = compute_hash(prev_hash_hex, record)
            this_hash = bytes.fromhex(this_hash_hex)
            sess.add(AEModel(
                chain_id=chain_id, seq=seq,
                project_id=project_id, run_id=run_id,
                actor=actor, action=action, target=target,
                allowlist_check=allowlist_check, override=override,
                success=success, detail=redacted_detail,
                schema_version=SCHEMA_VERSION,
                prev_hash=head.head_hash,
                this_hash=this_hash,
                created_at=now,
            ))
            head.head_seq = seq
            head.head_hash = this_hash
            record["this_hash"] = this_hash_hex
        return AuditEvent(**{k: v for k, v in record.items()
                             if k in AuditEvent.__dataclass_fields__})

    def read_chain(self, chain_id: str) -> Iterator[dict[str, Any]]:
        from sqlalchemy import select

        from redsim.db.models import AuditEvent as AEModel

        with self.session_factory() as sess:
            rows = sess.execute(
                select(AEModel).where(AEModel.chain_id == chain_id)
                .order_by(AEModel.seq)
            ).scalars().all()
            for row in rows:
                yield {
                    "chain_id": row.chain_id, "seq": row.seq,
                    # Not ``created_at.isoformat()``: sqlite returns the
                    # instant naive and Postgres renders it in the session
                    # zone, and only the canonical UTC string was hashed.
                    "ts": canonical_ts(row.created_at) if row.created_at else None,
                    "actor": row.actor, "action": row.action,
                    "target": row.target,
                    "allowlist_check": row.allowlist_check,
                    "override": row.override, "success": row.success,
                    "detail": row.detail or {},
                    "schema_version": row.schema_version,
                    "prev_hash": row.prev_hash.hex() if row.prev_hash else None,
                    "this_hash": row.this_hash.hex(),
                    "run_id": row.run_id, "project_id": row.project_id,
                }

    def iter_chain_ids(self) -> Iterator[str]:
        from sqlalchemy import select

        from redsim.db.models import AuditChainHead
        with self.session_factory() as sess:
            yield from sess.execute(select(AuditChainHead.chain_id)).scalars()


# ----------------------------------------------------------------------------
# Verify
# ----------------------------------------------------------------------------


def verify_chain(events: Iterable[dict[str, Any]]) -> VerificationResult:
    """Walk an ordered chain and return a verification verdict."""
    prev_hash: str | None = None
    expected_seq = 1
    count = 0
    chain_id: str | None = None
    for record in events:
        count += 1
        if chain_id is None:
            chain_id = record.get("chain_id")
        seq = record.get("seq")
        if seq != expected_seq:
            return VerificationResult(
                verified=False, count=count, broken_at=seq,
                reason=f"seq gap: expected {expected_seq}, got {seq}",
                chain_id=chain_id,
            )
        if record.get("prev_hash") != prev_hash:
            return VerificationResult(
                verified=False, count=count, broken_at=seq,
                reason=(f"prev_hash mismatch at seq {seq}: "
                        f"expected {prev_hash}, got {record.get('prev_hash')}"),
                chain_id=chain_id,
            )
        if record.get("schema_version") != SCHEMA_VERSION:
            return VerificationResult(
                verified=False, count=count, broken_at=seq,
                reason=(f"unknown schema_version {record.get('schema_version')} "
                        f"at seq {seq}"),
                chain_id=chain_id,
            )
        recomputed = compute_hash(prev_hash, record)
        if recomputed != record.get("this_hash"):
            return VerificationResult(
                verified=False, count=count, broken_at=seq,
                reason=(f"hash mismatch at seq {seq}: "
                        f"expected {recomputed}, got {record.get('this_hash')}"),
                chain_id=chain_id,
            )
        prev_hash = record["this_hash"]
        expected_seq += 1
    return VerificationResult(verified=True, count=count, chain_id=chain_id)


# ----------------------------------------------------------------------------
# In-memory writer (tests)
# ----------------------------------------------------------------------------


class InMemoryAuditWriter:
    """Test-only writer that collects events into ``self.events`` for
    assertions. Implements the ``AuditWriter`` Protocol; ``resolve_writer``
    selects it when ``REDSIM_TEST_AUDIT=memory``.
    """

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self._chains: dict[str, list[dict[str, Any]]] = {}

    def append(self, *, action: str, actor: str, target: str | None,
               allowlist_check: str, override: bool, success: bool,
               detail: dict[str, Any],
               run_id: str | None = None,
               project_id: str | None = None) -> AuditEvent:
        chain_id = _chain_id(project_id, run_id)
        seq = len(self._chains.get(chain_id, [])) + 1
        event = AuditEvent(
            chain_id=chain_id, seq=seq,
            ts=canonical_ts(datetime.now(UTC)),
            actor=actor, action=action, target=target,
            allowlist_check=allowlist_check, override=override,
            success=success, detail=dict(detail or {}),
            run_id=run_id, project_id=project_id,
        )
        self.events.append(event)
        self._chains.setdefault(chain_id, []).append(event.to_record())
        return event

    def read_chain(self, chain_id: str) -> Iterator[dict[str, Any]]:
        return iter(self._chains.get(chain_id, []))

    def iter_chain_ids(self) -> Iterator[str]:
        return iter(self._chains.keys())


# ----------------------------------------------------------------------------
# Writer resolution
# ----------------------------------------------------------------------------


def resolve_writer(config_or_dir: RedsimConfig | str | Path) -> AuditWriter:
    """Pick the writer based on environment / config.

    Resolution order:

    - ``REDSIM_TEST_AUDIT=memory`` → ``InMemoryAuditWriter`` (test seam).
    - ``REDSIM_DB_URL`` set → ``PostgresAuditWriter`` over the initialised
      session factory.
    - otherwise → ``JsonlAuditWriter`` rooted at ``<output_dir>/audit/``,
      where ``output_dir`` is ``config_or_dir.output_dir`` (a config
      object) or ``config_or_dir`` itself (a path).

    This is the single audit-writer selector — the duplicate
    ``redsim.audit.writers.open_writer`` was folded in here during the F7
    cleanup. Request-scoped callers pass the result to
    ``authorize(writer=…)``.
    """
    if os.environ.get("REDSIM_TEST_AUDIT") == "memory":
        return InMemoryAuditWriter()
    db_url = os.environ.get("REDSIM_DB_URL")
    if db_url:
        from redsim.db.session import get_session, init_engine
        init_engine(db_url)
        return PostgresAuditWriter(session_factory=get_session)

    if hasattr(config_or_dir, "output_dir"):
        base = Path(config_or_dir.output_dir) / "audit"
    else:
        base = Path(str(config_or_dir)) / "audit"
    return JsonlAuditWriter(base)
