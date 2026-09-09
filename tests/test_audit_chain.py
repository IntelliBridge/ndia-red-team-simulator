"""Hash-chain integrity tests (filesystem backend; Postgres parity is
exercised when REDSIM_TEST_DB_URL is set).

The ``PostgresAuditWriter`` timestamp tests at the bottom run it over the
shared sqlite harness from ``tests.conftest``, the same ORM writer and
verifier production uses, with sqlite standing in for Postgres. They are
function-style so only they carry the ``integration`` marker (the harness
skips when sqlalchemy is absent). The unittest classes above stay in the
unit tier.
"""

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from redsim.audit.chain import (
    JsonlAuditWriter,
    canonical_ts,
    verify_chain,
)
from redsim.audit.redact import redact_audit_detail
from tests.conftest import make_sqlite_session_factory


class TestHappyPath(unittest.TestCase):
    def test_n_events_verify_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            for i in range(5):
                writer.append(
                    action="scan.start", actor="cli:alice",
                    target="http://localhost:3000",
                    allowlist_check="pass", override=False, success=True,
                    detail={"seq": i}, run_id="run-1", project_id="proj-1",
                )
            events = list(writer.read_chain("run:run-1"))
            self.assertEqual(len(events), 5)
            result = verify_chain(events)
            self.assertTrue(result.verified, msg=result.reason)
            self.assertEqual(result.count, 5)


class TestTamperDetection(unittest.TestCase):
    def _writer(self, tmp: str) -> JsonlAuditWriter:
        return JsonlAuditWriter(Path(tmp))

    def test_mutation_breaks_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = self._writer(tmp)
            for i in range(3):
                writer.append(
                    action="a", actor="cli", target="localhost",
                    allowlist_check="pass", override=False, success=True,
                    detail={"i": i}, run_id="r", project_id="p",
                )
            chain_path = next(Path(tmp).glob("*.jsonl"))
            lines = chain_path.read_text().splitlines()
            tampered = json.loads(lines[1])
            tampered["detail"]["i"] = 999
            lines[1] = json.dumps(tampered)
            chain_path.write_text("\n".join(lines) + "\n")
            events = list(writer.read_chain("run:r"))
            result = verify_chain(events)
            self.assertFalse(result.verified)
            self.assertEqual(result.broken_at, 2)
            self.assertIn("hash mismatch", result.reason)

    def test_deletion_breaks_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = self._writer(tmp)
            for i in range(4):
                writer.append(
                    action="a", actor="cli", target="localhost",
                    allowlist_check="pass", override=False, success=True,
                    detail={"i": i}, run_id="r", project_id="p",
                )
            chain_path = next(Path(tmp).glob("*.jsonl"))
            lines = chain_path.read_text().splitlines()
            del lines[1]            # drop seq=2
            chain_path.write_text("\n".join(lines) + "\n")
            events = list(writer.read_chain("run:r"))
            result = verify_chain(events)
            self.assertFalse(result.verified)
            self.assertEqual(result.broken_at, 3)
            self.assertIn("seq gap", result.reason)

    def test_unknown_schema_version_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = self._writer(tmp)
            writer.append(
                action="a", actor="cli", target="localhost",
                allowlist_check="pass", override=False, success=True,
                detail={"i": 0}, run_id="r", project_id="p",
            )
            chain_path = next(Path(tmp).glob("*.jsonl"))
            rec = json.loads(chain_path.read_text().strip())
            rec["schema_version"] = 999
            chain_path.write_text(json.dumps(rec) + "\n")
            result = verify_chain(list(writer.read_chain("run:r")))
            self.assertFalse(result.verified)
            self.assertIn("schema_version", result.reason)


class TestRedaction(unittest.TestCase):
    def test_authorization_header_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            writer.append(
                action="x", actor="cli", target=None,
                allowlist_check="n/a", override=False, success=True,
                detail={
                    "headers": {"Authorization": "Bearer ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                    "password": "hunter2",
                },
                run_id=None, project_id="p",
            )
            chain_path = next(Path(tmp).glob("*.jsonl"))
            rec = json.loads(chain_path.read_text().strip())
            self.assertEqual(rec["detail"]["headers"]["Authorization"], "<REDACTED>")
            self.assertEqual(rec["detail"]["password"], "<REDACTED>")


class TestTokenRedaction(unittest.TestCase):
    """GOV-41 / G-REDACT: the Pythia ``pk_`` key and both Kaggle credential
    shapes are scrubbed from audit detail, by value and by key."""

    PYTHIA_KEY = "pk_fixture-not-a-real-key-0123456789-abcdef"
    KAGGLE_TOKEN = "KGAT_test_token_value_never_logged"
    KAGGLE_KEY = "kagglefakekagglefakekagglefake00"  # low-entropy, 32 alnum

    def test_pythia_key_scrubbed_from_string_values(self):
        out = redact_audit_detail({
            "note": f"Authorization: Bearer {self.PYTHIA_KEY} sent to gateway",
            "nested": [f"key={self.PYTHIA_KEY}"],
        })
        self.assertNotIn("pk_fixture", json.dumps(out))
        self.assertEqual(out["note"], "Authorization: Bearer <REDACTED> sent to gateway")
        self.assertEqual(out["nested"], ["key=<REDACTED>"])

    def test_kaggle_token_scrubbed_from_string_values(self):
        out = redact_audit_detail(f"export KAGGLE_API_TOKEN='{self.KAGGLE_TOKEN}'")
        self.assertNotIn("KGAT_test", out)
        self.assertIn("<REDACTED>", out)

    def test_legacy_kaggle_key_inline_scrubbed(self):
        for text in (
            f"KAGGLE_KEY={self.KAGGLE_KEY}",
            f'"kaggle_key": "{self.KAGGLE_KEY}"',
            f"kaggle_key: {self.KAGGLE_KEY}",
        ):
            with self.subTest(text=text):
                out = redact_audit_detail(text)
                self.assertNotIn(self.KAGGLE_KEY, out)
                self.assertIn("<REDACTED>", out)

    def test_credential_keys_redacted_by_name(self):
        out = redact_audit_detail({
            "PYTHIA_API_KEY": self.PYTHIA_KEY,
            "KAGGLE_API_TOKEN": self.KAGGLE_TOKEN,
            "KAGGLE_KEY": self.KAGGLE_KEY,
            "kaggle-key": self.KAGGLE_KEY,
            "KAGGLE_USERNAME": "alice",
            "base_url": "https://gw.example",
            "model": "pythia/auto",
        })
        for key in ("PYTHIA_API_KEY", "KAGGLE_API_TOKEN", "KAGGLE_KEY", "kaggle-key"):
            self.assertEqual(out[key], "<REDACTED>", key)
        # Non-secret Pythia settings (what PythiaSettings.redacted() keeps) survive.
        self.assertEqual(out["KAGGLE_USERNAME"], "alice")
        self.assertEqual(out["base_url"], "https://gw.example")
        self.assertEqual(out["model"], "pythia/auto")

    def test_short_or_benign_identifiers_untouched(self):
        benign = "pk_x pk_ref KGAT_ id=abc123 stage=attack:pgd"
        self.assertEqual(redact_audit_detail(benign), benign)

    def test_chain_writer_scrubs_pythia_and_kaggle_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            writer.append(
                action="harden.execute", actor="worker:redsim.ml_campaign_run",
                target=None, allowlist_check="n/a", override=False, success=True,
                detail={
                    "pythia": {"api_key": self.PYTHIA_KEY, "model": "pythia/auto"},
                    "debug": f"bearer {self.PYTHIA_KEY}; kaggle {self.KAGGLE_TOKEN}",
                },
                run_id="run-1", project_id="p",
            )
            raw = next(Path(tmp).glob("*.jsonl")).read_text()
        self.assertNotIn("pk_fixture", raw)
        self.assertNotIn("KGAT_test", raw)
        rec = json.loads(raw.strip())
        self.assertEqual(rec["detail"]["pythia"]["api_key"], "<REDACTED>")
        self.assertEqual(rec["detail"]["pythia"]["model"], "pythia/auto")
        self.assertEqual(rec["detail"]["debug"], "bearer <REDACTED>; kaggle <REDACTED>")


class TestSingleFileChainIds(unittest.TestCase):
    """Single-file mode names its chains inside the records, not in the filename."""

    def test_iter_chain_ids_lists_the_chains_the_file_carries(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp), single_file="audit.jsonl")
            self.assertEqual(list(writer.iter_chain_ids()), [])
            for run_id, project_id in (("r1", None), (None, "p1"), ("r1", None)):
                writer.append(
                    action="a", actor="cli", target=None,
                    allowlist_check="pass", override=False, success=True,
                    detail={}, run_id=run_id, project_id=project_id,
                )
            # Distinct ids, first-appearance order, never the file stem "audit".
            self.assertEqual(list(writer.iter_chain_ids()), ["run:r1", "project:p1"])
            for chain_id in writer.iter_chain_ids():
                result = verify_chain(writer.read_chain(chain_id))
                self.assertTrue(result.verified, msg=result.reason)


# ---------------------------------------------------------------------------
# Timestamp canonicalisation (``PostgresAuditWriter`` on the sqlite harness)
#
# ``ts`` is hashed, and ``read_chain`` re-derives it from ``created_at``. The
# old ``created_at.isoformat()`` lost the ``+00:00`` on sqlite (naive
# storage) and rendered the session zone on Postgres, so every chain failed
# at seq=1 unless a tz shim was installed around the driver. ``canonical_ts``
# makes the write and the read side produce the identical string.
# ---------------------------------------------------------------------------

_TS_RUN = "run-ts-1"
_TS_CHAIN = f"run:{_TS_RUN}"


def _append_three(writer):
    return [
        writer.append(
            action="scan.start", actor="cli:alice", target="http://localhost:3000",
            allowlist_check="pass", override=False, success=True,
            detail={"i": i}, run_id=_TS_RUN, project_id="proj-1",
        )
        for i in range(3)
    ]


def _stored_created_at(session_cm):
    from sqlalchemy import select

    from redsim.db.models import AuditEvent as AEModel

    with session_cm() as sess:
        return sess.execute(
            select(AEModel.created_at).where(AEModel.chain_id == _TS_CHAIN)
            .order_by(AEModel.seq)
        ).scalars().all()


def test_canonical_ts_renders_the_hashed_utc_string_for_naive_and_aware_inputs():
    instant = datetime(2026, 9, 8, 12, 34, 56, 789012, tzinfo=UTC)
    expected = instant.isoformat()
    assert expected.endswith("+00:00")
    assert canonical_ts(instant) == expected
    # sqlite hands the instant back naive: taken as UTC.
    assert canonical_ts(instant.replace(tzinfo=None)) == expected
    # psycopg under a non-UTC session TimeZone hands it back aware in that zone: converted.
    assert canonical_ts(instant.astimezone(timezone(timedelta(hours=-5)))) == expected
    assert canonical_ts(instant.astimezone(timezone(timedelta(hours=5, minutes=30)))) == expected
    # Whole seconds render without a fractional part, exactly as the hashed isoformat() did.
    whole = instant.replace(microsecond=0)
    assert canonical_ts(whole.replace(tzinfo=None)) == whole.isoformat()
    assert not whole.isoformat().endswith(".000000+00:00")


def test_postgres_writer_sqlite_round_trip_verifies_without_a_tz_shim(sqlite_session_factory):
    """The stock sqlite ``DateTime`` (no harness shim) drops the offset, and the chain still verifies."""
    from redsim.audit.chain import PostgresAuditWriter

    writer = PostgresAuditWriter(session_factory=sqlite_session_factory.session_cm)
    written = _append_three(writer)

    stored = _stored_created_at(sqlite_session_factory.session_cm)
    assert len(stored) == 3
    # The bug's trigger: the driver returns the instant naive, so the old
    # ``created_at.isoformat()`` would have produced a string without ``+00:00``.
    assert all(dt.tzinfo is None for dt in stored)
    assert all(not dt.isoformat().endswith("+00:00") for dt in stored)

    events = list(writer.read_chain(_TS_CHAIN))
    assert [e["ts"] for e in events] == [w.ts for w in written]
    assert all(e["ts"].endswith("+00:00") for e in events)
    result = verify_chain(events)
    assert result.verified, result.reason
    assert result.count == 3


def _install_session_zone_datetime(offset: timedelta):
    """Make sqlite's ``DateTime`` behave like psycopg under a non-UTC ``TimeZone``.

    The instant is stored with its offset and handed back *aware*, rendered in
    ``offset``'s zone, which is what a Postgres ``timestamptz`` read looks like when the
    session zone is, say, America/New_York. Returns the undo callable.
    """
    from sqlalchemy import types as sqltypes
    from sqlalchemy.dialects.sqlite import DATETIME
    from sqlalchemy.dialects.sqlite.pysqlite import SQLiteDialect_pysqlite

    zone = timezone(offset)

    class SessionZoneDateTime(DATETIME):
        def bind_processor(self, dialect):
            def process(value):
                if value is None:
                    return None
                if value.tzinfo is None:
                    value = value.replace(tzinfo=UTC)
                return value.astimezone(UTC).isoformat()
            return process

        def result_processor(self, dialect, coltype):
            def process(value):
                if value is None:
                    return None
                if not isinstance(value, datetime):
                    value = datetime.fromisoformat(str(value))
                return value.astimezone(zone)
            return process

    colspecs = SQLiteDialect_pysqlite.colspecs
    original = colspecs.get(sqltypes.DateTime)
    colspecs[sqltypes.DateTime] = SessionZoneDateTime

    def restore():
        if original is None:
            colspecs.pop(sqltypes.DateTime, None)
        else:
            colspecs[sqltypes.DateTime] = original

    return restore


@pytest.mark.integration
def test_postgres_writer_verifies_when_the_session_zone_is_not_utc():
    """``created_at`` rendered in a -05:00 session zone still re-derives the hashed ``+00:00`` ts."""
    pytest.importorskip("sqlalchemy")
    from redsim.audit.chain import PostgresAuditWriter

    restore = _install_session_zone_datetime(timedelta(hours=-5))
    try:
        factory = make_sqlite_session_factory()   # engine created after the swap, like the harness
        writer = PostgresAuditWriter(session_factory=factory.session_cm)
        written = _append_three(writer)

        stored = _stored_created_at(factory.session_cm)
        assert len(stored) == 3
        # What the reader sees: aware, in the session zone, not the hashed rendering.
        assert all(dt.utcoffset() == timedelta(hours=-5) for dt in stored)
        assert all(dt.isoformat().endswith("-05:00") for dt in stored)
        assert [dt.isoformat() for dt in stored] != [w.ts for w in written]

        events = list(writer.read_chain(_TS_CHAIN))
        assert [e["ts"] for e in events] == [w.ts for w in written]
        result = verify_chain(events)
        assert result.verified, result.reason
        assert result.count == 3
    finally:
        restore()


if __name__ == "__main__":
    unittest.main()
