"""Coverage-gap filler for the following modules:

- aegis/log_ingest/server.py
- aegis/log_ingest/writer.py
- aegis/audit/chain.py
- aegis/report.py
- aegis/services/targets.py

The pentest strix_runner / patch_workflow / cai_runner / services.fixes
coverage that once lived here was removed with the pentest domain.

All tests are offline-safe: subprocess/git/requests/DB session fully mocked.
No network, no Docker, no scanner binaries required.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

# ─────────────────────────────────────────────────────────────────────────────
# Helpers / fixtures
# ─────────────────────────────────────────────────────────────────────────────

def _make_finding(
    fid="vuln-test-1",
    title="Test Finding",
    severity="high",
    finding_type="dast",
    target="http://localhost:3000",
    endpoint="/api/test",
    cwe="CWE-89",
    cvss=7.5,
    description="A test vulnerability",
    impact="Data exposure",
    remediation_steps="Apply parameterized queries",
    poc_script_code="requests.get('http://localhost:3000/api?id=1 OR 1=1')",
    source_tool="strix",
    source_run_id="run-test",
    affected_component="/api/test",
    confidence="high",
    status="open",
    created_at="2026-01-01",
    updated_at="2026-01-01",
):
    from aegis.schema import AegisFinding
    f = AegisFinding(
        id=fid,
        title=title,
        severity=severity,
        finding_type=finding_type,
        description=description,
        source_tool=source_tool,
        source_run_id=source_run_id,
        affected_component=affected_component,
        confidence=confidence,
        status=status,
        created_at=created_at,
        updated_at=updated_at,
        cvss=cvss,
        cwe=cwe,
        target=target,
        endpoint=endpoint,
        impact=impact,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
    )
    return f


def _make_finding_with_locations(fid="vuln-loc-1"):
    from aegis.schema import CodeLocation
    f = _make_finding(fid=fid)
    f.code_locations = [
        CodeLocation(
            file="app/routes/login.py",
            start_line=10,
            end_line=20,
            snippet="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
            fix_after="cursor.execute('SELECT * FROM users WHERE id=?', (uid,))",
        )
    ]
    return f


def _make_config(target_allowlist=None):
    from aegis.config import AegisConfig
    return AegisConfig(
        target_allowlist=target_allowlist or ["localhost", "127.0.0.1"],
    )


def _make_run_state(tmp):
    from aegis.state import RunState
    return RunState(tmp, "run-test-1")


@contextmanager
def _fake_session_ctx(mock_sess=None):
    """Yield a fake SQLAlchemy session as a context manager factory."""
    sess = mock_sess or MagicMock()
    @contextmanager
    def factory():
        yield sess
    return factory


# ─────────────────────────────────────────────────────────────────────────────
# aegis/log_ingest/server.py — cover remaining branches
# ─────────────────────────────────────────────────────────────────────────────

class TestLogIngestServerEdgeCases(unittest.TestCase):
    def _make_client(self):
        from aegis.log_ingest.server import create_app
        from aegis.log_ingest.writer import LogIngestWriter
        writer = LogIngestWriter()
        return TestClient(create_app(writer)), writer

    def test_ingest_timestamp_as_float(self):
        """ts as float Unix timestamp is accepted."""
        client, writer = self._make_client()
        resp = client.post("/ingest", json={"records": [
            {"ts": 1717248000.0, "severity": "warn", "service": "api", "message": "float ts"},
        ]})
        self.assertEqual(resp.status_code, 202)
        self.assertEqual(writer.buffered(), 1)

    def test_ingest_timestamp_missing_defaults_to_now(self):
        """Missing ts defaults to current time without error."""
        client, writer = self._make_client()
        resp = client.post("/ingest", json={"records": [
            {"severity": "info", "service": "api", "message": "no ts"},
        ]})
        self.assertEqual(resp.status_code, 202)
        self.assertEqual(writer.buffered(), 1)

    def test_ingest_accepts_all_optional_fields(self):
        """All optional fields (job_id, project_id, actor, etc.) round-trip."""
        client, writer = self._make_client()
        resp = client.post("/ingest", json={"records": [
            {
                "ts": "2026-05-29T00:00:00+00:00",
                "severity": "info",
                "service": "worker",
                "message": "full record",
                "run_id": "run-a",
                "job_id": "job-b",
                "project_id": "proj-c",
                "actor": "user@example.com",
                "request_id": "req-d",
                "trace_id": "trace-e",
                "span_id": "span-f",
                "attrs": {"extra": "data"},
            }
        ]})
        self.assertEqual(resp.status_code, 202)
        row = writer._queue[0]
        self.assertEqual(row.run_id, "run-a")
        self.assertEqual(row.job_id, "job-b")
        self.assertEqual(row.project_id, "proj-c")
        self.assertEqual(row.actor, "user@example.com")
        self.assertEqual(row.attrs["extra"], "data")

    def test_otlp_non_string_body(self):
        """OTLP body that is not {'stringValue': ...} is stringified."""
        client, writer = self._make_client()
        resp = client.post("/v1/logs", json={"resourceLogs": [
            {
                "resource": {"attributes": []},
                "scopeLogs": [{
                    "logRecords": [{
                        "timeUnixNano": "1717248000000000000",
                        "severityNumber": 9,
                        "body": {"kvlistValue": {"values": []}},
                        "attributes": [],
                    }]
                }]
            }
        ]})
        self.assertEqual(resp.status_code, 202)
        self.assertEqual(writer.buffered(), 1)

    def test_otlp_ts_nano_invalid_string(self):
        """OTLP timeUnixNano with non-numeric string falls back to now."""
        client, writer = self._make_client()
        resp = client.post("/v1/logs", json={"resourceLogs": [
            {
                "resource": {"attributes": []},
                "scopeLogs": [{
                    "logRecords": [{
                        "timeUnixNano": "not_a_number",
                        "body": {"stringValue": "test"},
                        "attributes": [],
                    }]
                }]
            }
        ]})
        self.assertEqual(resp.status_code, 202)
        self.assertIsNotNone(writer._queue[0].ts.tzinfo)

    def test_otlp_all_kv_value_types(self):
        """OTLP attributes cover boolValue, doubleValue, arrayValue."""
        client, writer = self._make_client()
        resp = client.post("/v1/logs", json={"resourceLogs": [
            {
                "resource": {"attributes": []},
                "scopeLogs": [{
                    "logRecords": [{
                        "body": {"stringValue": "types test"},
                        "attributes": [
                            {"key": "flag", "value": {"boolValue": True}},
                            {"key": "ratio", "value": {"doubleValue": 0.99}},
                            {"key": "items", "value": {"arrayValue": {"values": [
                                {"stringValue": "a"},
                                {"intValue": 1},
                                {"boolValue": False},
                                {"doubleValue": 1.5},
                                {},
                            ]}}},
                            {"key": "nested", "value": {"kvlistValue": {"values": [
                                {"key": "k", "value": {"stringValue": "v"}}
                            ]}}},
                            {"key": "nullish", "value": {}},
                        ],
                    }]
                }]
            }
        ]})
        self.assertEqual(resp.status_code, 202)
        row = writer._queue[0]
        self.assertTrue(row.attrs["flag"])
        self.assertAlmostEqual(row.attrs["ratio"], 0.99)
        self.assertEqual(row.attrs["items"][0], "a")
        self.assertEqual(row.attrs["nested"]["k"], "v")
        self.assertIsNone(row.attrs["nullish"])

    def test_ingest_non_list_records(self):
        """records that is not a list returns 400."""
        client, writer = self._make_client()
        resp = client.post("/ingest", json={"records": "not a list"})
        self.assertEqual(resp.status_code, 400)

    def test_ingest_empty_list(self):
        """Empty records list is valid, returns 202 with accepted=0."""
        client, writer = self._make_client()
        resp = client.post("/ingest", json={"records": []})
        self.assertEqual(resp.status_code, 202)
        self.assertEqual(resp.json()["accepted"], 0)


# ─────────────────────────────────────────────────────────────────────────────
# aegis/log_ingest/writer.py — cover remaining branches
# ─────────────────────────────────────────────────────────────────────────────

class TestLogIngestWriterFlush(unittest.TestCase):
    def _make_row(self, msg="test"):
        from aegis.log_ingest.writer import LogIngestRow
        return LogIngestRow(
            ts=datetime.now(timezone.utc),
            severity="info",
            service="test",
            message=msg,
        )

    def test_flush_with_session_factory_calls_insert(self):
        """flush() drains the queue through the real _insert when a session
        factory is configured, writing one row object per queued record."""
        from aegis.log_ingest.writer import LogIngestWriter
        inserted = []

        class FakeSession:
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass
            def add_all(self, objs):
                inserted.extend(objs)
            def commit(self):
                pass

        def fake_factory():
            return FakeSession()

        # The real external boundary _insert touches is aegis.db.models.ApplicationLog.
        fake_log_cls = MagicMock(side_effect=lambda **kw: MagicMock())
        with patch.dict(sys.modules, {
            "aegis.db.models": MagicMock(ApplicationLog=fake_log_cls)
        }):
            writer = LogIngestWriter(session_factory=fake_factory)
            writer.append(self._make_row("a"))
            writer.append(self._make_row("b"))
            n = writer.flush()
        self.assertEqual(n, 2)
        self.assertEqual(writer.inserted_total, 2)
        self.assertEqual(len(inserted), 2)

    def test_flush_empty_queue_is_noop(self):
        """flush() with empty queue returns 0 immediately."""
        from aegis.log_ingest.writer import LogIngestWriter

        def fake_factory():
            return MagicMock()

        writer = LogIngestWriter(session_factory=fake_factory)
        n = writer.flush()
        self.assertEqual(n, 0)

    def test_flush_without_session_factory_does_not_drain(self):
        """flush() without session factory leaves queue intact."""
        from aegis.log_ingest.writer import LogIngestWriter
        writer = LogIngestWriter()  # no session
        writer.append(self._make_row())
        writer.flush()
        self.assertEqual(writer.buffered(), 1)

    def test_close_flushes(self):
        """close() calls flush()."""
        from aegis.log_ingest.writer import LogIngestWriter
        writer = LogIngestWriter()
        writer.append(self._make_row())
        with patch.object(writer, "flush") as mock_flush:
            writer.close()
        mock_flush.assert_called_once()

    def test_should_flush_by_batch_size(self):
        """_should_flush returns True when queue >= batch_size."""
        from aegis.log_ingest.writer import LogIngestWriter
        writer = LogIngestWriter(batch_size=2)
        writer._queue.append(self._make_row("a"))
        writer._queue.append(self._make_row("b"))
        self.assertTrue(writer._should_flush())

    def test_should_flush_by_time(self):
        """_should_flush returns True when flush_seconds has elapsed."""
        from aegis.log_ingest.writer import LogIngestWriter
        writer = LogIngestWriter(flush_seconds=0.001)
        time.sleep(0.01)
        self.assertTrue(writer._should_flush())

    def test_oversize_attrs_truncated(self):
        """attrs > 64KB are replaced with {'_truncated': True}."""
        from aegis.log_ingest.writer import LogIngestRow
        big_attrs = {f"key_{i}": "x" * 100 for i in range(700)}
        row = LogIngestRow(
            ts=datetime.now(timezone.utc),
            severity="info",
            service="svc",
            message="test",
            attrs=big_attrs,
        )
        self.assertEqual(row.attrs, {"_truncated": True})

    def test_insert_uses_session_factory(self):
        """flush() drains the queue through the session factory when one is set.

        We mock the DB model boundary (aegis.db.models.ApplicationLog) instead
        of the private _insert, and force a flush explicitly (bypass the
        _should_flush heuristic), then assert the row landed via the session.
        """
        from aegis.log_ingest.writer import LogIngestRow, LogIngestWriter

        mock_sess = MagicMock()

        @contextmanager
        def fake_session():
            yield mock_sess

        writer = LogIngestWriter(session_factory=fake_session, batch_size=100)
        writer._queue.append(LogIngestRow(
            ts=datetime.now(timezone.utc),
            severity="info", service="svc", message="hi",
        ))
        with patch.dict(sys.modules, {
            "aegis.db.models": MagicMock(ApplicationLog=MagicMock())
        }):
            result = writer.flush()
        mock_sess.add_all.assert_called_once()
        mock_sess.commit.assert_called_once()
        self.assertEqual(result, 1)
        self.assertEqual(writer.inserted_total, 1)

    def test_severity_from_otlp_warning_maps_to_warn(self):
        from aegis.log_ingest.writer import severity_from_otlp
        self.assertEqual(severity_from_otlp(None, "warning"), "warn")

    def test_severity_from_otlp_critical_passthrough(self):
        from aegis.log_ingest.writer import severity_from_otlp
        self.assertEqual(severity_from_otlp(None, "critical"), "critical")

    def test_severity_from_otlp_unknown_text_falls_to_number(self):
        from aegis.log_ingest.writer import severity_from_otlp
        # "verbose" is not a recognized text label; fall back to number bucket
        self.assertEqual(severity_from_otlp(5, "verbose"), "debug")

    def test_ts_from_unix_nano_positive(self):
        from aegis.log_ingest.writer import ts_from_unix_nano
        ts = ts_from_unix_nano(1_717_248_000_000_000_000)
        self.assertIsNotNone(ts.tzinfo)
        self.assertEqual(ts.year, 2024)


# ─────────────────────────────────────────────────────────────────────────────
# aegis/audit/chain.py — resolve_writer branches + InMemoryAuditWriter
# ─────────────────────────────────────────────────────────────────────────────

class TestResolveWriterBranches(unittest.TestCase):
    """``resolve_writer`` is the single audit-writer selector (the old
    ``aegis.audit.writers.open_writer`` duplicate was folded in)."""

    def _clean_env(self):
        return {k: v for k, v in os.environ.items()
                if k not in ("AEGIS_DB_URL", "AEGIS_TEST_AUDIT")}

    def test_offline_returns_jsonl_writer(self):
        from aegis.audit.chain import JsonlAuditWriter, resolve_writer
        with tempfile.TemporaryDirectory() as tmp, \
             patch.dict(os.environ, self._clean_env(), clear=True):
            writer = resolve_writer(tmp)
        self.assertIsInstance(writer, JsonlAuditWriter)

    def test_config_object_output_dir(self):
        """A config-like object with .output_dir roots the JSONL writer there."""
        from aegis.audit.chain import JsonlAuditWriter, resolve_writer
        with tempfile.TemporaryDirectory() as tmp, \
             patch.dict(os.environ, self._clean_env(), clear=True):
            writer = resolve_writer(SimpleNamespace(output_dir=tmp))
        self.assertIsInstance(writer, JsonlAuditWriter)
        self.assertEqual(writer.directory, Path(tmp) / "audit")

    def test_memory_env_returns_in_memory_writer(self):
        from aegis.audit.chain import InMemoryAuditWriter, resolve_writer
        with patch.dict(os.environ, {"AEGIS_TEST_AUDIT": "memory"}, clear=False):
            writer = resolve_writer("/tmp/ignored")
        self.assertIsInstance(writer, InMemoryAuditWriter)

    def test_memory_env_takes_precedence_over_db_url(self):
        """AEGIS_TEST_AUDIT=memory wins even when AEGIS_DB_URL is set."""
        from aegis.audit.chain import InMemoryAuditWriter, resolve_writer
        with patch.dict(os.environ,
                        {"AEGIS_TEST_AUDIT": "memory",
                         "AEGIS_DB_URL": "postgresql://fake/db"}, clear=False):
            writer = resolve_writer("/tmp/ignored")
        self.assertIsInstance(writer, InMemoryAuditWriter)


class TestInMemoryAuditWriter(unittest.TestCase):
    def _make_writer(self):
        from aegis.audit.chain import InMemoryAuditWriter
        return InMemoryAuditWriter()

    def test_append_stores_event(self):
        w = self._make_writer()
        event = w.append(
            action="scan.start", actor="cli:alice",
            target="localhost", allowlist_check="pass",
            override=False, success=True,
            detail={"test": True},
            run_id="run-x", project_id="proj-y",
        )
        self.assertEqual(len(w.events), 1)
        self.assertEqual(w.events[0].action, "scan.start")
        self.assertEqual(event.seq, 1)

    def test_append_increments_seq(self):
        w = self._make_writer()
        for i in range(3):
            w.append(
                action="a", actor="cli", target=None,
                allowlist_check="pass", override=False, success=True,
                detail={}, run_id="run-1",
            )
        seqs = [e.seq for e in w.events]
        self.assertEqual(seqs, [1, 2, 3])

    def test_read_chain_returns_records(self):
        w = self._make_writer()
        w.append(action="x", actor="c", target=None,
                 allowlist_check="n", override=False, success=True,
                 detail={}, run_id="r1")
        records = list(w.read_chain("run:r1"))
        self.assertEqual(len(records), 1)
        self.assertIn("action", records[0])

    def test_iter_chain_ids(self):
        w = self._make_writer()
        w.append(action="a", actor="c", target=None,
                 allowlist_check="n", override=False, success=True,
                 detail={}, run_id="r1")
        w.append(action="b", actor="c", target=None,
                 allowlist_check="n", override=False, success=True,
                 detail={}, project_id="proj-1")
        chain_ids = set(w.iter_chain_ids())
        self.assertIn("run:r1", chain_ids)
        self.assertIn("project:proj-1", chain_ids)

    def test_chain_id_system_fallback(self):
        """Without run_id or project_id the chain_id is 'system'."""
        w = self._make_writer()
        w.append(action="a", actor="c", target=None,
                 allowlist_check="n", override=False, success=True, detail={})
        self.assertIn("system", set(w.iter_chain_ids()))

    def test_read_chain_empty_for_unknown(self):
        w = self._make_writer()
        records = list(w.read_chain("nonexistent"))
        self.assertEqual(records, [])


# ─────────────────────────────────────────────────────────────────────────────
# aegis/audit/chain.py — cover remaining branches
# ─────────────────────────────────────────────────────────────────────────────

class TestJsonlAuditWriterSingleFile(unittest.TestCase):
    """JsonlAuditWriter single-file mode (Phase 2/3 compat)."""

    def test_single_file_all_chains_in_one_file(self):
        from aegis.audit.chain import JsonlAuditWriter
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp), single_file="audit.jsonl")
            writer.append(action="a", actor="cli", target=None,
                          allowlist_check="p", override=False, success=True,
                          detail={}, run_id="r1")
            writer.append(action="b", actor="cli", target=None,
                          allowlist_check="p", override=False, success=True,
                          detail={}, run_id="r2")
            audit_file = Path(tmp) / "audit.jsonl"
            self.assertTrue(audit_file.exists())
            lines = [line for line in audit_file.read_text().splitlines() if line.strip()]
            self.assertEqual(len(lines), 2)

    def test_iter_chain_ids(self):
        from aegis.audit.chain import JsonlAuditWriter
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            writer.append(action="a", actor="c", target=None,
                          allowlist_check="p", override=False, success=True,
                          detail={}, run_id="run-chain-1")
            writer.append(action="b", actor="c", target=None,
                          allowlist_check="p", override=False, success=True,
                          detail={}, project_id="proj-1")
            ids = set(writer.iter_chain_ids())
        self.assertIn("run:run-chain-1", ids)
        self.assertIn("project:proj-1", ids)

    def test_read_chain_empty_for_unknown(self):
        from aegis.audit.chain import JsonlAuditWriter
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            result = list(writer.read_chain("nonexistent:chain"))
        self.assertEqual(result, [])

    def test_system_chain_id_for_no_run_project(self):
        from aegis.audit.chain import JsonlAuditWriter
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            writer.append(action="a", actor="c", target=None,
                          allowlist_check="p", override=False, success=True,
                          detail={})
            ids = set(writer.iter_chain_ids())
        self.assertIn("system", ids)

    def test_colon_in_chain_id_replaced_on_filesystem(self):
        """Chain IDs with ':' are stored as '__' on the filesystem."""
        from aegis.audit.chain import JsonlAuditWriter
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            writer.append(action="a", actor="c", target=None,
                          allowlist_check="p", override=False, success=True,
                          detail={}, run_id="run-xyz")
            files = list(Path(tmp).glob("*.jsonl"))
        self.assertEqual(len(files), 1)
        self.assertIn("__", files[0].name)


class TestVerifyChainEmptyAndEdgeCases(unittest.TestCase):
    def test_empty_chain_is_verified(self):
        from aegis.audit.chain import verify_chain
        result = verify_chain([])
        self.assertTrue(result.verified)
        self.assertEqual(result.count, 0)

    def test_prev_hash_mismatch_detected(self):
        from aegis.audit.chain import JsonlAuditWriter, verify_chain
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            for i in range(3):
                writer.append(action="a", actor="c", target=None,
                               allowlist_check="p", override=False, success=True,
                               detail={"i": i}, run_id="r")
            chain_path = next(Path(tmp).glob("*.jsonl"))
            lines = chain_path.read_text().splitlines()
            # Corrupt prev_hash of second event
            rec = json.loads(lines[1])
            rec["prev_hash"] = "deadbeef" * 8  # wrong hash
            lines[1] = json.dumps(rec)
            chain_path.write_text("\n".join(lines) + "\n")
            events = list(writer.read_chain("run:r"))
            result = verify_chain(events)
        self.assertFalse(result.verified)
        self.assertIn("prev_hash mismatch", result.reason or "")


class TestResolveWriter(unittest.TestCase):
    def test_resolve_writer_offline(self):
        from aegis.audit.chain import JsonlAuditWriter, resolve_writer
        with tempfile.TemporaryDirectory() as tmp:
            env = {k: v for k, v in os.environ.items() if k != "AEGIS_DB_URL"}
            with patch.dict(os.environ, env, clear=True):
                writer = resolve_writer(tmp)
        self.assertIsInstance(writer, JsonlAuditWriter)

    def test_resolve_writer_with_config_object(self):
        from aegis.audit.chain import JsonlAuditWriter, resolve_writer
        with tempfile.TemporaryDirectory() as tmp:
            config = SimpleNamespace(output_dir=tmp)
            env = {k: v for k, v in os.environ.items() if k != "AEGIS_DB_URL"}
            with patch.dict(os.environ, env, clear=True):
                writer = resolve_writer(config)
        self.assertIsInstance(writer, JsonlAuditWriter)


class TestCanonicalJson(unittest.TestCase):
    def test_excludes_this_hash_field(self):
        from aegis.audit.chain import canonical_json
        rec = {"seq": 1, "actor": "a", "this_hash": "abc123"}
        result = json.loads(canonical_json(rec))
        self.assertNotIn("this_hash", result)
        self.assertIn("seq", result)

    def test_deterministic_sort(self):
        from aegis.audit.chain import canonical_json
        rec1 = {"b": 2, "a": 1}
        rec2 = {"a": 1, "b": 2}
        self.assertEqual(canonical_json(rec1), canonical_json(rec2))


# ─────────────────────────────────────────────────────────────────────────────
# aegis/report.py — cover remaining branches
# ─────────────────────────────────────────────────────────────────────────────

class TestReportEdgeCases(unittest.TestCase):
    def test_no_findings_still_generates_report(self):
        from aegis.report import generate_markdown_report
        with tempfile.TemporaryDirectory() as tmp:
            state = _make_run_state(tmp)
            md = generate_markdown_report(state, [])
        self.assertIn("Aegis Security Assessment Report", md)
        self.assertIn("**Total Findings:** 0", md)

    def test_multiple_targets_resolves_to_multiple(self):
        from aegis.report import _resolve_target
        f1 = _make_finding(target="http://a.example.com")
        f2 = _make_finding(target="http://b.example.com")
        self.assertEqual(_resolve_target([f1, f2]), "Multiple targets")

    def test_no_targets_resolves_to_unknown(self):
        from aegis.report import _resolve_target
        f1 = _make_finding(target=None)
        self.assertEqual(_resolve_target([f1]), "Unknown")

    def test_stage_table_rendered_when_present(self):
        import json

        from aegis.report import generate_markdown_report
        with tempfile.TemporaryDirectory() as tmp:
            state = _make_run_state(tmp)
            stage_table = {"stages": [
                {"name": "strix", "mode": "live", "success": True, "detail": ""},
                {"name": "cai", "mode": "golden", "success": False, "detail": "no diff"},
            ]}
            (state.run_path / "stage_table.json").write_text(json.dumps(stage_table))
            f = _make_finding()
            md = generate_markdown_report(state, [f])
        self.assertIn("Stage Provenance", md)
        self.assertIn("strix", md)

    def test_verify_panel_rendered_when_present(self):
        import json

        from aegis.report import generate_markdown_report
        with tempfile.TemporaryDirectory() as tmp:
            state = _make_run_state(tmp)
            verify_dir = state.run_path / "verify"
            verify_dir.mkdir(parents=True, exist_ok=True)
            fid = "vuln-test-1"
            verify_data = {
                "status": "verified",
                "strategy": "replay",
                "notes": "HTTP 403 after patch",
            }
            (verify_dir / f"{fid}.json").write_text(json.dumps(verify_data))
            f = _make_finding(fid=fid)
            md = generate_markdown_report(state, [f])
        self.assertIn("Verification", md)
        self.assertIn("Verified", md)

    def test_evidence_panel_after_rendered(self):
        import json

        from aegis.report import generate_markdown_report
        with tempfile.TemporaryDirectory() as tmp:
            state = _make_run_state(tmp)
            fid = "vuln-test-1"
            # Set up verify result so evidence block is reached
            verify_dir = state.run_path / "verify"
            verify_dir.mkdir(parents=True, exist_ok=True)
            (verify_dir / f"{fid}.json").write_text(json.dumps({"status": "verified", "strategy": "replay"}))
            # Set up evidence
            evidence_dir = state.run_path / "artifacts" / "evidence" / fid
            evidence_dir.mkdir(parents=True, exist_ok=True)
            (evidence_dir / "after.json").write_text(json.dumps({
                "status": 403,
                "body_excerpt": "Forbidden",
            }))
            f = _make_finding(fid=fid)
            md = generate_markdown_report(state, [f])
        self.assertIn("post-patch replay", md)
        self.assertIn("403", md)

    def test_remediation_log_section_rendered(self):
        import json

        from aegis.report import generate_markdown_report
        with tempfile.TemporaryDirectory() as tmp:
            state = _make_run_state(tmp)
            log_data = [
                {"finding_id": "v-1", "action": "patch_commit",
                 "result": "ok", "success": True, "timestamp": "2026-01-01T00:00:00Z"},
            ]
            state.remediation_log_path.write_text(json.dumps(log_data))
            f = _make_finding()
            md = generate_markdown_report(state, [f])
        self.assertIn("Remediation Actions", md)
        self.assertIn("patch_commit", md)

    def test_save_reports_writes_files(self):
        from aegis.report import save_reports
        with tempfile.TemporaryDirectory() as tmp:
            state = _make_run_state(tmp)
            f = _make_finding()
            md_path, json_path = save_reports(state, [f])
            self.assertTrue(Path(md_path).exists())
            self.assertTrue(Path(json_path).exists())
            with open(json_path) as fh:
                data = json.load(fh)
            self.assertIn("run_id", data)
            self.assertIn("findings", data)

    def test_save_reports_no_html(self):
        from aegis.report import save_reports
        with tempfile.TemporaryDirectory() as tmp:
            state = _make_run_state(tmp)
            f = _make_finding()
            save_reports(state, [f], html=False)
        self.assertFalse((state.run_path / "report.html").exists())

    def test_generate_html_report_includes_style(self):
        from aegis.report import generate_html_report
        with tempfile.TemporaryDirectory() as tmp:
            state = _make_run_state(tmp)
            f = _make_finding()
            html = generate_html_report(state, [f])
        self.assertIn("<!doctype html>", html)
        self.assertIn("<style>", html)

    def test_md_to_html_min_code_fence(self):
        """_md_to_html_min converts code fences to <pre><code>."""
        from aegis.report import _md_to_html_min
        md = "before\n```\nsome code\n```\nafter"
        html = _md_to_html_min(md)
        self.assertIn("<pre><code>", html)
        self.assertIn("some code", html)

    def test_md_to_html_min_table(self):
        """_md_to_html_min converts markdown tables to <table>."""
        from aegis.report import _md_to_html_min
        md = "| A | B |\n|---|---|\n| 1 | 2 |\n"
        html = _md_to_html_min(md)
        self.assertIn("<table>", html)
        self.assertIn("<th>", html)
        self.assertIn("<td>", html)

    def test_md_to_html_min_headings(self):
        from aegis.report import _md_to_html_min
        md = "# H1\n## H2\n### H3\n#### H4\n"
        html = _md_to_html_min(md)
        self.assertIn("<h1>", html)
        self.assertIn("<h2>", html)
        self.assertIn("<h3>", html)
        self.assertIn("<h4>", html)

    def test_md_to_html_min_hr(self):
        from aegis.report import _md_to_html_min
        html = _md_to_html_min("---")
        self.assertIn("<hr/>", html)

    def test_sort_findings_order(self):
        from aegis.report import _sort_findings
        f_low = _make_finding(fid="a", severity="low", title="B")
        f_crit = _make_finding(fid="b", severity="critical", title="A")
        f_high = _make_finding(fid="c", severity="high", title="C")
        sorted_ = _sort_findings([f_low, f_crit, f_high])
        self.assertEqual(sorted_[0].severity, "critical")
        self.assertEqual(sorted_[-1].severity, "low")

    def test_json_report_structure(self):
        from aegis.report import generate_json_report
        with tempfile.TemporaryDirectory() as tmp:
            state = _make_run_state(tmp)
            f1 = _make_finding(fid="v1", severity="critical")
            f2 = _make_finding(fid="v2", severity="low")
            report = generate_json_report(state, [f1, f2])
        self.assertEqual(report["summary"]["total"], 2)
        self.assertEqual(report["summary"]["severity"]["critical"], 1)
        self.assertEqual(report["summary"]["severity"]["low"], 1)
        self.assertEqual(len(report["findings"]), 2)

    def test_code_locations_in_report(self):
        """Findings with code_locations produce Vulnerable Code sections."""
        from aegis.report import generate_markdown_report
        with tempfile.TemporaryDirectory() as tmp:
            state = _make_run_state(tmp)
            f = _make_finding_with_locations()
            md = generate_markdown_report(state, [f])
        self.assertIn("Vulnerable Code", md)
        self.assertIn("Suggested Fix", md)


# ─────────────────────────────────────────────────────────────────────────────
# aegis/services/targets.py
# ─────────────────────────────────────────────────────────────────────────────

class TestCreateTarget(unittest.TestCase):
    def _make_audit_writer(self):
        from aegis.audit.chain import InMemoryAuditWriter
        return InMemoryAuditWriter()

    def test_create_target_calls_authorize_and_db(self):
        from aegis.services.targets import TargetRecord, create_target

        # Fake session context manager — patched at the DB session module
        # (targets.py does a lazy `from aegis.db.session import get_session`)
        mock_sess = MagicMock()

        @contextmanager
        def fake_session():
            yield mock_sess

        config = _make_config(target_allowlist=["localhost"])
        writer = self._make_audit_writer()

        with patch("aegis.db.session.get_session", fake_session), \
             patch("aegis.services.targets.authorize") as mock_auth:
            result = create_target(
                project_id="proj-1",
                kind="url",
                value="http://localhost:3000",
                actor="cli:alice",
                config=config,
                audit_writer=writer,
            )

        mock_auth.assert_called_once()
        call_kw = mock_auth.call_args
        self.assertEqual(call_kw.args[0], "target.manage")
        self.assertEqual(call_kw.args[1], "http://localhost:3000")
        mock_sess.add.assert_called_once()
        mock_sess.flush.assert_called_once()
        self.assertIsInstance(result, TargetRecord)
        self.assertFalse(result.verified)
        self.assertEqual(result.project_id, "proj-1")
        self.assertEqual(result.kind, "url")
        self.assertEqual(result.value, "http://localhost:3000")
        self.assertTrue(result.id.startswith("target-"))


class TestDeleteTarget(unittest.TestCase):
    def _make_audit_writer(self):
        from aegis.audit.chain import InMemoryAuditWriter
        return InMemoryAuditWriter()

    def test_delete_target_success(self):
        from aegis.db.models import Target
        from aegis.services.targets import delete_target

        mock_target = MagicMock(spec=Target)
        mock_target.project_id = "proj-1"
        mock_target.value = "http://localhost:3000"
        mock_target.kind = "url"

        mock_sess = MagicMock()
        mock_sess.get.return_value = mock_target
        mock_sess.delete = MagicMock()

        @contextmanager
        def fake_session():
            yield mock_sess

        config = _make_config(target_allowlist=["localhost"])
        writer = self._make_audit_writer()

        with patch("aegis.db.session.get_session", fake_session), \
             patch("aegis.services.targets.authorize") as mock_auth:
            result = delete_target(
                target_id="target-abc123",
                actor="cli:alice",
                config=config,
                audit_writer=writer,
            )

        mock_auth.assert_called_once()
        call_kw = mock_auth.call_args
        self.assertEqual(call_kw.args[0], "target.manage")
        self.assertEqual(result, "target-abc123")

    def test_delete_target_not_found_raises(self):
        from aegis.services.targets import delete_target

        mock_sess = MagicMock()
        mock_sess.get.return_value = None

        @contextmanager
        def fake_session():
            yield mock_sess

        config = _make_config()
        writer = self._make_audit_writer()

        with patch("aegis.db.session.get_session", fake_session):
            with self.assertRaises(LookupError):
                delete_target(
                    target_id="nonexistent",
                    actor="cli:alice",
                    config=config,
                    audit_writer=writer,
                )

    def test_delete_target_missing_on_second_get(self):
        """Target disappears between first and second session.get (race condition)."""
        from aegis.db.models import Target
        from aegis.services.targets import delete_target

        mock_target = MagicMock(spec=Target)
        mock_target.project_id = "proj-1"
        mock_target.value = "http://localhost:3000"
        mock_target.kind = "url"

        call_count = {"n": 0}

        mock_sess_first = MagicMock()
        mock_sess_first.get.return_value = mock_target

        mock_sess_second = MagicMock()
        mock_sess_second.get.return_value = None  # gone by 2nd call

        sessions = [mock_sess_first, mock_sess_second]

        @contextmanager
        def fake_session():
            yield sessions[call_count["n"]]
            call_count["n"] += 1

        config = _make_config(target_allowlist=["localhost"])
        writer = self._make_audit_writer()

        with patch("aegis.db.session.get_session", fake_session), \
             patch("aegis.services.targets.authorize"):
            result = delete_target(
                target_id="target-vanished",
                actor="cli:alice",
                config=config,
                audit_writer=writer,
            )
        self.assertEqual(result, "target-vanished")
        # Second session.get returned None; delete() should NOT have been called
        mock_sess_second.delete.assert_not_called()


class TestVerifyTargetUnavailable(unittest.TestCase):
    """``verify_target`` is an explicit engine-unavailable path.

    The DNS-TXT / GitHub-App ownership-verification engine was removed with
    the pentest domain. The 404 lookup still fires first, a known target then
    raises ``TargetVerificationUnavailable`` (a ``NotImplementedError``), and
    nothing is written: no audit row, no ``verified`` flip.
    """

    def test_unknown_target_raises_lookup_error_first(self):
        from aegis.services.targets import verify_target

        mock_sess = MagicMock()
        mock_sess.get.return_value = None
        writer = MagicMock()

        with self.assertRaises(LookupError):
            verify_target(mock_sess, "nonexistent", actor="cli:alice",
                          audit_writer=writer, config=_make_config())
        writer.append.assert_not_called()

    def test_known_target_raises_unavailable_and_leaves_verified_untouched(self):
        from aegis.db.models import Target
        from aegis.services.targets import (
            TargetVerificationUnavailable,
            verify_target,
        )

        mock_target = MagicMock(spec=Target)
        mock_target.project_id = "proj-1"
        mock_target.kind = "url"
        mock_target.value = "http://localhost:3000"
        mock_target.verified = False

        mock_sess = MagicMock()
        mock_sess.get.return_value = mock_target
        writer = MagicMock()

        with self.assertRaises(TargetVerificationUnavailable) as cm:
            verify_target(mock_sess, "target-abc123", actor="cli:alice",
                          audit_writer=writer, config=_make_config())

        message = str(cm.exception)
        self.assertIn("ownership verification is unavailable", message)
        self.assertIn("removed with the pentest domain", message)
        self.assertFalse(mock_target.verified)
        writer.append.assert_not_called()
        mock_sess.add.assert_not_called()
        mock_sess.flush.assert_not_called()

    def test_unavailable_is_a_not_implemented_error(self):
        from aegis.services.targets import TargetVerificationUnavailable
        self.assertTrue(issubclass(TargetVerificationUnavailable, NotImplementedError))

    def test_legacy_422_error_class_is_gone(self):
        # The old TargetVerificationError ("maps to 422") went with the engine.
        import aegis.services.targets as targets_mod
        self.assertFalse(hasattr(targets_mod, "TargetVerificationError"))


# ─────────────────────────────────────────────────────────────────────────────
# Additional gap-fill tests to push remaining modules to ≥90%
# ─────────────────────────────────────────────────────────────────────────────

class TestLogIngestWriterFlushAutoTrigger(unittest.TestCase):
    """Cover the flush() auto-trigger paths in append() and append_many()."""

    def _make_row(self, msg="x"):
        from aegis.log_ingest.writer import LogIngestRow
        return LogIngestRow(
            ts=datetime.now(timezone.utc),
            severity="info", service="svc", message=msg,
        )

    def test_append_triggers_flush_when_should(self):
        """append() calls flush() when _should_flush() is True."""
        from aegis.log_ingest.writer import LogIngestWriter
        writer = LogIngestWriter()
        with patch.object(writer, "_should_flush", return_value=True), \
             patch.object(writer, "flush") as mock_flush:
            writer.append(self._make_row())
        mock_flush.assert_called_once()

    def test_append_many_triggers_flush_when_should(self):
        """append_many() calls flush() when _should_flush() is True."""
        from aegis.log_ingest.writer import LogIngestWriter
        writer = LogIngestWriter()
        with patch.object(writer, "_should_flush", return_value=True), \
             patch.object(writer, "flush") as mock_flush:
            writer.append_many([self._make_row("a"), self._make_row("b")])
        mock_flush.assert_called_once()

    def test_real_insert_with_mocked_application_log(self):
        """_insert builds ApplicationLog objects and calls add_all + commit."""
        from aegis.log_ingest.writer import LogIngestRow, LogIngestWriter

        mock_sess = MagicMock()

        @contextmanager
        def fake_factory():
            yield mock_sess

        fake_log_cls = MagicMock(return_value=MagicMock())
        writer = LogIngestWriter(session_factory=fake_factory)
        rows = [
            LogIngestRow(ts=datetime.now(timezone.utc), severity="info",
                         service="svc", message="test"),
        ]
        # Patch ApplicationLog where _insert imports it from
        with patch.dict(sys.modules, {
            "aegis.db.models": MagicMock(ApplicationLog=fake_log_cls)
        }):
            n = writer._insert(rows)
        # ApplicationLog was instantiated once, add_all + commit called
        self.assertEqual(n, 1)
        mock_sess.add_all.assert_called_once()
        mock_sess.commit.assert_called_once()


class TestAuditChainBlankLineHandling(unittest.TestCase):
    """Cover the blank-line `continue` branch in _last() (line 150)."""

    def test_blank_lines_in_chain_file_are_skipped(self):
        from aegis.audit.chain import JsonlAuditWriter
        with tempfile.TemporaryDirectory() as tmp:
            writer = JsonlAuditWriter(Path(tmp))
            writer.append(action="a", actor="c", target=None,
                          allowlist_check="p", override=False, success=True,
                          detail={}, run_id="r-blank")
            # Inject a blank line at the start of the file
            chain_path = next(Path(tmp).glob("*.jsonl"))
            original = chain_path.read_text()
            chain_path.write_text("\n\n" + original + "\n")
            # Now append another event — this calls _last() which must handle blanks
            writer.append(action="b", actor="c", target=None,
                          allowlist_check="p", override=False, success=True,
                          detail={}, run_id="r-blank")
            events = list(writer.read_chain("run:r-blank"))
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["seq"], 1)
        self.assertEqual(events[1]["seq"], 2)


class TestResolveWriterDbUrlBranch(unittest.TestCase):
    """Cover resolve_writer when AEGIS_DB_URL is set (lines 381-383)."""

    def test_resolve_writer_with_db_url(self):
        from aegis.audit.chain import PostgresAuditWriter, resolve_writer
        with patch("aegis.db.session.init_engine") as mock_init, \
             patch("aegis.db.session.get_session", MagicMock()), \
             patch.dict(os.environ, {"AEGIS_DB_URL": "postgresql://fake/db"},
                        clear=False):
            writer = resolve_writer("/tmp/some/dir")
        mock_init.assert_called_once_with("postgresql://fake/db")
        self.assertIsInstance(writer, PostgresAuditWriter)


class TestPostgresAuditWriter(unittest.TestCase):
    """Cover PostgresAuditWriter.append / read_chain / iter_chain_ids plus the
    shared module-level _chain_id helper, using a fully-mocked SQLAlchemy
    session (no real DB required).
    """

    def _make_writer(self):
        from aegis.audit.chain import PostgresAuditWriter
        mock_sess = MagicMock()
        # scalar_one_or_none returns None → triggers new head creation path
        mock_sess.execute.return_value.scalar_one_or_none.return_value = None
        mock_sess.flush = MagicMock()
        mock_sess.add = MagicMock()
        mock_sess.commit = MagicMock()

        @contextmanager
        def fake_factory():
            yield mock_sess

        writer = PostgresAuditWriter(session_factory=fake_factory)
        return writer, mock_sess

    def _mock_models(self):
        """Return mocked AuditChainHead, AuditEvent, and select() for patching."""
        chain_head_cls = MagicMock()
        chain_head_instance = MagicMock()
        chain_head_instance.head_seq = 0
        chain_head_instance.head_hash = None
        chain_head_cls.return_value = chain_head_instance

        ae_model_cls = MagicMock()
        ae_model_cls.return_value = MagicMock()

        # select() returns something that .where().with_for_update() can be called on
        select_mock = MagicMock()

        return chain_head_cls, chain_head_instance, ae_model_cls, select_mock

    def test_chain_id_run(self):
        from aegis.audit.chain import _chain_id
        self.assertEqual(_chain_id(None, "r1"), "run:r1")

    def test_chain_id_project(self):
        from aegis.audit.chain import _chain_id
        self.assertEqual(_chain_id("proj-1", None), "project:proj-1")

    def test_chain_id_system(self):
        from aegis.audit.chain import _chain_id
        self.assertEqual(_chain_id(None, None), "system")

    def test_append_new_head(self):
        """append() with no existing head creates a new AuditChainHead row."""
        from aegis.audit.chain import AuditEvent, PostgresAuditWriter

        chain_head_cls, chain_head_inst, ae_model_cls, _ = self._mock_models()

        mock_sess = MagicMock()
        mock_sess.execute.return_value.scalar_one_or_none.return_value = None

        @contextmanager
        def fake_factory():
            yield mock_sess

        writer = PostgresAuditWriter(session_factory=fake_factory)

        fake_models = MagicMock()
        fake_models.AuditChainHead = chain_head_cls
        fake_models.AuditEvent = ae_model_cls
        fake_sqlalchemy = MagicMock()
        fake_sqlalchemy.select = MagicMock(return_value=MagicMock())

        with patch.dict(sys.modules, {
            "aegis.db.models": fake_models,
            "sqlalchemy": fake_sqlalchemy,
        }):
            event = writer.append(
                action="scan.start", actor="cli:alice",
                target="localhost", allowlist_check="pass",
                override=False, success=True,
                detail={"test": True},
                run_id="run-pg-1",
            )

        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(event.action, "scan.start")
        # The chain_head was added (new head path)
        mock_sess.add.assert_called()
        mock_sess.flush.assert_called()

    def test_append_existing_head(self):
        """append() with existing head increments seq from head.head_seq."""
        from aegis.audit.chain import AuditEvent, PostgresAuditWriter

        existing_head = MagicMock()
        existing_head.head_seq = 3
        existing_head.head_hash = bytes.fromhex("a" * 64)

        chain_head_cls = MagicMock()
        ae_model_cls = MagicMock()
        ae_model_cls.return_value = MagicMock()

        mock_sess = MagicMock()
        mock_sess.execute.return_value.scalar_one_or_none.return_value = existing_head

        @contextmanager
        def fake_factory():
            yield mock_sess

        writer = PostgresAuditWriter(session_factory=fake_factory)

        fake_models = MagicMock()
        fake_models.AuditChainHead = chain_head_cls
        fake_models.AuditEvent = ae_model_cls
        fake_sqlalchemy = MagicMock()
        fake_sqlalchemy.select = MagicMock(return_value=MagicMock())

        with patch.dict(sys.modules, {
            "aegis.db.models": fake_models,
            "sqlalchemy": fake_sqlalchemy,
        }):
            event = writer.append(
                action="scan.end", actor="cli:alice",
                target=None, allowlist_check="pass",
                override=False, success=True,
                detail={},
                run_id="run-pg-2",
            )

        self.assertIsInstance(event, AuditEvent)
        # seq should be existing_head.head_seq + 1 = 4
        self.assertEqual(event.seq, 4)
        # The head was NOT re-added (existing path); AuditEvent was added
        ae_model_cls.assert_called_once()

    def test_read_chain_returns_records(self):
        """read_chain() iterates over ORM rows and yields dicts."""
        from aegis.audit.chain import PostgresAuditWriter

        # Create a fake ORM row
        fake_row = MagicMock()
        fake_row.chain_id = "run:r1"
        fake_row.seq = 1
        fake_row.created_at.isoformat.return_value = "2026-01-01T00:00:00+00:00"
        fake_row.actor = "cli"
        fake_row.action = "scan.start"
        fake_row.target = None
        fake_row.allowlist_check = "pass"
        fake_row.override = False
        fake_row.success = True
        fake_row.detail = {}
        fake_row.schema_version = 1
        fake_row.prev_hash = None
        fake_row.this_hash = bytes.fromhex("ab" * 32)
        fake_row.run_id = "r1"
        fake_row.project_id = None

        mock_sess = MagicMock()
        mock_sess.execute.return_value.scalars.return_value.all.return_value = [fake_row]

        @contextmanager
        def fake_factory():
            yield mock_sess

        writer = PostgresAuditWriter(session_factory=fake_factory)

        fake_models = MagicMock()
        fake_models.AuditEvent = MagicMock()
        fake_sqlalchemy = MagicMock()

        with patch.dict(sys.modules, {
            "aegis.db.models": fake_models,
            "sqlalchemy": fake_sqlalchemy,
        }):
            records = list(writer.read_chain("run:r1"))

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["chain_id"], "run:r1")
        self.assertEqual(records[0]["seq"], 1)
        self.assertEqual(records[0]["this_hash"], "ab" * 32)

    def test_read_chain_with_no_prev_hash(self):
        """read_chain() handles prev_hash=None correctly."""
        from aegis.audit.chain import PostgresAuditWriter

        fake_row = MagicMock()
        fake_row.chain_id = "system"
        fake_row.seq = 1
        fake_row.created_at.isoformat.return_value = "2026-01-01T00:00:00+00:00"
        fake_row.actor = "cli"
        fake_row.action = "init"
        fake_row.target = None
        fake_row.allowlist_check = "n/a"
        fake_row.override = False
        fake_row.success = True
        fake_row.detail = {}
        fake_row.schema_version = 1
        fake_row.prev_hash = None  # first event, no prev
        fake_row.this_hash = bytes.fromhex("cd" * 32)
        fake_row.run_id = None
        fake_row.project_id = None

        mock_sess = MagicMock()
        mock_sess.execute.return_value.scalars.return_value.all.return_value = [fake_row]

        @contextmanager
        def fake_factory():
            yield mock_sess

        writer = PostgresAuditWriter(session_factory=fake_factory)

        with patch.dict(sys.modules, {
            "aegis.db.models": MagicMock(),
            "sqlalchemy": MagicMock(),
        }):
            records = list(writer.read_chain("system"))

        self.assertIsNone(records[0]["prev_hash"])

    def test_iter_chain_ids(self):
        """iter_chain_ids() yields chain_id strings from AuditChainHead."""
        from aegis.audit.chain import PostgresAuditWriter

        mock_sess = MagicMock()
        mock_sess.execute.return_value.scalars.return_value = iter(["run:r1", "system"])

        @contextmanager
        def fake_factory():
            yield mock_sess

        writer = PostgresAuditWriter(session_factory=fake_factory)

        fake_chain_head_cls = MagicMock()
        with patch.dict(sys.modules, {
            "aegis.db.models": MagicMock(AuditChainHead=fake_chain_head_cls),
            "sqlalchemy": MagicMock(),
        }):
            ids = list(writer.iter_chain_ids())

        self.assertIn("run:r1", ids)
        self.assertIn("system", ids)

if __name__ == "__main__":
    unittest.main()
