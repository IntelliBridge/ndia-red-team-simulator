"""Hash-chain integrity tests (filesystem backend; Postgres parity is
exercised when REDSIM_TEST_DB_URL is set)."""

import json
import tempfile
import unittest
from pathlib import Path

from redsim.audit.chain import (
    JsonlAuditWriter,
    verify_chain,
)
from redsim.audit.redact import redact_audit_detail


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


if __name__ == "__main__":
    unittest.main()
