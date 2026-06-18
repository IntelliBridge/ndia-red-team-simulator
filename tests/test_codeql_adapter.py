import json
import unittest
from pathlib import Path

from aegis.scanners.codeql_adapter import _convert, _extract_results
from aegis.schema import AegisFinding, CodeLocation

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"


class TestCodeqlAdapter(unittest.TestCase):
    def setUp(self):
        with open(FIXTURES / "codeql_raw.json") as f:
            self.payload = json.load(f)
        self.results = _extract_results(self.payload)

    def test_extract_results(self):
        self.assertEqual(len(self.results), 2)

    def test_convert_required_fields(self):
        result = _convert(self.results[0], "run-123")
        self.assertIsInstance(result, AegisFinding)
        self.assertEqual(result.id, "codeql:py/sql-injection:app/db.py:42")
        self.assertEqual(result.title, "py/sql-injection")
        self.assertEqual(result.severity, "high")
        self.assertEqual(result.finding_type, "sast")
        self.assertEqual(result.source_tool, "codeql")
        self.assertEqual(result.source_run_id, "run-123")
        self.assertEqual(result.affected_component, "app/db.py")
        self.assertEqual(result.status, "open")

    def test_tool_specific_fields(self):
        result = _convert(self.results[0], "run-123")
        self.assertIsNotNone(result.code_locations)
        self.assertEqual(len(result.code_locations), 1)
        loc = result.code_locations[0]
        self.assertIsInstance(loc, CodeLocation)
        self.assertEqual(loc.file, "app/db.py")
        self.assertEqual(loc.start_line, 42)
        self.assertEqual(loc.end_line, 45)

    def test_severity_mapping(self):
        error = _convert(self.results[0], "run-123")
        warning = _convert(self.results[1], "run-123")
        self.assertEqual(error.severity, "high")
        self.assertEqual(warning.severity, "medium")

    def test_convert_all(self):
        results = [_convert(r, "run-123") for r in self.results]
        self.assertEqual(len(results), 2)
        self.assertTrue(all(isinstance(r, AegisFinding) for r in results))


if __name__ == "__main__":
    unittest.main()
