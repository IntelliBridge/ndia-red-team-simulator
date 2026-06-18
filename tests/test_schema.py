import json
import os
import unittest

from aegis.schema import AegisFinding, CodeLocation

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


class TestAegisFinding(unittest.TestCase):

    def setUp(self):
        fixture_path = os.path.join(FIXTURES_DIR, "aegis_finding_expected.json")
        with open(fixture_path) as f:
            self.raw = json.load(f)

    def test_from_dict_key_fields(self):
        finding = AegisFinding.from_dict(self.raw)
        self.assertEqual(finding.id, "vuln-0001")
        self.assertEqual(finding.title, "SQL Injection in Login Form")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.finding_type, "dast")
        self.assertEqual(finding.source_tool, "strix")
        self.assertEqual(finding.status, "open")

    def test_code_locations_are_proper_instances(self):
        finding = AegisFinding.from_dict(self.raw)
        self.assertIsNotNone(finding.code_locations)
        self.assertIsInstance(finding.code_locations, list)
        self.assertTrue(len(finding.code_locations) > 0)
        for loc in finding.code_locations:
            self.assertIsInstance(loc, CodeLocation)
        loc = finding.code_locations[0]
        self.assertEqual(loc.file, "routes/login.js")
        self.assertEqual(loc.start_line, 42)
        self.assertEqual(loc.end_line, 48)

    def test_round_trip(self):
        finding = AegisFinding.from_dict(self.raw)
        result = finding.to_dict()
        self.assertEqual(result, self.raw)

    def test_is_dependency_finding_false_for_dast(self):
        finding = AegisFinding.from_dict(self.raw)
        self.assertFalse(finding.is_dependency_finding)


if __name__ == "__main__":
    unittest.main()
