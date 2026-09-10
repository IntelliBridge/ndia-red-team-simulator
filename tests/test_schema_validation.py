"""Runtime-validation behaviour of the Pydantic-v2 ``RedsimFinding`` schema.

Companion to ``test_schema.py`` (which covers from_dict/round-trip on the golden
fixture). These tests pin the new guarantees introduced by the dataclass ->
Pydantic migration: validation at construction, rejection of out-of-vocabulary
values, extra-key tolerance, guarded assignment, and the *lenient* legacy-read
path that keeps historical ``schema_blob`` rows loadable.
"""

import logging
import unittest

from pydantic import ValidationError

from redsim.schema import CodeLocation, RedsimFinding

_VALID = {
    "id": "f1", "title": "t", "severity": "high", "finding_type": "sast",
    "description": "d", "source_tool": "bandit", "source_run_id": "r1",
    "affected_component": "x.py", "confidence": "high", "status": "open",
    "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
}


class TestConstructionValidation(unittest.TestCase):
    def test_valid_construction(self):
        f = RedsimFinding(**_VALID)
        self.assertEqual(f.severity, "high")

    def test_bad_severity_rejected(self):
        with self.assertRaises(ValidationError):
            RedsimFinding(**{**_VALID, "severity": "informational"})

    def test_bad_finding_type_rejected(self):
        with self.assertRaises(ValidationError):
            RedsimFinding(**{**_VALID, "finding_type": "malware"})

    def test_missing_required_field_rejected(self):
        incomplete = {k: v for k, v in _VALID.items() if k != "title"}
        with self.assertRaises(ValidationError):
            RedsimFinding(**incomplete)


class TestSerializationRoundTrip(unittest.TestCase):
    def test_to_dict_from_dict_round_trip(self):
        f = RedsimFinding(**_VALID)
        self.assertEqual(RedsimFinding.from_dict(f.to_dict()), f)

    def test_nested_code_locations_coerced(self):
        f = RedsimFinding.from_dict({
            **_VALID,
            "code_locations": [{"file": "a.py", "start_line": 1, "end_line": 2}],
        })
        self.assertIsInstance(f.code_locations[0], CodeLocation)
        self.assertEqual(f.code_locations[0].file, "a.py")

    def test_extra_keys_tolerated(self):
        f = RedsimFinding.from_dict({**_VALID, "unknown_future_field": 123})
        self.assertFalse(hasattr(f, "unknown_future_field"))


class TestGuardedAssignment(unittest.TestCase):
    def test_valid_status_transition(self):
        f = RedsimFinding(**_VALID)
        f.status = "fixed"
        self.assertEqual(f.status, "fixed")

    def test_invalid_assignment_rejected(self):
        f = RedsimFinding(**_VALID)
        with self.assertRaises(ValidationError):
            f.status = "not-a-status"


class TestLenientLegacyRead(unittest.TestCase):
    def test_invalid_legacy_blob_loads_without_raising(self):
        """Old dataclasses never validated; a blob with an out-of-vocabulary
        severity must still load (best-effort) rather than break the read."""
        legacy = {**_VALID, "severity": "informational"}
        with self.assertLogs("redsim.schema", level=logging.WARNING):
            f = RedsimFinding.from_dict(legacy)
        # value preserved verbatim, matching pre-migration (unvalidated) behaviour
        self.assertEqual(f.severity, "informational")

    def test_invalid_legacy_blob_still_coerces_code_locations(self):
        legacy = {
            **_VALID, "severity": "informational",
            "code_locations": [{"file": "a.py", "start_line": 1, "end_line": 2}],
        }
        f = RedsimFinding.from_dict(legacy)
        self.assertIsInstance(f.code_locations[0], CodeLocation)


if __name__ == "__main__":
    unittest.main()
