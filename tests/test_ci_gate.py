"""CI-gate policy evaluator."""

import unittest

from aegis.workers.tasks.ci_gate import CIGatePolicy, evaluate


class TestEvaluatePolicy(unittest.TestCase):
    def test_blocks_on_high_severity_above_threshold(self):
        findings = [{"severity": "critical"}, {"severity": "low"}]
        code, reason = evaluate(findings, CIGatePolicy(severity_threshold="high"))
        self.assertEqual(code, 1)
        self.assertIn("blocking", reason)

    def test_passes_when_below_threshold(self):
        findings = [{"severity": "medium"}, {"severity": "low"}]
        code, reason = evaluate(findings, CIGatePolicy(severity_threshold="high"))
        self.assertEqual(code, 0)
        self.assertEqual(reason, "pass")

    def test_max_findings_limit(self):
        findings = [{"severity": "high"}] * 5
        code, reason = evaluate(findings,
                                CIGatePolicy(severity_threshold="high",
                                              max_findings=3))
        self.assertEqual(code, 1)
        self.assertIn("exceeds max", reason)

    def test_require_validated_drops_unvalidated_blockers(self):
        findings = [
            {"severity": "high", "validation_state": "unvalidated"},
            {"severity": "high", "validation_state": "poc_passed"},
        ]
        code, _ = evaluate(findings,
                           CIGatePolicy(severity_threshold="high",
                                         require_validated=True))
        # Only the validated one counts as blocking → still fails, but with one item.
        self.assertEqual(code, 1)

    def test_require_validated_with_no_validated_blockers_passes(self):
        findings = [
            {"severity": "high", "validation_state": "unvalidated"},
            {"severity": "high", "validation_state": "not_runnable"},
        ]
        code, reason = evaluate(findings,
                                CIGatePolicy(severity_threshold="high",
                                              require_validated=True))
        self.assertEqual(code, 0)
        self.assertEqual(reason, "pass")


if __name__ == "__main__":
    unittest.main()
