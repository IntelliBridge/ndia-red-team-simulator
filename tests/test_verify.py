import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from redsim.schema import CodeLocation, RedsimFinding
from redsim.state import RunState
from redsim.verify import (
    classify_dast_remediation,
    classify_sast_remediation,
    parse_curl,
    runtime_proves_post_patch,
    verify_finding,
)


def _finding(**overrides):
    base = {
        "id": "vuln-0001", "title": "SQL Injection",
        "severity": "critical", "finding_type": "dast",
        "description": "...", "source_tool": "strix", "source_run_id": "r",
        "affected_component": "/rest/user/login", "confidence": "high",
        "status": "open", "created_at": "2026-01-01", "updated_at": "2026-01-01",
        "target": "http://localhost:3000",
        "endpoint": "/rest/user/login",
        "method": "POST",
        "poc_script_code": (
            "curl -X POST http://localhost:3000/rest/user/login "
            "-H 'Content-Type: application/json' "
            "-d '{\"email\":\"x@y.z\",\"password\":\"p\"}'"
        ),
    }
    base.update(overrides)
    return RedsimFinding(**base)


def _write_runtime(run_path: Path, **fields):
    target_dir = run_path / "target"
    target_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "name": "juice-shop", "mode": "image", "url": "http://localhost:3000",
        "container_name": "redsim-juice-shop", "container_id": "abc",
        "image_tag": None, "source_repo": None,
        "source_ref_before": None, "source_ref_after": None,
        "built_image_digest": None, "started_at": "now",
        "ready_at": "now", "last_rebuild_at": None,
    }
    data.update(fields)
    (target_dir / "runtime.json").write_text(json.dumps(data))


class TestParseCurl(unittest.TestCase):
    def test_basic_post(self):
        parsed = parse_curl(
            "curl -X POST http://localhost:3000/login "
            "-H 'Content-Type: application/json' "
            "-d '{\"email\":\"a\",\"password\":\"b\"}'"
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["method"], "POST")
        self.assertEqual(parsed["url"], "http://localhost:3000/login")
        self.assertIn("Content-Type: application/json", parsed["headers"])
        self.assertEqual(parsed["body"], '{"email":"a","password":"b"}')

    def test_get_implicit(self):
        parsed = parse_curl("curl http://localhost:3000/x")
        self.assertEqual(parsed["method"], "GET")
        self.assertIsNone(parsed["body"])

    def test_data_promotes_to_post(self):
        parsed = parse_curl("curl http://localhost:3000/x -d 'a=1'")
        self.assertEqual(parsed["method"], "POST")
        self.assertEqual(parsed["body"], "a=1")

    def test_none_for_non_curl(self):
        self.assertIsNone(parse_curl("wget http://example.com"))


class TestDastDecision(unittest.TestCase):
    def test_4xx_status_is_verified(self):
        status, _ = classify_dast_remediation(None, {"status": 401, "body_excerpt": ""})
        self.assertEqual(status, "verified")

    def test_200_with_token_still_vulnerable(self):
        status, _ = classify_dast_remediation(
            None, {"status": 200, "body_excerpt": "{\"authentication\":{\"token\":\"abc\"}}"}
        )
        self.assertEqual(status, "still_vulnerable")

    def test_200_without_token_verified(self):
        status, _ = classify_dast_remediation(
            None, {"status": 200, "body_excerpt": "ok"}
        )
        self.assertEqual(status, "verified")

    def test_error_inconclusive(self):
        status, _ = classify_dast_remediation(None, {"status": None, "error": "conn refused"})
        self.assertEqual(status, "inconclusive")


class TestRuntimeProvenance(unittest.TestCase):
    def test_missing_runtime_not_proven(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "r1")
            proven, _ = runtime_proves_post_patch(state)
            self.assertFalse(proven)

    def test_image_mode_rejected_when_validating_code_patch(self):
        """The strict default refuses image mode — an upstream image cannot
        possibly carry a code patch generated locally."""
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "r1")
            _write_runtime(state.run_path, mode="image")
            proven, reason = runtime_proves_post_patch(state)
            self.assertFalse(proven)
            self.assertIn("image", reason)

    def test_image_mode_accepted_when_not_validating_patch(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "r1")
            _write_runtime(state.run_path, mode="image")
            proven, _ = runtime_proves_post_patch(state, require_source_rebuild=False)
            self.assertTrue(proven)

    def test_source_mode_requires_rebuild(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "r1")
            _write_runtime(state.run_path, mode="source", last_rebuild_at=None)
            proven, _ = runtime_proves_post_patch(state)
            self.assertFalse(proven)

    def test_source_mode_with_rebuild_proven(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "r1")
            _write_runtime(state.run_path, mode="source", last_rebuild_at="t",
                           source_ref_before="a", source_ref_after="b")
            proven, _ = runtime_proves_post_patch(state)
            self.assertTrue(proven)


class TestSastGrep(unittest.TestCase):
    def test_absent_snippet_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "routes").mkdir()
            (repo / "routes" / "login.js").write_text("clean code\n")
            f = _finding(
                finding_type="sast",
                code_locations=[CodeLocation(
                    file="routes/login.js", start_line=1, end_line=1,
                    snippet="raw_sql_query", fix_before="raw_sql_query",
                )],
            )
            status, _ = classify_sast_remediation(f, repo)
            self.assertEqual(status, "verified")

    def test_present_snippet_still_vulnerable(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "routes").mkdir()
            (repo / "routes" / "login.js").write_text("contains raw_sql_query here\n")
            f = _finding(
                finding_type="sast",
                code_locations=[CodeLocation(
                    file="routes/login.js", start_line=1, end_line=1,
                    snippet="raw_sql_query", fix_before="raw_sql_query",
                )],
            )
            status, _ = classify_sast_remediation(f, repo)
            self.assertEqual(status, "still_vulnerable")


class TestVerifyTopLevel(unittest.TestCase):
    def test_returns_inconclusive_without_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "r1")
            result = verify_finding(_finding(), run_state=state)
            self.assertEqual(result.status, "inconclusive")
            self.assertTrue((state.run_path / "verify" / "vuln-0001.json").exists())

    def test_dast_replay_verified_when_target_returns_401(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "r1")
            _write_runtime(state.run_path, mode="source", last_rebuild_at="t",
                           source_ref_before="a", source_ref_after="b")
            with patch("redsim.verify.replay_poc", return_value={
                "status": 401, "headers": {}, "body_excerpt": "",
                "body_sha256": "x", "duration_ms": 1,
            }):
                result = verify_finding(_finding(), run_state=state)
            self.assertEqual(result.status, "verified")
            evidence = json.loads((state.run_path / "verify" / "vuln-0001.json").read_text())
            self.assertEqual(evidence["strategy"], "dast_poc")
            self.assertTrue(
                (state.run_path / "artifacts" / "evidence" / "vuln-0001" / "after.json").exists()
            )

    def test_dast_replay_still_vulnerable_when_token_returned(self):
        # Loose provenance so we exercise the replay branch (image mode is
        # otherwise rejected under the strict default).
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "r1")
            _write_runtime(state.run_path, mode="image")
            with patch("redsim.verify.replay_poc", return_value={
                "status": 200, "headers": {},
                "body_excerpt": "{\"authentication\":{\"token\":\"xyz\"}}",
                "body_sha256": "x", "duration_ms": 1,
            }):
                result = verify_finding(_finding(), run_state=state, require_source_rebuild=False)
            self.assertEqual(result.status, "still_vulnerable")


class TestDependencyRescan(unittest.TestCase):
    """Dependency verification is unavailable in this build.

    The pentest dependency-rescan engine (the Trivy runner) was removed with
    the pentest domain, so a dependency finding now verifies as ``inconclusive``
    with an explicit "engine unavailable" reason — never a silent success.
    """

    def _dep(self, package="lodash", installed="4.17.20", fixed="4.17.21"):
        return RedsimFinding(
            id=f"CVE-2024-1111@{package}",
            title=f"{package} vuln", severity="high",
            finding_type="dependency",
            description="...", source_tool="trivy", source_run_id="r",
            affected_component=package, confidence="high", status="open",
            created_at="2026", updated_at="2026",
            cve="CVE-2024-1111", package_name=package,
            installed_version=installed, fixed_version=fixed,
        )

    def test_dependency_verification_is_inconclusive_and_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "r1")
            _write_runtime(state.run_path, mode="source", last_rebuild_at="t",
                           source_ref_before="a", source_ref_after="b")
            result = verify_finding(
                self._dep(), run_state=state,
                repo_path=Path(tmp), require_source_rebuild=False,
            )
            self.assertEqual(result.status, "inconclusive")
            self.assertEqual(result.strategy, "dependency_rescan")
            self.assertIn("unavailable", result.evidence["reason"])


if __name__ == "__main__":
    unittest.main()
