"""verify_target service + the targets verify/verification API.

Offline: in-memory sqlite (JSONB->TEXT), DNS/GitHub checks monkeypatched at
the ``aegis.services.target_verify`` seam so no network is touched. Mirrors
``test_finding_tickets.py``'s session-factory + FastAPI client pattern.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

import pytest

pytest.importorskip("sqlalchemy")

from aegis.audit.chain import InMemoryAuditWriter
from aegis.db.models import Organization, Project, Target
from aegis.services import targets as targets_svc
from tests.conftest import make_sqlite_session_factory as _make_session_factory

# DB-backed (sqlite harness); excluded from the CI unit job's "not integration".
pytestmark = pytest.mark.integration


def _seed(Session) -> None:
    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="a"))
        s.add(Project(id="proj-1", org_id="org-1", name="P", slug="p"))
        s.add(Target(id="tgt-url", project_id="proj-1", kind="url",
                     value="https://app.example.com", verified=False))
        s.add(Target(id="tgt-repo", project_id="proj-1", kind="github_repo",
                     value="acme/app", verified=False, installation_id=42))
        s.add(Target(id="tgt-img", project_id="proj-1", kind="image",
                     value="registry/img:tag", verified=False))
        s.commit()


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class TestVerifyTargetService(unittest.TestCase):
    def setUp(self):
        self.session_cm, _, self.Session = _make_session_factory()
        _seed(self.Session)

    def test_url_success_sets_verified_and_audits(self):
        writer = InMemoryAuditWriter()
        with patch("aegis.services.target_verify.verify_dns_txt",
                   return_value=(True, "matched TXT record on app.example.com")):
            with self.Session() as sess:
                result = targets_svc.verify_target(
                    sess, "tgt-url", actor="user:alice", audit_writer=writer)
                sess.commit()
        self.assertTrue(result.verified)
        self.assertEqual(result.verify_method, "dns-txt")
        with self.Session() as sess:
            self.assertTrue(sess.get(Target, "tgt-url").verified)
        ev = writer.events[0]
        self.assertEqual(ev.action, "target.verify")
        self.assertTrue(ev.success)
        self.assertTrue(ev.detail["matched"])
        self.assertEqual(ev.detail["kind"], "url")
        # secret-free
        self.assertNotIn("secret", ev.detail)
        self.assertNotIn("token", ev.detail)

    def test_url_failure_leaves_unverified_and_raises(self):
        writer = InMemoryAuditWriter()
        with patch("aegis.services.target_verify.verify_dns_txt",
                   return_value=(False, "no DNS record exists (NXDOMAIN)")):
            with self.Session() as sess:
                with self.assertRaises(targets_svc.TargetVerificationError) as ctx:
                    targets_svc.verify_target(
                        sess, "tgt-url", actor="user:alice", audit_writer=writer)
        self.assertIn("NXDOMAIN", str(ctx.exception))
        with self.Session() as sess:
            self.assertFalse(sess.get(Target, "tgt-url").verified)
        # a failure audit event was still emitted
        ev = writer.events[0]
        self.assertEqual(ev.action, "target.verify")
        self.assertFalse(ev.success)
        self.assertFalse(ev.detail["matched"])

    def test_github_repo_success(self):
        with patch("aegis.services.target_verify.verify_github_repo",
                   return_value=(True, "installation 42 can access acme/app")):
            with self.Session() as sess:
                result = targets_svc.verify_target(
                    sess, "tgt-repo", actor="user:bob")
                sess.commit()
        self.assertTrue(result.verified)
        self.assertEqual(result.verify_method, "github-app")

    def test_image_kind_unsupported(self):
        with self.Session() as sess:
            with self.assertRaises(targets_svc.TargetVerificationError) as ctx:
                targets_svc.verify_target(sess, "tgt-img", actor="user:a")
        self.assertIn("image", str(ctx.exception).lower())

    def test_unknown_target_raises_lookup(self):
        with self.Session() as sess:
            with self.assertRaises(LookupError):
                targets_svc.verify_target(sess, "nope", actor="user:a")


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

class TestVerifyAPI(unittest.TestCase):
    def setUp(self):
        import aegis.api.middleware.rate_limit as rl
        rl._BUCKETS.clear()

    def tearDown(self):
        import aegis.api.middleware.rate_limit as rl
        rl._BUCKETS.clear()

    def _app_and_cm(self):
        from aegis.api.app import create_app
        from aegis.api.settings import APISettings
        session_cm, _, Session = _make_session_factory()
        _seed(Session)
        app = create_app(APISettings(
            env="dev", auth_mode="dev",
            cors_origins=["http://localhost:3000"],
            rate_limit_per_user_per_min=10_000,
            rate_limit_per_project_per_min=10_000,
        ))
        return app, session_cm

    def _client(self, app, memberships):
        from fastapi.testclient import TestClient

        from aegis.api.auth import CurrentUser, get_current_user
        user = CurrentUser(sub="dev:u@test", email="u@test",
                           project_memberships=memberships)
        app.dependency_overrides[get_current_user] = lambda: user
        return TestClient(app, raise_server_exceptions=False)

    def test_get_verification_returns_token_no_secret(self):
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "scanner"})
        with patch("aegis.db.session.get_session", session_cm), \
             patch.dict("os.environ", {"AEGIS_VERIFY_SECRET": "top-secret"}):
            r = client.get("/v1/targets/tgt-url/verification")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["method"], "dns-txt")
        self.assertEqual(body["record_type"], "TXT")
        self.assertEqual(body["record_name"], "app.example.com")
        self.assertTrue(body["record_value"].startswith("aegis-site-verification="))
        # the raw secret must never appear in the response
        self.assertNotIn("top-secret", r.text)

    def test_get_verification_github(self):
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "scanner"})
        with patch("aegis.db.session.get_session", session_cm):
            r = client.get("/v1/targets/tgt-repo/verification")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["method"], "github-app")
        self.assertEqual(r.json()["installation_id"], 42)

    def test_get_verification_unknown_404(self):
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "scanner"})
        with patch("aegis.db.session.get_session", session_cm):
            r = client.get("/v1/targets/nope/verification")
        self.assertEqual(r.status_code, 404)

    def test_verify_success_200(self):
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "admin"})
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.targets.resolve_writer",
                   return_value=InMemoryAuditWriter()), \
             patch("aegis.services.target_verify.verify_dns_txt",
                   return_value=(True, "matched TXT record on app.example.com")):
            r = client.post("/v1/targets/tgt-url/verify")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["verified"])
        self.assertEqual(body["method"], "dns-txt")

    def test_verify_failure_422(self):
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "admin"})
        with patch("aegis.db.session.get_session", session_cm), \
             patch("aegis.api.v1.targets.resolve_writer",
                   return_value=InMemoryAuditWriter()), \
             patch("aegis.services.target_verify.verify_dns_txt",
                   return_value=(False, "no DNS record exists (NXDOMAIN)")):
            r = client.post("/v1/targets/tgt-url/verify")
        self.assertEqual(r.status_code, 422)
        self.assertIn("NXDOMAIN", r.json()["detail"])

    def test_verify_non_admin_403(self):
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "remediator"})
        with patch("aegis.db.session.get_session", session_cm):
            r = client.post("/v1/targets/tgt-url/verify")
        self.assertEqual(r.status_code, 403)

    def test_verify_unknown_404(self):
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"proj-1": "admin"})
        with patch("aegis.db.session.get_session", session_cm):
            r = client.post("/v1/targets/nope/verify")
        self.assertEqual(r.status_code, 404)

    def test_verify_non_member_403(self):
        pytest.importorskip("fastapi")
        app, session_cm = self._app_and_cm()
        client = self._client(app, {"other-proj": "admin"})
        with patch("aegis.db.session.get_session", session_cm):
            r = client.post("/v1/targets/tgt-url/verify")
        self.assertEqual(r.status_code, 403)


if __name__ == "__main__":
    unittest.main()
