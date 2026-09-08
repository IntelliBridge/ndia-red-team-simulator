"""Authenticated-DAST auth-profile API + service tests.

Mirrors the sqlite harness from ``test_projects_api.py``. Asserts the
contract that secret material never crosses the API boundary: responses
carry id/project_id/name/kind/config/created_at only; decryption happens
exclusively through ``services.auth_profiles.resolve_auth_for_scan``.
"""

from __future__ import annotations

import contextlib
import json
import os
import unittest
from unittest import mock
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")
pytest.importorskip("cryptography")

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from redsim.api.app import create_app
from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.settings import APISettings

SECRET = "hunter2-super-secret"


def _patch_jsonb_for_sqlite() -> None:
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles

    @compiles(JSONB, "sqlite")
    def _to_text(t, c, **kw):
        return "TEXT"


def _build_app_with_sqlite():
    _patch_jsonb_for_sqlite()
    from redsim.db.models import (
        Base,
        Organization,
        Project,
        ProjectMembership,
        User,
    )

    engine = create_engine(
        "sqlite://", future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as exc:  # noqa: BLE001 - skip on any sqlite failure
        raise unittest.SkipTest(f"sqlite: {exc}")
    Session = sessionmaker(engine, expire_on_commit=False)

    with Session() as s:
        s.add(Organization(id="org-1", name="A", slug="a"))
        s.add(Project(id="proj-a", org_id="org-1", name="ProjA", slug="proj-a"))
        s.add(User(id="u-alice", sub="dev:alice@x", email="alice@x",
                   display_name="Alice"))
        s.add(User(id="u-bob", sub="dev:bob@x", email="bob@x",
                   display_name="Bob"))
        s.add(ProjectMembership(user_id="u-alice", project_id="proj-a", role="admin"))
        s.add(ProjectMembership(user_id="u-bob", project_id="proj-a", role="scanner"))
        s.commit()

    @contextlib.contextmanager
    def session_cm():
        sess = Session()
        try:
            yield sess
            sess.commit()
        except Exception:
            sess.rollback()
            raise
        finally:
            sess.close()

    settings = APISettings(env="dev", auth_mode="dev",
                           cors_origins=["http://localhost:3000"])
    return create_app(settings), session_cm


def _override_user(app, user: CurrentUser):
    app.dependency_overrides[get_current_user] = lambda: user


ALICE = CurrentUser(sub="dev:alice@x", email="alice@x",
                    project_memberships={"proj-a": "admin"})
BOB = CurrentUser(sub="dev:bob@x", email="bob@x",
                  project_memberships={"proj-a": "scanner"})

BODY = {
    "project_id": "proj-a",
    "name": "staging-login",
    "kind": "form",
    "config": {"login_url": "http://localhost:3000/login",
               "username_field": "email", "password_field": "password",
               "username": "scan-bot@example.com"},
    "secret": SECRET,
}


class AuthProfilesApiBase(unittest.TestCase):
    def setUp(self):
        # The rate-limit bucket store is a module global shared across tests;
        # reset it so an earlier suite's writes don't drain it into a 429 here
        # (and clean up so this suite's writes don't drain it for later ones).
        import redsim.api.middleware.rate_limit as rl
        rl._BUCKETS.clear()
        self.addCleanup(rl._BUCKETS.clear)

        env = dict(os.environ)
        env.pop("REDSIM_DB_URL", None)  # keep resolve_writer off Postgres
        env["REDSIM_TEST_AUDIT"] = "memory"
        env["REDSIM_AUTH_PROFILES_KEY"] = Fernet.generate_key().decode()
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.app, self.session_cm = _build_app_with_sqlite()
        self.client = TestClient(self.app)

    def _request(self, method: str, url: str, *, user: CurrentUser = ALICE, **kw):
        _override_user(self.app, user)
        with patch("redsim.db.session.get_session", self.session_cm):
            return getattr(self.client, method)(url, **kw)


class TestAuthProfilesCrud(AuthProfilesApiBase):
    def test_create_returns_201_without_secret(self):
        resp = self._request("post", "/v1/auth-profiles", json=BODY)
        self.assertEqual(resp.status_code, 201)
        body = resp.json()
        self.assertEqual(body["project_id"], "proj-a")
        self.assertEqual(body["name"], "staging-login")
        self.assertEqual(body["kind"], "form")
        self.assertEqual(body["config"]["login_url"],
                         "http://localhost:3000/login")
        self.assertTrue(body["id"].startswith("authprof-"))
        self.assertIsNotNone(body["created_at"])
        self.assertNotIn("secret", body)
        self.assertNotIn("secret_ciphertext", body)
        self.assertNotIn(SECRET, json.dumps(body))

    def test_list_never_exposes_secret_material(self):
        self._request("post", "/v1/auth-profiles", json=BODY)
        resp = self._request("get", "/v1/auth-profiles?project=proj-a")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["count"], 1)
        profile = body["auth_profiles"][0]
        self.assertEqual(
            set(profile),
            {"id", "project_id", "name", "kind", "config", "created_at"},
        )
        self.assertNotIn(SECRET, json.dumps(body))

    def test_duplicate_name_returns_409(self):
        first = self._request("post", "/v1/auth-profiles", json=BODY)
        self.assertEqual(first.status_code, 201)
        dup = self._request("post", "/v1/auth-profiles", json=BODY)
        self.assertEqual(dup.status_code, 409)

    def test_delete_204_then_404(self):
        created = self._request("post", "/v1/auth-profiles", json=BODY)
        profile_id = created.json()["id"]
        resp = self._request("delete", f"/v1/auth-profiles/{profile_id}")
        self.assertEqual(resp.status_code, 204)
        again = self._request("delete", f"/v1/auth-profiles/{profile_id}")
        self.assertEqual(again.status_code, 404)
        listing = self._request("get", "/v1/auth-profiles?project=proj-a")
        self.assertEqual(listing.json()["count"], 0)

    def test_invalid_kind_returns_422(self):
        bad = dict(BODY, kind="oauth-dance")
        resp = self._request("post", "/v1/auth-profiles", json=bad)
        self.assertEqual(resp.status_code, 422)

    def test_create_requires_admin_role(self):
        resp = self._request("post", "/v1/auth-profiles", json=BODY, user=BOB)
        self.assertEqual(resp.status_code, 403)


class TestResolveAuthForScan(AuthProfilesApiBase):
    def test_resolves_decrypted_secret_for_worker(self):
        from redsim.services import auth_profiles as svc

        created = self._request("post", "/v1/auth-profiles", json=BODY)
        profile_id = created.json()["id"]

        with self.session_cm() as sess:
            resolved = svc.resolve_auth_for_scan(sess, profile_id)
        self.assertEqual(resolved["kind"], "form")
        self.assertEqual(resolved["config"]["username_field"], "email")
        self.assertEqual(resolved["secret"], SECRET)

    def test_unknown_profile_raises_lookup_error(self):
        from redsim.services import auth_profiles as svc

        with self.session_cm() as sess, self.assertRaises(LookupError):
            svc.resolve_auth_for_scan(sess, "authprof-nope")

    def test_stored_ciphertext_is_not_plaintext(self):
        from redsim.db.models import AuthProfile

        created = self._request("post", "/v1/auth-profiles", json=BODY)
        profile_id = created.json()["id"]
        with self.session_cm() as sess:
            row = sess.get(AuthProfile, profile_id)
            self.assertNotIn(SECRET.encode(), row.secret_ciphertext)


if __name__ == "__main__":
    unittest.main()
