"""The development seed plants both admin identities and repeats safely.

The two subjects matter: ``GET /v1/projects`` matches the caller on
``users.sub``, and the browser login carries the Keycloak subject uuid while
a dev bearer token carries ``dev:<email>``.
"""

import json
import pathlib
import unittest

import pytest

pytest.importorskip("sqlalchemy")
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from redsim.db.models import Base, ProjectMembership, User
from redsim.db.seed import ADMIN_EMAIL, KEYCLOAK_ADMIN_SUB, seed_default
from tests.conftest import patch_jsonb_for_sqlite

REALM_EXPORT = (pathlib.Path(__file__).resolve().parents[1]
                / "deploy" / "keycloak" / "realm-export.json")


def _session():
    patch_jsonb_for_sqlite()
    engine = create_engine("sqlite://", future=True)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(engine, future=True)()


class TestSeedDefault(unittest.TestCase):
    def test_seeds_both_admin_subjects_with_admin_membership(self):
        with _session() as sess:
            created = seed_default(sess)
            sess.commit()
            subs = {u.sub for u in sess.query(User).all()}
            roles = {m.user_id: m.role
                     for m in sess.query(ProjectMembership).all()}

        self.assertIn(f"org:{'default-org'}", created)
        self.assertEqual(subs, {KEYCLOAK_ADMIN_SUB, f"dev:{ADMIN_EMAIL}"})
        self.assertEqual(roles, {"admin": "admin", "admin-dev": "admin"})

    def test_second_run_creates_nothing(self):
        with _session() as sess:
            seed_default(sess)
            sess.commit()
            self.assertEqual(seed_default(sess), [])
            sess.commit()
            self.assertEqual(sess.query(User).count(), 2)


class TestRealmExportAgreesWithTheSeed(unittest.TestCase):
    """A drifting uuid would leave the browser login without a project."""

    def test_realm_admin_id_is_the_seeded_subject(self):
        realm = json.loads(REALM_EXPORT.read_text())
        admin = next(u for u in realm["users"] if u["username"] == "admin")
        self.assertEqual(admin["id"], KEYCLOAK_ADMIN_SUB)
        self.assertEqual(admin["email"], ADMIN_EMAIL)
        roles = admin["attributes"]["redsim_project_roles"]
        self.assertEqual(json.loads(roles[0]), {"default": "admin"})


if __name__ == "__main__":
    unittest.main()
