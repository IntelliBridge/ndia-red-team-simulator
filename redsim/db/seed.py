"""Idempotent development seed: the default org, project and admin users.

Run as ``python -m redsim.db.seed`` (``cd deploy && make seed``, and the API
container's start command). It is a development convenience, so it refuses to
run when ``REDSIM_ENV`` is ``prod``: the identities it plants are the ones
``deploy/keycloak/realm-export.json`` ships with a published password.

The admin exists twice on purpose, once per way of signing in to the local
stack. ``users.sub`` is what ``GET /v1/projects`` matches the caller on
(``redsim/api/v1/projects.py``), and the two login paths present different
subjects: the browser login carries the Keycloak subject uuid, while a
``Bearer dev:<email>`` token carries ``dev:<email>``. One row per subject is
what makes both paths land on a real membership row rather than the
token-only fallback.
"""

from __future__ import annotations

import os
from typing import Any

# The realm export pins this id on its ``admin`` user, so Keycloak issues it
# as the ``sub`` claim. Change the two together or the browser login stops
# resolving to this row.
KEYCLOAK_ADMIN_SUB = "9e2f6f2a-0000-4a00-9000-000000000001"
ADMIN_EMAIL = "admin@redsim.local"
ORG_ID = "default-org"
PROJECT_ID = "default"


def seed_default(session: Any) -> list[str]:
    """Create the default org, project and admin memberships if absent.

    Returns the ids of the rows this call created, empty when everything was
    already present. The caller owns the transaction.
    """
    from redsim.db.models import (
        Organization,
        Project,
        ProjectMembership,
        User,
    )

    created: list[str] = []
    if session.get(Organization, ORG_ID) is None:
        session.add(Organization(id=ORG_ID, name="Default", slug="default"))
        created.append(f"org:{ORG_ID}")
    if session.get(Project, PROJECT_ID) is None:
        session.add(Project(id=PROJECT_ID, org_id=ORG_ID,
                            name="Default", slug="default"))
        created.append(f"project:{PROJECT_ID}")

    for user_id, sub in (("admin", KEYCLOAK_ADMIN_SUB),
                         ("admin-dev", f"dev:{ADMIN_EMAIL}")):
        if session.get(User, user_id) is None:
            session.add(User(id=user_id, sub=sub, email=ADMIN_EMAIL,
                             display_name="Admin"))
            created.append(f"user:{user_id}")
        if session.get(ProjectMembership, (user_id, PROJECT_ID)) is None:
            session.add(ProjectMembership(user_id=user_id,
                                          project_id=PROJECT_ID, role="admin"))
            created.append(f"membership:{user_id}")
    return created


def main() -> int:
    """Seed against ``REDSIM_DB_URL`` and print what was created."""
    if os.environ.get("REDSIM_ENV") == "prod":
        print("seed: refused, REDSIM_ENV=prod")
        return 1

    from redsim.db.session import get_session, init_engine

    init_engine(os.environ["REDSIM_DB_URL"])
    with get_session() as session:
        created = seed_default(session)
    print("seeded: " + (", ".join(created) if created else "nothing new"))
    return 0


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main())
