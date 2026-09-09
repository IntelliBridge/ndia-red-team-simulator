"""Create the demo organisation and project rows, idempotently.

Runs inside the ``assets`` task definition (worker image, ``REDSIM_DB_URL``
from Secrets Manager) as a command override:

    python -c "$(cat seed_project.py)" <org_id> <project_id> [<name>]

Memberships are not rows: the API reads them from the ``redsim_project_roles``
token claim (``redsim.api.auth``), which ``seed_identity.py`` sets on each
Keycloak user. A second run finds the rows and changes nothing. Bundled model
registration is a separate step (``redsim ml seed --project <project_id>``)
because it needs the asset bundle mounted.
"""
import os
import sys


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: seed_project.py <org_id> <project_id> [<display name>]", file=sys.stderr)
        return 2
    org_id, project_id = argv[0], argv[1]
    name = argv[2] if len(argv) > 2 else project_id
    if not os.environ.get("REDSIM_DB_URL"):
        print("REDSIM_DB_URL is not set", file=sys.stderr)
        return 2
    from redsim.db.models import Organization, Project
    from redsim.db.session import get_session, init_engine

    init_engine(os.environ["REDSIM_DB_URL"])
    with get_session() as session:
        org = session.get(Organization, org_id)
        if org is None:
            session.add(Organization(id=org_id, name=name, slug=org_id))
            print(f"organisation {org_id}: created")
        else:
            print(f"organisation {org_id}: present")
        project = session.get(Project, project_id)
        if project is None:
            session.add(Project(id=project_id, org_id=org_id, name=name, slug=project_id))
            print(f"project {project_id}: created")
        elif project.org_id != org_id:
            print(f"project {project_id}: present under organisation {project.org_id}, not {org_id}", file=sys.stderr)
            return 1
        else:
            print(f"project {project_id}: present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
