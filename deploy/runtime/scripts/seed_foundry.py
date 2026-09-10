"""Seed a project's Foundry integration on a deployment, idempotently (2026-09-10).

Runs on the host through ``redsim-run api`` so ``REDSIM_DB_URL`` and
``REDSIM_AUTH_PROFILES_KEY`` come from the service environment::

    redsim-run api python deploy/runtime/scripts/seed_foundry.py <project_id> <secret.json> [--no-auto-push]

``secret.json`` (0600, deleted by the caller afterwards) is the Secrets Manager
document ``{"token": "<bearer>", "dataset_rid": "ri.foundry.main.dataset.…"}``.
The token becomes a bearer ``AuthProfile`` named ``foundry`` (reused when one
exists), the project's Foundry settings are validated exactly as the ``PUT``
route validates them and written with the same ``project.settings`` audit row.
The token is never printed. The deployment's ``REDSIM_INTEGRATION_FOUNDRY_*``
variables must already be in the environment, or ``auto_push`` is refused.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

PROFILE_NAME = "foundry"


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: seed_foundry.py <project_id> <secret.json> [--no-auto-push]", file=sys.stderr)
        return 2
    project_id, secret_path = argv[0], Path(argv[1])
    auto_push = "--no-auto-push" not in argv[2:]
    if not os.environ.get("REDSIM_DB_URL") or not os.environ.get("REDSIM_AUTH_PROFILES_KEY"):
        print("REDSIM_DB_URL and REDSIM_AUTH_PROFILES_KEY must be set (run through redsim-run api)", file=sys.stderr)
        return 2
    secret = json.loads(secret_path.read_text(encoding="utf-8"))
    token, dataset_rid = str(secret.get("token") or "").strip(), str(secret.get("dataset_rid") or "").strip() or None
    if not token:
        print("the secret document has no token", file=sys.stderr)
        return 2

    from sqlalchemy import select

    from redsim.api.errors import ApiError
    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config
    from redsim.db.models import AuthProfile, Project
    from redsim.db.session import get_session
    from redsim.safety import authorize
    from redsim.services.auth_profiles import create_auth_profile
    from redsim.services.ml_integrations import (
        foundry_project_settings,
        foundry_view,
        store_foundry_settings,
        validate_foundry_settings,
    )

    config = load_config()
    writer = resolve_writer(config)
    actor = "system:seed_foundry"
    with get_session() as sess:
        project = sess.get(Project, project_id)
        if project is None:
            print(f"project {project_id!r} not found", file=sys.stderr)
            return 1
        existing = sess.execute(select(AuthProfile).where(
            AuthProfile.project_id == project_id, AuthProfile.name == PROFILE_NAME, AuthProfile.kind == "bearer",
        )).scalars().first()
        if existing is not None and getattr(existing, "deleted_at", None) is None:
            profile_id = str(existing.id)
            print(f"auth profile {PROFILE_NAME!r} already present: {profile_id}")
        else:
            profile = create_auth_profile(sess, project_id=project_id, name=PROFILE_NAME, kind="bearer",
                                          config={"platform": "foundry"}, secret=token, actor=actor,
                                          audit_writer=writer)
            profile_id = str(profile.id)
            print(f"auth profile {PROFILE_NAME!r} created: {profile_id}")
        body = {"auth_profile_id": profile_id, "auto_push": auto_push}
        if dataset_rid:
            body["dataset_rid"] = dataset_rid
        previous = foundry_project_settings(project)
        try:
            merged = validate_foundry_settings(sess, project, body, actor=actor, config=config)
        except ApiError as exc:
            print(f"refused: {exc.code}: {exc}", file=sys.stderr)
            return 1
        authorize("project.settings", None, allowlist=[], actor=actor, writer=writer, project_id=project_id,
                  detail={"project_id": project_id, "field": "ml_integrations.foundry", "seed": True,
                          "auto_push": merged["auto_push"], "dataset_rid": merged["dataset_rid"],
                          "auth_profile_id": merged["auth_profile_id"], "previous_auto_push": previous["auto_push"]})
        store_foundry_settings(project, merged)
        sess.flush()
        view = foundry_view(sess, project, config)
        sess.commit()
    print(json.dumps({"deployment": view["deployment"], "settings": view["settings"], "effective": view["effective"]},
                     indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
