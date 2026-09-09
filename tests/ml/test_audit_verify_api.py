"""``GET /v1/audit/verify`` (register G-AUDITVERIFY, spec 5.11, 17.1).

``?all=1`` answers ``{"chains": [...]}`` for every chain the caller may verify and is
admin-only; ``?run=`` resolves the project through ``ensure_run_access`` so the caller's
``project_id`` argument cannot widen the gate; a tampered event is reported broken.
Chains are written with the real ``JsonlAuditWriter`` (the offline writer the CLI's
``redsim audit verify`` walks) so the hashes are genuine; sqlite would drop the tzinfo
the Postgres writer pins into ``ts`` and break every recomputed hash.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from redsim.audit.chain import JsonlAuditWriter
from tests.ml.test_findings_routes import (  # noqa: F401 - fixture import
    BASELINE,
    FOREIGN,
    OTHER_PROJECT,
    PROJECT,
    _user,
    ml_api,
)

pytestmark = pytest.mark.integration


def _seed_chains(api: dict[str, Any]) -> JsonlAuditWriter:
    writer = JsonlAuditWriter(api["tmp_path"] / "audit")

    def emit(action: str, *, project_id: str | None, run_id: str | None) -> None:
        writer.append(action=action, actor="user:seed", target=None, allowlist_check="n/a", override=False,
                      success=True, detail={"seeded": True}, run_id=run_id, project_id=project_id)

    emit("attack.run", project_id=PROJECT, run_id=None)
    emit("model.register", project_id=PROJECT, run_id=None)
    for action in ("model.load", "attack.execute.fgsm", "job.complete"):
        emit(action, project_id=PROJECT, run_id=BASELINE)
    emit("attack.run", project_id=OTHER_PROJECT, run_id=None)
    emit("job.complete", project_id=OTHER_PROJECT, run_id=FOREIGN)
    emit("audit.worm_export", project_id=None, run_id=None)
    return writer


def test_all_chains_admin_only(ml_api: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    writer = _seed_chains(ml_api)
    monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda _cfg: writer)

    admin = ml_api["as_user"](_user("auditor", "admin"))
    response = admin.get("/v1/audit/verify", params={"all": "1"})
    assert response.status_code == 200, response.text
    chains = {c["chain_id"]: c for c in response.json()["chains"]}
    # Only the chains of the caller's admin project, plus the beat-task system chain.
    assert set(chains) == {f"project:{PROJECT}", f"run:{BASELINE}", "system"}
    assert all(c["verified"] is True and c["broken_at"] is None and c["reason"] is None for c in chains.values())
    assert chains[f"run:{BASELINE}"]["event_count"] == 3 and chains[f"run:{BASELINE}"]["count"] == 3
    assert chains[f"project:{PROJECT}"]["event_count"] == 2
    assert all(isinstance(c["head_hash"], str) and len(c["head_hash"]) == 64 for c in chains.values())
    assert [c["chain_id"] for c in response.json()["chains"]] == sorted(chains)

    # Admin only: scanner and viewer members are refused; a system principal sees every chain.
    for role in ("scanner", "viewer", "approver"):
        refused = ml_api["as_user"](_user("member", role)).get("/v1/audit/verify", params={"all": "1"})
        assert refused.status_code == 403, role
    system = ml_api["as_user"](_user("worker", "admin", system=True)).get("/v1/audit/verify", params={"all": "true"})
    assert {c["chain_id"] for c in system.json()["chains"]} == {
        f"project:{PROJECT}", f"run:{BASELINE}", f"project:{OTHER_PROJECT}", f"run:{FOREIGN}", "system",
    }

    # ``run=`` resolves the project through the run, not through the caller's argument.
    one = admin.get("/v1/audit/verify", params={"run": BASELINE, "project_id": OTHER_PROJECT})
    assert one.status_code == 200 and one.json()["chain_id"] == f"run:{BASELINE}"
    assert one.json()["verified"] is True and one.json()["count"] == 3 and one.json()["event_count"] == 3
    assert admin.get("/v1/audit/verify", params={"run": FOREIGN}).status_code == 403
    assert admin.get("/v1/audit/verify", params={"run": "run-missing"}).status_code == 404
    assert admin.get("/v1/audit/verify", params={"project_id": OTHER_PROJECT}).status_code == 403
    project = admin.get("/v1/audit/verify", params={"project_id": PROJECT})
    assert project.status_code == 200 and project.json()["chain_id"] == f"project:{PROJECT}"
    assert project.json()["verified"] is True and project.json()["count"] == 2

    # A tampered event breaks the chain at its sequence number.
    chain_file = writer._path(f"run:{BASELINE}")
    lines = chain_file.read_text().splitlines()
    second = json.loads(lines[1])
    second["detail"] = {"seeded": False}
    lines[1] = json.dumps(second)
    chain_file.write_text("\n".join(lines) + "\n")
    broken = admin.get("/v1/audit/verify", params={"run": BASELINE}).json()
    assert broken["verified"] is False and broken["broken_at"] == 2 and "hash mismatch" in broken["reason"]
    everything = {c["chain_id"]: c for c in admin.get("/v1/audit/verify", params={"all": "1"}).json()["chains"]}
    assert everything[f"run:{BASELINE}"]["verified"] is False
    assert everything[f"project:{PROJECT}"]["verified"] is True
