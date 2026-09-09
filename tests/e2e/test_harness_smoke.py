"""Smoke test of the shared e2e harness against the tree (register row G-TESTS; spec 22.5, 24, 26).

One session, one sqlite file, one tiny asset tree; every test below drives the
production code path it names and asserts on what that path left behind (rows,
audit events, artifacts, the campaign record), never on a stub:

1. the asset builder writes a tree the manifest verifier accepts;
2. ``register_bundled_model`` creates per-project ``Target`` rows
   (``<bundled_id>-<8 hex>``, ``value = bundled:<id>``, ``detail.status = available``);
3. the role gate refuses a viewer, a stranger and a cross-organisation admin
   before any audit row or Run exists;
4. an image campaign runs through the real sandbox child and reaches
   ``Run.status == "succeeded"`` with the spec 10.5 audit vocabulary on its chain
   and a child environment that carries no secret and no ``.env``;
5. a tabular campaign runs PGD (surrogate transfer) plus HopSkipJump with the
   benign noise control at every grid budget (spec 12.9, demo step 6), and a
   second tabular campaign runs HopSkipJump plus the control alone so the
   tabular path through the child is proven even while admission still refuses
   PGD by surrogate (see the module note on that defect);
6. ``redsim audit verify --all`` is clean, then names the tampered sequence
   number after one stored event is mutated;
7. the mocked Pythia gateway flips ``narrative_source`` between ``llm`` and
   ``rules`` (mock on; mock off; ``REDSIM_DISABLE_LLM=1``; a rejected narrative),
   observed in child mode because the writer runs in the worker parent.

Every item is stamped ``e2e`` by ``tests/e2e/conftest.py`` and skipped unless
``REDSIM_E2E`` is set::

    REDSIM_E2E=1 pytest -q -p no:cacheprovider -m e2e tests/e2e/test_harness_smoke.py

Heavy imports happen inside the tests, after the session fixtures have checked
the extras, so collection stays green without them.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

import pytest

from tests.e2e import harness as h

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.e2e.harness import E2EApp, E2EOrg, PythiaToggle

pytestmark = pytest.mark.e2e

MOCK_CHAT_URL = f"{h.MOCK_PYTHIA_BASE_URL}/v1/chat/completions"


# ---------------------------------------------------------------------------
# Helpers (read-only views over the harness database)
# ---------------------------------------------------------------------------


def _chain_actions(e2e_app: E2EApp, chain_id: str) -> list[tuple[str, bool]]:
    return [(str(ev["action"]), bool(ev["success"])) for ev in e2e_app.read_chain(chain_id)]


def _events(e2e_app: E2EApp, chain_id: str, action: str) -> list[dict[str, Any]]:
    return [ev for ev in e2e_app.read_chain(chain_id) if ev["action"] == action]


def _artifact_kinds(e2e_app: E2EApp, run_id: str) -> set[str]:
    from sqlalchemy import select

    from redsim.db.models import Artifact

    with e2e_app.session() as sess:
        rows = sess.execute(select(Artifact.kind).where(Artifact.run_id == run_id)).scalars().all()
    return {str(kind) for kind in rows}


def _run_row(e2e_app: E2EApp, run_id: str) -> dict[str, Any]:
    from redsim.db.models import Run

    with e2e_app.session() as sess:
        run = sess.get(Run, run_id)
        assert run is not None, f"Run {run_id} is missing"
        return {"target_id": run.target_id, "status": run.status, "scanner": run.scanner,
                "project_id": run.project_id}


def _campaign_row(e2e_app: E2EApp, run_id: str) -> dict[str, Any]:
    from sqlalchemy import MetaData, Table

    with e2e_app.session() as sess:
        table = Table("ml_campaigns", MetaData(), autoload_with=sess.get_bind())
        row = sess.execute(table.select().where(table.c.run_id == run_id)).mappings().one()
        return dict(row)


def _count_runs(e2e_app: E2EApp) -> int:
    from sqlalchemy import func, select

    from redsim.db.models import Run

    with e2e_app.session() as sess:
        return int(sess.execute(select(func.count()).select_from(Run)).scalar() or 0)


def _evasion_attack_ids(campaign: dict[str, Any]) -> set[str]:
    return {str(m["attack_id"]) for m in campaign["measurements"]
            if m.get("family") == "evasion" and m.get("attack_id")}


def _control_eps(campaign: dict[str, Any]) -> set[float]:
    """The budgets the benign noise control ran at. ``eps`` lives in ``Measurement.params`` (spec 5.7)."""
    out: set[float] = set()
    for m in campaign["measurements"]:
        if m.get("family") == "control":
            eps = (m.get("params") or {}).get("eps")
            if eps is not None:
                out.add(float(eps))
    return out


def _recommendations(campaign: dict[str, Any]) -> list[dict[str, Any]]:
    recs = campaign.get("recommendations")
    return list(recs) if isinstance(recs, list) else []


def _assert_no_secret(text: str) -> None:
    """The mock key is a placeholder, and even that must never reach a record, a chain or an artifact."""
    assert h.MOCK_PYTHIA_API_KEY not in text
    assert "Bearer pk_" not in text


# ---------------------------------------------------------------------------
# 1. Asset build
# ---------------------------------------------------------------------------


def test_asset_build_writes_a_verifiable_tree(e2e_assets: Any) -> None:
    from redsim.ml.assets.manifest import MANIFEST_NAME, AssetManifest, verify_manifest, verify_model_assets

    root = e2e_assets
    document = h.asset_manifest(root)
    manifest = AssetManifest.model_validate(document)
    assert set(manifest.models) == set(h.BUNDLED_IDS)
    assert verify_manifest(manifest, root) == [], "the builder's own verifier must accept its tree"
    for bundled_id in h.BUNDLED_IDS:
        problems = verify_model_assets(manifest, root, bundled_id)
        assert not problems, f"{bundled_id}: {problems}"
        entry = manifest.models[bundled_id]
        assert entry.fixture_only is False, "a fixture-only entry could never be registered (spec 5.5)"
        assert (root / entry.file.path).is_file()
    image, tabular = manifest.models[h.IMAGE_MODEL_ID], manifest.models[h.TABULAR_MODEL_ID]
    assert image.modality == "image" and tabular.modality == "tabular"
    assert image.dataset_id == h.IMAGE_DATASET_ID
    assert tabular.dataset_id == h.URL_DATASET_ID
    assert image.class_names == list(h.IMAGE_CLASS_NAMES)
    assert manifest.datasets[image.dataset_id].splits[image.dataset_split].n == h.N_IMAGES // 2
    assert tabular.surrogate is not None, "PGD on the tree ensemble needs the declared surrogate (spec 12.9)"
    assert tabular.gradients is False
    assert h.asset_dataset_ids(root) == {
        h.IMAGE_MODEL_ID: image.dataset_id, h.TABULAR_MODEL_ID: tabular.dataset_id,
    }
    assert (root / MANIFEST_NAME).is_file()


# ---------------------------------------------------------------------------
# 2. Bundled registration
# ---------------------------------------------------------------------------


def test_bundled_registration_creates_per_project_targets(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str],
) -> None:
    from redsim.api.errors import ALREADY_REGISTERED

    dataset_ids = h.asset_dataset_ids(e2e_app.assets_dir)
    manifest_models = h.asset_manifest(e2e_app.assets_dir)["models"]
    project_chain = e2e_app.read_chain(f"project:{e2e_org.project_id}")
    registrations = {
        ev["detail"].get("bundled_id"): ev for ev in project_chain
        if ev["action"] == "model.register" and ev["success"]
    }
    viewer = e2e_org.client("viewer")

    for bundled_id in h.BUNDLED_IDS:
        model_id = e2e_bundled[bundled_id]
        assert model_id != bundled_id, "the Target id is per project, never the registry id"
        assert re.fullmatch(rf"{re.escape(bundled_id)}-[0-9a-f]{{8}}", model_id), model_id

        row = h.registered_target(e2e_app, model_id)
        detail = row["detail"]
        assert row["project_id"] == e2e_org.project_id
        assert row["kind"] == "ml_model_artifact"
        assert row["value"] == f"bundled:{bundled_id}"
        assert row["verified"] is True
        assert detail["status"] == "available"
        assert detail["source"] == "bundled"
        assert detail["bundled_id"] == bundled_id
        assert detail["fixture_only"] is False
        assert detail["modality"] == manifest_models[bundled_id]["modality"]
        assert detail["manifest"]["dataset_id"] == dataset_ids[bundled_id]
        assert detail["manifest"]["status"] == "available"
        assert detail["manifest"]["sha256"] == manifest_models[bundled_id]["sha256"]
        # The weights were copied into the blob store byte for byte (digest-addressed).
        assert detail["blob"]["sha256"] == manifest_models[bundled_id]["sha256"]
        assert detail["blob"]["key"].startswith(f"ml/assets/bundled/{bundled_id}/")
        assert detail["registered_by"] == e2e_org.actor("remediator")

        # The model.register row preceded the Target and names the per-project id (spec 9.3 step 4).
        event = registrations.get(bundled_id)
        assert event is not None, f"no successful model.register row for {bundled_id}"
        assert event["detail"]["target_id"] == model_id
        assert event["detail"]["source"] == "bundled"
        assert event["actor"] == e2e_org.actor("remediator")

        # The catalog serves the row under its per-project id.
        shown = h.model_record(viewer, model_id)
        assert shown["id"] == model_id and shown["bundled_id"] == bundled_id
        assert shown["registered"] is True and shown["status"] == "available"
        assert shown["manifest"]["dataset_id"] == dataset_ids[bundled_id]

    listing = viewer.get("/v1/models", params={"project": e2e_org.project_id})
    assert listing.status_code == 200, listing.text
    rows = listing.json()["models"]
    registered = {row["bundled_id"]: row for row in rows if row["registered"]}
    assert set(registered) == set(h.BUNDLED_IDS)
    unregistered_bundled = {row["bundled_id"] for row in rows if not row["registered"] and row["source"] == "bundled"}
    assert not (unregistered_bundled & set(h.BUNDLED_IDS)), "a registered bundled model is listed once"
    assert "cifar10_smallcnn" not in {row["id"] for row in rows}, "CI fixtures are never catalog entries"

    # A second registration of the same bundled model in the same project is a typed 409.
    duplicate = e2e_org.client("remediator").post("/v1/models", json={
        "source": "bundled", "bundled_id": h.IMAGE_MODEL_ID, "project_id": e2e_org.project_id,
    })
    assert duplicate.status_code == 409, duplicate.text
    assert duplicate.json()["detail"]["code"] == ALREADY_REGISTERED
    assert duplicate.json()["detail"]["target_id"] == e2e_bundled[h.IMAGE_MODEL_ID]
    refused = [ev for ev in e2e_app.read_chain(f"project:{e2e_org.project_id}")
               if ev["action"] == "model.register" and not ev["success"]]
    assert refused and refused[-1]["detail"]["reason"] == ALREADY_REGISTERED


# ---------------------------------------------------------------------------
# 3. One role gate
# ---------------------------------------------------------------------------


def test_role_gate_refuses_before_any_row_or_audit_event(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str],
) -> None:
    model_id = e2e_bundled[h.IMAGE_MODEL_ID]
    project_chain = f"project:{e2e_org.project_id}"
    runs_before = _count_runs(e2e_app)
    chain_before = len(e2e_app.read_chain(project_chain))
    chains_before = set(e2e_app.chain_ids())

    # attack.run needs scanner or above (spec 7); viewer, stranger and the other org's admin are refused.
    for identity in ("viewer", "stranger", h.OUTSIDER):
        response = e2e_org.client(identity).post(f"/v1/models/{model_id}/attacks", json=h.image_campaign())
        assert response.status_code == 403, f"{identity}: {response.status_code} {response.text}"

    # model.register needs remediator or above: the scanner may launch campaigns but not register models.
    for identity in ("viewer", "scanner"):
        response = e2e_org.client(identity).post("/v1/models", json={
            "source": "bundled", "bundled_id": h.TABULAR_MODEL_ID, "project_id": e2e_org.project_id,
        })
        assert response.status_code == 403, f"{identity}: {response.status_code} {response.text}"

    # The gate sits in front of the admission service: nothing was written anywhere.
    assert _count_runs(e2e_app) == runs_before
    assert len(e2e_app.read_chain(project_chain)) == chain_before
    assert set(e2e_app.chain_ids()) == chains_before

    # A viewer may still read the catalog of its own project, and nothing of the other project.
    assert e2e_org.client("viewer").get(f"/v1/models/{model_id}").status_code == 200
    assert e2e_org.client(h.OUTSIDER).get(f"/v1/models/{model_id}").status_code == 403


# ---------------------------------------------------------------------------
# 4. Image campaign through the real child
# ---------------------------------------------------------------------------


def test_image_campaign_succeeds_in_the_real_sandbox_child(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    import redsim.ml.sandbox as sandbox_module

    model_id = e2e_bundled[h.IMAGE_MODEL_ID]
    child_envs: list[dict[str, str]] = []
    original_child_env = sandbox_module._ml_child_env

    def recording_child_env(*args: Any, **kwargs: Any) -> dict[str, str]:
        env = original_child_env(*args, **kwargs)
        child_envs.append(dict(env))
        return env

    monkeypatch.setattr(sandbox_module, "_ml_child_env", recording_child_env)

    with e2e_app.sandbox.use("child"):
        result = h.run_campaign_via_api(e2e_org.client("scanner"), model_id, h.image_campaign())

    assert result.status == "succeeded", f"run {result.run_id}: {result.run.get('stage_table')}"
    assert result.campaign is not None, result.campaign_error
    assert e2e_app.sandbox.calls[-1] == "child"
    campaign = result.campaign

    # -- the child saw a resolved asset directory and nothing secret ----------------------
    assert child_envs, "the campaign did not go through the sandbox child"
    env = child_envs[-1]
    assert env["REDSIM_ML_ASSETS_DIR"] == str(e2e_app.assets_dir.resolve())
    assert not [k for k in env if k.startswith(("PYTHIA_", "KAGGLE_", "AWS_"))]
    assert "REDSIM_DB_URL" not in env and "REDSIM_BLOB_FS_PATH" not in env and "REDSIM_CONFIG" not in env
    assert env.get("REDSIM_DISABLE_LLM") == "1"
    from pathlib import Path

    assert not Path(env["REDSIM_ENV_FILE"]).exists(), "the child's REDSIM_ENV_FILE must name an absent file"
    assert (h.REPO_ROOT / ".env").resolve() != Path(env["REDSIM_ENV_FILE"]).resolve()

    # -- the record is the child's, re-keyed to the platform run -------------------------
    assert campaign["run_id"] == result.run_id
    assert campaign["status"] == "succeeded"
    assert campaign["config"]["target_id"] == model_id
    assert campaign["config"]["modality"] == "image"
    assert campaign["config"]["target_snapshot"]["value"] == f"bundled:{h.IMAGE_MODEL_ID}"
    assert campaign["config"]["target_snapshot"]["detail"]["bundled_id"] == h.IMAGE_MODEL_ID
    assert "eps" not in campaign["config"]["attack_params"].get("pgd", {}), (
        "eps is grid-owned; a frozen default would make the child refuse the configuration")
    stages = set(campaign["stages_done"])
    assert {"load_target", "sample", "clean_eval", "attack:fgsm", "attack:pgd", "control", "score",
            "interpret", "report"} <= stages, sorted(stages)
    clean = [m for m in campaign["measurements"] if m["family"] == "clean"]
    assert len(clean) == 1 and clean[0]["n"] == h.image_campaign()["n_samples"]
    assert _evasion_attack_ids(campaign) == {"fgsm", "pgd"}
    assert _control_eps(campaign) == set(h.image_campaign()["eps_grid"]), "a control accompanies every eps"
    for rec in _recommendations(campaign):
        assert rec["narrative_source"] == "rules" and rec["narrative"] is None
        assert rec["validation"] == "not evaluated"
    assert campaign["provenance"]["model_sha256"] == h.registered_target(e2e_app, model_id)["detail"]["sha256"]
    assert campaign["project_id"] == e2e_org.project_id
    assert isinstance(campaign["findings"], list)
    _assert_no_secret(json.dumps(campaign))

    # -- rows name the per-project Target, not the registry id ---------------------------
    run_row = _run_row(e2e_app, result.run_id)
    assert run_row["target_id"] == model_id and run_row["scanner"] == "ml.campaign"
    campaign_row = _campaign_row(e2e_app, result.run_id)
    assert campaign_row["target_id"] == model_id and campaign_row["kind"] == "attack"
    assert campaign_row["score"] is not None or campaign_row["limitations"], "score or its unavailability"
    assert campaign_row["completed_at"] is not None
    assert result.stage_table["completeness"] == campaign["completeness"]
    assert result.stage_table["stages"]["report"]["status"] == "succeeded"
    assert result.stage_table["jobs"][result.job_ids[0]]["status"] == "succeeded"

    # -- artifacts and the spec 10.5 audit vocabulary --------------------------------------
    kinds = _artifact_kinds(e2e_app, result.run_id)
    assert {"ml.run_record", "ml.score", "report.md", "report.json", "report.html", "ml.curve"} <= kinds, kinds
    actions = _chain_actions(e2e_app, f"run:{result.run_id}")
    names = [name for name, _ok in actions]
    assert names[0] == "attack.run", "admission is audited before any Run/Job row exists (spec 10.5)"
    for expected in ("model.load", "attack.execute.fgsm", "attack.execute.pgd", "campaign.score",
                     "report.render", "job.complete"):
        assert (expected, True) in actions, f"{expected} missing or refused: {actions}"
    assert names[-1] == "job.complete"
    assert names.index("model.load") < names.index("attack.execute.fgsm") < names.index("campaign.score")
    admission = _events(e2e_app, f"run:{result.run_id}", "attack.run")[0]
    assert admission["actor"] == e2e_org.actor("scanner")
    assert admission["detail"]["target_id"] == model_id
    worker_rows = [ev for ev in e2e_app.read_chain(f"run:{result.run_id}") if ev["action"] == "job.complete"]
    assert worker_rows[-1]["actor"] == "worker:attack.run"
    assert worker_rows[-1]["detail"]["requested_by"] == e2e_org.actor("scanner")
    assert worker_rows[-1]["detail"]["status"] == "succeeded"
    _assert_no_secret(json.dumps(e2e_app.read_chain(f"run:{result.run_id}"), default=str))


# ---------------------------------------------------------------------------
# 5. Tabular campaign: PGD by surrogate transfer + HopSkipJump + noise control
# ---------------------------------------------------------------------------

#: The admission check that refuses PGD by surrogate transfer on a tabular model. The runner
#: (``redsim.ml.campaign._surrogate_for_white_box``) hands white-box adapters the declared
#: surrogate estimator and the PGD adapter declares ``surrogate_transfer`` + ``modality:tabular``,
#: but ``create_attack_campaign`` refuses first on ``manifest.gradients is False`` alone.
_PGD_SURROGATE_ADMISSION_DEFECT = (
    "product defect, not a harness problem: redsim/services/ml_campaigns.py:489-492 raises "
    "attack_requires_gradients for a white-box attack whenever the model manifest says gradients=false, "
    "without considering the declared surrogate (Target.detail.surrogate / detail.manifest.surrogate, "
    "MLModelManifest.surrogate) or the adapter's 'surrogate_transfer' capability (redsim/ml/attacks/pgd.py:59-61). "
    "The runner would run PGD by surrogate transfer and record it as such (redsim/ml/campaign.py:727-757, spec 12.9, "
    "demo step 6), and the service's own module docstring (lines 27-36) says such an attack is admitted. "
    "Until admission exempts surrogate-capable adapters when a surrogate is declared, this test fails here."
)


def _launch_or_diagnose(e2e_org: E2EOrg, model_id: str, body: dict[str, Any]) -> h.CampaignRun:
    """Launch through the API; turn the known admission refusal into a precise, attributed failure."""
    from redsim.api.errors import ATTACK_REQUIRES_GRADIENTS

    refused: h.CampaignLaunchRefused | None = None
    try:
        return h.run_campaign_via_api(e2e_org.client("scanner"), model_id, body)
    except h.CampaignLaunchRefused as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        if not (exc.status_code == 422 and detail.get("code") == ATTACK_REQUIRES_GRADIENTS
                and "pgd" in body["attack_ids"]):
            raise
        refused = exc
    pytest.fail(f"{refused}\n\n{_PGD_SURROGATE_ADMISSION_DEFECT}", pytrace=False)


def test_tabular_campaign_runs_pgd_hopskipjump_and_control(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str],
) -> None:
    model_id = e2e_bundled[h.TABULAR_MODEL_ID]
    # The registered row carries what admission needs to admit PGD by surrogate transfer.
    detail = h.registered_target(e2e_app, model_id)["detail"]
    assert detail["gradients"] is False and detail["surrogate"] is not None, detail.keys()
    assert detail["manifest"]["surrogate"]["sha256"] == detail["surrogate"]["sha256"]

    body = h.tabular_campaign()
    result = _launch_or_diagnose(e2e_org, model_id, body)

    assert result.status == "succeeded", f"run {result.run_id}: {result.run.get('stage_table')}"
    assert result.campaign is not None, result.campaign_error
    campaign = result.campaign
    assert campaign["config"]["modality"] == "tabular"
    assert campaign["config"]["attack_ids"] == ["pgd", "hopskipjump"]
    assert campaign["config"]["include_control"] is True
    stages = set(campaign["stages_done"])
    assert {"attack:pgd", "attack:hopskipjump", "control", "score", "report"} <= stages, sorted(stages)

    # Both attacks ran (neither is recorded not_run) and the control accompanied every eps.
    assert _evasion_attack_ids(campaign) == {"pgd", "hopskipjump"}
    not_run = [i for i in campaign["interpretation"] if str(i["id"]).startswith("i.attack.not_run.")]
    assert not not_run, [i["statement"] for i in not_run]
    assert _control_eps(campaign) == set(body["eps_grid"])
    control_rows = [m for m in campaign["measurements"] if m["family"] == "control"]
    assert all(m["n"] == body["n_samples"] for m in control_rows)

    # PGD ran on the declared surrogate and was measured on the real model (spec 12.9): the record says so.
    text = " ".join(campaign["limitations"]).lower()
    assert "surrogate" in text, campaign["limitations"]
    pgd_rows = [m for m in campaign["measurements"] if m.get("attack_id") == "pgd"]
    assert pgd_rows and all(m["n"] == body["n_samples"] for m in pgd_rows)
    hsj_rows = [m for m in campaign["measurements"] if m.get("attack_id") == "hopskipjump"]
    assert hsj_rows and all("queries_mean" in m for m in hsj_rows), "HopSkipJump rows carry the query count field"

    # Audit: one attack.execute row per attack, both successful; the admission names both ids.
    chain = f"run:{result.run_id}"
    actions = _chain_actions(e2e_app, chain)
    assert ("attack.execute.pgd", True) in actions and ("attack.execute.hopskipjump", True) in actions, actions
    assert _events(e2e_app, chain, "attack.run")[0]["detail"]["attack_ids"] == ["pgd", "hopskipjump"]
    assert _run_row(e2e_app, result.run_id)["target_id"] == model_id


def test_tabular_hopskipjump_and_control_run_in_the_real_sandbox_child(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str],
) -> None:
    """The tabular path through the child with the black-box attack alone.

    Independent of the PGD admission defect above: HopSkipJump needs no
    gradients, so this proves the tree ensemble loads in the child, the
    featurised rows are sampled from the bound split, the decision-based attack
    and the benign control run at every budget, and the record is scored,
    whatever admission says about white-box attacks on this model.
    """
    model_id = e2e_bundled[h.TABULAR_MODEL_ID]
    body = h.tabular_campaign(attack_ids=["hopskipjump"])
    body["attack_params"] = {"hopskipjump": dict(body["attack_params"]["hopskipjump"])}

    with e2e_app.sandbox.use("child"):
        result = h.run_campaign_via_api(e2e_org.client("scanner"), model_id, body)

    assert result.status == "succeeded", f"run {result.run_id}: {result.run.get('stage_table')}"
    assert result.campaign is not None, result.campaign_error
    assert e2e_app.sandbox.calls[-1] == "child"
    campaign = result.campaign
    assert campaign["config"]["modality"] == "tabular"
    assert campaign["config"]["target_id"] == model_id
    assert campaign["config"]["target_snapshot"]["value"] == f"bundled:{h.TABULAR_MODEL_ID}"
    assert campaign["config"]["dataset_id"] == h.URL_DATASET_ID
    stages = set(campaign["stages_done"])
    assert {"load_target", "sample", "clean_eval", "attack:hopskipjump", "control", "score", "interpret",
            "report"} <= stages, sorted(stages)
    assert _evasion_attack_ids(campaign) == {"hopskipjump"}
    not_run = [i for i in campaign["interpretation"] if str(i["id"]).startswith("i.attack.not_run.")]
    assert not not_run, [i["statement"] for i in not_run]
    assert _control_eps(campaign) == set(body["eps_grid"]), "a control accompanies every eps"
    clean = [m for m in campaign["measurements"] if m["family"] == "clean"]
    assert len(clean) == 1 and clean[0]["n"] == body["n_samples"]
    hsj_rows = [m for m in campaign["measurements"] if m.get("attack_id") == "hopskipjump"]
    assert hsj_rows and all(m["n"] == body["n_samples"] for m in hsj_rows)
    assert all("queries_mean" in m for m in hsj_rows), "HopSkipJump rows carry the query count field"
    assert campaign["provenance"]["model_sha256"] == h.registered_target(e2e_app, model_id)["detail"]["sha256"]

    chain = f"run:{result.run_id}"
    actions = _chain_actions(e2e_app, chain)
    assert ("attack.execute.hopskipjump", True) in actions and ("job.complete", True) in actions, actions
    assert _events(e2e_app, chain, "attack.run")[0]["detail"]["attack_ids"] == ["hopskipjump"]
    assert _run_row(e2e_app, result.run_id)["target_id"] == model_id
    assert _campaign_row(e2e_app, result.run_id)["modality"] == "tabular"
    _assert_no_secret(json.dumps(campaign))


# ---------------------------------------------------------------------------
# 6. Audit verification through the real CLI, then a tamper
# ---------------------------------------------------------------------------


def test_audit_verify_all_is_clean_then_breaks_at_the_tampered_seq(
    e2e_app: E2EApp,
    audit_verify_all: Callable[[], tuple[int, str]],
    tamper_audit_event: Callable[..., tuple[str, int]],
) -> None:
    from redsim.audit.chain import verify_chain

    chain_ids = e2e_app.chain_ids()
    assert any(cid.startswith("run:") for cid in chain_ids), "the campaigns above left run chains"

    code, output = audit_verify_all()
    assert code == 0, output
    assert "broken at seq=" not in output
    verified_lines = [line for line in output.splitlines() if "events verified" in line]
    assert len(verified_lines) == len(chain_ids), output
    for chain_id in chain_ids:
        assert f"chain {chain_id!r}" in output

    chain_id, seq = tamper_audit_event()
    assert chain_id.startswith("run:") and seq > 1

    in_process = verify_chain(e2e_app.read_chain(chain_id))
    assert in_process.verified is False and in_process.broken_at == seq

    code, output = audit_verify_all()
    assert code == 1, output
    assert f"broken at seq={seq}" in output, output
    broken_lines = [line for line in output.splitlines() if "broken at seq=" in line]
    assert len(broken_lines) == 1 and f"chain {chain_id!r}" in broken_lines[0], output
    assert len([line for line in output.splitlines() if "events verified" in line]) == len(chain_ids) - 1


# ---------------------------------------------------------------------------
# 7. Mocked Pythia: narrative_source flips between llm and rules
# ---------------------------------------------------------------------------


def _narrated_campaign(e2e_org: E2EOrg, model_id: str) -> h.CampaignRun:
    result = h.run_campaign_via_api(
        e2e_org.client("scanner"), model_id, h.image_campaign(llm_narrative=True),
    )
    assert result.status == "succeeded", f"run {result.run_id}: {result.run.get('stage_table')}"
    assert result.campaign is not None, result.campaign_error
    return result


def test_mocked_narrative_flips_narrative_source(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], pythia: PythiaToggle,
) -> None:
    from sqlalchemy import select

    from redsim.db.models import LLMUsage

    model_id = e2e_bundled[h.IMAGE_MODEL_ID]
    assert e2e_app.sandbox.mode == "child", "the writer runs in the parent; the mock must show in child mode"

    # -- mock on: the parent narrates and the record says llm ---------------------------------
    with pythia:
        result = _narrated_campaign(e2e_org, model_id)
    assert e2e_app.sandbox.calls[-1] == "child"
    campaign = result.campaign
    assert campaign is not None
    recs = _recommendations(campaign)
    assert recs, "the rule layer produced no candidate on this run; nothing could be narrated"
    assert {rec["narrative_source"] for rec in recs} == {"llm"}
    for rec in recs:
        # ``split_by_recommendation`` strips the ``[r.X]`` marker, so the stored prose is the
        # paragraph body; the canned writer's fixed sentence proves it is the mock's text.
        assert rec["narrative"], rec
        assert "candidate recommendation that has not been evaluated" in rec["narrative"]
        assert rec["validation"] == "not evaluated"
    assert len(pythia.requests) == 1, pythia.requests
    request = pythia.requests[0]
    assert request["method"] == "POST" and request["url"] == MOCK_CHAT_URL
    assert request["headers"]["authorization"] == f"Bearer {h.MOCK_PYTHIA_API_KEY}"
    assert request["json"]["model"] == h.MOCK_PYTHIA_MODEL
    payload = pythia.last_payload() or ""
    assert "RANKED CANDIDATE RECOMMENDATIONS" in payload
    for rec in recs:
        assert f"[{rec['id']}]" in payload
    assert campaign["provenance"]["llm"]["model"] == h.MOCK_PYTHIA_MODEL
    assert campaign["provenance"]["llm"]["gateway"] == "pythia"
    assert "api_key" not in campaign["provenance"]["llm"]
    assert any("LLM narrative generated via Pythia" in lim for lim in campaign["limitations"])
    _assert_no_secret(json.dumps(campaign))

    chain = f"run:{result.run_id}"
    harden = _events(e2e_app, chain, "harden.execute")
    assert harden and harden[-1]["success"] is True
    detail = harden[-1]["detail"]
    assert detail["llm_used"] is True and detail["narrative_source"] == "llm"
    assert detail["llm_requested"] is True and detail["skipped_reason"] is None
    assert re.fullmatch(r"[0-9a-f]{64}", str(detail["prompt_sha256"]))
    assert re.fullmatch(r"[0-9a-f]{64}", str(detail["completion_sha256"]))
    _assert_no_secret(json.dumps(e2e_app.read_chain(chain), default=str))
    assert {"ml.harden.prompt", "ml.harden.completion", "ml.harden.narrative"} <= _artifact_kinds(
        e2e_app, result.run_id)
    with e2e_app.session() as sess:
        usage = sess.execute(select(LLMUsage).where(LLMUsage.run_id == result.run_id)).scalars().all()
    assert len(usage) == 1 and usage[0].task == "ml.harden_narrative" and usage[0].model == h.MOCK_PYTHIA_MODEL

    # -- mock off: the same request degrades to rules with the configuration gap named ---------
    calls_before = len(pythia.requests)
    result = _narrated_campaign(e2e_org, model_id)
    campaign = result.campaign
    assert campaign is not None
    recs = _recommendations(campaign)
    assert recs and {rec["narrative_source"] for rec in recs} == {"rules"}
    assert all(rec["narrative"] is None for rec in recs)
    assert len(pythia.requests) == calls_before, "no gateway call without configuration"
    assert any("not configured" in lim for lim in campaign["limitations"]), campaign["limitations"]
    assert campaign["provenance"]["llm"] is None
    harden = _events(e2e_app, f"run:{result.run_id}", "harden.execute")
    assert harden and harden[-1]["detail"]["llm_used"] is False
    assert "not configured" in str(harden[-1]["detail"]["skipped_reason"])

    # -- mock on but REDSIM_DISABLE_LLM=1 (the compose worker default): rules, no call ----------
    pythia.on()
    pythia.disable_llm(True)
    try:
        result = _narrated_campaign(e2e_org, model_id)
    finally:
        pythia.disable_llm(False)
        pythia.off()
    campaign = result.campaign
    assert campaign is not None
    recs = _recommendations(campaign)
    assert recs and {rec["narrative_source"] for rec in recs} == {"rules"}
    assert len(pythia.requests) == 0, "REDSIM_DISABLE_LLM=1 must stop the call before the transport"
    assert any("REDSIM_DISABLE_LLM" in lim for lim in campaign["limitations"]), campaign["limitations"]

    # -- mock on with a narrative that invents a number: the post-check rejects it -------------
    pythia.on(narrative="[r.R0] The MRI improves by 42 percent after this candidate.")
    try:
        result = _narrated_campaign(e2e_org, model_id)
    finally:
        pythia.off()
    campaign = result.campaign
    assert campaign is not None
    recs = _recommendations(campaign)
    assert recs and {rec["narrative_source"] for rec in recs} == {"rules"}
    assert len(pythia.requests) == 1, "the gateway was called once and its answer was refused"
    harden = _events(e2e_app, f"run:{result.run_id}", "harden.execute")
    assert harden and harden[-1]["detail"]["llm_used"] is False
    assert "rejected by post-check" in str(harden[-1]["detail"]["skipped_reason"])
    assert harden[-1]["detail"]["completion_sha256"] is not None, "the refused completion is still digested"
    assert any("rejected by post-check" in lim for lim in campaign["limitations"]), campaign["limitations"]
