"""Phase B attacks and training defenses through the e2e harness (plan 12 wave B4, TESTS_DOCS-10, ATTACKS_HARDEN-21/-23).

Four evidence tests over the real API, the real admission service, the eager
Celery task body and the real sandbox child:

1. ``test_norm_tags_are_enforced_at_admission``: the attack norm declarations
   (``norms`` / ``norm:<n>`` tags, ATTACKS_HARDEN-03) gate admission: FGSM under an
   L2 grid and Carlini-Wagner L2 or DeepFool under the L-inf grid are
   ``422 params_out_of_range`` on ``norm`` naming the adapter's norms and the
   attacks that do take the campaign norm; the refusal writes a ``success=False``
   ``attack.run`` row and creates no ``Run``.
2. ``test_l2_campaign_minimal_norm_rows_and_control``: PGD, CW-L2 and DeepFool on
   the L2 grid ``{0.25, 0.5, 1.0}``: the minimal-norm attacks run once and are
   thresholded per grid eps (spec 12.3, 15.1), so every eps has a row whose flips
   are monotone in the budget, the benign noise control stays inside the L2 ball
   at every eps (spec 12.4), and every row carries its denominators.
3. ``test_zoo_on_url_trees_keeps_frozen_features``: the score-based black-box ZOO
   attack on the bundled tabular ensemble records query counts and the
   realizability caveat, and the adversarial slice it left behind holds every
   frozen URL feature at its clean value (spec 12.9).
4. ``test_training_defense_verify_registers_a_derived_target``: a verify with
   ``adversarial_training`` and one with ``defensive_distillation`` (tiny budgets)
   admitted as ``kind: training`` defenses and run through the sandbox child. On a
   tree where the child can train, the ``defense_apply`` stage is in the stage
   table, a derived ``Target`` is registered with ``derived_from`` lineage and
   validated, the ``MeasuredDelta`` is attached to the recommendation naming the
   defense (its sign is not asserted) and ``verify.execute`` names the derived
   digest and the training budget. On ``cb1e559`` the child cannot train
   (``D_TRAIN_SLICE`` below): the honest failure state is asserted and the test
   fails with that attribution rather than a weakened assertion.
5. ``test_training_defenses_are_unavailable_for_the_tabular_tree_ensemble``: the
   register ATTACKS_HARDEN-20 statement on the real bundled ``url_trees`` target
   (a typed ``TrainingUnavailable``, never a run), and the catalog rows that say so.

The shared tree's ``vehicles_cnn`` is a one-epoch CNN that predicts one class for
every image (8 of 24 clean-correct, below the finding floor of 10), so no verify
can start from it. Test 4 therefore builds a second tiny tree with the **real
builder** (``build_tiny_assets(epochs=300)``, a memorising ``small_cnn``) plus a
bundled training slice written with ``redsim.ml.assets.datasets.write_train_slice``,
registers that ``vehicles_cnn`` into the *other* organisation's project through
``register_bundled_model`` (a throwaway blob store, so the shared blob is never
overwritten) and points ``REDSIM_ML_ASSETS_DIR`` at the tree only while its own
campaigns run. Nothing measured on either tree is a demo result.

Product defects found on ``cb1e559`` (see :data:`DEFECTS`):

* ``D_TRAIN_SLICE``: no target exposes ``train_sample`` and no bundled training
  slice is wired into ``build-assets`` or the bundled image target, so
  ``apply_training_defense`` raises ``TrainingDefenseUnavailable`` inside the
  verify child for every image target; ``campaign._apply_defense`` does not catch
  it, so the run fails instead of recording the defense as unavailable with the
  score withheld. No derived target and no measured delta can exist on this tree.

Run with::

    REDSIM_E2E=1 pytest -q -p no:cacheprovider -m e2e tests/e2e/test_ml_attacks_harden.py

The sandbox child inherits ``PYTHONPATH``; put the tree under test first on it
when the interpreter's editable install points at another checkout.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from tests.e2e import harness as h

if TYPE_CHECKING:
    from fastapi.testclient import TestClient

    from tests.e2e.harness import E2EApp, E2EOrg

pytestmark = pytest.mark.e2e

SUBSCORE_KEYS = ("S_acc", "S_asr", "S_eps", "S_conf", "S_expl")
_READINESS_RE = re.compile(
    r"\b(readiness|ready|certif\w*|deploy\w*|fielding|hardened|safe|safety|proven|validated|guaranteed)\b",
    re.IGNORECASE,
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

L2_GRID = [0.25, 0.5, 1.0]
L2_REFERENCE = 0.5
L2_ATTACKS = ["pgd", "cw_l2", "deepfool"]
MINIMAL_NORM_ATTACKS = ("cw_l2", "deepfool")
L2_PARAMS: dict[str, dict[str, Any]] = {
    "pgd": {"max_iter": 3},
    "cw_l2": {"binary_search_steps": 2, "max_iter": 5},
    "deepfool": {"max_iter": 5},
}
ZOO_PARAMS: dict[str, Any] = {"max_iter": 2, "nb_parallel": 4, "binary_search_steps": 1}
ZOO_N = 10
#: Epochs of the real ``small_cnn`` recipe (Adam 1e-3, one batch per epoch on 48 images) that memorise the slice.
MEMORISE_EPOCHS = 300
#: The whole 24-image evaluation split of the tiny tree.
N_EVAL = h.N_IMAGES // 2
FINDING_THRESHOLD = 0.2
#: Tiny, bounded training budgets (spec 3.3, 12.8): the verify child must finish in seconds on a laptop CPU.
ADVERSARIAL_TRAINING_PARAMS: dict[str, Any] = {"epochs": 1, "train_n": 32, "batch_size": 16, "pgd_iters": 1,
                                               "wall_budget_s": 60}
DISTILLATION_PARAMS: dict[str, Any] = {"epochs": 1, "train_n": 32, "batch_size": 16, "temperature": 10,
                                       "wall_budget_s": 60}

DEFECTS: dict[str, str] = {
    "D_TRAIN_SLICE": (
        "No target exposes the train_sample(n, seed) accessor redsim/ml/harden/apply.py:421-434 (load_train_slice) "
        "requires when no train_slice is passed: `grep -rn train_sample redsim/` finds only harden/apply.py. "
        "(On the rebased tree redsim/ml/campaign.py:_apply_defense catches the typed TrainingDefenseUnavailable and "
        "records the defense as unavailable with the score withheld, so the verify Run now succeeds without a "
        "defense_apply stage, a derived target or a MeasuredDelta; the honest shape is asserted below, the root "
        "cause is unchanged.) "
        "redsim/ml/assets/datasets.py:1485-1542 ships write_train_slice / TrainSliceOptions ('wiring into build.py "
        "is a follow-up in that file') but redsim/ml/assets/build.py:310-361 build_cnn_asset writes no training "
        "slice and redsim/ml/targets/bundled.py BundledImageTarget reads none (ATTACKS_HARDEN-11), so "
        "apply_training_defense raises TrainingDefenseUnavailable(NO_TRAIN_SLICE_REASON, infeasible=False) inside the "
        "verify child for every image target. redsim/ml/campaign.py:333-374 _apply_defense catches only an "
        "unimportable module or a missing hook as 'unavailable'; the raised TrainingDefenseUnavailable propagates, "
        "the child returns a failed partial record and the verify Run fails at the defense_apply stage instead of "
        "recording the defense as unavailable with the score withheld (the path services/ml_campaigns.py:95-97 "
        "documents). Consequently no derived Target with derived_from lineage is registered "
        "(workers/tasks/ml_campaign.py:1210-1351 is never reached with weights) and no MeasuredDelta exists "
        "(ATTACKS_HARDEN-13, -18; spec 15.6, 16.4, 26.3 item 15)."
    ),
    "D_RUNNER_NORM": (
        "redsim/ml/campaign.py:376-383 _resolve_attacks refuses every adapter without a `norm_l2` parameter under an "
        "L2 campaign ('supports the L-inf norm only; the campaign norm is l2') instead of asking "
        "redsim.ml.attacks.attack_supports_norm (the adapter's `norms` declaration, ATTACKS_HARDEN-03) the way "
        "services/ml_campaigns.py:964-979 does at admission. cw_l2 and deepfool declare norms={'l2'} and take no eps, "
        "so admission admits them under the L2 grid and the sandbox child then refuses the whole campaign "
        "(AttackNotApplicable raised before any stage), leaving a failed Run with no measurement: the two "
        "minimal-norm attacks can never run through the campaign frame under the only norm they support "
        "(ATTACKS_HARDEN-01, -02; spec 12.3 minimal-norm paragraph)."
    ),
    "D_DEFENSES_PHASE": (
        "redsim/api/v1/defenses.py:24-34 projects every catalog row with a hard-coded phase 'A' and status "
        "'available', so the two kind 'training' rows whose catalog phase is 'B' (redsim/ml/defenses.py:1028, "
        ":1059) are served as Phase A; the served phase should be the row's own."
    ),
}


def _quiet(_: str) -> None:
    return None


def _fail(defect: str, observed: str) -> None:
    pytest.fail(f"{observed}\n\nproduct defect, not a harness problem [{defect}]: {DEFECTS[defect]}", pytrace=False)


# ---------------------------------------------------------------------------
# Read-only helpers
# ---------------------------------------------------------------------------


def _eps_tag(eps: float) -> str:
    return f"eps{float(eps):g}"


def _by_id(campaign: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = campaign["measurements"]
    out = {str(m["id"]): m for m in rows}
    assert len(out) == len(rows), "measurement ids are unique within a run"
    return out


def _assert_counts(row: dict[str, Any], *, n: int) -> None:
    """Spec 14.2 / 26.2 item 7: ``k / n`` and per-class counts on one row."""
    assert row["n"] == n, row["id"]
    assert isinstance(row["n_correct"], int) and 0 <= row["n_correct"] <= row["n"], row
    assert row["accuracy"] == pytest.approx(row["n_correct"] / row["n"]), row["id"]
    per_class = row["per_class"]
    assert isinstance(per_class, dict) and per_class, f"{row['id']} has no per-class counts"
    assert sum(c["n"] for c in per_class.values()) == row["n"], row["id"]
    assert sum(c["n_correct"] for c in per_class.values()) == row["n_correct"], row["id"]


def _assert_asr(row: dict[str, Any], clean: dict[str, Any]) -> None:
    assert row["n_clean_correct"] == clean["n_correct"], row["id"]
    if clean["n_correct"] > 0:
        assert isinstance(row["n_flipped_from_clean"], int) and 0 <= row["n_flipped_from_clean"] <= clean["n_correct"]
        assert row["attack_success_rate"] == pytest.approx(row["n_flipped_from_clean"] / clean["n_correct"]), row["id"]
    else:
        assert row["attack_success_rate"] is None, "a zero denominator is 'not computed', never 0% (spec 14.2)"


def _artifact_rows(client: TestClient, run_id: str) -> dict[str, dict[str, Any]]:
    response = client.get(f"/v1/runs/{run_id}/artifacts")
    assert response.status_code == 200, response.text
    rows = response.json()["artifacts"]
    return {str(row["id"]): row for row in rows}


def _download(client: TestClient, row: dict[str, Any]) -> bytes:
    response = client.get(f"/v1/artifacts/{row['id']}")
    assert response.status_code == 200, (row["kind"], response.status_code, response.text[:200])
    data = response.content
    assert hashlib.sha256(data).hexdigest() == row["sha256"], f"{row['kind']}: bytes differ from Artifact.sha256"
    return data


def _events(e2e_app: E2EApp, chain_id: str, action: str) -> list[dict[str, Any]]:
    return [ev for ev in e2e_app.read_chain(chain_id) if ev["action"] == action]


def _actions(e2e_app: E2EApp, chain_id: str) -> list[str]:
    return [str(ev["action"]) for ev in e2e_app.read_chain(chain_id)]


def _campaign_row(e2e_app: E2EApp, run_id: str) -> dict[str, Any]:
    from sqlalchemy import MetaData, Table

    with e2e_app.session() as sess:
        table = Table("ml_campaigns", MetaData(), autoload_with=sess.get_bind())
        return dict(sess.execute(table.select().where(table.c.run_id == run_id)).mappings().one())


def _run_count(e2e_app: E2EApp) -> int:
    from sqlalchemy import func, select

    from redsim.db.models import Run

    with e2e_app.session() as sess:
        return int(sess.execute(select(func.count()).select_from(Run)).scalar() or 0)


def _job_detail(e2e_app: E2EApp, job_id: str) -> dict[str, Any]:
    from redsim.db.models import Job

    with e2e_app.session() as sess:
        job = sess.get(Job, job_id)
        assert job is not None, job_id
        return {"type": job.type, "status": job.status, "detail": dict(job.detail or {})}


def _derived_targets(e2e_app: E2EApp, project_id: str) -> list[dict[str, Any]]:
    from sqlalchemy import select

    from redsim.db.models import Target

    with e2e_app.session() as sess:
        rows = sess.execute(select(Target).where(Target.project_id == project_id)).scalars().all()
        return [{"id": str(r.id), "kind": str(r.kind), "value": str(r.value), "detail": dict(r.detail or {})}
                for r in rows if isinstance(r.detail, dict) and r.detail.get("source") == "derived"]


def _finding(client: TestClient, finding_id: str) -> dict[str, Any]:
    response = client.get(f"/v1/findings/{finding_id}")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _recs(detail: dict[str, Any]) -> list[dict[str, Any]]:
    recs = detail.get("recommendations")
    return list(recs) if isinstance(recs, list) else []


def _defense_ids(rec: dict[str, Any]) -> set[str]:
    from redsim.ml.schema import CandidateRecommendation
    from redsim.services.ml_campaigns import recommendation_defense_ids

    return recommendation_defense_ids(CandidateRecommendation.model_validate(rec))


def _assert_score_state(campaign: dict[str, Any]) -> bool:
    """Spec 15.4 / 26.3 item 13: ``mri`` never without all five subscores; returns True for a complete MRI."""
    from redsim.ml.schema import contains_banned_score_word, grade_for_mri

    score = campaign["score"]
    if score is None:
        status = campaign["score_status"]
        assert status is not None and status["state"] == "unavailable" and status["reason"], status
        assert campaign["completeness"] == "partial"
        return False
    absent = [key for key in SUBSCORE_KEYS if score["subscores"].get(key) is None]
    if score["mri"] is None:
        assert absent and score["completeness"] == "partial" and score["missing"], score
        assert score["grade"] is None and score["reading"] is None
        return False
    assert not absent and score["completeness"] == "complete" and score["missing"] == []
    assert isinstance(score["mri"], int) and 0 <= score["mri"] <= 100 and score["grade"] == grade_for_mri(score["mri"])
    assert not contains_banned_score_word(score["reading"]) and not _READINESS_RE.search(score["reading"])
    return True


@contextlib.contextmanager
def _assets_dir(root: Path) -> Iterator[None]:
    """Point ``REDSIM_ML_ASSETS_DIR`` (this process and the sandbox child it spawns) at ``root`` for a block.

    The bundled target instances cache their manifest entry on load; they are unloaded on both sides of the
    block so nothing from one tree is served against the other.
    """
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("REDSIM_ML_ASSETS_DIR", str(root))
        h.unload_bundled_targets()
        try:
            yield
        finally:
            h.unload_bundled_targets()


# ---------------------------------------------------------------------------
# A second tiny tree: a memorising small_cnn with a bundled training slice
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def memorising_tree(e2e_app: E2EApp, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """``build_tiny_assets(epochs=300)`` into its own root, plus ``write_train_slice`` on the training split.

    A precondition of the verify evidence, not a product claim: the memorising CNN clears the finding floor on
    the tiny slice so a Finding can exist; the shared one-epoch tree's cannot (asserted in
    ``test_ml_verify_upload_reports.py``).
    """
    from redsim.ml.assets import datasets as ds
    from redsim.ml.assets.build import dataset_dir
    from redsim.ml.assets.manifest import MANIFEST_NAME, AssetManifest, verify_model_assets, write_manifest
    from redsim.ml.scoring import MIN_CLEAN_CORRECT_FOR_FINDING

    del e2e_app  # ordering only: the harness engine exists before a second tree is built
    root = tmp_path_factory.mktemp("e2e-harden-assets")
    h.build_tiny_assets(root, epochs=MEMORISE_EPOCHS)
    manifest_path = root / MANIFEST_NAME
    manifest = AssetManifest.model_validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    entry = manifest.datasets[h.IMAGE_DATASET_ID]
    data = h.synthetic_images()
    slice_split, split_entry = ds.write_train_slice(
        data.train, dataset_dir(root, entry) / ds.TRAIN_SLICE_NAME, root, n=h.N_IMAGES, seed=0,
        exclude_indices=data.eval.indices,
    )
    entry.splits[split_entry.name] = split_entry
    write_manifest(manifest, manifest_path)
    reparsed = AssetManifest.model_validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    for model_id in reparsed.models:
        problems = verify_model_assets(reparsed, root, model_id)
        assert not problems, f"{model_id}: {list(problems.model) + list(problems.dataset)}"
    model = reparsed.models[h.IMAGE_MODEL_ID]
    assert model.clean_accuracy is not None
    clean_correct = round(model.clean_accuracy.value * model.clean_accuracy.n)
    if clean_correct < MIN_CLEAN_CORRECT_FOR_FINDING:
        pytest.fail(f"harness precondition: the {MEMORISE_EPOCHS}-epoch small_cnn reached only {clean_correct}/"
                    f"{model.clean_accuracy.n} clean-correct on the tiny slice, below the finding floor "
                    f"{MIN_CLEAN_CORRECT_FOR_FINDING}; raise MEMORISE_EPOCHS")
    return {"root": root, "clean_correct": clean_correct, "n_eval": model.clean_accuracy.n,
            "model_sha256": model.sha256, "train_slice": split_entry.name, "train_slice_n": slice_split.n}


@pytest.fixture(scope="module")
def memorising_model(e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str],
                     memorising_tree: dict[str, Any], tmp_path_factory: pytest.TempPathFactory) -> str:
    """The memorising ``vehicles_cnn`` registered into the other organisation's project (outsider = its admin)."""
    from redsim.services.ml_models import register_bundled_model
    from redsim.storage.blobs import FilesystemBlobStore

    del e2e_bundled  # ordering: the shared registrations precede this one
    blobs = tmp_path_factory.mktemp("e2e-harden-blobs")
    with _assets_dir(memorising_tree["root"]), e2e_app.session() as sess:
        target = register_bundled_model(
            sess, e2e_org.other_project_id, h.IMAGE_MODEL_ID, e2e_org.actor(h.OUTSIDER),
            blob_store=FilesystemBlobStore(blobs), assets_root=memorising_tree["root"],
        )
        model_id = str(target.id)
    stored = h.registered_target(e2e_app, model_id)
    assert stored["project_id"] == e2e_org.other_project_id and stored["detail"]["sha256"] == memorising_tree["model_sha256"]
    assert stored["detail"]["gradients"] is True and stored["detail"]["modality"] == "image"
    return model_id


@pytest.fixture(scope="module")
def finding_run(e2e_org: E2EOrg, memorising_model: str, memorising_tree: dict[str, Any]) -> h.CampaignRun:
    """FGSM + PGD (L-inf, the whole 24-image slice) on the memorising model: the baseline the verifies pair with."""
    body = h.image_campaign(n_samples=N_EVAL, finding_asr_threshold=FINDING_THRESHOLD)
    with _assets_dir(memorising_tree["root"]):
        result = h.run_campaign_via_api(e2e_org.client(h.OUTSIDER), memorising_model, body,
                                        project_id=e2e_org.other_project_id, timeout_s=120.0)
    assert result.status == "succeeded", f"run {result.run_id}: {result.stage_table}"
    assert result.campaign is not None, result.campaign_error
    clean = next(m for m in result.campaign["measurements"] if m["family"] == "clean")
    if not result.findings:
        asr = {m["id"]: m.get("attack_success_rate") for m in result.campaign["measurements"] if m["family"] == "evasion"}
        pytest.fail(f"harness precondition: the memorising model produced no finding (clean {clean['n_correct']}/"
                    f"{clean['n']}, ASR by row {asr}, threshold {FINDING_THRESHOLD}); nothing to verify")
    return result


# ---------------------------------------------------------------------------
# 1. Norm declarations gate admission (ATTACKS_HARDEN-03; spec 12.3, 17.3)
# ---------------------------------------------------------------------------


def test_norm_tags_are_enforced_at_admission(e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str]) -> None:
    from redsim.api.errors import PARAMS_OUT_OF_RANGE
    from redsim.ml.attacks import attack_capabilities, attack_norms, get_attack

    model_id = e2e_bundled[h.IMAGE_MODEL_ID]
    scanner = e2e_org.client("scanner")
    project_chain = f"project:{e2e_org.project_id}"

    # The declarations the admission reads: minimal-norm L2 attacks carry norm:l2 only, FGSM norm:linf only, PGD both.
    assert attack_norms(get_attack("cw_l2")) == frozenset({"l2"}) == attack_norms(get_attack("deepfool"))
    assert attack_norms(get_attack("fgsm")) == frozenset({"linf"})
    assert attack_norms(get_attack("pgd")) == frozenset({"linf", "l2"})
    for attack_id in MINIMAL_NORM_ATTACKS:
        tags = attack_capabilities(get_attack(attack_id))
        assert {"white_box", "minimal_norm", "norm:l2", "modality:image", "family:evasion"} <= tags, sorted(tags)
        assert "norm:linf" not in tags and "takes_eps" not in tags
    assert {"black_box", "score_based", "minimal_norm", "modality:tabular", "norm:linf", "norm:l2"} <= attack_capabilities(
        get_attack("zoo"))
    catalog = scanner.get("/v1/attacks")
    assert catalog.status_code == 200, catalog.text
    listed = {row["id"]: row for row in catalog.json()["attacks"]}
    for attack_id in ("cw_l2", "deepfool", "zoo"):
        assert listed[attack_id]["status"] == "available" and listed[attack_id]["phase"] == "B", listed.get(attack_id)

    def refused(body: dict[str, Any]) -> dict[str, Any]:
        runs_before = _run_count(e2e_app)
        refusals_before = len([ev for ev in _events(e2e_app, project_chain, "attack.run") if not ev["success"]])
        response = scanner.post(f"/v1/models/{model_id}/attacks", json=body)
        assert response.status_code == 422, response.text
        detail = response.json()["detail"]
        assert detail["code"] == PARAMS_OUT_OF_RANGE
        # Spec 10.5 / 26.5 item 22: a refused admission is a success=False row; no Run, no Job exists for it.
        assert _run_count(e2e_app) == runs_before
        refusals = [ev for ev in _events(e2e_app, project_chain, "attack.run") if not ev["success"]]
        assert len(refusals) == refusals_before + 1
        assert refusals[-1]["detail"]["code"] == PARAMS_OUT_OF_RANGE and refusals[-1]["detail"]["refused"] is True
        assert refusals[-1]["detail"]["attack_ids"] == body["attack_ids"]
        assert refusals[-1]["actor"] == e2e_org.actor("scanner")
        return dict(detail)

    # FGSM has no L2 form: under the L2 grid it is refused on ``norm`` with the attacks that do take L2 listed.
    detail = refused(h.image_campaign(attack_ids=["fgsm", "pgd"], norm="l2", eps_grid=L2_GRID, reference_eps=L2_REFERENCE))
    assert detail["field"] == "norm" and detail["reasons"] == ["fgsm declares no norm_l2 parameter"]
    assert "'fgsm' supports the L-inf norm only" in detail["message"]
    for capable in ("pgd", "cw_l2", "deepfool"):
        assert f"'{capable}'" in detail["message"], detail["message"]
    # CW-L2 and DeepFool are L2-only: an L-inf campaign (the default norm) may not name them.
    for attack_id in MINIMAL_NORM_ATTACKS:
        detail = refused(h.image_campaign(attack_ids=[attack_id, "pgd"], attack_params={"pgd": {"max_iter": 3}}))
        assert detail["field"] == "norm"
        assert detail["reasons"] == [f"{attack_id} supports norms ['l2'], not 'linf'"], detail["reasons"]
        assert f"attack '{attack_id}' supports the L2 norm only" in detail["message"]
    detail = refused(h.image_campaign(attack_ids=["cw_l2"], attack_params={}, norm="linf"))
    assert detail["field"] == "norm" and "'fgsm'" in detail["message"] and "'pgd'" in detail["message"]
    # The benign control is never an attack: naming it in the set is refused on ``attack_ids`` (spec 12.4).
    response = scanner.post(f"/v1/models/{model_id}/attacks",
                            json=h.image_campaign(attack_ids=["fgsm", "noise_control"], attack_params={}))
    assert response.status_code == 422 and response.json()["detail"]["field"] == "attack_ids", response.text


# ---------------------------------------------------------------------------
# 2. L2 campaign: minimal-norm attacks thresholded per eps, the control inside the ball (spec 12.3, 12.4, 15.1)
# ---------------------------------------------------------------------------


def test_l2_campaign_minimal_norm_rows_and_control(
    e2e_app: E2EApp, e2e_org: E2EOrg, memorising_model: str, memorising_tree: dict[str, Any],
) -> None:
    from redsim.ml.attacks import MINIMAL_NORM_NOTE
    from redsim.services.ml_campaigns import BUDGET_LABELS

    body = h.image_campaign(attack_ids=list(L2_ATTACKS), attack_params=L2_PARAMS, norm="l2", eps_grid=L2_GRID,
                            reference_eps=L2_REFERENCE)
    n = body["n_samples"]
    with _assets_dir(memorising_tree["root"]):
        result = h.run_campaign_via_api(e2e_org.client(h.OUTSIDER), memorising_model, body,
                                        project_id=e2e_org.other_project_id, timeout_s=180.0)
    # Admission (attack_supports_norm) admitted cw_l2 and deepfool under L2: the run exists and reached the child.
    admitted = _events(e2e_app, f"run:{result.run_id}", "attack.run")
    assert len(admitted) == 1 and admitted[0]["success"] is True and admitted[0]["detail"]["norm"] == "l2"
    if result.status != "succeeded":
        error = str(result.stage_table.get("error") or "")
        if "supports the L-inf norm only" in error and "the campaign norm is 'l2'" in error:
            # The honest failure state: a failed Run, no measurement, the refused attack named on its audit row.
            assert result.stage_table["completeness"] == "partial" and result.stage_table["stages_done"] == []
            complete = _events(e2e_app, f"run:{result.run_id}", "job.complete")[-1]
            assert complete["success"] is False and complete["detail"]["n_measurements"] == 0
            assert result.campaign is not None and result.campaign["status"] == "failed"
            assert result.campaign["measurements"] == [] and result.campaign["score"] is None
            _fail("D_RUNNER_NORM", f"run {result.run_id} failed inside the sandbox child: {error}")
        pytest.fail(f"run {result.run_id} did not succeed: {result.status}; error={error}; "
                    f"stages={result.stage_table.get('stages_done')}")
    assert result.campaign is not None, result.campaign_error
    campaign = result.campaign
    config = campaign["config"]
    assert config["norm"] == "l2" and config["eps_grid"] == L2_GRID and config["reference_eps"] == L2_REFERENCE
    assert config["attack_ids"] == L2_ATTACKS and config["target_id"] == memorising_model
    for attack_id, params in L2_PARAMS.items():
        assert config["attack_params"][attack_id] == params, "the caller's overrides are frozen, never eps / norm_l2"
    admission = _events(e2e_app, f"run:{result.run_id}", "attack.run")[0]
    assert admission["detail"]["norm"] == "l2" and admission["detail"]["budget"] == BUDGET_LABELS["l2"]
    assert admission["detail"]["eps_grid"] == L2_GRID

    by_id = _by_id(campaign)
    clean = by_id["m.clean"]
    _assert_counts(clean, n=n)
    for attack_id in L2_ATTACKS:
        flips: list[int] = []
        for eps in L2_GRID:
            row = by_id[f"m.evasion.{attack_id}.{_eps_tag(eps)}"]
            assert row["attack_id"] == attack_id and row["params"]["eps"] == pytest.approx(eps)
            assert row["params"]["norm"] == "l2"
            _assert_counts(row, n=n)
            _assert_asr(row, clean)
            assert row["l2_norm_mean"] is not None and row["l2_norm_mean"] >= 0.0
            # ATTACKS_HARDEN-01/-02, spec 12.3: a minimal-norm attack runs once; each eps row is the thresholding.
            if attack_id in MINIMAL_NORM_ATTACKS:
                assert MINIMAL_NORM_NOTE in row["notes"], row["notes"]
                threshold_note = next((note for note in row["notes"] if note.startswith(f"thresholded at eps={eps:g}:")),
                                      None)
                assert threshold_note is not None, row["notes"]
                within = int(threshold_note.split(":")[1].strip().split("/")[0])
                assert 0 <= within <= n and f"/{n} adversarial examples within budget" in threshold_note
                assert "wall_time_s is the single attack run shared by every eps row" in row["notes"]
                # Examples over budget revert to the clean input, so the mean L2 on the row never exceeds eps.
                assert row["l2_norm_mean"] <= eps + 1e-6, (row["id"], row["l2_norm_mean"])
            else:
                assert row["params"]["norm_l2"] is True, "PGD ran in the L2 norm the campaign declared"
                assert row["l2_norm_mean"] <= eps + 1e-6, (row["id"], row["l2_norm_mean"])
            flips.append(int(row["n_flipped_from_clean"] or 0))
        if attack_id in MINIMAL_NORM_ATTACKS:
            assert flips == sorted(flips), f"{attack_id}: flips must be monotone in the evaluation budget: {flips}"
        # A control at the same eps accompanies every evasion row and stays inside the L2 ball (spec 12.4).
        for eps in L2_GRID:
            control = by_id[f"m.control.noise.{_eps_tag(eps)}"]
            assert control["family"] == "control" and control["params"]["eps"] == pytest.approx(eps)
            assert control["params"]["norm_l2"] is True and control["params"]["norm"] == "l2"
            _assert_counts(control, n=n)
            assert control["l2_norm_mean"] is not None and control["l2_norm_mean"] <= eps + 1e-6, control["id"]
    families = [m["family"] for m in campaign["measurements"]]
    assert families.count("evasion") == len(L2_ATTACKS) * len(L2_GRID) and families.count("control") == len(L2_GRID)
    curves = {c["attack_id"]: c for c in campaign["curve"]}
    assert set(curves) == set(L2_ATTACKS)
    for curve in curves.values():
        assert curve["norm"] == "l2" and [p["eps"] for p in curve["points"]] == L2_GRID
        assert all(p["n"] == n for p in curve["points"])
    # Every attack executed and was audited; the stage table names each attack stage (spec 6.5, 10.5).
    for attack_id in L2_ATTACKS:
        rows = _events(e2e_app, f"run:{result.run_id}", f"attack.execute.{attack_id}")
        assert rows and rows[-1]["success"] is True and rows[-1]["detail"]["norm"] == "l2"
        assert result.stage_table["stages"][f"attack:{attack_id}"]["status"] == "succeeded"
    assert not [i for i in campaign["interpretation"] if str(i["id"]).startswith("i.attack.not_run.")]
    complete = _assert_score_state(campaign)
    if complete:
        assert campaign["score"]["norm"] == "l2" and campaign["score"]["eps_grid"] == L2_GRID
        assert set(campaign["score"]["per_attack"]) >= set(L2_ATTACKS)
    assert _campaign_row(e2e_app, result.run_id)["modality"] == "image"


# ---------------------------------------------------------------------------
# 3. ZOO on the tabular ensemble: query counts, realizability, frozen features (spec 12.9; ATTACKS_HARDEN-05)
# ---------------------------------------------------------------------------


def test_zoo_on_url_trees_keeps_frozen_features(e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str]) -> None:
    import numpy as np

    from redsim.ml.attacks import MINIMAL_NORM_NOTE, QUERIES_DENOMINATOR_NOTE
    from redsim.ml.campaign import REALIZABILITY_CAVEAT, TABULAR_LIMITATION
    from redsim.ml.scoring import MIN_CLEAN_CORRECT_FOR_FINDING
    from redsim.ml.targets import TARGETS
    from redsim.ml.targets.tabular import FROZEN_URL_FEATURES

    model_id = e2e_bundled[h.TABULAR_MODEL_ID]
    body = h.tabular_campaign(attack_ids=["zoo"], attack_params={"zoo": ZOO_PARAMS}, n_samples=ZOO_N)
    result = h.run_campaign_via_api(e2e_org.client("scanner"), model_id, body, timeout_s=300.0)
    assert result.status == "succeeded", f"run {result.run_id}: {result.stage_table}"
    assert result.campaign is not None, result.campaign_error
    campaign = result.campaign
    config = campaign["config"]
    assert config["modality"] == "tabular" and config["attack_ids"] == ["zoo"] and config["norm"] == "linf"
    assert config["attack_params"]["zoo"] == ZOO_PARAMS
    grid = config["eps_grid"]
    n = ZOO_N

    # The declared feature contract: the flags are frozen, the lexical counts perturbable (spec 12.9).
    features = config["target_snapshot"]["detail"]["manifest"]["features"]
    frozen_names = [f["name"] for f in features if not f["perturbable"]]
    assert set(frozen_names) == set(FROZEN_URL_FEATURES), frozen_names
    frozen_idx = [i for i, f in enumerate(features) if not f["perturbable"]]
    integer_idx = [i for i, f in enumerate(features) if f["dtype"] in {"int", "bool"}]

    by_id = _by_id(campaign)
    clean = by_id["m.clean"]
    _assert_counts(clean, n=n)
    flips: list[int] = []
    for eps in grid:
        row = by_id[f"m.evasion.zoo.{_eps_tag(eps)}"]
        _assert_counts(row, n=n)
        _assert_asr(row, clean)
        assert row["params"]["max_iter"] == 2 and row["params"]["nb_parallel"] == 4
        # Black-box, score-based, query-counted: the denominator rule is stated on the row (spec 12.5).
        assert "queries_mean" in row and QUERIES_DENOMINATOR_NOTE in row["notes"]
        assert MINIMAL_NORM_NOTE in row["notes"] and any(note.startswith(f"thresholded at eps={eps:g}:") for note in row["notes"])
        assert REALIZABILITY_CAVEAT in row["notes"], "spec 12.9: the caveat is on every tabular evasion row"
        assert any("frozen features" in note and "re-impos" in note for note in row["notes"]), row["notes"]
        assert any("black-box score-based" in note for note in row["notes"])
        flips.append(int(row["n_flipped_from_clean"] or 0))
        _assert_counts(by_id[f"m.control.noise.{_eps_tag(eps)}"], n=n)
    assert flips == sorted(flips), f"a minimal-norm attack's flips are monotone in the evaluation budget: {flips}"
    limitations = campaign["limitations"]
    assert TABULAR_LIMITATION in limitations and any("realizab" in item.lower() for item in limitations)
    if clean["n_correct"] < MIN_CLEAN_CORRECT_FOR_FINDING:
        # The tiny URL slice sits below the finding floor: no Finding, and the rows say why (spec 12.6).
        assert result.findings == []
        assert all(any("denominator too small for a finding" in note for note in by_id[f"m.evasion.zoo.{_eps_tag(e)}"]["notes"])
                   for e in grid)
    _assert_score_state(campaign)

    # The adversarial slices the child left behind: frozen features equal their clean values, integers stay integral.
    viewer = e2e_org.client("viewer")
    artifacts = _artifact_rows(viewer, result.run_id)
    slices = [row for row in artifacts.values() if row["kind"] == "ml.adv_slice"]
    assert slices, sorted({row["kind"] for row in artifacts.values()})
    with _assets_dir(e2e_app.assets_dir):
        target = TARGETS.get(h.TABULAR_MODEL_ID)
        target.load()
        sample = target.sample(n, config["seed"])
        mask = np.asarray(target.perturbable_mask(), dtype=bool)
    assert [i for i, keep in enumerate(mask) if not keep] == frozen_idx
    x_clean = np.asarray(sample.x, dtype=np.float32)
    clean_rows = [row for row in artifacts.values() if row["kind"] == "ml.clean_slice"]
    if clean_rows:  # INTEROP-04: the persisted clean slice is the same rows the campaign sampled
        with np.load(io.BytesIO(_download(viewer, clean_rows[0])), allow_pickle=False) as npz:
            assert np.array_equal(np.asarray(npz["indices"], dtype=np.int64), np.asarray(sample.indices, dtype=np.int64))
            assert np.allclose(np.asarray(npz["x"], dtype=np.float32), x_clean)
    changed_any = False
    for row in slices:
        with np.load(io.BytesIO(_download(viewer, row)), allow_pickle=False) as npz:
            x_adv = np.asarray(npz["x_adv"], dtype=np.float32)
            assert x_adv.shape == x_clean.shape
            assert np.array_equal(np.asarray(npz["indices"], dtype=np.int64), np.asarray(sample.indices, dtype=np.int64))
            assert np.array_equal(np.asarray(npz["y"]), np.asarray(sample.y))
        # Spec 12.9: frozen features are held at their clean values on every adversarial row.
        assert np.array_equal(x_adv[:, frozen_idx], x_clean[:, frozen_idx]), "a frozen URL feature moved"
        assert np.array_equal(x_adv[:, integer_idx], np.rint(x_adv[:, integer_idx])), "integer features stay integral"
        changed_any = changed_any or bool(np.any(x_adv != x_clean))
    # Whether ZOO moved anything is measured, not assumed; the rows above already state the flips it achieved.
    assert changed_any == any(int(by_id[f"m.evasion.zoo.{_eps_tag(e)}"]["n_flipped_from_clean"] or 0) > 0 for e in grid) \
        or changed_any, "a flip needs a changed row; a changed row need not flip"
    executed = _events(e2e_app, f"run:{result.run_id}", "attack.execute.zoo")
    assert executed and executed[-1]["success"] is True


# ---------------------------------------------------------------------------
# 4. Training defenses through the verify child (ATTACKS_HARDEN-11..18; spec 15.6, 16.4, 16.5, 26.3 item 15)
# ---------------------------------------------------------------------------


def _verify(e2e_app: E2EApp, client: TestClient, finding_id: str, body: dict[str, Any],
            root: Path) -> dict[str, Any]:
    """POST the verify with the memorising tree active; return everything it left behind."""
    with _assets_dir(root):
        response = client.post(f"/v1/findings/{finding_id}/verify", json=body)
        assert response.status_code == 202, response.text
        launch: dict[str, Any] = response.json()
        run_id = str(launch["run_id"])
        run = h.wait_for_run(client, run_id, timeout_s=120.0)
    record_response = client.get(f"/v1/runs/{run_id}/campaign")
    assert record_response.status_code == 200, record_response.text
    return {"run_id": run_id, "job_id": str(launch["job_ids"][0]), "run": run, "record": record_response.json(),
            "finding": _finding(client, finding_id)}


def _assert_training_verify_admitted(e2e_app: E2EApp, e2e_org: E2EOrg, verify: dict[str, Any], *, defense_id: str,
                                     params: dict[str, Any], baseline: h.CampaignRun) -> None:
    """The admission half is the same on every tree: the training defense is frozen and audited as such."""
    from redsim.ml.defenses import get_defense

    spec = get_defense(defense_id)
    assert spec["kind"] == "training" and spec["domains"] == ("image",)
    admission = _events(e2e_app, f"run:{verify['run_id']}", "verify.replay")
    assert len(admission) == 1 and admission[0]["success"] is True and admission[0]["actor"] == e2e_org.actor(h.OUTSIDER)
    detail = admission[0]["detail"]
    assert detail["defense_kind"] == "training" and detail["defense"]["id"] == defense_id
    assert detail["defense"]["art_class"] == spec["art_class"] and detail["baseline_run_id"] == baseline.run_id
    for key, value in params.items():
        assert detail["defense"]["params"][key] == value, (key, detail["defense"]["params"])
    job = _job_detail(e2e_app, verify["job_id"])
    assert job["type"] == "verify.replay" and job["detail"]["campaign_config"]["defense"]["id"] == defense_id
    row = _campaign_row(e2e_app, verify["run_id"])
    assert row["kind"] == "verify" and row["baseline_run_id"] == baseline.run_id
    record = verify["record"]
    assert record["kind"] == "verify" and record["baseline_run_id"] == baseline.run_id
    assert record["config"]["defense"]["id"] == defense_id
    assert baseline.campaign is not None
    assert record["settings_hash"] == baseline.campaign["settings_hash"], "the defense is outside the settings hash"


def _assert_training_verify_succeeded(e2e_app: E2EApp, e2e_org: E2EOrg, verify: dict[str, Any], *, defense_id: str,
                                      params: dict[str, Any], baseline: h.CampaignRun, model_id: str,
                                      derived_before: set[str]) -> None:
    """The full ATTACKS_HARDEN-13 / -18 evidence: stage, derived target, lineage, MeasuredDelta, audit row."""
    from redsim.ml.schema import STAGES, DerivedFrom, MeasuredDelta
    from redsim.workers.tasks.ml_campaign import VERIFY_STATUS_MAP
    from redsim.workers.tasks.verify import _STATE_MAP

    record = verify["record"]
    assert record["status"] == "succeeded" and verify["run"]["status"] == "succeeded"
    # Spec 6.5 / ATTACKS_HARDEN-15: defense_apply sits after load_target and before sample, and succeeded.
    table = verify["run"]["stage_table"]
    assert "defense_apply" in STAGES and table["stages"]["defense_apply"]["status"] == "succeeded", table["stages"]
    done = list(table["stages_done"])
    assert done.index("load_target") < done.index("defense_apply") < done.index("sample"), done
    provenance = record["provenance"]
    defense_prov = provenance["defense"]
    assert defense_prov["id"] == defense_id and defense_prov["kind"] == "training"
    assert _HEX64.match(defense_prov["derived_sha256"]) and defense_prov["derived_sha256"] != defense_prov["parent_sha256"]
    assert baseline.campaign is not None
    assert provenance["model_sha256"] == baseline.campaign["provenance"]["model_sha256"], "the 15.6 identity is the parent"
    report = defense_prov["training_report"]
    assert report["epochs_requested"] == params["epochs"] and 1 <= report["epochs_run"] <= params["epochs"]
    assert report["n_train"] <= params["train_n"] and report["wall_budget_s"] == params["wall_budget_s"]
    assert report["budget_exhausted"] is True or report["wall_time_s"] <= report["wall_budget_s"]
    assert report["weights_sha256"] == defense_prov["derived_sha256"]
    assert "train_clean_correct_before" in report and "train_clean_correct_after" in report, "k of n, no claim"

    # ATTACKS_HARDEN-13: exactly one new derived Target, registered then validated, with DerivedFrom lineage.
    derived = [t for t in _derived_targets(e2e_app, e2e_org.other_project_id) if t["id"] not in derived_before]
    assert len(derived) == 1, [t["id"] for t in derived]
    target = derived[0]
    assert target["kind"] == "ml_model_artifact" and target["id"].startswith("derived-")
    detail = target["detail"]
    lineage = DerivedFrom.model_validate(detail["derived_from"])
    assert lineage.parent_target_id == model_id and lineage.defense_id == defense_id
    assert lineage.parent_sha256 == defense_prov["parent_sha256"]
    assert lineage.training_budget["epochs_run"] == report["epochs_run"]
    assert detail["manifest"]["derived_from"]["defense_id"] == defense_id
    assert detail["status"] == "available", f"the derived target was not validated: {detail.get('validation')}"
    validate_chain = f"run:{detail['validation']['ingest_run_id']}"
    actions = _actions(e2e_app, validate_chain)
    assert actions[:2] == ["model.register", "model.validate"] and "job.complete" in actions, actions
    register = _events(e2e_app, validate_chain, "model.register")[0]
    assert register["detail"]["source"] == "derived" and register["detail"]["target_id"] == target["id"]
    assert register["detail"]["derived_sha256"] == defense_prov["derived_sha256"]
    artifacts = _artifact_rows(e2e_org.client(h.OUTSIDER), verify["run_id"])
    kinds = {row["kind"] for row in artifacts.values()}
    assert {"ml.derived_model", "ml.training_report"} <= kinds, sorted(kinds)

    # ATTACKS_HARDEN-18: verify.execute names the derived digest and the training budget.
    execute = _events(e2e_app, f"run:{verify['run_id']}", "verify.execute")[-1]
    assert execute["detail"]["derived_target_id"] == target["id"]
    assert execute["detail"]["derived_sha256"] == defense_prov["derived_sha256"]
    assert execute["detail"]["training_budget"]["epochs_run"] == report["epochs_run"]
    outcome = execute["detail"]["outcome"]
    finding = verify["finding"]
    assert finding["validation_state"] == _STATE_MAP[outcome] and finding["status"] == VERIFY_STATUS_MAP[outcome]

    # Spec 16.4 / 26.3 item 15: the MeasuredDelta sits on the recommendation naming the defense; sign not asserted.
    if outcome == "inconclusive":
        pytest.fail(f"verify {verify['run_id']} ({defense_id}) was inconclusive: {execute['detail']['inconclusive_reason']}; "
                    f"no MeasuredDelta could be attached (limitations: {record['limitations']})")
    delta = record["score"]["delta"]
    assert delta is not None and delta["baseline_run_id"] == baseline.run_id
    assert isinstance(delta["delta"], int) and delta["delta"] == delta["mri_after"] - delta["mri_before"]
    recs = _recs(finding["schema_blob"]["ml"])
    naming = {rec["id"] for rec in recs if defense_id in _defense_ids(rec)}
    assert naming, f"no candidate names {defense_id}: " + ", ".join(f"{r['id']}={sorted(_defense_ids(r))}" for r in recs)
    measured = {rec["id"]: rec for rec in recs if rec["validation"] == "measured" and rec["measured"] is not None
                and rec["measured"]["verify_run_id"] == verify["run_id"]}
    assert set(measured) == naming, (sorted(measured), sorted(naming))
    for rec in measured.values():
        block = MeasuredDelta.model_validate(rec["measured"])
        assert block.defense.id == defense_id and block.delta_mri == delta["delta"]
        assert block.baseline_run_id == baseline.run_id and block.settings_hash == record["settings_hash"]
    assert execute["detail"]["measured_for"] == sorted(measured, key=[r["id"] for r in recs].index)
    compare = e2e_org.client(h.OUTSIDER).get(f"/v1/runs/{verify['run_id']}/compare", params={"with": baseline.run_id})
    assert compare.status_code == 200, compare.text
    assert compare.json()["mode"] == "verify_delta" and compare.json()["changed_variables"] == ["defense"]
    assert compare.json()["delta_mri"] == delta["delta"]


def _assert_training_verify_failed_honestly(e2e_app: E2EApp, e2e_org: E2EOrg, verify: dict[str, Any], *,
                                            defense_id: str, derived_before: set[str]) -> str:
    """The honest state of a verify whose child could not train: nothing faked, the finding left open."""
    from redsim.ml.harden.apply import NO_TRAIN_SLICE_REASON

    record = verify["record"]
    error = str(record["error"] or verify["run"]["stage_table"].get("error") or "")
    assert verify["run"]["status"] == "failed" and record["status"] == "failed"
    assert record["score"] is None and record["completeness"] == "partial"
    # The frame marks load_target done only after the defense hook returned, so the child died inside the
    # open load_target stage: no stage is done, the open stage is failed, defense_apply never appears.
    table = verify["run"]["stage_table"]
    assert table["stages_done"] == [] and table["completeness"] == "partial", table
    assert table["stages"]["load_target"]["status"] == "failed", table["stages"]
    # The worker prefixes the raised class on the stage table ("RuntimeError: TrainingDefenseUnavailable: ...").
    assert "defense_apply" not in table["stages"] and "TrainingDefenseUnavailable" in str(table["error"])
    # No derived target, no measured delta, the finding inconclusive -> open (spec 6.4).
    assert not [t for t in _derived_targets(e2e_app, e2e_org.other_project_id) if t["id"] not in derived_before]
    finding = verify["finding"]
    assert finding["status"] == "open" and finding["validation_state"] == "inconclusive"
    detail = finding["schema_blob"]["ml"]
    assert detail["verify"]["run_id"] == verify["run_id"] and detail["verify"]["outcome"] == "inconclusive"
    assert detail["verify"]["defense"]["id"] == defense_id and detail["verify"]["delta"] is None
    assert any(r["run_id"] == verify["run_id"] for r in detail["retests"]), "every verify is a retest (REVIEW_REPORTS-08)"
    assert all(rec["validation"] == "not evaluated" and rec["measured"] is None for rec in _recs(detail))
    execute = _events(e2e_app, f"run:{verify['run_id']}", "verify.execute")[-1]
    assert execute["success"] is False and execute["detail"]["outcome"] == "inconclusive"
    assert execute["detail"]["delta_mri"] is None and execute["detail"]["measured_for"] == []
    assert "derived_sha256" not in execute["detail"]
    complete = _events(e2e_app, f"run:{verify['run_id']}", "job.complete")[-1]
    assert complete["success"] is False and complete["detail"]["error_class"] == "TrainingDefenseUnavailable"
    assert error.startswith("TrainingDefenseUnavailable") and NO_TRAIN_SLICE_REASON.split(":")[0] in error, error
    return error


def _assert_training_verify_unavailable_honestly(e2e_app: E2EApp, e2e_org: E2EOrg, verify: dict[str, Any], *,
                                                 defense_id: str, derived_before: set[str]) -> str:
    """The honest state of a verify whose child recorded the training defense as unavailable (spec 15.6 / 16.4):
    the run succeeds on the undefended model, no defense_apply stage, no score, no derived target, no delta, the
    finding inconclusive -> open. Nothing is claimed that was not measured."""
    from redsim.ml.harden.apply import NO_TRAIN_SLICE_REASON

    record = verify["record"]
    defense_prov = record["provenance"]["defense"]
    assert defense_prov["status"] == "unavailable" and defense_prov["kind"] == "training"
    assert defense_prov["id"] == defense_id and "derived_sha256" not in defense_prov
    reason = str(defense_prov["reason"])
    table = verify["run"]["stage_table"]
    assert "defense_apply" not in table["stages_done"], "nothing was applied, so no stage says it was"
    assert table["stages"].get("defense_apply", {}).get("status") in (None, "skipped"), table["stages"]
    assert record["score"] is None and record["completeness"] == "partial"
    assert any("was not applied" in item and defense_id in item for item in record["limitations"]), record["limitations"]
    assert not [t for t in _derived_targets(e2e_app, e2e_org.other_project_id) if t["id"] not in derived_before]
    finding = verify["finding"]
    assert finding["status"] == "open" and finding["validation_state"] == "inconclusive"
    detail = finding["schema_blob"]["ml"]
    assert detail["verify"]["run_id"] == verify["run_id"] and detail["verify"]["outcome"] == "inconclusive"
    assert detail["verify"]["defense"]["id"] == defense_id and detail["verify"]["delta"] is None
    assert all(rec["validation"] == "not evaluated" and rec["measured"] is None for rec in _recs(detail))
    execute = _events(e2e_app, f"run:{verify['run_id']}", "verify.execute")[-1]
    assert execute["success"] is False and execute["detail"]["outcome"] == "inconclusive"
    assert "derived_sha256" not in execute["detail"] and execute["detail"]["measured_for"] == []
    assert not _events(e2e_app, f"run:{verify['run_id']}", "campaign.score"), "no score row without a score"
    assert NO_TRAIN_SLICE_REASON.split(":")[0] in reason, reason
    return f"{defense_id}: recorded unavailable ({reason})"


def test_training_defense_verify_registers_a_derived_target(
    e2e_app: E2EApp, e2e_org: E2EOrg, memorising_model: str, memorising_tree: dict[str, Any], finding_run: h.CampaignRun,
) -> None:
    client = e2e_org.client(h.OUTSIDER)
    finding_id = str(finding_run.findings[0]["id"])
    seed = _finding(client, finding_id)
    assert seed["status"] == "open" and seed["validation_state"] == "unvalidated"
    assert seed["schema_blob"]["ml"]["verify"] is None
    failures: list[str] = []
    for defense_id, params in (("adversarial_training", ADVERSARIAL_TRAINING_PARAMS),
                               ("defensive_distillation", DISTILLATION_PARAMS)):
        derived_before = {t["id"] for t in _derived_targets(e2e_app, e2e_org.other_project_id)}
        verify = _verify(e2e_app, client, finding_id, {"defense": defense_id, "params": params},
                         memorising_tree["root"])
        _assert_training_verify_admitted(e2e_app, e2e_org, verify, defense_id=defense_id, params=params,
                                         baseline=finding_run)
        defense_prov = (verify["record"].get("provenance") or {}).get("defense") or {}
        if verify["run"]["status"] == "succeeded" and defense_prov.get("status") == "unavailable":
            # The child could not train (no training slice reachable from the target) and said so: the run
            # measures the undefended model with the score withheld. Asserted honestly, then attributed.
            failures.append(_assert_training_verify_unavailable_honestly(
                e2e_app, e2e_org, verify, defense_id=defense_id, derived_before=derived_before))
            continue
        if verify["run"]["status"] == "succeeded":
            _assert_training_verify_succeeded(e2e_app, e2e_org, verify, defense_id=defense_id, params=params,
                                              baseline=finding_run, model_id=memorising_model,
                                              derived_before=derived_before)
            continue
        error = str(verify["record"].get("error") or verify["run"]["stage_table"].get("error") or "")
        if not error.startswith("TrainingDefenseUnavailable"):
            pytest.fail(f"verify {verify['run_id']} ({defense_id}) failed for an unexpected reason: {error}; "
                        f"stages={verify['run']['stage_table'].get('stages_done')}")
        failures.append(_assert_training_verify_failed_honestly(e2e_app, e2e_org, verify, defense_id=defense_id,
                                                                derived_before=derived_before))
    if failures:
        _fail("D_TRAIN_SLICE", "the verify child could not train on the bundled image model (training slice "
                               f"{memorising_tree['train_slice']!r} with {memorising_tree['train_slice_n']} rows is in "
                               "the tree's manifest but no target reads it):\n  " + "\n  ".join(failures))


# ---------------------------------------------------------------------------
# 5. The tabular tree ensemble: training defenses are a typed unavailable, never a run (ATTACKS_HARDEN-20)
# ---------------------------------------------------------------------------


def test_training_defenses_are_unavailable_for_the_tabular_tree_ensemble(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str],
) -> None:
    from redsim.ml.defenses import DISTILLATION_ART_NOTE, DISTILLATION_BYPASS, get_defense
    from redsim.ml.harden.apply import TREE_ENSEMBLE_REASON, TrainingUnavailable, assess_training_target
    from redsim.ml.targets import TARGETS

    # The catalog the API serves says what each training row needs and does not claim (spec 16.6).
    catalog = e2e_org.client("viewer").get("/v1/defenses")
    assert catalog.status_code == 200, catalog.text
    rows = {row["id"]: row for row in catalog.json()["defenses"]}
    for defense_id in ("adversarial_training", "defensive_distillation"):
        row = rows[defense_id]
        assert row["kind"] == "training" and row["modalities"] == ["image"], row
        assert row["requires"] == {"torch_module": True, "train_slice": True}
        assert not _READINESS_RE.search(row["description"]), row["description"]
        budget = {p["name"]: p for p in row["params_schema"]}
        assert budget["epochs"]["max"] == 5 and budget["wall_budget_s"]["max"] == 600, "bounded budgets (spec 12.8)"
    assert DISTILLATION_BYPASS in rows["defensive_distillation"]["references"]
    assert DISTILLATION_ART_NOTE in rows["defensive_distillation"]["references"]
    assert any("cw_l2" in ref for ref in rows["defensive_distillation"]["references"]), "the bypass names the attack"

    # On the real loaded bundled tabular target, the same typed record the verify child would persist.
    del e2e_bundled  # the shared url_trees is registered; the library check reads the same asset tree
    with _assets_dir(e2e_app.assets_dir):
        target = TARGETS.get(h.TABULAR_MODEL_ID)
        target.load()
        assert target.info().domain == "tabular"
        for defense_id in ("adversarial_training", "defensive_distillation"):
            unavailable = assess_training_target(target, defense_id)
            assert isinstance(unavailable, TrainingUnavailable), defense_id
            assert unavailable.infeasible is True and unavailable.register_item == "ATTACKS_HARDEN-20"
            assert unavailable.reason == TREE_ENSEMBLE_REASON and unavailable.code == "training_defense_unavailable"
            assert unavailable.target_id == h.TABULAR_MODEL_ID and unavailable.domain == "tabular"
    # The route-level refusal (422 defense_modality_mismatch) needs a tabular Finding to verify; the tiny URL slice
    # cannot produce one (fewer than MIN_CLEAN_CORRECT_FOR_FINDING clean-correct rows, asserted in test 3), so the
    # admission check is proven on the finding-independent halves above and in tests/ml/test_admission_phase_b.py.
    # The served phase label must be the catalog's own (spec 26.5 item 24: unsupported paths say what they are).
    mislabelled = {did: (rows[did]["phase"], get_defense(did)["phase"]) for did in ("adversarial_training",
                                                                                   "defensive_distillation")
                   if rows[did]["phase"] != get_defense(did)["phase"]}
    if mislabelled:
        _fail("D_DEFENSES_PHASE", f"GET /v1/defenses serves phase {mislabelled} as (served, catalog)")
