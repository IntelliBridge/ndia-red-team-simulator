"""Phase B attacks and the harden route through the e2e harness (plan 12 wave B4, TESTS_DOCS-10, ATTACKS_HARDEN-21/-23).

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
4. ``test_harden_route_yields_candidates_only``: ``POST /v1/findings/{id}/harden``
   on a worker finding is admitted (``harden.recommend`` row first), runs an
   ``ml.harden`` follow-on through the sandbox child and merges rule candidates
   back onto the finding. Every recommendation is ``status: candidate`` and
   nothing more (no validation label, no measured block, no gain, no
   ``defense:`` reference), the ``harden.execute`` row records ``narrative_source
   rules`` and the record's limitations carry the standing sentence that no
   candidate has been evaluated against this model.

Every run is a measurement in its own right (product decision of 2026-09-09):
there is no verify campaign, no defense catalog, no training defense, no derived
target and no measured delta anywhere in this file or in the product.

The shared tree's ``vehicles_cnn`` is a one-epoch CNN that predicts one class for
every image (8 of 24 clean-correct, below the finding floor of 10), so it yields
neither a meaningful L2 curve nor a finding. Tests 2 and 4 therefore build a
second tiny tree with the **real builder** (``build_tiny_assets(epochs=300)``, a
memorising ``small_cnn``), register that ``vehicles_cnn`` into the *other*
organisation's project through ``register_bundled_model`` (a throwaway blob
store, so the shared blob is never overwritten) and point ``REDSIM_ML_ASSETS_DIR``
at the tree only while their own campaigns run. Nothing measured on either tree
is a demo result.

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
#: The default finding threshold of spec 15.3; the memorising model crosses it under FGSM and PGD.
FINDING_THRESHOLD = 0.2
#: Keys that left the recommendation contract with the verify paradigm (2026-09-09).
_RETIRED_RECOMMENDATION_KEYS = frozenset({"validation", "measured", "expected_gain", "delta", "delta_mri"})
#: A bare "+N": no gain is ever claimed for a candidate.
_BARE_GAIN = re.compile(r"(?<![\w.\-])\+\d")

DEFECTS: dict[str, str] = {
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


def _finding(client: TestClient, finding_id: str) -> dict[str, Any]:
    response = client.get(f"/v1/findings/{finding_id}")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _recs(detail: dict[str, Any]) -> list[dict[str, Any]]:
    recs = detail.get("recommendations")
    return list(recs) if isinstance(recs, list) else []


def _assert_candidates_only(recs: list[dict[str, Any]]) -> None:
    """A recommendation is ``status: candidate`` and nothing more: no validation label, no gain, no delta."""
    from redsim.ml.schema import CandidateRecommendation

    assert recs, "the rule layer always produces R7"
    allowed = set(CandidateRecommendation.model_fields)
    for rec in recs:
        assert rec["status"] == "candidate", rec.get("id")
        assert not (set(rec) & _RETIRED_RECOMMENDATION_KEYS), sorted(set(rec) & _RETIRED_RECOMMENDATION_KEYS)
        assert set(rec) <= allowed, sorted(set(rec) - allowed)
        text = " ".join(str(rec.get(k) or "") for k in ("title", "rationale", "narrative"))
        assert not _BARE_GAIN.search(text) and "expected gain" not in text.lower(), text[:200]
        assert "not evaluated" not in text.lower(), text[:200]
        assert not [r for r in rec.get("references") or [] if str(r).startswith("defense:")], rec["references"]


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
# A second tiny tree: a memorising small_cnn
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def memorising_tree(e2e_app: E2EApp, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """``build_tiny_assets(epochs=300)`` into its own root: a memorising ``small_cnn`` the real builder wrote.

    A precondition of the L2 and harden evidence, not a product claim: the memorising CNN clears the finding
    floor on the tiny slice so a Finding can exist; the shared one-epoch tree's cannot (asserted in
    ``test_ml_upload_reports.py``).
    """
    from redsim.ml.assets.manifest import MANIFEST_NAME, AssetManifest, verify_model_assets
    from redsim.ml.scoring import MIN_CLEAN_CORRECT_FOR_FINDING

    del e2e_app  # ordering only: the harness engine exists before a second tree is built
    root = tmp_path_factory.mktemp("e2e-harden-assets")
    h.build_tiny_assets(root, epochs=MEMORISE_EPOCHS)
    manifest = AssetManifest.model_validate(json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8")))
    for model_id in manifest.models:
        problems = verify_model_assets(manifest, root, model_id)
        assert not problems, f"{model_id}: {list(problems.model) + list(problems.dataset)}"
    model = manifest.models[h.IMAGE_MODEL_ID]
    assert model.clean_accuracy is not None
    clean_correct = round(model.clean_accuracy.value * model.clean_accuracy.n)
    if clean_correct < MIN_CLEAN_CORRECT_FOR_FINDING:
        pytest.fail(f"harness precondition: the {MEMORISE_EPOCHS}-epoch small_cnn reached only {clean_correct}/"
                    f"{model.clean_accuracy.n} clean-correct on the tiny slice, below the finding floor "
                    f"{MIN_CLEAN_CORRECT_FOR_FINDING}; raise MEMORISE_EPOCHS")
    return {"root": root, "clean_correct": clean_correct, "n_eval": model.clean_accuracy.n,
            "model_sha256": model.sha256}


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
    """FGSM + PGD (L-inf, the whole 24-image slice) on the memorising model: the campaign that yields the finding."""
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
                    f"{clean['n']}, ASR by row {asr}, threshold {FINDING_THRESHOLD}); nothing to harden")
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
# 4. The harden route: rule candidates merged onto the finding, candidates and nothing more (spec 16.2, 16.4)
# ---------------------------------------------------------------------------


def test_harden_route_yields_candidates_only(
    e2e_app: E2EApp, e2e_org: E2EOrg, memorising_tree: dict[str, Any], finding_run: h.CampaignRun,
) -> None:
    from redsim.ml.schema import STANDING_LIMITATIONS

    client = e2e_org.client(h.OUTSIDER)
    finding_id = str(finding_run.findings[0]["id"])
    seed = _finding(client, finding_id)
    assert seed["status"] == "open" and "validation_state" not in seed and "validated_at" not in seed
    seed_detail = seed["schema_blob"]["ml"]
    assert "verify" not in seed_detail and "retests" not in seed_detail, sorted(seed_detail)
    _assert_candidates_only(_recs(seed_detail))
    steps = str(seed["schema_blob"]["remediation_steps"])
    assert steps.startswith("CANDIDATE: ") and "not evaluated" not in steps, steps[:120]
    assert finding_run.campaign is not None
    assert STANDING_LIMITATIONS[3] in finding_run.campaign["limitations"]
    assert "defense" not in finding_run.campaign["config"] and "defense" not in finding_run.campaign["provenance"]

    # The retired verify routes are gone from the surface: 404, no operation, no gate, no audit row.
    events_before = len(e2e_app.read_chain(f"run:{finding_run.run_id}"))
    assert client.post(f"/v1/findings/{finding_id}/verify", json={}).status_code == 404
    assert client.get(f"/v1/findings/{finding_id}/retests").status_code == 404
    assert client.get("/v1/defenses").status_code == 404
    assert len(e2e_app.read_chain(f"run:{finding_run.run_id}")) == events_before

    # harden.recommend is remediator and above; the outsider is admin of the other project.
    assert e2e_org.client("remediator").post(f"/v1/findings/{finding_id}/harden",
                                             json={"llm_narrative": False}).status_code in (403, 404)
    with _assets_dir(memorising_tree["root"]):
        response = client.post(f"/v1/findings/{finding_id}/harden", json={"llm_narrative": False})
        assert response.status_code == 202, response.text
        launch = response.json()
        run_id = str(launch["run_id"])
        run = h.wait_for_run(client, run_id, timeout_s=180.0)
    assert run["status"] == "succeeded", f"harden run {run_id}: {run.get('stage_table')}"
    assert run["scanner"] == "ml.harden"
    chain = f"run:{run_id}"
    actions = _actions(e2e_app, chain)
    assert actions[0] == "harden.recommend", actions
    admission = _events(e2e_app, chain, "harden.recommend")[0]
    assert admission["success"] is True and admission["actor"] == e2e_org.actor(h.OUTSIDER)
    assert admission["detail"]["finding_id"] == finding_id
    assert "harden.execute" in actions and "job.complete" in actions, actions
    assert not [a for a in actions if a.startswith("verify.")], actions
    execute = _events(e2e_app, chain, "harden.execute")[-1]
    assert execute["detail"]["llm_requested"] is False and execute["detail"]["llm_used"] is False
    assert execute["detail"]["narrative_source"] == "rules"
    assert not {"measured_for", "delta_mri", "defense", "derived_sha256"} & set(execute["detail"]), execute["detail"]
    record_response = client.get(f"/v1/runs/{run_id}/campaign")
    assert record_response.status_code == 200, record_response.text
    record = record_response.json()
    assert record["kind"] == "attack" and "baseline_run_id" not in record and "defense" not in record["config"]
    assert STANDING_LIMITATIONS[3] in record["limitations"], record["limitations"]
    _assert_candidates_only(_recs(record))

    # The follow-on merged its candidates onto the finding: candidates and nothing more, the review block intact.
    after = _finding(client, finding_id)
    detail = after["schema_blob"]["ml"]
    recs = _recs(detail)
    _assert_candidates_only(recs)
    assert {rec["narrative_source"] for rec in recs} == {"rules"} and all(rec["narrative"] is None for rec in recs)
    # The merge keeps the candidates that cite this attack's evidence (worker ``_merge_followon``), never every rule.
    attack_id = str(detail["attack_id"])
    known = {m["id"] for m in detail["measurements"] if m.get("attack_id") == attack_id} | {
        o["id"] for o in detail["observations"]}
    assert all(set(rec["triggered_by"]) & known for rec in recs), "every merged candidate cites this finding's evidence"
    assert detail["review"] == seed_detail["review"], "a harden run never touches the review block"
    assert after["status"] == "open" and "validation_state" not in after
    assert STANDING_LIMITATIONS[3] in detail["limitations"]
    assert any(key.startswith("harden.recommend:") for key in detail["artifacts"]), sorted(detail["artifacts"])
    assert h.MOCK_PYTHIA_API_KEY not in json.dumps(after)
