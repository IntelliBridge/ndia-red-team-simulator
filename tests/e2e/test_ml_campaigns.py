"""Demo-path campaigns through the shared e2e harness (spec 24 steps 1-6; 26.1-26.3).

Four tests over the real API, admission services, eager Celery task bodies and
the ML sandbox child, against the tiny asset tree ``tests/e2e/conftest.py``
builds. Every assertion is on what the production path left behind (the
campaign record served by ``GET /v1/runs/{id}/campaign``, the ``Run`` stage
table, ``Artifact`` rows and their bytes, the audit chain, ``LLMUsage`` rows);
nothing is stubbed beyond the harness's three infrastructure doubles.

1. ``test_image_campaign_completes_with_scorecard`` (demo steps 1-4; 26.2 items
   6-9, 26.3 items 12-15): FGSM + PGD with the benign noise control on the
   default grid, ``explain_k > 0``; the record carries the clean row, one
   evasion row per attack per eps and one control row per eps, each with ``n``
   and ``n_correct`` and per-class counts; SHAP observations are ``heuristic``
   and the "not causal proof" limitation is present; interpretation is
   ``inferred`` with basis ids; recommendations are ``candidate`` /
   ``not evaluated`` with no expected-gain field; the standing limitations are
   present; the stage table has every ``STAGES`` entry in the spec 6.5 shape;
   the score is either a complete five-subscore MRI with an attack-scoped
   reading, or the honest partial state, and ``mri`` never appears without all
   five subscores; the curve and SHAP artifacts are listed and download
   byte-for-byte against their recorded digests.
2. ``test_tabular_campaign_own_mri`` (demo step 6; spec 12.9, D9 i): PGD by
   surrogate transfer + HopSkipJump + control on ``url_trees``; the
   realizability caveat is on every evasion row and in the limitations; the
   record is tabular; comparing it with the image run is
   ``409 incompatible_campaigns``.
3. ``test_narrative_on_and_off`` (spec 10.8, 16.3): the mocked Pythia gateway
   on gives ``narrative_source == "llm"`` with prompt/completion artifacts and
   one ``LLMUsage`` row; ``REDSIM_DISABLE_LLM=1`` gives ``rules`` with the skip
   reason recorded and the job still succeeded.
4. ``test_rerun_links_parent_and_never_mutates_terminal`` (spec 10.6, 10.7,
   26.1 item 3): a queued campaign is cancelled through the route, rerun via
   ``parent_run_id``, the lineage is recorded and the parent's rows are
   byte-identical before and after; a succeeded parent is refused with the
   documented code.

Run with::

    REDSIM_E2E=1 pytest -q -p no:cacheprovider -m e2e tests/e2e/test_ml_campaigns.py

Heavy imports happen inside the tests, after the session fixtures have checked
the extras, so collection stays green without them.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any

import pytest

from tests.e2e import harness as h

if TYPE_CHECKING:
    from fastapi.testclient import TestClient

    from tests.e2e.harness import E2EApp, E2EOrg, PythiaToggle

pytestmark = pytest.mark.e2e

#: Spec 6.5 per-stage status vocabulary.
STAGE_STATUSES = frozenset({"queued", "running", "succeeded", "failed", "skipped", "cancelled", "timed_out"})
#: The five MRI dimensions (spec 15.2), in the schema's order.
SUBSCORE_KEYS = ("S_acc", "S_asr", "S_eps", "S_conf", "S_expl")
#: Readiness / certification wording that never appears in a grade reading (spec 15.8 iii, 14.7).
_READINESS_RE = re.compile(
    r"\b(readiness|ready|certif\w*|deploy\w*|fielding|hardened|safe|safety|proven|validated|guaranteed)\b",
    re.IGNORECASE,
)
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


# ---------------------------------------------------------------------------
# Helpers (read-only views over the API and the harness database)
# ---------------------------------------------------------------------------


def _eps_tag(eps: float) -> str:
    """``0.03 -> "eps0.03"``, the measurement-id suffix of spec 14.1 (mirrors ``redsim.ml.eval.eps_tag``)."""
    return f"eps{float(eps):g}"


def _by_id(campaign: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = campaign["measurements"]
    out = {str(m["id"]): m for m in rows}
    assert len(out) == len(rows), "measurement ids are unique within a run"
    return out


def _known_ids(campaign: dict[str, Any]) -> set[str]:
    return ({str(m["id"]) for m in campaign["measurements"]}
            | {str(o["id"]) for o in campaign["observations"]}
            | {str(i["id"]) for i in campaign["interpretation"]})


def _assert_counts(row: dict[str, Any], *, n: int, class_names: set[str] | None = None) -> None:
    """``k / n`` denominators and per-class counts on one measurement row (spec 14.2)."""
    assert row["n"] == n, row["id"]
    assert isinstance(row["n_correct"], int) and 0 <= row["n_correct"] <= row["n"], row
    assert row["accuracy"] == pytest.approx(row["n_correct"] / row["n"]), row["id"]
    per_class = row["per_class"]
    assert isinstance(per_class, dict) and per_class, f"{row['id']} has no per-class counts"
    for label, counts in per_class.items():
        assert set(counts) >= {"n", "n_correct"}, (row["id"], label, counts)
        assert isinstance(counts["n"], int) and isinstance(counts["n_correct"], int)
        assert 0 <= counts["n_correct"] <= counts["n"]
    if class_names is not None:
        assert set(per_class) <= class_names, (row["id"], sorted(per_class))
    assert sum(c["n"] for c in per_class.values()) == row["n"], row["id"]
    assert sum(c["n_correct"] for c in per_class.values()) == row["n_correct"], row["id"]


def _artifact_rows(client: TestClient, run_id: str) -> dict[str, dict[str, Any]]:
    response = client.get(f"/v1/runs/{run_id}/artifacts")
    assert response.status_code == 200, response.text
    rows = response.json()["artifacts"]
    assert response.json()["count"] == len(rows)
    return {str(row["id"]): row for row in rows}


def _download(client: TestClient, row: dict[str, Any]) -> bytes:
    """``GET /v1/artifacts/{id}``: the bytes, verified against the recorded digest and headers (spec 17.2)."""
    response = client.get(f"/v1/artifacts/{row['id']}")
    assert response.status_code == 200, (row["kind"], response.status_code, response.text[:200])
    data = response.content
    assert hashlib.sha256(data).hexdigest() == row["sha256"], f"{row['kind']}: bytes differ from Artifact.sha256"
    if row.get("size_bytes") is not None:
        assert len(data) == row["size_bytes"], row["kind"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"] == "default-src 'none'"
    assert response.headers["etag"] == f'"{row["sha256"]}"'
    assert response.headers["content-type"].split(";")[0] == row["content_type"].split(";")[0]
    return data


def _events(e2e_app: E2EApp, chain_id: str, action: str) -> list[dict[str, Any]]:
    return [ev for ev in e2e_app.read_chain(chain_id) if ev["action"] == action]


def _campaign_row(e2e_app: E2EApp, run_id: str) -> dict[str, Any]:
    from sqlalchemy import MetaData, Table

    with e2e_app.session() as sess:
        table = Table("ml_campaigns", MetaData(), autoload_with=sess.get_bind())
        row = sess.execute(table.select().where(table.c.run_id == run_id)).mappings().one()
        return dict(row)


def _job_rows(e2e_app: E2EApp, run_id: str) -> list[dict[str, Any]]:
    from sqlalchemy import select

    from redsim.db.models import Job

    with e2e_app.session() as sess:
        jobs = sess.execute(select(Job).where(Job.run_id == run_id).order_by(Job.id)).scalars().all()
        return [{"id": j.id, "type": j.type, "status": j.status, "detail": j.detail, "created_by": j.created_by,
                 "completed_at": j.completed_at, "celery_task_id": j.celery_task_id, "error": j.error}
                for j in jobs]


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _record_snapshot(e2e_app: E2EApp, client: TestClient, run_id: str) -> dict[str, str]:
    """Canonical bytes of everything a terminal run owns: the run, its jobs, its campaign row, its artifacts."""
    run = client.get(f"/v1/runs/{run_id}")
    assert run.status_code == 200, run.text
    artifacts = client.get(f"/v1/runs/{run_id}/artifacts")
    assert artifacts.status_code == 200, artifacts.text
    return {
        "run": _canonical(run.json()),
        "jobs": _canonical(_job_rows(e2e_app, run_id)),
        "campaign_row": _canonical(_campaign_row(e2e_app, run_id)),
        "artifacts": _canonical(artifacts.json()),
    }


#: The explain stage dies inside the real sandbox child on every campaign of this tree. The child's
#: ``DirectoryArtifactSink.put`` returns the reference ``sandbox:<name>:<digest>``
#: (``redsim/ml/sandbox_worker.py:119``) while its ``sha256`` is keyed by the bare artifact name
#: (``redsim/ml/sandbox_worker.py:135``); the explainers digest their files through the value ``put``
#: returned (``redsim/ml/explain/shap_image.py:521`` and ``:590``, ``redsim/ml/explain/shap_tabular.py:470``
#: and ``:551``), which the ``FilesystemSink`` (``redsim/ml/artifacts.py:39-42``, keyed by the returned
#: path) and the worker's ``DatabaseArtifactSink`` (``redsim/workers/tasks/ml_campaign.py:325-330``, keyed
#: by name and id) both accept. The child raises ``KeyError('sandbox:obs_000/clean.png:<sha>')``,
#: ``redsim/ml/campaign.py:903-911`` records "Explain stage unavailable" for every attack, no observation is
#: written, ``S_expl`` has no input and the MRI is never computed through the production sandbox path.
#: The ml tier and the in-process sandbox mode never see it because they use the other two sinks.
_CHILD_SINK_DEFECT = (
    "product defect, not a harness problem: redsim/ml/sandbox_worker.py:135 (DirectoryArtifactSink.sha256) "
    "is keyed by the artifact name while put() at redsim/ml/sandbox_worker.py:119 returns "
    "'sandbox:<name>:<digest>'; the explainers call sink.sha256(<value put returned>) "
    "(redsim/ml/explain/shap_image.py:521, :590; redsim/ml/explain/shap_tabular.py:470, :551), which the "
    "FilesystemSink (redsim/ml/artifacts.py:39-42) and DatabaseArtifactSink "
    "(redsim/workers/tasks/ml_campaign.py:325-330) accept and the sandbox child does not. Every campaign through "
    "the real child loses its explain stage (redsim/ml/campaign.py:903-911 records 'Explain stage unavailable'), "
    "so no observation, no S_expl and no MRI ever comes out of the production sandbox path. Until the child sink "
    "accepts the reference it returned (or the explainers digest by name), this test fails here. "
    "REDSIM_E2E_SANDBOX=inprocess runs the same campaign through the DatabaseArtifactSink and passes."
)


def _fail_on_child_sink_defect(campaign: dict[str, Any]) -> None:
    """Turn the known child-sink failure into a precise, attributed failure instead of an opaque one."""
    signature = [item for item in campaign["limitations"]
                 if item.startswith("Explain stage unavailable") and "KeyError: 'sandbox:" in item]
    if signature and not campaign["observations"]:
        pytest.fail("\n".join(signature) + "\n\n" + _CHILD_SINK_DEFECT, pytrace=False)


def _assert_score_state(campaign: dict[str, Any]) -> bool:
    """Spec 15.4 / 6.7 invariant: ``mri`` never without all five subscores; a partial score names what is missing.

    Returns ``True`` when the record carries a complete MRI, ``False`` for the honest partial state.
    """
    from redsim.ml.schema import contains_banned_score_word, grade_for_mri

    score = campaign["score"]
    limitations = campaign["limitations"]
    if score is None:
        status = campaign["score_status"]
        assert status is not None, "a campaign without a score must carry score_status (CampaignRecord)"
        assert status["state"] == "unavailable" and status["reason"], status
        assert campaign["completeness"] == "partial" and campaign["missing"], "no score means a partial record"
        assert any("MRI not computed" in item for item in limitations), limitations
        return False

    subscores = score["subscores"]
    absent = [key for key in SUBSCORE_KEYS if subscores.get(key) is None]
    assert campaign["completeness"] == score["completeness"]
    if score["mri"] is None:
        # Honest partial state: no number, no grade, no reading; the missing dimensions are named.
        assert absent, "mri None while every subscore is present"
        assert score["completeness"] == "partial" and score["missing"], score
        assert score["grade"] is None and score["reading"] is None
        assert campaign["missing"] == score["missing"]
        assert any("MRI not computed" in item for item in limitations), limitations
        return False

    # Complete MRI: every subscore present, grade derived from the number, attack-scoped reading only.
    assert not absent, f"mri {score['mri']} present while subscores are missing: {absent}"
    assert score["completeness"] == "complete" and score["missing"] == []
    assert isinstance(score["mri"], int) and 0 <= score["mri"] <= 100
    assert score["grade"] == grade_for_mri(score["mri"])
    reading = score["reading"]
    assert isinstance(reading, str) and reading.strip()
    assert not contains_banned_score_word(reading), reading
    assert not _READINESS_RE.search(reading), f"grade reading carries readiness wording: {reading!r}"
    for attack_id in campaign["config"]["attack_ids"]:
        assert attack_id in score["per_attack"], sorted(score["per_attack"])
    assert score["attack_ids"] == campaign["config"]["attack_ids"]
    assert score["eps_grid"] == campaign["config"]["eps_grid"]
    assert score["reference_eps"] == campaign["config"]["reference_eps"]
    assert score["settings_hash"] == campaign["settings_hash"]
    for row in score["inputs"]:
        assert isinstance(row["n"], int) and row["n"] > 0, row
    return True


def _assert_curve(campaign: dict[str, Any], *, n: int) -> dict[str, dict[str, Any]]:
    """The eps curve derived from the rows (spec 12.3, 15.8 ii): one curve per attack, ``n`` on every point."""
    config = campaign["config"]
    curves = {str(c["attack_id"]): c for c in campaign["curve"]}
    assert set(curves) == set(config["attack_ids"]), sorted(curves)
    for attack_id, curve in curves.items():
        assert curve["eps_grid"] == config["eps_grid"] and curve["norm"] == config["norm"]
        assert curve["clean"]["n"] == n and isinstance(curve["clean"]["n_correct"], int)
        assert [p["eps"] for p in curve["points"]] == config["eps_grid"], attack_id
        for point in curve["points"]:
            assert point["n"] == n and isinstance(point["n_correct"], int)
        if config["include_control"]:
            assert [p["eps"] for p in curve["control"]] == config["eps_grid"], attack_id
            assert all(p["n"] == n for p in curve["control"])
    return curves


# ---------------------------------------------------------------------------
# Shared image campaign (demo steps 2-3), run once for this module
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def image_run(e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str]) -> h.CampaignRun:
    """The demo's FGSM + PGD campaign on the registered ``vehicles_cnn`` through the real API and sandbox."""
    body = h.image_campaign()
    assert body["attack_ids"] == ["fgsm", "pgd"] and body["include_control"] is True
    assert body["eps_grid"] == [0.01, 0.03, 0.1] and body["explain_k"] > 0
    return h.run_campaign_via_api(e2e_org.client("scanner"), e2e_bundled[h.IMAGE_MODEL_ID], body)


# ---------------------------------------------------------------------------
# 1. Image campaign: record, scorecard, artifacts (demo steps 1-4)
# ---------------------------------------------------------------------------


def test_image_campaign_completes_with_scorecard(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], image_run: h.CampaignRun,
) -> None:
    from redsim.ml.campaign import D3_BOUNDS_LIMITATION, MRI_SCOPE_LIMITATION
    from redsim.ml.schema import (
        STAGES,
        STANDING_LIMITATIONS,
        SWEEP_LIMITATION_TEMPLATE,
        CampaignConfig,
        CandidateRecommendation,
        contains_banned_score_word,
    )
    from redsim.workers.tasks.ml_campaign import expected_stages

    model_id = e2e_bundled[h.IMAGE_MODEL_ID]
    body = h.image_campaign()
    n = body["n_samples"]
    grid = body["eps_grid"]
    viewer = e2e_org.client("viewer")
    result = image_run

    assert result.status == "succeeded", f"run {result.run_id}: {result.run.get('stage_table')}"
    assert result.campaign is not None, result.campaign_error
    campaign = result.campaign
    assert campaign["run_id"] == result.run_id and campaign["status"] == "succeeded"
    assert campaign["kind"] == "attack" and campaign["completed_at"] is not None
    config = campaign["config"]
    assert config["target_id"] == model_id and config["modality"] == "image"
    assert config["attack_ids"] == ["fgsm", "pgd"] and config["include_control"] is True
    assert config["eps_grid"] == grid and config["reference_eps"] == body["reference_eps"]
    assert config["explain_k"] == body["explain_k"] > 0 and config["n_samples"] == n
    assert config["target_snapshot"]["detail"]["bundled_id"] == h.IMAGE_MODEL_ID
    assert campaign["settings_hash"], "the settings hash is the precondition for any comparison (spec 5.6)"

    # -- measurements: clean, evasion per attack per eps, control per eps, k/n everywhere ----------
    by_id = _by_id(campaign)
    class_names = set(h.IMAGE_CLASS_NAMES)
    clean = by_id["m.clean"]
    assert clean["family"] == "clean" and clean["attack_id"] is None
    _assert_counts(clean, n=n, class_names=class_names)
    for attack_id in ("fgsm", "pgd"):
        for eps in grid:
            row = by_id[f"m.evasion.{attack_id}.{_eps_tag(eps)}"]
            assert row["family"] == "evasion" and row["attack_id"] == attack_id
            assert row["params"]["eps"] == pytest.approx(eps)
            _assert_counts(row, n=n, class_names=class_names)
            # ASR is n_flipped / clean n_correct, the denominator disclosed on the row (spec 14.2, 15.1).
            assert row["n_clean_correct"] == clean["n_correct"]
            assert isinstance(row["n_flipped_from_clean"], int)
            assert 0 <= row["n_flipped_from_clean"] <= clean["n_correct"]
            if clean["n_correct"] > 0:
                assert row["attack_success_rate"] == pytest.approx(row["n_flipped_from_clean"] / clean["n_correct"])
            else:
                assert row["attack_success_rate"] is None, "a zero denominator is 'not computed', never 0%"
                assert any("denominator" in note for note in row["notes"]), row["notes"]
    for eps in grid:
        row = by_id[f"m.control.noise.{_eps_tag(eps)}"]
        assert row["family"] == "control" and row["params"]["eps"] == pytest.approx(eps)
        _assert_counts(row, n=n, class_names=class_names)
    families = [m["family"] for m in campaign["measurements"]]
    assert families.count("clean") == 1 and families.count("evasion") == 2 * len(grid)
    assert families.count("control") == len(grid), "a control accompanies every eps (spec 14.3)"
    assert len(campaign["measurements"]) == 1 + 2 * len(grid) + len(grid)

    # -- observations: SHAP evidence labelled heuristic, with the standing "not causal proof" limitation
    observations = campaign["observations"]
    _fail_on_child_sink_defect(campaign)
    assert observations, "explain_k > 0 must leave SHAP observations"
    known = _known_ids(campaign)
    for obs in observations:
        assert obs["metric_kind"] == "heuristic", obs["id"]
        assert "proxy" in obs["metric_note"] and "not a segmentation" in obs["metric_note"], obs["metric_note"]
        assert obs["pred_clean"] in class_names and obs["pred_adv"] in class_names and obs["true_label"] in class_names
        assert obs["flipped"] == (obs["pred_adv"] != obs["pred_clean"])
        assert {"shap_clean.png", "shap_adv.png"} <= set(obs["artifacts"]), sorted(obs["artifacts"])
        assert set(obs["artifact_sha256"]) == set(obs["artifacts"]), obs["id"]
    limitations = campaign["limitations"]
    assert limitations, "limitations are never empty on a succeeded run (spec 14.5)"
    shap_sentence = STANDING_LIMITATIONS[0]
    assert "not causal proof" in shap_sentence and shap_sentence in limitations

    # -- interpretation: inferred, every basis id resolves ------------------------------------------
    for item in campaign["interpretation"]:
        assert item["kind"] == "inferred", item
        assert item["basis"], item["id"]
        assert set(item["basis"]) <= known, (item["id"], sorted(set(item["basis"]) - known))

    # -- candidate recommendations: candidate / not evaluated, no expected-gain field ---------------
    recommendations = campaign["recommendations"]
    assert recommendations, "the rule layer always fires R7 (spec 16.2)"
    allowed_keys = set(CandidateRecommendation.model_fields)
    for rec in recommendations:
        assert rec["status"] == "candidate" and rec["validation"] == "not evaluated", rec["id"]
        assert rec["measured"] is None, "a measured delta exists only after a verify run (spec 16.4)"
        assert set(rec) <= allowed_keys, sorted(set(rec) - allowed_keys)
        assert not [k for k in rec if "gain" in k.lower() or "expected" in k.lower() or "estimate" in k.lower()]
        assert rec["triggered_by"] and set(rec["triggered_by"]) <= known, rec["id"]
        assert rec["narrative_source"] == "rules" and rec["narrative"] is None, "no narrative was requested"
        assert not contains_banned_score_word(f"{rec['title']} {rec['rationale']}"), rec["id"]
    assert "r.R7" in {rec["id"] for rec in recommendations}

    # -- limitations: the standing sentences, the sweep sentence, the D3 bounds -----------------------
    for sentence in STANDING_LIMITATIONS:
        assert sentence in limitations, sentence
    assert SWEEP_LIMITATION_TEMPLATE.format(eps_grid=grid) in limitations
    assert any("open, unclassified public benchmark" in item for item in limitations), "dataset sentence"
    assert D3_BOUNDS_LIMITATION in limitations
    assert campaign["provenance"]["nondeterminism"], "nondeterminism sources are recorded (spec 14.4)"
    assert campaign["provenance"]["settings_hash"] == campaign["settings_hash"]
    assert campaign["provenance"]["sample_indices_sha256"]

    # -- stage table in the spec 6.5 shape with every STAGES entry -----------------------------------
    table = result.stage_table
    assert set(table) >= {"stage", "stages_done", "stages", "jobs", "error"}, sorted(table)
    assert table["error"] is None and table["stage"] == "report"
    from_stages: list[str] = []
    for stage in STAGES:
        if stage == "defense_apply":
            continue  # Phase B: expected only when the campaign applies a training defense
        if stage == "attack":
            from_stages.extend(f"attack:{a}" for a in config["attack_ids"])
        else:
            from_stages.append(stage)
    expected = expected_stages(CampaignConfig.model_validate(config))
    assert expected == from_stages, "control on, explain_k > 0 and auto_recommend make every STAGES entry expected"
    job_id = result.job_ids[0]
    for name in expected:
        entry = table["stages"][name]
        assert set(entry) >= {"status", "started_at", "finished_at", "job_id"}, (name, entry)
        assert entry["status"] in STAGE_STATUSES and entry["status"] == "succeeded", (name, entry)
        assert entry["finished_at"] is not None and entry["job_id"] == job_id
    assert set(table["stages_done"]) == set(expected)
    order = {name: i for i, name in enumerate(expected)}
    positions = [order[name] for name in table["stages_done"]]
    assert positions == sorted(positions), "stages advance monotonically (spec 6.5)"
    assert table["stages_done"][-1] == "report"
    assert table["jobs"][job_id]["type"] == "attack.run" and table["jobs"][job_id]["status"] == "succeeded"
    assert table["completeness"] == campaign["completeness"]
    assert set(campaign["stages_done"]) == set(expected)

    # -- the score: a complete MRI with its curve, or the honest partial state -----------------------
    complete = _assert_score_state(campaign)
    curves = _assert_curve(campaign, n=n)
    if complete:
        assert MRI_SCOPE_LIMITATION in limitations
        assert campaign["completeness"] == "complete"
    else:
        assert MRI_SCOPE_LIMITATION not in limitations, "the scope sentence accompanies a computed MRI only"
    # A computed MRI is only ever a complete one: the campaign row mirrors the record's score.
    row = _campaign_row(e2e_app, result.run_id)
    assert row["modality"] == "image" and row["kind"] == "attack" and row["settings_hash"] == campaign["settings_hash"]
    assert (row["score"] is None) == (campaign["score"] is None)
    if row["score"] is not None:
        assert row["score"]["mri"] == campaign["score"]["mri"]
        assert (row["score"]["mri"] is None) or all(row["score"]["subscores"][k] is not None for k in SUBSCORE_KEYS)

    # -- artifacts: the curve and the SHAP files are listed and download byte-for-byte -----------------
    artifacts = _artifact_rows(viewer, result.run_id)
    kinds = {row["kind"] for row in artifacts.values()}
    assert {"ml.run_record", "ml.curve", "ml.shap.image", "ml.shap.meta", "ml.shap.values",
            "report.md", "report.json", "report.html"} <= kinds, sorted(kinds)
    curve_rows = [row for row in artifacts.values() if row["kind"] == "ml.curve"]
    curve_json_rows = [row for row in curve_rows if row["content_type"].startswith("application/json")]
    assert len(curve_json_rows) == len(curves), "one curve JSON per attack (spec 5.8 ml.curve)"
    seen_curve_attacks: set[str] = set()
    for row in curve_json_rows:
        parsed = json.loads(_download(viewer, row))
        attack_id = str(parsed["attack_id"])
        assert parsed == curves[attack_id], f"the curve artifact for {attack_id} differs from the record's curve"
        seen_curve_attacks.add(attack_id)
    assert seen_curve_attacks == set(curves)
    for row in curve_rows:
        if row["content_type"] == "image/png":
            assert _download(viewer, row)[:8] == _PNG_MAGIC
    for obs in observations:
        for name, artifact_id in obs["artifacts"].items():
            row = artifacts.get(artifact_id)
            assert row is not None, f"{obs['id']} cites artifact {artifact_id} that /artifacts does not list"
            assert row["sha256"] == obs["artifact_sha256"][name], (obs["id"], name)
            if name in ("shap_clean.png", "shap_adv.png", "shap_adv_predclass.png"):
                assert row["kind"] == "ml.shap.image" and row["content_type"] == "image/png", (name, row)
                assert _download(viewer, row)[:8] == _PNG_MAGIC, name
            elif name == "shap_meta.json":
                meta = json.loads(_download(viewer, row))
                assert meta["metric_kind"] == "heuristic"
                # The campaign disambiguates an id explained for two attacks as ``o.000.<attack_id>`` after the
                # explainer wrote its meta file, so the meta names the id or its un-suffixed form.
                assert obs["id"] == meta["observation_id"] or obs["id"].startswith(f"{meta['observation_id']}.")
    # The record artifact is the bytes the /campaign route served (re-keyed projections aside).
    record_rows = [row for row in artifacts.values() if row["kind"] == "ml.run_record"]
    assert record_rows
    newest = json.loads(_download(viewer, max(record_rows, key=lambda r: str(r["created_at"]))))
    assert newest["run_id"] == result.run_id and newest["measurements"] == campaign["measurements"]
    assert newest["score"] == campaign["score"] and newest["limitations"] == campaign["limitations"]

    # -- the audit trail names the score it wrote, or wrote none ----------------------------------------
    chain = f"run:{result.run_id}"
    scored = _events(e2e_app, chain, "campaign.score")
    if campaign["score"] is not None:
        assert scored and scored[-1]["detail"]["mri"] == campaign["score"]["mri"]
        assert scored[-1]["detail"]["completeness"] == campaign["score"]["completeness"]
    else:
        assert not scored, "no campaign.score row without a score record"
    assert _events(e2e_app, chain, "job.complete")[-1]["detail"]["status"] == "succeeded"


# ---------------------------------------------------------------------------
# 2. Tabular campaign: its own MRI, never compared with the image one (demo step 6)
# ---------------------------------------------------------------------------


def test_tabular_campaign_own_mri(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], image_run: h.CampaignRun,
) -> None:
    from redsim.api.errors import INCOMPATIBLE_CAMPAIGNS
    from redsim.ml.campaign import REALIZABILITY_CAVEAT, TABULAR_LIMITATION

    model_id = e2e_bundled[h.TABULAR_MODEL_ID]
    body = h.tabular_campaign()
    assert body["attack_ids"] == ["pgd", "hopskipjump"] and body["include_control"] is True
    scanner = e2e_org.client("scanner")
    viewer = e2e_org.client("viewer")

    result = h.run_campaign_via_api(scanner, model_id, body)
    assert result.status == "succeeded", f"run {result.run_id}: {result.run.get('stage_table')}"
    assert result.campaign is not None, result.campaign_error
    campaign = result.campaign
    config = campaign["config"]
    assert config["modality"] == "tabular" and config["target_id"] == model_id
    assert config["attack_ids"] == ["pgd", "hopskipjump"] and config["include_control"] is True
    assert config["dataset_id"] == h.URL_DATASET_ID
    assert _campaign_row(e2e_app, result.run_id)["modality"] == "tabular"

    # Both attacks ran and were measured on the real model; the control accompanied every eps.
    by_id = _by_id(campaign)
    n = body["n_samples"]
    clean = by_id["m.clean"]
    _assert_counts(clean, n=n)
    for attack_id in ("pgd", "hopskipjump"):
        for eps in body["eps_grid"]:
            row = by_id[f"m.evasion.{attack_id}.{_eps_tag(eps)}"]
            _assert_counts(row, n=n)
            assert row["n_clean_correct"] == clean["n_correct"]
            # Spec 12.9: the realizability caveat is stated on every tabular evasion row.
            assert REALIZABILITY_CAVEAT in row["notes"], (row["id"], row["notes"])
    for eps in body["eps_grid"]:
        _assert_counts(by_id[f"m.control.noise.{_eps_tag(eps)}"], n=n)
    not_run = [i for i in campaign["interpretation"] if str(i["id"]).startswith("i.attack.not_run.")]
    assert not not_run, [i["statement"] for i in not_run]
    hsj_rows = [m for m in campaign["measurements"] if m.get("attack_id") == "hopskipjump"]
    assert hsj_rows and all("queries_mean" in m for m in hsj_rows)

    # The realizability caveat and the surrogate-transfer statement are in the limitations (spec 12.9, 14.5).
    limitations = campaign["limitations"]
    assert TABULAR_LIMITATION in limitations, limitations
    assert any("realizab" in item.lower() for item in limitations)
    assert any("surrogate transfer" in item.lower() for item in limitations), limitations
    pgd_notes = " ".join(note for m in campaign["measurements"] if m.get("attack_id") == "pgd" for note in m["notes"])
    assert "surrogate" in pgd_notes.lower(), "PGD rows say they came from the declared surrogate"

    # The tabular campaign's score is its own: complete or honestly partial, and never combined with the image one.
    _assert_score_state(campaign)
    _assert_curve(campaign, n=n)
    assert image_run.campaign is not None
    assert campaign["settings_hash"] != image_run.campaign["settings_hash"]
    for left, right in ((result.run_id, image_run.run_id), (image_run.run_id, result.run_id)):
        compare = viewer.get(f"/v1/runs/{left}/compare", params={"with": right})
        assert compare.status_code == 409, compare.text
        detail = compare.json()["detail"]
        assert detail["code"] == INCOMPATIBLE_CAMPAIGNS == "incompatible_campaigns"
        assert "modality" in detail["reasons"] and "attack_ids" in detail["reasons"], detail["reasons"]
        assert "delta" not in detail and "scorecards" not in detail, "a refusal reveals no score"
    # A member of another organisation learns nothing about either run.
    outsider = e2e_org.client(h.OUTSIDER).get(f"/v1/runs/{result.run_id}/compare", params={"with": image_run.run_id})
    assert outsider.status_code == 403, outsider.text


# ---------------------------------------------------------------------------
# 3. Narrative through the mocked Pythia gateway: llm on, rules when disabled
# ---------------------------------------------------------------------------


def _narrated(e2e_org: E2EOrg, model_id: str) -> h.CampaignRun:
    result = h.run_campaign_via_api(e2e_org.client("scanner"), model_id, h.image_campaign(llm_narrative=True))
    assert result.status == "succeeded", f"run {result.run_id}: {result.run.get('stage_table')}"
    assert result.campaign is not None, result.campaign_error
    return result


def _llm_usage_rows(e2e_app: E2EApp, run_id: str) -> list[dict[str, Any]]:
    from sqlalchemy import select

    from redsim.db.models import LLMUsage

    with e2e_app.session() as sess:
        rows = sess.execute(select(LLMUsage).where(LLMUsage.run_id == run_id)).scalars().all()
        return [{"task": r.task, "model": r.model, "project_id": r.project_id, "prompt_tokens": r.prompt_tokens,
                 "completion_tokens": r.completion_tokens, "cost_cents": r.cost_cents} for r in rows]


def test_narrative_on_and_off(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], pythia: PythiaToggle,
) -> None:
    model_id = e2e_bundled[h.IMAGE_MODEL_ID]
    viewer = e2e_org.client("viewer")

    # -- ON: the worker parent narrates through the mocked gateway --------------------------------
    with pythia:
        on = _narrated(e2e_org, model_id)
    campaign = on.campaign
    assert campaign is not None
    recs = campaign["recommendations"]
    assert recs, "nothing to narrate"
    assert {rec["narrative_source"] for rec in recs} == {"llm"}
    for rec in recs:
        assert rec["narrative"] and rec["status"] == "candidate" and rec["validation"] == "not evaluated"
        assert rec["measured"] is None
    assert len(pythia.requests) == 1, pythia.requests
    assert pythia.requests[0]["json"]["model"] == h.MOCK_PYTHIA_MODEL
    llm = campaign["provenance"]["llm"]
    assert llm["model"] == h.MOCK_PYTHIA_MODEL and llm["gateway"] == "pythia"
    assert "api_key" not in llm and h.MOCK_PYTHIA_API_KEY not in json.dumps(campaign)
    assert any("LLM narrative generated via Pythia" in item for item in campaign["limitations"])

    # Artifacts: the exact prompt and completion, listed and downloadable; digests match the audit row.
    artifacts = _artifact_rows(viewer, on.run_id)
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for row in artifacts.values():
        by_kind.setdefault(str(row["kind"]), []).append(row)
    assert {"ml.harden.prompt", "ml.harden.completion", "ml.harden.narrative"} <= set(by_kind), sorted(by_kind)
    harden = _events(e2e_app, f"run:{on.run_id}", "harden.execute")
    assert harden and harden[-1]["success"] is True
    detail = harden[-1]["detail"]
    assert detail["llm_used"] is True and detail["narrative_source"] == "llm"
    assert detail["llm_requested"] is True and detail["skipped_reason"] is None
    (prompt_row,) = by_kind["ml.harden.prompt"]
    (completion_row,) = by_kind["ml.harden.completion"]
    prompt = _download(viewer, prompt_row).decode("utf-8")
    completion = _download(viewer, completion_row).decode("utf-8")
    assert prompt_row["sha256"] == detail["prompt_sha256"], "the audit row digests the prompt artifact"
    assert completion_row["sha256"] == detail["completion_sha256"]
    for rec in recs:
        assert f"[{rec['id']}]" in prompt, rec["id"]
    assert "candidate recommendation that has not been evaluated" in completion, "the mock's canned text"
    for text in (prompt, completion, json.dumps(e2e_app.read_chain(f"run:{on.run_id}"), default=str)):
        assert h.MOCK_PYTHIA_API_KEY not in text and "Bearer pk_" not in text
    usage = _llm_usage_rows(e2e_app, on.run_id)
    assert len(usage) == 1, usage
    assert usage[0]["task"] == "ml.harden_narrative" and usage[0]["model"] == h.MOCK_PYTHIA_MODEL
    assert usage[0]["project_id"] == e2e_org.project_id

    # -- OFF: the gateway is configured but REDSIM_DISABLE_LLM=1 stops the call before the transport --
    pythia.on()
    pythia.disable_llm(True)
    try:
        off = _narrated(e2e_org, model_id)
    finally:
        pythia.disable_llm(False)
        pythia.off()
    campaign = off.campaign
    assert campaign is not None
    assert off.status == "succeeded" and campaign["status"] == "succeeded", "the narrative never fails the job"
    assert off.stage_table["stages"]["report"]["status"] == "succeeded"
    recs = campaign["recommendations"]
    assert recs and {rec["narrative_source"] for rec in recs} == {"rules"}
    assert all(rec["narrative"] is None for rec in recs)
    assert len(pythia.requests) == 0, "no request may reach the mocked transport when the writer is disabled"
    assert campaign["provenance"]["llm"] is None
    assert any("REDSIM_DISABLE_LLM" in item for item in campaign["limitations"]), campaign["limitations"]
    harden = _events(e2e_app, f"run:{off.run_id}", "harden.execute")
    assert harden and harden[-1]["success"] is True
    detail = harden[-1]["detail"]
    assert detail["llm_used"] is False and detail["narrative_source"] == "rules"
    assert detail["llm_requested"] is True
    assert "REDSIM_DISABLE_LLM" in str(detail["skipped_reason"]), detail
    assert detail["prompt_sha256"] is None and detail["completion_sha256"] is None
    kinds = {row["kind"] for row in _artifact_rows(viewer, off.run_id).values()}
    assert not ({"ml.harden.prompt", "ml.harden.completion", "ml.harden.narrative"} & kinds), sorted(kinds)
    assert _llm_usage_rows(e2e_app, off.run_id) == []
    assert _events(e2e_app, f"run:{off.run_id}", "job.complete")[-1]["detail"]["status"] == "succeeded"


# ---------------------------------------------------------------------------
# 4. Rerun: lineage through parent_run_id, the terminal parent never mutated
# ---------------------------------------------------------------------------


def test_rerun_links_parent_and_never_mutates_terminal(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], image_run: h.CampaignRun,
) -> None:
    from redsim.api.errors import PARAMS_OUT_OF_RANGE, RUN_TERMINAL
    from redsim.config import load_config
    from redsim.services.ml_campaigns import create_attack_campaign

    model_id = e2e_bundled[h.IMAGE_MODEL_ID]
    scanner = e2e_org.client("scanner")
    remediator = e2e_org.client("remediator")

    # A queued campaign. Eager Celery runs the job inside the POST, so the same admission service the
    # route calls is used with ``enqueue=False``: the audit row, Run, Job and campaign rows exist and the
    # run is ``queued``, which is the only state ``POST /v1/runs/{id}/cancel`` admits.
    body = h.image_campaign()
    body["target_id"] = model_id
    handle = create_attack_campaign(
        campaign=body, project_id=e2e_org.project_id, actor=e2e_org.actor("scanner"),
        config=load_config(), audit_writer=e2e_app.audit_writer(), enqueue=False,
    )
    parent_id = handle.run_id
    queued = scanner.get(f"/v1/runs/{parent_id}")
    assert queued.status_code == 200 and queued.json()["status"] == "queued", queued.text
    assert _events(e2e_app, f"run:{parent_id}", "attack.run")[0]["detail"]["rerun"] is False

    # Cancel through the route (remediator): audit row first, then the run and its job are cancelled.
    cancel = remediator.post(f"/v1/runs/{parent_id}/cancel")
    assert cancel.status_code == 200, cancel.text
    assert cancel.json() == {"run_id": parent_id, "status": "cancelled", "jobs_cancelled": 1}
    parent = scanner.get(f"/v1/runs/{parent_id}").json()
    assert parent["status"] == "cancelled" and parent["completed_at"] is not None
    assert [j["status"] for j in _job_rows(e2e_app, parent_id)] == ["cancelled"]
    cancel_rows = _events(e2e_app, f"run:{parent_id}", "run.cancel")
    assert len(cancel_rows) == 1 and cancel_rows[0]["success"] is True
    assert cancel_rows[0]["actor"] == e2e_org.actor("remediator")
    parent_chain_before = _canonical(e2e_app.read_chain(f"run:{parent_id}"))
    before = _record_snapshot(e2e_app, scanner, parent_id)

    # Rerun: parent_run_id alone; the parent's configuration is copied and every admission check re-runs.
    launch = scanner.post(f"/v1/models/{model_id}/attacks", json={"parent_run_id": parent_id})
    assert launch.status_code == 202, launch.text
    child_id = str(launch.json()["run_id"])
    (child_job_id,) = launch.json()["job_ids"]
    assert child_id != parent_id and launch.json()["status_url"] == f"/v1/runs/{child_id}"
    child_run = h.wait_for_run(scanner, child_id)
    assert child_run["status"] == "succeeded", child_run.get("stage_table")
    assert child_run["stage_table"]["parent_run_id"] == parent_id
    assert child_run["stage_table"]["stages"]["report"]["status"] == "succeeded"
    assert child_run["stage_table"]["jobs"][child_job_id]["status"] == "succeeded"

    record_response = scanner.get(f"/v1/runs/{child_id}/campaign")
    assert record_response.status_code == 200, record_response.text
    record = record_response.json()
    assert record["run_id"] == child_id and record["status"] == "succeeded"
    assert record["parent_run_id"] == parent_id, "lineage on the record (spec 26.1 item 3)"
    assert record["provenance"]["parent_run_id"] == parent_id, "lineage in provenance (spec 14.4)"
    assert record["baseline_run_id"] is None, "a rerun is not a verify pairing"
    parent_row = _campaign_row(e2e_app, parent_id)
    child_row = _campaign_row(e2e_app, child_id)
    assert child_row["parent_run_id"] == parent_id and parent_row["parent_run_id"] is None
    assert child_row["kind"] == "attack" and child_row["target_id"] == parent_row["target_id"] == model_id
    parent_config = parent_row["config"]
    for key in ("attack_ids", "attack_params", "norm", "eps_grid", "reference_eps", "finding_asr_threshold",
                "n_samples", "seed", "include_control", "explain_k", "dataset_id", "dataset_revision",
                "dataset_split", "scoring", "modality"):
        assert record["config"][key] == parent_config[key], key
    assert child_row["settings_hash"] == parent_row["settings_hash"], "same configuration, same model, same hash"
    assert record["settings_hash"] == parent_row["settings_hash"]
    job_detail = _job_rows(e2e_app, child_id)[0]["detail"]
    assert job_detail["parent_run_id"] == parent_id
    admission = _events(e2e_app, f"run:{child_id}", "attack.run")
    assert len(admission) == 1 and admission[0]["success"] is True
    assert admission[0]["detail"]["rerun"] is True and admission[0]["detail"]["parent_run_id"] == parent_id
    assert admission[0]["actor"] == e2e_org.actor("scanner")

    # The original is byte-identical: run, jobs, campaign row, artifacts and its chain.
    after = _record_snapshot(e2e_app, scanner, parent_id)
    assert after == before, {k: (before[k], after[k]) for k in before if before[k] != after[k]}
    assert _canonical(e2e_app.read_chain(f"run:{parent_id}")) == parent_chain_before

    # A second cancel on the terminal parent is refused with the documented code and mutates nothing
    # but the chain, which keeps the refused admission as its ordering record (spec 10.7, 17.3).
    again = remediator.post(f"/v1/runs/{parent_id}/cancel")
    assert again.status_code == 409, again.text
    assert again.json()["detail"]["code"] == RUN_TERMINAL == "run_terminal"
    assert again.json()["detail"]["status"] == "cancelled"
    assert _record_snapshot(e2e_app, scanner, parent_id) == before
    refused_cancels = [ev for ev in _events(e2e_app, f"run:{parent_id}", "run.cancel") if not ev["success"]]
    assert len(refused_cancels) == 1 and refused_cancels[0]["detail"]["reason"] == "run_terminal"

    # A succeeded parent is not rerun (spec 10.6: retry applies to failed / cancelled campaigns);
    # the refusal carries the documented code, names the field and the parent's status, and the
    # succeeded run itself stays byte-identical.
    succeeded_before = _record_snapshot(e2e_app, scanner, image_run.run_id)
    refused = scanner.post(f"/v1/models/{model_id}/attacks", json={"parent_run_id": image_run.run_id})
    assert refused.status_code == 422, refused.text
    detail = refused.json()["detail"]
    assert detail["code"] == PARAMS_OUT_OF_RANGE == "params_out_of_range"
    assert detail["field"] == "parent_run_id" and detail["status"] == "succeeded"
    assert _record_snapshot(e2e_app, scanner, image_run.run_id) == succeeded_before
    assert scanner.get(f"/v1/runs/{image_run.run_id}").json()["status"] == "succeeded"
