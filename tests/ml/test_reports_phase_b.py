"""Phase B reports, snapshots, N-run comparison and per-project weights (plan 12 wave B2).

Register rows REVIEW_REPORTS-15..22, -26, -28, -30. Offline over the ``ml_api``
harness of ``test_findings_routes.py`` (sqlite, in-memory blobs and audit
writer, dependency-overridden caller) plus the hand-built records of
``test_report.py`` for the pure renderers.

* PDF: ``%PDF-`` magic, byte-identical for identical inputs, the six spec 14.8
  sections in order with the ``ε`` glyph, ``MRI not computed`` on a partial
  record, the non-default-weights badge, ``schema_version`` in section 1;
  ``render_campaign_reports`` adds the PDF only when asked.
* Snapshots: the render admission is audit-first and refuses a second render in
  flight; the worker task writes one immutable ``report_snapshots`` row per
  render whose artifact ids and digests equal the ``Artifact`` rows; a second
  render leaves the first untouched; ``?snapshot=`` serves the old bytes; the
  admin archive flag is audited, hides nothing from the list, refuses a
  non-admin fetch and restores.
* N-run compare: request-order rows, one scorecard per row and no delta, mean
  or rank key anywhere, ``409`` on an incompatible pair
  (naming the pair) or a partial score, ``403`` before any body for a foreign
  run, ``422`` outside 2..10 ids, ``scoring.weights`` named for a differing vector.
* Weights: ``GET`` default, admin ``PUT`` of a full vector, partial or non-unit
  vectors refused (422) and audited as refusals, non-admin 403, ``null`` resets,
  ``/campaign`` carries ``non_default_weights``.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")
pytest.importorskip("reportlab")
pytest.importorskip("pypdf")

import pypdf
from sqlalchemy import select

from redsim.db.models import Artifact, Job, ReportSnapshot, Run
from redsim.ml import compare as cmp
from redsim.ml.pdf import PDF_MAGIC, PDF_SECTION_HEADINGS, render_pdf
from redsim.ml.reporting import (
    DEFAULT_WEIGHTS_NOTE,
    DETECTION_EVIDENCE_HEADING,
    DETECTION_SCORECARD_HEADING,
    EXPORT_REDACTION_NOTE,
    LICENCE_UNRECORDED,
    LLM_EMBED_NOTE,
    LLM_HEADING,
    NON_DEFAULT_WEIGHTS_BADGE,
    REPORT_FORMATS_ALL,
    SECTION_HEADINGS,
    TEXT_BUDGET_HEADING,
    TEXT_EVIDENCE_HEADING,
    is_llm_probe_record,
    render_campaign_reports,
    render_html,
    render_markdown,
)
from redsim.ml.schema import (
    AttackInfo,
    CampaignConfig,
    CampaignRecord,
    DetectionMetrics,
    DetectionObservation,
    Measurement,
    MRIWeights,
    Observation,
    ScoreStatus,
    ScoringConfig,
    TargetInfo,
    TextObservation,
)
from tests.ml.test_findings_routes import (  # noqa: F401 - fixture import
    BASELINE,
    FOREIGN,
    OTHER_MODEL,
    OTHER_PROJECT,
    OTHER_SEED,
    PARTIAL,
    PLAIN,
    PROJECT,
    MemoryBlobStore,
    RecordingAuditWriter,
    _sha,
    _user,
    ml_api,
)
from tests.ml.test_report import NOW, _record, _score

pytestmark = pytest.mark.integration

FIXTURE = Path(__file__).parent / "fixtures" / "run_record.json"
CUSTOM_WEIGHTS = {"acc": 0.5, "asr": 0.2, "eps": 0.1, "conf": 0.1, "expl": 0.1}
OTHER_WEIGHTS = "run-other-weights"


@pytest.fixture(autouse=True)
def _no_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """The shared harness app keeps the default write limiter; these tests issue many writes."""
    monkeypatch.setattr("redsim.api.middleware.rate_limit._is_throttled", lambda _m, _p: False)


@pytest.fixture(autouse=True)
def _no_broker(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """No Celery broker in tests: the enqueue records the job id instead of calling ``delay``."""
    calls: list[str] = []

    def fake_enqueue(job_id: str) -> str:
        calls.append(job_id)
        return f"task-{job_id}"

    monkeypatch.setattr("redsim.services.reports._enqueue_report_render", fake_enqueue)
    return calls


def _call(api: dict[str, Any], user: Any, method: str, url: str, **kwargs: Any) -> Any:
    client = api["as_user"](user)
    client._holder["user"] = client.user
    return client._client.request(method, url, **kwargs)


def _pdf_text(data: bytes) -> str:
    reader = pypdf.PdfReader(io.BytesIO(data))
    return "\n".join(page.extract_text() for page in reader.pages)


def _flat(text: str) -> str:
    """PDF text with wrapping normalised: pypdf yields one line per typeset line, so a table cell that
    wrapped at a space comes back with a newline where the space was."""
    return " ".join(text.split())


def _unscored(**overrides: Any) -> dict[str, Any]:
    """Record fields of a run that carries no MRI: text, detection and LLM probe records are scorecard runs."""
    return {
        "score": None, "score_status": ScoreStatus(state="unavailable", reason="no MRI for this modality"),
        "curve": [], "interpretation": [], "recommendations": [], **overrides,
    }


def _text_record() -> CampaignRecord:
    """A text campaign the way the text runner records it: edit budget, realised edit fraction, word positions."""
    config = CampaignConfig(
        target_id="sms_tfidf_lr", modality="text", attack_ids=["word_substitution"], norm="edit",
        eps_grid=[0.1, 0.2, 0.3], reference_eps=0.2, n_samples=200, seed=0, explain_k=8,
        dataset_id="uci:sms-spam-collection", dataset_revision="rev-1",
    )
    measurements = [
        Measurement(id="m.clean", family="clean", n=200, n_correct=180, accuracy=0.9),
        Measurement(id="m.evasion.word_substitution.eps0.2", family="evasion", attack_id="word_substitution",
                    params={"eps": 0.2, "norm": "edit"}, n=200, n_correct=120, accuracy=0.6,
                    n_flipped_from_clean=60, n_clean_correct=180, attack_success_rate=round(60 / 180, 4),
                    edit_fraction_mean=0.1875, wall_time_s=3.5),
        Measurement(id="m.control.noise.eps0.2", family="control", attack_id="text_noise_control",
                    params={"eps": 0.2, "norm": "edit"}, n=200, n_correct=176, accuracy=0.88,
                    n_flipped_from_clean=4, n_clean_correct=180, attack_success_rate=round(4 / 180, 4),
                    edit_fraction_mean=0.19),
    ]
    observation = Observation(
        id="o.000", sample_index=5, true_label="spam", pred_clean="spam", pred_adv="ham", flipped=True,
        confidence_clean=0.97, confidence_adv=0.58, artifacts={"text_diff": "art-o.000-diff"},
        metric_note="token attribution shift over aligned word positions",
        text=TextObservation(n_tokens=12, n_changed=2, changed_positions=[3, 7], edit_fraction=2 / 12,
                             top_tokens_clean=[3, 0, 7], top_tokens_adv=[7, 3, 1],
                             attribution_artifacts={"shap_text": "art-o.000-shap"}),
    )
    return _record(
        run_id="run-text-1", config=config, measurements=measurements, observations=[observation],
        target=TargetInfo(id="sms_tfidf_lr", name="SMS spam classifier", domain="text", status="available"),
        attacks=[AttackInfo(id="word_substitution", name="Word substitution", domain="text", family="evasion")],
        **_unscored(),
    )


def _detection_record() -> CampaignRecord:
    """A detection campaign: box counts on every row (``Measurement.detection``), a patch box per observation."""
    config = CampaignConfig(
        target_id="assets_frcnn_mnv3", modality="detection", attack_ids=["dpatch"], norm="patch_area",
        eps_grid=[0.01, 0.03, 0.05], reference_eps=0.03, n_samples=50, seed=0, explain_k=8,
        dataset_id="kaggle:military-assets", dataset_revision="rev-1",
    )
    measurements = [
        Measurement(id="m.clean", family="clean", n=120, n_correct=96, accuracy=0.8,
                    detection=DetectionMetrics(n_boxes=120, n_matched=96, map50=0.71, recall=0.8)),
        Measurement(id="m.evasion.dpatch.eps0.03", family="evasion", attack_id="dpatch",
                    params={"eps": 0.03, "norm": "patch_area"}, n=120, n_correct=60, accuracy=0.5,
                    n_flipped_from_clean=36, n_clean_correct=96, attack_success_rate=0.375, wall_time_s=91.2,
                    detection=DetectionMetrics(n_boxes=120, n_matched=60, map50=0.4, recall=0.5,
                                               suppression_rate=0.375)),
    ]
    observation = Observation(
        id="o.003.dpatch", sample_index=3, true_label="tank", pred_clean="4/4 boxes matched",
        pred_adv="2/4 boxes matched", flipped=True, confidence_clean=0.9, confidence_adv=0.7,
        artifacts={"boxes": "art-o.003-boxes"}, metric_note="no attribution metric for detection",
        detection=DetectionObservation(n_gt=4, n_matched_clean=4, n_matched_adv=2, patch_bbox=[10, 12, 42, 44]),
    )
    return _record(
        run_id="run-detection-1", config=config, measurements=measurements, observations=[observation],
        target=TargetInfo(id="assets_frcnn_mnv3", name="Military assets detector", domain="detection",
                          status="available"),
        attacks=[AttackInfo(id="dpatch", name="DPatch", domain="detection", family="evasion")],
        **_unscored(),
    )


def _llm_probe_record() -> CampaignRecord:
    """A probe run carried as a CampaignRecord: an LLM endpoint target and the scorecard dump in the manifest."""
    from redsim.ml.llm.scorecard import (
        DetectorResult,
        LLMProbeScorecard,
        ProbeFamilyResult,
        ProbeResult,
        llm_standing_limitations,
    )

    card = LLMProbeScorecard(
        run_id="run-probe-1", target_id="llm-gateway-1", model_id="openai/gpt-4o-mini",
        gateway_host="pythia.example.test", guardrail_mode="permission_gate_only", garak_version="0.16.0",
        catalog_garak_version="0.16.0", probe_ids_requested=["dan.Dan_11_0"],
        families=[ProbeFamilyResult(family="dan", n_probes_run=1, probes=[ProbeResult(
            probe_id="dan.Dan_11_0", short_id="Dan_11_0", family="dan", status="run", n_prompts_sent=4, n_outputs=4,
            detectors=[DetectorResult(row_id="dan.Dan_11_0/dan.DAN", detector="dan.DAN", n_evaluated=4, n_hits=1,
                                      n_passed=3, hit_rate=0.25)],
        )])],
        limitations=llm_standing_limitations(guardrail_mode="permission_gate_only", max_prompts_per_probe=16,
                                             seed=0, garak_version="0.16.0"),
    )
    provenance = _record().provenance.model_dump(mode="json")  # type: ignore[union-attr]
    provenance["model_manifest"] = {"endpoint": {"kind": "llm"}, "llm_scorecard": card.model_dump(mode="json")}
    return _record(
        run_id="run-probe-1", provenance=provenance, measurements=[], observations=[],
        target=TargetInfo(id="llm-gateway-1", name="Gateway LLM", domain="llm", status="available",
                          metadata={"endpoint_kind": "llm", "model_id": "openai/gpt-4o-mini"}),
        **_unscored(),
    )


def _custom_weights_record() -> CampaignRecord:
    weights = MRIWeights(**CUSTOM_WEIGHTS)
    config = CampaignConfig(
        target_id="tiny", modality="image", attack_ids=["fgsm"], eps_grid=[0.03], reference_eps=0.03,
        n_samples=200, seed=0, explain_k=8, dataset_id="synthetic", dataset_revision="rev-1",
        scoring=ScoringConfig(weights=weights),
    )
    return _record(config=config, score=_score().model_copy(update={"weights": weights}))


# --------------------------------------------------------------------------- PDF (REVIEW_REPORTS-15, -16)


def test_pdf_is_deterministic_and_carries_the_six_sections_with_glyphs() -> None:
    record = CampaignRecord.model_validate_json(FIXTURE.read_bytes())
    first = render_pdf(record, generated_at=NOW)
    second = render_pdf(record, generated_at=NOW)
    assert first.startswith(PDF_MAGIC) and first == second, "identical inputs give identical bytes"
    text = _pdf_text(first)
    positions = [text.find(heading) for heading in PDF_SECTION_HEADINGS]
    assert all(p >= 0 for p in positions), dict(zip(PDF_SECTION_HEADINGS, positions, strict=True))
    assert positions == sorted(positions), "spec 14.8 fixes the section order"
    assert "MRI 42" in text and "grade D" in text
    assert "ε" in text, "the bundled DejaVu face renders the epsilon glyph"
    assert "campaign-record-1" in text, "schema_version is disclosed in section 1 (REVIEW_REPORTS-18)"
    assert DEFAULT_WEIGHTS_NOTE.split(" ")[0] in text and "Non-default weights" not in text
    assert "112/200" in text, "every rate travels with its fraction"
    # A different stamp is a different document; the record itself is unchanged.
    assert render_pdf(record, generated_at=datetime(2026, 9, 10, tzinfo=UTC)) != first


def test_pdf_partial_record_says_mri_not_computed() -> None:
    partial = json.loads(FIXTURE.read_text())
    partial["completeness"] = "partial"
    partial["missing"] = ["S_expl unavailable (explainer failed)"]
    partial["score"].update({"mri": None, "grade": None, "completeness": "partial",
                             "missing": ["S_expl unavailable (explainer failed)"]})
    partial["score"]["subscores"]["S_expl"] = None
    text = _pdf_text(render_pdf(CampaignRecord.model_validate(partial), generated_at=NOW))
    assert "MRI not computed" in text and "grade D" not in text and "MRI 42" not in text
    attack_text = _pdf_text(render_pdf(_record(), generated_at=NOW))
    assert "ΔMRI" not in attack_text and "Expected gain" not in attack_text, "one measurement, no delta"


def test_non_default_weights_badge_in_markdown_and_pdf(monkeypatch: pytest.MonkeyPatch) -> None:
    record = _custom_weights_record()
    outputs = {name: data for name, data, _ct in render_campaign_reports(record, generated_at=NOW,
                                                                         formats=REPORT_FORMATS_ALL)}
    md = outputs["report.md"].decode()
    assert NON_DEFAULT_WEIGHTS_BADGE in md and "acc = 0.5" in md
    assert md.count(NON_DEFAULT_WEIGHTS_BADGE) == 1, "one badge, in the scorecard block"
    assert "(**non-default weights**)" in md, "section 1 names the vector as non-default too"
    assert "Non-default weights" in _pdf_text(outputs["report.pdf"])
    # The default vector prints the default note, never the badge.
    default_md = next(d for n, d, _c in render_campaign_reports(_record(), generated_at=NOW)).decode()
    assert NON_DEFAULT_WEIGHTS_BADGE not in default_md and DEFAULT_WEIGHTS_NOTE in default_md
    assert cmp.is_default_weights(MRIWeights()) and not cmp.is_default_weights(CUSTOM_WEIGHTS)
    assert not cmp.is_default_weights({"acc": 0.5}), "a partial vector is never the default vector"


def test_render_campaign_reports_adds_pdf_only_when_asked() -> None:
    record = _record()
    names = [name for name, _d, _c in render_campaign_reports(record, generated_at=NOW)]
    assert names == ["report.md", "report.json", "report.html"], "the Phase A set is the default"
    full = render_campaign_reports(record, generated_at=NOW, formats=REPORT_FORMATS_ALL)
    assert [name for name, _d, _c in full] == ["report.md", "report.json", "report.html", "report.pdf"]
    name, data, content_type = full[-1]
    assert content_type == "application/pdf" and data.startswith(PDF_MAGIC)
    only_pdf = render_campaign_reports(record, generated_at=NOW, formats=["pdf"])
    assert [n for n, _d, _c in only_pdf] == ["report.pdf"] and only_pdf[0][1] == data
    with pytest.raises(ValueError, match="unknown report formats"):
        render_campaign_reports(record, formats=["docx"])
    # schema_version is in the Markdown configuration section (REVIEW_REPORTS-18).
    md = full[0][1].decode()
    section_1 = md[md.find(SECTION_HEADINGS[0]):md.find(SECTION_HEADINGS[1])]
    assert "**Schema version:** `campaign-record-1`" in section_1
    # REVIEW_REPORTS-19: the licence line and the open-D006 export-redaction sentence, in md and pdf.
    assert f"**Licence (model and dataset manifests):** {LICENCE_UNRECORDED}" in section_1
    section_6 = md[md.find(SECTION_HEADINGS[5]):]
    assert EXPORT_REDACTION_NOTE in section_6 and "export-redaction" in _pdf_text(data)
    licensed = _record(config=CampaignConfig(
        target_id="tiny", modality="image", attack_ids=["fgsm"], eps_grid=[0.03], reference_eps=0.03,
        n_samples=200, seed=0, explain_k=8, dataset_id="synthetic", dataset_revision="rev-1",
        target_snapshot={"manifest": {"license": "CC BY 4.0"}},
    ))
    licensed_md = next(d for n, d, _c in render_campaign_reports(licensed, generated_at=NOW)).decode()
    assert "**Licence (model and dataset manifests):** CC BY 4.0" in licensed_md


# --------------------------------------------------------------------------- snapshots (REVIEW_REPORTS-20..22)


def _render_through_worker(api: dict[str, Any], monkeypatch: pytest.MonkeyPatch, job_id: str) -> dict[str, Any]:
    """Run ``redsim.report_render`` for ``job_id`` the way the worker does, over the harness."""
    pytest.importorskip("celery")
    from redsim.state import PostgresRunState
    from redsim.workers.tasks.report import report_render

    store: MemoryBlobStore = api["store"]
    writer: RecordingAuditWriter = api["writer"]
    sessions = api["sessions"]

    @contextmanager
    def fake_task_context(job_id_: str, task: Any = None) -> Any:
        from redsim.workers.bootstrap import TaskContext

        with sessions.begin() as session:
            run_state = PostgresRunState(session, run_id=BASELINE, project_id=PROJECT,
                                         output_dir=api["tmp_path"], blob_store=store)
            yield TaskContext(job_id=job_id_, run_id=BASELINE, project_id=PROJECT, session=session,
                              blob_store=store, run_state=run_state, audit_writer=writer, actor="user:exporter")

    monkeypatch.setattr("redsim.workers.bootstrap.task_context", fake_task_context)
    result: dict[str, Any] = report_render.apply(args=[job_id]).get()
    # The real ``task_context`` closes the Job row; the fake one leaves that to the test.
    with sessions.begin() as session:
        session.get(Job, job_id).status = "succeeded"
    return result


def test_render_admission_is_audit_first_and_refuses_a_second_render_in_flight(
    ml_api: dict[str, Any], _no_broker: list[str],  # noqa: F811
) -> None:
    writer: RecordingAuditWriter = ml_api["writer"]
    sessions = ml_api["sessions"]
    scanner = _user("exporter", "scanner")

    def _no_job_yet(event: dict[str, Any]) -> None:
        if event["action"] == "report.render" and event["success"]:
            with sessions() as check:
                assert check.query(Job).filter(Job.run_id == BASELINE, Job.type == "report.render").count() == 0

    writer.on_append = _no_job_yet
    resp = _call(ml_api, scanner, "POST", f"/v1/runs/{BASELINE}/report.render", json={})
    writer.on_append = None
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["run_id"] == BASELINE and body["status"] == "queued" and body["type"] == "report.render"
    assert body["formats"] == ["md", "json", "html", "pdf"] and body["job_ids"] == [body["job_id"]]
    assert _no_broker == [body["job_id"]], "the enqueue follows the audit row and the Job row"
    with sessions() as sess:
        job = sess.get(Job, body["job_id"])
        assert job is not None and job.status == "queued" and job.celery_task_id == f"task-{body['job_id']}"
        assert job.detail["formats"] == body["formats"]
        assert sess.get(Run, BASELINE).status == "succeeded", "a render never reopens the run (spec 6.2)"
    admitted = writer.last("report.render")
    assert admitted.success is True and admitted.run_id == BASELINE and admitted.project_id == PROJECT
    assert admitted.detail["job_id"] == body["job_id"] and admitted.detail["phase"] == "admitted"

    # A second render while the first is queued is refused, on the chain as success=False.
    again = _call(ml_api, scanner, "POST", f"/v1/runs/{BASELINE}/report.render", json={"formats": ["pdf"]})
    assert again.status_code == 409 and again.json()["detail"]["code"] == "job_in_flight"
    refused = writer.last("report.render")
    assert refused.success is False and refused.detail["refusal"] == "job_in_flight"
    assert refused.detail["in_flight_job_id"] == body["job_id"]
    with sessions() as sess:
        assert sess.query(Job).filter(Job.run_id == BASELINE, Job.type == "report.render").count() == 1

    # Gates and shape checks.
    assert _call(ml_api, _user("reader", "viewer"), "POST", f"/v1/runs/{BASELINE}/report.render").status_code == 403
    outsider = _user("outsider", "admin", project=OTHER_PROJECT)
    assert _call(ml_api, outsider, "POST", f"/v1/runs/{BASELINE}/report.render").status_code == 403
    assert _call(ml_api, scanner, "POST", "/v1/runs/run-missing/report.render").status_code == 404
    plain = _call(ml_api, scanner, "POST", f"/v1/runs/{PLAIN}/report.render")
    assert plain.status_code == 404, "a run that is not a campaign has no record to render"
    bad = _call(ml_api, scanner, "POST", f"/v1/runs/{OTHER_SEED}/report.render", json={"formats": ["docx"]})
    assert bad.status_code == 422 and bad.json()["detail"]["code"] == "params_out_of_range"
    assert bad.json()["detail"]["field"] == "formats"
    # A live run is refused with campaign_not_terminal and a success=False row.
    with sessions.begin() as sess:
        sess.get(Run, OTHER_MODEL).status = "running"
    live = _call(ml_api, scanner, "POST", f"/v1/runs/{OTHER_MODEL}/report.render")
    assert live.status_code == 409 and live.json()["detail"]["code"] == "campaign_not_terminal"
    assert writer.last("report.render").success is False


def test_snapshots_are_immutable_rows_over_the_artifacts_and_pdf_is_served(
    ml_api: dict[str, Any], monkeypatch: pytest.MonkeyPatch,  # noqa: F811
) -> None:
    scanner = _user("exporter", "scanner")
    sessions = ml_api["sessions"]
    store: MemoryBlobStore = ml_api["store"]

    # Before any render: no snapshot, and the PDF is 404 (never a filesystem fallback).
    empty = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/snapshots")
    assert empty.status_code == 200 and empty.json() == {"run_id": BASELINE, "snapshots": [], "count": 0}
    missing_pdf = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/report.pdf")
    assert missing_pdf.status_code == 404 and missing_pdf.json()["detail"] == "report not yet rendered"
    assert _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/report.pdf?snapshot=1").status_code == 404

    first_job = _call(ml_api, scanner, "POST", f"/v1/runs/{BASELINE}/report.render", json={}).json()["job_id"]
    result = _render_through_worker(ml_api, monkeypatch, first_job)
    assert result["formats"] == ["md", "json", "html", "pdf"]
    assert set(result["artifacts"]) == {"md", "json", "html", "pdf"}

    listed = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/snapshots").json()
    assert listed["count"] == 1
    snap = listed["snapshots"][0]
    assert snap["version"] == 1 and snap["archived"] is False and snap["created_by"] == "user:exporter"
    assert snap["record_sha256"] == _sha(ml_api["records"][BASELINE].model_dump_json().encode())
    assert set(snap["formats"]) == {"md", "json", "html", "pdf"}
    with sessions() as sess:
        rows = {str(r.id): r for r in sess.execute(select(Artifact).where(Artifact.run_id == BASELINE)).scalars()}
        row = sess.get(ReportSnapshot, snap["id"])
        assert row is not None and list(row.artifact_ids) == snap["artifact_ids"]
        for ext, entry in snap["formats"].items():
            artifact = rows[entry["artifact_id"]]
            assert artifact.kind == f"ml.report_{ext}" and artifact.sha256 == entry["sha256"]
            assert artifact.size_bytes == entry["size_bytes"] == len(store.get(artifact.location))
            assert result["artifacts"][ext]["sha256"] == entry["sha256"]
            assert result["artifacts"][ext]["artifact_id"] == entry["artifact_id"]
    by_ref = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/snapshots/1").json()
    assert by_ref == snap
    assert _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/snapshots/{snap['id']}").json() == snap
    unknown = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/snapshots/99")
    assert unknown.status_code == 404 and unknown.json()["detail"]["code"] == "snapshot_not_found"

    # The PDF route serves the snapshot's artifact with the download headers and the digest as ETag.
    pdf = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(PDF_MAGIC)
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.headers["content-disposition"].startswith("attachment") and "report.pdf" in pdf.headers["content-disposition"]
    assert pdf.headers["x-content-type-options"] == "nosniff"
    assert pdf.headers["etag"] == f'"{snap["formats"]["pdf"]["sha256"]}"' == f'"{_sha(pdf.content)}"'
    text = _pdf_text(pdf.content)
    assert "MRI 42" in text and PDF_SECTION_HEADINGS[0] in text
    assert _call(ml_api, _user("reader", "viewer"), "GET", f"/v1/runs/{BASELINE}/report.pdf").status_code == 403
    first_md = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/report.md")
    assert first_md.status_code == 200 and first_md.headers["etag"] == f'"{snap["formats"]["md"]["sha256"]}"'

    # A second render (with reviewer notes changed) is a second row; the first is untouched.
    with sessions.begin() as sess:
        table = ml_api["campaigns"]
        sess.execute(table.update().where(table.c.run_id == BASELINE).values(reviewer_notes="Second look."))
    second_job = _call(ml_api, scanner, "POST", f"/v1/runs/{BASELINE}/report.render", json={}).json()["job_id"]
    _render_through_worker(ml_api, monkeypatch, second_job)
    listed = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/snapshots").json()
    assert listed["count"] == 2 and [s["version"] for s in listed["snapshots"]] == [2, 1], "newest first"
    newest, oldest = listed["snapshots"]
    assert oldest == snap, "the first snapshot row did not change"
    assert newest["record_sha256"] == snap["record_sha256"], "same record bytes, a new projection"
    assert newest["formats"]["md"]["sha256"] != snap["formats"]["md"]["sha256"]
    latest_md = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/report.md")
    assert "Second look." in latest_md.text and latest_md.headers["etag"] == f'"{newest["formats"]["md"]["sha256"]}"'
    old_md = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/report.md?snapshot=1")
    assert old_md.status_code == 200 and old_md.content == first_md.content
    assert old_md.headers["etag"] == first_md.headers["etag"] and "Second look." not in old_md.text
    assert _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/report.pdf?snapshot={snap['id']}").content == pdf.content
    # Tampered bytes are never served as the snapshot.
    store.blobs[[loc for loc in store.blobs if loc.endswith(snap["formats"]["pdf"]["sha256"])][0]] = b"%PDF-tampered"
    tampered = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/report.pdf?snapshot=1")
    assert tampered.status_code == 409 and tampered.json()["detail"]["code"] == "report_artifact_digest_mismatch"

    # Audit: two admission rows and two worker rows named report.render, formats listed.
    writer: RecordingAuditWriter = ml_api["writer"]
    renders = [e for e in writer.events if e.action == "report.render" and e.success]
    assert len(renders) == 4 and all(e.detail["formats"] == ["md", "json", "html", "pdf"] for e in renders)


def test_snapshot_archive_is_an_audited_admin_soft_flag(ml_api: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    scanner = _user("exporter", "scanner")
    admin = _user("owner", "admin")
    writer: RecordingAuditWriter = ml_api["writer"]
    sessions = ml_api["sessions"]
    job_id = _call(ml_api, scanner, "POST", f"/v1/runs/{BASELINE}/report.render", json={}).json()["job_id"]
    _render_through_worker(ml_api, monkeypatch, job_id)
    snap = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/snapshots/1").json()
    before_count = len(writer.events)

    # Only an admin archives; a remediator is refused before any audit row.
    remediator = _user("fixer", "remediator")
    assert _call(ml_api, remediator, "POST", f"/v1/runs/{BASELINE}/snapshots/1/archive").status_code == 403
    assert _call(ml_api, scanner, "POST", f"/v1/runs/{BASELINE}/snapshots/1/archive").status_code == 403
    assert len(writer.events) == before_count
    outsider = _user("outsider", "admin", project=OTHER_PROJECT)
    assert _call(ml_api, outsider, "POST", f"/v1/runs/{BASELINE}/snapshots/1/archive").status_code == 403
    missing = _call(ml_api, admin, "POST", f"/v1/runs/{BASELINE}/snapshots/7/archive")
    assert missing.status_code == 404 and missing.json()["detail"]["code"] == "snapshot_not_found"

    archived = _call(ml_api, admin, "POST", f"/v1/runs/{BASELINE}/snapshots/1/archive")
    assert archived.status_code == 200, archived.text
    assert archived.json()["archived"] is True and archived.json()["changed"] is True
    event = writer.last("report.snapshot.archive")
    assert event.success is True and event.run_id == BASELINE and event.project_id == PROJECT
    assert event.detail["snapshot_id"] == snap["id"] and event.detail["record_sha256"] == snap["record_sha256"]
    assert event.detail["archived_after"] is True and "bytes" not in json.dumps(event.detail)

    # The list still shows the row (flagged); a non-admin fetch of it is refused; an admin reads it.
    listed = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/snapshots").json()
    assert listed["count"] == 1 and listed["snapshots"][0]["archived"] is True
    refused = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/snapshots/1")
    assert refused.status_code == 409 and refused.json()["detail"]["code"] == "snapshot_archived"
    refused_pdf = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/report.pdf?snapshot=1")
    assert refused_pdf.status_code == 409 and refused_pdf.json()["detail"]["code"] == "snapshot_archived"
    assert _call(ml_api, admin, "GET", f"/v1/runs/{BASELINE}/snapshots/1").json()["archived"] is True
    assert _call(ml_api, admin, "GET", f"/v1/runs/{BASELINE}/report.pdf?snapshot=1").status_code == 200
    # With every snapshot archived the unqualified route has no snapshot to serve; the
    # newest artifact row of the kind still answers (the bytes were never deleted).
    assert _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/report.pdf").status_code == 200
    with sessions() as sess:
        row = sess.get(ReportSnapshot, snap["id"])
        assert row.archived is True and list(row.artifact_ids) == snap["artifact_ids"]
        assert row.record_sha256 == snap["record_sha256"] and row.rendered_at.isoformat().startswith(snap["rendered_at"][:19])
        assert sess.execute(select(Artifact).where(Artifact.run_id == BASELINE)).scalars().all(), "nothing deleted"

    # Archiving again is a no-op that is still audited; restore reverses.
    again = _call(ml_api, admin, "POST", f"/v1/runs/{BASELINE}/snapshots/1/archive").json()
    assert again["archived"] is True and again["changed"] is False
    restored = _call(ml_api, admin, "POST", f"/v1/runs/{BASELINE}/snapshots/{snap['id']}/restore").json()
    assert restored["archived"] is False and restored["changed"] is True
    assert writer.last("report.snapshot.restore").detail["archived_after"] is False
    assert _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/snapshots/1").status_code == 200
    final = _call(ml_api, scanner, "GET", f"/v1/runs/{BASELINE}/snapshots/1").json()
    assert {k: v for k, v in final.items() if k != "archived"} == {k: v for k, v in snap.items() if k != "archived"}


# --------------------------------------------------------------------------- Phase B projections (B2 reconcile)


def test_schema_version_and_llm_hook_render_for_a_real_record_and_a_probe_record() -> None:
    """The fixture record shows schema_version and no LLM block; a probe record embeds the LLM fragment nested."""
    from redsim.ml.llm.report_section import LLM_SECTION_HEADING
    from redsim.ml.llm.scorecard import D9_SENTENCE

    real = CampaignRecord.model_validate_json(FIXTURE.read_bytes())
    md = render_markdown(real, generated_at=NOW)
    assert "- **Schema version:** `campaign-record-1`" in md and real.schema_version == "campaign-record-1"
    assert not is_llm_probe_record(real) and LLM_HEADING not in md and "LLM probe scorecard" not in md
    pdf_text = _flat(_pdf_text(render_pdf(real, generated_at=NOW)))
    assert "campaign-record-1" in pdf_text and "LLM probe results" not in pdf_text

    probe = _llm_probe_record()
    assert is_llm_probe_record(probe)
    md = render_markdown(probe, generated_at=NOW)
    assert [line for line in md.splitlines() if line.startswith("## ")] == list(SECTION_HEADINGS), \
        "the embedded fragment adds no seventh section"
    assert LLM_HEADING in md and LLM_EMBED_NOTE in md
    assert "#### " + LLM_SECTION_HEADING.removeprefix("## ") in md, "the fragment's own heading is nested"
    assert "#### 2. Probe scorecard" in md and "**Family `dan`" in md, "sections nest, sub-headings become bold lines"
    assert "1/4 (0.2500)" in md and D9_SENTENCE in md and "openai/gpt-4o-mini" in md
    assert md.index(SECTION_HEADINGS[1]) < md.index(LLM_HEADING) < md.index(SECTION_HEADINGS[2])
    assert "MRI not computed" in md, "a probe record has no MRI and the scorecard says so"
    html = render_html(md, probe)
    assert "<h4>" in html and "<h5>" not in html
    pdf_text = _flat(_pdf_text(render_pdf(probe, generated_at=NOW)))
    assert "LLM probe results" in pdf_text and "1/4 (0.2500)" in pdf_text and "campaign-record-1" in pdf_text
    # The PDF and the Markdown of one render agree on the stamp; the PDF is deterministic for the probe record too.
    assert render_pdf(probe, generated_at=NOW) == render_pdf(probe, generated_at=NOW)


def test_text_and_detection_scorecards_render_in_markdown_and_pdf() -> None:
    """MODALITIES-43: the Phase B rows and observation blocks reach every projection with their denominators."""
    text = _text_record()
    md = render_markdown(text, generated_at=NOW)
    assert "- **Norm:** edit; budget axis: edit budget (share of words substituted)" in md
    assert TEXT_BUDGET_HEADING in md and "| 0.1875 |" in md and "60/180 (0.3333)" in md
    assert TEXT_EVIDENCE_HEADING in md and "2/12 (0.1667)" in md and "| 3, 7 |" in md
    assert "3, 0, 7 → 7, 3, 1" in md and "shap_text: art-o.000-shap" in md
    assert DETECTION_SCORECARD_HEADING not in md and DETECTION_EVIDENCE_HEADING not in md
    pdf_text = _flat(_pdf_text(render_pdf(text, generated_at=NOW)))
    assert "Text edit budget" in pdf_text and "0.1875" in pdf_text and "60/180 (0.3333)" in pdf_text
    assert "Text evidence" in pdf_text and "2/12 (0.1667)" in pdf_text

    detection = _detection_record()
    md = render_markdown(detection, generated_at=NOW)
    assert "- **Norm:** patch_area; budget axis: patch area (share of the image area)" in md
    assert DETECTION_SCORECARD_HEADING in md and "96/120 (0.8000)" in md and "60/120 (0.5000)" in md
    assert "36/96 (0.3750)" in md and "n/a (clean row)" in md and "| 0.7100 |" in md and "| 0.4000 |" in md
    assert DETECTION_EVIDENCE_HEADING in md and "4/4 (1.0000)" in md and "2/4 (0.5000)" in md
    assert "[10, 12, 42, 44] (x_min, y_min, x_max, y_max px)" in md
    assert TEXT_BUDGET_HEADING not in md and TEXT_EVIDENCE_HEADING not in md
    assert "MRI not computed" in md and "MRI 0" not in md
    pdf_text = _flat(_pdf_text(render_pdf(detection, generated_at=NOW)))
    assert "Detection scorecard" in pdf_text and "96/120 (0.8000)" in pdf_text and "36/96 (0.3750)" in pdf_text
    assert "Detection evidence" in pdf_text and "[10, 12, 42, 44]" in pdf_text
    # report.json stays the record dump: the Phase B fields round-trip untouched.
    reports = {name: data for name, data, _ct in render_campaign_reports(detection, generated_at=NOW,
                                                                        formats=REPORT_FORMATS_ALL)}
    assert set(reports) == {"report.md", "report.json", "report.html", "report.pdf"}
    payload = json.loads(reports["report.json"])
    assert payload["measurements"][1]["detection"]["suppression_rate"] == 0.375
    assert payload["observations"][0]["detection"]["patch_bbox"] == [10.0, 12.0, 42.0, 44.0]
    assert CampaignRecord.model_validate(payload) == detection


# --------------------------------------------------------------------------- N-run compare (REVIEW_REPORTS-26, -30)


def _seed_variant(api: dict[str, Any], run_id: str, mutate: Any) -> None:
    """Add one more campaign to the harness: a copy of the baseline record changed by ``mutate``."""
    from redsim.db.models import Run as RunRow

    base = json.loads(FIXTURE.read_text())
    base["run_id"] = run_id
    mutate(base)
    record = CampaignRecord.model_validate(base)
    raw = record.model_dump_json().encode()
    location = f"memory://{PROJECT}/{run_id}/run_record.json/{_sha(raw)}"
    api["store"].blobs[location] = raw
    api["records"][run_id] = record
    with api["get_session"]() as session:
        session.add(RunRow(id=run_id, project_id=PROJECT, target_id=record.config.target_id, mode="api",
                           scanner="ml.campaign", status="succeeded", created_by="user:creator", stage_table={}))
        session.flush()
        session.add(Artifact(id=f"artifact-{run_id}-record", run_id=run_id, project_id=PROJECT,
                             kind="ml.run_record", sha256=_sha(raw), location=location,
                             content_type="application/json", size_bytes=len(raw)))
        session.execute(api["campaigns"].insert().values(
            run_id=run_id, project_id=PROJECT, target_id=record.config.target_id, kind=record.kind,
            modality="image", config=record.config.model_dump(mode="json"), settings_hash=record.settings_hash,
            provenance=record.provenance.model_dump(mode="json") if record.provenance else None,
            score=record.score.model_dump(mode="json") if record.score else None,
            limitations=list(record.limitations),
        ))


def _custom_weights(rec: dict[str, Any]) -> None:
    rec["config"]["scoring"]["weights"] = dict(CUSTOM_WEIGHTS)
    rec["score"]["weights"] = dict(CUSTOM_WEIGHTS)
    rec["settings_hash"] = "e" * 64
    rec["provenance"]["settings_hash"] = "e" * 64
    rec["score"]["settings_hash"] = "e" * 64


def _walk_keys(payload: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(payload, dict):
        for k, v in payload.items():
            keys.add(str(k).lower())
            keys |= _walk_keys(v)
    elif isinstance(payload, list):
        for item in payload:
            keys |= _walk_keys(item)
    return keys


def test_n_run_table_rows_in_request_order_without_a_delta(ml_api: dict[str, Any]) -> None:  # noqa: F811
    viewer = _user("reader", "viewer")
    resp = _call(ml_api, viewer, "GET", "/v1/runs/compare", params={"ids": f"{OTHER_MODEL},{BASELINE}"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["mode"] == "table" and body["compatible"] is True
    assert [row["run_id"] for row in body["rows"]] == [OTHER_MODEL, BASELINE], "request order"
    for row in body["rows"]:
        assert row["mri"] is not None and row["grade"] and row["subscores"] and row["per_attack"]
        assert row["curve"] and row["families"] and row["limitations"], "never an MRI without its tables (15.8 ii)"
        assert all({"n", "n_correct"} <= set(f) for f in row["families"])
        assert row["weights"] == MRIWeights().as_dict() and row["non_default_weights"] is False
        assert row["kind"] == "attack"
    assert body["changed_variables_per_row"][OTHER_MODEL] == []
    assert body["changed_variables_per_row"][BASELINE] == ["model", "target"]
    assert "seed" in body["unchanged_variables"] and "model_sha256" not in body["unchanged_variables"]
    assert body["ignored_variables"] == list(cmp.IGNORED_VARIABLES) and body["caveats"] == sorted(body["caveats"])
    keys = _walk_keys(body)
    assert not (keys & {"mean", "rank", "average", "aggregate", "ranking"}), "no aggregate column (D9 i)"
    assert not {k for k in keys if k.startswith("delta") or k.startswith("baseline")}, "every run is its own measurement"
    # The same pair through the pairwise route: side by side, two scorecards, no delta.
    pair = _call(ml_api, viewer, "GET", f"/v1/runs/{BASELINE}/compare", params={"with": OTHER_MODEL}).json()
    assert pair["mode"] == "side_by_side" and len(pair["scorecards"]) == 2
    assert not {k for k in _walk_keys(pair) if k.startswith("delta") or k.startswith("baseline")}
    assert "defense" not in pair["changed_variables"]


def test_n_run_table_refusals(ml_api: dict[str, Any]) -> None:  # noqa: F811
    viewer = _user("reader", "viewer")
    # One incompatible pair refuses the whole table and names the pair.
    resp = _call(ml_api, viewer, "GET", "/v1/runs/compare", params={"ids": f"{BASELINE},{OTHER_MODEL},{OTHER_SEED}"})
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "incompatible_campaigns"
    assert detail["reasons"] == ["n_samples", "seed", "sample_indices_sha256"]
    assert {tuple(p["runs"]) for p in detail["pairs"]} == {(BASELINE, OTHER_SEED), (OTHER_MODEL, OTHER_SEED)}
    assert all(p["reasons"] == detail["reasons"] for p in detail["pairs"])
    # A partial score refuses the table naming the run; compatibility is checked first.
    partial = _call(ml_api, viewer, "GET", "/v1/runs/compare", params={"ids": f"{BASELINE},{PARTIAL}"})
    assert partial.status_code == 409 and partial.json()["detail"]["code"] == "score_unavailable"
    assert partial.json()["detail"]["reasons"] == [f"{PARTIAL}: MRI not computed (S_expl unavailable (explainer failed))"]
    # Membership on every id before any body.
    foreign = _call(ml_api, viewer, "GET", "/v1/runs/compare", params={"ids": f"{BASELINE},{FOREIGN}"})
    assert foreign.status_code == 403 and "reasons" not in foreign.text
    assert _call(ml_api, viewer, "GET", "/v1/runs/compare", params={"ids": f"{BASELINE},run-missing"}).status_code == 404
    # Bounds: 1 id, 11 ids, a repeated id.
    one = _call(ml_api, viewer, "GET", "/v1/runs/compare", params={"ids": BASELINE})
    assert one.status_code == 422 and one.json()["detail"]["code"] == "params_out_of_range"
    assert one.json()["detail"]["field"] == "ids"
    eleven = ",".join([BASELINE] + [f"run-x{i}" for i in range(10)])
    assert _call(ml_api, viewer, "GET", "/v1/runs/compare", params={"ids": eleven}).status_code == 422
    assert _call(ml_api, viewer, "GET", "/v1/runs/compare", params={"ids": f"{BASELINE},{BASELINE}"}).status_code == 422
    assert _call(ml_api, viewer, "GET", "/v1/runs/compare").status_code == 422, "ids is required"
    # The pairwise route is unchanged by the new path.
    pair = _call(ml_api, viewer, "GET", f"/v1/runs/{BASELINE}/compare", params={"with": OTHER_SEED})
    assert pair.status_code == 409 and pair.json()["detail"]["code"] == "incompatible_campaigns"


def test_differing_weight_vectors_are_incomparable_and_the_campaign_carries_the_badge(ml_api: dict[str, Any]) -> None:  # noqa: F811
    _seed_variant(ml_api, OTHER_WEIGHTS, _custom_weights)
    viewer = _user("reader", "viewer")
    pairwise = _call(ml_api, viewer, "GET", f"/v1/runs/{BASELINE}/compare", params={"with": OTHER_WEIGHTS})
    assert pairwise.status_code == 409 and pairwise.json()["detail"]["code"] == "incompatible_campaigns"
    assert pairwise.json()["detail"]["reasons"] == ["scoring.weights"], "the vector is named, not the whole block"
    table = _call(ml_api, viewer, "GET", "/v1/runs/compare", params={"ids": f"{BASELINE},{OTHER_WEIGHTS}"})
    assert table.status_code == 409 and table.json()["detail"]["reasons"] == ["scoring.weights"]

    campaign = _call(ml_api, viewer, "GET", f"/v1/runs/{OTHER_WEIGHTS}/campaign").json()
    assert campaign["non_default_weights"] is True and campaign["weights"] == CUSTOM_WEIGHTS
    baseline = _call(ml_api, viewer, "GET", f"/v1/runs/{BASELINE}/campaign").json()
    assert baseline["non_default_weights"] is False and baseline["weights"] == MRIWeights().as_dict()
    # The pure module agrees, and the scorecard projection carries the flag.
    record = ml_api["records"][OTHER_WEIGHTS].model_dump(mode="json")
    assert cmp.non_default_weights(record) is True
    score = cmp.score(record)
    assert score is not None and cmp.scorecard_projection(record, score)["non_default_weights"] is True


def test_comparison_table_is_pure_and_refuses_aggregate_keys() -> None:
    base = json.loads(FIXTURE.read_text())
    twin = copy.deepcopy(base)
    twin["run_id"] = "run-twin"
    table = cmp.comparison_table([(base["run_id"], base, None), ("run-twin", twin, None)])
    assert [r["run_id"] for r in table["rows"]] == [base["run_id"], "run-twin"]
    assert "delta" not in table["rows"][1] and "delta_source" not in table["rows"][1], "no delta column"
    with pytest.raises(ValueError, match="at least 2"):
        cmp.comparison_table([(base["run_id"], base, None)])
    with pytest.raises(ValueError, match="only once"):
        cmp.comparison_table([(base["run_id"], base, None), (base["run_id"], base, None)])
    with pytest.raises(ValueError, match="aggregate key"):
        cmp.assert_no_aggregate_keys({"rows": [{"mean": 1}]})
    # A differing seed is refused as a variable-level mismatch naming the pair.
    other_seed = copy.deepcopy(twin)
    other_seed["config"]["seed"] = 7
    other_seed["settings_hash"] = other_seed["provenance"]["settings_hash"] = "b" * 64
    with pytest.raises(cmp.Incompatible) as excinfo:
        cmp.comparison_table([(base["run_id"], base, None), ("run-twin", other_seed, None)])
    assert "seed" in excinfo.value.reasons
    assert excinfo.value.pairs[0]["runs"] == [base["run_id"], "run-twin"]


# --------------------------------------------------------------------------- per-project weights (REVIEW_REPORTS-28)


def _scoring_url(slug: str = "p1") -> str:
    return f"/v1/projects/{slug}/ml-scoring"


def test_ml_scoring_default_read_admin_put_and_refusals(ml_api: dict[str, Any]) -> None:  # noqa: F811
    admin = _user("owner", "admin")
    scanner = _user("exporter", "scanner")
    writer: RecordingAuditWriter = ml_api["writer"]

    default = _call(ml_api, scanner, "GET", _scoring_url())
    assert default.status_code == 200, default.text
    assert default.json()["source"] == "default" and default.json()["non_default_weights"] is False
    assert default.json()["ml_scoring"] == ScoringConfig().model_dump(mode="json")
    assert default.json()["project_id"] == PROJECT
    assert _call(ml_api, _user("outsider", "admin", project=OTHER_PROJECT), "GET", _scoring_url()).status_code == 403
    assert _call(ml_api, admin, "GET", _scoring_url("nope")).status_code == 404

    full = {"version": "mri-1", "weights": dict(CUSTOM_WEIGHTS)}
    # Non-admins are refused before any audit row.
    before = len(writer.events)
    assert _call(ml_api, scanner, "PUT", _scoring_url(), json=full).status_code == 403
    assert _call(ml_api, _user("fixer", "approver"), "PUT", _scoring_url(), json=full).status_code == 403
    assert len(writer.events) == before

    put = _call(ml_api, admin, "PUT", _scoring_url(), json=full)
    assert put.status_code == 200, put.text
    body = put.json()
    assert body["source"] == "project" and body["non_default_weights"] is True
    assert body["ml_scoring"]["weights"] == CUSTOM_WEIGHTS
    assert body["ml_scoring"]["severity"] == {"asr_high": 0.5, "asr_mid": 0.2}, "a full ScoringConfig is stored"
    assert set(body["ml_scoring"]) == {"version", "weights", "severity", "confidence", "interpretation"}
    event = writer.last("project.settings")
    assert event.success is True and event.project_id == PROJECT and event.run_id is None
    assert event.detail["field"] == "ml_scoring" and event.detail["old_sha256"] is None
    assert event.detail["new_sha256"] == hashlib.sha256(
        json.dumps(body["ml_scoring"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert event.detail["weights"] == CUSTOM_WEIGHTS
    assert _call(ml_api, scanner, "GET", _scoring_url()).json()["ml_scoring"]["weights"] == CUSTOM_WEIGHTS
    with ml_api["sessions"]() as sess:
        from redsim.db.models import Project

        assert sess.get(Project, PROJECT).ml_scoring["weights"] == CUSTOM_WEIGHTS

    # Refusals: partial vector, wrong sum, extra key, non-numeric, not an object. Never renormalised.
    refusals = [
        {"weights": {"acc": 0.5}},
        {"weights": {"acc": 0.5, "asr": 0.2, "eps": 0.1, "conf": 0.05, "expl": 0.05}},
        {"weights": {**CUSTOM_WEIGHTS, "extra": 0.0}},
        {"weights": {**CUSTOM_WEIGHTS, "acc": "half"}},
        {"version": "mri-1"},
        ["not", "an", "object"],
    ]
    for bad in refusals:
        resp = _call(ml_api, admin, "PUT", _scoring_url(), json=bad)
        assert resp.status_code == 422, (bad, resp.text)
        detail = resp.json()["detail"]
        assert detail["code"] in {"scoring_weights_invalid", "params_out_of_range"}
        assert detail["field"] == "ml_scoring.weights"
        refused = writer.last("project.settings")
        assert refused.success is False and refused.detail["refusal"] == detail["code"]
    assert _call(ml_api, scanner, "GET", _scoring_url()).json()["ml_scoring"]["weights"] == CUSTOM_WEIGHTS, \
        "a refused override changes nothing"
    # A vector off by less than 1e-9 is accepted as summing to 1; off by 1e-6 is not.
    close = {"weights": {"acc": 0.35, "asr": 0.25, "eps": 0.2, "conf": 0.1, "expl": 0.1 + 1e-12}}
    assert _call(ml_api, admin, "PUT", _scoring_url(), json=close).status_code == 200
    off = {"weights": {"acc": 0.35, "asr": 0.25, "eps": 0.2, "conf": 0.1, "expl": 0.1 + 1e-6}}
    assert _call(ml_api, admin, "PUT", _scoring_url(), json=off).status_code == 422

    # ``null`` clears the override (audited with the old digest) and the default is back.
    cleared = _call(ml_api, admin, "PUT", _scoring_url(), content=b"null",
                    headers={"content-type": "application/json"})
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["source"] == "default" and cleared.json()["non_default_weights"] is False
    event = writer.last("project.settings")
    assert event.detail["cleared"] is True and event.detail["old_sha256"] and event.detail["new_sha256"] is None
