"""``redsim.ml.reporting`` against spec 14.8 (G-REP1).

Six sections in the fixed order; the MRI scorecard as a sub-block of section 2; the ΔMRI block on
verify runs; HTML escaped once, through ``redsim.report``'s helpers, with the Markdown left raw;
``report.json`` equal to the record dump (the RunRecord plus the MRIRecord); URL strings inert.
Records are hand-built from the frozen schema, so the tests are offline and fast.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from redsim.ml.reporting import (
    DELTA_HEADING,
    NOT_MEASURED,
    REVIEWER_NOTES_HEADING,
    SCORECARD_HEADING,
    SECTION_HEADINGS,
    render_campaign_reports,
)
from redsim.ml.schema import (
    GRADE_STATEMENT,
    AccuracyPoint,
    AttackInfo,
    CampaignConfig,
    CampaignRecord,
    CandidateRecommendation,
    CleanAccuracyDelta,
    CurvePoint,
    DefenseConfig,
    FamilyDelta,
    Interpretation,
    MeasuredDelta,
    Measurement,
    MRIDelta,
    MRIInputRow,
    MRIRecord,
    MRIWeights,
    Observation,
    PerAttackSubscores,
    RobustnessCurve,
    ScoredValue,
    ScoreStatus,
    Subscores,
    TargetInfo,
    grade_for_mri,
)

NOW = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
HASH = "ab" * 32
URL = "https://example.invalid/paper?x=1&y=2"
SCRIPT = "<script>alert(1)</script>"
FIXTURE = Path(__file__).parent / "fixtures" / "run_record.json"


def _measurement(
    id_: str, family: str, attack_id: str | None, eps: float | None, n: int, n_correct: int, *,
    clean_correct: int | None = None, flipped: int | None = None, **extra: object,
) -> Measurement:
    asr = None
    if flipped is not None and clean_correct:
        asr = round(flipped / clean_correct, 4)
    params: dict[str, float | str] = {"eps": eps, "norm": "linf"} if eps is not None else {}
    return Measurement(
        id=id_, family=family, attack_id=attack_id, params=params, n=n, n_correct=n_correct,  # type: ignore[arg-type]
        accuracy=(n_correct / n) if n else 0.0, n_flipped_from_clean=flipped, n_clean_correct=clean_correct,
        attack_success_rate=asr, **extra,  # type: ignore[arg-type]
    )


def _measurements(*, true_label: str = "circle") -> list[Measurement]:
    per_class = {true_label: {"n": 100, "n_correct": 90}, "square": {"n": 100, "n_correct": 82}}
    return [
        _measurement("m.clean", "clean", None, None, 200, 172, per_class=per_class),
        _measurement("m.evasion.fgsm.eps0.03", "evasion", "fgsm", 0.03, 200, 112, clean_correct=172, flipped=64,
                     linf_norm_mean=0.03, l2_norm_mean=0.39, pert_first_success_mean=0.021, pert_first_success_n=64,
                     conf_gap_mean=0.31, conf_gap_n=200, expl_shift_mean=0.42, expl_shift_n=16,
                     expl_shift_n_excluded=0, expl_shift_noise_floor=0.08, expl_shift_noise_floor_n=16,
                     per_class={true_label: {"n": 100, "n_correct": 60}, "square": {"n": 100, "n_correct": 52}}),
        _measurement("m.control.noise.eps0.03", "control", "noise_control", 0.03, 200, 168, clean_correct=172,
                     flipped=4, linf_norm_mean=0.03, l2_norm_mean=0.24),
    ]


def _score(*, mri: int = 42, delta: MRIDelta | None = None) -> MRIRecord:
    scored = {k: ScoredValue(value=v, n=n) for k, v, n in (
        ("S_acc", 35.5, 200), ("S_asr", 62.8, 172), ("S_eps", 51.0, 200), ("S_conf", 69.0, 200),
        ("S_expl", 58.0, 16),
    )}
    return MRIRecord(
        scoring_version="mri-1", weights=MRIWeights(), eps_grid=[0.03], reference_eps=0.03, norm="linf",
        attack_ids=["fgsm"], finding_asr_threshold=0.2, settings_hash=HASH,
        inputs=[MRIInputRow(attack_id="fgsm", eps=0.03, acc_clean=0.86, acc_adv=0.56, asr=0.3721, pert=0.021,
                            conf_gap=0.31, expl_shift=0.42, n=200, n_correct_clean=172, n_attacked=200,
                            n_explained=16)],
        per_attack={"fgsm": PerAttackSubscores(**scored)},
        subscores=Subscores(S_acc=24.2, S_asr=54.4, S_eps=44.3, S_conf=61.0, S_expl=51.5),
        mri=mri, grade=grade_for_mri(mri), completeness="complete",
        reading="The cheapest in-scope attack succeeded at the reference budget on a large share of the slice.",
        delta=delta, computed_at=NOW,
    )


def _curve() -> list[RobustnessCurve]:
    return [RobustnessCurve(
        attack_id="fgsm", norm="linf", eps_grid=[0.03], reference_eps=0.03,
        clean=AccuracyPoint(n=200, n_correct=172, accuracy=0.86),
        points=[CurvePoint(eps=0.03, n=200, n_correct=112, accuracy=0.56, n_clean_correct=172,
                           n_flipped_from_clean=64, asr=0.3721)],
        control=[CurvePoint(eps=0.03, n=200, n_correct=168, accuracy=0.84)],
    )]


def _provenance(*, defense: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "redsim_version": "0.13.0", "python": "3.12.12", "torch": "2.3.0", "art": "1.18.0", "shap": "0.46.0",
        "numpy": "1.26.4", "model_sha256": "d0" * 32, "dataset": "synthetic", "dataset_revision": "rev-1",
        "dataset_split": "test", "sample_indices_sha256": "5a" * 32, "settings_hash": HASH, "defense": defense,
        "thread_env": {"OMP_NUM_THREADS": "2"}, "model_manifest": {"model": "TinyNet", "source_url": URL},
        "started_at": NOW, "finished_at": NOW, "hostname": "test", "device": "cpu",
        "nondeterminism": ["CPU float32 reductions; results may differ across BLAS builds and thread counts"],
    }


def _record(**overrides: object) -> CampaignRecord:
    true_label = str(overrides.pop("true_label", "circle"))
    references = list(overrides.pop("references", ["art.defences.preprocessor.FeatureSqueezing", URL]))  # type: ignore[call-overload]
    base: dict[str, object] = {
        "run_id": "run-attack-1", "status": "succeeded", "stage": "report", "stages_done": ["load_target", "report"],
        "created_at": NOW, "kind": "attack", "completed_at": NOW, "settings_hash": HASH,
        "config": CampaignConfig(
            target_id="tiny", modality="image", attack_ids=["fgsm"], eps_grid=[0.03], reference_eps=0.03,
            n_samples=200, seed=0, explain_k=8, dataset_id="synthetic", dataset_revision="rev-1",
        ),
        "target": TargetInfo(id="tiny", name="Tiny random CNN (test double)", domain="image", status="available"),
        "attacks": [AttackInfo(id="fgsm", name="Fast Gradient Sign Method", domain="image", family="evasion")],
        "provenance": _provenance(),
        "measurements": _measurements(true_label=true_label),
        "observations": [Observation(
            id="o.000", sample_index=3, true_label=true_label, pred_clean=true_label, pred_adv="square",
            flipped=True, confidence_clean=0.91, confidence_adv=0.62,
            artifacts={"input_clean": "art-o.000-clean", "shap_adv": "art-o.000-shap-adv"},
            artifact_sha256={"input_clean": "00" * 32}, center_mass_ratio_clean=0.71, center_mass_ratio_adv=0.44,
            expl_shift=0.61,
        )],
        "interpretation": [Interpretation(
            id="i.1", statement="Random noise at ε=0.03 did not reduce accuracy while fgsm did.",
            basis=["m.clean", "m.evasion.fgsm.eps0.03", "m.control.noise.eps0.03"],
        )],
        "recommendations": [CandidateRecommendation(
            id="r.R2", title="Feature squeezing as an input preprocessor",
            rationale="Intended to reduce ASR at small ε.", triggered_by=["m.evasion.fgsm.eps0.03", "i.1"],
            references=references,
        )],
        "score": _score(), "curve": _curve(), "completeness": "complete",
        "limitations": ["synthetic is an open, unclassified public benchmark.",
                        "Recommendations are candidates. None has been validated against this model."],
    }
    base.update(overrides)
    return CampaignRecord.model_validate(base)


def _verify_record() -> CampaignRecord:
    defense = DefenseConfig(id="feature_squeezing", art_class="art.defences.preprocessor.FeatureSqueezing",
                            params={"bit_depth": 4})
    before = AccuracyPoint(n=200, n_correct=172, accuracy=0.86)
    after = AccuracyPoint(n=200, n_correct=168, accuracy=0.84)
    sub = Subscores(S_acc=1.0, S_asr=5.5, S_eps=3.0, S_conf=2.0, S_expl=0.5)
    delta = MRIDelta(
        baseline_run_id="run-attack-1", mri_before=40, mri_after=55, delta=15, delta_subscores=sub,
        delta_acc_clean=CleanAccuracyDelta(before=before, after=after, delta=-0.02),
        delta_families=[FamilyDelta(measurement_id="m.evasion.fgsm.eps0.03",
                                    before=AccuracyPoint(n=200, n_correct=112, accuracy=0.56),
                                    after=AccuracyPoint(n=200, n_correct=150, accuracy=0.75), delta=0.19)],
    )
    measured = MeasuredDelta(
        verify_run_id="run-verify-1", baseline_run_id="run-attack-1", defense=defense, delta_mri=15,
        delta_subscores=sub, delta_acc_clean=CleanAccuracyDelta(before=before, after=after, delta=-0.02),
        settings_hash=HASH, measured_at=NOW,
    )
    config = CampaignConfig(
        target_id="tiny", modality="image", attack_ids=["fgsm"], eps_grid=[0.03], reference_eps=0.03,
        n_samples=200, seed=0, explain_k=8, dataset_id="synthetic", dataset_revision="rev-1", defense=defense,
    )
    return _record(
        run_id="run-verify-1", kind="verify", baseline_run_id="run-attack-1", config=config,
        provenance=_provenance(defense=defense.model_dump()), score=_score(mri=55, delta=delta),
        recommendations=[CandidateRecommendation(
            id="r.R2", title="Feature squeezing as an input preprocessor",
            rationale="Intended to reduce ASR at small ε.", triggered_by=["m.evasion.fgsm.eps0.03"],
            references=[defense.art_class or ""], validation="measured", measured=measured,
        )],
        reviewer_notes="Reviewed the flipped samples.\nThe centre-mass shift looks real on o.000.",
    )


def _reports(record: CampaignRecord) -> dict[str, str]:
    return {name: data.decode() for name, data, _content_type in render_campaign_reports(record, generated_at=NOW)}


def _positions(text: str, needles: tuple[str, ...]) -> list[int]:
    positions = [text.find(n) for n in needles]
    assert all(p >= 0 for p in positions), dict(zip(needles, positions, strict=True))
    return positions


# --- order and content ---------------------------------------------------------------------------------


def test_six_sections_in_order() -> None:
    reports = _reports(_record())
    md = reports["report.md"]

    positions = _positions(md, SECTION_HEADINGS)
    assert positions == sorted(positions), "spec 14.8 fixes the section order"
    assert md.count("\n## ") == len(SECTION_HEADINGS), "no seventh section, no duplicate section"
    # The scorecard is a sub-block of section 2 and appears nowhere else.
    scorecard = md.find(SCORECARD_HEADING)
    assert positions[1] < scorecard < positions[2] and md.count(SCORECARD_HEADING) == 1
    assert md.count("MRI 42") == 1 and "grade D" in md and GRADE_STATEMENT in md
    assert "Reading (attack-scoped): The cheapest in-scope attack" in md
    assert "| S_asr | 0.25 | 54.4 | 62.8 (n=172) |" in md, "five subscores with denominators"
    assert "| 0.03 (reference) | 112/200 (0.5600) | 64/172 (0.3721) | 168/200 (0.8400) |" in md, "curve table"
    assert DELTA_HEADING not in md, "an attack run carries no ΔMRI block"
    # Section 1 carries the configuration, the provenance and the generation stamp.
    section_1 = md[positions[0]:positions[1]]
    assert f"**Generated at:** {NOW.isoformat()}" in section_1 and f"`{HASH}`" in section_1
    assert "**Baseline run:** none (not a verify run)" in section_1 and "Nondeterminism sources" in section_1
    # Section 2: every rate travels with its fraction, and the row header is the one the worker tests pin.
    section_2 = md[positions[1]:positions[2]]
    assert "| Attack | Epsilon | N | Clean correct |" in section_2 and "| fgsm | 0.03 | 200 | 172 |" in section_2
    assert "112/200 (0.5600)" in section_2 and "64/172 (0.3721)" in section_2
    assert "| m.clean | 90/100 (0.9000) | 82/100 (0.8200) |" in section_2, "per-class table with denominators"
    assert not re.search(r"\d+(\.\d+)?%", section_2), "no bare percentages"
    # Sections 3 to 6 carry their labels verbatim from the Literal fields.
    section_3 = md[positions[2]:positions[3]]
    assert "Metric kind: **heuristic**" in section_3 and "0.710 → 0.440 [heuristic]" in section_3
    assert "| o.000 | input_clean | art-o.000-clean | " + "00" * 32 + " |" in section_3
    section_4 = md[positions[3]:positions[4]]
    assert "- **i.1** [inferred] Random noise" in section_4 and "basis: `m.clean`, `m.evasion.fgsm.eps0.03`" in section_4
    section_5 = md[positions[4]:positions[5]]
    assert "- **r.R2** [candidate] Feature squeezing" in section_5
    assert "Validation: not evaluated" in section_5 and NOT_MEASURED in section_5
    assert "Measured ΔMRI" not in section_5, "no gain figure before a verify run measured one"
    section_6 = md[positions[5]:]
    assert "- Recommendations are candidates." in section_6 and REVIEWER_NOTES_HEADING not in section_6

    html = reports["report.html"]
    h2 = re.findall(r"<h2>(.*?)</h2>", html)
    assert h2 == [h.removeprefix("## ") for h in SECTION_HEADINGS]
    assert "<h3>MRI scorecard (derived summary)</h3>" in html and "<table>" in html


def test_verify_run_renders_delta_block_and_measured_sentence() -> None:
    record = _verify_record()
    md = _reports(record)["report.md"]
    positions = _positions(md, SECTION_HEADINGS)

    delta_at = md.find(DELTA_HEADING)
    assert positions[1] < delta_at < positions[2], "the ΔMRI block lives inside section 2"
    block = md[delta_at:positions[2]]
    assert "Changed variable: defense `feature_squeezing` (`art.defences.preprocessor.FeatureSqueezing`)" in block
    assert "**ΔMRI +15** (MRI 40 → 55)." in block
    assert "Clean accuracy: 172/200 (0.8600) → 168/200 (0.8400) (Δ -0.0200)." in block
    assert "| S_asr | +5.5 |" in block
    assert "| m.evasion.fgsm.eps0.03 | 112/200 (0.5600) | 150/200 (0.7500) | +0.1900 |" in block
    assert "Baseline run `run-attack-1` → verify run `run-verify-1`" in block and f"`{HASH}`" in block

    section_5 = md[positions[4]:positions[5]]
    assert "Validation: measured" in section_5 and NOT_MEASURED not in section_5
    assert (
        "Measured ΔMRI +15 (MRI 40 → 55; clean accuracy 172/200 (0.8600) → 168/200 (0.8400); "
        f"verify run run-verify-1, settings {HASH[:12]}, defense "
        'art.defences.preprocessor.FeatureSqueezing({"bit_depth": 4}))'
    ) in section_5, "spec 16.4 (5): the full delta-at-settings sentence, never a bare +15"
    assert f"share settings hash `{HASH}` (before = after)" in section_5
    assert "Per-dimension Δ: S_acc +1.0, S_asr +5.5, S_eps +3.0, S_conf +2.0, S_expl +0.5" in section_5

    section_1 = md[positions[0]:positions[1]]
    assert "**Kind:** verify" in section_1 and "**Baseline run:** `run-attack-1`" in section_1
    assert "Defense (the changed variable of a verify run)" in section_1
    section_6 = md[positions[5]:]
    assert section_6.find("- synthetic is an open") < section_6.find(REVIEWER_NOTES_HEADING)
    assert "> Reviewed the flipped samples." in section_6 and "> The centre-mass shift" in section_6


def test_partial_and_unscored_records_refuse_to_invent_numbers() -> None:
    zero = _measurement("m.evasion.fgsm.eps0.03", "evasion", "fgsm", 0.03, 0, 0, clean_correct=0, flipped=0)
    record = _record(
        status="failed", error="ML sandbox exited 1", completeness="partial",
        missing=["S_expl unavailable (explainer unsupported)"], score=None,
        score_status=ScoreStatus(state="unavailable", reason="one or more subscores unavailable"),
        measurements=[_measurements()[0], zero], observations=[], interpretation=[], recommendations=[],
        curve=[], limitations=[],
    )
    md = _reports(record)["report.md"]
    positions = _positions(md, SECTION_HEADINGS)
    assert positions == sorted(positions), "the six sections render even for a failed run"
    assert "**MRI not computed** — score unavailable: one or more subscores unavailable." in md
    assert "Completeness: **partial** — S_expl unavailable (explainer unsupported)." in md
    assert "0/0 — not computed (denominator 0)" in md and "No robustness curve was recorded" in md
    assert "No observations were recorded (no evidence recorded)." in md
    assert "No limitations were recorded (run status: failed)." in md
    assert not re.search(r"\b(0|100)%", md) and "MRI 0" not in md and "— grade" not in md
    assert "Reading: none (no grade was assigned)." in md and GRADE_STATEMENT in md


# --- escaping ------------------------------------------------------------------------------------------


def test_html_escapes_script_class_name() -> None:
    limitation = "line one\n```\n" + SCRIPT + "\n# not a heading\n| not | a | row |"
    record = _record(
        true_label=SCRIPT,
        target=TargetInfo(id="tiny", name='<img src=x onerror="alert(2)">', domain="image", status="available"),
        limitations=[limitation, "Recommendations are candidates."],
        reviewer_notes="```\n" + SCRIPT,
    )
    reports = _reports(record)
    md, html = reports["report.md"], reports["report.html"]

    # The Markdown carries the raw strings: escaping happens once, at the HTML boundary.
    assert SCRIPT in md and '<img src=x onerror="alert(2)">' in md
    assert "&lt;" not in md and "&amp;" not in md and "&gt;" not in md
    # No user string starts a Markdown line, so none can open a fence, heading or table row.
    assert "\n```" not in md and "\n# not a heading" not in md and "\n| not | a | row |" not in md
    # The HTML never contains the payload unescaped, in any of the places the class name lands.
    assert "<script" not in html and "<img" not in html, "no element from a user string, in text or table cells"
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=" in html, "quotes are inert in text content; the tag itself is escaped"
    assert "<title>Redsim ML campaign report — run-attack-1</title>" in html
    assert html.count("&lt;script&gt;") == md.count(SCRIPT), "each occurrence escaped exactly once"


def test_url_string_has_no_anchor() -> None:
    record = _record(references=[URL, "Madry et al. 2018"])
    reports = _reports(record)
    md, html = reports["report.md"], reports["report.html"]

    assert URL in md, "the reference and the manifest source_url render as inert text"
    assert f"`{URL}`" in md and "](http" not in md and "<http" not in md
    assert "<a " not in html and "href=" not in html and "<a>" not in html
    assert "https://example.invalid/paper?x=1&amp;y=2" in html


# --- json ----------------------------------------------------------------------------------------------


def test_json_round_trips_record() -> None:
    for record in (_record(), _verify_record(), CampaignRecord.model_validate_json(FIXTURE.read_bytes())):
        reports = {name: (data, content_type) for name, data, content_type in
                   render_campaign_reports(record, generated_at=NOW)}
        assert [name for name in reports] == ["report.md", "report.json", "report.html"]
        assert reports["report.json"][1] == "application/json"
        payload = json.loads(reports["report.json"][0])
        assert payload == record.model_dump(mode="json"), "report.json is the record dump, nothing added"
        assert CampaignRecord.model_validate(payload) == record
        if record.score is not None:
            assert payload["score"] == record.score.model_dump(mode="json"), "the MRIRecord travels under score"
            assert MRIRecord.model_validate(payload["score"]) == record.score
        assert "generated_at" not in payload, "the generation stamp lives in the rendered documents only"
        # Canonical: sorted keys, stable indentation, trailing newline.
        assert reports["report.json"][0] == (json.dumps(payload, sort_keys=True, indent=2,
                                                        separators=(",", ": ")) + "\n").encode()


def test_generated_at_defaults_to_now_and_is_stamped_in_markdown() -> None:
    record = _record()
    md = next(data for name, data, _ct in render_campaign_reports(record) if name == "report.md").decode()
    stamp = re.search(r"\*\*Generated at:\*\* (\S+)", md)
    assert stamp is not None
    generated = datetime.fromisoformat(stamp.group(1))
    assert generated.tzinfo is not None and abs((datetime.now(UTC) - generated).total_seconds()) < 60
