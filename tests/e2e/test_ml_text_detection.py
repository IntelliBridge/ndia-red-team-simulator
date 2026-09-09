"""Text and detection campaigns through the e2e harness (plan 12 wave B4, TESTS_DOCS-08/-09, MODALITIES-47).

Two Phase B modalities are driven through the real API, the real admission
service (``SUPPORTED_MODALITIES``: the ``edit`` and ``patch_area`` budgets, the
per-modality default grids, the detection ``n_samples`` cap), the eager Celery
task body and the real sandbox child, against tiny assets this module adds to the
session's asset tree with the **real builders**:

* ``sms_tfidf_lr`` (``redsim.ml.assets.train_text_classifier.build_text_asset``) on
  the committed 300-row SMS Spam Collection sample, plus a harness-owned synonym
  table under ``<assets>/lexicons/synonyms.json`` (the corpus's own ham-only and
  spam-only words, never WordNet, labelled as such);
* ``assets_frcnn_mnv3`` (``redsim.ml.assets.train_detector.train_detector``): the
  real torchvision Faster R-CNN architecture fine-tuned for 25 epochs from a
  seeded random initialisation on 48 synthetic 16 px rectangle images, with the
  manifest score threshold recorded at 0.1 (a laptop-CPU budget, never a demo
  result).

Every assertion is on what the production path left behind (the campaign record
served by ``GET /v1/runs/{id}/campaign``, the ``ml_campaigns`` row, artifact
bytes, the audit chain) and every assertion names the spec criterion it proves.
The honest state is asserted, never an invented number: a rate whose denominator
is zero is ``None`` with its note; a detection run has **no** MRI (spec 15.4,
owner decision MODALITIES-36); a text score is complete or honestly partial.

Product defects this module found on ``cb1e559`` are recorded in
:data:`DEFECTS` and surface as attributed ``pytest.fail`` calls at the point the
production path stops, never as weakened assertions:

* ``D_REGISTRY``: ``redsim/ml/targets/__init__.py`` imports neither
  ``redsim.ml.targets.text`` nor ``redsim.ml.targets.detection``, so the two
  bundled Phase B targets are absent from ``TARGETS`` in any process that does
  not import those modules by accident (the API process for ``sms_tfidf_lr``;
  the sandbox child resolves the text target through ``TARGETS`` too).
* ``D_TEXT_OBS``: ``redsim/ml/explain/shap_text.py`` builds the
  ``Observation.text`` block with ``attribution_artifacts`` as a list of names and
  ``n_changed`` possibly ``None`` while ``schema.TextObservation`` requires a
  ``dict[str, str]`` and an ``int``; every text observation raises
  ``ValidationError`` inside the explain closure, so the text run records
  "Explain stage unavailable" and its MRI is never complete.
* ``D_SMS_FIXTURE``: ``redsim/ml/datasets/sms_spam.py:read_sms_tsv`` refuses the
  committed fixture ``sms_spam.fixture_path()`` points at (three columns with an
  ``index`` header); this module converts the rows to the two-column layout the
  loader reads, and records the fixture's own digest beside them.
* ``D_DET_OBS``: ``redsim/ml/runners/detection.py:_observation`` builds the
  ``Observation.detection`` block with keys the ``schema.DetectionObservation``
  model does not have (``n_boxes`` / ``n_suppressed`` / ``patch`` instead of
  ``n_gt`` / ``patch_bbox``), so the block is silently dropped and the box
  evidence lives only in ``boxes.json``.

Run with::

    REDSIM_E2E=1 pytest -q -p no:cacheprovider -m e2e tests/e2e/test_ml_text_detection.py

The sandbox child is ``python -m redsim.ml.sandbox_worker`` and inherits only the
allowlisted environment, ``PYTHONPATH`` included; run the tier with the tree under
test first on ``PYTHONPATH`` when the interpreter's editable install points elsewhere.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from tests.e2e import harness as h

if TYPE_CHECKING:
    from fastapi.testclient import TestClient

    from tests.e2e.harness import E2EApp, E2EOrg

pytestmark = pytest.mark.e2e

#: The five MRI dimensions (spec 15.2).
SUBSCORE_KEYS = ("S_acc", "S_asr", "S_eps", "S_conf", "S_expl")
#: Readiness / certification wording that never appears in a grade reading or a scorecard reason (spec 15.5, 26.3 14).
_READINESS_RE = re.compile(
    r"\b(readiness|ready|certif\w*|deploy\w*|fielding|hardened|safe|safety|proven|validated|guaranteed)\b",
    re.IGNORECASE,
)
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

TEXT_MODEL_ID = "sms_tfidf_lr"
TEXT_ATTACK_ID = "word_substitution"
TEXT_EDIT_GRID = [0.1, 0.2, 0.3]
TEXT_REFERENCE = 0.2
TEXT_N = 12
DETECTOR_ID = "assets_frcnn_mnv3"
DET_ATTACK_ID = "dpatch"
DET_REVISION = "synthetic-e2e-det-v1"
DET_IMAGE_SIZE = 16
DET_TRAIN_N = 48
DET_EVAL_N = 16
DET_EPOCHS = 25
DET_SCORE_THRESHOLD = 0.1
DET_PATCH_GRID = [0.01, 0.03, 0.05]
DET_REFERENCE = 0.03
DET_N = 10
LEXICON_LICENSE = ("e2e harness double: synonym candidates are the corpus's own ham-only and spam-only words "
                   "(no WordNet content); labelled so a substitution can move a prediction on this tiny model")

#: Product defects found on cb1e559 (file:line, message). Referenced by the attributed failures below.
DEFECTS: dict[str, str] = {
    "D_REGISTRY": (
        "redsim/ml/targets/__init__.py:24-27 imports bundled, tabular and unavailable only: redsim.ml.targets.text "
        "(registers 'sms_tfidf_lr' at import, text.py:351-352) and redsim.ml.targets.detection (registers "
        "'assets_frcnn_mnv3', detection.py:701) are never imported by the package, so TARGETS lacks both in the API "
        "process (register_bundled_model -> 404 unknown_bundled_model, services/ml_models.py:701-703) and the "
        "sandbox child resolves the text campaign's target through TARGETS.maybe_get (campaign.py:306-308) and fails "
        "with TargetUnavailable('unknown target'). The detector is registered only as a side effect of "
        "redsim.ml.attacks importing dpatch."
    ),
    "D_TEXT_OBS": (
        "redsim/ml/explain/shap_text.py:409-428 builds Observation.text as "
        "{'attribution_artifacts': sorted(artifacts) (a list of names), 'n_changed': None when the pair is not "
        "aligned, ...} while redsim/ml/schema.py:389-405 TextObservation declares attribution_artifacts: "
        "dict[str, str] and n_changed: int; Observation(**obs_kwargs) raises pydantic ValidationError "
        "('text.attribution_artifacts Input should be a valid dictionary') for every explained message, the text "
        "runner's explain closure (runners/text.py:374-384) records 'Explain stage unavailable for "
        "'word_substitution': ValidationError' with no observation, S_expl has no input and the text MRI is never "
        "complete (spec 15.4)."
    ),
    "D_SMS_FIXTURE": (
        "redsim/ml/datasets/sms_spam.py:123-149 read_sms_tsv accepts '<label>\\t<message>' rows (optional "
        "'label\\ttext' header) but the committed fixture sms_spam.fixture_path() -> "
        "tests/ml/fixtures/sms_spam_sample.tsv has three columns with an 'index\\tlabel\\ttext' header, so "
        "load_sms_spam(fixture_path()) raises DatasetUnavailable(\"unknown label 'index'\"); the fixture and its "
        "loader disagree and nothing in the ml tier reads the committed file."
    ),
    "D_DET_OBS": (
        "redsim/ml/runners/detection.py:852-858 builds Observation.detection as {'n_boxes', 'n_matched_clean', "
        "'n_matched_adv', 'n_suppressed', 'patch'} while redsim/ml/schema.py:413-424 DetectionObservation requires "
        "n_gt, n_matched_clean, n_matched_adv and patch_bbox; the ValidationError is swallowed and the block is "
        "dropped, so detection observations never carry the B0 block (the facts survive only in boxes.json)."
    ),
}


def _quiet(_: str) -> None:
    return None


def _fail(defect: str, observed: str) -> None:
    """A product defect outside this file: fail here with the attribution, never with a weaker assertion."""
    pytest.fail(f"{observed}\n\nproduct defect, not a harness problem [{defect}]: {DEFECTS[defect]}", pytrace=False)


# ---------------------------------------------------------------------------
# Read-only helpers over the API and the harness database
# ---------------------------------------------------------------------------


def _eps_tag(eps: float) -> str:
    return f"eps{float(eps):g}"


def _by_id(campaign: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = campaign["measurements"]
    out = {str(m["id"]): m for m in rows}
    assert len(out) == len(rows), "measurement ids are unique within a run"
    return out


def _assert_counts(row: dict[str, Any], *, n: int, class_names: set[str] | None = None) -> None:
    """Spec 14.2 / 26.2 item 7: ``k / n`` denominators and per-class counts on one measurement row."""
    assert row["n"] == n, row["id"]
    assert isinstance(row["n_correct"], int) and 0 <= row["n_correct"] <= row["n"], row
    assert row["accuracy"] == pytest.approx(row["n_correct"] / row["n"]), row["id"]
    per_class = row["per_class"]
    assert isinstance(per_class, dict) and per_class, f"{row['id']} has no per-class counts"
    for label, counts in per_class.items():
        assert set(counts) >= {"n", "n_correct"}, (row["id"], label, counts)
        assert 0 <= counts["n_correct"] <= counts["n"]
    if class_names is not None:
        assert set(per_class) <= class_names, (row["id"], sorted(per_class))
    assert sum(c["n"] for c in per_class.values()) == row["n"], row["id"]
    assert sum(c["n_correct"] for c in per_class.values()) == row["n_correct"], row["id"]


def _assert_asr(row: dict[str, Any], clean: dict[str, Any]) -> None:
    """Spec 14.2 / 15.1: ASR is ``n_flipped / clean n_correct`` with the denominator disclosed, or ``None`` at 0."""
    assert row["n_clean_correct"] == clean["n_correct"], row["id"]
    if clean["n_correct"] > 0:
        assert isinstance(row["n_flipped_from_clean"], int) and 0 <= row["n_flipped_from_clean"] <= clean["n_correct"]
        assert row["attack_success_rate"] == pytest.approx(row["n_flipped_from_clean"] / clean["n_correct"]), row["id"]
    else:
        assert row["attack_success_rate"] is None, "a zero denominator is 'not computed', never 0% (spec 14.2)"
        assert any("denominator" in note for note in row["notes"]), row["notes"]


def _artifact_rows(client: TestClient, run_id: str) -> dict[str, dict[str, Any]]:
    response = client.get(f"/v1/runs/{run_id}/artifacts")
    assert response.status_code == 200, response.text
    rows = response.json()["artifacts"]
    assert response.json()["count"] == len(rows)
    return {str(row["id"]): row for row in rows}


def _download(client: TestClient, row: dict[str, Any]) -> bytes:
    """``GET /v1/artifacts/{id}``: bytes verified against the recorded digest (spec 17.2, 26.2 item 5)."""
    response = client.get(f"/v1/artifacts/{row['id']}")
    assert response.status_code == 200, (row["kind"], response.status_code, response.text[:200])
    data = response.content
    assert hashlib.sha256(data).hexdigest() == row["sha256"], f"{row['kind']}: bytes differ from Artifact.sha256"
    assert response.headers["x-content-type-options"] == "nosniff"
    return data


def _events(e2e_app: E2EApp, chain_id: str, action: str) -> list[dict[str, Any]]:
    return [ev for ev in e2e_app.read_chain(chain_id) if ev["action"] == action]


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


def _keys_recursive(payload: Any) -> set[str]:
    out: set[str] = set()
    if isinstance(payload, dict):
        for key, value in payload.items():
            out.add(str(key))
            out |= _keys_recursive(value)
    elif isinstance(payload, list):
        for value in payload:
            out |= _keys_recursive(value)
    return out


def _explain_unavailable(campaign: dict[str, Any], attack_id: str) -> str | None:
    prefix = f"Explain stage unavailable for '{attack_id}'"
    return next((lim for lim in campaign["limitations"] if str(lim).startswith(prefix)), None)


def _assert_score_state(campaign: dict[str, Any]) -> bool:
    """Spec 15.4 / 6.7 / 26.3 item 13: ``mri`` never without all five subscores; a partial score names what is missing.

    Returns ``True`` for a complete MRI, ``False`` for the honest partial state.
    """
    from redsim.ml.schema import contains_banned_score_word, grade_for_mri

    score = campaign["score"]
    limitations = campaign["limitations"]
    if score is None:
        status = campaign["score_status"]
        assert status is not None and status["state"] == "unavailable" and status["reason"], status
        assert campaign["completeness"] == "partial" and campaign["missing"]
        assert any("MRI not computed" in item for item in limitations), limitations
        return False
    subscores = score["subscores"]
    absent = [key for key in SUBSCORE_KEYS if subscores.get(key) is None]
    assert campaign["completeness"] == score["completeness"]
    if score["mri"] is None:
        assert absent, "mri None while every subscore is present"
        assert score["completeness"] == "partial" and score["missing"], score
        assert score["grade"] is None and score["reading"] is None
        assert any("MRI not computed" in item for item in limitations), limitations
        return False
    assert not absent, f"mri {score['mri']} present while subscores are missing: {absent}"
    assert score["completeness"] == "complete" and score["missing"] == []
    assert isinstance(score["mri"], int) and 0 <= score["mri"] <= 100
    assert score["grade"] == grade_for_mri(score["mri"])
    reading = score["reading"]
    assert isinstance(reading, str) and reading.strip()
    assert not contains_banned_score_word(reading), reading
    assert not _READINESS_RE.search(reading), f"grade reading carries readiness wording: {reading!r}"
    for row in score["inputs"]:
        assert isinstance(row["n"], int) and row["n"] > 0, row
    return True


# ---------------------------------------------------------------------------
# Assets: the text classifier and the detector, built with the real builders into the session tree
# ---------------------------------------------------------------------------


def _two_column_sms(fixture: Path, dest: Path) -> tuple[Path, str, int]:
    """The committed three-column fixture rewritten as ``<label>\\t<message>`` (the layout ``read_sms_tsv`` reads).

    Returns ``(path, sha256 of the committed fixture, rows written)``. The rows are the fixture's rows unchanged;
    only the ``index`` column and its header are dropped (see ``D_SMS_FIXTURE``).
    """
    lines = fixture.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    assert header[:2] == ["index", "label"], f"unexpected fixture header {header!r}"
    rows = [line.split("\t", 2) for line in lines[1:] if line.strip()]
    dest.write_text("".join(f"{label}\t{text}\n" for _index, label, text in rows), encoding="utf-8")
    return dest, hashlib.sha256(fixture.read_bytes()).hexdigest(), len(rows)


def _harness_lexicon(texts: list[str], labels: Any, root: Path) -> Path:
    """``<assets>/lexicons/synonyms.json``: each ham word maps to spam-only words and vice versa (seeded)."""
    import numpy as np

    from redsim.ml.datasets.sms_spam import tokenize

    ham = [t for t, label in zip(texts, list(labels), strict=True) if int(label) == 0]
    spam = [t for t, label in zip(texts, list(labels), strict=True) if int(label) == 1]

    def vocabulary(rows: list[str]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for text in rows:
            for word in tokenize(text.lower()):
                if re.fullmatch(r"[a-z]{3,}", word):
                    counts[word] = counts.get(word, 0) + 1
        return counts

    ham_vocab, spam_vocab = vocabulary(ham), vocabulary(spam)
    ham_only = [w for w, _ in sorted(ham_vocab.items(), key=lambda kv: (-kv[1], kv[0])) if w not in spam_vocab][:40]
    spam_only = [w for w, _ in sorted(spam_vocab.items(), key=lambda kv: (-kv[1], kv[0])) if w not in ham_vocab][:40]
    rng = np.random.default_rng(0)
    table: dict[str, list[str]] = {}
    for word in sorted(ham_vocab):
        table[word] = [str(w) for w in rng.choice(spam_only, size=min(4, len(spam_only)), replace=False)]
    for word in sorted(spam_vocab):
        table[word] = [str(w) for w in rng.choice(ham_only, size=min(4, len(ham_only)), replace=False)]
    path = root / "lexicons" / "synonyms.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"license": LEXICON_LICENSE, "synonyms": table}, indent=1), encoding="utf-8")
    return path


def _sanitize(value: Any) -> Any:
    """NaN-free copy of a metrics block (JSON round trips through the manifest must be canonical)."""
    if isinstance(value, float) and math.isnan(value):
        return None
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


@pytest.fixture(scope="module")
def phase_b_assets(e2e_assets: Path, e2e_app: E2EApp, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Add ``sms_tfidf_lr`` and ``assets_frcnn_mnv3`` to the session's asset tree with the real builders.

    Additive: the image and URL entries the session fixture built are re-verified after the manifest rewrite
    (``verify_model_assets`` clean for every model). Records which of the two ids ``TARGETS`` knew before this
    module imported their target modules (``D_REGISTRY``).
    """
    import torch

    from redsim.ml.targets import TARGETS

    # Recorded before anything below imports the two target modules (D_REGISTRY): who was in TARGETS already.
    registry_gap = [mid for mid in (TEXT_MODEL_ID, DETECTOR_ID) if mid not in TARGETS]

    from redsim.ml.assets import train_detector as tr
    from redsim.ml.assets.manifest import (
        MANIFEST_NAME,
        AssetManifest,
        DatasetEntry,
        ModelEntry,
        SplitEntry,
        file_entry,
        library_versions,
        stamp_manifest_sha256,
        verify_model_assets,
        with_dataset_caveats,
        write_manifest,
    )
    from redsim.ml.assets.train_text_classifier import build_text_asset
    from redsim.ml.datasets import military_assets as ma
    from redsim.ml.datasets import sms_spam
    from redsim.ml.schema import CleanAccuracy
    from redsim.ml.targets import detection as td

    root = Path(e2e_assets)
    del e2e_app  # ordering only: the harness app exists before the tree is extended

    # -- text: the committed SMS sample rows through build_text_asset -------------------------------------
    fixture = sms_spam.fixture_path()
    assert fixture is not None and fixture.is_file(), "the committed SMS fixture is missing from this checkout"
    scratch = tmp_path_factory.mktemp("e2e-text-detection")
    two_column, fixture_sha256, n_rows = _two_column_sms(fixture, scratch / "sms_spam_sample.two_column.tsv")
    fixture_refused: str | None = None
    try:
        sms_spam.load_sms_spam(fixture, fixture_only=False)
    except Exception as exc:  # noqa: BLE001 - the loader's refusal of its own fixture is what is recorded
        fixture_refused = f"{type(exc).__name__}: {exc}"
    table = sms_spam.load_sms_spam(two_column, fixture_only=False)
    text_entry, text_model = build_text_asset(
        root, table=table, seed=0, log=_quiet,
        caveats=["e2e harness build: the committed 300-row CI sample of the SMS Spam Collection, not the full corpus; "
                 "nothing measured on it is a demo result"],
    )
    text_entry.notes = [*text_entry.notes,
                        f"e2e harness: rows are the committed sample {fixture.name} (sha256 {fixture_sha256}) "
                        "rewritten to the two-column layout the loader reads; the model is trained on its 80% split"]
    text_entry.sampled_from = {"fixture": fixture.name, "fixture_sha256": fixture_sha256, "n_rows": n_rows,
                               "layout": "index\\tlabel\\ttext -> label\\ttext"}
    lexicon_path = _harness_lexicon(table.texts, table.labels, root)

    # -- detection: the real torchvision detector fine-tuned from random init on synthetic rectangles ---------
    torch.set_num_threads(2)
    train = ma.synthetic_detection_split(DET_TRAIN_N, DET_IMAGE_SIZE, seed=1, name="train", max_boxes=1)
    eval_split = ma.synthetic_detection_split(DET_EVAL_N, DET_IMAGE_SIZE, seed=2, name="eval", max_boxes=1)
    result = tr.train_detector(train, eval_split, epochs=DET_EPOCHS, seed=0, batch_size=8, lr=0.05,
                               anchor_sizes=(4, 6, 8), pretrained=False, threads=2,
                               score_threshold=DET_SCORE_THRESHOLD, log=_quiet)
    weights_path = tr.save_state_dict(result.model, root / "bundled" / DETECTOR_ID / "weights.pt")
    slice_path = root / "datasets" / "local--synthetic-detection-rectangles" / DET_REVISION / ma.EVAL_SLICE_NAME
    tr.write_eval_slice(eval_split, slice_path, dataset_id=ma.SYNTHETIC_DATASET_ID, dataset_revision=DET_REVISION)
    weights = file_entry(root, weights_path)
    det_entry = DatasetEntry(
        id=ma.SYNTHETIC_DATASET_ID, source="local", revision=DET_REVISION, license="n/a",
        license_note="e2e harness double: seeded synthetic rectangles, no licence applies",
        class_names=list(ma.SYNTHETIC_CLASS_NAMES), fixture_only=False,
        notes=["e2e harness double: dark-noise images with one coloured rectangle per image "
               "(redsim.ml.datasets.military_assets.synthetic_detection_split); never a demo dataset"],
        caveats=["synthetic rectangles: recall and mAP describe this build on these pixels only"],
        splits={"train": SplitEntry(name="train", n=train.n, seed=1),
                "eval": SplitEntry(name="eval", n=eval_split.n, seed=2, file=file_entry(root, slice_path))},
    )
    n_gt = int(result.metrics["n_gt_boxes"])
    recall = result.metrics["recall"]
    det_model = ModelEntry(
        id=DETECTOR_ID, name="e2e harness Faster R-CNN (MobileNetV3 320 FPN) on synthetic rectangles",
        modality="detection", format="torch_state_dict", sha256=weights.sha256, size_bytes=weights.size_bytes,
        file=weights, architecture_id=td.ARCHITECTURE_ID, architecture=dict(result.architecture),
        input_shape=[3, DET_IMAGE_SIZE, DET_IMAGE_SIZE], n_classes=len(ma.SYNTHETIC_CLASS_NAMES),
        class_names=list(ma.SYNTHETIC_CLASS_NAMES), dataset_id=det_entry.id, dataset_revision=DET_REVISION,
        dataset_split="eval", train_split="train",
        clean_accuracy=CleanAccuracy(value=float(recall) if recall is not None else 0.0, n=n_gt, split="eval"),
        gradients=True, license="n/a", seed=0, epochs=DET_EPOCHS, training=_sanitize(result.training),
        metrics=_sanitize(result.metrics), library_versions=library_versions(("torch", "torchvision", "numpy")),
        fixture_only=False,
        notes=[f"e2e harness build: {DET_EPOCHS} epochs of SGD from a seeded random initialisation (no COCO cache), "
               f"{DET_TRAIN_N} synthetic {DET_IMAGE_SIZE} px images; clean_accuracy is recall@IoU>=0.5 at score "
               f"threshold {DET_SCORE_THRESHOLD} over {n_gt} ground-truth boxes",
               "Nothing measured on this detector is a demo result."],
        detection=result.detection,
    )
    det_model = stamp_manifest_sha256(with_dataset_caveats(det_model, det_entry))

    # -- one manifest rewrite, then every model (old and new) re-verifies -------------------------------------
    manifest_path = root / MANIFEST_NAME
    manifest = AssetManifest.model_validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    before = sorted(manifest.models)
    manifest.datasets[text_entry.id] = text_entry
    manifest.models[text_model.id] = text_model
    manifest.datasets[det_entry.id] = det_entry
    manifest.models[det_model.id] = det_model
    write_manifest(manifest, manifest_path)
    reparsed = AssetManifest.model_validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    for model_id in [*before, TEXT_MODEL_ID, DETECTOR_ID]:
        problems = verify_model_assets(reparsed, root, model_id)
        assert not problems, f"{model_id}: {list(problems.model) + list(problems.dataset)}"
    h.unload_bundled_targets()
    # The two target modules register their instances at import (D_REGISTRY records who did not import them).
    import redsim.ml.targets.text  # noqa: F401  (registers sms_tfidf_lr in this process)

    assert TEXT_MODEL_ID in TARGETS and DETECTOR_ID in TARGETS
    h.unload_bundled_targets()
    return {
        "root": root, "registry_gap": registry_gap, "fixture_refused": fixture_refused,
        "text_dataset_id": text_entry.id, "text_eval_n": text_entry.splits["eval"].n,
        "text_clean_accuracy": text_model.clean_accuracy.model_dump() if text_model.clean_accuracy else None,
        "lexicon_sha256": hashlib.sha256(lexicon_path.read_bytes()).hexdigest(),
        "det_dataset_id": det_entry.id, "det_n_gt": n_gt, "det_recall": recall, "det_eval_n": eval_split.n,
        "det_metrics": _sanitize(result.metrics),
    }


@pytest.fixture(scope="module")
def text_model(e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], phase_b_assets: dict[str, Any]) -> str:
    """``sms_tfidf_lr`` registered into the project through the bundled admission boundary."""
    from redsim.api.errors import ApiError

    del e2e_bundled  # ordering: the image and URL registrations precede these on the project chain
    try:
        return h.register_bundled(e2e_app, e2e_org.client("remediator"), project_id=e2e_org.project_id,
                                  bundled_id=TEXT_MODEL_ID, actor=e2e_org.actor("remediator"))
    except ApiError as exc:
        if exc.code == "not_found":
            _fail("D_REGISTRY", f"register_bundled_model({TEXT_MODEL_ID!r}) answered {exc.code}: {exc}; "
                                f"TARGETS lacked {phase_b_assets['registry_gap']} before this module imported them")
        raise


@pytest.fixture(scope="module")
def detector_model(e2e_app: E2EApp, e2e_org: E2EOrg, text_model: str, phase_b_assets: dict[str, Any]) -> str:
    """``assets_frcnn_mnv3`` registered into the project through the bundled admission boundary."""
    from redsim.api.errors import ApiError

    del text_model
    try:
        return h.register_bundled(e2e_app, e2e_org.client("remediator"), project_id=e2e_org.project_id,
                                  bundled_id=DETECTOR_ID, actor=e2e_org.actor("remediator"))
    except ApiError as exc:
        if exc.code == "not_found":
            _fail("D_REGISTRY", f"register_bundled_model({DETECTOR_ID!r}) answered {exc.code}: {exc}; "
                                f"TARGETS lacked {phase_b_assets['registry_gap']} before this module imported them")
        raise


# ---------------------------------------------------------------------------
# Campaigns (module-scoped: one text run, one detection run, one image run for the D9 negatives)
# ---------------------------------------------------------------------------


def text_campaign(**overrides: Any) -> dict[str, Any]:
    """Word substitution on the spec 12.3 edit grid with the random-swap control; 12 messages, ``explain_k`` 2."""
    body: dict[str, Any] = {
        "attack_ids": [TEXT_ATTACK_ID],
        "attack_params": {TEXT_ATTACK_ID: {"max_candidates": 4}},
        "norm": "edit",
        "eps_grid": list(TEXT_EDIT_GRID),
        "reference_eps": TEXT_REFERENCE,
        "n_samples": TEXT_N,
        "seed": 0,
        "explain_k": 2,
        "include_control": True,
    }
    body.update(overrides)
    return body


def detection_campaign(**overrides: Any) -> dict[str, Any]:
    """DPatch on the spec 12.3 patch-area grid with the random-patch control; 10 images, ``explain_k`` 2."""
    body: dict[str, Any] = {
        "attack_ids": [DET_ATTACK_ID],
        "attack_params": {DET_ATTACK_ID: {"max_iter": 3, "batch_size": 4}},
        "norm": "patch_area",
        "eps_grid": list(DET_PATCH_GRID),
        "reference_eps": DET_REFERENCE,
        "n_samples": DET_N,
        "seed": 0,
        "explain_k": 2,
        "include_control": True,
    }
    body.update(overrides)
    return body


@pytest.fixture(scope="module")
def image_run(e2e_org: E2EOrg, e2e_bundled: dict[str, str]) -> h.CampaignRun:
    """The shared FGSM + PGD image campaign: the other side of every D9 (i) negative below."""
    result = h.run_campaign_via_api(e2e_org.client("scanner"), e2e_bundled[h.IMAGE_MODEL_ID], h.image_campaign(),
                                    timeout_s=60.0)
    assert result.status == "succeeded", f"run {result.run_id}: {result.stage_table}"
    assert result.campaign is not None, result.campaign_error
    return result


@pytest.fixture(scope="module")
def text_run(e2e_org: E2EOrg, text_model: str, phase_b_assets: dict[str, Any]) -> h.CampaignRun:
    """The text campaign through the API, the admission service and the sandbox child."""
    result = h.run_campaign_via_api(e2e_org.client("scanner"), text_model, text_campaign(), timeout_s=120.0)
    if result.status != "succeeded":
        error = str(result.stage_table.get("error") or result.campaign_error)
        if "unknown target" in error and TEXT_MODEL_ID in error:
            _fail("D_REGISTRY", f"text run {result.run_id} failed inside the sandbox child: {error}; TARGETS lacked "
                                f"{phase_b_assets['registry_gap']} in this process before the module imported them")
        pytest.fail(f"text run {result.run_id} did not succeed: {result.status}; error={error}; "
                    f"stages={result.stage_table.get('stages_done')}")
    assert result.campaign is not None, result.campaign_error
    return result


@pytest.fixture(scope="module")
def detection_run(e2e_org: E2EOrg, detector_model: str) -> h.CampaignRun:
    """The detection campaign through the API, the admission service and the sandbox child."""
    result = h.run_campaign_via_api(e2e_org.client("scanner"), detector_model, detection_campaign(), timeout_s=300.0)
    if result.status != "succeeded":
        pytest.fail(f"detection run {result.run_id} did not succeed: {result.status}; "
                    f"error={result.stage_table.get('error') or result.campaign_error}; "
                    f"stages={result.stage_table.get('stages_done')}")
    assert result.campaign is not None, result.campaign_error
    return result


# ---------------------------------------------------------------------------
# 1. Text: measurements with the realised edit budget and the denominators (26.2 items 6, 7, 9)
# ---------------------------------------------------------------------------


def test_text_campaign_measurements_and_edit_budget(
    e2e_app: E2EApp, e2e_org: E2EOrg, text_model: str, text_run: h.CampaignRun, phase_b_assets: dict[str, Any],
) -> None:
    from redsim.ml.campaign import D3_BOUNDS_LIMITATION
    from redsim.ml.datasets import sms_spam
    from redsim.ml.runners.base import CONTROL_ATTACK_ID
    from redsim.ml.runners.text import (
        NORMS_NOT_APPLICABLE_NOTE,
        TEXT_LIMITATIONS,
        TEXT_SCORING_LIMITATION_TEMPLATE,
        WHITE_BOX_WITH_TEXT_BLACK_BOX,
    )
    from redsim.ml.schema import STANDING_LIMITATIONS
    from redsim.services.ml_campaigns import BUDGET_LABELS, DEFAULT_EDIT_GRID, DEFAULT_EDIT_REFERENCE

    campaign = text_run.campaign
    assert campaign is not None
    body = text_campaign()
    n = body["n_samples"]
    config = campaign["config"]

    # -- the frozen configuration is a text campaign under the edit budget (MODALITIES-06..08, spec 12.3) -----
    assert config["target_id"] == text_model and config["modality"] == "text" and config["norm"] == "edit"
    assert config["eps_grid"] == list(DEFAULT_EDIT_GRID) == TEXT_EDIT_GRID
    assert config["reference_eps"] == DEFAULT_EDIT_REFERENCE == TEXT_REFERENCE
    assert config["dataset_id"] == sms_spam.DATASET_ID == phase_b_assets["text_dataset_id"]
    assert config["target_snapshot"]["detail"]["bundled_id"] == TEXT_MODEL_ID
    assert config["target_snapshot"]["detail"]["manifest"]["modality"] == "text"
    assert config["target_snapshot"]["detail"]["gradients"] is False, "a TF-IDF pipeline exposes no gradients"
    assert campaign["settings_hash"], "the settings hash is the precondition for any comparison (spec 5.6)"
    row = _campaign_row(e2e_app, text_run.run_id)
    assert row["modality"] == "text" and row["kind"] == "attack" and row["settings_hash"] == campaign["settings_hash"]
    admission = _events(e2e_app, f"run:{text_run.run_id}", "attack.run")
    assert len(admission) == 1 and admission[0]["success"] is True
    assert admission[0]["detail"]["modality"] == "text" and admission[0]["detail"]["norm"] == "edit"
    assert admission[0]["detail"]["budget"] == BUDGET_LABELS["edit"] == "edit budget (share of words substituted)"

    # -- measurements by family with k / n everywhere (spec 14.2, 26.2 item 7) -------------------------------
    by_id = _by_id(campaign)
    class_names = set(sms_spam.CLASS_NAMES)
    clean = by_id["m.clean"]
    assert clean["family"] == "clean" and clean["attack_id"] is None
    _assert_counts(clean, n=n, class_names=class_names)
    assert clean["n"] <= phase_b_assets["text_eval_n"]
    for eps in TEXT_EDIT_GRID:
        evasion = by_id[f"m.evasion.{TEXT_ATTACK_ID}.{_eps_tag(eps)}"]
        assert evasion["family"] == "evasion" and evasion["attack_id"] == TEXT_ATTACK_ID
        assert evasion["params"]["eps"] == pytest.approx(eps) and evasion["params"]["norm"] == "edit"
        assert evasion["params"]["max_candidates"] == 4, "the caller's override is the effective value"
        _assert_counts(evasion, n=n, class_names=class_names)
        _assert_asr(evasion, clean)
        # MODALITIES-03: the realised edit share travels on the row; pixel norms are undefined for text.
        realised = evasion["edit_fraction_mean"]
        if realised is None:
            assert any("edit_fraction_mean not computed" in note for note in evasion["notes"]), evasion["notes"]
        else:
            assert 0.0 < realised <= 1.0, (evasion["id"], realised)
            assert any(note.startswith("edit_fraction_mean = ") for note in evasion["notes"]), evasion["notes"]
        assert any(f"budget eps={eps:g}" in note for note in evasion["notes"]), evasion["notes"]
        assert evasion["linf_norm_mean"] is None and evasion["l2_norm_mean"] is None
        assert NORMS_NOT_APPLICABLE_NOTE in evasion["notes"]
        # Black-box, query-counted (spec 12.5 queries): a float per flipped sample, or None with the total in notes.
        assert "queries_mean" in evasion
        if evasion["queries_mean"] is None:
            assert any("queries" in note for note in evasion["notes"]), evasion["notes"]
        else:
            assert evasion["queries_mean"] > 0
        control = by_id[f"m.control.noise.{_eps_tag(eps)}"]
        assert control["family"] == "control" and control["attack_id"] == CONTROL_ATTACK_ID
        assert control["params"]["eps"] == pytest.approx(eps) and control["params"]["norm"] == "edit"
        _assert_counts(control, n=n, class_names=class_names)
        assert control["edit_fraction_mean"] is None or 0.0 < control["edit_fraction_mean"] <= 1.0
        assert any("random word swaps" in note for note in control["notes"]), control["notes"]
        assert "control rows never create a Finding and never enter the MRI" in control["notes"]
    families = [m["family"] for m in campaign["measurements"]]
    assert families.count("clean") == 1 and families.count("evasion") == len(TEXT_EDIT_GRID)
    assert families.count("control") == len(TEXT_EDIT_GRID), "a control accompanies every budget (spec 14.3)"
    reference = by_id[f"m.evasion.{TEXT_ATTACK_ID}.{_eps_tag(TEXT_REFERENCE)}"]
    assert "pert_first_success_mean" in reference
    assert any(note.startswith("pert_first_success_mean") for note in reference["notes"]), reference["notes"]

    # -- limitations: standing, D3, dataset caveats, the text caveats and the edit-budget scoring caveat (14.5)
    limitations = campaign["limitations"]
    assert limitations, "limitations are never empty on a succeeded run (spec 26.2 item 9)"
    for sentence in STANDING_LIMITATIONS:
        assert sentence in limitations, sentence
    assert D3_BOUNDS_LIMITATION in limitations
    assert any(item.startswith(f"Dataset caveat ({sms_spam.DATASET_ID})") for item in limitations), limitations
    for sentence in TEXT_LIMITATIONS:
        assert sentence in limitations, sentence
    assert WHITE_BOX_WITH_TEXT_BLACK_BOX in limitations
    caveat_prefix = TEXT_SCORING_LIMITATION_TEMPLATE.split("{", 1)[0]
    caveats = [item for item in limitations if item.startswith(caveat_prefix)]
    assert caveats, f"the edit-budget scoring caveat is missing: {limitations}"
    assert phase_b_assets["lexicon_sha256"] in caveats[0], "the caveat names the lexicon digest the attack used"
    assert campaign["provenance"]["nondeterminism"], "nondeterminism sources are recorded (spec 14.4)"
    assert campaign["provenance"]["settings_hash"] == campaign["settings_hash"]

    # -- findings: created only above the threshold with the denominator floor, never otherwise (spec 12.6, 15.5)
    from redsim.ml.scoring import MIN_CLEAN_CORRECT_FOR_FINDING

    findings = text_run.findings
    if clean["n_correct"] < MIN_CLEAN_CORRECT_FOR_FINDING:
        assert findings == []
        assert any("denominator too small for a finding" in note for m in campaign["measurements"]
                   if m["family"] == "evasion" for note in m["notes"])
    else:
        crossed = [m for m in campaign["measurements"] if m["family"] == "evasion"
                   and m["attack_success_rate"] is not None
                   and m["attack_success_rate"] >= config["finding_asr_threshold"]]
        assert bool(findings) == bool(crossed), (len(findings), [m["id"] for m in crossed])
        for finding in findings:
            detail = finding["schema_blob"]["ml"]
            assert detail["attack_id"] == TEXT_ATTACK_ID and detail["norm"] == "edit"
            assert finding["schema_blob"]["finding_type"] == "adversarial_ml"
            assert finding["severity"] in {"critical", "high", "medium", "low"}, "severity is derived (26.3 item 16)"

    # -- the campaign never faked a stage: every reported stage is in the spec 6.5 table ----------------------
    table = text_run.stage_table
    assert table["error"] is None and table["stages_done"][-1] == "report"
    assert "defense_apply" not in table["stages"], "an attack run applies no defense"
    for name in ("load_target", "sample", "clean_eval", f"attack:{TEXT_ATTACK_ID}", "control", "score", "report"):
        assert table["stages"][name]["status"] == "succeeded", (name, table["stages"][name])


# ---------------------------------------------------------------------------
# 2. Text: SHAP token observations (26.2 items 6, 8) -- attributed failure on this tree (D_TEXT_OBS)
# ---------------------------------------------------------------------------


def test_text_observations_are_token_level_evidence(e2e_org: E2EOrg, text_run: h.CampaignRun) -> None:
    from redsim.ml.explain.shap_text import TEXT_METRIC_NOTE
    from redsim.ml.schema import TextObservation

    campaign = text_run.campaign
    assert campaign is not None
    observations = campaign["observations"]
    unavailable = _explain_unavailable(campaign, TEXT_ATTACK_ID)
    if not observations and unavailable is not None and "ValidationError" in unavailable:
        _fail("D_TEXT_OBS", f"run {text_run.run_id}: {unavailable}")
    assert observations, f"explain_k > 0 must leave token observations; limitations: {campaign['limitations']}"
    viewer = e2e_org.client("viewer")
    artifacts = _artifact_rows(viewer, text_run.run_id)
    class_names = {"ham", "spam"}
    for obs in observations:
        # Spec 26.2 item 6 / 8: the label is heuristic, the note is the text explainer's own, no image heuristic.
        assert obs["metric_kind"] == "heuristic" and obs["metric_note"] == TEXT_METRIC_NOTE, obs["id"]
        assert obs["center_mass_ratio_clean"] is None and obs["center_mass_ratio_adv"] is None
        assert obs["top_features_clean"] == [] and obs["top_features_adv"] == [], "tabular fields stay empty"
        assert obs["pred_clean"] in class_names and obs["pred_adv"] in class_names and obs["true_label"] in class_names
        assert obs["flipped"] == (obs["pred_adv"] != obs["pred_clean"])
        # MODALITIES-04: the TextObservation block carries positions and counts, never message text.
        block = TextObservation.model_validate(obs["text"])
        assert block.n_tokens >= 1 and 0 <= block.n_changed <= block.n_tokens
        assert all(0 <= p < block.n_tokens for p in block.changed_positions)
        assert all(0 <= p < block.n_tokens for p in block.top_tokens_clean + block.top_tokens_adv)
        assert set(block.attribution_artifacts) <= set(obs["artifacts"])
        # Every cited artifact is listed and downloads byte-for-byte (26.2 item 5).
        assert set(obs["artifact_sha256"]) == set(obs["artifacts"]), obs["id"]
        for name, artifact_id in obs["artifacts"].items():
            row = artifacts.get(artifact_id)
            assert row is not None, f"{obs['id']} cites artifact {artifact_id} that /artifacts does not list"
            assert row["sha256"] == obs["artifact_sha256"][name], (obs["id"], name)
            data = _download(viewer, row)
            if name.endswith(".png"):
                assert data[:8] == _PNG_MAGIC, name
            elif name.endswith(".json"):
                json.loads(data)


# ---------------------------------------------------------------------------
# 3. Text: its own score under the edit budget; never compared with an image run (26.3 items 12, 13, 14)
# ---------------------------------------------------------------------------


def test_text_scorecard_is_its_own_and_never_compared_with_image(
    e2e_app: E2EApp, e2e_org: E2EOrg, text_run: h.CampaignRun, image_run: h.CampaignRun,
    detection_run: h.CampaignRun,
) -> None:
    from redsim.api.errors import INCOMPATIBLE_CAMPAIGNS, PARAMS_OUT_OF_RANGE
    from redsim.ml.campaign import MRI_SCOPE_LIMITATION

    campaign = text_run.campaign
    assert campaign is not None and image_run.campaign is not None and detection_run.campaign is not None
    viewer = e2e_org.client("viewer")

    # Spec 15.4: complete only with all five subscores; a missing S_expl is named, never filled in.
    complete = _assert_score_state(campaign)
    score = campaign["score"]
    if score is not None:
        assert score["norm"] == "edit" and score["eps_grid"] == TEXT_EDIT_GRID
        assert score["reference_eps"] == TEXT_REFERENCE and score["attack_ids"] == [TEXT_ATTACK_ID]
        assert score["settings_hash"] == campaign["settings_hash"]
        # Spec 15.7: every subscore is a 0-100 number (the frozen ``Subscores`` model, redsim/ml/schema.py) and
        # its denominators are the ``score["inputs"]`` rows ``_assert_score_state`` checked (``n`` > 0 each); a
        # subscore value is never a dict. (Test fix: this loop used to look for ``"n"`` inside the float.)
        for key in SUBSCORE_KEYS:
            value = score["subscores"].get(key)
            if value is not None:
                assert isinstance(value, (int, float)) and 0.0 <= value <= 100.0, (key, value)
        assert score["inputs"], "a computed subscore names the rows and denominators it was read from"
    if complete:
        assert MRI_SCOPE_LIMITATION in campaign["limitations"]
    else:
        assert MRI_SCOPE_LIMITATION not in campaign["limitations"], "the scope sentence accompanies a computed MRI only"
        unavailable = _explain_unavailable(campaign, TEXT_ATTACK_ID)
        missing = " ".join(campaign["missing"] or (score or {}).get("missing") or [])
        assert "S_expl" in missing or unavailable is not None, (campaign["missing"], campaign["limitations"])
    row = _campaign_row(e2e_app, text_run.run_id)
    assert (row["score"] is None) == (score is None)
    scored = _events(e2e_app, f"run:{text_run.run_id}", "campaign.score")
    if score is not None:
        assert scored and scored[-1]["detail"]["mri"] == score["mri"]
    else:
        assert not scored, "no campaign.score row without a score record"
    # No banned readiness wording anywhere in the record's own sentences (26.3 item 14).
    for text in [*campaign["limitations"], *(i["statement"] for i in campaign["interpretation"])]:
        assert "deployment-ready" not in text.lower() and "harden before fielding" not in text.lower(), text

    # D9 (i): a text run is never compared with an image or a detection run; the refusal names the modality and
    # reveals no score (both directions, both other modalities).
    assert campaign["settings_hash"] != image_run.campaign["settings_hash"]
    assert campaign["settings_hash"] != detection_run.campaign["settings_hash"]
    for other in (image_run.run_id, detection_run.run_id):
        for left, right in ((text_run.run_id, other), (other, text_run.run_id)):
            compare = viewer.get(f"/v1/runs/{left}/compare", params={"with": right})
            assert compare.status_code == 409, compare.text
            detail = compare.json()["detail"]
            assert detail["code"] == INCOMPATIBLE_CAMPAIGNS == "incompatible_campaigns"
            assert "modality" in detail["reasons"] and "norm" in detail["reasons"], detail["reasons"]
            assert "delta" not in detail and "scorecards" not in detail, "a refusal reveals no score"

    # MODALITIES-08: a text campaign under a pixel norm is refused at admission; no Run is created.
    runs_before = _run_count(e2e_app)
    refused = e2e_org.client("scanner").post(f"/v1/models/{campaign['config']['target_id']}/attacks",
                                             json=text_campaign(norm="linf", eps_grid=[0.01, 0.03, 0.1],
                                                                reference_eps=0.03))
    assert refused.status_code == 422, refused.text
    detail = refused.json()["detail"]
    assert detail["code"] == PARAMS_OUT_OF_RANGE and detail["field"] == "norm"
    assert "edit" in detail["message"] and _run_count(e2e_app) == runs_before
    refusals = [ev for ev in _events(e2e_app, f"project:{e2e_org.project_id}", "attack.run") if not ev["success"]]
    assert refusals and refusals[-1]["detail"]["code"] == PARAMS_OUT_OF_RANGE


# ---------------------------------------------------------------------------
# 4. Detection: rows count boxes, every rate has its denominator (26.2 item 7; MODALITIES-33, -34)
# ---------------------------------------------------------------------------


def test_detection_measurements_count_boxes_with_denominators(
    e2e_app: E2EApp, e2e_org: E2EOrg, detector_model: str, detection_run: h.CampaignRun,
    phase_b_assets: dict[str, Any],
) -> None:
    from redsim.ml.attacks.dpatch import PATCH_CONTROL_ID
    from redsim.ml.datasets import military_assets as ma
    from redsim.ml.runners.detection import CONF_GAP_NOTE, CONTROL_NOTE, RECALL_NOTE, SUPPRESSION_NOTE
    from redsim.ml.schema import DetectionMetrics
    from redsim.services.ml_campaigns import (
        BUDGET_LABELS,
        DEFAULT_PATCH_AREA_GRID,
        DEFAULT_PATCH_AREA_REFERENCE,
    )

    campaign = detection_run.campaign
    assert campaign is not None
    config = campaign["config"]
    assert config["target_id"] == detector_model and config["modality"] == "detection"
    assert config["norm"] == "patch_area" and config["eps_grid"] == list(DEFAULT_PATCH_AREA_GRID) == DET_PATCH_GRID
    assert config["reference_eps"] == DEFAULT_PATCH_AREA_REFERENCE == DET_REFERENCE and config["n_samples"] == DET_N
    assert config["dataset_id"] == ma.SYNTHETIC_DATASET_ID == phase_b_assets["det_dataset_id"]
    assert config["target_snapshot"]["detail"]["bundled_id"] == DETECTOR_ID
    assert config["target_snapshot"]["detail"]["manifest"]["detection"]["score_threshold"] == DET_SCORE_THRESHOLD
    assert _campaign_row(e2e_app, detection_run.run_id)["modality"] == "detection"
    admission = _events(e2e_app, f"run:{detection_run.run_id}", "attack.run")
    assert len(admission) == 1 and admission[0]["success"] is True
    assert admission[0]["detail"]["budget"] == BUDGET_LABELS["patch_area"] and admission[0]["detail"]["norm"] == "patch_area"

    by_id = _by_id(campaign)
    class_names = set(ma.SYNTHETIC_CLASS_NAMES)
    clean = by_id["m.clean"]
    # A detection row's n counts ground-truth boxes, n_correct the boxes matched, accuracy is recall (MODALITIES-33).
    assert clean["family"] == "clean" and clean["n"] > 0, "the slice holds ground-truth boxes"
    assert clean["n"] <= phase_b_assets["det_n_gt"], "at most the whole evaluation split's boxes"
    _assert_counts(clean, n=clean["n"], class_names=class_names)
    assert clean["notes"][0] == RECALL_NOTE.format(iou=0.5, score=DET_SCORE_THRESHOLD)
    assert CONF_GAP_NOTE in clean["notes"] and clean["conf_gap_mean"] is None
    block = DetectionMetrics.model_validate(clean["detection"])
    assert block.n_boxes == clean["n"] and block.n_matched == clean["n_correct"]
    assert block.recall == pytest.approx(clean["accuracy"]) and block.suppression_rate is None
    assert clean["params"]["det_n_boxes"] == clean["n"] and clean["params"]["det_n_images"] == DET_N
    assert clean["params"]["det_score_threshold"] == DET_SCORE_THRESHOLD and clean["params"]["det_iou_threshold"] == 0.5
    n_boxes = clean["n"]
    for eps in DET_PATCH_GRID:
        evasion = by_id[f"m.evasion.{DET_ATTACK_ID}.{_eps_tag(eps)}"]
        assert evasion["family"] == "evasion" and evasion["attack_id"] == DET_ATTACK_ID
        assert evasion["params"]["eps"] == pytest.approx(eps) and evasion["params"]["norm"] == "patch_area"
        assert evasion["params"]["budget"] == "patch_area" and evasion["params"]["max_iter"] == 3
        _assert_counts(evasion, n=n_boxes, class_names=class_names)
        # The suppression rate is n_suppressed / clean matched boxes; None when no clean box matched (14.2).
        _assert_asr(evasion, clean)
        assert SUPPRESSION_NOTE in evasion["notes"]
        evasion_block = DetectionMetrics.model_validate(evasion["detection"])
        assert evasion_block.n_boxes == n_boxes and evasion_block.n_matched == evasion["n_correct"]
        if clean["n_correct"] > 0:
            assert evasion_block.suppression_rate == pytest.approx(evasion["attack_success_rate"])
        else:
            assert evasion_block.suppression_rate is None
        assert evasion["conf_gap_mean"] is None and evasion["conf_gap_n"] is None, "undefined for detection"
        assert evasion["linf_norm_mean"] is not None and evasion["l2_norm_mean"] is not None, "pixel norms recorded"
        control = by_id[f"m.control.noise.{_eps_tag(eps)}"]
        assert control["family"] == "control" and control["attack_id"] == PATCH_CONTROL_ID
        assert control["params"]["eps"] == pytest.approx(eps) and control["params"]["budget"] == "patch_area"
        _assert_counts(control, n=n_boxes, class_names=class_names)
        assert CONTROL_NOTE in control["notes"]
        DetectionMetrics.model_validate(control["detection"])
    families = [m["family"] for m in campaign["measurements"]]
    assert families.count("clean") == 1 and families.count("evasion") == len(DET_PATCH_GRID)
    assert families.count("control") == len(DET_PATCH_GRID), "a random patch of the same area at every budget (12.4)"
    # Denominator floor: a Finding needs at least MIN_CLEAN_CORRECT_FOR_FINDING clean-matched boxes (spec 12.6).
    from redsim.ml.scoring import MIN_CLEAN_CORRECT_FOR_FINDING

    if clean["n_correct"] < MIN_CLEAN_CORRECT_FOR_FINDING:
        assert detection_run.findings == []
        assert any("denominator too small for a finding" in note
                   for m in campaign["measurements"] if m["family"] == "evasion" for note in m["notes"])
    # The stage table names every stage the child completed and nothing it did not.
    table = detection_run.stage_table
    assert table["error"] is None and table["stages_done"][-1] == "report"
    for name in ("load_target", "sample", "clean_eval", f"attack:{DET_ATTACK_ID}", "control", "explain", "score",
                 "report"):
        assert table["stages"][name]["status"] == "succeeded", (name, table["stages"][name])
    assert "defense_apply" not in table["stages"]


# ---------------------------------------------------------------------------
# 5. Detection: the explainer is unavailable and says so; box evidence, never an attribution map (26.2 item 8)
# ---------------------------------------------------------------------------


def test_detection_explainer_unavailable_recorded_honestly(e2e_org: E2EOrg, detection_run: h.CampaignRun) -> None:
    from redsim.ml.runners.detection import EXPLAIN_LIMITATION, OBS_METRIC_NOTE
    from redsim.ml.targets.detection import EXPLAINER_UNAVAILABLE_REASON

    campaign = detection_run.campaign
    assert campaign is not None
    viewer = e2e_org.client("viewer")
    limitations = campaign["limitations"]
    unavailable = _explain_unavailable(campaign, DET_ATTACK_ID)
    assert unavailable is not None and "ExplainerUnavailable" in unavailable, limitations
    assert EXPLAINER_UNAVAILABLE_REASON in unavailable and EXPLAIN_LIMITATION in limitations
    statement = next(i for i in campaign["interpretation"] if i["id"] == f"i.explain.unavailable.{DET_ATTACK_ID}")
    assert statement["kind"] == "inferred" and "ExplainerUnavailable" in statement["statement"]
    assert "S_expl has no input" in statement["statement"]
    assert statement["basis"] == [f"m.evasion.{DET_ATTACK_ID}.{_eps_tag(DET_REFERENCE)}"]
    # Every interpretation basis id resolves to a measurement or observation id (spec 14.1).
    known = {m["id"] for m in campaign["measurements"]} | {o["id"] for o in campaign["observations"]}
    for item in campaign["interpretation"]:
        assert item["kind"] == "inferred" and item["basis"] and set(item["basis"]) <= known, item["id"]

    # Observations are drawn boxes plus a boxes.json; no heatmap, no centre-mass number, no fabricated metric.
    observations = campaign["observations"]
    assert observations, "explain_k > 0 leaves box evidence per observed image"
    artifacts = _artifact_rows(viewer, detection_run.run_id)
    block_seen = False
    for obs in observations:
        assert obs["metric_kind"] == "heuristic" and obs["metric_note"] == OBS_METRIC_NOTE
        assert obs["center_mass_ratio_clean"] is None and obs["center_mass_ratio_adv"] is None
        assert obs["expl_shift"] is None, "no attribution shift exists for a detector"
        assert re.fullmatch(r"\d+/\d+ boxes matched", obs["pred_clean"]) and re.fullmatch(r"\d+/\d+ boxes matched",
                                                                                             obs["pred_adv"])
        assert set(obs["artifacts"]) == {"clean_boxes", "adv_boxes", "boxes"}, sorted(obs["artifacts"])
        assert set(obs["artifact_sha256"]) == set(obs["artifacts"])
        for name, artifact_id in obs["artifacts"].items():
            row = artifacts.get(artifact_id)
            assert row is not None, f"{obs['id']} cites artifact {artifact_id} that /artifacts does not list"
            assert row["sha256"] == obs["artifact_sha256"][name]
            data = _download(viewer, row)
            if name == "boxes":
                doc = json.loads(data)
                assert doc["attack_id"] == DET_ATTACK_ID and doc["eps"] == pytest.approx(DET_REFERENCE)
                assert doc["sample_index"] == obs["sample_index"]
                assert len(doc["ground_truth"]["boxes"]) == len(doc["clean"]["matched_gt"]) == len(
                    doc["adversarial"]["matched_gt"])
                assert f"{sum(doc['clean']['matched_gt'])}/{len(doc['ground_truth']['boxes'])} boxes matched" == obs[
                    "pred_clean"]
                assert doc["patch"] is not None and doc["patch"]["side"] >= 1, "the patch location is recorded"
            else:
                assert data[:8] == _PNG_MAGIC, name
        if obs.get("detection") is not None:
            block_seen = True
            assert obs["detection"]["n_gt"] >= 1
    if not block_seen:
        # Recorded, not asserted away: the B0 block never survives the runner's shape (D_DET_OBS); the same
        # facts are carried by boxes.json above.
        assert all(obs.get("detection") is None for obs in observations)
    # The explain.execute row is honest about zero attribution evidence while box evidence exists.
    assert not any(s.startswith("Explanations were not attempted") for s in limitations)


# ---------------------------------------------------------------------------
# 6. Detection: no MRI by construction, a scorecard with denominators instead (spec 15.4; MODALITIES-36)
# ---------------------------------------------------------------------------


def test_detection_has_no_mri_only_a_scorecard(
    e2e_app: E2EApp, e2e_org: E2EOrg, detection_run: h.CampaignRun,
) -> None:
    from redsim.ml.runners.detection import (
        FORBIDDEN_SCORECARD_KEYS,
        NO_MRI_LIMITATION,
        NO_MRI_REASON,
        PATCH_LIMITATION,
        RECALL_LIMITATION,
        SCORECARD_NAME,
        DetectionScorecard,
        validate_scorecard_payload,
    )
    from redsim.ml.schema import contains_banned_score_word

    campaign = detection_run.campaign
    assert campaign is not None
    viewer = e2e_org.client("viewer")
    by_id = _by_id(campaign)
    clean = by_id["m.clean"]

    # Spec 15.4 / MODALITIES-36: score None with the detection reason; partial completeness naming the dimensions.
    assert campaign["score"] is None, "a detection campaign never carries an MRI record"
    status = campaign["score_status"]
    assert status["state"] == "unavailable" and status["reason"] == NO_MRI_REASON
    assert campaign["completeness"] == "partial"
    missing = " ".join(campaign["missing"])
    assert "S_conf" in missing and "S_expl" in missing, campaign["missing"]
    assert NO_MRI_REASON in campaign["limitations"] and NO_MRI_LIMITATION in campaign["limitations"]
    assert RECALL_LIMITATION in campaign["limitations"] and PATCH_LIMITATION in campaign["limitations"]
    assert not contains_banned_score_word(NO_MRI_REASON) and not _READINESS_RE.search(status["reason"])
    assert _campaign_row(e2e_app, detection_run.run_id)["score"] is None
    assert not _events(e2e_app, f"run:{detection_run.run_id}", "campaign.score"), "no campaign.score row without a score"
    assert detection_run.stage_table["completeness"] == "partial"

    # The detection scorecard artifact: every value with its denominator, no MRI key anywhere. Its kind is the
    # worker's spec 5.8 table entry for SCORECARD_NAME (``ml.detection.scorecard``, docs/architecture/ml-vertical.md);
    # test fix: an earlier revision derived ``ml.detection_scorecard`` from the file stem.
    from redsim.workers.tasks.ml_campaign import artifact_kind

    artifacts = _artifact_rows(viewer, detection_run.run_id)
    kind = artifact_kind(SCORECARD_NAME)
    assert kind == "ml.detection.scorecard"
    rows = [row for row in artifacts.values() if row["kind"] == kind]
    assert len(rows) == 1, f"one {SCORECARD_NAME} artifact (kind {kind}); kinds: {sorted({r['kind'] for r in artifacts.values()})}"
    payload = json.loads(_download(viewer, rows[0]))
    assert payload["kind"] == "detection_scorecards" and payload["reason_no_mri"] == NO_MRI_REASON
    validate_scorecard_payload(payload)
    assert not (_keys_recursive(payload) & FORBIDDEN_SCORECARD_KEYS), sorted(_keys_recursive(payload) & FORBIDDEN_SCORECARD_KEYS)
    card = DetectionScorecard.model_validate(payload["per_attack"][DET_ATTACK_ID])
    assert card.attack_id == DET_ATTACK_ID and card.norm == "patch_area"
    assert card.eps_grid == DET_PATCH_GRID and card.reference_eps == DET_REFERENCE
    assert card.score_threshold == DET_SCORE_THRESHOLD and card.iou_threshold == 0.5
    assert card.settings_hash == campaign["settings_hash"]
    assert card.clean_recall.n == clean["n"] and card.clean_recall.n_correct == clean["n_correct"]
    assert card.worst_case_recall_ratio.n == clean["n"] and card.recall_auc.n == clean["n"]
    if clean["n_correct"] > 0:
        assert card.clean_recall.accuracy == pytest.approx(clean["accuracy"])
        assert card.worst_case_recall_ratio.value is not None and 0.0 <= card.worst_case_recall_ratio.value <= 1.0
        assert card.worst_case_recall_ratio.eps in DET_PATCH_GRID
        assert card.recall_auc.value is not None and 0.0 <= card.recall_auc.value <= 1.0
        reference = by_id[f"m.evasion.{DET_ATTACK_ID}.{_eps_tag(DET_REFERENCE)}"]
        assert card.suppression_rate_at_reference.n == reference["n_clean_correct"] == clean["n_correct"]
        assert card.suppression_rate_at_reference.value == pytest.approx(reference["attack_success_rate"])
    else:
        # Honest zero-recall state: ratios undefined with the reason, never 0.0 or 1.0 by fiat.
        assert card.worst_case_recall_ratio.value is None and card.worst_case_recall_ratio.reason
        assert card.recall_auc.value is None and card.suppression_rate_at_reference.value is None
    for eps in DET_PATCH_GRID:
        point = card.recall_by_eps[f"{eps:g}"]
        row = by_id[f"m.evasion.{DET_ATTACK_ID}.{_eps_tag(eps)}"]
        assert point.n == row["n"] and point.n_correct == row["n_correct"]
        control_point = card.control_recall_by_eps[f"{eps:g}"]
        control = by_id[f"m.control.noise.{_eps_tag(eps)}"]
        assert control_point.n == control["n"] and control_point.n_correct == control["n_correct"]
        assert card.suppression_by_eps[f"{eps:g}"] == row["attack_success_rate"]
    scorecard_statement = next(i for i in campaign["interpretation"] if i["id"] == f"i.detection.scorecard.{DET_ATTACK_ID}")
    assert "No MRI is computed for detection" in scorecard_statement["statement"]
    # The record artifact the route served carries the same absence.
    record_rows = [row for row in artifacts.values() if row["kind"] == "ml.run_record"]
    newest = json.loads(_download(viewer, max(record_rows, key=lambda r: str(r["created_at"]))))
    assert newest["score"] is None and newest["score_status"]["reason"] == NO_MRI_REASON


# ---------------------------------------------------------------------------
# 7. Detection: never compared with an image run; the admission cap is explicit (D9 i; MODALITIES-07)
#    (the detection-versus-text pair is asserted in test 3, which owns the text run)
# ---------------------------------------------------------------------------


def test_detection_compare_refused_with_every_other_modality(
    e2e_app: E2EApp, e2e_org: E2EOrg, detector_model: str, detection_run: h.CampaignRun, image_run: h.CampaignRun,
) -> None:
    from redsim.api.errors import INCOMPATIBLE_CAMPAIGNS, PARAMS_OUT_OF_RANGE
    from redsim.services.ml_campaigns import DETECTION_N_SAMPLES_CAP

    viewer = e2e_org.client("viewer")
    assert detection_run.campaign is not None and image_run.campaign is not None
    assert detection_run.campaign["settings_hash"] != image_run.campaign["settings_hash"]
    for left, right in ((detection_run.run_id, image_run.run_id), (image_run.run_id, detection_run.run_id)):
        compare = viewer.get(f"/v1/runs/{left}/compare", params={"with": right})
        assert compare.status_code == 409, compare.text
        detail = compare.json()["detail"]
        assert detail["code"] == INCOMPATIBLE_CAMPAIGNS
        assert "modality" in detail["reasons"] and "norm" in detail["reasons"], detail["reasons"]
        assert "delta" not in detail and "scorecards" not in detail
    # A member of another organisation learns nothing about the detection run.
    outsider = e2e_org.client(h.OUTSIDER).get(f"/v1/runs/{detection_run.run_id}/compare", params={"with": image_run.run_id})
    assert outsider.status_code == 403, outsider.text

    # MODALITIES-07: the CPU cap on detection n_samples is an admission refusal naming the cap; no Run is created.
    runs_before = _run_count(e2e_app)
    refused = e2e_org.client("scanner").post(f"/v1/models/{detector_model}/attacks",
                                             json=detection_campaign(n_samples=DETECTION_N_SAMPLES_CAP + 1))
    assert refused.status_code == 422, refused.text
    detail = refused.json()["detail"]
    assert detail["code"] == PARAMS_OUT_OF_RANGE and detail["field"] == "n_samples"
    assert detail["cap"] == DETECTION_N_SAMPLES_CAP and _run_count(e2e_app) == runs_before
    # And a detection campaign under a pixel norm is refused the same way (MODALITIES-08).
    refused = e2e_org.client("scanner").post(f"/v1/models/{detector_model}/attacks",
                                             json=detection_campaign(norm="linf", eps_grid=[0.01, 0.03, 0.1],
                                                                     reference_eps=0.03))
    assert refused.status_code == 422 and refused.json()["detail"]["field"] == "norm", refused.text
    assert _run_count(e2e_app) == runs_before
