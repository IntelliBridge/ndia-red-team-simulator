"""Text modality on the ``TinyTextTarget`` double (MODALITIES-13..26, ``ml`` tier, offline).

Covers the tokenizer contract shared by model, masker and attack; training and the manifest entry of the
bundled ``sms_tfidf_lr`` (on an inline corpus, since the committed SMS fixture belongs to wave B0); the
digest-gated text target; the edit-budget bounds, determinism and query counting of ``word_substitution``;
the random word-swap control at the same budget; the SHAP text explainer's alignment rule and noise floor;
and a full text campaign through ``redsim.ml.runners.text`` with denominators on every row.
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path

import pytest

pytest.importorskip("numpy")
pytest.importorskip("sklearn")
pytest.importorskip("shap")

import numpy as np

from redsim.ml import campaign as campaign_mod
from redsim.ml.artifacts import FilesystemSink
from redsim.ml.attacks import ATLAS_TECHNIQUES
from redsim.ml.attacks import word_substitution as ws
from redsim.ml.attacks.registry import ATTACKS, attack_capabilities, attack_norms
from redsim.ml.campaign import run_campaign
from redsim.ml.datasets import sms_spam
from redsim.ml.errors import AttackNotApplicable, DatasetUnavailable, UnsupportedArtifact
from redsim.ml.explain import shap_text
from redsim.ml.explain.base import ExplainOutput
from redsim.ml.runners import text as text_runner
from redsim.ml.runners.base import MODALITY_RUNNERS, ModalityRunnerUnavailable, resolve_runner
from redsim.ml.schema import CampaignConfig, CampaignRecord, MLModelManifest, Observation
from tests.ml.fakes_text import SYNONYMS_TINY, TEXT_CLASS_NAMES, TinyTextTarget, tiny_tsv

pytestmark = pytest.mark.ml

GRID = [0.1, 0.2, 0.3]
REF = 0.2
N = 12


@pytest.fixture(scope="module")
def target() -> TinyTextTarget:
    return TinyTextTarget(seed=0)


@pytest.fixture(scope="module")
def slice_(target: TinyTextTarget):
    return target.sample(N, seed=0)


@pytest.fixture(scope="module")
def lexicon() -> ws.SynonymLexicon:
    return ws.SynonymLexicon.from_json(SYNONYMS_TINY)


@pytest.fixture(scope="module")
def adapter(lexicon: ws.SynonymLexicon) -> ws.WordSubstitutionAdapter:
    return ws.WordSubstitutionAdapter(lexicon=lexicon)


def _quiet(_: str) -> None:
    return None


def _texts(x) -> list[str]:
    return [str(t) for t in x.tolist()]


def _budget(eps: float, text: str) -> int:
    return ws.edit_budget(eps, sms_spam.n_words(text))


class _CountingTarget:
    """Proxy that counts predict_proba rows (to prove the control queries nothing)."""

    def __init__(self, inner: TinyTextTarget) -> None:
        self._inner = inner
        self.rows = 0
        self.id = inner.id

    def predict_proba(self, x):
        self.rows += len(x)
        return self._inner.predict_proba(x)

    def __getattr__(self, name):
        return getattr(self._inner, name)


# --- tokenizer contract ------------------------------------------------------------------------------------

@pytest.mark.parametrize("text", ["Bake the garlic, then simmer.", "(Compost near the greenhouse today)",
                                  "  leading spaces and trailing!!", "single", "", "!!!", "a-b_c 9x"])
def test_tokenizer_matches_shap_text_masker(text: str):
    import shap

    masker = shap.maskers.Text(sms_spam.MASKER_SPLIT_PATTERN)
    masker_tokens = [t for t in masker.tokenizer(text, return_offsets_mapping=True)["input_ids"] if t != ""]
    assert masker_tokens == sms_spam.tokenize(text)
    assert [text[s:e] for s, e in sms_spam.word_spans(text)] == sms_spam.tokenize(text)
    assert re.findall(r"\w+", text) == sms_spam.tokenize(text)


def test_changed_positions_and_edit_fraction():
    a, b = "Bake the garlic, then simmer.", "Roast the garlic, then boil."
    assert sms_spam.changed_positions(a, b) == [0, 4]
    assert sms_spam.edit_fraction(a, b) == pytest.approx(2 / 5)
    assert sms_spam.changed_positions(a, "Bake the garlic then") is None      # token count differs
    assert sms_spam.edit_fraction("", "") is None
    assert ws.edit_budget(0.1, 7) == 1 and ws.edit_budget(0.3, 7) == 3 and ws.edit_budget(0.2, 5) == 1
    assert ws.edit_budget(1.0, 4) == 4 and ws.edit_budget(0.2, 0) == 0


# --- dataset loader ------------------------------------------------------------------------------------------

def test_sms_spam_tsv_and_eval_jsonl_round_trip(tmp_path: Path):
    tsv = tiny_tsv(tmp_path / "corpus.tsv", n_per_class=6)
    table = sms_spam.load_sms_spam(tsv, fixture_only=True)
    assert table.n_rows == 12 and table.class_names == ["ham", "spam"] and table.fixture_only
    assert table.per_class() == {"ham": 6, "spam": 6}
    assert table.source_sha256 == sms_spam.sha256_file(tsv)
    with pytest.raises(DatasetUnavailable, match="hash_mismatch"):
        sms_spam.load_sms_spam(tsv, expected_sha256="0" * 64)
    bad = tmp_path / "bad.tsv"
    bad.write_text("maybe\tunknown label row\n", encoding="utf-8")
    with pytest.raises(DatasetUnavailable, match="unknown label"):
        sms_spam.read_sms_tsv(bad)
    out = tmp_path / "eval.jsonl"
    digest = sms_spam.write_eval_jsonl(out, texts=table.texts[:4], labels=table.labels[:4], indices=np.arange(4))
    texts, y, idx = sms_spam.read_eval_jsonl(out, expected_sha256=digest)
    assert texts == table.texts[:4] and y.tolist() == table.labels[:4].tolist() and idx.tolist() == [0, 1, 2, 3]
    with pytest.raises(DatasetUnavailable):
        sms_spam.read_eval_jsonl(out, expected_sha256="f" * 64)


# --- training and the manifest entry -----------------------------------------------------------------------

def test_train_text_classifier_measures_and_records_tokenizer_spec(tmp_path: Path):
    from redsim.ml.assets.train_text_classifier import train_text_classifier

    table = sms_spam.load_sms_spam(tiny_tsv(tmp_path / "corpus.tsv", n_per_class=20), fixture_only=True)
    result = train_text_classifier(table.texts, table.labels, seed=0, log=_quiet)
    assert result.metrics["n"] == len(result.eval_idx) == 8            # 20 % of 40 rows, stratified
    assert sum(c["n"] for c in result.metrics["per_class"].values()) == result.metrics["n"]
    assert 0.0 <= result.metrics["clean_accuracy"] <= 1.0 and 0.0 <= result.metrics["macro_f1"] <= 1.0
    assert not set(result.train_idx.tolist()) & set(result.eval_idx.tolist())
    spec = result.text_spec
    assert spec["tokenizer_regex"] == sms_spam.TOKEN_PATTERN and spec["masker_split_regex"] == sms_spam.MASKER_SPLIT_PATTERN
    assert spec["lowercase"] is True and spec["ngram_range"] == [1, 2] and spec["vocabulary_size"] > 0
    assert result.training["text"] == spec and result.training["library"] == "scikit-learn"
    same = train_text_classifier(table.texts, table.labels, seed=0, log=_quiet)
    assert same.metrics == result.metrics and same.eval_idx.tolist() == result.eval_idx.tolist()


def test_build_text_asset_writes_verifiable_manifest(tmp_path: Path):
    from redsim.ml.assets.manifest import AssetManifest, load_manifest, verify_manifest, write_manifest
    from redsim.ml.assets.train_text_classifier import TEXT_ARCHITECTURE_ID, TEXT_MODEL_ID, build_text_asset

    root = tmp_path / "assets"
    entry, model = build_text_asset(root, source=tiny_tsv(tmp_path / "corpus.tsv", n_per_class=20), seed=0,
                                    fixture_only=True, log=_quiet)
    assert model.id == TEXT_MODEL_ID and model.modality == "text" and model.format == "sklearn_joblib"
    assert model.architecture_id == TEXT_ARCHITECTURE_ID and model.gradients is False and model.input_shape == []
    assert model.clean_accuracy is not None and model.clean_accuracy.n == entry.splits["eval"].n == 8
    assert model.metrics["macro_f1"] is not None and model.architecture["text"]["tokenizer_regex"] == sms_spam.TOKEN_PATTERN
    assert entry.id == sms_spam.DATASET_ID and entry.license == "CC BY 4.0" and entry.revision == model.dataset_revision
    assert entry.splits["eval"].file is not None and entry.splits["eval"].file.path.endswith("eval.jsonl")
    assert any("Tokenizer contract" in c for c in entry.caveats) and model.dataset_caveats == entry.caveats
    assert all(c in entry.caveats for c in sms_spam.SMS_CAVEATS)
    # The frozen projection validates and the digest is recomputable by a consumer holding only the schema shape.
    projected = MLModelManifest.model_validate(model.model_dump(mode="json"))
    assert projected.manifest_sha256 == model.manifest_sha256
    manifest = AssetManifest.new()
    manifest.datasets[entry.id] = entry
    manifest.models[model.id] = model
    write_manifest(manifest, root / "MANIFEST.json")
    assert verify_manifest(load_manifest(root / "MANIFEST.json"), root) == []
    assert model.text is not None and projected.text is not None, "MLModelManifest.text carries the tokenizer spec"


# --- the bundled target ---------------------------------------------------------------------------------------

def _build_tree(tmp_path: Path) -> Path:
    from redsim.ml.assets.manifest import AssetManifest, write_manifest
    from redsim.ml.assets.train_text_classifier import build_text_asset

    root = tmp_path / "assets"
    entry, model = build_text_asset(root, source=tiny_tsv(tmp_path / "corpus.tsv", n_per_class=20), seed=0,
                                    fixture_only=True, log=_quiet)
    manifest = AssetManifest.new()
    manifest.datasets[entry.id] = entry
    manifest.models[model.id] = model
    write_manifest(manifest, root / "MANIFEST.json")
    return root


def test_bundled_text_target_loads_only_digest_matching_joblib(tmp_path: Path):
    from redsim.ml.targets.text import BundledTextTarget

    absent = BundledTextTarget(assets_dir=tmp_path / "nowhere")
    info = absent.info()
    assert info.status == "not_implemented" and info.domain == "text" and "build-assets" in (info.reason or "")

    root = _build_tree(tmp_path)
    tgt = BundledTextTarget(assets_dir=root)
    info = tgt.info()
    assert info.status == "available" and info.domain == "text" and info.metadata["gradients"] is False
    assert info.metadata["text"]["tokenizer_regex"] == sms_spam.TOKEN_PATTERN and info.metadata["fixture_only"] is True
    tgt.load()
    s = tgt.sample(6, seed=0)
    assert s.x.dtype == object and all(isinstance(t, str) for t in s.x) and s.y.tolist().count(0) == 3
    proba = tgt.predict_proba(s.x)
    assert proba.shape == (6, 2) and proba.dtype == np.float32 and np.allclose(proba.sum(axis=1), 1.0, atol=1e-5)
    assert tgt.torch_model() is None and tgt.sklearn_model() is not None
    with pytest.raises(AttackNotApplicable, match="no ART estimator"):
        tgt.art_classifier()
    assert tgt.synonym_lexicon() is None                      # no <assets>/lexicons in this tree
    m = tgt.manifest()
    assert m["modality"] == "text" and m["format"] == "sklearn_joblib" and m["gradients"] is False
    assert m["text"]["ngram_range"] == [1, 2] and m["manifest_verified"] is True and m["torch_model"] is None
    MLModelManifest.model_validate({k: v for k, v in m.items() if k in MLModelManifest.model_fields})
    assert s.indices.tolist() == sorted(s.indices.tolist(), key=lambda i: s.indices.tolist().index(i))

    # Tampered joblib: refused before deserialisation. Tampered eval slice: DatasetUnavailable.
    model_path = root / "bundled" / "sms_tfidf_lr" / "model.joblib"
    original = model_path.read_bytes()
    model_path.write_bytes(original + b"\x00")
    tampered = BundledTextTarget(assets_dir=root)
    with pytest.raises(UnsupportedArtifact):
        tampered.load()
    model_path.write_bytes(original)
    eval_path = next((root / "datasets").rglob("eval.jsonl"))
    eval_bytes = eval_path.read_bytes()
    eval_path.write_bytes(eval_bytes.replace(b'"label": "ham"', b'"label": "spam"', 1))
    with pytest.raises(DatasetUnavailable):
        BundledTextTarget(assets_dir=root).load()
    eval_path.write_bytes(eval_bytes)
    BundledTextTarget(assets_dir=root).load()

    # A lexicon under <assets>/lexicons/synonyms.json is picked up by synonym_lexicon().
    lex_dir = root / "lexicons"
    lex_dir.mkdir()
    (lex_dir / "synonyms.json").write_bytes(SYNONYMS_TINY.read_bytes())
    with_lex = BundledTextTarget(assets_dir=root)
    lex = with_lex.synonym_lexicon()
    assert isinstance(lex, ws.SynonymLexicon) and lex.synonyms("bake") == ["prune", "roast", "toast"]
    manifest = with_lex.manifest()
    assert manifest["lexicon"]["sha256"] == lex.sha256
    # The target's text block carries the schema name of the token regex (TextModelSpec.token_pattern) and the
    # attack / masker names, all the same value, so the frozen projection never claims whitespace tokenisation.
    assert manifest["text"]["token_pattern"] == manifest["text"]["tokenizer_regex"] == sms_spam.TOKEN_PATTERN
    assert manifest["text"]["masker_split_regex"] == sms_spam.MASKER_SPLIT_PATTERN
    spec = MLModelManifest.model_validate(manifest).text
    assert spec is not None and spec.token_pattern == sms_spam.TOKEN_PATTERN and spec.ngram_range == [1, 2]
    assert with_lex.info().metadata["text"]["token_pattern"] == sms_spam.TOKEN_PATTERN


# --- the attack ----------------------------------------------------------------------------------------------

def test_word_substitution_info_and_capability_tags(adapter: ws.WordSubstitutionAdapter):
    info = adapter.info()
    assert info.id == "word_substitution" and info.domain == "text" and info.family == "evasion"
    assert info.access == "black-box" and info.requires_gradients is False and info.phase == "B"
    assert "counter-fitted" in info.description and any("1907.11932" in r for r in info.references)
    assert {"black_box", "modality:text", "norm:edit", "query_counted", "takes_eps"} <= adapter.capabilities
    assert adapter.norms == frozenset({"edit"}) and adapter.domains == frozenset({"text"})
    assert {"modality:text", "norm:edit", "black_box"} <= attack_capabilities(adapter)
    assert attack_norms(adapter) == attack_norms(ws.CONTROL) == frozenset({"edit"})
    with pytest.raises(ValueError):
        adapter.resolve_params({"eps": 0.0})
    with pytest.raises(ValueError):
        adapter.resolve_params({"eps": 0.2, "max_candidates": 99})
    with pytest.raises(ValueError):
        adapter.resolve_params({"eps": 0.2, "unknown": 1})
    assert adapter.resolve_params({"eps": 0.2}) == {"eps": 0.2, "max_candidates": 8, "min_word_len": 3,
                                                   "preserve_case": True}


@pytest.mark.parametrize("eps", GRID)
def test_word_substitution_respects_edit_budget_and_counts_queries(target, slice_, adapter, eps: float):
    counting = _CountingTarget(target)
    out = adapter.run(counting, slice_.x, slice_.y, {"eps": eps}, seed=0)
    clean, adv = _texts(slice_.x), _texts(out.x_adv)
    assert out.x_adv.dtype == object and len(adv) == len(clean)
    changed_total = 0
    for c, a in zip(clean, adv, strict=True):
        changed = sms_spam.changed_positions(c, a)
        assert changed is not None, "token count must be preserved"
        assert len(changed) <= _budget(eps, c)
        assert re.findall(r"\W+", c) == re.findall(r"\W+", a), "delimiters are kept"
        for pos in changed:
            new = sms_spam.tokenize(a)[pos]
            assert re.fullmatch(r"[^\W\d_]+", new), "a synonym is one alphabetic token"
            assert sms_spam.tokenize(c)[pos][0].isupper() == new[0].isupper(), "case preserved"
        changed_total += len(changed)
    assert math.isnan(out.linf_norm_mean) and math.isnan(out.l2_norm_mean)
    assert counting.rows > 0 and any("predict rows" in n for n in out.notes)
    y_clean = target.predict_proba(slice_.x).argmax(axis=1)
    y_adv = target.predict_proba(out.x_adv).argmax(axis=1)
    n_flipped = int((y_clean != y_adv).sum())
    if n_flipped:
        assert out.queries_mean is not None and out.queries_mean > 0
    else:
        assert out.queries_mean is None and any("denominator 0" in n for n in out.notes)
    assert any(n.startswith("edit budget") for n in out.notes) and ws.DEVIATIONS_NOTE in out.notes
    assert any(n.startswith("lexicon: source=json:synonyms_synthetic_tiny.json") for n in out.notes)
    again = adapter.run(target, slice_.x, slice_.y, {"eps": eps}, seed=0)
    assert _texts(again.x_adv) == adv, "same seed -> identical adversarial texts"
    assert changed_total >= 0


def test_word_substitution_flips_some_predictions_at_the_largest_budget(target, slice_, adapter):
    out = adapter.run(target, slice_.x, slice_.y, {"eps": 0.3}, seed=0)
    y_clean = target.predict_proba(slice_.x).argmax(axis=1)
    y_adv = target.predict_proba(out.x_adv).argmax(axis=1)
    assert int((y_clean != y_adv).sum()) >= 1, "the fixture lexicon offers cross-topic synonyms; expect a flip"
    assert out.queries_mean is not None


def test_word_substitution_without_lexicon_is_not_applicable(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("NLTK_DATA", raising=False)
    bare = TinyTextTarget(seed=0, lexicon=False)
    s = bare.sample(N, seed=0)
    with pytest.raises(AttackNotApplicable, match="no synonym lexicon"):
        ws.ADAPTER.run(bare, s.x, s.y, {"eps": 0.2}, seed=0)
    with pytest.raises(ws.LexiconUnavailable):
        ws.SynonymLexicon.from_nltk_data(Path("/nonexistent/nltk_data"))
    monkeypatch.setenv("NLTK_DATA", "/nonexistent/nltk_data")
    with pytest.raises(AttackNotApplicable):
        ws.resolve_lexicon(bare)


def test_lexicon_filters_to_single_alphabetic_lowercase_tokens():
    lex = ws.SynonymLexicon.from_mapping({"Bake": ["Roast", "two words", "x_y", "bake", "12", "toast"]})
    assert lex.synonyms("BAKE") == ["roast", "toast"] and lex.synonyms("unknown") == []
    assert lex.size == 1 and lex.source == "inline" and len(lex.sha256) == 64


# --- the control ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("eps", GRID)
def test_text_control_swaps_same_budget_and_is_seeded(target, slice_, eps: float):
    counting = _CountingTarget(target)
    out = ws.CONTROL.run(counting, slice_.x, slice_.y, {"eps": eps}, seed=0)
    assert counting.rows == 0, "the control never queries the model"
    clean, ctrl = _texts(slice_.x), _texts(out.x_adv)
    vocabulary = set(ws.slice_vocabulary(clean))
    for c, a in zip(clean, ctrl, strict=True):
        changed = sms_spam.changed_positions(c, a)
        assert changed is not None and len(changed) == _budget(eps, c), "exactly the attack's budget"
        for pos in changed:
            assert sms_spam.tokenize(a)[pos].lower() in vocabulary
    again = ws.CONTROL.run(target, slice_.x, slice_.y, {"eps": eps}, seed=0)
    assert _texts(again.x_adv) == ctrl
    other = ws.CONTROL.run(target, slice_.x, slice_.y, {"eps": eps}, seed=1)
    assert _texts(other.x_adv) != ctrl
    assert ws.CONTROL.info().family == "control" and "family:control" in ws.CONTROL.capabilities


# --- the explainer -------------------------------------------------------------------------------------------

def test_shap_text_explainer_alignment_and_noise_floor(tmp_path: Path, target, slice_, adapter):
    sink = FilesystemSink(tmp_path / "run")
    attack = adapter.run(target, slice_.x, slice_.y, {"eps": REF}, seed=0)
    control = ws.CONTROL.run(target, slice_.x, slice_.y, {"eps": REF}, seed=0)
    proba_clean = target.predict_proba(slice_.x)
    proba_adv = target.predict_proba(attack.x_adv)
    # Break the alignment of one explained sample on purpose: delete a word (token count changes).
    x_adv = np.array(_texts(attack.x_adv), dtype=object)
    flipped = proba_clean.argmax(axis=1) != proba_adv.argmax(axis=1)
    victim = int(np.flatnonzero(~flipped)[0])
    spans = sms_spam.word_spans(str(x_adv[victim]))
    x_adv[victim] = ws.delete_word(str(x_adv[victim]), spans, len(spans) - 1)
    proba_adv = target.predict_proba(x_adv)

    out = shap_text.explain(target, slice_, x_adv, proba_clean, proba_adv, sink, k=2, seed=0, x_ctrl=control.x_adv,
                            eps=REF, attack_id="word_substitution", max_evals=64)
    assert isinstance(out, ExplainOutput)
    assert 1 <= len(out.observations) <= 4
    assert out.expl_shift_n_excluded >= 1, "the sample whose token count changed is excluded and counted"
    assert out.meta["n_alignment_excluded"] >= 1 and out.meta["explainer"] == "PartitionExplainer"
    assert out.expl_shift_noise_floor is not None and out.expl_shift_noise_floor_n is not None
    assert out.meta["max_evals"] == 64 and out.meta["cache"]["enabled"] in (True, False)
    slice_words = {w.lower() for t in _texts(slice_.x) for w in sms_spam.tokenize(t)}
    summary = (tmp_path / "run" / out.meta["artifacts"]["shap_summary.json"]).read_text(encoding="utf-8")
    summary_words = {w.lower() for w in re.findall(r"[A-Za-z]+", summary)}
    topic_words = {w for words in __import__("tests.ml.fakes_text", fromlist=["TOPIC_WORDS"]).TOPIC_WORDS.values() for w in words}
    assert not (summary_words & topic_words), "the campaign-level summary carries no message tokens"
    assert slice_words, "sanity"
    for obs in out.observations:
        assert obs.top_features_clean == [] and obs.top_features_adv == []
        assert obs.center_mass_ratio_clean is None and "token" in obs.metric_note
        assert obs.expl_shift is None or 0.0 <= obs.expl_shift <= 1.0
        diff = json.loads((tmp_path / "run" / obs.artifacts[shap_text.TEXT_DIFF_NAME]).read_text(encoding="utf-8"))
        assert diff["n_tokens_clean"] == len(sms_spam.tokenize(str(slice_.x[obs.sample_index])))
        if diff["aligned"]:
            assert shap_text.TEXT_PLOT_NAME in obs.artifacts
            assert (tmp_path / "run" / obs.artifacts[shap_text.TEXT_PLOT_NAME]).read_bytes()[:4] == b"\x89PNG"
            assert len(diff["shap_clean"]) == len(diff["shap_adv"]) == diff["n_tokens_clean"]
        else:
            assert obs.expl_shift is None
        if "text" in Observation.model_fields:
            block = getattr(obs, "text", None)
            assert block is not None
            n_tokens = block["n_tokens"] if isinstance(block, dict) else block.n_tokens
            assert n_tokens == diff["n_tokens_clean"]
    victim_obs = [o for o in out.observations if o.sample_index == victim]
    assert victim_obs and victim_obs[0].expl_shift is None


def test_shap_text_explainer_refuses_explain_k_zero(tmp_path: Path, target, slice_):
    from redsim.ml.errors import ExplainUnavailable

    proba = target.predict_proba(slice_.x)
    with pytest.raises(ExplainUnavailable):
        shap_text.explain(target, slice_, slice_.x, proba, proba, FilesystemSink(tmp_path / "r"), k=0, seed=0)


# --- the runner: a full text campaign through the frame ---------------------------------------------------

def _config(**overrides) -> CampaignConfig:
    cfg = {"target_id": "tiny_text", "modality": "text", "attack_ids": ["word_substitution"],
           "attack_params": {"word_substitution": {"max_candidates": 4}}, "norm": "edit", "eps_grid": GRID,
           "reference_eps": REF, "n_samples": N, "seed": 0, "explain_k": 2, "dataset_id": "synthetic_text"}
    cfg.update(overrides)
    return CampaignConfig(**cfg)


def test_run_text_is_the_registered_text_runner():
    assert MODALITY_RUNNERS["text"] == "redsim.ml.runners.text:run_text"
    assert resolve_runner("text") is text_runner.run_text
    with pytest.raises(ModalityRunnerUnavailable):
        resolve_runner("holograms")
    # The attacks package registers the text attack with the bundled set; the text control is the runner's own
    # (run directly, its rows recorded as noise_control) and is deliberately not an attack in the catalog.
    assert ATTACKS.get(ws.ATTACK_ID) is ws.ADAPTER and ATTACKS.maybe_get(ws.CONTROL_ID) is None
    assert ATLAS_TECHNIQUES[ws.ATTACK_ID].id == "AML.T0040"


def test_text_campaign_end_to_end_through_the_frame(tmp_path: Path, target):
    stages: list[str] = []
    sink = FilesystemSink(tmp_path / "run")
    rec = run_campaign(_config(), sink, target_override=target, on_stage=stages.append)
    assert isinstance(rec, CampaignRecord) and rec.status == "succeeded" and rec.kind == "attack"
    assert rec.stages_done == stages
    assert rec.stages_done == ["load_target", "sample", "clean_eval", "attack:word_substitution", "control", "explain",
                               "score", "interpret", "recommend", "report"]
    ids = [m.id for m in rec.measurements]
    assert ids[0] == "m.clean"
    for e in ("0.1", "0.2", "0.3"):
        assert f"m.evasion.word_substitution.eps{e}" in ids and f"m.control.noise.eps{e}" in ids
    clean = rec.measurements[0]
    assert clean.n == N and sum(c["n"] for c in clean.per_class.values()) == N
    for m in rec.measurements[1:]:
        assert m.n == N and m.n_clean_correct == clean.n_correct and m.n_flipped_from_clean is not None
        assert m.linf_norm_mean is None and m.l2_norm_mean is None
        assert any(n.startswith("edit_fraction_mean") for n in m.notes), "the realised edit share is on every row"
        assert m.params["norm"] == "edit" and isinstance(m.params["eps"], float)
        assert m.conf_gap_mean is not None and m.conf_gap_n == N
        if m.family == "evasion":
            eps = float(m.params["eps"])
            assert m.edit_fraction_mean is not None, "Measurement.edit_fraction_mean is filled on every text evasion row"
            assert m.edit_fraction_mean <= eps + 1 / 5 + 1e-9, "bounded by ceil(eps * n_words) with n_words >= 5"
            assert any(n.startswith("edit budget") for n in m.notes) and ws.DEVIATIONS_NOTE in m.notes
            assert any(n.startswith("lexicon: source=json:synonyms_synthetic_tiny.json") for n in m.notes)
        else:
            assert m.attack_id == "noise_control" and any("text_noise_control" in n for n in m.notes)
    ref_row = next(m for m in rec.measurements if m.id == "m.evasion.word_substitution.eps0.2")
    assert ref_row.expl_shift_mean is not None and 0.0 <= ref_row.expl_shift_mean <= 1.0
    assert ref_row.expl_shift_n is not None and ref_row.expl_shift_n >= 1
    assert ref_row.expl_shift_noise_floor is not None and ref_row.expl_shift_noise_floor_n is not None
    if ref_row.pert_first_success_mean is not None:
        assert 0.0 < ref_row.pert_first_success_mean <= 1.0 and ref_row.pert_first_success_n
    # The score is complete (five subscores) or partial with the reason named; never invented.
    assert rec.score is not None and rec.score.norm == "edit"
    if rec.score.mri is None:
        assert rec.score.completeness == "partial" and rec.score.missing and rec.missing
    else:
        assert rec.score.grade is not None and rec.completeness == "complete"
    assert [c.attack_id for c in rec.curve] == ["word_substitution"] and rec.curve[0].norm == "edit"
    assert len(rec.curve[0].points) == 3 and len(rec.curve[0].control) == 3
    assert rec.attacks[0].id == "word_substitution" and rec.target.domain == "text"
    assert rec.provenance is not None and rec.provenance.settings_hash == rec.settings_hash
    assert rec.provenance.sklearn is not None
    assert any("PartitionExplainer" in s for s in rec.provenance.nondeterminism)
    assert any("seeded candidate order" in s for s in rec.provenance.nondeterminism)
    # Limitations: standing -> D3 -> dataset caveats and stage notes -> text limitations (trailing).
    assert rec.limitations[0].startswith("synthetic_text is an open, unclassified public benchmark")
    assert campaign_mod.D3_BOUNDS_LIMITATION in rec.limitations
    for lim in (text_runner.WHITE_BOX_WITH_TEXT_BLACK_BOX, *text_runner.TEXT_LIMITATIONS):
        assert lim in rec.limitations
    d3 = rec.limitations.index(campaign_mod.D3_BOUNDS_LIMITATION)
    caveat = next(i for i, s in enumerate(rec.limitations) if s.startswith("Dataset caveat (synthetic_text)"))
    text_lim = rec.limitations.index(text_runner.TEXT_LIMITATIONS[0])
    assert d3 < caveat < text_lim
    assert any(s.startswith("The edit-budget grid is a share of words") and "sha256=" in s for s in rec.limitations)
    if rec.score.mri is not None:
        assert campaign_mod.MRI_SCOPE_LIMITATION in rec.limitations
    # Every citation resolves; candidates carry no measurement of their effect.
    known = {m.id for m in rec.measurements} | {o.id for o in rec.observations} | {i.id for i in rec.interpretation}
    assert all(b in known for i in rec.interpretation for b in i.basis)
    assert all(r.status == "candidate" for r in rec.recommendations)
    assert rec.observations and all(o.top_features_clean == [] for o in rec.observations)
    # Artifacts.
    run_dir = tmp_path / "run"
    assert (run_dir / "artifacts" / "run_record.json").is_file()
    flip = json.loads((run_dir / "artifacts" / "flip_matrix.json").read_text(encoding="utf-8"))
    assert flip["norm"] == "edit" and flip["attack_ids"] == ["word_substitution"] and len(flip["n_words"]) == N
    assert flip["budget"] == text_runner.BUDGET_LABEL
    assert set(flip["flipped"]["word_substitution"]) == {"eps0.1", "eps0.2", "eps0.3"}
    assert all(len(v) == N for v in flip["edit_fraction"]["word_substitution"].values())
    adv_rows = [json.loads(line) for line in
                (run_dir / "artifacts" / "adv_slice" / "word_substitution_eps0.2.jsonl").read_text("utf-8").splitlines()]
    assert len(adv_rows) == N and {"index", "text", "label"} <= set(adv_rows[0])
    assert (run_dir / "artifacts" / "curve" / "word_substitution.json").is_file()
    assert (run_dir / "artifacts" / "curve" / "robustness_curve.png").read_bytes()[:4] == b"\x89PNG"
    summary_txt = (run_dir / "artifacts" / "shap_summary.txt").read_text(encoding="utf-8")
    from tests.ml.fakes_text import TOPIC_WORDS

    topic_words = {w for words in TOPIC_WORDS.values() for w in words}
    assert not ({w.lower() for w in re.findall(r"[A-Za-z]+", summary_txt)} & topic_words), "no message text in the summary"
    # The record round-trips through JSON under this tree's schema.
    again = CampaignRecord.model_validate_json((run_dir / "artifacts" / "run_record.json").read_text("utf-8"))
    assert again.run_id == rec.run_id and len(again.measurements) == len(rec.measurements)
    assert again.config.norm == "edit" and again.config.modality == "text"


def test_text_campaign_records_not_run_without_a_lexicon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("NLTK_DATA", raising=False)
    bare = TinyTextTarget(seed=0, lexicon=False)
    rec = run_campaign(_config(explain_k=2), FilesystemSink(tmp_path / "run"), target_override=bare)
    assert rec.status == "succeeded" and rec.attacks == [] and rec.score is None
    assert rec.score_status is not None and rec.score_status.state == "unavailable"
    assert any(i.id == "i.attack.not_run.word_substitution" for i in rec.interpretation)
    assert any("no synonym lexicon" in s for s in rec.limitations)
    assert [m.family for m in rec.measurements] == ["clean", "control", "control", "control"]
    assert "attack:word_substitution" not in rec.stages_done and "explain" not in rec.stages_done
    assert not any(s.startswith("The edit-budget grid") for s in rec.limitations), "no scoring statement without a score"
    flip = json.loads((tmp_path / "run" / "artifacts" / "flip_matrix.json").read_text(encoding="utf-8"))
    assert flip["not_run"] and flip["attack_ids"] == []


def test_text_runner_refuses_a_non_edit_norm(tmp_path: Path, target):
    # The frame refuses before any stage (spec 12.3: an adapter is evaluated only in a norm it declares) ...
    with pytest.raises(AttackNotApplicable, match="supports the edit norm only; the campaign norm is 'linf'"):
        run_campaign(_config(norm="linf"), FilesystemSink(tmp_path / "a"), target_override=target)
    # ... and the runner keeps its own guard for a caller that bypasses the frame.
    with pytest.raises(ValueError, match="norm is 'edit'"):
        text_runner.run_text(_config(norm="linf"), target, frame=None)  # type: ignore[arg-type]


def test_default_edit_grid_fits_the_config_validator():
    cfg = _config(eps_grid=list(ws.DEFAULT_EDIT_GRID), reference_eps=ws.DEFAULT_EDIT_REFERENCE)
    assert cfg.eps_grid == [0.1, 0.2, 0.3] and cfg.reference_eps == 0.2 and cfg.norm == "edit"
    assert TEXT_CLASS_NAMES == ["cooking", "gardening", "astronomy"]
