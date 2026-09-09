"""LLM core: catalog, ``PythiaGenerator``, the probe child, scorecard, rules and report (plan 12 wave B2, llm-core).

The pure-Python parts (catalog, scorecard, rules, report fragment) run in the
default tier with no garak installed. The tests that build the generator or
spawn ``python -m redsim.ml.llm.probe_child`` carry the ``garak`` marker and
run against :class:`tests.ml.fake_openai_server.FakeOpenAIServer` on
127.0.0.1: no gateway, no key, no network. The key used everywhere is the
low-entropy fake ``pk_fake_probe_key_not_real_0001``.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from redsim.ml.llm import catalog as catalog_mod
from redsim.ml.llm.catalog import (
    AUDIT_ACTION_MAX,
    CORE_MODULES,
    CORE_SET,
    DETECTOR_OFFLINE_REASON,
    EXPECTED_GARAK_VERSION,
    EXTENDED_SET,
    SHORT_ID_MAX,
    audit_action_for,
    load_catalog,
    resolve_selection,
    row_id,
)
from redsim.ml.llm.probe_child import (
    KEY_FILE,
    ChildDetectorCounts,
    ChildProbeResult,
    ChildResult,
    LLMProbeChildSpec,
    cap_probe_prompts,
)
from redsim.ml.llm.report_section import (
    LLM_SECTION_HEADING,
    NO_SCORECARD_NOTE,
    SECTION_HEADINGS,
    check_llm_report_text,
    render_llm_reports,
    render_llm_section,
)
from redsim.ml.llm.rules import RERUN_RULE_ID, interpret, recommend
from redsim.ml.llm.runner import (
    ALLOWED_REDSIM_KEYS,
    FORBIDDEN_ENV_PREFIXES,
    ChildOutcome,
    ProbeChildTimeout,
    ProbeRunnerConfig,
    build_child_env,
    prepare_work_dir,
    run_probe_child,
)
from redsim.ml.llm.scorecard import (
    D9_SENTENCE,
    GUARDRAIL_TEXT,
    DetectorResult,
    LLMProbeScorecard,
    assert_no_mri,
    build_scorecard,
)
from redsim.ml.schema import BANNED_SCORE_WORDS
from tests.ml.fake_openai_server import DAN_REPLY, DEFAULT_TOKEN, REFUSAL_REPLY, FakeOpenAIServer

ROOT = Path(__file__).resolve().parents[2]
FAKE_KEY = DEFAULT_TOKEN
MODEL_ID = "amazon/nova-micro-v1:0"

#: What a worker parent realistically holds; none may reach the child (low-entropy fakes, never credentials).
PARENT_SECRETS: dict[str, str] = {
    "PYTHIA_API_KEY": "pk_parent_narrative_key_not_real_0002",
    "PYTHIA_BASE_URL": "https://pythia.example.invalid",
    "PYTHIA_PERSONA": "default",
    "REDSIM_DB_URL": "postgresql://user:pw@db.invalid/redsim",
    "REDSIM_S3_SECRET_ACCESS_KEY": "fake-s3-secret-not-real",
    "REDSIM_WORKER_SIGNING_KEY": "fake-signing-key-not-real",
    "REDSIM_AUTH_PROFILES_KEY": "fake-fernet-key-not-real",
    "AWS_SECRET_ACCESS_KEY": "fake-aws-secret-not-real",
    "KAGGLE_KEY": "fake-kaggle-key",
    "OPENAI_API_KEY": "fake-openai-key-not-real",
    "HF_TOKEN": "fake-hf-token",
}
FORBIDDEN_CHILD_NAMES = ("PYTHIA_", "AWS_", "KAGGLE", "OPENAI", "HF_TOKEN")
_RATE = re.compile(r"\d+/\d+ \(\d\.\d{4}\)")


def _dan_prompt_substring() -> str:
    """A distinctive fragment of a garak DAN prompt, read from garak's own data file (never committed here)."""
    garak = pytest.importorskip("garak")
    path = Path(garak.__file__).resolve().parent / "data" / "dan" / "Dan_11_0.json"
    prompts = json.loads(path.read_text(encoding="utf-8"))
    text = str(prompts[0])
    # garak substitutes ``{generator.name}``-style placeholders at load time: take eight plain words from
    # the longest brace-free stretch so the fragment is what actually went over the wire.
    segments = sorted(re.split(r"\{[^}]*\}", text), key=len, reverse=True)
    for segment in segments:
        match = re.search(r"(?:[A-Za-z]+ ){7}[A-Za-z]+", segment)
        if match:
            return match.group(0)
    raise AssertionError("no brace-free fragment in the DAN prompt")


# ---------------------------------------------------------------------------
# Catalog (no garak needed)
# ---------------------------------------------------------------------------


_BLOCKED_IMPORT_PROBE = r"""
import importlib, json, sys
blocked = %r
for name in blocked:
    sys.modules[name] = None
for name in ("redsim.ml.llm", "redsim.ml.llm.catalog", "redsim.ml.llm.scorecard", "redsim.ml.llm.rules",
             "redsim.ml.llm.report_section", "redsim.ml.llm.probe_child", "redsim.ml.llm.runner"):
    importlib.import_module(name)
from redsim.ml.llm.catalog import load_catalog
cat = load_catalog()
loaded = sorted(m for m in sys.modules if m.split(".")[0] in blocked and sys.modules[m] is not None)
print(json.dumps({"n": len(cat.probes), "loaded": loaded, "scoring": "redsim.ml.scoring" in sys.modules}))
"""


def test_llm_modules_import_without_garak_or_ml_libraries() -> None:
    """The API may import the catalog, scorecard, rules and report modules: no garak, openai, litellm, torch."""
    blocked = ("garak", "openai", "litellm", "torch", "transformers", "shap", "sklearn", "art", "onnxruntime")
    proc = subprocess.run(
        [sys.executable, "-c", _BLOCKED_IMPORT_PROBE % (blocked,)],
        capture_output=True, text=True, cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT)}, timeout=120, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out["loaded"] == []
    assert out["n"] > 0
    # D9: nothing in the LLM package pulls the MRI module in.
    assert out["scoring"] is False


def test_llm_package_never_imports_the_scoring_module() -> None:
    """D9 in the import graph: no module of the LLM package imports ``redsim.ml.scoring`` or names ``MRIRecord``."""
    package = ROOT / "redsim" / "ml" / "llm"
    import_line = re.compile(r"^\s*(?:from\s+redsim\.ml\.scoring\b|import\s+redsim\.ml\.scoring\b)", re.MULTILINE)
    for path in package.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not import_line.search(text), path
        assert "MRIRecord" not in text, path


def test_catalog_sets_short_ids_and_exclusions() -> None:
    cat = load_catalog()
    assert cat.garak_version == EXPECTED_GARAK_VERSION
    core = cat.probe_ids_for_set(CORE_SET)
    extended = cat.probe_ids_for_set(EXTENDED_SET)
    assert core and set(core) <= set(extended)
    by_id = cat.by_id()
    for pid in core:
        assert by_id[pid].detector_offline is True
        assert by_id[pid].status == "available"
    assert {by_id[p].module for p in core} == set(CORE_MODULES)
    hf_only = set(extended) - set(core)
    assert hf_only and all(by_id[p].detector_offline is False for p in hf_only)
    for probe in cat.probes:
        assert len(probe.short_id) <= SHORT_ID_MAX
        assert len(audit_action_for(probe)) <= AUDIT_ACTION_MAX
        if probe.status == "excluded":
            assert probe.sets == [] and probe.exclusion_reason
    long_name = by_id["donotanswer.DiscriminationExclusionToxicityHatefulOffensive"]
    assert long_name.short_id != long_name.cls and len(audit_action_for(long_name)) <= AUDIT_ACTION_MAX
    fitd = by_id["fitd.FITD"]
    assert fitd.status == "excluded" and fitd.exclusion_decision == "LLM-08" and "HarmBench" in (fitd.exclusion_reason or "")
    assert by_id["dan.DanInTheWild"].data_files == ["inthewild_jailbreak_llms.json"]
    assert "not redistributed" in by_id["dan.DanInTheWild"].upstream_licence_note
    assert by_id["dan.DanInTheWildFull"].status == "excluded"


def test_resolve_selection_reports_every_refusal() -> None:
    cat = load_catalog()
    sel = resolve_selection(cat, probe_ids=["dan.Dan_11_0", "nope.Nope", "fitd.FITD", "realtoxicityprompts.RTPBlank"])
    assert sel.runnable == ["dan.Dan_11_0"]
    assert sel.unknown == ["nope.Nope"]
    assert "fitd.FITD" in sel.excluded
    assert sel.detector_unavailable == {"realtoxicityprompts.RTPBlank": DETECTOR_OFFLINE_REASON}
    hf = resolve_selection(cat, probe_ids=["realtoxicityprompts.RTPBlank"], detector_mode="hf")
    assert hf.runnable == ["realtoxicityprompts.RTPBlank"]
    core = resolve_selection(cat, probe_set=CORE_SET)
    assert core.runnable == cat.probe_ids_for_set(CORE_SET) and not core.unknown
    with pytest.raises(ValueError):
        resolve_selection(cat)


@pytest.mark.garak
def test_committed_catalog_matches_a_fresh_regeneration(garak_env: dict[str, str]) -> None:
    pytest.importorskip("garak")
    fresh = catalog_mod.build_catalog_from_garak()
    assert catalog_mod.canonical_json(fresh) == catalog_mod.canonical_json(load_catalog())


# ---------------------------------------------------------------------------
# Scorecard, rules, report (no garak needed)
# ---------------------------------------------------------------------------


def _counts(detector: str, passed: int, fails: int, nones: int = 0) -> ChildDetectorCounts:
    return ChildDetectorCounts(detector=detector, passed=passed, fails=fails, nones=nones,
                               total_evaluated=passed + fails, total_processed=passed + fails + nones)


def _fixture_child_result() -> ChildResult:
    return ChildResult(
        status="succeeded", garak_version=EXPECTED_GARAK_VERSION, model_id=MODEL_ID, persona="redteam",
        gateway_host="127.0.0.1", seed=0, max_prompts_per_probe=4, detector_mode="offline",
        probes_requested=["dan.Dan_11_0", "dan.DanInTheWild", "encoding.InjectBase64", "test.Blank",
                          "realtoxicityprompts.RTPBlank", "nope.Nope"],
        probes_run=["dan.Dan_11_0", "dan.DanInTheWild", "encoding.InjectBase64", "test.Blank"],
        probes=[
            ChildProbeResult(probe_id="dan.Dan_11_0", status="run", n_prompts_loaded=1, n_prompts_after_cap=1,
                             n_attempts_complete=1, n_outputs=1, detectors=[_counts("dan.DAN", 0, 1)]),
            ChildProbeResult(probe_id="dan.DanInTheWild", status="run", n_prompts_loaded=4, n_prompts_after_cap=4,
                             n_attempts_complete=4, n_outputs=4, detectors=[_counts("mitigation.MitigationBypass", 3, 1)]),
            ChildProbeResult(probe_id="encoding.InjectBase64", status="run", n_prompts_loaded=4, n_prompts_after_cap=4,
                             n_attempts_complete=4, n_outputs=4, detectors=[_counts("encoding.DecodeMatch", 4, 0)]),
            ChildProbeResult(probe_id="test.Blank", status="run", n_prompts_loaded=1, n_prompts_after_cap=1,
                             n_attempts_complete=1, n_outputs=1, n_outputs_none=1,
                             detectors=[_counts("any.AnyOutput", 0, 0, nones=1)]),
            ChildProbeResult(probe_id="realtoxicityprompts.RTPBlank", status="not_run", reason=DETECTOR_OFFLINE_REASON),
            ChildProbeResult(probe_id="nope.Nope", status="not_run", reason="unknown_probe"),
        ],
        usage={"requests": 10, "responses_ok": 10, "prompt_tokens": 210, "completion_tokens": 70, "total_tokens": 280,
               "models_seen": {MODEL_ID: 10}, "tls_mode": "injected", "wall_time_s": 0.5},
    )


def _fixture_scorecard(**overrides: Any) -> LLMProbeScorecard:
    kwargs: dict[str, Any] = {"run_id": "run-llm-1", "target_id": "tgt-llm-1", "guardrail_mode": "permission_gate_only"}
    kwargs.update(overrides)
    return build_scorecard(_fixture_child_result(), **kwargs)


def test_scorecard_denominators_and_none_rate() -> None:
    card = _fixture_scorecard(probe_set=None, probe_ids_requested=_fixture_child_result().probes_requested)
    rows = {d.row_id: d for _, d in card.rows()}
    dan = rows[row_id("dan.Dan_11_0", "dan.DAN")]
    assert (dan.n_hits, dan.n_evaluated, dan.hit_rate) == (1, 1, 1.0)
    wild = rows[row_id("dan.DanInTheWild", "mitigation.MitigationBypass")]
    assert (wild.n_hits, wild.n_passed, wild.n_evaluated) == (1, 3, 4) and wild.hit_rate == pytest.approx(0.25)
    blank = rows[row_id("test.Blank", "any.AnyOutput")]
    assert blank.n_evaluated == 0 and blank.hit_rate is None and blank.n_none == 1
    assert "denominator 0" in blank.fraction()
    # not_run probes keep a row naming the primary detector and the reason; unknown probes have no detector row.
    rtp = rows[row_id("realtoxicityprompts.RTPBlank", "unsafe_content.ToxicCommentModel")]
    assert rtp.status == "not_run" and rtp.reason == DETECTOR_OFFLINE_REASON and rtp.n_evaluated == 0
    assert [p.probe_id for p in card.not_run()] == ["nope.Nope", "realtoxicityprompts.RTPBlank"]
    assert card.completeness == "partial"
    assert [f.family for f in card.families] == ["dan", "encoding", "nope", "realtoxicityprompts", "test"]
    totals = card.totals()
    assert totals["n_probes_run"] == 4 and totals["n_probes_not_run"] == 2 and totals["n_prompts_sent"] == 10
    assert set(totals) == {"n_probes_requested", "n_probes_run", "n_probes_not_run", "n_probes_failed", "n_rows",
                           "n_rows_with_hits", "n_prompts_sent"}  # counts only, never a pooled rate
    assert card.usage.prompt_tokens == 210 and card.usage.models_seen == {MODEL_ID: 10}


def test_scorecard_forbids_mri_grade_and_subscore_keys() -> None:
    card = _fixture_scorecard()
    dumped = card.model_dump(mode="json")
    assert_no_mri(dumped)
    for key in ("mri", "grade", "subscores", "S_acc", "MRI", "mri_delta"):
        with pytest.raises(ValueError):
            assert_no_mri({**dumped, key: 1})
        with pytest.raises(ValueError):
            assert_no_mri({"families": [{"probes": [{key: 0.5}]}]})
    with pytest.raises(ValueError):
        LLMProbeScorecard.model_validate({**dumped, "mri": 72})
    with pytest.raises(ValueError):
        LLMProbeScorecard.model_validate({**dumped, "limitations": ["only this"]})
    with pytest.raises(ValueError):
        DetectorResult(row_id="x", detector="d", n_evaluated=4, n_hits=1, n_passed=3, hit_rate=0.5)
    with pytest.raises(ValueError):
        DetectorResult(row_id="x", detector="d", n_evaluated=0, n_hits=0, n_passed=0, hit_rate=0.0)


def test_scorecard_limitations_state_d9_and_guardrail_mode() -> None:
    for mode in ("permission_gate_only", "content_filtered", "unknown"):
        card = _fixture_scorecard(guardrail_mode=mode)
        assert card.limitations[0] == D9_SENTENCE
        assert GUARDRAIL_TEXT[mode] in card.limitations
        assert any("HarmBench" in line for line in card.limitations)
        assert any("realtoxicityprompts.RTPBlank" in line for line in card.limitations)
        assert not any(w in " ".join(card.limitations).lower() for w in ("readiness", "certif"))
    auto = build_scorecard(_fixture_child_result().model_copy(update={"model_id": "pythia/auto"}),
                           run_id="r", target_id="t", guardrail_mode="unknown")
    assert any("pythia/auto is not a stable target" in line for line in auto.limitations)


def test_rules_fire_on_dan_hits_and_always_ask_for_a_rerun() -> None:
    card = _fixture_scorecard()
    recs = recommend(card, hit_threshold=0.2)
    by_id = {r.id: r for r in recs}
    assert set(by_id) == {"r.L1", RERUN_RULE_ID}
    dan_rows = {row_id("dan.Dan_11_0", "dan.DAN"), row_id("dan.DanInTheWild", "mitigation.MitigationBypass")}
    assert set(by_id["r.L1"].triggered_by) == dan_rows
    for rec in recs:
        assert rec.status == "candidate" and rec.validation == "not evaluated" and rec.measured is None
        assert rec.narrative is None and rec.narrative_source == "rules"
        assert rec.references and all(ref.startswith("https://") for ref in rec.references)
        assert "0.2" in rec.rationale or rec.id == RERUN_RULE_ID
    assert any("garak.probes.dan" in ref for ref in by_id["r.L1"].references)
    # A higher threshold silences the DAN rule but never the rerun rule.
    assert {r.id for r in recommend(card, hit_threshold=0.5)} == {"r.L1", RERUN_RULE_ID}  # Dan_11_0 is 1/1
    assert {r.id for r in recommend(card, hit_threshold=1.01)} == {RERUN_RULE_ID}
    interp = interpret(card, hit_threshold=0.2)
    ids = {i.id for i in interp}
    assert f"i.{row_id('dan.Dan_11_0', 'dan.DAN')}" in ids and "i.llm.nope.Nope.not_run" in ids
    for item in interp:
        assert item.kind == "inferred" and item.basis
    blank = next(i for i in interp if i.id == f"i.{row_id('test.Blank', 'any.AnyOutput')}")
    assert "denominator 0" in blank.statement


def test_report_sections_fractions_escaping_and_no_score_words() -> None:
    card = _fixture_scorecard(probe_set=CORE_SET)
    hostile = card.model_copy(update={"persona": "<script>alert(1)</script>"})
    reports = render_llm_reports(hostile, artifacts={"ml.llm.report_jsonl": {"kind": "ml.llm.report_jsonl", "id": "a1",
                                                                             "sha256": "0" * 64, "size_bytes": 10}})
    names = [name for name, _, _ in reports]
    assert names == ["report.md", "report.json", "report.html"]
    md = reports[0][1].decode()
    html = reports[2][1].decode()
    positions = [md.index(h) for h in SECTION_HEADINGS]
    assert positions == sorted(positions)
    assert md.count(D9_SENTENCE) == 1
    # Every rate is preceded by its k/n fraction; a zero denominator never renders as a rate.
    for match in re.finditer(r"\((\d\.\d{4})\)", md):
        assert _RATE.search(md[max(0, match.start() - 12): match.end()]), md[match.start() - 30: match.end()]
    assert "0/0 (not computed, denominator 0)" in md
    assert check_llm_report_text(md) == [] and check_llm_report_text(html) == []
    assert not any(re.search(rf"\b{re.escape(w)}\b", md, re.IGNORECASE) for w in BANNED_SCORE_WORDS)
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "candidate · not evaluated" in md and "Expected gain: not measured" in md
    assert "prompts and responses" in md.lower()
    payload = json.loads(reports[1][1])
    assert payload["kind"] == "llm_probe" and payload["narrative_source"] == "rules"
    assert LLMProbeScorecard.model_validate(payload["scorecard"]) == hostile
    assert_no_mri(payload)
    fragment = render_llm_section(card)
    assert fragment.markdown.startswith(LLM_SECTION_HEADING)
    assert "<h2>" in fragment.html and "<!doctype" not in fragment.html


def test_section_hook_accepts_records_and_stays_honest_without_a_scorecard() -> None:
    """``redsim.ml.reporting._llm_section`` hands a record over and iterates the result as Markdown lines."""
    from types import SimpleNamespace

    card = _fixture_scorecard()
    dumped = card.model_dump(mode="json")
    # The scorecard itself, its dump, a record carrying it, and a record whose manifest carries it.
    for record in (card, dumped, SimpleNamespace(scorecard=dumped),
                   SimpleNamespace(provenance=SimpleNamespace(model_manifest={"llm_scorecard": dumped}))):
        fragment = render_llm_section(record)
        lines = list(fragment)
        assert lines[0] == LLM_SECTION_HEADING and str(fragment) == fragment.markdown
        assert fragment.scorecard == card and any(SECTION_HEADINGS[1] == line for line in lines)
        assert fragment.markdown.count(D9_SENTENCE) == 1 and "<h2>" in fragment.html
    # A campaign-shaped record without a scorecard: the heading and an honest note, nothing invented.
    empty = render_llm_section(SimpleNamespace(kind="attack", provenance=SimpleNamespace(model_manifest={})))
    assert list(empty) == [LLM_SECTION_HEADING, "", NO_SCORECARD_NOTE] and empty.scorecard is None
    assert "k / n" in empty.markdown and "(0." not in empty.markdown
    # An attached object that does not validate is reported, not rendered.
    broken = render_llm_section({"scorecard": {**dumped, "mri": 3}})
    assert "does not validate" in broken.markdown and "mri" not in broken.markdown.lower().replace("no mri", "")
    with pytest.raises(TypeError):
        render_llm_reports(SimpleNamespace())


def test_register_named_modules_and_positional_report_call() -> None:
    """The worker task imports ``redsim.ml.llm.schema`` / ``.reporting`` and calls the positional forms."""
    from redsim.ml.llm import reporting as reporting_alias
    from redsim.ml.llm import schema as schema_alias

    assert schema_alias.LLMProbeScorecard is LLMProbeScorecard
    assert schema_alias.LLM_STANDING_LIMITATIONS[0] == D9_SENTENCE
    assert all(isinstance(s, str) for s in schema_alias.LLM_STANDING_LIMITATIONS)
    card = _fixture_scorecard()
    dumped = card.model_dump(mode="json")
    recs = [r.model_dump(mode="json") for r in recommend(dumped)]      # the task passes the dump and gets dicts
    assert {r["id"] for r in recs} == {"r.L1", RERUN_RULE_ID}
    findings = [{"id": "f-1", "title": "LLM probe dan.Dan_11_0 hit rate 1/1 (detector dan.DAN)", "severity": "high",
                 "status": "open", "validation_state": "unvalidated",
                 "llm": {"probe_id": "dan.Dan_11_0", "detector": "dan.DAN", "n_hits": 1, "n_evaluated": 1}}]
    files = reporting_alias.render_probe_reports(dumped, findings, recs,
                                                 artifacts={"ml.llm.scorecard": {"kind": "ml.llm.scorecard", "id": "a1",
                                                                                 "sha256": "1" * 64, "size_bytes": 5}})
    assert [f[0] for f in files] == ["report.md", "report.json", "report.html"]
    md = files[0][1].decode()
    assert SECTION_HEADINGS[2] in md and "| f-1 |" in md and "1/1" in md
    assert "derived from hit rate" in md and check_llm_report_text(md) == []
    payload = json.loads(files[1][1])
    assert payload["findings"] == findings and [r["id"] for r in payload["recommendations"]] == [r["id"] for r in recs]
    assert reporting_alias.render_reports is reporting_alias.render_probe_reports


def test_cap_probe_prompts_prunes_aligned_lists_deterministically() -> None:
    import random

    class Probe:
        prompts = tuple(f"p{i}" for i in range(10))
        triggers = tuple(f"t{i}" for i in range(10))
        _prompt_intents = [f"i{i}" for i in range(10)]
        unrelated = [1, 2, 3]

    a, b = Probe(), Probe()
    assert cap_probe_prompts(a, 4, random.Random(0)) == (10, 4)
    assert cap_probe_prompts(b, 4, random.Random(0)) == (10, 4)
    assert a.prompts == b.prompts and len(a.prompts) == 4
    assert [p[1:] for p in a.prompts] == [t[1:] for t in a.triggers] == [i[1:] for i in a._prompt_intents]
    assert a.unrelated == [1, 2, 3]
    c = Probe()
    assert cap_probe_prompts(c, 10, random.Random(0)) == (10, 10) and len(c.prompts) == 10


def test_build_child_env_holds_no_credential(tmp_path: Path) -> None:
    environ = {**PARENT_SECRETS, "PATH": os.environ.get("PATH", "/usr/bin"), "HOME": "/Users/someone",
               "HTTPS_PROXY": "http://proxy.example.invalid:3128", "SSL_CERT_FILE": "/etc/ssl/cert.pem",
               "REDSIM_TLS_TRUSTSTORE": "1", "REDSIM_ML_ASSETS_DIR": "/srv/assets", "REDSIM_PLUGINS": "1"}
    env = build_child_env(tmp_path, environ=environ)
    assert not any(k.startswith(FORBIDDEN_CHILD_NAMES) for k in env), sorted(env)
    assert {k for k in env if k.startswith("REDSIM_")} <= ALLOWED_REDSIM_KEYS
    assert set(env.values()).isdisjoint(PARENT_SECRETS.values())
    assert env["HOME"] == str(tmp_path) and env["TMPDIR"] == str(tmp_path)
    assert env["HTTPS_PROXY"] == "http://proxy.example.invalid:3128" and env["SSL_CERT_FILE"] == "/etc/ssl/cert.pem"
    assert env["HF_HUB_OFFLINE"] == "1" and env["XDG_DATA_HOME"].startswith(str(tmp_path))
    assert env["REDSIM_ENV_FILE"] == str(tmp_path / "no-env") and env["REDSIM_PLUGINS"] == "0"
    assert str(ROOT) in env["PYTHONPATH"]
    assert all(not k.upper().startswith(p) for k in env for p in FORBIDDEN_ENV_PREFIXES)


# ---------------------------------------------------------------------------
# garak-marked: the generator in process, the child as a subprocess
# ---------------------------------------------------------------------------


@pytest.fixture
def garak_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """XDG directories and garak.log under tmp so an in-process garak import writes nothing in HOME."""
    pytest.importorskip("garak")
    pins = {
        "XDG_DATA_HOME": str(tmp_path / "xdg" / "data"), "XDG_CONFIG_HOME": str(tmp_path / "xdg" / "config"),
        "XDG_CACHE_HOME": str(tmp_path / "xdg" / "cache"), "GARAK_LOG_FILE": str(tmp_path / "garak.log"),
        "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
    }
    for key, value in pins.items():
        monkeypatch.setenv(key, value)
    for key in PARENT_SECRETS:
        monkeypatch.delenv(key, raising=False)
    from garak import _config

    _config.load_base_config()
    return pins


@pytest.mark.garak
def test_pythia_generator_contract_with_a_mock_transport(garak_env: dict[str, str]) -> None:
    import garak.attempt as attempt
    import garak.exception
    import httpx

    from redsim.ml.llm.generator import (
        PERSONA_HEADER,
        ProbeKeyUnavailable,
        PythiaGenerator,
        assert_no_litellm,
        gateway_uri,
    )

    seen: list[tuple[httpx.Request, dict[str, Any]]] = []
    status_queue: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        seen.append((request, body))
        status = status_queue.pop(0) if status_queue else 200
        if status != 200:
            return httpx.Response(status, json={"error": {"message": "forced", "type": "server_error"}})
        return httpx.Response(200, json={
            "id": "chatcmpl-1", "object": "chat.completion", "model": MODEL_ID,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "Pong."}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
        })

    def factory(_gen: PythiaGenerator) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(handler))

    assert gateway_uri("https://gateway.invalid") == "https://gateway.invalid/v1/"
    assert gateway_uri("https://gateway.invalid/v1") == "https://gateway.invalid/v1/"
    gen = PythiaGenerator(name=MODEL_ID, api_key=FAKE_KEY, uri=gateway_uri("https://gateway.invalid"),
                          persona="redteam", http_client_factory=factory)
    conv = attempt.Conversation([attempt.Turn("user", attempt.Message("ping"))])
    out = gen.generate(conv, 1)
    assert [m.text for m in out] == ["Pong."]
    request, body = seen[0]
    assert request.method == "POST" and str(request.url) == "https://gateway.invalid/v1/chat/completions"
    assert request.headers["authorization"] == f"Bearer {FAKE_KEY}"
    assert request.headers[PERSONA_HEADER.lower()] == "redteam"
    assert body["model"] == MODEL_ID and body["messages"] == [{"role": "user", "content": "ping"}]
    assert set(body) == {"model", "messages", "temperature", "max_tokens"}  # no stop / n / top_p / seed / tools
    ledger = gen.ledger.to_dict()
    assert ledger["requests"] == 1 and ledger["prompt_tokens"] == 5 and ledger["completion_tokens"] == 2
    assert ledger["models_seen"] == {MODEL_ID: 1} and ledger["tls_mode"] == "injected"
    assert_no_litellm()
    assert "litellm" not in sys.modules
    # The key never comes from the environment: no key -> refused before any request.
    with pytest.raises(ProbeKeyUnavailable):
        PythiaGenerator(name=MODEL_ID, uri="https://gateway.invalid/v1/", http_client_factory=factory)
    # 401 is terminal: one request, one GarakException, no retry loop.
    status_queue[:] = [401]
    before = len(seen)
    with pytest.raises(garak.exception.GarakException):
        gen.generate(conv, 1)
    assert len(seen) == before + 1
    # 5xx is retried a bounded number of times, then raised.
    gen.transport_max_tries = 3
    gen.transport_backoff_s = 0.001
    status_queue[:] = [500, 500, 500, 500]
    before = len(seen)
    with pytest.raises(garak.exception.GarakException, match="after 3 tries"):
        gen.generate(conv, 1)
    assert len(seen) == before + 3
    assert gen.ledger.retries == 2 and gen.ledger.to_dict()["transport_errors"] == {"InternalServerError": 3}
    assert gen.ledger.to_dict()["http_errors"] == {"401": 1, "500": 3}
    gen.close()


@pytest.mark.garak
def test_key_file_must_be_private(tmp_path: Path, garak_env: dict[str, str]) -> None:
    from redsim.ml.llm.generator import ProbeKeyUnavailable, read_key_file

    loose = tmp_path / "loose.key"
    loose.write_text(FAKE_KEY)
    os.chmod(loose, 0o644)
    with pytest.raises(ProbeKeyUnavailable, match="0600"):
        read_key_file(loose)
    tight = tmp_path / "tight.key"
    tight.write_text(FAKE_KEY + "\n")
    os.chmod(tight, 0o600)
    assert read_key_file(tight) == FAKE_KEY
    with pytest.raises(ProbeKeyUnavailable, match="missing"):
        read_key_file(tmp_path / "absent.key")


def _spec(server: FakeOpenAIServer, work_dir: Path, probe_ids: list[str], **overrides: Any) -> LLMProbeChildSpec:
    fields: dict[str, Any] = {
        "model_id": MODEL_ID, "gateway_url": server.base_url, "persona": "redteam", "probe_ids": probe_ids,
        "max_prompts_per_probe": 4, "seed": 0, "work_dir": str(work_dir), "key_file": str(work_dir / KEY_FILE),
    }
    fields.update(overrides)
    return LLMProbeChildSpec(**fields)


def _reply_for(messages: list[dict[str, Any]]) -> str:
    text = " ".join(str(m.get("content") or "") for m in messages)
    return DAN_REPLY if "DAN" in text else REFUSAL_REPLY


@pytest.fixture(scope="module")
def child_run(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[ChildOutcome, FakeOpenAIServer, LLMProbeChildSpec]]:
    """One real child run against the fake gateway, shared by the tests that read its files."""
    pytest.importorskip("garak")
    root = tmp_path_factory.mktemp("llm-work")
    with pytest.MonkeyPatch.context() as mp:
        for key, value in PARENT_SECRETS.items():
            mp.setenv(key, value)
        mp.setenv("REDSIM_ML_WORK_DIR", str(root))
        server = FakeOpenAIServer(reply_for=_reply_for)
        server.start()
        try:
            work_dir = prepare_work_dir("job-llm-1", root=root)
            spec = _spec(server, work_dir, ["test.Blank", "test.Test", "dan.Dan_11_0", "encoding.InjectBase64",
                                            "nope.Nope", "realtoxicityprompts.RTPBlank", "fitd.FITD"])
            outcome = run_probe_child(spec, api_key=FAKE_KEY, config=ProbeRunnerConfig(timeout_s=600))
            yield outcome, server, spec
        finally:
            server.stop()


@pytest.mark.garak
def test_child_runs_garak_end_to_end_against_the_fake_gateway(child_run: tuple[ChildOutcome, FakeOpenAIServer, LLMProbeChildSpec]) -> None:
    outcome, server, spec = child_run
    assert outcome.status == "succeeded", (outcome.error, outcome.stderr_tail[-800:])
    assert outcome.exit_code == 0 and outcome.result is not None and outcome.succeeded
    result = outcome.result
    assert result.garak_version == EXPECTED_GARAK_VERSION
    for name in ("report_jsonl", "hitlog_jsonl", "digest_html", "usage_json", "child_result_json"):
        assert outcome.files[name] is not None and outcome.files[name].is_file(), name
    assert outcome.discard["garak_log"] is not None and outcome.discard["garak_log"].parent == outcome.work_dir
    rows = {p.probe_id: p for p in result.probes}
    assert result.probes_run == ["test.Blank", "test.Test", "dan.Dan_11_0", "encoding.InjectBase64"]
    assert rows["nope.Nope"].status == "not_run" and rows["nope.Nope"].reason == "unknown_probe"
    assert rows["realtoxicityprompts.RTPBlank"].status == "not_run"
    assert rows["realtoxicityprompts.RTPBlank"].reason == DETECTOR_OFFLINE_REASON
    assert rows["fitd.FITD"].status == "not_run" and "probe_excluded" in (rows["fitd.FITD"].reason or "")
    # The hard prompt cap: test.Test ships 8 prompts and ignores soft_probe_prompt_cap.
    assert (rows["test.Test"].n_prompts_loaded, rows["test.Test"].n_prompts_after_cap) == (8, 4)
    assert rows["test.Test"].n_attempts_complete == 4 and rows["test.Test"].n_outputs == 4
    assert rows["dan.Dan_11_0"].n_attempts_complete == 1
    # Denominators equal garak's own eval records and the attempts it logged as complete.
    evals: dict[tuple[str, str], dict[str, int]] = {}
    complete: dict[str, int] = {}
    report_path = outcome.files["report_jsonl"]
    assert report_path is not None
    for line in report_path.read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        if entry.get("entry_type") == "eval":
            evals[(entry["probe"], entry["detector"])] = entry
        elif entry.get("entry_type") == "attempt" and entry.get("status") == 2:
            complete[entry["probe_classname"]] = complete.get(entry["probe_classname"], 0) + 1
    for pid in result.probes_run:
        assert rows[pid].n_attempts_complete == complete[pid]
        for det in rows[pid].detectors:
            entry = evals[(pid, det.detector)]
            assert (det.passed, det.fails, det.nones, det.total_evaluated) == (
                entry["passed"], entry["fails"], entry["nones"], entry["total_evaluated"])
    dan = rows["dan.Dan_11_0"].detectors[0]
    assert (dan.detector, dan.fails, dan.total_evaluated) == ("dan.DAN", 1, 1)      # the fake adopted the DAN persona
    enc = rows["encoding.InjectBase64"].detectors[0]
    assert (enc.detector, enc.fails, enc.total_evaluated) == ("encoding.DecodeMatch", 0, 4)
    # Gateway traffic: one chat request per prompt sent, the persona on each, minimal bodies, no /v1/models call.
    n_sent = sum(p.n_attempts_complete for p in result.probes)
    assert len(server.chat_requests) == n_sent == 10
    assert all(r["persona"] == "redteam" and r["auth_ok"] for r in server.chat_requests)
    assert {tuple(r["body_keys"]) for r in server.chat_requests} == {("max_tokens", "messages", "model", "temperature")}
    assert {r["model"] for r in server.chat_requests} == {MODEL_ID}
    assert server.model_requests == []
    usage = result.usage
    assert usage["requests"] == 10 and (usage["prompt_tokens"], usage["completion_tokens"]) == server.token_sums()
    assert usage["models_seen"] == {MODEL_ID: 10} and usage["tls_mode"] == "truststore"
    assert outcome.wall_time_s > 0 and result.wall_time_s is not None
    # garak's own directories all live under the work dir, never under the real HOME.
    assert (outcome.work_dir / "xdg").is_dir() and (outcome.work_dir / "garak").is_dir()


@pytest.mark.garak
def test_child_environment_and_files_never_carry_the_key_or_a_prompt(child_run: tuple[ChildOutcome, FakeOpenAIServer, LLMProbeChildSpec]) -> None:
    outcome, _server, spec = child_run
    assert outcome.env_keys, "the child records the names of its environment variables"
    leaked = [k for k in outcome.env_keys if k.startswith(FORBIDDEN_CHILD_NAMES)]
    assert leaked == [], leaked
    assert {k for k in outcome.env_keys if k.startswith("REDSIM_")} <= ALLOWED_REDSIM_KEYS
    for name in ("REDSIM_DB_URL", "REDSIM_AUTH_PROFILES_KEY", "REDSIM_WORKER_SIGNING_KEY", "PYTHIA_API_KEY", "KAGGLE_KEY"):
        assert name not in outcome.env_keys
    for name in ("XDG_DATA_HOME", "GARAK_LOG_FILE", "HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "REDSIM_ENV_FILE"):
        assert name in outcome.env_keys
    # The key: file deleted, absent from every file the run wrote, from the tails and from the result.
    assert not Path(spec.key_file).exists()
    key_bytes = FAKE_KEY.encode()
    for path in outcome.work_dir.rglob("*"):
        if path.is_file():
            assert key_bytes not in path.read_bytes(), path
    assert FAKE_KEY not in outcome.stdout_tail and FAKE_KEY not in outcome.stderr_tail
    assert outcome.result is not None and outcome.result.key_leak_scrubbed is False
    assert "pk_" not in json.dumps(outcome.result.model_dump(mode="json"))
    # Prompts stay inside garak's report artifacts; counts-only files and rendered surfaces never carry them.
    fragment = _dan_prompt_substring()
    report_path = outcome.files["report_jsonl"]
    assert report_path is not None and fragment in report_path.read_text(encoding="utf-8")
    for name in ("child_result_json", "usage_json"):
        path = outcome.files[name]
        assert path is not None and fragment not in path.read_text(encoding="utf-8")
    card = build_scorecard(outcome.result, run_id="run-1", target_id="tgt-1", guardrail_mode="permission_gate_only")
    reports = render_llm_reports(card)
    for _name, data, _ctype in reports:
        assert fragment not in data.decode()
    assert fragment not in json.dumps(card.model_dump(mode="json"))
    # The parent's cleanup removes the work directory (garak.log with it) unless told to keep it.
    keep = ProbeRunnerConfig.from_env()
    assert keep.keep_work_dir is False


@pytest.mark.garak
def test_scorecard_from_the_real_child_run_has_denominators_and_no_mri(child_run: tuple[ChildOutcome, FakeOpenAIServer, LLMProbeChildSpec]) -> None:
    outcome, _server, spec = child_run
    assert outcome.result is not None
    selection = resolve_selection(load_catalog(), probe_ids=spec.probe_ids)
    card = build_scorecard(outcome.result, run_id="run-1", target_id="tgt-1", guardrail_mode="content_filtered",
                           selection=selection, artifacts={"ml.llm.report_jsonl": "0" * 64})
    assert card.kind == "llm_probe" and card.completeness == "partial"
    rows = {d.row_id: d for _, d in card.rows()}
    assert rows[row_id("dan.Dan_11_0", "dan.DAN")].fraction() == "1/1 (1.0000)"
    assert rows[row_id("encoding.InjectBase64", "encoding.DecodeMatch")].fraction() == "0/4 (0.0000)"
    assert rows[row_id("test.Blank", "any.AnyOutput")].fraction() == "1/1 (1.0000)"
    assert rows[row_id("test.Test", "always.Pass")].fraction() == "0/4 (0.0000)"
    assert rows[row_id("realtoxicityprompts.RTPBlank", "unsafe_content.ToxicCommentModel")].status == "not_run"
    assert GUARDRAIL_TEXT["content_filtered"] in card.limitations and D9_SENTENCE in card.limitations
    assert card.usage.prompt_tokens == 210 and card.usage.requests == 10
    assert_no_mri(card)
    dumped = json.dumps(card.model_dump(mode="json")).lower()
    assert '"mri"' not in dumped and '"grade"' not in dumped and "subscore" not in dumped
    recs = recommend(card)
    assert {r.id for r in recs} == {"r.L1", RERUN_RULE_ID}
    md = render_llm_reports(card)[0][1].decode()
    assert check_llm_report_text(md) == [] and md.count(D9_SENTENCE) == 1


@pytest.mark.garak
def test_child_refuses_a_garak_version_mismatch_before_any_request(tmp_path: Path) -> None:
    pytest.importorskip("garak")
    with FakeOpenAIServer() as server:
        work_dir = prepare_work_dir("job-llm-version", root=tmp_path)
        spec = _spec(server, work_dir, ["test.Blank"], expected_garak_version="0.0.0")
        outcome = run_probe_child(spec, api_key=FAKE_KEY, config=ProbeRunnerConfig(timeout_s=300))
        assert outcome.status == "failed" and outcome.exit_code == 3
        assert outcome.result is not None and outcome.result.error_type == "garak_version_mismatch"
        assert "0.16" in (outcome.result.error or "") and FAKE_KEY not in (outcome.result.error or "")
        assert server.chat_requests == []
        assert not Path(spec.key_file).exists()
        with pytest.raises(Exception, match="garak_version_mismatch|probe child"):
            outcome.raise_for_status()
        outcome.cleanup(keep=False)
        assert not work_dir.exists()


@pytest.mark.garak
def test_offline_mode_records_hf_detector_probes_as_not_run_without_a_request(tmp_path: Path) -> None:
    pytest.importorskip("garak")
    with FakeOpenAIServer() as server:
        work_dir = prepare_work_dir("job-llm-offline", root=tmp_path)
        spec = _spec(server, work_dir, ["realtoxicityprompts.RTPBlank", "latentinjection.LatentJailbreak"])
        outcome = run_probe_child(spec, api_key=FAKE_KEY, config=ProbeRunnerConfig(timeout_s=300))
        assert outcome.status == "succeeded", (outcome.error, outcome.stderr_tail[-500:])
        assert outcome.result is not None and outcome.result.probes_run == []
        assert {p.reason for p in outcome.result.probes} == {DETECTOR_OFFLINE_REASON}
        assert server.chat_requests == []
        assert "HF_HUB_OFFLINE" in outcome.env_keys
        card = build_scorecard(outcome.result, run_id="r", target_id="t", guardrail_mode="permission_gate_only")
        assert card.completeness == "none" and all(p.status == "not_run" for p in card.probes())
        assert recommend(card) == []
        outcome.cleanup(keep=False)


@pytest.mark.garak
def test_child_timeout_kills_the_process_group_and_removes_the_key(tmp_path: Path) -> None:
    pytest.importorskip("garak")
    with FakeOpenAIServer(latency_s=30.0) as server:
        work_dir = prepare_work_dir("job-llm-timeout", root=tmp_path)
        spec = _spec(server, work_dir, ["test.Test"], max_prompts_per_probe=8)
        started = time.monotonic()
        outcome = run_probe_child(spec, api_key=FAKE_KEY, config=ProbeRunnerConfig(timeout_s=12), poll_s=0.2)
        elapsed = time.monotonic() - started
        assert outcome.status == "timed_out", (outcome.status, outcome.error)
        assert elapsed < 60
        assert not Path(spec.key_file).exists()
        assert outcome.error is not None and "killed" in outcome.error and FAKE_KEY not in outcome.error
        with pytest.raises(ProbeChildTimeout):
            outcome.raise_for_status()
        outcome.cleanup(keep=False)
        assert not work_dir.exists()


@pytest.mark.garak
def test_write_key_file_is_0600(tmp_path: Path) -> None:
    from redsim.ml.llm.runner import write_key_file

    path = write_key_file(tmp_path, FAKE_KEY)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and path.read_text() == FAKE_KEY


@pytest.mark.garak
@pytest.mark.parametrize("header,expected", [("2", 2.0), ("0", 0.0), ("invalid", None),
                                               ("nan", None), ("inf", None),
                                               ("Thu, 01 Jan 1970 00:00:12 GMT", 2.0),
                                               ("Thu, 01 Jan 1970 00:00:01 GMT", 0.0)])
def test_retry_after_parser(header, expected):
    from redsim.ml.llm.generator import retry_after_seconds
    assert retry_after_seconds(header, now=10.0) == expected


@pytest.mark.garak
def test_child_honours_retry_after_and_completes_five_attempts(tmp_path, garak_env):
    with FakeOpenAIServer(fail_status=429, fail_first=3, retry_after=2) as server:
        spec = _spec(server, prepare_work_dir("retry-child", root=tmp_path),
                     ["dan.DanInTheWild"], max_prompts_per_probe=5)
        outcome = run_probe_child(spec, api_key=FAKE_KEY)
        assert outcome.result is not None and outcome.result.status == "succeeded"
        assert outcome.result.probes[0].n_attempts_complete == 5
        assert outcome.result.usage["retries"] == 3
        assert outcome.result.usage["retry_after_honoured"] == 3
        assert len(server.chat_requests) == 8
        card = build_scorecard(outcome.result, run_id="retry-run", target_id="retry-target",
                               guardrail_mode="content_filtered",
                               selection=resolve_selection(load_catalog(), probe_ids=spec.probe_ids))
        assert card.completeness == "complete"
        assert card.usage.retry_after_honoured == 3


@pytest.mark.garak
def test_retry_after_above_operator_cap_never_retries_early(garak_env):
    import garak.exception

    from redsim.ml.llm.generator import PythiaGenerator, gateway_uri
    with FakeOpenAIServer(fail_status=429, retry_after=61) as server:
        gen = PythiaGenerator(name=MODEL_ID, api_key=FAKE_KEY, uri=gateway_uri(server.base_url))
        try:
            with pytest.raises(garak.exception.GarakException, match="exceeds retry wait budget"):
                gen._call_model([])
            assert len(server.chat_requests) == 1
            assert gen.ledger.retries == 0
        finally:
            gen.close()


def test_worker_passes_validated_retry_overrides(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from redsim.workers.tasks.ml_llm import _run_child
    monkeypatch.setenv("REDSIM_LLM_PROBE_TRANSPORT_MAX_TRIES", "11")
    monkeypatch.setenv("REDSIM_LLM_PROBE_TRANSPORT_MAX_SLEEP_S", "42")
    runner = SimpleNamespace(prepare_work_dir=lambda job: tmp_path,
                             run_probe_child=lambda spec, **kw: spec)
    spec = _run_child(runner, detail={"probe_ids": ["dan.DanInTheWild"]},
                      gateway_url="https://gateway.invalid", model_id=MODEL_ID, persona="test",
                      api_key=FAKE_KEY, job_id="retry-job", is_cancelled=lambda: False)
    assert spec.transport_max_tries == 11 and spec.transport_max_sleep_s == 42
    monkeypatch.setenv("REDSIM_LLM_PROBE_TRANSPORT_MAX_TRIES", "13")
    with pytest.raises(ValueError):
        _run_child(runner, detail={"probe_ids": ["dan.DanInTheWild"]},
                   gateway_url="https://gateway.invalid", model_id=MODEL_ID, persona="test",
                   api_key=FAKE_KEY, job_id="retry-job", is_cancelled=lambda: False)


@pytest.mark.garak
def test_content_filter_blocks_are_counted_without_aborting(tmp_path, garak_env):
    body = {"error": {"code": "persona_denied", "type": "permission_error",
                      "message": "Blocked by synthetic_filter"}}
    with FakeOpenAIServer(fail_status=403, fail_body=body, fail_indices={2, 4}) as server:
        spec = _spec(server, prepare_work_dir("blocked-child", root=tmp_path),
                     ["dan.DanInTheWild"], max_prompts_per_probe=5)
        outcome = run_probe_child(spec, api_key=FAKE_KEY)
        result = outcome.result
        assert result is not None and result.status == "succeeded"
        row = result.probes[0]
        assert row.n_attempts_complete == 5 and row.n_outputs_blocked == 2
        assert result.usage["gateway_blocked"] == 2 and result.usage["retries"] == 0
        assert sum(d.total_evaluated for d in row.detectors) == 3
        card = build_scorecard(result, run_id="blocked-run", target_id="blocked-target",
                               guardrail_mode="permission_gate_only")
        assert card.probes()[0].n_outputs_blocked == 2
        assert any("blocked 2 prompts" in line for line in card.limitations)
        from redsim.workers.tasks.ml_llm import normalise_child_result, usage_block
        normalized = normalise_child_result(result)
        assert normalized.probes[0].n_outputs_blocked == 2
        assert usage_block(normalized.usage, MODEL_ID)["gateway_blocked"] == 2


@pytest.mark.garak
@pytest.mark.parametrize("body", [{"detail": "Unknown or unauthorized persona"},
                                  {"error": {"code": "permission_denied", "message": "Unauthorized persona"}}])
def test_plain_permission_denial_stays_terminal(body, garak_env):
    import garak.exception

    from redsim.ml.llm.generator import PythiaGenerator, gateway_uri
    with FakeOpenAIServer(fail_status=403, fail_body=body) as server:
        gen = PythiaGenerator(name=MODEL_ID, api_key=FAKE_KEY, uri=gateway_uri(server.base_url))
        try:
            with pytest.raises(garak.exception.GarakException, match="authentication failed"):
                gen._call_model([])
            assert len(server.chat_requests) == 1
            assert gen.ledger.gateway_blocked == 0 and gen.ledger.retries == 0
        finally:
            gen.close()
