"""One garak run in a fresh, credential-minimised subprocess (LLM-09, -10, -18, -21, -33).

    python -m redsim.ml.llm.probe_child --spec <work_dir>/probe_spec.json

The worker parent (:mod:`redsim.ml.llm.runner`) writes the spec and a 0600
key file into a per-job work directory and launches this module with an
allowlisted environment. The child:

1. pins garak's XDG directories and ``garak.log`` under the work directory and
   sets ``HF_HUB_OFFLINE=1`` / ``TRANSFORMERS_OFFLINE=1`` *before* importing
   garak (its import creates the directories and installs a DEBUG file logger);
2. reads the probe key from the 0600 file and deletes the file at once; the key
   lives in one local variable until the generator holds it;
3. imports garak and refuses a version other than the one the catalog was built
   from (exit 3, ``garak_version_mismatch``);
4. writes the run configuration as a YAML file and loads it through
   ``_config.load_config(run_config_filename=...)``: ``system.lite=False``,
   parallelism off, ``generations=1``, the seed, ``soft_probe_prompt_cap`` and
   ``run.spec`` (the probe selection), the generator options under
   ``plugins.generators.pythia_redsim.PythiaGenerator`` (never the key), the
   report directory under the work directory. The ``--model_type`` /
   ``--probes`` flags are deprecated in 0.16, so nothing goes through argv;
5. validates the requested probes against the live plugin registry and the
   detector policy: unknown ids, catalog-excluded probes, and probes whose
   primary detector needs a model download in ``offline`` mode become
   ``not_run`` rows with the reason, never a silent drop and never a fake row;
6. wraps ``garak._plugins.load_plugin`` so every probe's prompt list is capped
   at ``max_prompts_per_probe`` (garak's ``soft_probe_prompt_cap`` is honoured
   by some probes only; this makes the gateway-call bound hold for all of them,
   pruning aligned ``triggers`` / intent lists with the same seeded indices);
7. runs ``start_run`` -> ``probewise_run`` -> ``end_run`` with a
   :class:`~redsim.ml.llm.generator.PythiaGenerator`;
8. reads back ``report.jsonl`` counting only: attempts per probe, outputs and
   ``None`` outputs, and the ``eval`` records (``passed`` / ``fails`` /
   ``nones`` / ``total_evaluated`` per detector). No prompt or output text is
   ever read into a result field;
9. writes ``usage.json`` (the generator ledger), ``child_result.json`` and
   ``env_keys.json`` (the names of its environment variables, for the boundary
   test), scrubs the key shape from its own error messages, checks
   ``garak.log`` for the key and scrubs it in place if found (recorded).

Exit codes: 0 ran (possibly with every probe ``not_run``), 2 spec invalid,
3 garak version mismatch, 4 probe key unavailable, 5 run failed. On every
non-zero exit the child still tries to write ``child_result.json`` with
``status: failed`` and the reason.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from redsim.ml.llm.catalog import (
    DETECTOR_OFFLINE_REASON,
    EXCLUDED_PROBE_REASON,
    EXPECTED_GARAK_VERSION,
    UNKNOWN_PROBE_REASON,
    load_catalog,
)

SPEC_VERSION = "llm-probe-child-spec-1"
RESULT_VERSION = "llm-probe-child-result-1"

EXIT_OK = 0
EXIT_SPEC = 2
EXIT_VERSION = 3
EXIT_KEY = 4
EXIT_RUN = 5

SPEC_FILE = "probe_spec.json"
KEY_FILE = "probe.key"
RESULT_FILE = "child_result.json"
USAGE_FILE = "usage.json"
ENV_KEYS_FILE = "env_keys.json"
GARAK_CONFIG_FILE = "garak.yaml"
GARAK_LOG_FILE = "garak.log"
GARAK_DIR = "garak"
REPORT_PREFIX = "probe"

MAX_PROMPTS_PER_PROBE_CEILING = 256

DetectorMode = Literal["offline", "hf"]
ProbeRunStatus = Literal["run", "not_run", "failed"]

#: Detector base classes that must not be instantiated without a cached model or a second LLM.
_NON_OFFLINE_BASES = frozenset({"HFDetector", "ModelAsJudge", "EvaluationJudge"})
_NON_OFFLINE_MODULES = frozenset({"judge", "perspective"})
_KEY_RE = re.compile(r"pk_[A-Za-z0-9_\-]{8,}")


# ---------------------------------------------------------------------------
# Spec and result models (pydantic only; the parent imports these)
# ---------------------------------------------------------------------------


class LLMProbeChildSpec(BaseModel):
    """What one probe run is. Ids, counts and settings only: the key travels in the 0600 file."""

    model_config = ConfigDict(extra="forbid")

    spec_version: Literal["llm-probe-child-spec-1"] = "llm-probe-child-spec-1"
    model_id: str = Field(min_length=3)                 # canonical ``<vendor>/<model>`` or ``pythia/auto``
    gateway_url: str = Field(min_length=8)              # PYTHIA_BASE_URL; the child appends ``/v1/``
    persona: str | None = None                          # sent as X-Pythia-Persona; the name is not a secret
    probe_ids: list[str] = Field(min_length=1)
    max_prompts_per_probe: int = Field(16, ge=1, le=MAX_PROMPTS_PER_PROBE_CEILING)
    seed: int = 0
    detector_mode: DetectorMode = "offline"
    expected_garak_version: str = EXPECTED_GARAK_VERSION
    eval_threshold: float = Field(0.5, gt=0.0, le=1.0)
    generations: Literal[1] = 1
    request_timeout_s: float = Field(60.0, gt=0.0, le=600.0)
    transport_max_tries: int = Field(8, ge=1, le=12)
    transport_max_sleep_s: float = Field(60.0, ge=0, le=600, allow_inf_nan=False)
    max_tokens: int = Field(400, ge=1, le=4096)
    temperature: float = Field(0.7, ge=0.0, le=2.0)
    target_lang: str = "en"
    hf_home: str | None = None                          # pre-cached detector models (``hf`` mode only)
    work_dir: str
    key_file: str


class ChildDetectorCounts(BaseModel):
    """garak's ``eval`` record for one (probe, detector): counts only."""

    model_config = ConfigDict(extra="forbid")

    detector: str
    passed: int = 0
    fails: int = 0
    nones: int = 0
    total_evaluated: int = 0
    total_processed: int = 0
    confidence_method: str | None = None
    confidence: float | None = None
    confidence_lower: float | None = None
    confidence_upper: float | None = None


class ChildProbeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    probe_id: str
    status: ProbeRunStatus
    reason: str | None = None
    n_prompts_loaded: int | None = None
    n_prompts_after_cap: int | None = None
    n_attempts_complete: int = 0
    n_outputs: int = 0
    n_outputs_none: int = 0
    n_outputs_blocked: int = 0
    detectors: list[ChildDetectorCounts] = Field(default_factory=list)


class ChildResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["llm-probe-child-result-1"] = "llm-probe-child-result-1"
    status: Literal["succeeded", "failed"]
    error: str | None = None
    error_type: str | None = None
    exit_code: int = EXIT_OK
    garak_version: str | None = None
    model_id: str
    persona: str | None = None
    gateway_host: str | None = None
    seed: int = 0
    generations: int = 1
    max_prompts_per_probe: int = 16
    detector_mode: DetectorMode = "offline"
    extended_detectors: bool = False
    eval_threshold: float = 0.5
    started_at: datetime | None = None
    finished_at: datetime | None = None
    wall_time_s: float | None = None
    probes: list[ChildProbeResult] = Field(default_factory=list)
    probes_requested: list[str] = Field(default_factory=list)
    probes_run: list[str] = Field(default_factory=list)
    files: dict[str, str | None] = Field(default_factory=dict)   # work-dir-relative paths
    usage: dict[str, Any] = Field(default_factory=dict)
    key_leak_scrubbed: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


def _scrub(text: str, *secrets: str) -> str:
    out = str(text)
    for secret in secrets:
        if secret:
            out = out.replace(secret, "<REDACTED>")
    return _KEY_RE.sub("<REDACTED>", out)


def _gateway_host(url: str) -> str | None:
    from urllib.parse import urlsplit

    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def pin_environment(work_dir: Path, *, hf_home: str | None = None) -> dict[str, str]:
    """The environment garak needs pinned before its import: XDG dirs, log file, offline hub."""
    xdg = work_dir / "xdg"
    pins = {
        "XDG_DATA_HOME": str(xdg / "data"),
        "XDG_CONFIG_HOME": str(xdg / "config"),
        "XDG_CACHE_HOME": str(xdg / "cache"),
        "GARAK_LOG_FILE": str(work_dir / GARAK_LOG_FILE),
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_DATASETS_OFFLINE": "1",
        "TOKENIZERS_PARALLELISM": "false",
        "PYTHONUNBUFFERED": "1",
    }
    if hf_home:
        pins["HF_HOME"] = str(hf_home)
    for key, value in pins.items():
        os.environ[key] = value
    for name in pins.values():
        if name.startswith(str(work_dir)):
            Path(name).parent.mkdir(parents=True, exist_ok=True)
    return pins


def garak_run_config(spec: LLMProbeChildSpec, work_dir: Path) -> dict[str, Any]:
    """The YAML run configuration (garak's ``--config`` shape). No secret is ever placed here."""
    from redsim.ml.llm.generator import TARGET_TYPE, gateway_uri

    generator_options: dict[str, Any] = {
        "uri": gateway_uri(spec.gateway_url),
        "max_tokens": spec.max_tokens,
        "temperature": spec.temperature,
        "request_timeout_s": spec.request_timeout_s,
        "transport_max_tries": spec.transport_max_tries,
        "transport_max_sleep_s": spec.transport_max_sleep_s,
    }
    if spec.persona:
        generator_options["persona"] = spec.persona
    module, _, cls = TARGET_TYPE.partition(".")
    return {
        "system": {
            "verbose": 0,
            "narrow_output": True,
            "parallel_requests": False,
            "parallel_attempts": False,
            "lite": False,
            "show_z": False,
        },
        "run": {
            "seed": spec.seed,
            "deprefix": True,
            "eval_threshold": spec.eval_threshold,
            "generations": spec.generations,
            "soft_probe_prompt_cap": spec.max_prompts_per_probe,
            "target_lang": spec.target_lang,
            "langproviders": [],
            "spec": {"include": [f"probes.{pid}" for pid in spec.probe_ids], "exclude": []},
        },
        "plugins": {
            "target_type": TARGET_TYPE,
            "target_name": spec.model_id,
            "detector_spec": "auto",
            "extended_detectors": spec.detector_mode == "hf",
            "generators": {module: {cls: generator_options}},
        },
        "reporting": {
            "report_prefix": REPORT_PREFIX,
            "report_dir": str(work_dir / GARAK_DIR),
            "taxonomy": None,
        },
    }


def detector_offline(name: str) -> bool | None:
    """Live check in the child: ``True`` when the detector needs no model download and no LLM."""
    import importlib

    module, _, cls = name.partition(".")
    if module in _NON_OFFLINE_MODULES:
        return False
    try:
        klass = getattr(importlib.import_module(f"garak.detectors.{module}"), cls)
    except Exception:  # noqa: BLE001 - not importable means not runnable
        return None
    mro = {c.__name__ for c in klass.__mro__}
    if mro & _NON_OFFLINE_BASES:
        return False
    return not (getattr(klass, "extra_dependency_names", None) or [])


def cap_probe_prompts(probe: Any, cap: int, rng: random.Random) -> tuple[int, int]:
    """Prune ``probe.prompts`` (and every aligned per-prompt list) to ``cap`` with seeded indices.

    Returns ``(n_loaded, n_after)``. Aligned sequences are ``triggers`` and
    ``_prompt_intents`` when their length equals the prompt count; they are
    pruned at the same indices so detectors keep reading the right trigger.
    """
    prompts = getattr(probe, "prompts", None)
    if not isinstance(prompts, (list, tuple)):
        return (0, 0)
    n_loaded = len(prompts)
    if n_loaded <= cap:
        return (n_loaded, n_loaded)
    keep = sorted(rng.sample(range(n_loaded), cap))
    probe.prompts = [prompts[i] for i in keep]
    for attr in ("triggers", "_prompt_intents"):
        aligned = getattr(probe, attr, None)
        if isinstance(aligned, (list, tuple)) and len(aligned) == n_loaded:
            setattr(probe, attr, [aligned[i] for i in keep])
    return (n_loaded, cap)


def _install_prompt_cap(cap: int, seed: int, counts: dict[str, tuple[int, int]]) -> None:
    from garak import _config, _plugins
    from garak.probes.base import Probe

    original = _plugins.load_plugin
    rng = random.Random(seed)

    def capped(path: str, break_on_fail: bool = True, config_root: Any = _config) -> Any:
        plugin = original(path, break_on_fail=break_on_fail, config_root=config_root)
        if isinstance(plugin, Probe) and str(path).startswith("probes."):
            probe_id = str(path)[len("probes."):]
            counts[probe_id] = cap_probe_prompts(plugin, cap, rng)
        return plugin

    _plugins.load_plugin = capped


def _normalise_probe_name(name: str) -> str:
    text = str(name)
    for prefix in ("garak.probes.", "probes."):
        if text.startswith(prefix):
            text = text[len(prefix):]
    return text


def count_report(report_path: Path) -> tuple[dict[str, dict[str, int]], dict[str, list[ChildDetectorCounts]]]:
    """Counts from ``report.jsonl``: attempts / outputs per probe and the ``eval`` records. No text is kept."""
    attempts: dict[str, dict[str, int]] = {}
    evals: dict[str, list[ChildDetectorCounts]] = {}
    if not report_path.is_file():
        return attempts, evals
    with report_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if not isinstance(entry, dict):
                continue
            kind = entry.get("entry_type")
            if kind == "attempt":
                probe = _normalise_probe_name(str(entry.get("probe_classname") or ""))
                if not probe:
                    continue
                tally = attempts.setdefault(probe, {"complete": 0, "outputs": 0, "outputs_none": 0})
                # garak logs each attempt twice: once when started (status 1) and once complete (status 2).
                if int(entry.get("status") or 0) != 2:
                    continue
                tally["complete"] += 1
                outputs = entry.get("outputs")
                if isinstance(outputs, list):
                    tally["outputs"] += len(outputs)
                    tally["outputs_none"] += sum(1 for o in outputs if o is None or (isinstance(o, dict) and o.get("text") is None))
            elif kind == "eval":
                probe = _normalise_probe_name(str(entry.get("probe") or ""))
                if not probe:
                    continue
                evals.setdefault(probe, []).append(ChildDetectorCounts(
                    detector=str(entry.get("detector") or ""),
                    passed=int(entry.get("passed") or 0),
                    fails=int(entry.get("fails") or 0),
                    nones=int(entry.get("nones") or 0),
                    total_evaluated=int(entry.get("total_evaluated") or 0),
                    total_processed=int(entry.get("total_processed") or 0),
                    confidence_method=entry.get("confidence_method"),
                    confidence=entry.get("confidence"),
                    confidence_lower=entry.get("confidence_lower"),
                    confidence_upper=entry.get("confidence_upper"),
                ))
    return attempts, evals


def _scrub_file_in_place(path: Path, secret: str) -> bool:
    """Replace the key in a text file the run wrote. Returns whether anything was replaced."""
    if not path.is_file():
        return False
    try:
        data = path.read_bytes()
    except OSError:
        return False
    needle = secret.encode("utf-8")
    if needle not in data and not _KEY_RE.search(data.decode("utf-8", "replace")):
        return False
    text = _scrub(data.decode("utf-8", "replace"), secret)
    path.write_text(text, encoding="utf-8")
    return True


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _write_result(work_dir: Path, result: ChildResult) -> None:
    _write_json(work_dir / RESULT_FILE, result.model_dump(mode="json"))


def _write_env_keys(work_dir: Path) -> None:
    _write_json(work_dir / ENV_KEYS_FILE, sorted(os.environ))


def _relative(work_dir: Path, path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    try:
        return str(path.relative_to(work_dir))
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


def _fail(work_dir: Path, result: ChildResult, code: int, error_type: str, message: str, *secrets: str) -> int:
    result.status = "failed"
    result.exit_code = code
    result.error_type = error_type
    result.error = _scrub(message, *secrets)
    result.finished_at = _now()
    if result.started_at is not None:
        result.wall_time_s = round((result.finished_at - result.started_at).total_seconds(), 6)
    try:
        _write_result(work_dir, result)
        _write_env_keys(work_dir)
    except OSError:
        pass
    return code


def run(spec: LLMProbeChildSpec) -> int:
    work_dir = Path(spec.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    result = ChildResult(
        status="failed", model_id=spec.model_id, persona=spec.persona, gateway_host=_gateway_host(spec.gateway_url),
        seed=spec.seed, generations=spec.generations, max_prompts_per_probe=spec.max_prompts_per_probe,
        detector_mode=spec.detector_mode, extended_detectors=spec.detector_mode == "hf",
        eval_threshold=spec.eval_threshold, probes_requested=list(spec.probe_ids), started_at=_now(),
    )
    if "garak" in sys.modules:
        return _fail(work_dir, result, EXIT_RUN, "garak_imported_early", "garak was imported before the environment was pinned")
    pin_environment(work_dir, hf_home=spec.hf_home)

    # The key: read once, file deleted at once, held in one local until the generator owns it.
    from redsim.ml.llm.generator import ProbeKeyUnavailable, read_key_file

    key_path = Path(spec.key_file)
    try:
        api_key = read_key_file(key_path)
    except ProbeKeyUnavailable as exc:
        key_path.unlink(missing_ok=True)
        return _fail(work_dir, result, EXIT_KEY, "probe_key_unavailable", str(exc))
    key_path.unlink(missing_ok=True)

    import garak

    result.garak_version = str(garak.__version__)
    if str(garak.__version__) != spec.expected_garak_version:
        return _fail(work_dir, result, EXIT_VERSION, "garak_version_mismatch",
                     f"installed garak {garak.__version__}, catalog expects {spec.expected_garak_version}", api_key)

    # Library debug logs would otherwise reach garak.log (root logger at DEBUG).
    for name in ("openai", "httpx", "httpcore", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)

    import yaml
    from garak import _config, _plugins, _selection, command
    from garak._spec import parse_spec_file
    from garak.evaluators import ThresholdEvaluator

    from redsim.ml.llm.generator import GatewayProviderUnavailable, PythiaGenerator, assert_no_litellm

    config_path = work_dir / GARAK_CONFIG_FILE
    config_path.write_text(yaml.safe_dump(garak_run_config(spec, work_dir), sort_keys=False), encoding="utf-8")
    try:
        _config.load_config(run_config_filename=str(config_path))
    except Exception as exc:  # noqa: BLE001 - garak raises several types here
        return _fail(work_dir, result, EXIT_RUN, "garak_config_invalid", f"{type(exc).__name__}: {exc}", api_key)
    _config.transient.starttime = datetime.now()
    _config.transient.starttime_iso = _config.transient.starttime.isoformat()
    random.seed(spec.seed)

    # Probe validation against the live registry and the detector policy.
    known = {name.split(".", 1)[1]: active for name, active in _plugins.enumerate_plugins(category="probes")}
    catalog = load_catalog()
    rows: dict[str, ChildProbeResult] = {}
    runnable: list[str] = []
    for pid in spec.probe_ids:
        info = catalog.get(pid)
        if pid not in known:
            rows[pid] = ChildProbeResult(probe_id=pid, status="not_run", reason=UNKNOWN_PROBE_REASON)
            continue
        if info is not None and info.status == "excluded":
            rows[pid] = ChildProbeResult(probe_id=pid, status="not_run",
                                         reason=f"{EXCLUDED_PROBE_REASON}: {info.exclusion_reason}")
            continue
        primary = _plugins.plugin_info(f"probes.{pid}").get("primary_detector")
        offline = detector_offline(str(primary)) if primary else None
        if primary is None or offline is None:
            rows[pid] = ChildProbeResult(probe_id=pid, status="not_run", reason="no importable primary detector")
            continue
        if spec.detector_mode == "offline" and not offline:
            rows[pid] = ChildProbeResult(probe_id=pid, status="not_run", reason=DETECTOR_OFFLINE_REASON)
            continue
        runnable.append(pid)
        rows[pid] = ChildProbeResult(probe_id=pid, status="run")
    # garak resolves the same selection from run.spec; anything it rejects is recorded, not guessed.
    resolved = _selection.resolve_spec(parse_spec_file(_config.run.spec), skip_unknown=True)
    resolved_ids = {_normalise_probe_name(p) for p in resolved.probes}
    for pid in list(runnable):
        if pid not in resolved_ids:
            rows[pid] = ChildProbeResult(probe_id=pid, status="not_run", reason=f"{UNKNOWN_PROBE_REASON}: rejected by garak run.spec")
            runnable.remove(pid)

    counts: dict[str, tuple[int, int]] = {}
    _install_prompt_cap(spec.max_prompts_per_probe, spec.seed, counts)

    report_path: Path | None = None
    run_error: tuple[str, str] | None = None
    generator: PythiaGenerator | None = None
    try:
        generator = PythiaGenerator(name=spec.model_id, config_root=_config, api_key=api_key)
        del api_key
        assert_no_litellm()
        command.start_run()
        report_path = Path(str(_config.transient.report_filename))
        for pid in runnable:
            blocked_before = generator.ledger.gateway_blocked
            try:
                command.probewise_run(generator, [f"probes.{pid}"], ThresholdEvaluator(spec.eval_threshold), [])
            finally:
                rows[pid].n_outputs_blocked = generator.ledger.gateway_blocked - blocked_before
    except BaseException as exc:  # noqa: BLE001 - the whole run is reported, then re-raised as an exit code
        run_error = ("provider_unavailable" if isinstance(exc, GatewayProviderUnavailable) else type(exc).__name__, str(exc))
        if isinstance(exc, KeyboardInterrupt):
            run_error = ("interrupted", "run interrupted")
    finally:
        if getattr(_config.transient, "reportfile", None) is not None:
            try:
                command.end_run()
            except Exception as exc:  # noqa: BLE001 - keep the partial report
                logging.getLogger(__name__).warning("garak end_run failed: %s", type(exc).__name__)
    secret_for_scrub = generator.api_key if generator is not None else ""

    # Counts from the report; usage from the ledger.
    attempts, evals = count_report(report_path) if report_path else ({}, {})
    for pid in runnable:
        row = rows[pid]
        loaded, after = counts.get(pid, (None, None))
        row.n_prompts_loaded, row.n_prompts_after_cap = loaded, after
        tally = attempts.get(pid, {})
        row.n_attempts_complete = int(tally.get("complete", 0))
        row.n_outputs = int(tally.get("outputs", 0))
        row.n_outputs_none = int(tally.get("outputs_none", 0))
        row.detectors = evals.get(pid, [])
        if run_error is not None and not row.detectors:
            row.status = "not_run" if run_error[0] == "provider_unavailable" else "failed"
            row.reason = "provider_unavailable" if run_error[0] == "provider_unavailable" else _scrub(
                f"run aborted: {run_error[0]}", secret_for_scrub
            )
    result.probes = [rows[pid] for pid in spec.probe_ids]
    result.probes_run = [pid for pid in runnable if rows[pid].status == "run"]
    result.usage = generator.ledger.to_dict() if generator is not None else {}
    _write_json(work_dir / USAGE_FILE, result.usage)

    garak_dir = work_dir / GARAK_DIR
    hitlog = garak_dir / f"{REPORT_PREFIX}.hitlog.jsonl"
    digest = garak_dir / f"{REPORT_PREFIX}.report.html"
    result.files = {
        "report_jsonl": _relative(work_dir, report_path),
        "hitlog_jsonl": _relative(work_dir, hitlog),
        "digest_html": _relative(work_dir, digest),
        "usage_json": _relative(work_dir, work_dir / USAGE_FILE),
        "garak_config": _relative(work_dir, config_path),
        "garak_log": _relative(work_dir, work_dir / GARAK_LOG_FILE),
    }
    # Fail closed on the key: nothing the run wrote may carry it.
    if secret_for_scrub:
        for candidate in (work_dir / GARAK_LOG_FILE, report_path, hitlog, digest, config_path):
            if candidate is not None and _scrub_file_in_place(candidate, secret_for_scrub):
                result.key_leak_scrubbed = True
    if generator is not None:
        generator.close()

    result.finished_at = _now()
    result.wall_time_s = round((result.finished_at - (result.started_at or result.finished_at)).total_seconds(), 6)
    if run_error is not None:
        return _fail(work_dir, result, EXIT_RUN, run_error[0], run_error[1], secret_for_scrub)
    result.status = "succeeded"
    result.exit_code = EXIT_OK
    _write_result(work_dir, result)
    _write_env_keys(work_dir)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m redsim.ml.llm.probe_child",
                                     description="Run one garak probe set through the Pythia gateway (redsim worker child).")
    parser.add_argument("--spec", required=True, help="path of the LLMProbeChildSpec JSON written by the worker parent")
    args = parser.parse_args(argv)
    spec_path = Path(args.spec)
    try:
        spec = LLMProbeChildSpec.model_validate_json(spec_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - reported as exit 2
        sys.stderr.write(f"probe_child: invalid spec: {type(exc).__name__}: {_scrub(str(exc))}\n")
        work_dir = spec_path.parent
        try:
            _write_result(work_dir, ChildResult(status="failed", model_id="unknown", exit_code=EXIT_SPEC,
                                                error_type="spec_invalid", error=_scrub(str(exc))))
        except OSError:
            pass
        return EXIT_SPEC
    return run(spec)


if __name__ == "__main__":  # pragma: no cover - exercised through the runner
    sys.exit(main())
