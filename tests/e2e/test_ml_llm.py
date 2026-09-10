"""LLM probe runs end to end: garak through the gateway contract (register LLM-30, TESTS_DOCS; plan 12 wave B4).

Spec sections 11.6 (probe material; HarmBench excluded by owner decision
LLM-08), 15.9 / D9 (k/n scorecards never enter an MRI), 17.4 (the probe
routes), 21.7 (the probe key lives in an ``AuthProfile``), 26.4 item 20 (every
LLM call goes through the gateway, no provider key anywhere) and 26.5 item 22
(the audit chain), on the shared harness of ``tests/e2e/conftest.py`` /
``tests/e2e/harness.py``.

The gateway is ``tests/ml/fake_openai_server.py``: the Pythia OpenAI-compatible
surface (``GET /v1/models``, ``POST /v1/chat/completions``) on 127.0.0.1,
answering every prompt with a canned DAN-style reply so the string detectors
have something to fire on. garak 0.16 runs for real in the credential-minimised
probe child (``redsim.ml.llm.runner``); no network beyond loopback, no provider
key. The whole file carries the ``garak`` marker and skips cleanly when garak
or the llm-core package is absent. Nothing measured here is a claim about any
model: the hit rates are what two probes did against a canned reply.

1. ``test_probe_catalog_lists_core_and_marks_harmbench_excluded``:
   ``GET /v1/llm/probes`` lists ``redsim-core`` with every member runnable
   offline and the HarmBench-backed probe ``excluded`` with the LLM-08 reason.
2. ``test_llm_target_registration_gates_and_row``: registering an LLM target
   is admin (``target.manage``); the row carries the canonical model id, the
   persona and the ``guardrail_mode`` declaration, the gateway URL is the
   audited target, and the probe key is nowhere in it.
3. ``test_probe_run_gates``: ``llm.probe.run`` is remediator; the viewer and
   the scanner are ``403``; a probe run on a classifier target is
   ``409 llm_target_required``; nothing is enqueued.
4. ``test_probe_run_end_to_end``: the remediator runs two ``redsim-core``
   probes with a prompt cap of four; the run succeeds through the real child;
   the scorecard is k/n per family, probe and detector with ``hit_rate`` only
   where a denominator exists and no ``mri`` / ``grade`` / ``subscores`` key
   anywhere; findings carry a severity derived from the hit rate and labelled
   so; ``/campaign`` and ``/compare`` refuse the run; the probe key is in no
   child environment, spec file, log line, audit row, job detail, scorecard or
   report; one ``LLMUsage`` row accounts for the probe traffic; the run chain
   carries the LLM vocabulary and ``redsim audit verify --all`` passes.

Run::

    REDSIM_E2E=1 pytest -q -p no:cacheprovider -m e2e tests/e2e/test_ml_llm.py

The harness fixtures are not edited here; every helper lives in this file.
Heavy imports happen inside fixtures and tests, after the session fixtures
have checked the extras, so collection stays green without them.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import pytest

from tests.e2e import harness as h

if TYPE_CHECKING:
    from tests.e2e.harness import E2EApp, E2EOrg

pytestmark = [pytest.mark.e2e, pytest.mark.garak]

#: The probe key: a low-entropy fake in the ``pk_`` shape the redaction and storage guards look for.
PROBE_KEY = f"pk_e2e_fake_probe_key_{uuid4().hex[:16]}"
#: A canonical ``<vendor>/<model>`` Pythia id (``redsim.llm.router.is_pythia_canonical``); the fake gateway
#: lists it. ``redsim/ml/llm/catalog.json`` is the probe catalog and carries no model ids.
MODEL_ID = "amazon/nova-micro-v1:0"
PERSONA = "e2e-redteam"
GUARDRAIL_MODE = "permission_gate_only"
#: Two ``redsim-core`` probes whose primary detectors are offline string detectors.
PROBES = ["dan.Dan_11_0", "encoding.InjectBase64"]
MAX_PROMPTS = 4
#: The MRI vocabulary that never appears in a probe scorecard (spec 15.9, D9; register LLM-13).
FORBIDDEN_KEYS = frozenset({"mri", "grade", "subscores"})
_PK_SHAPE = re.compile(r"\bpk_[A-Za-z0-9_\-]{8,}\b")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _forbidden_paths(value: Any, path: str = "") -> list[str]:
    """Every ``mri`` / ``grade`` / ``subscores`` key path in ``value`` (empty for a valid scorecard)."""
    found: list[str] = []
    if isinstance(value, dict):
        for key, inner in value.items():
            here = f"{path}.{key}" if path else str(key)
            if str(key) in FORBIDDEN_KEYS:
                found.append(here)
            found.extend(_forbidden_paths(inner, here))
    elif isinstance(value, (list, tuple)):
        for index, inner in enumerate(value):
            found.extend(_forbidden_paths(inner, f"{path}[{index}]"))
    return found


def _detail_code(response: Any) -> str | None:
    try:
        detail = response.json().get("detail")
    except ValueError:
        return None
    return str(detail.get("code")) if isinstance(detail, dict) else None


def _events(e2e_app: E2EApp, chain_id: str, action: str | None = None) -> list[dict[str, Any]]:
    return [ev for ev in e2e_app.read_chain(chain_id) if action is None or ev["action"] == action]


def _count(e2e_app: E2EApp, model: Any, **where: Any) -> int:
    from sqlalchemy import func, select

    with e2e_app.session() as sess:
        stmt = select(func.count()).select_from(model)
        for key, value in where.items():
            stmt = stmt.where(getattr(model, key) == value)
        return int(sess.execute(stmt).scalar() or 0)


def assert_key_free(text: str, *, where: str) -> None:
    """Neither the probe key nor any ``pk_`` shaped token appears (spec 21.7, LLM-04)."""
    assert PROBE_KEY not in text, f"{where}: the probe key appears"
    assert not _PK_SHAPE.search(text), f"{where}: a pk_-shaped token appears"


def _verified_and_broken(output: str) -> tuple[set[str], dict[str, str]]:
    verified = {match.group(1) for line in output.splitlines() if "events verified" in line
                for match in [re.search(r"chain '([^']+)'", line)] if match}
    broken: dict[str, str] = {}
    for line in output.splitlines():
        match = re.search(r"chain '([^']+)'", line)
        if "broken at seq=" in line and match:
            broken[match.group(1)] = line
    return verified, broken


# ---------------------------------------------------------------------------
# The probe-child spy: what the garak child was spawned with (argv, environment, spec file)
# ---------------------------------------------------------------------------


@dataclass
class ChildSpawn:
    argv: list[str]
    env: dict[str, str]
    spec_text: str | None
    key_file: Path | None


@dataclass
class RunnerSpy:
    """Records every ``python -m redsim.ml.llm.probe_child`` spawn; other subprocesses pass through."""

    spawns: list[ChildSpawn] = field(default_factory=list)

    def install(self, patch: pytest.MonkeyPatch) -> None:
        import redsim.ml.llm.runner as runner_module

        real_popen = runner_module.subprocess.Popen
        spy = self

        def spawn(*args: Any, **kwargs: Any) -> Any:
            argv = list(args[0]) if args else list(kwargs.get("args") or [])
            if "redsim.ml.llm.probe_child" in argv:
                spec_text: str | None = None
                key_file: Path | None = None
                if "--spec" in argv:
                    spec_path = Path(argv[argv.index("--spec") + 1])
                    if spec_path.is_file():
                        spec_text = spec_path.read_text(encoding="utf-8")
                        try:
                            key_file = Path(str(json.loads(spec_text).get("key_file")))
                        except (ValueError, AttributeError, TypeError):
                            key_file = None
                spy.spawns.append(ChildSpawn(argv=argv, env=dict(kwargs.get("env") or {}), spec_text=spec_text,
                                             key_file=key_file))
            return real_popen(*args, **kwargs)

        patch.setattr(runner_module.subprocess, "Popen", spawn)


# ---------------------------------------------------------------------------
# Module fixtures: garak present, the fake gateway, the environment, the probe key, the target
# ---------------------------------------------------------------------------


@dataclass
class LLMLab:
    server: Any
    spy: RunnerSpy
    patch: pytest.MonkeyPatch

    @property
    def gateway_url(self) -> str:
        return str(self.server.base_url)

    @property
    def gateway_host(self) -> str:
        return "127.0.0.1"

    def registration(self, **overrides: Any) -> dict[str, Any]:
        body: dict[str, Any] = {
            "source": "endpoint", "endpoint_kind": "llm", "project_id": h.PROJECT_ID,
            "model_id": MODEL_ID, "persona": PERSONA, "guardrail_mode": GUARDRAIL_MODE,
            "gateway_url": self.gateway_url, "name": "e2e LLM target (fake gateway)",
        }
        body.update(overrides)
        return body


@pytest.fixture(scope="module")
def lab(e2e_app: E2EApp, e2e_org: E2EOrg) -> Iterator[LLMLab]:
    """garak, the llm-core runner and the fake gateway; skips cleanly when the garak extra is absent."""
    pytest.importorskip("garak", reason="the garak extra is not installed; the LLM probe tier needs garak 0.16")
    pytest.importorskip("redsim.ml.llm.runner", reason="redsim.ml.llm (llm-core) is not on this tree")
    pytest.importorskip("cryptography")
    from cryptography.fernet import Fernet

    from redsim.services import ml_llm
    from tests.ml.fake_openai_server import DAN_REPLY, FakeOpenAIServer

    try:
        ml_llm.load_probe_catalog()
    except ml_llm.CatalogUnavailable as exc:
        pytest.skip(f"the committed probe catalog is not readable: {exc.reason}")

    patch = pytest.MonkeyPatch()
    patch.setenv("REDSIM_AUTH_PROFILES_KEY", Fernet.generate_key().decode())
    patch.delenv("REDSIM_AUTH_PROFILES_KEY_PREVIOUS", raising=False)
    # The gateway is named per target (gateway_url); the worker must not be told to skip LLM work.
    patch.delenv("PYTHIA_BASE_URL", raising=False)
    patch.delenv("REDSIM_DISABLE_LLM", raising=False)
    patch.setenv("REDSIM_LLM_PROBE_TIMEOUT_S", "600")
    for name in (ml_llm.QUOTA_ENV, ml_llm.MAX_PROMPTS_ENV, ml_llm.HF_DETECTORS_ENV):
        patch.delenv(name, raising=False)
    spy = RunnerSpy()
    spy.install(patch)
    server = FakeOpenAIServer(token=PROBE_KEY, models=(MODEL_ID, "pythia/auto"), reply=DAN_REPLY)
    server.start()
    try:
        yield LLMLab(server=server, spy=spy, patch=patch)
    finally:
        server.stop()
        patch.undo()


@pytest.fixture(scope="module")
def probe_profile_id(lab: LLMLab, e2e_org: E2EOrg) -> str:
    """The bearer ``AuthProfile`` holding the probe key (register LLM-26: its own persona, never the writer's)."""
    admin = e2e_org.client("admin")
    body = {"project_id": h.PROJECT_ID, "name": f"e2e-probe-key-{uuid4().hex[:8]}", "kind": "bearer",
            "config": {"persona": PERSONA, "gateway": "pythia"}, "secret": PROBE_KEY}
    assert e2e_org.client("remediator").post("/v1/auth-profiles", json=body).status_code == 403
    created = admin.post("/v1/auth-profiles", json=body)
    assert created.status_code == 201, created.text
    assert_key_free(created.text, where="POST /v1/auth-profiles response")
    return str(created.json()["id"])


@pytest.fixture(scope="module")
def llm_target(lab: LLMLab, e2e_org: E2EOrg, probe_profile_id: str) -> dict[str, Any]:
    """The LLM target registered by the admin through ``POST /v1/models`` (``endpoint_kind=llm``)."""
    response = e2e_org.client("admin").post("/v1/models", json=lab.registration(auth_profile_id=probe_profile_id))
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


# ---------------------------------------------------------------------------
# 1. The probe catalog
# ---------------------------------------------------------------------------


def test_probe_catalog_lists_core_and_marks_harmbench_excluded(lab: LLMLab, e2e_org: E2EOrg) -> None:
    from redsim.services.ml_llm import D9_SENTENCE

    # spec 11.6 / register LLM-07, -12: the committed catalog with a status and reason per probe; viewer may read.
    response = e2e_org.client("viewer").get("/v1/llm/probes")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["garak_version"] == "0.16.0" and body["default_probe_set"] == "redsim-core"
    sets = {row["id"]: row for row in body["sets"]}
    assert "redsim-core" in sets and sets["redsim-core"]["n_probes"] > 0
    assert sets["redsim-core"]["n_excluded"] == 0, "the core set never carries an excluded probe"
    assert sets["redsim-core"]["n_offline"] == sets["redsim-core"]["n_probes"], "every core member runs offline"
    rows = {row["id"]: row for row in body["probes"]}
    for probe_id in PROBES:
        assert rows[probe_id]["status"] == "offline" and "redsim-core" in rows[probe_id]["sets"], rows[probe_id]
    # Owner decision LLM-08: HarmBench material is reachable only through fitd.FITD, which is excluded and says why.
    harmbench = [row for row in rows.values() if "harmbench" in json.dumps(row).lower()]
    assert harmbench, "the catalog names the HarmBench-backed probe"
    for row in harmbench:
        assert row["status"] == "excluded" and row["sets"] == [], row
        assert "LLM-08" in row["reason"] and "HarmBench" in row["reason"], row["reason"]
    assert all(row["status"] in {"offline", "extended", "excluded"} and row["reason"] for row in rows.values())
    assert any(D9_SENTENCE in item for item in body["limitations"]), body["limitations"]
    assert_key_free(response.text, where="GET /v1/llm/probes")


# ---------------------------------------------------------------------------
# 2. LLM target registration
# ---------------------------------------------------------------------------


def test_llm_target_registration_gates_and_row(
    lab: LLMLab, e2e_app: E2EApp, e2e_org: E2EOrg, probe_profile_id: str, llm_target: dict[str, Any],
) -> None:
    from redsim.db.models import Target

    body = lab.registration(auth_profile_id=probe_profile_id, persona=f"{PERSONA}-denied")
    targets_before = _count(e2e_app, Target, kind="ml_model_endpoint")
    # spec 7.3 / register LLM-03: registering an LLM target is target.manage (admin); the gate writes nothing.
    for who in ("viewer", "scanner", "remediator", "approver", h.OUTSIDER):
        refused = e2e_org.client(who).post("/v1/models", json=body)
        assert refused.status_code == 403, f"{who}: {refused.text}"
        assert isinstance(refused.json()["detail"], str)
    assert _count(e2e_app, Target, kind="ml_model_endpoint") == targets_before
    assert lab.server.requests == [], "registration contacts no gateway"

    # The admin's row (module fixture): modality llm, format endpoint, available, gradients false, key nowhere.
    assert llm_target["modality"] == "llm" and llm_target["source"] == "endpoint" and llm_target["format"] == "endpoint"
    assert llm_target["status"] == "available" and llm_target["gradients"] is False
    manifest = llm_target["manifest"]
    assert manifest["model_id"] == MODEL_ID and manifest["persona"] == PERSONA
    assert manifest["guardrail_mode"] == GUARDRAIL_MODE and manifest["auth_profile_id"] == probe_profile_id
    assert manifest["gateway_host"] == lab.gateway_host and manifest["garak_version_expected"] == "0.16.0"
    assert llm_target["validation"]["entitlement"] == "unverified", "entitlement is checked by the worker, not claimed"
    assert_key_free(json.dumps(llm_target), where="POST /v1/models response")
    # spec 5.11: the chained model.register row, with the gateway URL as the audited target (allowlist applies).
    rows = [ev for ev in _events(e2e_app, f"project:{h.PROJECT_ID}", "model.register")
            if ev["detail"].get("target_id") == llm_target["id"]]
    assert len(rows) == 1 and rows[0]["success"] is True and rows[0]["actor"] == e2e_org.actor("admin")
    assert rows[0]["target"].startswith(lab.gateway_url) and rows[0]["allowlist_check"] == "pass"
    assert rows[0]["detail"]["endpoint_kind"] == "llm" and rows[0]["detail"]["model_id"] == MODEL_ID
    assert rows[0]["detail"]["auth_profile_id"] == probe_profile_id
    assert_key_free(json.dumps(rows[0]["detail"]), where="model.register detail")
    shown = e2e_org.client("viewer").get(f"/v1/models/{llm_target['id']}")
    assert shown.status_code == 200 and shown.json()["modality"] == "llm" and shown.json()["status"] == "available"
    assert_key_free(shown.text, where="GET /v1/models/{id}")


# ---------------------------------------------------------------------------
# 3. Probe-run gates
# ---------------------------------------------------------------------------


def test_probe_run_gates(
    lab: LLMLab, e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], llm_target: dict[str, Any],
) -> None:
    from redsim.api.errors import LLM_TARGET_REQUIRED
    from redsim.db.models import Run
    from redsim.services.ml_llm import LLM_SCANNER

    body = {"probe_ids": PROBES, "max_prompts_per_probe": MAX_PROMPTS, "seed": 0}
    runs_before = _count(e2e_app, Run, scanner=LLM_SCANNER)
    project_rows_before = len(_events(e2e_app, f"project:{h.PROJECT_ID}"))
    # spec 7.3 / register LLM-25: llm.probe.run is remediator; the viewer and the scanner are refused, nothing runs.
    for who in ("viewer", "scanner", h.OUTSIDER, h.STRANGER):
        refused = e2e_org.client(who).post(f"/v1/models/{llm_target['id']}/probes", json=body)
        assert refused.status_code == 403, f"{who}: {refused.text}"
    assert _count(e2e_app, Run, scanner=LLM_SCANNER) == runs_before
    assert len(_events(e2e_app, f"project:{h.PROJECT_ID}")) == project_rows_before, "a role refusal writes no row"
    assert lab.server.requests == [], "no gateway request for a refused probe run"

    # spec 17.3 llm_target_required (D9): a classifier target runs campaigns, never probes; audited refusal.
    refused = e2e_org.client("remediator").post(f"/v1/models/{e2e_bundled[h.TABULAR_MODEL_ID]}/probes", json=body)
    assert refused.status_code == 409 and _detail_code(refused) == LLM_TARGET_REQUIRED, refused.text
    assert "/attacks" in refused.json()["detail"]["message"]
    rows = _events(e2e_app, f"project:{h.PROJECT_ID}", "llm.probe.run")
    assert rows and rows[-1]["success"] is False and rows[-1]["detail"]["code"] == LLM_TARGET_REQUIRED
    assert rows[-1]["detail"]["target_id"] == e2e_bundled[h.TABULAR_MODEL_ID]
    assert _count(e2e_app, Run, scanner=LLM_SCANNER) == runs_before


# ---------------------------------------------------------------------------
# 4. The probe run through the real garak child against the fake gateway
# ---------------------------------------------------------------------------


def test_probe_run_end_to_end(
    lab: LLMLab, e2e_app: E2EApp, e2e_org: E2EOrg, probe_profile_id: str, llm_target: dict[str, Any],
    audit_verify_all: Callable[[], tuple[int, str]], caplog: pytest.LogCaptureFixture,
) -> None:
    from redsim.audit.chain import verify_chain
    from redsim.db.models import Finding, LLMUsage
    from redsim.services.ml_findings import LLM_SEVERITY_BASIS, LLM_SOURCE_TOOL
    from redsim.services.ml_llm import D9_SENTENCE, LLM_JOB_TYPE, LLM_SCANNER, LLM_USAGE_TASK
    from tests.ml.fake_openai_server import DAN_REPLY

    remediator, viewer = e2e_org.client("remediator"), e2e_org.client("viewer")
    target_id = str(llm_target["id"])
    spawns_before = len(lab.spy.spawns)

    # -- spec 17.4: POST /v1/models/{id}/probes (remediator) admits and the eager worker runs the child ---------
    with caplog.at_level(logging.DEBUG):
        launched = remediator.post(f"/v1/models/{target_id}/probes",
                                   json={"probe_ids": PROBES, "max_prompts_per_probe": MAX_PROMPTS, "seed": 0})
        assert launched.status_code == 202, launched.text
        handle = launched.json()
        run_id = str(handle["run_id"])
        assert handle["kind"] == "llm_probe" and handle["scorecard_url"] == f"/v1/runs/{run_id}/llm-scorecard"
        run = h.wait_for_run(remediator, run_id, timeout_s=30)
    if run["status"] != "succeeded":
        table = run.get("stage_table") or {}
        pytest.fail(f"redsim/workers/tasks/ml_llm.py: probe run {run_id} ended {run['status']!r}: "
                    f"error={table.get('error')!r} stages_done={table.get('stages_done')!r}")
    assert run["scanner"] == LLM_SCANNER
    table = run["stage_table"]
    assert table["kind"] == "llm_probe" and table["completeness"] == "complete", table
    assert table["stages_done"] == ["load_target", "entitlement", "probe:Dan_11_0", "probe:InjectBase64", "score",
                                    "findings", "report"], table["stages_done"]

    # -- LLM-32 / LLM-28: the entitlement listing and every probe prompt reached the gateway with the probe key --
    assert lab.server.model_requests and all(r["auth_ok"] and r["status"] == 200 for r in lab.server.model_requests)
    chats = lab.server.chat_requests
    assert chats, "garak sent probe prompts through the child"
    assert all(r["auth_ok"] and r["persona"] == PERSONA and r["model"] == MODEL_ID for r in chats), chats[0]
    assert all(r["status"] == 200 for r in chats)

    # -- spec 15.9 / D9 (register LLM-13): the k/n scorecard, never an MRI -------------------------------------
    served = viewer.get(f"/v1/runs/{run_id}/llm-scorecard")
    assert served.status_code == 200, served.text
    body = served.json()
    assert body["kind"] == "llm_probe" and body["artifact"]["run_status"] == "succeeded"
    scorecard = body["scorecard"]
    assert _forbidden_paths(body) == [], "no mri, grade or subscores key anywhere in the scorecard response"
    assert scorecard["schema"] == "llm-probe-scorecard-1" and scorecard["run_id"] == run_id
    assert scorecard["model_id"] == MODEL_ID and scorecard["persona"] == PERSONA
    assert scorecard["guardrail_mode"] == GUARDRAIL_MODE and scorecard["garak_version"] == "0.16.0"
    assert scorecard["probe_ids"] == PROBES and scorecard["max_prompts_per_probe"] == MAX_PROMPTS
    assert scorecard["completeness"] == "complete" and scorecard["child_status"] == "succeeded"
    counts = scorecard["counts"]
    assert counts["n_probes"] == 2 and counts["n_probes_run"] == 2 and counts["n_probes_not_run"] == 0
    assert counts["n_families"] == 2, counts
    families = {row["family"]: row for row in scorecard["families"]}
    assert set(families) == {"dan", "encoding"}
    detectors = [(probe["probe_id"], d) for fam in scorecard["families"] for probe in fam["probes"]
                 for d in probe["detectors"]]
    assert detectors, "each probe carries at least one detector row"
    evaluated = 0
    for probe_id, row in detectors:
        # k hits / n evaluated with the denominator on the row; no rate without a denominator.
        assert set(row) >= {"detector", "status", "n_evaluated", "n_hits", "n_passed", "n_none", "hit_rate"}, row
        assert 0 <= row["n_hits"] <= row["n_evaluated"] <= MAX_PROMPTS, (probe_id, row)
        if row["n_evaluated"] == 0:
            assert row["hit_rate"] is None, (probe_id, row)
        else:
            assert row["hit_rate"] == pytest.approx(row["n_hits"] / row["n_evaluated"]), (probe_id, row)
            evaluated += 1
    assert evaluated > 0, "at least one detector evaluated responses"
    for fam in scorecard["families"]:
        assert "hit_rate" not in fam and "rate" not in {k.lower() for k in fam}, "no cross-probe aggregate rate"
    assert any(D9_SENTENCE in item for item in scorecard["limitations"]), scorecard["limitations"]
    assert "No MRI or grade" in scorecard["reading"]
    usage = scorecard["usage"]
    assert usage["n_requests"] == len(chats), (usage, len(chats))
    assert usage["prompt_tokens"] > 0 and usage["completion_tokens"] > 0, "the token ledger sums what the gateway returned"
    assert scorecard["models_seen"] == [MODEL_ID], "pythia/auto is never substituted for the named model"
    # Prompt and response text never leave garak's own files (LLM-18): the canned reply is not in the record.
    assert DAN_REPLY not in json.dumps(body)
    assert_key_free(served.text, where="GET /v1/runs/{id}/llm-scorecard")

    # -- 2026-09-10, live progress: the persisted block after the real child reads 100 of the normalised
    #    completed-prompt count (the sum of n_prompts_sent, never the raw request count, which counts retries).
    progress = table["progress"]
    sent = sum(int(p["n_prompts_sent"] or 0) for fam in scorecard["families"] for p in fam["probes"])
    assert progress["unit"] == "prompts" and progress["percent"] == 100, progress
    assert progress["done"] == progress["total"] == sent > 0, (progress, sent)
    assert progress["probes_done"] == progress["n_probes"] == 2 and progress["probe"] is None, progress
    assert isinstance(progress["updated_at"], str) and progress["updated_at"], progress
    # The count never enters evidence: no progress or percent key in the served scorecard.
    scorecard_text = json.dumps(scorecard)
    assert '"progress":' not in scorecard_text and '"percent":' not in scorecard_text

    # -- register LLM-15: findings with a severity derived from the hit rate and labelled so ---------------------
    with e2e_app.session() as sess:
        from sqlalchemy import select

        finding_rows = sess.execute(select(Finding).where(Finding.run_id == run_id)).scalars().all()
        findings = [(row.id, row.severity, row.source_tool, dict(row.schema_blob or {})) for row in finding_rows]
        usage_rows = sess.execute(select(LLMUsage).where(LLMUsage.run_id == run_id)).scalars().all()
        ledger = [(row.task, row.model, row.prompt_tokens, row.completion_tokens, row.project_id) for row in usage_rows]
    hits = [(pid, d) for pid, d in detectors if d["n_evaluated"] > 0 and d["hit_rate"] >= 0.2]
    if hits:
        assert findings, f"detectors crossed the finding threshold {hits} yet no finding was projected"
    else:
        assert not findings, "no detector crossed the threshold, so no finding is projected"
    for finding_id, severity, source_tool, blob in findings:
        assert source_tool == LLM_SOURCE_TOOL and severity in {"high", "medium", "low"}
        llm = blob["llm"]
        assert llm["severity_basis"] == LLM_SEVERITY_BASIS and llm["severity"] == severity
        assert llm["n_evaluated"] > 0 and llm["hit_rate"] == pytest.approx(llm["n_hits"] / llm["n_evaluated"])
        assert llm["hit_rate"] >= llm["threshold"] == 0.2
        assert "derived from the hit rate bands" in blob["description"], blob["description"]
        assert "not from the spec 15.5 ASR bands" in blob["description"]
        assert blob["finding_kind"] == "adversarial_llm" and not blob.get("ml"), "no MRI finding detail on a probe finding"
        assert llm["artifacts"]["scorecard"] == body["artifact"]["artifact_id"]
        assert _forbidden_paths(blob) == []
        assert_key_free(json.dumps(blob), where=f"finding {finding_id} blob")
        assert DAN_REPLY not in json.dumps(blob)
        shown = viewer.get(f"/v1/findings/{finding_id}")
        assert shown.status_code == 200, shown.text
        assert shown.json()["severity"] == severity and shown.json()["schema_blob"]["llm"]["severity_basis"] == LLM_SEVERITY_BASIS
        assert_key_free(shown.text, where=f"GET /v1/findings/{finding_id}")

    # -- register LLM-20 / spec 5.12: one LLMUsage row accounts for the probe traffic --------------------------
    assert len(ledger) == 1, ledger
    assert ledger[0][0] == LLM_USAGE_TASK and ledger[0][1] == MODEL_ID and ledger[0][4] == h.PROJECT_ID
    assert (ledger[0][2], ledger[0][3]) == (usage["prompt_tokens"], usage["completion_tokens"])

    # -- D9: the campaign and compare reads refuse a probe run; no MRI is ever served for it -------------------
    for path in (f"/v1/runs/{run_id}/campaign", f"/v1/runs/{run_id}/compare?with={run_id}"):
        refused = remediator.get(path)
        assert refused.status_code in (404, 409), (path, refused.text)
        detail = refused.json()["detail"]
        assert isinstance(detail, dict) and detail["code"] in {"campaign_not_found", "llm_target_required"}, (path, detail)
        assert "mri" not in refused.text.lower() or detail["code"] == "llm_target_required", (path, refused.text)

    # -- LLM-10 / LLM-33: the child held no credential; the key travelled by file inside the 0700 work dir ------
    spawns = lab.spy.spawns[spawns_before:]
    assert len(spawns) == 1, f"expected one probe child, saw {len(spawns)}"
    child = spawns[0]
    env_text = json.dumps(child.env)
    assert_key_free(env_text, where="probe child environment")
    assert not any(k.startswith("PYTHIA_") for k in child.env), "no PYTHIA_* variable reaches the child"
    for forbidden in ("REDSIM_AUTH_PROFILES_KEY", "REDSIM_DB_URL", "REDSIM_CONFIG", "REDSIM_BLOB_FS_PATH",
                      "OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "KAGGLE_API_TOKEN"):
        assert forbidden not in child.env, f"{forbidden} reached the probe child"
    assert child.env.get("HF_HUB_OFFLINE") == "1" and child.env.get("REDSIM_PLUGINS") == "0"
    assert child.spec_text is not None, "the child spec file was written before the spawn"
    assert_key_free(child.spec_text, where="probe child spec file")
    spec = json.loads(child.spec_text)
    assert spec["model_id"] == MODEL_ID and spec["probe_ids"] == PROBES and spec["gateway_url"].startswith(lab.gateway_url)
    assert child.key_file is not None and child.key_file.parent == Path(spec["work_dir"])
    assert not child.key_file.exists(), "the key file is deleted with the work directory"
    assert not Path(spec["work_dir"]).exists(), "garak.log (prompts and responses) never survives the run"
    # -- no key and no response text in any log line the worker parent emitted -------------------------------
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert_key_free(log_text, where="worker log")
    assert DAN_REPLY not in log_text

    # -- spec 5.10: Job.detail carries ids and settings, never the key -----------------------------------------
    from redsim.db.models import Job

    with e2e_app.session() as sess:
        from sqlalchemy import select

        jobs = sess.execute(select(Job).where(Job.run_id == run_id)).scalars().all()
        job_details = [(str(job.type), str(job.status), dict(job.detail or {})) for job in jobs]
    assert len(job_details) == 1 and job_details[0][0] == LLM_JOB_TYPE and job_details[0][1] == "succeeded"
    assert job_details[0][2]["auth_profile_id"] == probe_profile_id and job_details[0][2]["probe_ids"] == PROBES
    assert_key_free(json.dumps(job_details[0][2]), where="llm.probe Job.detail")

    # -- spec 14.8: the report is served and reads as counts, never as an MRI or as prompt text -----------------
    report = remediator.get(f"/v1/runs/{run_id}/report.md")
    assert report.status_code == 200, report.text[:200]
    assert D9_SENTENCE in report.text and "k hits / n evaluated" in report.text
    assert "## 2. Probe scorecard" in report.text and "## 5. Limitations" in report.text
    assert_key_free(report.text, where="report.md")
    assert DAN_REPLY not in report.text

    # -- spec 26.5 item 22 / register LLM-19: the run chain carries the LLM vocabulary and verifies -------------
    chain = e2e_app.read_chain(f"run:{run_id}")
    actions = [ev["action"] for ev in chain]
    assert actions == ["llm.probe.entitlement", "llm.probe.execute.Dan_11_0", "llm.probe.execute.InjectBase64",
                       "llm.probe.score", "report.render", "job.complete"], actions
    assert all(ev["success"] for ev in chain), [(ev["action"], ev["detail"]) for ev in chain if not ev["success"]]
    assert all(ev["actor"] == f"worker:{LLM_JOB_TYPE}" for ev in chain)
    assert all(ev["detail"]["requested_by"] == e2e_org.actor("remediator") for ev in chain)
    entitlement = chain[0]["detail"]
    assert entitlement["entitled"] is True and entitlement["n_entitled"] == 2 and entitlement["model_id"] == MODEL_ID
    for ev in chain[1:3]:
        assert ev["detail"]["status"] == "run" and ev["detail"]["detectors"], ev["detail"]
        for row in ev["detail"]["detectors"]:
            assert set(row) == {"detector", "status", "n_evaluated", "n_hits", "n_none"}, "counts only on the chain"
    score_row = chain[3]["detail"]
    assert score_row["scorecard_sha256"] == body["artifact"]["sha256"] and score_row["counts"]["n_probes_run"] == 2
    assert score_row["usage"]["requests"] == len(chats)
    assert chain[4]["detail"]["formats"] == ["md", "json", "html"]
    assert chain[5]["detail"]["status"] == "succeeded" and chain[5]["detail"]["n_findings"] == len(findings)
    chain_text = json.dumps(chain, default=str)
    assert_key_free(chain_text, where=f"run:{run_id} chain")
    assert DAN_REPLY not in chain_text
    admission = [ev for ev in _events(e2e_app, f"project:{h.PROJECT_ID}", "llm.probe.run")
                 if ev["detail"].get("run_id") == run_id]
    assert len(admission) == 1 and admission[0]["success"] is True and admission[0]["actor"] == e2e_org.actor("remediator")
    assert admission[0]["target"].startswith(lab.gateway_url) and admission[0]["allowlist_check"] == "pass"
    assert admission[0]["detail"]["n_probes"] == 2 and admission[0]["detail"]["catalog_garak_version"] == "0.16.0"
    assert_key_free(json.dumps(admission[0]["detail"]), where="llm.probe.run admission detail")
    # The chain verifies in process and through the real CLI (a sibling module may have left a tampered chain).
    assert verify_chain(chain).verified is True
    pre_broken = {cid for cid in e2e_app.chain_ids() if not verify_chain(e2e_app.read_chain(cid)).verified}
    assert f"run:{run_id}" not in pre_broken
    code, output = audit_verify_all()
    verified, broken = _verified_and_broken(output)
    assert set(broken) == pre_broken, output
    assert (code == 0) == (not pre_broken), f"exit {code}:\n{output}"
    assert f"run:{run_id}" in verified and f"project:{h.PROJECT_ID}" in verified, output
    assert_key_free(output, where="redsim audit verify --all output")
    # No chain anywhere carries the probe key.
    everything = json.dumps([ev for cid in e2e_app.chain_ids() for ev in e2e_app.read_chain(cid)], default=str)
    assert_key_free(everything, where="every audit chain")
