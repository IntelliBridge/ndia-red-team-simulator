"""Black-box endpoint connector end to end (register ENDPOINT-20..23, TESTS_DOCS-05; plan 12 wave B4).

Spec sections 9.1 rule 4 (queries leave only from the worker), 17.2 / 17.3
(``POST /v1/models`` ``source=endpoint`` and its codes), 21.7 (egress
allowlist, credentials in an ``AuthProfile``), 26.2 item 7 (denominators),
26.3 items 12 to 14 (the honest scorecard state of spec 15.4), 26.4 items 17,
20, 21 (boundaries and RBAC) and 26.5 item 22 (the audit chain), on the shared
harness of ``tests/e2e/conftest.py`` / ``tests/e2e/harness.py``. Every test
drives the production path it names and asserts on what that path left behind.

The endpoint is ``tests/ml/tiny_endpoint_server.py``: ``TinyTarget`` (a random
weight 8x8x3 test double) behind ``POST /predict`` on 127.0.0.1, authenticated
with a low-entropy fake bearer token that lives in an ``AuthProfile``. Nothing
measured against it is a demo result; the test asserts the shape and the
honesty of the record, never a number it did not observe.

1. ``test_registration_rbac_and_static_refusals``: registering a host to query
   is ``target.manage`` (admin); the scanner, remediator, approver, viewer and
   the other organisation's admin are ``403`` and nothing is written; a URL
   with userinfo is ``422 endpoint_url_invalid`` and a host outside the
   allowlist ``403 endpoint_not_allowlisted``, each a ``success=False``
   ``model.register`` row that carries the host and never the userinfo.
2. ``test_registration_validates_through_the_broker_to_available``: the admin
   registers the tiny server; the eager ``model.validate`` job probes it from
   the worker parent's broker (the child holds no credential), the target
   becomes ``available`` with ``gradients: false`` and the response
   fingerprint recorded, the black-box attack set is listed, and the ingest
   chain carries ``model.register``, ``model.validate``, ``job.complete``.
3. ``test_black_box_campaign_runs_through_the_broker``: the scanner launches
   HopSkipJump plus the benign noise control (small query budget) on the
   endpoint; the run succeeds through the real sandbox child, the record has
   denominators on every row, the broker's query counts and the budget the
   job stayed under are on the record and on the ``attack.execute`` /
   ``campaign.score`` / ``job.complete`` rows, explain is either recorded
   PartitionExplainer observations or an honest ``ExplainerUnavailable``
   limitation, the scorecard is in one of the spec 15.4 states, and the
   credential is in no child request file, child environment, audit detail,
   job detail or report.
4. ``test_white_box_attack_is_refused``: FGSM and PGD on the endpoint are
   ``422 attack_requires_gradients`` (predictions only, no surrogate) with a
   refused admission row and no ``Run``.
5. ``test_endpoint_delete_is_audited_and_chains_verify``: ``redsim audit
   verify --all`` is clean over the connector's chains, a remediator cannot
   delete, the profile cannot be deleted while the target is live (``409
   auth_profile_in_use`` naming the target, a ``success=False``
   ``auth_profile.delete`` row, ENDPOINT-18), the admin's delete is a
   ``target.manage`` row naming the host, the credential stays with its
   profile until the admin deletes it (``204``, its own row), and the chains
   still verify.

Run::

    REDSIM_E2E=1 pytest -q -p no:cacheprovider -m e2e tests/e2e/test_ml_endpoint.py

The harness fixtures are not edited here; every helper lives in this file.
Heavy imports happen inside fixtures and tests, after the session fixtures
have checked the extras, so collection stays green without them.
"""

from __future__ import annotations

import json
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

pytestmark = pytest.mark.e2e

#: The endpoint credential: a low-entropy fake, unique per session so a substring scan is meaningful.
TOKEN = f"tok-e2e-{uuid4().hex[:12]}"
#: Secrets the worker parent realistically holds; none may reach a sandbox child, a row or a file.
PARENT_SENTINELS = {
    "KAGGLE_API_TOKEN": f"kaggle-e2e-{uuid4().hex}",
    "AWS_SECRET_ACCESS_KEY": f"aws-e2e-{uuid4().hex}",
    "PYTHIA_API_KEY": f"pk_e2e_parent_{uuid4().hex[:16]}",
}
#: The broker's outbound rate limit for this file (``REDSIM_ML_ENDPOINT_RPS``): the endpoint is loopback,
#: and the limit in force is recorded on every row the test reads back.
BROKER_RPS = "100"
#: Keys that would carry a credential; none may appear in a projection, a row or a file.
SECRET_KEYS = frozenset({"secret", "secret_ciphertext", "authorization", "token", "password", "api_key"})
#: Readiness / certification wording that never appears in a grade reading (spec 15.8 iii, 14.7).
_READINESS_RE = re.compile(
    r"\b(readiness|ready|certif\w*|deploy\w*|fielding|hardened|safe|safety|proven|validated|guaranteed)\b",
    re.IGNORECASE,
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
SUBSCORE_KEYS = ("S_acc", "S_asr", "S_eps", "S_conf", "S_expl")
#: HopSkipJump with the small query budget the ml tier uses (worst case bounded at admission, ENDPOINT-08).
HSJ_PARAMS = {"max_iter": 1, "max_eval": 100, "init_eval": 10, "init_size": 3}


# ---------------------------------------------------------------------------
# Helpers (read-only views over the API and the harness database)
# ---------------------------------------------------------------------------


def _strings(value: Any) -> Iterator[str]:
    """Every string leaf (and key) of a JSON-like value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _keys(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key).lower()
            yield from _keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _keys(item)


def assert_secret_free(document: Any, *, where: str, forbid_url_path: bool = True) -> None:
    """No credential, no parent secret, no secret-shaped key and (by default) no URL path (D3: host only)."""
    text = json.dumps(document, default=str)
    assert TOKEN not in text, f"{where}: the endpoint credential appears"
    for name, value in PARENT_SENTINELS.items():
        assert value not in text, f"{where}: the worker parent's {name} appears"
    assert "Bearer " not in text, f"{where}: an Authorization header value appears"
    leaked = set(_keys(document)) & SECRET_KEYS
    assert not leaked, f"{where}: secret-shaped keys {sorted(leaked)}"
    if forbid_url_path:
        assert "/predict" not in text, f"{where}: the endpoint URL path appears; rows and projections carry the host only"


def _detail_code(response: Any) -> str | None:
    try:
        detail = response.json().get("detail")
    except ValueError:
        return None
    return str(detail.get("code")) if isinstance(detail, dict) else None


def _events(e2e_app: E2EApp, chain_id: str, action: str | None = None) -> list[dict[str, Any]]:
    events = e2e_app.read_chain(chain_id)
    return [ev for ev in events if action is None or ev["action"] == action]


def _count_targets(e2e_app: E2EApp, *, kind: str = "ml_model_endpoint") -> int:
    from sqlalchemy import func, select

    from redsim.db.models import Target

    with e2e_app.session() as sess:
        return int(sess.execute(select(func.count()).select_from(Target).where(Target.kind == kind)).scalar() or 0)


def _count_runs(e2e_app: E2EApp) -> int:
    from sqlalchemy import func, select

    from redsim.db.models import Run

    with e2e_app.session() as sess:
        return int(sess.execute(select(func.count()).select_from(Run)).scalar() or 0)


def _job_details(e2e_app: E2EApp, run_id: str) -> list[dict[str, Any]]:
    from sqlalchemy import select

    from redsim.db.models import Job

    with e2e_app.session() as sess:
        rows = sess.execute(select(Job).where(Job.run_id == run_id)).scalars().all()
        return [dict(row.detail or {}) for row in rows]


def _host_of(url: str) -> str:
    from redsim.services.ml_models import endpoint_host

    return endpoint_host(url)


def _measurements(campaign: dict[str, Any], family: str, attack_id: str | None = None) -> list[dict[str, Any]]:
    return [
        m for m in campaign["measurements"]
        if m["family"] == family and (attack_id is None or m.get("attack_id") == attack_id)
    ]


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
# The sandbox spy: what every child was spawned with (argv, environment, request file)
# ---------------------------------------------------------------------------


@dataclass
class ChildSpawn:
    argv: list[str]
    env: dict[str, str]
    request: dict[str, Any] | None
    request_text: str | None

    @property
    def mode(self) -> str | None:
        return str(self.request.get("mode")) if isinstance(self.request, dict) else None


@dataclass
class SandboxSpy:
    """Records every ``python -m redsim.ml.sandbox_worker`` spawn: the argv, the environment and the request file.

    The request file is read at spawn time (the sandbox clears its work directory afterwards). Other
    subprocesses (the CLI, the LLM probe child) pass through unrecorded.
    """

    spawns: list[ChildSpawn] = field(default_factory=list)

    def install(self, patch: pytest.MonkeyPatch) -> None:
        import redsim.ml.sandbox as sandbox_module

        real_popen = sandbox_module.subprocess.Popen
        spy = self

        def spawn(*args: Any, **kwargs: Any) -> Any:
            argv = list(args[0]) if args else list(kwargs.get("args") or [])
            if "redsim.ml.sandbox_worker" in argv:
                request_text: str | None = None
                request: dict[str, Any] | None = None
                if "--request" in argv:
                    path = Path(argv[argv.index("--request") + 1])
                    if path.is_file():
                        request_text = path.read_text(encoding="utf-8")
                        try:
                            parsed = json.loads(request_text)
                        except ValueError:
                            parsed = None
                        request = parsed if isinstance(parsed, dict) else None
                spy.spawns.append(ChildSpawn(argv=argv, env=dict(kwargs.get("env") or {}),
                                             request=request, request_text=request_text))
            return real_popen(*args, **kwargs)

        patch.setattr(sandbox_module.subprocess, "Popen", spawn)

    def campaign_children(self) -> list[ChildSpawn]:
        return [s for s in self.spawns if s.mode == "campaign"]

    def validate_children(self) -> list[ChildSpawn]:
        return [s for s in self.spawns if s.mode == "validate"]


def assert_child_boundary(spawn: ChildSpawn, *, where: str) -> None:
    """Spec 9.4 / 21.7 (ENDPOINT-22): the child saw no credential, no parent secret, no proxy, no REDSIM_ secret."""
    env_text = json.dumps(spawn.env)
    assert TOKEN not in env_text, f"{where}: the endpoint credential reached the child environment"
    for name, value in PARENT_SENTINELS.items():
        assert value not in env_text and name not in spawn.env, f"{where}: {name} reached the child environment"
    assert not any(key.upper().endswith("_PROXY") for key in spawn.env), f"{where}: a proxy variable reached the child"
    for forbidden in ("REDSIM_AUTH_PROFILES_KEY", "REDSIM_DB_URL", "REDSIM_BLOB_FS_PATH", "REDSIM_CONFIG"):
        assert forbidden not in spawn.env, f"{where}: {forbidden} reached the child environment"
    assert not any(key.startswith("PYTHIA_") for key in spawn.env), f"{where}: a PYTHIA_* variable reached the child"
    assert spawn.env.get("REDSIM_DISABLE_LLM") == "1", f"{where}: the child does not pin REDSIM_DISABLE_LLM=1"
    # The request file names the broker socket and the host, never the URL, the token or the profile secret.
    assert spawn.request_text is not None and spawn.request is not None, f"{where}: no request file was read"
    assert TOKEN not in spawn.request_text, f"{where}: the credential is in the child request file"
    for value in PARENT_SENTINELS.values():
        assert value not in spawn.request_text, f"{where}: a parent secret is in the child request file"
    spec = spawn.request.get("target_endpoint")
    assert isinstance(spec, dict), f"{where}: request.json carries no target_endpoint block"
    assert "url" not in spec and "secret" not in spec and "auth" not in spec, f"{where}: {sorted(spec)}"
    assert str(spec.get("socket", "")).endswith(".sock"), f"{where}: the child is not pointed at a broker socket"
    assert spec.get("url_host") and spec.get("scheme") == "http", spec
    assert "/predict" not in spawn.request_text, f"{where}: the URL path is in the child request file"


# ---------------------------------------------------------------------------
# Module fixtures: the tiny endpoint, the environment, the credential, the registered target
# ---------------------------------------------------------------------------


@dataclass
class EndpointLab:
    """The tiny server, the spy, the environment patch and the harness handles the tests share."""

    server: Any
    spy: SandboxSpy
    patch: pytest.MonkeyPatch
    manifest: dict[str, Any]

    @property
    def url(self) -> str:
        return str(self.server.url)

    @property
    def host(self) -> str:
        return _host_of(self.url)

    @property
    def class_names(self) -> list[str]:
        return list(self.manifest["datasets"][h.IMAGE_DATASET_ID]["class_names"])

    @property
    def dataset_split(self) -> str:
        return str(self.manifest["models"][h.IMAGE_MODEL_ID]["dataset_split"])

    def registration(self, **overrides: Any) -> dict[str, Any]:
        """The ``POST /v1/models`` body for the tiny server bound to the harness image split."""
        body: dict[str, Any] = {
            "source": "endpoint", "project_id": h.PROJECT_ID, "url": self.url,
            "modality": "image", "dataset_id": h.IMAGE_DATASET_ID, "dataset_split": self.dataset_split,
            "name": "e2e tiny endpoint (TinyTarget test double)",
            "license_statement": "non-operational evaluation instance of a test double; harness-owned",
            "evaluation_instance_attestation": True,
            "input_shape": [3, h.IMAGE_SIZE, h.IMAGE_SIZE], "class_names": self.class_names,
            "batch_rows": 64, "timeout_s": 10,
        }
        for key, value in overrides.items():
            if value is None:
                body.pop(key, None)
            else:
                body[key] = value
        return body


@pytest.fixture(scope="module")
def lab(e2e_app: E2EApp, e2e_org: E2EOrg, e2e_assets: Path) -> Iterator[EndpointLab]:
    """The tiny endpoint server, the sandbox spy and the environment this file needs, undone at module end."""
    pytest.importorskip("cryptography")
    from cryptography.fernet import Fernet

    from tests.ml.tiny_endpoint_server import TinyEndpointServer

    patch = pytest.MonkeyPatch()
    # The AuthProfile vault key (spec 21.7): set for the API and the worker (one process here); the child never sees it.
    patch.setenv("REDSIM_AUTH_PROFILES_KEY", Fernet.generate_key().decode())
    patch.delenv("REDSIM_AUTH_PROFILES_KEY_PREVIOUS", raising=False)
    patch.setenv("REDSIM_ML_ENDPOINT_RPS", BROKER_RPS)
    for name, value in PARENT_SENTINELS.items():
        patch.setenv(name, value)
    spy = SandboxSpy()
    spy.install(patch)
    server = TinyEndpointServer(token=TOKEN)
    server.start()
    try:
        yield EndpointLab(server=server, spy=spy, patch=patch, manifest=h.asset_manifest(e2e_assets))
    finally:
        server.stop()
        patch.undo()


@pytest.fixture(scope="module")
def auth_profile_id(lab: EndpointLab, e2e_org: E2EOrg) -> str:
    """The bearer ``AuthProfile`` holding the endpoint credential, created through the API by the admin."""
    admin = e2e_org.client("admin")
    body = {"project_id": h.PROJECT_ID, "name": f"e2e-endpoint-{uuid4().hex[:8]}", "kind": "bearer",
            "config": {}, "secret": TOKEN}
    # auth_profile.manage is admin-only (spec 7.3): the remediator cannot create the credential.
    assert e2e_org.client("remediator").post("/v1/auth-profiles", json=body).status_code == 403
    created = admin.post("/v1/auth-profiles", json=body)
    assert created.status_code == 201, created.text
    row = created.json()
    assert_secret_free(row, where="POST /v1/auth-profiles response", forbid_url_path=False)
    listed = admin.get("/v1/auth-profiles", params={"project": h.PROJECT_ID})
    assert listed.status_code == 200 and TOKEN not in listed.text, "the vault never returns a secret"
    return str(row["id"])


@dataclass
class RegisteredEndpoint:
    """What registering the tiny server left behind."""

    model_id: str
    ingest_run_id: str
    ingest_job_id: str
    registration: dict[str, Any]
    ingest_run: dict[str, Any]
    model: dict[str, Any]
    server_requests_before: int


def require_available(endpoint_model: RegisteredEndpoint) -> None:
    """Fail, attributed to the product seam, when the eager validate job did not reach ``available``.

    On a tree where ``redsim.ml.endpoint_broker.build_predict_body`` still emits the pre-B0 body
    (``{contract, inputs, encoding}``) while the module resolves the B0
    ``redsim.ml.targets.endpoint_contract.PredictRequest`` (``input_format`` required, extras
    forbidden), every real probe fails inside the broker and no endpoint can become available;
    the tests that need an available target fail here with that attribution rather than on a
    secondary assertion. Nothing is worked around.
    """
    model = endpoint_model.model
    if endpoint_model.ingest_run["status"] != "succeeded":
        pytest.fail(f"redsim/workers/tasks/ml_model.py::ml_model_validate: the ml.ingest run "
                    f"{endpoint_model.ingest_run_id} ended {endpoint_model.ingest_run['status']!r}: "
                    f"{endpoint_model.ingest_run.get('stage_table')}")
    if model["status"] == "available":
        return
    probe = dict((model.get("endpoint") or {}).get("probe") or {})
    reason = str(probe.get("reason") or model.get("reason") or "")
    outcome = f"the target is {model['status']!r} ({model.get('refusal_reason')}). Probe: {reason[:400]!r}"
    if probe.get("error_class") == "EndpointError" and "PredictRequest" in reason:
        pytest.fail(
            "redsim/ml/endpoint_broker.py:179 build_predict_body sends {contract, inputs, encoding='list'} while "
            "redsim/ml/endpoint_broker.py:173 resolves PredictRequest to the B0 contract "
            "(redsim/ml/targets/endpoint_contract.py:268: input_format required, extras forbidden); the broker "
            f"cannot speak the endpoint-v1 request body, so no probe reaches the endpoint and {outcome}"
        )
    if "outside [0, 1]" in reason:
        pytest.fail(
            "redsim/ml/targets/endpoint.py:228 EndpointTarget.load sends x[probe_idx] as float32 without the "
            "as_model_input scaling that sample() applies (redsim/ml/datasets/sampling.py:93), so a uint8 image "
            "split (every bundled split: pixel values 0-255) yields probe rows the endpoint-v1 contract refuses "
            f"(redsim/ml/targets/endpoint_contract.py:247 unit interval); {outcome}"
        )
    if "requires an endpoint block" in reason:
        pytest.fail(
            "redsim/ml/targets/endpoint.py:248 EndpointTarget.load builds its manifest with format='endpoint' and no "
            "endpoint block, which the B0 MLModelManifest validator refuses (redsim/ml/schema.py:764); the probe "
            f"succeeded but the child cannot form the manifest and {outcome}"
        )
    pytest.fail(f"redsim/workers/tasks/ml_model.py::_validate_endpoint: {outcome}; probe={probe}")


@pytest.fixture(scope="module")
def endpoint_model(lab: EndpointLab, e2e_org: E2EOrg, auth_profile_id: str) -> RegisteredEndpoint:
    """The tiny server registered by the admin and validated by the eager ``model.validate`` job."""
    admin = e2e_org.client("admin")
    requests_before = lab.server.n_requests
    response = admin.post("/v1/models", json=lab.registration(auth_profile_id=auth_profile_id))
    assert response.status_code == 201, response.text
    registration = response.json()
    model_id = str(registration["id"])
    ingest_run_id = str(registration["ingest_run_id"])
    ingest_run = h.wait_for_run(admin, ingest_run_id)
    model = h.model_record(admin, model_id)
    return RegisteredEndpoint(
        model_id=model_id, ingest_run_id=ingest_run_id, ingest_job_id=str(registration["ingest_job_id"]),
        registration=registration, ingest_run=ingest_run, model=model, server_requests_before=requests_before,
    )


# ---------------------------------------------------------------------------
# 1. Registration: RBAC and the static refusals
# ---------------------------------------------------------------------------


def test_registration_rbac_and_static_refusals(
    lab: EndpointLab, e2e_app: E2EApp, e2e_org: E2EOrg, auth_profile_id: str,
) -> None:
    from redsim.api.errors import ENDPOINT_NOT_ALLOWLISTED, ENDPOINT_URL_INVALID

    project_chain = f"project:{h.PROJECT_ID}"
    body = lab.registration(auth_profile_id=auth_profile_id)
    targets_before, runs_before = _count_targets(e2e_app), _count_runs(e2e_app)
    events_before = len(e2e_app.read_chain(project_chain))
    success_rows_before = len([ev for ev in _events(e2e_app, project_chain, "model.register") if ev["success"]])

    # -- spec 7.3 / 7.4, ENDPOINT-20 (26.4 item 21): registering a host to query is target.manage (admin) ----
    denied = {
        "viewer": e2e_org.client("viewer").post("/v1/models", json=body),
        "scanner": e2e_org.client("scanner").post("/v1/models", json=body),
        "remediator": e2e_org.client("remediator").post("/v1/models", json=body),
        "approver": e2e_org.client("approver").post("/v1/models", json=body),
        "outsider (admin of the other org)": e2e_org.client(h.OUTSIDER).post("/v1/models", json=body),
        "stranger (no membership)": e2e_org.client(h.STRANGER).post("/v1/models", json=body),
    }
    wrong = {who: (r.status_code, r.text[:160]) for who, r in denied.items() if r.status_code != 403}
    assert not wrong, f"spec 7.3 gates endpoint registration at admin; these callers were not refused:\n{wrong}"
    for who, response in denied.items():
        assert isinstance(response.json()["detail"], str), f"{who}: a role refusal is the plain forbidden detail"
        assert TOKEN not in response.text
    # A role refusal is decided before the admission service runs: no Target, no Run, no audit row (spec 7.8).
    assert _count_targets(e2e_app) == targets_before and _count_runs(e2e_app) == runs_before
    assert len(e2e_app.read_chain(project_chain)) == events_before
    assert lab.server.n_requests == 0, "nothing contacted the endpoint from the API process"

    admin = e2e_org.client("admin")

    # -- spec 17.3 endpoint_url_invalid, 21.7 (ENDPOINT-07): userinfo in the URL is refused before anything else
    port = lab.url.split(":")[-1].split("/")[0]
    userinfo_url = f"http://user:pw@127.0.0.1:{port}/predict"
    refused = admin.post("/v1/models", json=lab.registration(auth_profile_id=auth_profile_id, url=userinfo_url))
    assert refused.status_code == 422, refused.text
    detail = refused.json()["detail"]
    assert detail["code"] == ENDPOINT_URL_INVALID and detail["field"] == "url", detail
    assert "user:pw" not in refused.text and ":pw@" not in refused.text, "the userinfo never comes back"
    rows = [ev for ev in _events(e2e_app, project_chain, "model.register") if not ev["success"]]
    assert rows and rows[-1]["detail"]["reason"] == ENDPOINT_URL_INVALID and rows[-1]["detail"]["field"] == "url"
    assert rows[-1]["actor"] == e2e_org.actor("admin") and rows[-1]["detail"]["source"] == "endpoint"
    assert rows[-1]["target"] is None and rows[-1]["allowlist_check"] == "n/a"
    assert "pw" not in json.dumps(rows[-1]["detail"]).replace("password", ""), "userinfo never reaches the chain"
    assert_secret_free(rows[-1]["detail"], where="refused model.register row (userinfo)")

    # -- spec 17.3 endpoint_not_allowlisted, 21.7 (ENDPOINT-07 rule a): a host outside target_allowlist is 403 --
    outside = "https://models.example.invalid/predict"
    refused = admin.post("/v1/models", json=lab.registration(auth_profile_id=auth_profile_id, url=outside))
    assert refused.status_code == 403, refused.text
    detail = refused.json()["detail"]
    assert detail["code"] == ENDPOINT_NOT_ALLOWLISTED and detail["field"] == "url", detail
    assert detail.get("host") == "models.example.invalid"
    rows = [ev for ev in _events(e2e_app, project_chain, "model.register") if not ev["success"]]
    assert rows[-1]["detail"]["reason"] == ENDPOINT_NOT_ALLOWLISTED and rows[-1]["detail"]["host"] == "models.example.invalid"
    # Like every allowlist refusal: the refused URL is the row's target and the verdict is on the row.
    assert rows[-1]["target"] == outside and rows[-1]["allowlist_check"] == "fail"
    assert rows[-1]["detail"]["rule"] == "not_allowlisted"

    # Neither refusal created a row or queried anything (spec 9.3 step 2).
    assert _count_targets(e2e_app) == targets_before and _count_runs(e2e_app) == runs_before
    assert len([ev for ev in _events(e2e_app, project_chain, "model.register") if ev["success"]]) == success_rows_before
    assert lab.server.n_requests == 0
    assert lab.spy.spawns == [], "no sandbox child was spawned for a refused registration"


# ---------------------------------------------------------------------------
# 2. Registration to available through the broker
# ---------------------------------------------------------------------------


def test_registration_validates_through_the_broker_to_available(
    lab: EndpointLab, e2e_app: E2EApp, e2e_org: E2EOrg, auth_profile_id: str, endpoint_model: RegisteredEndpoint,
) -> None:
    reg = endpoint_model.registration
    # -- spec 17.2 POST /v1/models source=endpoint (ENDPOINT-01): 201, validating, gradients false, host only ---
    assert reg["source"] == "endpoint" and reg["format"] == "endpoint" and reg["status"] == "validating"
    assert reg["modality"] == "image" and reg["gradients"] is False and reg["registered"] is True
    assert reg["endpoint"]["host"] == lab.host and reg["endpoint"]["auth_profile_id"] == auth_profile_id
    assert reg["endpoint"]["auth_kind"] == "bearer" and reg["endpoint"]["plaintext"] is True
    assert reg["endpoint"]["verified"] is False, "ownership verification is not built (ENDPOINT-26 option a)"
    assert reg["endpoint"]["fingerprint_sha256"] is None, "no fingerprint before the endpoint answered"
    assert reg["enqueued"] is True
    assert_secret_free(reg, where="registration response")

    # -- spec 9.3 step 6 / ENDPOINT-09: the eager validate job probed the endpoint and marked it available -----
    require_available(endpoint_model)
    model = endpoint_model.model
    assert model["gradients"] is False, "an endpoint exposes predictions only (spec 9.5)"
    endpoint = model["endpoint"]
    assert isinstance(endpoint["fingerprint_sha256"], str) and _HEX64.match(endpoint["fingerprint_sha256"]), endpoint
    assert endpoint["fingerprint_label"] and "weights" in endpoint["fingerprint_label"], (
        "the fingerprint is labelled remote model identity, not a weights digest (ENDPOINT-27)")
    assert endpoint["output_kind"] == "probabilities"
    assert endpoint["probe"]["http_status"] == 200 and endpoint["probe"]["n_rows"] == 8, endpoint["probe"]
    assert endpoint["probe"]["tls_mode"] == "plaintext", "http to loopback is recorded as plaintext (rule c)"
    validation = model["validation"]
    assert validation["detected_format"] == "endpoint" and validation["gradients"] is False
    # Agreement is between two loaders of the same bytes: not applicable to an endpoint and never invented.
    assert validation["onnx_torch_argmax_agreement"] is None and validation["onnx_conversion"] is None
    assert validation["probe"]["fingerprint_sha256"] == endpoint["fingerprint_sha256"]
    assert validation["probe"]["host"] == lab.host and validation["probe"]["rows"] == 8
    # Spec 9.5 / 18.2: the black-box attack set only, read from the adapter capability tags.
    assert model["available_attacks"] == ["hopskipjump"], model["available_attacks"]
    assert model["manifest"]["endpoint"]["url_host"] == lab.host
    assert model["manifest"]["n_classes"] == len(lab.class_names) and model["manifest"]["class_names"] == lab.class_names
    assert model["campaign_history"] == []
    assert_secret_free(model, where="GET /v1/models/{id} after validation")

    # -- the endpoint saw exactly one authenticated probe of 8 rows: the credential came from the broker --------
    probes = lab.server.requests[endpoint_model.server_requests_before:]
    assert len(probes) == 1 and probes[0]["rows"] == 8 and probes[0]["status"] == 200, probes
    assert probes[0]["auth_ok"] is True, "the AuthProfile secret authenticated the probe"

    # -- ENDPOINT-22: the validate child held no credential and was pointed at the broker socket -------------
    children = lab.spy.validate_children()
    assert len(children) == 1, f"expected one validate child, saw {[c.mode for c in lab.spy.spawns]}"
    assert_child_boundary(children[0], where="validate child")
    assert children[0].request["target_endpoint"]["auth_profile_id"] == auth_profile_id

    # -- spec 26.5 item 22 / 5.11: the ingest chain is register, validate, complete; details are ids and counts -
    chain = e2e_app.read_chain(f"run:{endpoint_model.ingest_run_id}")
    assert [ev["action"] for ev in chain] == ["model.register", "model.validate", "job.complete"], chain
    register, validate, complete = chain
    assert register["actor"] == e2e_org.actor("admin") and register["success"] is True
    assert register["target"] == lab.url and register["allowlist_check"] == "pass", "the URL is the audited target"
    assert register["detail"]["host"] == lab.host and register["detail"]["auth_profile_id"] == auth_profile_id
    assert register["detail"]["descriptor_sha256"] == endpoint_model.registration["sha256"]
    assert register["detail"]["attestation"] == {"evaluation_instance": True}, "the D3 attestation is on the row"
    assert validate["success"] is True and validate["target"] == lab.url and validate["allowlist_check"] == "pass"
    assert validate["detail"]["status"] == "available" and validate["detail"]["gradients"] is False
    assert validate["detail"]["fingerprint_sha256"] == endpoint["fingerprint_sha256"]
    assert validate["detail"]["host"] == lab.host and validate["detail"]["rows"] == 8
    assert complete["success"] is True and complete["detail"]["validation_status"] == "available"
    assert complete["detail"]["counts"]["endpoint_rows"] == 8 and complete["detail"]["counts"]["endpoint_requests"] == 1
    for ev in chain:
        assert_secret_free(ev["detail"], where=f"{ev['action']} detail")
    # The job row names the profile by id only (spec 5.10, ENDPOINT-29).
    details = _job_details(e2e_app, endpoint_model.ingest_run_id)
    assert details and details[0]["auth_profile_id"] == auth_profile_id and details[0]["declared_format"] == "endpoint"
    for detail in details:
        assert_secret_free(detail, where="model.validate Job.detail")


# ---------------------------------------------------------------------------
# 3. A black-box campaign through the broker
# ---------------------------------------------------------------------------


def _campaign_config() -> dict[str, Any]:
    """HopSkipJump plus the benign control on the default L-inf grid; 12 samples; two explained inputs."""
    return {
        "attack_ids": ["hopskipjump"],
        "attack_params": {"hopskipjump": dict(HSJ_PARAMS)},
        "eps_grid": [0.01, 0.03, 0.1],
        "reference_eps": 0.03,
        "n_samples": 12,
        "seed": 0,
        "explain_k": 2,
        "include_control": True,
    }


def test_black_box_campaign_runs_through_the_broker(
    lab: EndpointLab, e2e_app: E2EApp, e2e_org: E2EOrg, auth_profile_id: str, endpoint_model: RegisteredEndpoint,
) -> None:
    require_available(endpoint_model)
    scanner = e2e_org.client("scanner")
    requests_before, rows_before = lab.server.n_requests, lab.server.rows_total
    children_before = len(lab.spy.campaign_children())

    # -- spec 7.3: attack.run stays scanner-level on an endpoint (ENDPOINT-20) -----------------------------------
    run = h.run_campaign_via_api(scanner, endpoint_model.model_id, _campaign_config(), timeout_s=60)
    if run.status != "succeeded" or run.campaign is None:
        pytest.fail(f"redsim/workers/tasks/ml_campaign.py: the endpoint campaign {run.run_id} ended {run.status!r} "
                    f"(campaign route: {run.campaign_status} {run.campaign_error}); stage_table={run.stage_table}")
    campaign = run.campaign
    assert campaign["status"] == "succeeded" and campaign["config"]["target_id"] == endpoint_model.model_id
    config = campaign["config"]
    assert config["attack_ids"] == ["hopskipjump"] and config["explain_k"] == 2 and config["n_samples"] == 12
    assert "eps" not in config["attack_params"].get("hopskipjump", {}), "grid-owned eps is never frozen (dd2bbd4)"

    # -- ENDPOINT-08 / -11: the frozen snapshot carries the redacted endpoint binding and the query budget -------
    snapshot = config["target_snapshot"]
    assert snapshot["kind"] == "ml_model_endpoint" and snapshot["value"] == f"endpoint:{lab.host}"
    budget = snapshot["endpoint"]["query_budget"]
    assert snapshot["endpoint"]["url_host"] == lab.host and snapshot["endpoint"]["auth_profile_id"] == auth_profile_id
    assert budget["estimated_rows"] <= budget["max_rows"], budget
    assert budget["attack_rows"]["hopskipjump"] > 0 and budget["eval_rows"] == 12 and budget["control_rows"] == 36
    assert "worst-case" in budget["estimate_kind"], "the admission estimate is labelled a bound, never a measurement"
    assert snapshot["endpoint"]["limits"]["rps"] == float(BROKER_RPS), "the limit in force is the recorded one"
    assert snapshot["endpoint"]["explain_k_requested"] == 2 and snapshot["endpoint"]["explain_caps"]["explain_k"] == 8
    assert_secret_free(snapshot, where="frozen target_snapshot")

    # -- spec 26.2 item 7: clean, evasion per eps and control per eps, every row with denominators -------------
    clean = _measurements(campaign, "clean")
    assert len(clean) == 1 and clean[0]["n"] == 12 and 0 <= clean[0]["n_correct"] <= clean[0]["n"], clean
    assert sum(c["n"] for c in clean[0]["per_class"].values()) == clean[0]["n"], "per-class counts sum to n"
    assert set(clean[0]["per_class"]) <= set(lab.class_names), sorted(clean[0]["per_class"])
    evasion = _measurements(campaign, "evasion", "hopskipjump")
    control = _measurements(campaign, "control")
    assert sorted(m["params"]["eps"] for m in evasion) == config["eps_grid"], [m["id"] for m in evasion]
    assert sorted(m["params"]["eps"] for m in control) == config["eps_grid"], [m["id"] for m in control]
    for row in evasion + control:
        assert row["n"] == 12 and 0 <= row["n_correct"] <= row["n"], row["id"]
        assert row["accuracy"] == pytest.approx(row["n_correct"] / row["n"]), row["id"]
    for row in evasion:
        # A black-box attack records how many predictions it spent (spec 12.9, ENDPOINT-05).
        assert row.get("queries_mean") is None or row["queries_mean"] >= 0, row["id"]

    # -- ENDPOINT-05 / -08: the parent-side broker tally on the record: rows, requests, purposes, the budget -----
    manifest = campaign["provenance"]["model_manifest"]
    broker = manifest.get("endpoint_broker")
    assert isinstance(broker, dict), "the worker parent's broker counters are on the record's provenance"
    assert broker["rows"] > 0 and broker["requests"] > 0 and broker["failures"] == 0, broker
    assert broker["rows"] <= broker["limits"]["max_rows"] and broker["requests"] <= broker["limits"]["max_requests"]
    # The budget the broker enforced is the budget admission froze (ENDPOINT-08: max rows, max requests, rate).
    assert broker["limits"]["rps"] == float(BROKER_RPS)
    assert broker["limits"]["max_rows"] == budget["max_rows"] and broker["limits"]["max_requests"] == budget["max_requests"]
    # Per-purpose split as the broker saw it: the 8-row load probe, then the campaign's predictions. (The
    # classification runner does not label attack / control / explain purposes on the transport, so the
    # broker's buckets are ``probe`` and ``predict``; nothing finer is claimed here.)
    by_purpose = broker["by_purpose"]
    assert by_purpose.get("probe") == {"requests": 1, "rows": 8}, by_purpose
    assert sum(bucket["rows"] for bucket in by_purpose.values()) == broker["rows"], by_purpose
    assert sum(bucket["requests"] for bucket in by_purpose.values()) == broker["requests"], by_purpose
    assert broker["rows"] > 8, "the campaign queried the endpoint beyond the load probe"
    assert isinstance(broker["fingerprint_sha256"], str) and _HEX64.match(broker["fingerprint_sha256"])
    assert broker["fingerprint_sha256"] == endpoint_model.model["endpoint"]["fingerprint_sha256"], (
        "the same seeded probe rows against the same endpoint answer with the same fingerprint (ENDPOINT-27)")
    assert manifest["gradients"] is False and manifest["format"] == "endpoint" and manifest["access"] == "black-box-endpoint"
    # The parent's broker counters are authoritative for what left the worker (ENDPOINT-05); the child's own
    # ``endpoint_queries`` is a client-side counter captured with the manifest at load time and never exceeds them.
    client_side = manifest.get("endpoint_queries")
    assert isinstance(client_side, dict) and 0 < client_side["rows"] <= broker["rows"], (client_side, broker["rows"])
    # ENDPOINT-08: the worst-case bound frozen at admission held for the measured traffic.
    assert broker["rows"] <= budget["estimated_rows"], (broker["rows"], budget)
    # What the endpoint actually received is what the broker says it sent (spec 12.9 query counts are measured).
    served = lab.server.requests[requests_before:]
    assert lab.server.rows_total - rows_before == broker["rows"], (served[:3], broker)
    assert len(served) == broker["requests"] + broker.get("retries", 0), (len(served), broker)
    assert all(r["auth_ok"] for r in served), "every request the endpoint saw carried the profile's credential"
    assert all(r["status"] == 200 for r in served)

    # -- spec 13.2 / 14.7: PartitionExplainer observations, or the honest ExplainerUnavailable state ------------
    observations = campaign["observations"]
    unavailable = [lim for lim in campaign["limitations"] if lim.startswith("Explain stage unavailable for 'hopskipjump'")]
    if observations:
        assert not unavailable
        for obs in observations:
            assert obs["metric_kind"] == "heuristic" and obs["artifacts"] and obs["artifact_sha256"], obs["id"]
        assert "Partition" in str(manifest.get("explainer")), manifest.get("explainer")
    else:
        assert unavailable, f"no observations and no ExplainerUnavailable limitation: {campaign['limitations']}"
        assert any(item["id"] == "i.explain.unavailable.hopskipjump" for item in campaign["interpretation"])

    # -- spec 15.4 (26.3 items 12 to 14): the scorecard is in exactly one honest state --------------------------
    score = campaign["score"]
    if score is None:
        status = campaign["score_status"]
        assert status["state"] in {"pending", "unavailable"} and status.get("reason"), status
        assert campaign["missing"], "a campaign without a score names what is missing"
    else:
        assert campaign["score_status"] is None
        assert score["eps_grid"] == config["eps_grid"] and score["reference_eps"] == 0.03
        assert score["attack_ids"] == ["hopskipjump"] and score["settings_hash"]
        assert score["inputs"], "the per-(attack, eps) input rows travel with the score"
        for row in score["inputs"]:
            assert row["n"] == 12 and row["attack_id"] == "hopskipjump", row
        if score["completeness"] == "complete":
            assert isinstance(score["mri"], int) and 0 <= score["mri"] <= 100
            assert all(score["subscores"][k] is not None for k in SUBSCORE_KEYS), score["subscores"]
            assert score["grade"] in {"A", "B", "C", "D", "F"} and score["reading"]
            assert not _READINESS_RE.search(score["reading"]), score["reading"]
            assert not score["missing"]
        else:
            assert score["completeness"] == "partial" and score["mri"] is None and score["grade"] is None
            assert score["missing"], "a partial score names the missing dimension"
            assert any(score["subscores"][k] is None for k in SUBSCORE_KEYS)
            if not observations:
                assert "S_expl" in score["missing"], score["missing"]
    assert campaign["limitations"], "limitations are non-empty on every succeeded run (26.2 item 9)"
    assert any("readiness" in lim.lower() for lim in campaign["limitations"]), (
        "the standing limitation that no result establishes safety or readiness is present (26.2 item 9)")
    assert any("endpoint" in lim.lower() for lim in campaign["limitations"]), "the remote-endpoint caveat is stated"

    # -- ENDPOINT-22: the campaign child held no credential; the socket, not the URL, is in its request ---------
    children = lab.spy.campaign_children()[children_before:]
    assert len(children) == 1, f"expected one campaign child, saw {len(children)}"
    assert_child_boundary(children[0], where="campaign child")
    assert children[0].request["target_endpoint"]["auth_profile_id"] == auth_profile_id
    assert children[0].request["target_endpoint"]["limits"]["rps"] == float(BROKER_RPS)

    # -- spec 10.5 / 26.5 item 22: the run chain, with the query counts and budget on the rows -----------------
    chain = e2e_app.read_chain(f"run:{run.run_id}")
    names = [ev["action"] for ev in chain]
    assert names[0] == "attack.run" and chain[0]["actor"] == e2e_org.actor("scanner") and chain[0]["success"] is True
    admission = chain[0]["detail"]
    assert admission["endpoint"]["url_host"] == lab.host and admission["endpoint"]["auth_profile_id"] == auth_profile_id
    by_action = {ev["action"]: ev for ev in chain}
    assert by_action["model.load"]["success"] is True and by_action["model.load"]["detail"]["source"] == "endpoint"
    assert by_action["model.load"]["detail"]["gradients"] is False
    execute = by_action["attack.execute.hopskipjump"]
    assert execute["success"] is True and execute["detail"]["executed"] is True
    assert execute["detail"]["endpoint"]["rows"] == broker["rows"] and execute["detail"]["endpoint"]["requests"] == broker["requests"]
    assert execute["detail"]["endpoint"]["budget"]["max_rows"] == broker["limits"]["max_rows"]
    assert execute["detail"]["endpoint"]["by_purpose"] == broker["by_purpose"]
    assert "explain.execute" in by_action
    if score is not None:
        score_row = by_action["campaign.score"]["detail"]
        assert score_row["mri"] == score["mri"] and score_row["completeness"] == score["completeness"]
        assert score_row["endpoint"]["rows"] == broker["rows"]
    complete = by_action["job.complete"]
    assert complete["success"] is True and complete["detail"]["status"] == "succeeded"
    assert complete["detail"]["endpoint"]["rows"] == broker["rows"]
    for ev in chain:
        assert ev["actor"].startswith(("user:", "worker:")), ev
        assert_secret_free(ev["detail"], where=f"{ev['action']} detail on run:{run.run_id}")
    assert "/predict" not in json.dumps([ev["detail"] for ev in chain]), "rows carry the host, never the URL path"

    # -- spec 5.10 / 21.8: Job.detail, the record and the report carry ids and digests, never the credential ----
    for detail in _job_details(e2e_app, run.run_id):
        assert_secret_free(detail, where="attack.run Job.detail")
        assert detail["campaign_config"]["target_snapshot"]["value"] == f"endpoint:{lab.host}"
    assert_secret_free(campaign, where="GET /v1/runs/{id}/campaign body")
    report = scanner.get(f"/v1/runs/{run.run_id}/report.md")
    assert report.status_code == 200, report.text[:200]
    assert TOKEN not in report.text and "/predict" not in report.text
    for value in PARENT_SENTINELS.values():
        assert value not in report.text
    history = h.model_record(e2e_org.client("admin"), endpoint_model.model_id)["campaign_history"]
    assert any(item["run_id"] == run.run_id for item in history), history


# ---------------------------------------------------------------------------
# 4. White-box attacks are refused, never substituted
# ---------------------------------------------------------------------------


def test_white_box_attack_is_refused(
    lab: EndpointLab, e2e_app: E2EApp, e2e_org: E2EOrg, endpoint_model: RegisteredEndpoint,
) -> None:
    from redsim.api.errors import ATTACK_REQUIRES_GRADIENTS

    require_available(endpoint_model)
    scanner = e2e_org.client("scanner")
    project_chain = f"project:{h.PROJECT_ID}"
    runs_before = _count_runs(e2e_app)
    refused_before = len([ev for ev in _events(e2e_app, project_chain, "attack.run") if not ev["success"]])
    requests_before = lab.server.n_requests
    manifest = endpoint_model.model["manifest"]

    for attack_id in ("fgsm", "pgd"):
        body = {**_campaign_config(), "attack_ids": [attack_id], "attack_params": {},
                "dataset_id": manifest["dataset_id"], "dataset_revision": manifest["dataset_revision"]}
        # spec 9.5 / 17.3 (ENDPOINT-11): predictions only, no surrogate; the white-box attack is refused 422,
        # never downgraded to a black-box one.
        refused = scanner.post(f"/v1/models/{endpoint_model.model_id}/attacks", json=body)
        assert refused.status_code == 422, f"{attack_id}: {refused.text}"
        detail = refused.json()["detail"]
        assert detail["code"] == ATTACK_REQUIRES_GRADIENTS, detail
        assert "endpoint" in detail["message"].lower() or "gradients" in detail["message"].lower()
        assert_secret_free(detail, where=f"{attack_id} refusal detail")
    refused_rows = [ev for ev in _events(e2e_app, project_chain, "attack.run") if not ev["success"]]
    assert len(refused_rows) == refused_before + 2, "each refused admission is a success=False row (spec 5.11)"
    for ev in refused_rows[-2:]:
        assert ev["actor"] == e2e_org.actor("scanner") and ev["detail"]["target_id"] == endpoint_model.model_id
        assert_secret_free(ev["detail"], where="refused attack.run detail")
    assert _count_runs(e2e_app) == runs_before, "no Run is created for a refused campaign"
    assert lab.server.n_requests == requests_before, "a refused admission never queries the endpoint"


# ---------------------------------------------------------------------------
# 5. Delete is audited; the chains verify through the real CLI
# ---------------------------------------------------------------------------


def test_endpoint_delete_is_audited_and_chains_verify(
    lab: EndpointLab, e2e_app: E2EApp, e2e_org: E2EOrg, auth_profile_id: str, endpoint_model: RegisteredEndpoint,
    audit_verify_all: Callable[[], tuple[int, str]],
) -> None:
    from redsim.audit.chain import verify_chain

    admin, remediator = e2e_org.client("admin"), e2e_org.client("remediator")
    project_chain = f"project:{h.PROJECT_ID}"
    ingest_chain = f"run:{endpoint_model.ingest_run_id}"
    campaign_chains = [f"run:{item['run_id']}" for item in h.model_record(admin, endpoint_model.model_id)["campaign_history"]]

    # -- spec 26.5 item 22: redsim audit verify --all (the real CLI) over the connector's chains -----------------
    # A sibling module may have tampered with its own chain and left it; the CLI must name exactly those.
    pre_broken = {cid for cid in e2e_app.chain_ids() if not verify_chain(e2e_app.read_chain(cid)).verified}
    assert ingest_chain not in pre_broken and not (set(campaign_chains) & pre_broken)
    code, output = audit_verify_all()
    verified, broken = _verified_and_broken(output)
    assert set(broken) == pre_broken, output
    assert (code == 0) == (not pre_broken), f"exit {code}:\n{output}"
    assert ingest_chain in verified and set(campaign_chains) <= verified and project_chain in verified, output

    # -- spec 7.3 target.manage (admin): a remediator cannot delete the endpoint target ---------------------------
    # (The delete semantics do not depend on the validation outcome; the status is read, never assumed.)
    status_before = h.model_record(admin, endpoint_model.model_id)["status"]
    assert remediator.delete(f"/v1/models/{endpoint_model.model_id}").status_code == 403
    assert h.model_record(admin, endpoint_model.model_id)["status"] == status_before

    # -- ENDPOINT-18: while the endpoint target is live its credential profile cannot be deleted, so a queued
    #    campaign can never resolve a dangling credential: 409 auth_profile_in_use naming the target, a
    #    success=False auth_profile.delete row on the project chain, the profile still listed -------------------
    profile_deletes_before = len(_events(e2e_app, project_chain, "auth_profile.delete"))
    in_use = admin.delete(f"/v1/auth-profiles/{auth_profile_id}")
    assert in_use.status_code == 409, in_use.text
    in_use_detail = in_use.json()["detail"]
    assert in_use_detail["code"] == "auth_profile_in_use" and in_use_detail["message"]
    assert endpoint_model.model_id in in_use_detail["target_ids"], in_use_detail
    assert_secret_free(in_use_detail, where="auth_profile_in_use envelope", forbid_url_path=False)
    profile_deletes = _events(e2e_app, project_chain, "auth_profile.delete")
    assert len(profile_deletes) == profile_deletes_before + 1 and profile_deletes[-1]["success"] is False
    assert profile_deletes[-1]["detail"]["refusal"] == "auth_profile_in_use"
    assert endpoint_model.model_id in profile_deletes[-1]["detail"]["target_ids"]
    assert profile_deletes[-1]["actor"] == e2e_org.actor("admin") and TOKEN not in json.dumps(profile_deletes[-1])
    still_listed = admin.get("/v1/auth-profiles", params={"project": h.PROJECT_ID}).json()["auth_profiles"]
    assert auth_profile_id in {row["id"] for row in still_listed}, "a refused delete keeps the row"
    # The viewer is refused by the policy layer before the in-use check and writes nothing.
    assert e2e_org.client("viewer").delete(f"/v1/auth-profiles/{auth_profile_id}").status_code == 403
    assert len(_events(e2e_app, project_chain, "auth_profile.delete")) == profile_deletes_before + 1

    # -- ENDPOINT-18: the admin's delete is audited with the host; the credential stays with its profile -------
    requests_before = lab.server.n_requests
    manage_before = len(_events(e2e_app, project_chain, "target.manage"))
    deleted = admin.delete(f"/v1/models/{endpoint_model.model_id}")
    assert deleted.status_code == 200, deleted.text
    assert deleted.json() == {"deleted": endpoint_model.model_id, "status": "deleted", "blob_deleted": None}, (
        "an endpoint has no blob: nothing is deleted from the store and the row says so")
    manage = _events(e2e_app, project_chain, "target.manage")
    assert len(manage) == manage_before + 1 and manage[-1]["success"] is True
    detail = manage[-1]["detail"]
    assert manage[-1]["actor"] == e2e_org.actor("admin") and detail["target_id"] == endpoint_model.model_id
    assert detail["op"] == "delete" and detail["kind"] == "ml_model_endpoint" and detail["source"] == "endpoint"
    assert detail["host"] == lab.host and detail["auth_profile_id"] == auth_profile_id
    assert detail["previous_status"] == status_before
    assert_secret_free(detail, where="target.manage detail")
    assert lab.server.n_requests == requests_before, "deleting the target never queries the endpoint"
    # Soft delete: the catalog hides it, the id answers 404, the campaign rows are retained.
    gone = admin.get(f"/v1/models/{endpoint_model.model_id}", params={"project": h.PROJECT_ID})
    assert gone.status_code == 404, gone.text
    listing = admin.get("/v1/models", params={"project": h.PROJECT_ID}).json()["models"]
    assert endpoint_model.model_id not in {row["id"] for row in listing}
    for chain_id in campaign_chains:
        assert admin.get(f"/v1/runs/{chain_id.removeprefix('run:')}").status_code == 200
    profiles = admin.get("/v1/auth-profiles", params={"project": h.PROJECT_ID}).json()["auth_profiles"]
    assert auth_profile_id in {row["id"] for row in profiles}, "the AuthProfile outlives the target (ENDPOINT-18)"
    assert TOKEN not in json.dumps(profiles)

    # -- with no live target referencing it, the admin deletes the profile: 204 and its own success row --------
    released = admin.delete(f"/v1/auth-profiles/{auth_profile_id}")
    assert released.status_code == 204, released.text
    profile_deletes = _events(e2e_app, project_chain, "auth_profile.delete")
    assert len(profile_deletes) == profile_deletes_before + 2 and profile_deletes[-1]["success"] is True
    assert profile_deletes[-1]["detail"]["profile_id"] == auth_profile_id and TOKEN not in json.dumps(profile_deletes[-1])
    remaining = admin.get("/v1/auth-profiles", params={"project": h.PROJECT_ID}).json()["auth_profiles"]
    assert auth_profile_id not in {row["id"] for row in remaining}
    assert admin.delete(f"/v1/auth-profiles/{auth_profile_id}").status_code == 404

    # -- and the chains, including the new rows, still verify ---------------------------------------------------
    code, output = audit_verify_all()
    verified, broken = _verified_and_broken(output)
    assert set(broken) == pre_broken and (code == 0) == (not pre_broken), output
    assert project_chain in verified and ingest_chain in verified and set(campaign_chains) <= verified

    # -- no chain of this module carries the credential or a parent secret -------------------------------------
    everything = [ev for cid in e2e_app.chain_ids() for ev in e2e_app.read_chain(cid)]
    dump = json.dumps(everything, default=str)
    assert TOKEN not in dump, "the endpoint credential reached an audit row"
    for name, value in PARENT_SENTINELS.items():
        assert value not in dump, f"{name} reached an audit row"
