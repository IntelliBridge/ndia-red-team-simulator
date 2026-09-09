"""Phase B admission (wave B2 admission-phase-b): modalities, norms, endpoint rules, project scoring.

Register rows MODALITIES-06..08 (``SUPPORTED_MODALITIES``, the norm-to-modality
check, per-modality default grids and the detection ``n_samples`` cap),
ATTACKS_HARDEN-03 (an attack may only run under a norm it declares), the
endpoint admission rules (white-box refused with ``attack_requires_gradients``,
``explain_k`` capped through ``EXPLAIN_QUERY_CAPS``, the worst-case query budget
recorded in the frozen snapshot and compared with the per-job cap, no URL or
credential in the snapshot) and REVIEW_REPORTS-29 (the project's ``ml_scoring``
override frozen at admission, a client-sent ``scoring`` refused, reruns and
verify runs keeping their lineage's block).

Offline, on the sqlite harness of ``tests/ml/test_campaign_routes.py``: the real
FastAPI app, a recording audit writer and a fake ``ml_campaign_run.delay``.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from redsim.api.errors import HTTP_STATUS, PARAMS_OUT_OF_RANGE, ApiError
from redsim.config import RedsimConfig
from redsim.db.models import Job, Project, Target
from redsim.ml.attacks import ATTACKS, attack_norms, get_attack
from redsim.ml.attacks import KNOWN_NORMS as REGISTRY_KNOWN_NORMS
from redsim.ml.attacks import dpatch as dpatch_module
from redsim.ml.attacks import word_substitution as ws_module
from redsim.ml.explain.base import EXPLAIN_QUERY_CAPS, estimate_kernel_explain_rows
from redsim.ml.schema import CampaignConfig, MRIWeights, ScoringConfig
from redsim.ml.scoring import (
    DEFAULT_EPS_GRID_L2,
    DEFAULT_EPS_GRID_LINF,
    DEFAULT_REFERENCE_EPS,
    default_reference_eps,
)
from redsim.services import ml_campaigns
from redsim.services.ml_campaigns import (
    BUDGET_LABELS,
    DEFAULT_EDIT_GRID,
    DEFAULT_EDIT_REFERENCE,
    DEFAULT_PATCH_AREA_GRID,
    DEFAULT_PATCH_AREA_REFERENCE,
    DETECTION_N_SAMPLES_CAP,
    DETECTION_N_SAMPLES_DEFAULT,
    KNOWN_NORMS,
    NOT_IMPLEMENTED_MODALITIES,
    SUPPORTED_MODALITIES,
    check_norm_for_modality,
    create_attack_campaign,
    default_eps_grid_for,
    default_reference_eps_for,
    is_default_weights,
    modality_norms,
)
from tests.ml.test_admission import seed_verify_baseline
from tests.ml.test_campaign_routes import (
    ACTOR,
    DATASET,
    DATASET_REVISION,
    MODEL,
    PROJECT,
    SHA256,
    Harness,
    assert_refused,
    build_harness,
    launch,
    parent_config,
    seed_campaign_run,
    seed_model,
)

pytestmark = pytest.mark.integration

ENDPOINT_MODEL = "model-endpoint-1"
ENDPOINT_HOST = "127.0.0.1:8443"
#: Low-entropy fake secret: only its absence from every frozen or audited row is asserted.
FAKE_TOKEN = "fake-token-not-a-secret"
CUSTOM_WEIGHTS = {"acc": 0.5, "asr": 0.2, "eps": 0.1, "conf": 0.1, "expl": 0.1}


@pytest.fixture
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Harness]:
    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    yield build_harness(tmp_path, monkeypatch, with_api=True)
    rl._BUCKETS.clear()


def frozen_config(harness: Harness, response: Any) -> dict[str, Any]:
    assert response.status_code == 202, response.text
    with harness.Session() as session:
        job = session.get(Job, response.json()["job_ids"][0])
    assert job is not None
    return dict(job.detail["campaign_config"])


def set_project_scoring(harness: Harness, block: dict[str, Any] | None) -> None:
    with harness.Session.begin() as session:
        project = session.get(Project, PROJECT)
        assert project is not None
        project.ml_scoring = block


def seed_endpoint(
    harness: Harness, model_id: str = ENDPOINT_MODEL, *, modality: str = "image",
    limits: dict[str, Any] | None = None, with_binding: bool = True, surrogate: bool = False,
    batch_rows: int | None = 32,
) -> str:
    """An endpoint target the way the endpoint registration route leaves it: status from the probe, an
    ``EndpointSpec`` block with the host only, and (deliberately, for the redaction test) a URL and a
    credential-shaped key on the row that must never reach a frozen snapshot."""
    endpoint: dict[str, Any] = {
        "url_host": ENDPOINT_HOST, "auth_profile_id": "ap-1", "contract_version": "endpoint-v1",
        "input_shape": [3, 32, 32] if modality == "image" else [16], "timeout_s": 30.0,
    }
    if batch_rows is not None:
        endpoint["batch_rows"] = batch_rows
    if limits is not None:
        endpoint["limits"] = dict(limits)
    manifest: dict[str, Any] = {
        "sha256": SHA256, "modality": modality, "name": "seeded endpoint", "format": "endpoint",
        "dataset_id": DATASET, "dataset_revision": DATASET_REVISION, "gradients": False, "status": "available",
    }
    if with_binding:
        manifest["endpoint"] = dict(endpoint)
    detail: dict[str, Any] = {
        **manifest, "source": "endpoint", "manifest": dict(manifest),
        "url": f"https://{ENDPOINT_HOST}/predict", "auth": {"kind": "bearer", "token": FAKE_TOKEN},
    }
    if surrogate:
        detail["surrogate"] = {"kind": "resnet18", "sha256": "cd" * 32}
    with harness.Session.begin() as session:
        session.add(Target(id=model_id, project_id=PROJECT, kind="ml_model_endpoint",
                           value=f"https://{ENDPOINT_HOST}/predict", verified=True, detail=detail))
    return model_id


def _walk(value: Any) -> Iterator[Any]:
    yield value
    if isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from _walk(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v)


def assert_no_secret_or_url(blob: Any) -> None:
    leaves = [leaf for leaf in _walk(blob) if isinstance(leaf, str)]
    assert not any(FAKE_TOKEN in leaf for leaf in leaves), "credential leaked"
    assert not any("https://" in leaf or "/predict" in leaf for leaf in leaves), "URL leaked"


# --------------------------------------------------------------------------- the table (MODALITIES-06, -08)

def test_supported_modalities_cover_the_final_attack_registry() -> None:
    """The admission tables against the registry wave B1 left (ten adapters; ATTACKS_HARDEN-03, MODALITIES-06).

    Admission decides norms with the registry's own predicate (``attack_supports_norm``), so the table and
    the adapters' declarations must agree: every norm an adapter declares belongs to a modality it applies
    to, every modality's default norm has at least one evasion adapter that takes it, and the text and
    detection adapters are evaluated under their own budget only.
    """
    from redsim.ml.attacks import (
        ATTACKS,
        REGISTERED_IDS,
        attack_capabilities,
        attack_norms,
        attack_supports_norm,
        get_attack,
    )

    assert tuple(ATTACKS.ids()) == REGISTERED_IDS and len(REGISTERED_IDS) == 10
    for adapter in ATTACKS:
        tags = attack_capabilities(adapter)
        modalities = {tag.removeprefix("modality:") for tag in tags if tag.startswith("modality:")}
        assert modalities and modalities <= set(SUPPORTED_MODALITIES), (adapter.id, sorted(modalities))
        allowed = {norm for m in modalities for norm in SUPPORTED_MODALITIES[m].norms}
        norms = attack_norms(adapter)
        assert norms and norms <= allowed, (adapter.id, sorted(norms), sorted(allowed))
        for norm in KNOWN_NORMS:
            assert attack_supports_norm(adapter, norm) is (norm in norms), (adapter.id, norm)
    for modality, spec in SUPPORTED_MODALITIES.items():
        capable = sorted(
            a.id for a in ATTACKS
            if a.info().family == "evasion" and f"modality:{modality}" in attack_capabilities(a)
            and attack_supports_norm(a, spec.default_norm)
        )
        assert capable, f"no evasion adapter takes the default norm {spec.default_norm!r} on {modality}"
    assert attack_norms(get_attack("word_substitution")) == {"edit"}
    assert attack_norms(get_attack("dpatch")) == {"patch_area"}
    assert {"linf", "l2"} <= attack_norms(get_attack("hopskipjump")), "the endpoint adapter takes both budgets"


def test_supported_modalities_table_matches_the_library_constants() -> None:
    assert set(SUPPORTED_MODALITIES) == {"image", "tabular", "text", "detection"}
    assert set(NOT_IMPLEMENTED_MODALITIES) == {"llm"}
    assert KNOWN_NORMS == REGISTRY_KNOWN_NORMS == {"linf", "l2", "edit", "patch_area"}
    for spec in SUPPORTED_MODALITIES.values():
        assert spec.default_norm in spec.norms
        for norm in spec.norms:
            grid = spec.default_eps_grid(norm)
            assert grid == sorted(grid) and all(0.0 < e <= 1.0 for e in grid)
            assert spec.default_reference_eps(norm) in grid
            assert norm in BUDGET_LABELS
    assert modality_norms("image") == modality_norms("tabular") == {"linf", "l2"}
    assert modality_norms("text") == {"edit"} and modality_norms("detection") == {"patch_area"}
    assert modality_norms("llm") == frozenset()
    # Image and tabular read the scoring module's spec 12.3 constants.
    assert default_eps_grid_for("image", "linf") == list(DEFAULT_EPS_GRID_LINF)
    assert default_eps_grid_for("tabular", "l2") == list(DEFAULT_EPS_GRID_L2)
    assert default_reference_eps_for("image", "linf") == DEFAULT_REFERENCE_EPS
    assert default_reference_eps_for("tabular", "l2") == default_reference_eps("l2")
    # Text and detection agree with their adapters' constants (one source of truth per budget).
    assert DEFAULT_EDIT_GRID == ws_module.DEFAULT_EDIT_GRID == (0.1, 0.2, 0.3)
    assert DEFAULT_EDIT_REFERENCE == ws_module.DEFAULT_EDIT_REFERENCE == 0.2
    assert DEFAULT_PATCH_AREA_GRID == dpatch_module.DEFAULT_PATCH_AREA_GRID == (0.01, 0.03, 0.05)
    assert DEFAULT_PATCH_AREA_REFERENCE == dpatch_module.DEFAULT_REFERENCE_PATCH_AREA == 0.03
    assert SUPPORTED_MODALITIES["detection"].mri is False, "a detection campaign carries a scorecard, never an MRI"
    assert SUPPORTED_MODALITIES["detection"].max_n_samples == DETECTION_N_SAMPLES_CAP == 200
    assert SUPPORTED_MODALITIES["detection"].default_n_samples == DETECTION_N_SAMPLES_DEFAULT == 50
    assert {m for m, s in SUPPORTED_MODALITIES.items() if s.endpoint} == {"image", "tabular"}
    with pytest.raises(ValueError, match="no default grid"):
        default_eps_grid_for("text", "linf")
    with pytest.raises(ValueError, match="unknown campaign modality"):
        default_reference_eps_for("llm", "linf")


@pytest.mark.parametrize(
    ("modality", "norm", "ok"),
    [
        ("image", "linf", True), ("image", "l2", True), ("image", "edit", False), ("image", "patch_area", False),
        ("tabular", "l2", True), ("tabular", "patch_area", False),
        ("text", "edit", True), ("text", "linf", False), ("text", "l2", False),
        ("detection", "patch_area", True), ("detection", "linf", False), ("detection", "edit", False),
        ("image", "l1", False), ("text", None, False), ("llm", "linf", False),
    ],
)
def test_check_norm_for_modality(modality: str, norm: Any, ok: bool) -> None:
    error = check_norm_for_modality(modality, norm)
    if ok:
        assert error is None
        return
    assert isinstance(error, ApiError) and error.code == PARAMS_OUT_OF_RANGE and error.status == 422
    assert error.detail["field"] == ("modality" if modality == "llm" else "norm")
    assert error.detail.get("reasons") or modality == "llm"


# --------------------------------------------------------------------------- default fill per modality

@pytest.mark.parametrize(
    ("modality", "attack", "gradients", "norm", "grid", "reference", "n_samples"),
    [
        pytest.param("image", "fgsm", True, "linf", list(DEFAULT_EPS_GRID_LINF), DEFAULT_REFERENCE_EPS, 200,
                     id="image"),
        pytest.param("tabular", "zoo", False, "linf", list(DEFAULT_EPS_GRID_LINF), DEFAULT_REFERENCE_EPS, 200,
                     id="tabular"),
        pytest.param("text", "word_substitution", False, "edit", list(DEFAULT_EDIT_GRID), DEFAULT_EDIT_REFERENCE,
                     200, id="text"),
        pytest.param("detection", "dpatch", True, "patch_area", list(DEFAULT_PATCH_AREA_GRID),
                     DEFAULT_PATCH_AREA_REFERENCE, DETECTION_N_SAMPLES_DEFAULT, id="detection"),
    ],
)
def test_default_grid_fill_per_modality(api: Harness, modality: str, attack: str, gradients: bool, norm: str,
                                        grid: list[float], reference: float, n_samples: int) -> None:
    seed_model(api, modality=modality, gradients=gradients)

    config = frozen_config(api, launch(api, {"attack_ids": [attack]}))

    assert config["modality"] == modality and config["norm"] == norm
    assert config["eps_grid"] == grid and config["reference_eps"] == reference
    assert config["n_samples"] == n_samples
    assert config["dataset_id"] == DATASET and config["dataset_revision"] == DATASET_REVISION
    assert [a["id"] for a in config["attacks"]] == [attack]
    assert config["scoring"] == ScoringConfig().model_dump(mode="json")
    (event,) = api.events("attack.run")
    assert event.success and event.detail["modality"] == modality and event.detail["norm"] == norm
    assert event.detail["budget"] == BUDGET_LABELS[norm]
    assert event.detail["scoring_source"] == "default" and event.detail["non_default_weights"] is False


def test_detection_grid_can_be_given_explicitly_in_patch_area_units(api: Harness) -> None:
    seed_model(api, modality="detection", gradients=True)
    config = frozen_config(api, launch(api, {"attack_ids": ["dpatch"], "eps_grid": [0.02, 0.05, 0.1],
                                             "reference_eps": 0.05, "n_samples": 20}))
    assert config["norm"] == "patch_area" and config["eps_grid"] == [0.02, 0.05, 0.1]
    assert config["reference_eps"] == 0.05 and config["n_samples"] == 20


def test_default_reference_outside_a_custom_text_grid_is_reference_eps_not_in_grid(api: Harness) -> None:
    seed_model(api, modality="text", gradients=False)
    detail = assert_refused(api, launch(api, {"attack_ids": ["word_substitution"], "eps_grid": [0.05, 0.1]}),
                            "reference_eps_not_in_grid")
    assert detail["field"] == "reference_eps" and "0.2" in detail["message"]


# --------------------------------------------------------------------------- modality x norm x attack matrix

@pytest.mark.parametrize(
    ("modality", "gradients", "norm", "attack", "code", "field"),
    [
        # image
        pytest.param("image", True, "linf", "fgsm", None, None, id="image-linf-fgsm"),
        pytest.param("image", True, "l2", "fgsm", "params_out_of_range", "norm", id="image-l2-fgsm-linf-only"),
        pytest.param("image", True, "l2", "pgd", None, None, id="image-l2-pgd"),
        pytest.param("image", True, "l2", "cw_l2", None, None, id="image-l2-cw"),
        pytest.param("image", True, "linf", "cw_l2", "params_out_of_range", "norm", id="image-linf-cw-l2-only"),
        pytest.param("image", True, "linf", "deepfool", "params_out_of_range", "norm", id="image-linf-deepfool"),
        pytest.param("image", True, "l2", "hopskipjump", None, None, id="image-l2-hsj"),
        pytest.param("image", True, "edit", "fgsm", "params_out_of_range", "norm", id="image-edit-not-a-budget"),
        pytest.param("image", True, "patch_area", "pgd", "params_out_of_range", "norm", id="image-patch-area"),
        pytest.param("image", True, "linf", "zoo", "attack_modality_mismatch", "attack_ids", id="image-zoo"),
        pytest.param("image", True, "linf", "word_substitution", "attack_modality_mismatch", "attack_ids",
                     id="image-word-substitution"),
        pytest.param("image", True, "linf", "l1", "unknown_attack", "attack_ids", id="image-unknown-attack"),
        pytest.param("image", True, "l1", "fgsm", "params_out_of_range", "norm", id="image-unknown-norm"),
        # tabular
        pytest.param("tabular", False, "linf", "zoo", None, None, id="tabular-linf-zoo"),
        pytest.param("tabular", False, "l2", "zoo", None, None, id="tabular-l2-zoo"),
        pytest.param("tabular", False, "l2", "hopskipjump", None, None, id="tabular-l2-hsj"),
        pytest.param("tabular", True, "linf", "fgsm", "attack_modality_mismatch", "attack_ids", id="tabular-fgsm"),
        pytest.param("tabular", True, "edit", "pgd", "params_out_of_range", "norm", id="tabular-edit"),
        pytest.param("tabular", False, "linf", "dpatch", "attack_modality_mismatch", "attack_ids",
                     id="tabular-dpatch"),
        # text
        pytest.param("text", False, "edit", "word_substitution", None, None, id="text-edit"),
        pytest.param("text", False, "linf", "word_substitution", "params_out_of_range", "norm", id="text-linf"),
        pytest.param("text", False, "l2", "word_substitution", "params_out_of_range", "norm", id="text-l2"),
        pytest.param("text", False, "patch_area", "word_substitution", "params_out_of_range", "norm",
                     id="text-patch-area"),
        pytest.param("text", True, "edit", "fgsm", "attack_modality_mismatch", "attack_ids", id="text-fgsm"),
        pytest.param("text", False, "edit", "hopskipjump", "attack_modality_mismatch", "attack_ids", id="text-hsj"),
        # detection
        pytest.param("detection", True, "patch_area", "dpatch", None, None, id="detection-patch-area"),
        pytest.param("detection", True, "linf", "dpatch", "params_out_of_range", "norm", id="detection-linf"),
        pytest.param("detection", True, "edit", "dpatch", "params_out_of_range", "norm", id="detection-edit"),
        pytest.param("detection", True, "patch_area", "patch_noise_control", "params_out_of_range", "attack_ids",
                     id="detection-control-is-not-an-attack"),
        pytest.param("detection", True, "patch_area", "fgsm", "attack_modality_mismatch", "attack_ids",
                     id="detection-fgsm"),
        pytest.param("detection", False, "patch_area", "dpatch", "attack_requires_gradients", "attack_ids",
                     id="detection-dpatch-no-gradients"),
    ],
)
def test_modality_norm_attack_admission_matrix(api: Harness, modality: str, gradients: bool, norm: str,
                                                attack: str, code: str | None, field: str | None) -> None:
    seed_model(api, modality=modality, gradients=gradients)
    body = {"attack_ids": [attack], "norm": norm}

    response = launch(api, body)

    if code is None:
        config = frozen_config(api, response)
        assert config["norm"] == norm and config["modality"] == modality
        assert config["eps_grid"] == default_eps_grid_for(modality, norm)
        assert norm in attack_norms(get_attack(attack)), "admission agrees with the registry declaration"
        return
    detail = assert_refused(api, response, code)
    assert detail["field"] == field
    if code == "params_out_of_range" and field == "norm":
        assert detail["reasons"]
        if norm in KNOWN_NORMS and norm not in SUPPORTED_MODALITIES[modality].norms:
            assert "does not belong to modality" in detail["reasons"][0]
        elif norm in KNOWN_NORMS:
            # An attack that does not support the campaign norm: the alternatives on this modality are named.
            assert attack in detail["message"] and norm in detail["message"]
            for other in ATTACKS:
                info = other.info()
                if info.family == "evasion" and norm in attack_norms(other) and modality in getattr(other, "domains", {info.domain}):
                    assert other.id in detail["message"]


def test_norm_mismatch_message_names_the_attacks_norms(api: Harness) -> None:
    seed_model(api)
    detail = assert_refused(api, launch(api, {"attack_ids": ["cw_l2"], "norm": "linf"}), "params_out_of_range")
    assert detail["field"] == "norm"
    assert detail["reasons"] == ["cw_l2 supports norms ['l2'], not 'linf'"]
    assert "L2" in detail["message"] and "fgsm" in detail["message"] and "pgd" in detail["message"]


def test_llm_modality_is_not_implemented_with_the_reason(api: Harness) -> None:
    seed_model(api, modality="llm", gradients=False)
    detail = assert_refused(api, launch(api, {"attack_ids": ["hopskipjump"]}), "not_implemented")
    assert detail["phase"] == "B" and detail["field"] == "modality"
    assert "probes" in detail["reason"] and "MRI" in detail["reason"]


# --------------------------------------------------------------------------- detection n_samples cap

def test_detection_n_samples_cap(api: Harness) -> None:
    seed_model(api, modality="detection", gradients=True)

    detail = assert_refused(api, launch(api, {"attack_ids": ["dpatch"], "n_samples": DETECTION_N_SAMPLES_CAP + 1}),
                            "params_out_of_range")
    assert detail["field"] == "n_samples" and detail["cap"] == DETECTION_N_SAMPLES_CAP
    assert str(DETECTION_N_SAMPLES_CAP) in detail["message"]
    (refused,) = api.events("attack.run")
    assert refused.success is False and refused.detail["attack_ids"] == ["dpatch"]

    config = frozen_config(api, launch(api, {"attack_ids": ["dpatch"], "n_samples": DETECTION_N_SAMPLES_CAP}))
    assert config["n_samples"] == DETECTION_N_SAMPLES_CAP


def test_detection_n_samples_cap_is_explicit_configuration(api: Harness) -> None:
    seed_model(api, modality="detection", gradients=True)
    with pytest.raises(ApiError) as excinfo:
        create_attack_campaign(
            campaign={"target_id": MODEL, "attack_ids": ["dpatch"], "n_samples": 150},
            project_id=PROJECT, actor=ACTOR, config=RedsimConfig(), audit_writer=api.writer,
            max_n_samples={"detection": 100},
        )
    assert excinfo.value.code == "params_out_of_range" and excinfo.value.detail["cap"] == 100
    # Image campaigns are not capped by the detection bound.
    seed_model(api, "model-image-2")
    handle = create_attack_campaign(
        campaign={"target_id": "model-image-2", "attack_ids": ["fgsm"], "n_samples": 1000},
        project_id=PROJECT, actor=ACTOR, config=RedsimConfig(), audit_writer=api.writer,
    )
    assert handle.run_id


def test_schema_range_still_applies_above_the_cap(api: Harness) -> None:
    seed_model(api, modality="detection", gradients=True)
    assert_refused(api, launch(api, {"attack_ids": ["dpatch"], "n_samples": 5}), "params_out_of_range")


# --------------------------------------------------------------------------- endpoint targets

def test_endpoint_without_its_binding_stays_not_implemented(api: Harness) -> None:
    seed_endpoint(api, with_binding=False)
    detail = assert_refused(api, launch(api, {"attack_ids": ["hopskipjump"]}, model_id=ENDPOINT_MODEL),
                            "not_implemented")
    assert detail["phase"] == "B" and "EndpointSpec" in detail["message"] and "binding" in detail["reason"]


@pytest.mark.parametrize("attack", ["fgsm", "pgd", "cw_l2", "deepfool"])
def test_endpoint_white_box_attacks_are_refused_with_attack_requires_gradients(api: Harness, attack: str) -> None:
    # A hand-written ``surrogate`` on the row changes nothing: an endpoint has no build-time surrogate.
    seed_endpoint(api, surrogate=True)
    norm = "l2" if attack in {"cw_l2", "deepfool"} else "linf"
    detail = assert_refused(api, launch(api, {"attack_ids": [attack], "norm": norm}, model_id=ENDPOINT_MODEL),
                            "attack_requires_gradients")
    assert detail["field"] == "attack_ids" and "endpoint" in detail["message"]
    (refused,) = api.events("attack.run")
    assert_no_secret_or_url(refused.detail)


def test_endpoint_black_box_campaign_is_admitted_with_caps_and_a_recorded_budget(api: Harness) -> None:
    seed_endpoint(api)

    response = launch(api, {"attack_ids": ["hopskipjump"], "explain_k": 16, "n_samples": 10}, model_id=ENDPOINT_MODEL)

    config = frozen_config(api, response)
    assert config["explain_k"] == EXPLAIN_QUERY_CAPS.explain_k == 8, "explain capped through EXPLAIN_QUERY_CAPS"
    assert config["norm"] == "linf" and config["eps_grid"] == list(DEFAULT_EPS_GRID_LINF)
    snapshot = config["target_snapshot"]
    assert snapshot["kind"] == "ml_model_endpoint" and snapshot["value"] == f"endpoint:{ENDPOINT_HOST}"
    assert_no_secret_or_url(snapshot)
    assert "url" not in snapshot["detail"] and "auth" not in snapshot["detail"]
    assert snapshot["detail"]["manifest"]["endpoint"]["url_host"] == ENDPOINT_HOST
    endpoint = snapshot["endpoint"]
    assert endpoint["url_host"] == ENDPOINT_HOST and endpoint["auth_profile_id"] == "ap-1"
    assert endpoint["explain_k_requested"] == 16 and endpoint["explain_caps"] == EXPLAIN_QUERY_CAPS.as_dict()
    assert endpoint["limits"]["max_rows"] == 500_000 and endpoint["limits"]["batch_rows"] == 32
    assert endpoint["limits"]["timeout_s"] == 30.0
    # The worst-case bound is derived from the resolved parameters (image cost defaults for HopSkipJump).
    adapter = get_attack("hopskipjump")
    from redsim.ml.attacks import apply_domain_defaults

    p = adapter.resolve_params(apply_domain_defaults(adapter, "image", {}))
    n_eps = len(config["eps_grid"]) if getattr(adapter, "takes_eps", True) else 1
    hsj_rows = 10 * (p["init_size"] + p["max_iter"] * (p["max_eval"] + 1)) * n_eps
    explain_rows = estimate_kernel_explain_rows(k=8, background_rows=1, nsamples=EXPLAIN_QUERY_CAPS.nsamples,
                                                with_control=True)
    budget = endpoint["query_budget"]
    assert budget["eval_rows"] == 10 and budget["control_rows"] == 10 * len(config["eps_grid"])
    assert budget["attack_rows"] == {"hopskipjump": hsj_rows} and budget["explain_rows"] == explain_rows
    assert budget["estimated_rows"] == 10 + 10 * len(config["eps_grid"]) + hsj_rows + explain_rows
    assert budget["max_rows"] == 500_000 and budget["max_requests"] == 20_000
    assert "upper bound" in budget["estimate_kind"] and "never summed" in budget["estimate_kind"]
    assert config["attack_params"] == {"hopskipjump": {}}, "caller overrides only are frozen"
    # The audit row carries the host, counts and ids only.
    (event,) = api.events("attack.run")
    assert event.success and event.detail["target_kind"] == "ml_model_endpoint"
    assert event.detail["endpoint"]["estimated_rows"] == budget["estimated_rows"]
    assert event.detail["endpoint"]["max_rows"] == 500_000 and event.detail["endpoint"]["explain_k_requested"] == 16
    assert_no_secret_or_url(event.detail)
    # The campaign row and the settings hash are the usual ones.
    row = api.campaign_row(response.json()["run_id"])
    assert row is not None and row["modality"] == "image" and row["config"]["explain_k"] == 8


def test_endpoint_tabular_zoo_budget_uses_the_kernel_explainer_caps(api: Harness) -> None:
    # No batch_rows on the binding: the environment default for the modality applies (256 for tabular).
    seed_endpoint(api, modality="tabular", batch_rows=None)
    config = frozen_config(api, launch(api, {"attack_ids": ["zoo"], "n_samples": 10, "include_control": False},
                                       model_id=ENDPOINT_MODEL))
    budget = config["target_snapshot"]["endpoint"]["query_budget"]
    assert budget["control_rows"] == 0
    assert budget["explain_rows"] == EXPLAIN_QUERY_CAPS.estimate_rows(8, with_control=False)
    adapter = get_attack("zoo")
    p = adapter.resolve_params({})
    n_eps = len(config["eps_grid"]) if getattr(adapter, "takes_eps", True) else 1
    assert budget["attack_rows"] == {"zoo": 10 * p["max_iter"] * p["binary_search_steps"] * 2 * p["nb_parallel"] * n_eps}
    assert config["target_snapshot"]["endpoint"]["limits"]["batch_rows"] == 256, "tabular batch default"


def test_endpoint_query_budget_exceeded_is_refused_with_estimate_and_cap(api: Harness) -> None:
    seed_endpoint(api, limits={"max_rows": 1_000})
    expected = "query_budget_exceeded" if "query_budget_exceeded" in HTTP_STATUS else "params_out_of_range"

    detail = assert_refused(api, launch(api, {"attack_ids": ["hopskipjump"], "n_samples": 10}, model_id=ENDPOINT_MODEL),
                            expected)

    assert detail["cap"] == 1_000 and detail["estimate"] > 1_000 and detail["field"] == "n_samples"
    assert "REDSIM_ML_ENDPOINT_MAX_ROWS" in detail["message"]
    (refused,) = api.events("attack.run")
    assert refused.success is False and refused.detail["code"] == expected
    assert_no_secret_or_url(refused.detail)


def test_endpoint_explain_k_zero_costs_no_explain_rows(api: Harness) -> None:
    seed_endpoint(api)
    config = frozen_config(api, launch(api, {"attack_ids": ["hopskipjump"], "n_samples": 10, "explain_k": 0},
                                       model_id=ENDPOINT_MODEL))
    assert config["explain_k"] == 0
    assert config["target_snapshot"]["endpoint"]["query_budget"]["explain_rows"] == 0


@pytest.mark.parametrize(("modality", "attack"), [("text", "word_substitution"), ("detection", "dpatch")])
def test_endpoint_on_a_non_classifier_modality_is_not_implemented(api: Harness, modality: str, attack: str) -> None:
    seed_endpoint(api, modality=modality)
    detail = assert_refused(api, launch(api, {"attack_ids": [attack]}, model_id=ENDPOINT_MODEL), "not_implemented")
    assert detail["phase"] == "B" and detail["field"] == "modality" and modality in detail["reason"]


def test_endpoint_status_is_still_checked(api: Harness) -> None:
    seed_endpoint(api)
    with api.Session.begin() as session:
        target = session.get(Target, ENDPOINT_MODEL)
        assert target is not None
        target.detail = {**target.detail, "status": "validating"}
    detail = assert_refused(api, launch(api, {"attack_ids": ["hopskipjump"]}, model_id=ENDPOINT_MODEL),
                            "model_load_refused")
    assert detail["status"] == "validating"


# --------------------------------------------------------------------------- project scoring (REVIEW_REPORTS-29)

def test_project_scoring_override_is_frozen_flagged_and_changes_the_settings_hash(api: Harness) -> None:
    seed_model(api)
    default_response = launch(api, {"attack_ids": ["fgsm"]})
    default_body = default_response.json()
    assert default_body["scoring_source"] == "default" and default_body["non_default_weights"] is False
    assert default_body["scoring_weights"] == MRIWeights().as_dict()
    default_row = api.campaign_row(default_body["run_id"])
    assert default_row is not None

    override = ScoringConfig(weights=MRIWeights(**CUSTOM_WEIGHTS)).model_dump(mode="json")
    set_project_scoring(api, override)
    response = launch(api, {"attack_ids": ["fgsm"]})

    body = response.json()
    assert body["scoring_source"] == "project" and body["non_default_weights"] is True
    assert body["scoring_weights"] == CUSTOM_WEIGHTS
    config = frozen_config(api, response)
    assert config["scoring"] == override, "the override is frozen as stored, never renormalised"
    assert config["scoring"]["weights"] == CUSTOM_WEIGHTS
    row = api.campaign_row(body["run_id"])
    assert row is not None and row["settings_hash"] != default_row["settings_hash"], \
        "campaigns under different weight vectors are incomparable by construction"
    events = api.events("attack.run")
    assert [e.detail["scoring_source"] for e in events] == ["default", "project"]
    assert events[1].detail["scoring_weights"] == CUSTOM_WEIGHTS and events[1].detail["non_default_weights"] is True
    assert events[1].detail["config"]["scoring"] == override


def test_client_sent_scoring_is_refused_422(api: Harness) -> None:
    seed_model(api)
    detail = assert_refused(api, launch(api, {"attack_ids": ["fgsm"], "scoring": ScoringConfig().model_dump()}),
                            "params_out_of_range")
    assert detail["field"] == "scoring" and detail["reasons"] == ["client-sent scoring"]
    assert "server-owned" in detail["message"]
    (refused,) = api.events("attack.run")
    assert "scoring" not in refused.detail and "config" not in refused.detail


def test_client_sent_scoring_is_refused_even_when_it_equals_the_project_override(api: Harness) -> None:
    seed_model(api)
    override = ScoringConfig(weights=MRIWeights(**CUSTOM_WEIGHTS)).model_dump(mode="json")
    set_project_scoring(api, override)
    assert_refused(api, launch(api, {"attack_ids": ["fgsm"], "scoring": override}), "params_out_of_range")


def test_invalid_project_override_is_refused_not_renormalised(api: Harness) -> None:
    seed_model(api)
    set_project_scoring(api, {"weights": {"acc": 0.5, "asr": 0.2, "eps": 0.1, "conf": 0.05, "expl": 0.05}})

    detail = assert_refused(api, launch(api, {"attack_ids": ["fgsm"]}), "params_out_of_range")

    assert detail["field"] == "scoring" and detail["scoring_source"] == "project"
    assert any("sum to 1" in reason for reason in detail["reasons"])
    assert "never renormalised" in detail["message"]


def test_rerun_keeps_the_parents_frozen_scoring_after_the_override_changed(api: Harness) -> None:
    seed_model(api)
    parent = parent_config()
    assert parent["scoring"] == ScoringConfig().model_dump(mode="json")
    seed_campaign_run(api, "run-parent-failed", status="failed", config=parent)
    set_project_scoring(api, ScoringConfig(weights=MRIWeights(**CUSTOM_WEIGHTS)).model_dump(mode="json"))

    response = launch(api, {"parent_run_id": "run-parent-failed"})

    body = response.json()
    assert body["scoring_source"] == "parent" and body["non_default_weights"] is False
    config = frozen_config(api, response)
    assert config["scoring"] == parent["scoring"], "lineage pairs stay comparable"
    (event,) = api.events("attack.run")
    assert event.detail["rerun"] is True and event.detail["scoring_source"] == "parent"

    # A fresh campaign on the same model now takes the override: the two are not comparable, by design.
    fresh = frozen_config(api, launch(api, {"attack_ids": ["fgsm"]}))
    assert fresh["scoring"]["weights"] == CUSTOM_WEIGHTS


def test_verify_keeps_the_baselines_scoring_and_the_phase_a_response_shape(
    api: Harness, monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = seed_verify_baseline(api, monkeypatch)
    set_project_scoring(api, ScoringConfig(weights=MRIWeights(**CUSTOM_WEIGHTS)).model_dump(mode="json"))
    assert api.client is not None

    response = api.client.post(f"/v1/findings/{ids['fgsm']}/verify", json={})

    assert response.status_code == 202, response.text
    body = response.json()
    assert set(body) == {"run_id", "job_ids", "status_url"}
    with api.Session() as session:
        job = session.get(Job, body["job_ids"][0])
    assert job is not None
    assert job.detail["campaign_config"]["scoring"] == ScoringConfig().model_dump(mode="json"), \
        "the verify run keeps the baseline's block, not today's project override"
    (event,) = api.events("verify.replay")
    assert event.detail["scoring_source"] == "baseline" and event.detail["non_default_weights"] is False
    assert event.detail["defense_kind"] == "preprocessing"


def test_is_default_weights_predicate() -> None:
    assert is_default_weights(ScoringConfig()) is True
    assert is_default_weights({"weights": MRIWeights().as_dict()}) is True
    assert is_default_weights({}) is True
    assert is_default_weights(ScoringConfig(weights=MRIWeights(**CUSTOM_WEIGHTS))) is False
    assert is_default_weights({"weights": CUSTOM_WEIGHTS}) is False
    assert is_default_weights({"weights": {"acc": 1.0}}) is False, "a partial vector is never treated as default"


# --------------------------------------------------------------------------- verify: training defenses

def test_verify_admits_a_training_defense_on_an_image_torch_model(api: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    ids = seed_verify_baseline(api, monkeypatch)
    assert api.client is not None
    from redsim.ml.defenses import get_defense

    if get_defense("adversarial_training").get("kind") != "training":   # pragma: no cover - older catalog
        pytest.skip("the defenses catalog carries no training rows on this tree")

    # r.R1 cites adversarial_training only, so the defense resolves from the recommendation.
    response = api.client.post(f"/v1/findings/{ids['fgsm']}/verify", json={"recommendation_id": "r.R1"})

    assert response.status_code == 202, response.text
    with api.Session() as session:
        job = session.get(Job, response.json()["job_ids"][0])
    assert job is not None
    defense = job.detail["campaign_config"]["defense"]
    assert defense["id"] == "adversarial_training" and defense["params"]["epochs"] >= 1
    (event,) = api.events("verify.replay")
    assert event.success and event.detail["defense_kind"] == "training"


def test_training_defense_on_a_tabular_tree_ensemble_is_defense_modality_mismatch() -> None:
    from redsim.ml.defenses import get_defense
    from redsim.ml.harden.apply import TREE_ENSEMBLE_REASON

    spec = get_defense("adversarial_training")
    with pytest.raises(ApiError) as excinfo:
        ml_campaigns._check_training_defense("adversarial_training", spec, modality="tabular", gradients=False)
    assert excinfo.value.code == "defense_modality_mismatch" and excinfo.value.status == 422
    assert excinfo.value.detail["reasons"] == [TREE_ENSEMBLE_REASON]
    # Without gradients there is no torch module to fine-tune: refused, never run and recorded as a fake delta.
    with pytest.raises(ApiError) as excinfo:
        ml_campaigns._check_training_defense("adversarial_training", spec, modality="image", gradients=False)
    assert excinfo.value.code == "params_out_of_range" and "training_defense_unavailable" in excinfo.value.detail["reasons"]
    # Preprocessing rows are untouched by the check.
    ml_campaigns._check_training_defense("feature_squeezing", get_defense("feature_squeezing"), modality="tabular",
                                         gradients=False)


# --------------------------------------------------------------------------- the frozen config round-trips

def test_frozen_phase_b_configs_validate_as_campaign_configs(api: Harness) -> None:
    seed_model(api, "model-text", modality="text", gradients=False)
    seed_model(api, "model-det", modality="detection", gradients=True)
    text = frozen_config(api, launch(api, {"attack_ids": ["word_substitution"]}, model_id="model-text"))
    det = frozen_config(api, launch(api, {"attack_ids": ["dpatch"]}, model_id="model-det"))
    assert CampaignConfig.model_validate(text).norm == "edit"
    assert CampaignConfig.model_validate(det).norm == "patch_area"
