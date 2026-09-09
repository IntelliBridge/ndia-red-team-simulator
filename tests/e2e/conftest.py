"""Session-scoped fixtures for the end-to-end tier (register row G-TESTS; spec 22.5, 24, 26).

Every test collected under ``tests/e2e`` is stamped ``e2e`` here and skipped
unless ``REDSIM_E2E`` is set, so the default ``pytest -q`` (whose ``addopts``
deselect ``e2e``) runs nothing from this directory and ``pytest -m e2e tests/e2e``
without the variable skips rather than fails. Run the tier with::

    REDSIM_E2E=1 pytest -q -m e2e tests/e2e

This module imports only the standard library, pytest and ``tests.e2e.harness``
(itself stdlib + pytest at import time), so collection stays green in the unit
CI job that installs neither the ``api`` nor the ``ml`` extra. Everything heavy
is imported inside the fixtures, after ``REDSIM_E2E`` has been checked.

Fixture graph (all session-scoped unless noted)::

    e2e_harness_dir ─ e2e_env ─ e2e_assets ─ e2e_app ─ e2e_org ─ e2e_bundled
                                                  ├──── pythia
                                                  ├──── audit_verify_all   (function)
                                                  └──── tamper_audit_event (function)
    postgres_url (independent; skips when REDSIM_E2E_POSTGRES_URL is unset)

See ``tests/e2e/README.md`` for what each one provides and what the tier excludes.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from tests.e2e import harness as h

if TYPE_CHECKING:
    from tests.e2e.harness import E2EApp, E2EOrg, PythiaToggle

_HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Collection: stamp ``e2e`` and gate on REDSIM_E2E
# ---------------------------------------------------------------------------


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Mark everything under ``tests/e2e`` as ``e2e``; skip it all when the tier is off.

    ``tryfirst`` runs this before pytest's own ``-m`` deselection, so the marker
    is in place when ``addopts`` (``-m 'not ... e2e ...'``) is evaluated.
    """
    del config
    skip = None if h.e2e_enabled() else pytest.mark.skip(
        reason=f"end-to-end tier is off: set {h.E2E_ENV}=1 (tests/e2e/README.md)"
    )
    for item in items:
        try:
            under_e2e = Path(str(item.path)).resolve().is_relative_to(_HERE)
        except (AttributeError, ValueError):
            under_e2e = False
        if not under_e2e:
            continue
        item.add_marker(pytest.mark.e2e)
        if skip is not None:
            item.add_marker(skip)


# ---------------------------------------------------------------------------
# Environment and assets
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def e2e_harness_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One directory for the whole tier: assets, sqlite file, blobs, sandbox work dirs, config."""
    return tmp_path_factory.mktemp("redsim-e2e")


@pytest.fixture(scope="session")
def e2e_env(e2e_harness_dir: Path) -> Iterator[pytest.MonkeyPatch]:
    """A session ``MonkeyPatch`` with developer credentials and stray redsim settings scrubbed.

    Deletes ``KAGGLE_*``, ``PYTHIA_*``, the LLM model variables, ``REDSIM_TEST_AUDIT``,
    ``REDSIM_DB_URL`` and the storage/config selectors the harness sets itself;
    points ``REDSIM_ENV_FILE`` at an absent file and the Pythia repo-root ``.env``
    fallback at the harness directory. Fixtures below add their own variables to
    this same patch so everything is undone together at session end.
    """
    h.require_e2e()
    monkeypatch = pytest.MonkeyPatch()
    h.sanitize_environment(monkeypatch, e2e_harness_dir)
    yield monkeypatch
    monkeypatch.undo()


@pytest.fixture(scope="session")
def e2e_assets(e2e_env: pytest.MonkeyPatch, e2e_harness_dir: Path) -> Iterator[Path]:
    """A tiny real asset tree (``small_cnn`` on 8x8 synthetic images + the URL tree ensemble).

    Built with ``redsim.ml.assets.build`` exactly as ``redsim ml build-assets``
    would, then ``REDSIM_ML_ASSETS_DIR`` points the registered ``vehicles_cnn``
    and ``url_trees`` targets at it. Requires the ``ml`` extra; skips otherwise.
    Returns the tree root; ``harness.asset_dataset_ids(root)`` gives the dataset
    ids the builder recorded.
    """
    for module in ("numpy", "torch", "sklearn", "art"):
        pytest.importorskip(module)
    root = h.build_tiny_assets(e2e_harness_dir / "assets")
    e2e_env.setenv("REDSIM_ML_ASSETS_DIR", str(root))
    h.unload_bundled_targets()
    yield root
    h.unload_bundled_targets()


# ---------------------------------------------------------------------------
# Application, organisation, models
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def e2e_app(e2e_env: pytest.MonkeyPatch, e2e_assets: Path, e2e_harness_dir: Path) -> Iterator[E2EApp]:
    """The FastAPI app over a file-backed sqlite database with eager Celery and a filesystem blob store.

    ``REDSIM_DB_URL`` is set for the process, so the API's admission events and
    the worker's stage events share one ``audit_events`` table (the ORM chain
    writer works on sqlite). Celery runs ``task_always_eager`` with propagation;
    the ML sandbox runs as a real child process unless ``REDSIM_E2E_SANDBOX=inprocess``
    or ``e2e_app.sandbox.use("inprocess")``. See ``E2EApp`` in ``harness.py``.
    """
    for module in ("fastapi", "sqlalchemy", "celery"):
        pytest.importorskip(module)
    harness = h.build_harness(e2e_env, e2e_harness_dir, assets_dir=e2e_assets,
                              sandbox_mode=h.sandbox_mode_from_env())
    yield harness
    harness.close()


@pytest.fixture(scope="session")
def e2e_org(e2e_app: E2EApp) -> E2EOrg:
    """Two organisations and projects, plus one authenticated ``TestClient`` per identity.

    ``e2e_org.client(role)`` for ``viewer`` / ``scanner`` / ``remediator`` /
    ``approver`` / ``admin`` (members of ``e2e_org.project_id``), ``outsider``
    (admin of the second organisation's project) and ``stranger`` (no
    memberships). Row-level security is Postgres-only: on this sqlite harness a
    cross-org negative proves the application gates, not the database policy.
    """
    return h.seed_org(e2e_app)


@pytest.fixture(scope="session")
def e2e_bundled(e2e_app: E2EApp, e2e_org: E2EOrg) -> dict[str, str]:
    """``{"vehicles_cnn": <model_id>, "url_trees": <model_id>}`` registered into ``e2e_org.project_id``.

    Goes through ``redsim.services.ml_models.register_bundled_model`` when the
    wave-2 service is on the tree, else ``POST /v1/models`` as the remediator.
    Session-scoped: a test that deletes one of these models changes what later
    tests see; re-register with ``harness.register_bundled`` if you must.
    """
    return h.register_all_bundled(e2e_app, e2e_org)


# ---------------------------------------------------------------------------
# Pythia, audit, Postgres
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def pythia(e2e_app: E2EApp) -> Iterator[PythiaToggle]:
    """Mocked Pythia gateway, off by default.

    ``pythia.on()`` (or ``with pythia:``) exports the three settings variables,
    routes ``redsim.llm.pythia.make_backend`` through an ``httpx.MockTransport``
    that answers with a narrative built only from the payload's own words, and
    runs campaigns in-process (the sandbox child strips ``PYTHIA_*``).
    ``pythia.requests`` records every call; ``pythia.disable_llm(True)`` sets
    ``REDSIM_DISABLE_LLM=1``. Always switched off at session end.
    """
    toggle = h.PythiaToggle(e2e_app)
    yield toggle
    toggle.off()
    toggle.disable_llm(False)


@pytest.fixture
def audit_verify_all(e2e_app: E2EApp) -> Callable[[], tuple[int, str]]:
    """``() -> (exit_code, output)``: ``redsim audit verify --all`` as a subprocess on the harness DB."""

    def _verify() -> tuple[int, str]:
        return h.audit_verify_all(e2e_app)

    return _verify


@pytest.fixture
def tamper_audit_event(e2e_app: E2EApp) -> Callable[..., tuple[str, int]]:
    """``(chain_id=None, seq=None, mutation="detail") -> (chain_id, seq)``: mutate one stored audit event."""

    def _tamper(**kwargs: Any) -> tuple[str, int]:
        return h.tamper_audit_event(e2e_app, **kwargs)

    return _tamper


@pytest.fixture(scope="session")
def postgres_url() -> str:
    """The migrated Postgres for the RLS lane; skips unless ``REDSIM_E2E_POSTGRES_URL`` is set.

    Fails (does not skip) when the database is reachable but ``alembic upgrade
    head`` has not created ``ml_campaigns`` / ``audit_events`` / ``targets``.
    """
    url = h.postgres_url_from_env()
    if url is None:
        pytest.skip(f"Postgres lane is off: set {h.POSTGRES_URL_ENV} (tests/e2e/README.md)")
    pytest.importorskip("sqlalchemy")
    h.check_postgres_migrated(url)
    return url


@pytest.fixture(scope="session")
def e2e_env_snapshot() -> dict[str, str]:
    """The process environment as the tier started (for tests asserting nothing leaked)."""
    return dict(os.environ)
