"""Shared end-to-end harness for redsim (spec sections 22.5, 24 and 26; register row G-TESTS).

Everything a completion-criteria test needs to drive one campaign through the
real API, the real admission services, the real Celery task bodies (eager) and
the real ML sandbox against tiny synthetic assets built with the real
``redsim.ml.assets`` builder, then check the audit chain with the real CLI.

The fixtures in ``tests/e2e/conftest.py`` wrap the builders here; tests import
the plain helpers (``run_campaign_via_api``, ``audit_verify_all``,
``tamper_audit_event``, ``image_campaign``, ``tabular_campaign``) from this
module. Nothing in this module is imported by the default ``pytest -q`` tier:
module-level imports are stdlib plus pytest so the unit CI job, which installs
neither the ``api`` nor the ``ml`` extra, can still load ``tests/e2e/conftest.py``
at collection time.

Design notes
------------
* **One process, one sqlite file.** The FastAPI app, the eager Celery worker
  and the CLI subprocess all read ``REDSIM_DB_URL=sqlite:///<harness>/e2e.db``.
  Because the URL is set, ``redsim.audit.chain.resolve_writer`` selects the
  ``PostgresAuditWriter`` (an ORM writer that works on sqlite too), so API-side
  admission events and worker-side stage events land in the same
  ``audit_events`` table that ``redsim audit verify --all`` reads.
* **The sandbox is real by default.** ``run_campaign_sandboxed`` spawns
  ``python -m redsim.ml.sandbox_worker`` exactly as production does. An
  in-process mode (``REDSIM_E2E_SANDBOX=inprocess`` or
  ``e2e_app.sandbox.use("inprocess")``) calls ``redsim.ml.campaign.run_campaign``
  directly in the worker thread; it exists because the child's environment
  strips every ``PYTHIA_*`` variable, so a mocked Pythia gateway can only be
  observed in-process. ``PythiaToggle.on()`` switches to it automatically.
* **Roles are real dev tokens.** ``redsim.api.auth._dev_user`` is replaced by a
  lookup over the users ``seed_org`` created, so ``Authorization: Bearer
  dev:<email>`` resolves through the production header -> token -> user path
  (and through the tenant middleware) with role-specific memberships instead of
  the dev default ``{"default": "admin"}``.
* **RLS is Postgres-only.** sqlite has no row-level security; cross-org negatives
  on this harness prove the application-layer gates (``ensure_project_access``,
  list scoping), not the database policy. ``postgres_url`` names a migrated
  Postgres for the RLS lane and skips when ``REDSIM_E2E_POSTGRES_URL`` is unset.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import pytest

if TYPE_CHECKING:
    import httpx
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import Session

    from redsim.api.auth import CurrentUser
    from redsim.api.settings import APISettings
    from redsim.ml.assets.datasets import ImageDataset
    from redsim.ml.campaign import ArtifactSink
    from redsim.ml.schema import CampaignConfig, CampaignRecord

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]

E2E_ENV = "REDSIM_E2E"
POSTGRES_URL_ENV = "REDSIM_E2E_POSTGRES_URL"
SANDBOX_MODE_ENV = "REDSIM_E2E_SANDBOX"

SandboxMode = Literal["child", "inprocess"]
SANDBOX_MODES: tuple[SandboxMode, ...] = ("child", "inprocess")

#: The five redsim roles of spec section 7, lowest rank first.
ROLES: tuple[str, ...] = ("viewer", "scanner", "remediator", "approver", "admin")
#: Admin of the *other* organisation's project: the cross-tenant negative.
OUTSIDER = "outsider"
#: Authenticated caller with no membership anywhere.
STRANGER = "stranger"
ALL_IDENTITIES: tuple[str, ...] = (*ROLES, OUTSIDER, STRANGER)

ORG_ID = "org-e2e"
ORG_SLUG = "e2e-org"
PROJECT_ID = "proj-e2e"
PROJECT_SLUG = "e2e-project"
OTHER_ORG_ID = "org-e2e-other"
OTHER_ORG_SLUG = "e2e-other-org"
OTHER_PROJECT_ID = "proj-e2e-other"
OTHER_PROJECT_SLUG = "e2e-other-project"
IDENTITY_DOMAIN = "e2e.redsim.test"

#: Bundled demo targets registered by ``e2e_bundled``.
IMAGE_MODEL_ID = "vehicles_cnn"
TABULAR_MODEL_ID = "url_trees"
BUNDLED_IDS: tuple[str, ...] = (IMAGE_MODEL_ID, TABULAR_MODEL_ID)

#: The synthetic image set the tiny asset tree is built from.
IMAGE_DATASET_ID = "local:synthetic-images"
IMAGE_DATASET_REVISION = "synthetic-e2e-v1"
IMAGE_CLASS_NAMES: tuple[str, ...] = ("class_0", "class_1", "class_2")
IMAGE_SIZE = 8
N_IMAGES = 48                      # 24 land in the evaluation split (8 per class)
URL_SAMPLE_CSV = REPO_ROOT / "tests" / "ml" / "fixtures" / "malicious_urls_sample.csv"

TERMINAL_RUN_STATUSES = frozenset({"succeeded", "failed", "cancelled"})

#: What the mocked gateway answers to. Never a real host; never a real key.
MOCK_PYTHIA_BASE_URL = "https://pythia.e2e.invalid"
MOCK_PYTHIA_API_KEY = "pk_e2e_mock_key_not_a_secret"
MOCK_PYTHIA_MODEL = "e2e/mock-writer"

#: Environment keys the CLI subprocess inherits (mirrors the sandbox allowlist).
_CLI_SAFE_ENV_KEYS = (
    "PATH", "PYTHONHOME", "VIRTUAL_ENV", "HOME", "TMPDIR", "TEMP", "TMP",
    "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ", "SYSTEMROOT",
    "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
)

#: Variables a test session must never inherit from the developer's shell.
_SCRUBBED_ENV_KEYS = (
    "KAGGLE_API_TOKEN", "KAGGLE_USERNAME", "KAGGLE_KEY",
    "PYTHIA_BASE_URL", "PYTHIA_API_KEY", "PYTHIA_PERSONA", "PYTHIA_TIMEOUT_S",
    "REDSIM_ML_LLM_MODEL", "REDSIM_LLM_MODEL", "AEGIS_ML_LLM_MODEL",
    "REDSIM_TEST_AUDIT", "REDSIM_DB_URL", "REDSIM_DB_OWNER_URL", "REDSIM_DISABLE_LLM",
    "REDSIM_MODE", "REDSIM_API_URL", "REDSIM_CONFIG", "REDSIM_OUTPUT_DIR",
    "REDSIM_ML_ASSETS_DIR", "REDSIM_ML_WORK_DIR", "REDSIM_ML_KEEP_WORK_DIR",
    "REDSIM_BLOB_BACKEND", "REDSIM_BLOB_FS_PATH", "REDSIM_WORM_EXPORT",
    "REDSIM_POLICY_ENGINE", "REDSIM_PLUGINS",
)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_REC_LINE = re.compile(r"^\s*\d+\.\s+\[(r\.[A-Za-z0-9_]+)\]\s+(.*)$")
_TRIGGERED_LINE = re.compile(r"^\s*triggered_by:\s*(.*)$")


class E2EHarnessError(RuntimeError):
    """A harness precondition failed; the message says what to fix."""


class CampaignLaunchRefused(E2EHarnessError):
    """``POST /v1/models/{id}/attacks`` did not answer 202."""

    def __init__(self, status_code: int, detail: Any) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"campaign launch refused with HTTP {status_code}: {detail!r}")


# ---------------------------------------------------------------------------
# Gating helpers
# ---------------------------------------------------------------------------


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() not in {"", "0", "false", "no", "off"}


def e2e_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """``True`` when ``REDSIM_E2E`` is set to a truthy value."""
    env = os.environ if environ is None else environ
    return _truthy(env.get(E2E_ENV))


def require_e2e() -> None:
    """Skip the requesting test unless the e2e tier is switched on."""
    if not e2e_enabled():
        pytest.skip(f"end-to-end tier is off: set {E2E_ENV}=1 (see tests/e2e/README.md)")


def sandbox_mode_from_env(environ: Mapping[str, str] | None = None) -> SandboxMode:
    """``REDSIM_E2E_SANDBOX``: ``child`` (default, real subprocess) or ``inprocess``."""
    env = os.environ if environ is None else environ
    raw = env.get(SANDBOX_MODE_ENV, "child").strip().lower() or "child"
    if raw not in SANDBOX_MODES:
        raise E2EHarnessError(f"{SANDBOX_MODE_ENV}={raw!r}; expected one of {SANDBOX_MODES}")
    return "inprocess" if raw == "inprocess" else "child"


def strip_ansi(text: str) -> str:
    """The CLI colours its verdicts; tests compare the plain text."""
    return _ANSI.sub("", text)


def sanitize_environment(monkeypatch: pytest.MonkeyPatch, harness_dir: Path) -> None:
    """Keep the session away from developer credentials and stray redsim settings.

    Deletes every gateway/dataset credential and every ``REDSIM_*`` selector the
    harness sets itself, points ``REDSIM_ENV_FILE`` at an absent file and the
    Pythia repo-root ``.env`` fallback at the harness directory, the way
    ``tests/ml/conftest.py`` does for the ml tier.
    """
    from redsim.llm import pythia

    for key in _SCRUBBED_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv(pythia.ENV_FILE_VAR, str(harness_dir / "absent.env"))
    monkeypatch.setattr(pythia, "_REPO_ROOT", harness_dir)


def developer_env_file_in_reach() -> Path | None:
    """The ``.env`` a *sandbox child* would read, or ``None``.

    The child's environment strips ``REDSIM_ENV_FILE`` (every ``REDSIM_*`` key),
    so ``redsim.llm.pythia`` inside the child falls back to ``./.env`` and the
    repo-root ``.env``. When one exists, a child-mode campaign that requests an
    LLM narrative would contact a real gateway; the harness refuses that.
    """
    for candidate in (Path.cwd() / ".env", REPO_ROOT / ".env"):
        if candidate.is_file():
            return candidate
    return None


# ---------------------------------------------------------------------------
# Tiny real assets
# ---------------------------------------------------------------------------


def _quiet(_: str) -> None:
    return None


def synthetic_images(n: int = N_IMAGES, image_size: int = IMAGE_SIZE, seed: int = 0) -> ImageDataset:
    """A seeded random RGB image set with balanced labels, shaped like the real loader's output."""
    import numpy as np

    from redsim.ml.assets import datasets as ds
    from redsim.ml.assets.manifest import DatasetEntry

    classes = list(IMAGE_CLASS_NAMES)
    rng = np.random.default_rng(seed)
    x = rng.integers(0, 256, size=(n, 3, image_size, image_size), dtype=np.uint8)
    y = (np.arange(n) % len(classes)).astype(np.int64)
    entry = DatasetEntry(
        id=IMAGE_DATASET_ID, source="local", revision=IMAGE_DATASET_REVISION, license="n/a",
        class_names=classes, fixture_only=True,
        notes=["e2e harness double: seeded random pixels, never a demo dataset"],
    )
    train = ds.ImageSplit(name="train", x=x, y=y, indices=np.arange(n, dtype=np.int64), class_names=classes)
    n_eval = n // 2
    evaluation = ds.ImageSplit(name="test", x=x[:n_eval], y=y[:n_eval],
                               indices=np.arange(n_eval, dtype=np.int64), class_names=classes)
    return ds.ImageDataset(dataset=entry, train=train, eval=evaluation)


def build_tiny_assets(root: Path, *, n_images: int = N_IMAGES, image_size: int = IMAGE_SIZE,
                      seed: int = 0, epochs: int = 1) -> Path:
    """Write a complete asset tree with the real builder: one image CNN, one URL tree ensemble.

    ``build_cnn_asset`` trains ``small_cnn`` for ``epochs`` on :func:`synthetic_images`;
    ``build_url_asset`` fits the sklearn ensemble plus its declared surrogate on the
    committed ``malicious_urls_sample.csv``. No network, no Kaggle, no download. The
    manifest is what ``redsim ml build-assets`` writes, so the registered
    ``vehicles_cnn`` / ``url_trees`` targets load it unchanged.
    """
    from redsim.ml.assets import datasets as ds
    from redsim.ml.assets.build import build_cnn_asset, build_url_asset
    from redsim.ml.assets.manifest import MANIFEST_NAME, AssetManifest, write_manifest

    if not URL_SAMPLE_CSV.is_file():
        raise E2EHarnessError(f"URL sample fixture missing: {URL_SAMPLE_CSV}")
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    img_ds, img_model = build_cnn_asset(
        synthetic_images(n_images, image_size, seed), model_id=IMAGE_MODEL_ID, root=root,
        epochs=epochs, seed=seed, log=_quiet,
    )
    url_ds, url_model = build_url_asset(
        ds.sample_url_table(URL_SAMPLE_CSV), model_id=TABULAR_MODEL_ID, root=root, seed=seed, log=_quiet,
    )
    manifest = AssetManifest.new()
    manifest.datasets[img_ds.id] = img_ds
    manifest.datasets[url_ds.id] = url_ds
    manifest.models[img_model.id] = img_model
    manifest.models[url_model.id] = url_model
    write_manifest(manifest, root / MANIFEST_NAME)
    return root


def asset_manifest(assets_dir: Path) -> dict[str, Any]:
    """The raw ``MANIFEST.json`` of a built tree."""
    from redsim.ml.assets.manifest import MANIFEST_NAME

    return dict(json.loads((Path(assets_dir) / MANIFEST_NAME).read_text(encoding="utf-8")))


def asset_dataset_ids(assets_dir: Path) -> dict[str, str]:
    """``{model_id: dataset_id}`` as the builder recorded them (never hard-coded in tests)."""
    models = asset_manifest(assets_dir).get("models") or {}
    return {str(mid): str(entry.get("dataset_id")) for mid, entry in models.items()}


def unload_bundled_targets() -> None:
    """Drop cached weights and slices so a later fixture (or test) sees a fresh registry."""
    try:
        from redsim.ml.targets import TARGETS
    except ImportError:
        return
    for target in TARGETS:
        unload = getattr(target, "unload", None)
        if callable(unload):
            unload()


# ---------------------------------------------------------------------------
# Sandbox controller (real child by default; in-process on request)
# ---------------------------------------------------------------------------


class SandboxController:
    """Switch the worker's campaign sandbox between the real child and an in-process shim.

    The worker task imports ``run_campaign_sandboxed`` from ``redsim.ml.sandbox``
    at call time, so replacing that module attribute is enough. ``calls`` records
    the mode each campaign actually ran in. ``validate_model_sandboxed`` (the
    upload path) is never replaced: uploads always validate in the real child.
    """

    def __init__(self, mode: SandboxMode = "child") -> None:
        import redsim.ml.sandbox as sandbox_module

        self._module = sandbox_module
        self._original: Callable[..., Any] = sandbox_module.run_campaign_sandboxed
        self._mode: SandboxMode = mode
        self.calls: list[SandboxMode] = []
        self._install()

    @property
    def mode(self) -> SandboxMode:
        return self._mode

    def set(self, mode: SandboxMode) -> None:
        if mode not in SANDBOX_MODES:
            raise E2EHarnessError(f"unknown sandbox mode {mode!r}; expected one of {SANDBOX_MODES}")
        self._mode = mode
        self._install()

    @contextlib.contextmanager
    def use(self, mode: SandboxMode) -> Iterator[None]:
        previous = self._mode
        self.set(mode)
        try:
            yield
        finally:
            self.set(previous)

    def restore(self) -> None:
        self._module.run_campaign_sandboxed = self._original

    def _install(self) -> None:
        controller = self

        def dispatch(config: CampaignConfig, sink: ArtifactSink, **kwargs: Any) -> CampaignRecord:
            controller.calls.append(controller._mode)
            if controller._mode == "inprocess":
                return run_campaign_inprocess(config, sink, **kwargs)
            result: CampaignRecord = controller._original(config, sink, **kwargs)
            return result

        self._module.run_campaign_sandboxed = dispatch


def run_campaign_inprocess(
    config: CampaignConfig,
    sink: ArtifactSink,
    *,
    target_file: Path | None = None,
    target_detail: dict[str, Any] | None = None,
    baseline_run_id: str | None = None,
    parent_run_id: str | None = None,
    on_stage: Callable[[str], None] | None = None,
    is_cancelled: Callable[[], bool] | None = None,
    job_id: str | None = None,
) -> CampaignRecord:
    """``run_campaign_sandboxed``'s contract without the child process.

    Mirrors ``redsim.ml.sandbox_worker._campaign``: an uploaded target is built
    through ``artifact_target_from_path`` (sniff, digest and architecture checks
    included), and any exception becomes a ``failed`` partial record naming the
    error class, never a crash. Artifacts go straight into ``sink`` (the worker's
    ``DatabaseArtifactSink``), so observation artifact references are Artifact
    row ids exactly as the parent would have mapped them.
    """
    del is_cancelled, job_id  # cancellation polling is a child-process concern
    from redsim.ml.campaign import run_campaign
    from redsim.ml.sandbox import partial_campaign_record

    stages: list[str] = []

    def _on_stage(stage: str) -> None:
        stages.append(stage)
        if on_stage is not None:
            on_stage(stage)

    try:
        target = None
        if target_file is not None:
            from redsim.services.ml_models import artifact_target_from_path

            target = artifact_target_from_path(config.target_id, Path(target_file), dict(target_detail or {}))
        return run_campaign(
            config, sink, explain=config.explain_k > 0,
            baseline_run_id=baseline_run_id, parent_run_id=parent_run_id,
            on_stage=_on_stage, target_override=target,
        )
    except Exception as exc:  # noqa: BLE001 - failure is evidence, as in the child
        return partial_campaign_record(
            config, status="failed", error=f"{type(exc).__name__}: {exc}", stages_done=stages,
            baseline_run_id=baseline_run_id, parent_run_id=parent_run_id,
        )


# ---------------------------------------------------------------------------
# The application harness
# ---------------------------------------------------------------------------


def install_sqlite_tz_datetime() -> Callable[[], None]:
    """Make sqlite round-trip timezone-aware ``DateTime`` columns the way Postgres ``timestamptz`` does.

    SQLAlchemy's sqlite ``DATETIME`` storage format has no offset component, so
    ``AuditEvent.created_at`` (``DateTime(timezone=True)``) comes back naive and
    ``PostgresAuditWriter.read_chain`` re-derives ``ts`` as
    ``2026-...T...`` instead of the hashed ``2026-...T...+00:00``: every chain
    then fails ``verify_chain`` at ``seq=1`` before anyone tampers with it. This
    swaps the pysqlite dialect's ``DateTime`` implementation for one that stores
    ``isoformat()`` (offset included) and parses it back, so the production
    writer and verifier are exercised unchanged. Returns the undo callable.
    Process-wide for the dialect class; the harness installs it before creating
    its engine and undoes it in :meth:`E2EApp.close`.
    """
    import datetime as _dt

    from sqlalchemy import types as sqltypes
    from sqlalchemy.dialects.sqlite import DATETIME
    from sqlalchemy.dialects.sqlite.pysqlite import SQLiteDialect_pysqlite

    class TZDateTime(DATETIME):
        def bind_processor(self, dialect: Any) -> Callable[[Any], Any]:
            def process(value: Any) -> Any:
                return None if value is None else value.isoformat()
            return process

        def result_processor(self, dialect: Any, coltype: Any) -> Callable[[Any], Any]:
            def process(value: Any) -> Any:
                if value is None or isinstance(value, _dt.datetime):
                    return value
                return _dt.datetime.fromisoformat(str(value))
            return process

    colspecs = SQLiteDialect_pysqlite.colspecs
    original = colspecs.get(sqltypes.DateTime)
    colspecs[sqltypes.DateTime] = TZDateTime

    def restore() -> None:
        if original is None:
            colspecs.pop(sqltypes.DateTime, None)
        else:
            colspecs[sqltypes.DateTime] = original

    return restore


#: ``python -c`` bootstrap for the CLI subprocess on a sqlite harness database: install the same
#: timezone shim, then hand ``sys.argv[1:]`` to the real ``redsim.cli.main.main``.
_CLI_SQLITE_BOOTSTRAP = (
    "import sys; from tests.e2e.harness import install_sqlite_tz_datetime; install_sqlite_tz_datetime(); "
    "from redsim.cli.main import main; main(sys.argv[1:])"
)


def campaign_table(metadata: Any) -> Any:
    """``ml_campaigns`` as migration ``0010_ml_vertical`` shapes it.

    The table is migration-owned (no ORM model), so the sqlite harness creates it
    from this mirror. Foreign keys are omitted: sqlite does not enforce them
    without a per-connection pragma and the worker re-creates the engine per
    task, so declaring them here would only be decorative.
    """
    from sqlalchemy import JSON, Column, DateTime, String, Table, Text, func, text

    return Table(
        "ml_campaigns", metadata,
        Column("run_id", String(64), primary_key=True),
        Column("project_id", String(64), nullable=False, index=True),
        Column("org_id", String(64), nullable=True, index=True),
        Column("target_id", String(64), nullable=False, index=True),
        Column("kind", String(16), nullable=False),
        Column("modality", String(16), nullable=False),
        Column("baseline_run_id", String(64), nullable=True),
        Column("parent_run_id", String(64), nullable=True),
        Column("settings_hash", String(64), nullable=True, index=True),
        Column("config", JSON, nullable=False),
        Column("provenance", JSON, nullable=True),
        Column("score", JSON, nullable=True),
        Column("limitations", JSON, nullable=False, server_default=text("'[]'")),
        Column("reviewer_notes", Text, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("completed_at", DateTime(timezone=True), nullable=True),
    )


@dataclass
class E2EApp:
    """The assembled harness: app, storage roots, worker wiring and identity table."""

    app: FastAPI
    settings: APISettings
    harness_dir: Path
    config_path: Path
    db_path: Path
    db_url: str
    output_dir: Path
    blob_root: Path
    work_dir: Path
    assets_dir: Path
    celery_app: Any
    sandbox: SandboxController
    #: ``email -> CurrentUser``; the dev-token resolver consults it per request.
    users: dict[str, CurrentUser] = field(default_factory=dict)
    _celery_saved: dict[str, Any] = field(default_factory=dict)
    _clients: list[TestClient] = field(default_factory=list)
    _restore_sqlite_tz: Callable[[], None] | None = None

    @property
    def is_sqlite(self) -> bool:
        return self.db_url.startswith("sqlite")

    # -- database ---------------------------------------------------------

    def session(self) -> contextlib.AbstractContextManager[Session]:
        """The production ``get_session`` (commit on exit, rollback on error)."""
        from redsim.db.session import get_session

        return get_session()

    def audit_writer(self) -> Any:
        """The same ORM chain writer the API and the worker use on this database."""
        from redsim.audit.chain import PostgresAuditWriter
        from redsim.db.session import get_session

        return PostgresAuditWriter(session_factory=get_session)

    def chain_ids(self) -> list[str]:
        return sorted(self.audit_writer().iter_chain_ids())

    def read_chain(self, chain_id: str) -> list[dict[str, Any]]:
        return list(self.audit_writer().read_chain(chain_id))

    # -- identities -------------------------------------------------------

    def add_user(self, user: CurrentUser) -> CurrentUser:
        self.users[user.email] = user
        return user

    def client_for(self, user: CurrentUser | str) -> TestClient:
        """A ``TestClient`` sending ``Authorization: Bearer dev:<email>`` on every request."""
        from fastapi.testclient import TestClient

        email = user if isinstance(user, str) else user.email
        if email not in self.users:
            raise E2EHarnessError(f"no harness identity for {email!r}; call add_user() or seed_org() first")
        client = TestClient(self.app)
        client.headers.update({"Authorization": f"Bearer dev:{email}"})
        self._clients.append(client)
        return client

    # -- subprocesses -----------------------------------------------------

    def cli_argv(self, *args: str) -> list[str]:
        """The subprocess command for ``redsim <args>`` against this harness.

        ``python -m redsim.cli`` for a Postgres database; on sqlite the same
        ``redsim.cli.main.main`` is entered through a one-line bootstrap that
        first installs :func:`install_sqlite_tz_datetime`, without which the
        chain verifier cannot reproduce the hashed timestamps (see that function).
        """
        if self.is_sqlite:
            return [sys.executable, "-c", _CLI_SQLITE_BOOTSTRAP, *args]
        return [sys.executable, "-m", "redsim.cli", *args]

    def cli_env(self) -> dict[str, str]:
        """A minimal environment for the CLI subprocess against this harness.

        The worktree that owns this file is put first on ``PYTHONPATH`` so the
        subprocess runs the code under test rather than an installed copy.
        """
        env = {key: os.environ[key] for key in _CLI_SAFE_ENV_KEYS if key in os.environ}
        existing = os.environ.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(REPO_ROOT) + (os.pathsep + existing if existing else "")
        env.update({
            "REDSIM_DB_URL": self.db_url,
            "REDSIM_CONFIG": str(self.config_path),
            "REDSIM_ENV_FILE": str(self.harness_dir / "absent.env"),
            "REDSIM_BLOB_BACKEND": "fs",
            "REDSIM_BLOB_FS_PATH": str(self.blob_root),
            "REDSIM_PLUGINS": "0",
            "PYTHONUNBUFFERED": "1",
        })
        return env

    # -- lifecycle --------------------------------------------------------

    def close(self) -> None:
        import redsim.api.middleware.rate_limit as rate_limit

        for client in self._clients:
            with contextlib.suppress(Exception):
                client.close()
        self._clients.clear()
        for key, value in self._celery_saved.items():
            self.celery_app.conf[key] = value
        self.sandbox.restore()
        rate_limit._BUCKETS.clear()
        unload_bundled_targets()
        with contextlib.suppress(Exception):
            from redsim.db import session as db_session

            if db_session._ENGINE is not None:
                db_session._ENGINE.dispose()
        if self._restore_sqlite_tz is not None:
            self._restore_sqlite_tz()
            self._restore_sqlite_tz = None


def build_harness(monkeypatch: pytest.MonkeyPatch, harness_dir: Path, *, assets_dir: Path,
                  sandbox_mode: SandboxMode = "child") -> E2EApp:
    """Assemble the app over a file-backed sqlite database with eager Celery.

    Steps, in order: write ``redsim.yaml`` (output dir) and point ``REDSIM_CONFIG``
    at it; set ``REDSIM_DB_URL`` / blob / work-dir variables; create the schema
    (ORM tables plus the migration-owned ``ml_campaigns`` mirror) in WAL mode;
    put the shared Celery app in eager+propagate mode; silence the Redis event
    publisher (no broker here); build the FastAPI app in dev auth mode with the
    rate limiter effectively off; install the identity-table dev-token resolver;
    install the sandbox controller.
    """
    from sqlalchemy import MetaData

    import redsim.api.auth as auth_module
    import redsim.api.middleware.rate_limit as rate_limit
    import redsim.workers.events as events_module
    from redsim.api.app import create_app
    from redsim.api.settings import APISettings
    from redsim.db import session as db_session
    from redsim.db.models import Base
    from redsim.workers.celery_app import app as celery_app
    from tests.conftest import patch_jsonb_for_sqlite

    harness_dir = Path(harness_dir)
    output_dir = harness_dir / "output"
    blob_root = harness_dir / "blobs"
    work_dir = harness_dir / "ml_work"
    for path in (output_dir, blob_root, work_dir):
        path.mkdir(parents=True, exist_ok=True)
    db_path = harness_dir / "e2e.db"
    db_url = f"sqlite:///{db_path}"
    config_path = harness_dir / "redsim.yaml"
    config_path.write_text(f"output_dir: {json.dumps(str(output_dir))}\n", encoding="utf-8")

    monkeypatch.setenv("REDSIM_CONFIG", str(config_path))
    monkeypatch.setenv("REDSIM_DB_URL", db_url)
    monkeypatch.setenv("REDSIM_BLOB_BACKEND", "fs")
    monkeypatch.setenv("REDSIM_BLOB_FS_PATH", str(blob_root))
    monkeypatch.setenv("REDSIM_ML_WORK_DIR", str(work_dir))
    monkeypatch.setenv("REDSIM_ENV", "dev")
    monkeypatch.setenv("REDSIM_AUTH_MODE", "dev")
    monkeypatch.delenv("REDSIM_TEST_AUDIT", raising=False)

    patch_jsonb_for_sqlite()
    restore_sqlite_tz = install_sqlite_tz_datetime()
    engine = db_session.init_engine(db_url)
    with engine.begin() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode=WAL")
    Base.metadata.create_all(engine)
    campaign_table(MetaData()).create(engine, checkfirst=True)

    celery_saved = {
        key: celery_app.conf.get(key)
        for key in ("task_always_eager", "task_eager_propagate", "task_store_eager_result")
    }
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagate = True
    celery_app.conf.task_store_eager_result = False

    # The WebSocket event stream is a live-UI convenience over Redis; the harness
    # has no broker, so the publisher degrades to its documented no-op path.
    monkeypatch.setattr(events_module, "_redis_client", lambda: None)

    rate_limit._BUCKETS.clear()
    settings = APISettings(
        env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
        rate_limit_per_user_per_min=1_000_000, rate_limit_per_project_per_min=1_000_000,
        db_url=db_url, output_dir=str(output_dir), blob_backend="fs",
    )
    app = create_app(settings)

    users: dict[str, CurrentUser] = {}
    original_dev_user = auth_module._dev_user

    def _dev_user(token: str) -> CurrentUser:
        _, _, email = token.partition(":")
        known = users.get(email.strip())
        return known if known is not None else original_dev_user(token)

    monkeypatch.setattr(auth_module, "_dev_user", _dev_user)

    return E2EApp(
        app=app, settings=settings, harness_dir=harness_dir, config_path=config_path,
        db_path=db_path, db_url=db_url, output_dir=output_dir, blob_root=blob_root,
        work_dir=work_dir, assets_dir=Path(assets_dir), celery_app=celery_app,
        sandbox=SandboxController(sandbox_mode), users=users, _celery_saved=celery_saved,
        _restore_sqlite_tz=restore_sqlite_tz,
    )


# ---------------------------------------------------------------------------
# Organisation, roles, clients
# ---------------------------------------------------------------------------


@dataclass
class E2EOrg:
    """Two organisations, one project each, one identity per role on the first."""

    org_id: str
    project_id: str
    other_org_id: str
    other_project_id: str
    users: dict[str, CurrentUser]
    clients: dict[str, TestClient]

    def user(self, identity: str) -> CurrentUser:
        try:
            return self.users[identity]
        except KeyError:
            raise E2EHarnessError(f"unknown identity {identity!r}; one of {ALL_IDENTITIES}") from None

    def client(self, identity: str) -> TestClient:
        """``viewer`` | ``scanner`` | ``remediator`` | ``approver`` | ``admin`` | ``outsider`` | ``stranger``."""
        try:
            return self.clients[identity]
        except KeyError:
            raise E2EHarnessError(f"unknown identity {identity!r}; one of {ALL_IDENTITIES}") from None

    def actor(self, identity: str) -> str:
        """The audit actor string the API records for this identity (``user:<sub>``)."""
        return f"user:{self.user(identity).sub}"


def identity_email(identity: str) -> str:
    return f"{identity}@{IDENTITY_DOMAIN}"


def seed_org(harness: E2EApp) -> E2EOrg:
    """Create both organisations, both projects, the role users and their memberships.

    Memberships are written twice on purpose: on the ``CurrentUser`` the token
    resolves to (what ``check`` / ``ensure_project_access`` read) and as
    ``project_memberships`` rows (what ``/v1/projects`` and the membership
    listing read), so both views agree.
    """
    from redsim.api.auth import CurrentUser
    from redsim.db.models import Organization, Project, ProjectMembership, User

    memberships: dict[str, dict[str, str]] = {role: {PROJECT_ID: role} for role in ROLES}
    memberships[OUTSIDER] = {OTHER_PROJECT_ID: "admin"}
    memberships[STRANGER] = {}

    with harness.session() as sess:
        if sess.get(Organization, ORG_ID) is None:
            sess.add(Organization(id=ORG_ID, name="E2E organisation", slug=ORG_SLUG))
            sess.add(Organization(id=OTHER_ORG_ID, name="E2E other organisation", slug=OTHER_ORG_SLUG))
            sess.flush()
            sess.add(Project(id=PROJECT_ID, org_id=ORG_ID, name="E2E project", slug=PROJECT_SLUG))
            sess.add(Project(id=OTHER_PROJECT_ID, org_id=OTHER_ORG_ID, name="E2E other project",
                             slug=OTHER_PROJECT_SLUG))
            sess.flush()
            for identity, roles in memberships.items():
                user_id = f"user-e2e-{identity}"
                sess.add(User(id=user_id, sub=f"dev:{identity_email(identity)}",
                              email=identity_email(identity), display_name=f"E2E {identity}"))
                sess.flush()
                for project_id, role in roles.items():
                    sess.add(ProjectMembership(user_id=user_id, project_id=project_id, role=role))
            sess.flush()

    users: dict[str, CurrentUser] = {}
    clients: dict[str, TestClient] = {}
    for identity, roles in memberships.items():
        email = identity_email(identity)
        user = CurrentUser(sub=f"dev:{email}", email=email, display_name=f"E2E {identity}",
                           project_memberships=dict(roles), is_system=False)
        harness.add_user(user)
        users[identity] = user
        clients[identity] = harness.client_for(user)
    return E2EOrg(org_id=ORG_ID, project_id=PROJECT_ID, other_org_id=OTHER_ORG_ID,
                  other_project_id=OTHER_PROJECT_ID, users=users, clients=clients)


# ---------------------------------------------------------------------------
# Bundled model registration
# ---------------------------------------------------------------------------


def _extract_model_id(result: Any, fallback: str) -> str:
    if isinstance(result, str):
        return result
    if isinstance(result, Mapping):
        for key in ("id", "model_id", "target_id"):
            if result.get(key):
                return str(result[key])
        return fallback
    for attr in ("id", "model_id", "target_id"):
        value = getattr(result, attr, None)
        if isinstance(value, str) and value:
            return value
    return fallback


def register_bundled(harness: E2EApp, client: TestClient, *, project_id: str, bundled_id: str,
                     actor: str, prefer_route: bool = False) -> str:
    """Register one bundled target into ``project_id`` and return its model id.

    Uses ``redsim.services.ml_models.register_bundled_model(session, project_id,
    bundled_id, actor)`` when that wave-2 service is present on the tree (it puts
    the weights blob and writes the ``model.register`` audit row before the
    Target), otherwise ``POST /v1/models`` with ``source=bundled`` through
    ``client``, whose identity must hold ``model.register`` (remediator or above).
    ``prefer_route=True`` always takes the route.
    """
    from redsim.services import ml_models

    service = getattr(ml_models, "register_bundled_model", None)
    if service is not None and not prefer_route:
        with harness.session() as sess:
            result = service(sess, project_id, bundled_id, actor)
        return _extract_model_id(result, bundled_id)

    response = client.post("/v1/models", json={
        "source": "bundled", "bundled_id": bundled_id, "project_id": project_id,
    })
    if response.status_code not in (200, 201):
        raise E2EHarnessError(
            f"POST /v1/models for bundled {bundled_id!r} answered {response.status_code}: {response.text}"
        )
    body = response.json()
    return _extract_model_id(body, bundled_id)


def register_all_bundled(harness: E2EApp, org: E2EOrg, *, identity: str = "remediator") -> dict[str, str]:
    """``{bundled_id: model_id}`` for every id in :data:`BUNDLED_IDS`."""
    client = org.client(identity)
    actor = org.actor(identity)
    return {
        bundled_id: register_bundled(harness, client, project_id=org.project_id,
                                     bundled_id=bundled_id, actor=actor)
        for bundled_id in BUNDLED_IDS
    }


# ---------------------------------------------------------------------------
# Campaign configurations sized for the tiny assets
# ---------------------------------------------------------------------------


def image_campaign(**overrides: Any) -> dict[str, Any]:
    """FGSM + PGD on the default L-inf grid, 12 samples (4 per class) from the 24-image slice.

    ``dataset_id`` is filled by :func:`run_campaign_via_api` from the model's
    manifest when absent, so the id the builder recorded is never guessed.
    """
    body: dict[str, Any] = {
        "attack_ids": ["fgsm", "pgd"],
        "attack_params": {"pgd": {"max_iter": 3}},
        "eps_grid": [0.01, 0.03, 0.1],
        "reference_eps": 0.03,
        "n_samples": 12,
        "seed": 0,
        "explain_k": 2,
        "include_control": True,
    }
    body.update(overrides)
    return body


def tabular_campaign(**overrides: Any) -> dict[str, Any]:
    """PGD (surrogate transfer) + HopSkipJump with the small query budget the ml tier uses; 12 rows."""
    body: dict[str, Any] = {
        "attack_ids": ["pgd", "hopskipjump"],
        "attack_params": {
            "pgd": {"max_iter": 3},
            "hopskipjump": {"max_iter": 1, "max_eval": 100, "init_eval": 10, "init_size": 3},
        },
        "eps_grid": [0.01, 0.03, 0.1],
        "reference_eps": 0.03,
        "n_samples": 12,
        "seed": 0,
        "explain_k": 2,
        "include_control": True,
    }
    body.update(overrides)
    return body


# ---------------------------------------------------------------------------
# Driving a campaign through the API
# ---------------------------------------------------------------------------


@dataclass
class CampaignRun:
    """What one API-driven campaign left behind."""

    run_id: str
    job_ids: list[str]
    launch: dict[str, Any]
    run: dict[str, Any]
    campaign: dict[str, Any] | None
    campaign_status: int
    campaign_error: Any | None = None

    @property
    def status(self) -> str:
        return str(self.run.get("status"))

    @property
    def succeeded(self) -> bool:
        return self.status == "succeeded" and self.campaign is not None

    @property
    def stage_table(self) -> dict[str, Any]:
        table = self.run.get("stage_table")
        return dict(table) if isinstance(table, dict) else {}

    @property
    def findings(self) -> list[dict[str, Any]]:
        if self.campaign is None:
            return []
        rows = self.campaign.get("findings")
        return list(rows) if isinstance(rows, list) else []


def model_record(client: TestClient, model_id: str, *, project_id: str | None = None) -> dict[str, Any]:
    params = {"project": project_id} if project_id else None
    response = client.get(f"/v1/models/{model_id}", params=params)
    if response.status_code != 200:
        raise E2EHarnessError(f"GET /v1/models/{model_id} answered {response.status_code}: {response.text}")
    body: dict[str, Any] = response.json()
    return body


def wait_for_run(client: TestClient, run_id: str, *, timeout_s: float = 10.0,
                 poll_interval_s: float = 0.1) -> dict[str, Any]:
    """Poll ``GET /v1/runs/{id}`` until a terminal status; eager Celery makes this one round trip."""
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while True:
        response = client.get(f"/v1/runs/{run_id}")
        if response.status_code != 200:
            raise E2EHarnessError(f"GET /v1/runs/{run_id} answered {response.status_code}: {response.text}")
        last = response.json()
        if last.get("status") in TERMINAL_RUN_STATUSES:
            return last
        if time.monotonic() >= deadline:
            raise E2EHarnessError(
                f"run {run_id} is still {last.get('status')!r} after {timeout_s}s; the harness expects eager "
                f"Celery (task_always_eager) so a POST returns with the run already terminal. "
                f"stage_table={last.get('stage_table')!r}"
            )
        time.sleep(poll_interval_s)


def run_campaign_via_api(client: TestClient, model_id: str, config: Mapping[str, Any], *,
                         project_id: str | None = None, timeout_s: float = 10.0,
                         sandbox_mode: SandboxMode | None = None) -> CampaignRun:
    """POST the campaign, wait for the eager run, return ``GET /v1/runs/{id}/campaign``.

    ``config`` is the ``POST /v1/models/{id}/attacks`` body (see
    :func:`image_campaign` / :func:`tabular_campaign`); ``dataset_id`` and
    ``dataset_revision`` are copied from the model's manifest when absent. A
    non-202 launch raises :class:`CampaignLaunchRefused` carrying the 17.3
    ``detail``; tests asserting refusal codes should call the route directly.
    The returned :class:`CampaignRun` carries the terminal ``/v1/runs/{id}``
    row and the campaign record (``None`` with the error detail when the record
    route refuses, for example after a failed campaign).

    ``sandbox_mode`` documents the mode the caller expects; when it is ``child``
    and the body requests an LLM narrative while a developer ``.env`` is in the
    child's reach, the launch is refused here rather than letting the child
    contact a real gateway from a test.
    """
    body = dict(config)
    if "dataset_id" not in body or "dataset_revision" not in body:
        manifest = model_record(client, model_id, project_id=project_id).get("manifest") or {}
        if isinstance(manifest, dict):
            body.setdefault("dataset_id", manifest.get("dataset_id"))
            if manifest.get("dataset_revision"):
                body.setdefault("dataset_revision", manifest.get("dataset_revision"))
    if body.get("llm_narrative") and (sandbox_mode or "child") == "child":
        env_file = developer_env_file_in_reach()
        if env_file is not None:
            raise E2EHarnessError(
                f"llm_narrative=True in child-sandbox mode while {env_file} exists: the sandbox child strips "
                "PYTHIA_* from its environment and would read that file, contacting a real gateway from a "
                "test. Use the pythia fixture (pythia.on() runs the campaign in-process against a mock "
                "transport) or e2e_app.sandbox.use('inprocess')."
            )

    response = client.post(f"/v1/models/{model_id}/attacks", json=body)
    if response.status_code != 202:
        detail: Any
        try:
            detail = response.json().get("detail")
        except ValueError:
            detail = response.text
        raise CampaignLaunchRefused(response.status_code, detail)
    launch: dict[str, Any] = response.json()
    run_id = str(launch["run_id"])
    job_ids = [str(item) for item in launch.get("job_ids", [])]

    run = wait_for_run(client, run_id, timeout_s=timeout_s)
    record_response = client.get(f"/v1/runs/{run_id}/campaign")
    campaign: dict[str, Any] | None = None
    error: Any | None = None
    if record_response.status_code == 200:
        campaign = record_response.json()
    else:
        try:
            error = record_response.json().get("detail")
        except ValueError:
            error = record_response.text
    return CampaignRun(run_id=run_id, job_ids=job_ids, launch=launch, run=run, campaign=campaign,
                       campaign_status=record_response.status_code, campaign_error=error)


# ---------------------------------------------------------------------------
# Pythia: mocked gateway toggle
# ---------------------------------------------------------------------------

NarrativeSource = str | Callable[[dict[str, Any]], str] | None


def canned_narrative(payload_text: str) -> str:
    """One ``[r.X]`` paragraph per candidate, built only from words already in the payload.

    Copies each candidate's title and ``triggered_by`` ids from the user message
    and adds a fixed sentence with no digits, so the writer's numeric-consistency
    and banned-word post-checks pass and the recommendations come back with
    ``narrative_source="llm"``.
    """
    paragraphs: list[str] = []
    current: tuple[str, str] | None = None
    for line in payload_text.splitlines():
        match = _REC_LINE.match(line)
        if match:
            if current is not None:
                paragraphs.append(_paragraph(current, None))
            current = (match.group(1), match.group(2).strip())
            continue
        triggered = _TRIGGERED_LINE.match(line)
        if triggered and current is not None:
            paragraphs.append(_paragraph(current, triggered.group(1).strip()))
            current = None
    if current is not None:
        paragraphs.append(_paragraph(current, None))
    if not paragraphs:
        return "No candidate recommendations were listed in the input, so there is nothing to rephrase."
    return "\n\n".join(paragraphs)


def _paragraph(rec: tuple[str, str], triggered_by: str | None) -> str:
    rec_id, title = rec
    basis = f" It was triggered by {triggered_by}." if triggered_by else ""
    return (f"[{rec_id}] {title}.{basis} This is a candidate recommendation that has not been "
            "evaluated on this model; the direction is as the rule layer states it.")


class PythiaToggle:
    """Switch a mocked Pythia gateway on and off for the whole harness.

    ``on()`` exports the three variables ``PythiaSettings.from_env`` requires
    (pointing at an ``.invalid`` host with a placeholder key), replaces
    ``redsim.llm.pythia.make_backend`` with the in-repo httpx client over an
    ``httpx.MockTransport``, and forces the in-process sandbox because the child
    process strips ``PYTHIA_*``. Every request the writer makes is recorded in
    ``requests`` (method, URL, headers, JSON body). ``off()`` restores all of it.

    ``disable_llm(True)`` sets ``REDSIM_DISABLE_LLM=1`` independently of the
    gateway state, so a test can prove the compose-worker default leaves the
    rule text standing whatever the gateway would say.
    """

    def __init__(self, harness: E2EApp) -> None:
        self.harness = harness
        self.enabled = False
        self.requests: list[dict[str, Any]] = []
        self._narrative: NarrativeSource = None
        self._status_code = 200
        self._saved_env: dict[str, str | None] = {}
        self._saved_make_backend: Callable[..., Any] | None = None
        self._saved_sandbox_mode: SandboxMode | None = None

    # -- switches ---------------------------------------------------------

    def on(self, *, narrative: NarrativeSource = None, status_code: int = 200,
           force_inprocess: bool = True) -> PythiaToggle:
        """Enable the mock. ``narrative`` overrides the canned text (a string or ``payload -> str``);
        ``status_code`` other than 200 makes the gateway fail so the writer degrades to rules."""
        from redsim.llm import pythia

        if self.enabled:
            self.off()
        self._narrative = narrative
        self._status_code = status_code
        self.requests.clear()
        for key, value in (
            ("PYTHIA_BASE_URL", MOCK_PYTHIA_BASE_URL),
            ("PYTHIA_API_KEY", MOCK_PYTHIA_API_KEY),
            (pythia.MODEL_ENV, MOCK_PYTHIA_MODEL),
            ("PYTHIA_PERSONA", None),
        ):
            self._saved_env[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._saved_make_backend = pythia.make_backend
        transport = self.transport()

        def make_backend(settings: pythia.PythiaSettings, transport_override: Any = None) -> Any:
            return pythia._HttpxBackend(settings, transport=transport_override or transport)

        pythia.make_backend = make_backend  # type: ignore[assignment]
        if force_inprocess and self.harness.sandbox.mode != "inprocess":
            self._saved_sandbox_mode = self.harness.sandbox.mode
            self.harness.sandbox.set("inprocess")
        self.enabled = True
        return self

    def off(self) -> None:
        if not self.enabled:
            return
        from redsim.llm import pythia

        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._saved_env.clear()
        if self._saved_make_backend is not None:
            pythia.make_backend = self._saved_make_backend
            self._saved_make_backend = None
        if self._saved_sandbox_mode is not None:
            self.harness.sandbox.set(self._saved_sandbox_mode)
            self._saved_sandbox_mode = None
        self.enabled = False

    def disable_llm(self, disabled: bool = True) -> None:
        """``REDSIM_DISABLE_LLM=1`` (the compose worker default) on or off."""
        if disabled:
            os.environ["REDSIM_DISABLE_LLM"] = "1"
        else:
            os.environ.pop("REDSIM_DISABLE_LLM", None)

    def __enter__(self) -> PythiaToggle:
        return self.on() if not self.enabled else self

    def __exit__(self, *exc: object) -> None:
        self.off()

    # -- the mocked gateway ----------------------------------------------

    def transport(self) -> httpx.MockTransport:
        import httpx

        return httpx.MockTransport(self.handler)

    def handler(self, request: httpx.Request) -> httpx.Response:
        import httpx

        body: dict[str, Any] = {}
        with contextlib.suppress(ValueError):
            parsed = json.loads(request.content or b"{}")
            if isinstance(parsed, dict):
                body = parsed
        self.requests.append({
            "method": request.method,
            "url": str(request.url),
            "headers": dict(request.headers),
            "json": body,
        })
        if self._status_code != 200:
            return httpx.Response(self._status_code, json={"error": {"message": "e2e mock gateway failure"}})
        payload_text = self.last_payload() or ""
        if callable(self._narrative):
            text = self._narrative(body)
        elif isinstance(self._narrative, str):
            text = self._narrative
        else:
            text = canned_narrative(payload_text)
        return httpx.Response(200, json={
            "id": "chatcmpl-e2e",
            "object": "chat.completion",
            "model": body.get("model", MOCK_PYTHIA_MODEL),
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        })

    def last_payload(self) -> str | None:
        """The ``user`` message of the most recent request (the writer's text-only payload)."""
        if not self.requests:
            return None
        messages = self.requests[-1]["json"].get("messages") or []
        for message in reversed(messages):
            if isinstance(message, dict) and message.get("role") == "user":
                content = message.get("content")
                return content if isinstance(content, str) else json.dumps(content)
        return None


# ---------------------------------------------------------------------------
# Audit: CLI verification and tampering
# ---------------------------------------------------------------------------


def audit_verify_all(harness: E2EApp, *, timeout_s: float = 180.0) -> tuple[int, str]:
    """Run ``redsim audit verify --all`` as a subprocess against the harness database.

    Returns ``(exit_code, output)`` where ``output`` is stdout followed by stderr
    with colours stripped. Exit ``0`` means every chain verified; ``1`` names the
    broken chain and sequence number (``broken at seq=...``). The command is
    :meth:`E2EApp.cli_argv`; the environment :meth:`E2EApp.cli_env`.
    """
    completed = subprocess.run(
        harness.cli_argv("audit", "verify", "--all"),
        cwd=str(harness.harness_dir), env=harness.cli_env(),
        capture_output=True, text=True, timeout=timeout_s, check=False,
    )
    output = strip_ansi(completed.stdout) + (("\n" + strip_ansi(completed.stderr)) if completed.stderr else "")
    return completed.returncode, output.strip()


TamperField = Literal["detail", "actor", "action", "success"]


def tamper_audit_event(harness: E2EApp, *, chain_id: str | None = None, seq: int | None = None,
                       mutation: TamperField = "detail") -> tuple[str, int]:
    """Mutate one stored audit event in place and return ``(chain_id, seq)``.

    Defaults to a ``run:`` chain when one exists (else the first chain) and to
    the middle event, so both the event's own hash and the next event's
    ``prev_hash`` stop matching. On Postgres the append-only trigger of
    migration 0007 refuses the UPDATE; the raised :class:`E2EHarnessError` says
    so, because that refusal is itself the property under test there.
    """
    from sqlalchemy import select

    from redsim.db.models import AuditEvent

    with harness.session() as sess:
        if chain_id is None:
            ids = harness.chain_ids()
            if not ids:
                raise E2EHarnessError("no audit chains exist yet; run a campaign first")
            chain_id = next((cid for cid in ids if cid.startswith("run:")), ids[0])
        rows = sess.execute(
            select(AuditEvent).where(AuditEvent.chain_id == chain_id).order_by(AuditEvent.seq)
        ).scalars().all()
        if not rows:
            raise E2EHarnessError(f"audit chain {chain_id!r} has no events")
        if seq is None:
            row = rows[len(rows) // 2]
        else:
            matches = [item for item in rows if item.seq == seq]
            if not matches:
                raise E2EHarnessError(f"audit chain {chain_id!r} has no event with seq={seq}")
            row = matches[0]
        try:
            if mutation == "detail":
                row.detail = {**dict(row.detail or {}), "tampered": True}
            elif mutation == "actor":
                row.actor = f"{row.actor}-tampered"
            elif mutation == "action":
                row.action = f"tampered.{row.action}"
            elif mutation == "success":
                row.success = not bool(row.success)
            else:
                raise E2EHarnessError(f"unknown mutation {mutation!r}")
            sess.flush()
        except E2EHarnessError:
            raise
        except Exception as exc:  # noqa: BLE001 - surface the append-only guard as a harness message
            raise E2EHarnessError(
                f"could not tamper with {chain_id!r} seq={row.seq}: {type(exc).__name__}: {exc}. On Postgres "
                "the audit_events append-only trigger refuses updates by design; tamper tests there must "
                "target the trigger, not the row."
            ) from exc
        return chain_id, int(row.seq)


# ---------------------------------------------------------------------------
# Postgres lane
# ---------------------------------------------------------------------------


def postgres_url_from_env(environ: Mapping[str, str] | None = None) -> str | None:
    env = os.environ if environ is None else environ
    value = env.get(POSTGRES_URL_ENV, "").strip()
    return value or None


def check_postgres_migrated(url: str) -> None:
    """Fail loudly (never skip) when the RLS-lane database is reachable but not migrated."""
    from sqlalchemy import create_engine, inspect

    engine = create_engine(url, future=True)
    try:
        with engine.connect() as conn:
            inspector = inspect(conn)
            missing = [name for name in ("ml_campaigns", "audit_events", "targets")
                       if not inspector.has_table(name)]
    finally:
        engine.dispose()
    if missing:
        raise E2EHarnessError(
            f"{POSTGRES_URL_ENV} points at a database without {missing}; run "
            f"`REDSIM_DB_URL=<url> alembic upgrade head` first (tests/e2e/README.md, Postgres lane)."
        )


__all__ = [
    "ALL_IDENTITIES",
    "BUNDLED_IDS",
    "E2E_ENV",
    "IMAGE_CLASS_NAMES",
    "IMAGE_DATASET_ID",
    "IMAGE_MODEL_ID",
    "MOCK_PYTHIA_API_KEY",
    "MOCK_PYTHIA_BASE_URL",
    "MOCK_PYTHIA_MODEL",
    "ORG_ID",
    "OTHER_ORG_ID",
    "OTHER_PROJECT_ID",
    "OUTSIDER",
    "POSTGRES_URL_ENV",
    "PROJECT_ID",
    "REPO_ROOT",
    "ROLES",
    "SANDBOX_MODE_ENV",
    "STRANGER",
    "TABULAR_MODEL_ID",
    "TERMINAL_RUN_STATUSES",
    "CampaignLaunchRefused",
    "CampaignRun",
    "E2EApp",
    "E2EHarnessError",
    "E2EOrg",
    "PythiaToggle",
    "SandboxController",
    "SandboxMode",
    "asset_dataset_ids",
    "asset_manifest",
    "audit_verify_all",
    "build_harness",
    "build_tiny_assets",
    "campaign_table",
    "canned_narrative",
    "check_postgres_migrated",
    "developer_env_file_in_reach",
    "e2e_enabled",
    "identity_email",
    "image_campaign",
    "install_sqlite_tz_datetime",
    "model_record",
    "postgres_url_from_env",
    "register_all_bundled",
    "register_bundled",
    "require_e2e",
    "run_campaign_inprocess",
    "run_campaign_via_api",
    "sandbox_mode_from_env",
    "sanitize_environment",
    "seed_org",
    "strip_ansi",
    "synthetic_images",
    "tabular_campaign",
    "tamper_audit_event",
    "unload_bundled_targets",
    "wait_for_run",
]
