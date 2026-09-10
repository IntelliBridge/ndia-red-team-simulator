"""Docs-versus-tree consistency for Phase B and the gate that runs it (plan 12 wave B4, phase-b-gate track).

Register rows TESTS_DOCS-36 (the gate), -18 to -23 and -26 (the test half). Spec
26.11 says no document claims what did not happen and 26.24 says every
unsupported path is visible as not implemented with a reason: this module is the
executable form of those two criteria for the Phase B documentation, plus the
unit test of the gate's HTTP probe logic. Everything here is offline: the
documents are parsed from the tree, the app is built in this process over an
in-memory sqlite (the one route test), and the probe program is driven through a
fake HTTP layer.

What is asserted, and who owns the fix when it fails:

* every test file the spec section 22 addendum and ``docs/dev/testing.md`` name
  exists (a doc naming a test that is not on the tree is a claim of evidence that
  does not exist, 26.11);
* every route in the Phase B table of ``docs/api/v1.md`` is mounted (compared
  with the app's OpenAPI document) and its status column says "landed" exactly
  when the handler is not a wave B0 ``501 not_implemented`` stub for an allowed
  role (26.24);
* the README "Open items" section names the web UI, the owner decisions and the
  remaining-work brief (26.11);
* no document still says "open PR #23" (it merged as ``10650da``) or "not
  started" of a Phase B wave, B0 to B4 (26.11). The wave a sentence is about is
  the nearest ``B<n>`` before the phrase in the same sentence or table cell,
  else the row's subject cell, else the enclosing heading, so "B0 to B3 landed,
  B4 not started" is a claim about B4 only;
* the mkdocs nav lists plans 10, 11 and 12 so a reader can find them;
* since the verify paradigm removal of 2026-09-09 (product owner decision,
  ``docs/project-brief.md`` item 16, master plan section 5) no page that
  describes the tree names the removed loop as a present feature: no sentence
  of the root pages or of ``docs/`` (outside the dated history set below)
  carries a verify-loop, defense-catalog, validation-state or delta token
  unless that same sentence names the 2026-09-09 removal, and the four removed
  routes are neither documented as mounted nor mounted (26.11, 26.24);
* ``scripts/phase_b_gate.sh`` is provably discriminating: its probe program,
  run against a fake stack whose Phase B routes still answer ``501`` for an
  allowed role, fails and names the spec 26 criterion; its garak step, driven
  with a fake interpreter, fails on pytest exit 5 (nothing collected), on a run
  in which no test passed and on a missing garak extra, and passes only when
  garak-marked tests ran; ``make check-phase-b`` and the ``e2e-python`` /
  ``garak-offline`` CI jobs call the same script.

A failure outside this track's files is reported with an attribution prefix in
square brackets naming the file to fix, never by weakening the assertion. The
dated registers ``docs/plans/09-*``, ``10-*`` and ``11-*`` are audits of an
earlier state and quote the stale phrases as work items, so they are excluded
from the stale-phrase scan and say so here. The verify-token scan excludes a
larger history set: the product spec (its dated banner marks the loop sections
as history), the superseded design documents, the ADRs, the brief (the decision
record) and every dated plan and register except ``EXECUTION-CONTEXT.md``,
which describes the tree.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import types
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC = REPO_ROOT / "docs" / "superpowers" / "specs" / "2026-09-08-adversarial-ml-redteam-spec.md"
TESTING_MD = REPO_ROOT / "docs" / "dev" / "testing.md"
API_MD = REPO_ROOT / "docs" / "api" / "v1.md"
README = REPO_ROOT / "README.md"
MKDOCS = REPO_ROOT / "mkdocs.yml"
GATE = REPO_ROOT / "scripts" / "phase_b_gate.sh"
MAKEFILE = REPO_ROOT / "Makefile"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "redsim-ci.yml"

#: Documents scanned for stale phrases: the root pages plus every page under docs/.
ROOT_DOCS = ("README.md", "CLAUDE.md", "SECURITY.md", "CONTRIBUTING.md")
#: Dated audits that quote the stale phrases as work items; rewriting them would falsify history.
STALE_SCAN_EXCLUDED = {
    "docs/plans/09-gap-register-2026-09-08.md",
    "docs/plans/10-remaining-work-brief.md",
    "docs/plans/11-phase-b-register-2026-09-09.md",
}
#: History kept on purpose after the verify paradigm removal (2026-09-09): excluded from the verify-token scan.
VERIFY_HISTORY_EXCLUDED_PREFIXES = (
    "docs/superpowers/",
    "docs/adversarial-ml-redteam-spec.md",
    "docs/adr/",
    "docs/project-brief.md",
)
VERIFY_HISTORY_EXCLUDED_PLANS = re.compile(r"^docs/plans/\d{2}-")
#: Tokens of the removed loop. A sentence may carry one only when it names the 2026-09-09 removal.
STALE_VERIFY_TOKENS = (
    "verify-after-harden", "verify after harden", "verify.replay", "verify.execute", "verify_replay",
    "/v1/defenses", "/findings/{id}/verify", "/verify/bulk", "/retests",
    "MeasuredDelta", "MRIDelta", "FamilyDelta", "CleanAccuracyDelta", "verify_delta",
    "validation_state", "validated_at", "poc_passed", "poc_failed", "unvalidated",
    "defense_apply", "DefenseConfig", "defenses.py", "unknown_defense", "defense_modality_mismatch",
    "feature_squeezing", "spatial_smoothing", "jpeg_compression", "adversarial_training",
    "defensive_distillation", "train_slice", "derived_from", "ml.derived_model", "ml.training_report",
    "`ml.verify`", "Expected gain:", "baseline_run_id", "redsim_verify_status_total",
    "`redsim verify`", "redsim/verify", "verifyFinding", "useDefenses",
)
REMOVAL_WORDS = re.compile(r"\b(removed|removal|left|gone|superseded|history|deleted|drops|dropped|void)\b",
                           re.IGNORECASE)
#: The routes the removal unmounted. They must be absent from the docs and from the OpenAPI document.
REMOVED_VERIFY_ROUTES = (
    ("GET", "/v1/defenses"),
    ("POST", "/v1/findings/{finding_id}/verify"),
    ("POST", "/v1/findings/{finding_id}/verify/bulk"),
    ("GET", "/v1/findings/{finding_id}/retests"),
)
#: Test files the spec 22 addendum still names as history, deleted with the verify paradigm. They must stay absent.
REMOVED_WITH_VERIFY_PARADIGM = frozenset({"tests/ml/test_hardening.py"})
#: The plan pages the mkdocs nav must list (plan 12 wave B4 phase-b-gate brief).
NAV_PLANS = (
    "plans/10-remaining-work-brief.md",
    "plans/11-phase-b-register-2026-09-09.md",
    "plans/12-phase-b-plan.md",
)
#: The gate's steps in the order the brief fixes them (scripts/phase_b_gate.sh --list).
GATE_STEPS = ("ruff", "mypy", "unit", "ml", "garak", "e2e", "docs", "docs-consistency", "probes")

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")


def attributed_fail(owner: str, message: str) -> None:
    """Fail naming the file (and track) that owns the fix; the assertion itself is never weakened."""
    pytest.fail(f"[{owner}] {message}", pytrace=False)


def _section(text: str, start: str, end: str) -> str | None:
    """The text from the first line matching ``start`` up to (not including) the next line matching ``end``."""
    lines = text.splitlines()
    begin = next((i for i, line in enumerate(lines) if re.match(start, line)), None)
    if begin is None:
        return None
    stop = next((i for i in range(begin + 1, len(lines)) if re.match(end, lines[i])), len(lines))
    return "\n".join(lines[begin:stop])


def _table_rows(section: str) -> list[list[str]]:
    """The first markdown table of ``section`` as rows of stripped cells (header first, separator dropped)."""
    rows: list[list[str]] = []
    in_table = False
    for line in section.splitlines():
        stripped = line.strip()
        if stripped.startswith("|"):
            in_table = True
            cells = [cell.strip() for cell in stripped.strip("|").split("|")]
            if all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells if cell):
                continue
            rows.append(cells)
        elif in_table and stripped == "":
            break
        elif in_table:
            break
    return rows


# ---------------------------------------------------------------------------
# Test files named by the docs exist (26.11)
# ---------------------------------------------------------------------------


def _resolve_test_file(name: str) -> Path | None:
    """A ``tests/...py`` path as given, or a bare ``test_x.py`` located anywhere under tests/."""
    if name.startswith("tests/"):
        candidate = REPO_ROOT / name
        return candidate if candidate.is_file() else None
    matches = sorted(REPO_ROOT.joinpath("tests").rglob(name))
    return matches[0] if matches else None


def test_spec_22_addendum_names_only_test_files_that_exist() -> None:
    """26.11: the spec 22 addendum's evidence files are on the tree."""
    text = SPEC.read_text(encoding="utf-8")
    section = _section(text, r"^## 22\.", r"^## 23\.")
    assert section is not None, "spec section 22 not found"
    marker = re.search(r"addendum", section, re.IGNORECASE)
    if marker is None:
        attributed_fail("docs track: spec section 22",
                        "section 22 has no Phase B addendum naming the wave B0 to B4 test files "
                        "(plan 12 wave B4 docs track: 'the spec (22 and 26 addenda ...)')")
        return
    region = section[marker.start():]
    named = sorted(set(re.findall(r"tests/[\w./-]+?\.py", region)))
    assert named, "the spec 22 addendum names no test file"
    # The spec is history under its dated banner: the one verify test it names must stay deleted.
    resurrected = [name for name in named if name in REMOVED_WITH_VERIFY_PARADIGM and _resolve_test_file(name)]
    if resurrected:
        attributed_fail("tests/ (the verify paradigm was removed on 2026-09-09)",
                        "test files deleted with the verify paradigm are back on the tree: " + ", ".join(resurrected))
    missing = [name for name in named
               if name not in REMOVED_WITH_VERIFY_PARADIGM and _resolve_test_file(name) is None]
    if missing:
        attributed_fail("docs track: spec section 22 addendum",
                        "test files named but absent from the tree: " + ", ".join(missing))


def test_testing_md_names_only_test_files_that_exist() -> None:
    """26.11: docs/dev/testing.md names test files that exist (bare names are located under tests/)."""
    text = TESTING_MD.read_text(encoding="utf-8")
    named = sorted(set(re.findall(r"`((?:tests/[\w./-]+/)?test_\w+\.py)`", text)))
    assert named, "docs/dev/testing.md names no test file"
    missing = [name for name in named if _resolve_test_file(name) is None]
    if missing:
        attributed_fail("docs/dev/testing.md", "test files named but absent from the tree: " + ", ".join(missing))


# ---------------------------------------------------------------------------
# The Phase B route table matches the app (26.24)
# ---------------------------------------------------------------------------

PROJECT = "project-docs-1"
RUN = "run-docs-1"
TARGET = "tgt-docs-1"
FINDING = "finding-docs-1"

#: Path parameters of the documented routes, substituted before the probe call.
PATH_PARAMS = {
    "run_id": RUN, "id": RUN, "model_id": TARGET, "target_id": TARGET, "finding_id": FINDING,
    "dataset_id": RUN, "batch_id": "batch-docs-1", "ext": "pdf", "ref": "1", "slug": PROJECT,
    "transition": "confirm", "org_id": "org-docs-1", "artifact_id": "art-docs-1", "profile_id": "prof-docs-1",
    "snapshot_id": "1", "version": "1",
}


def _phase_b_table() -> list[tuple[str, str, str, str]]:
    """``(method, path, status_cell, raw_row)`` per data row of the Phase B routes table in docs/api/v1.md."""
    text = API_MD.read_text(encoding="utf-8")
    section = _section(text, r"^##+ .*Phase B routes", r"^## ")
    if section is None:
        attributed_fail("docs track: docs/api/v1.md", "no 'Phase B routes' section found")
    rows = _table_rows(section or "")
    if len(rows) < 2:
        attributed_fail("docs track: docs/api/v1.md", "the Phase B routes section has no table")
    header = [cell.lower() for cell in rows[0]]
    status_col = next((i for i, cell in enumerate(header) if "status" in cell), None)
    if status_col is None:
        attributed_fail("docs track: docs/api/v1.md", f"the Phase B table has no Status column (header {rows[0]!r})")
    method_col = next((i for i, cell in enumerate(header) if cell == "method"), None)
    path_col = next((i for i, cell in enumerate(header) if cell in {"path", "route"}), None)
    parsed: list[tuple[str, str, str, str]] = []
    for cells in rows[1:]:
        raw = " | ".join(cells)
        if method_col is not None and path_col is not None and method_col != path_col:
            method = cells[method_col].strip("` ").upper()
            path = cells[path_col].strip("` ")
        else:
            route_cell = cells[path_col] if path_col is not None else cells[0]
            match = re.search(r"(GET|POST|PUT|PATCH|DELETE)\s+(/\S+)", route_cell)
            if match is None:
                attributed_fail("docs track: docs/api/v1.md", f"cannot read a method and path from the row {raw!r}")
                continue
            method, path = match.group(1), match.group(2).strip("`")
        path = path.split("?", 1)[0].rstrip("`")
        assert method in HTTP_METHODS, raw
        parsed.append((method, path, cells[status_col] if status_col is not None and status_col < len(cells) else "",
                       raw))
    if not parsed:
        attributed_fail("docs track: docs/api/v1.md", "the Phase B table has no data rows")
    return parsed


def _template_regex(template: str) -> re.Pattern[str]:
    """An OpenAPI path template as a regex: ``{param}`` matches one non-empty segment piece."""
    return re.compile("^" + re.sub(r"\\\{[^}]+\\\}", r"[^/]+", re.escape(template)) + "$")


def _concrete(path: str) -> str:
    return re.sub(r"\{([^}]+)\}", lambda m: PATH_PARAMS.get(m.group(1), "x"), path)


def _campaign_mirror(engine: Any) -> None:
    """The migration-owned ``ml_campaigns`` shape on sqlite, empty.

    0010 plus the 0011 ``batch_id`` column, less the baseline column that 0012
    dropped with the verify paradigm. Routes that read the campaign row reflect
    this table; without it a route would raise instead of answering its typed
    refusal.
    """
    from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, Text

    Table(
        "ml_campaigns", MetaData(),
        Column("run_id", String, primary_key=True),
        Column("project_id", String, nullable=False),
        Column("org_id", String),
        Column("target_id", String, nullable=False),
        Column("kind", String, nullable=False),
        Column("modality", String, nullable=False),
        Column("config", JSON, nullable=False),
        Column("settings_hash", String),
        Column("provenance", JSON),
        Column("score", JSON),
        Column("limitations", JSON, nullable=False),
        Column("parent_run_id", String),
        Column("batch_id", String),
        Column("reviewer_notes", Text),
        Column("created_at", DateTime),
        Column("completed_at", DateTime),
    ).create(engine)


@pytest.fixture
def docs_api(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[SimpleNamespace]:
    """The real app in dev auth over an in-memory sqlite: one project with an available model, a run, a finding.

    The caller is an admin member of the project, so every gate admits it and
    the answer is the handler's own (a typed refusal, a read, or the wave B0
    ``501 not_implemented`` stub if one is left).
    """
    pytest.importorskip("fastapi")
    pytest.importorskip("sqlalchemy")
    # numpy is API-process metadata for the catalog registries (pyproject ``api`` extra).
    pytest.importorskip("numpy")
    from fastapi.testclient import TestClient

    from redsim.api.app import create_app
    from redsim.api.auth import CurrentUser, get_current_user
    from redsim.api.settings import APISettings
    from redsim.audit.chain import InMemoryAuditWriter
    from redsim.db.models import Finding, Organization, Project, Run, Target
    from tests.conftest import make_sqlite_session_factory

    factory = make_sqlite_session_factory()
    _campaign_mirror(factory.engine)
    with factory.Session() as sess:
        sess.add(Organization(id="org-docs-1", name="Org", slug="org-docs"))
        sess.add(Project(id=PROJECT, org_id="org-docs-1", name="Project", slug=PROJECT))
        sess.flush()
        sess.add(Target(id=TARGET, project_id=PROJECT, kind="ml_model_artifact", value="bundled:tiny",
                        verified=True, detail={"modality": "image", "status": "available"}))
        sess.flush()
        sess.add(Run(id=RUN, project_id=PROJECT, target_id=TARGET, mode="api", scanner="ml.campaign",
                     status="succeeded", stage_table={}))
        sess.flush()
        sess.add(Finding(id=FINDING, scanner_finding_id="ml.pgd", run_id=RUN, project_id=PROJECT,
                         schema_blob={"finding_type": "adversarial_ml", "ml": {}}, status="open",
                         severity="high", source_tool="redsim.ml/pgd"))
        sess.commit()

    monkeypatch.setattr("redsim.db.session.get_session", factory.session_cm)
    monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda _config: InMemoryAuditWriter())
    # No broker here: a route that admits a job (report.render on the seeded run) enqueues through
    # ``Task.apply_async`` (``.delay`` calls it), which would otherwise retry Redis for 20 s per call.
    import celery.app.task

    monkeypatch.setattr(celery.app.task.Task, "apply_async",
                        lambda self, *args, **kwargs: SimpleNamespace(id=f"fake-{self.name}"))
    monkeypatch.setenv("REDSIM_CONFIG", str(tmp_path / "absent.yaml"))
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(tmp_path / "no-assets"))
    monkeypatch.delenv("REDSIM_INTEGRATION_FOUNDRY_URL", raising=False)

    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    app = create_app(APISettings(
        env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
        rate_limit_per_user_per_min=10_000, rate_limit_per_project_per_min=10_000,
    ))
    admin = CurrentUser(sub="dev:docs-admin@test", email="docs-admin@test", project_memberships={PROJECT: "admin"})
    app.dependency_overrides[get_current_user] = lambda: admin
    client = TestClient(app, raise_server_exceptions=False)
    yield SimpleNamespace(app=app, client=client, openapi=app.openapi())
    rl._BUCKETS.clear()


@pytest.mark.integration
def test_phase_b_route_table_is_mounted_and_its_status_is_honest(docs_api: SimpleNamespace) -> None:
    """26.24: every documented Phase B route is mounted, and "landed" means the handler is not a 501 stub."""
    rows = _phase_b_table()
    templates = [(method.upper(), path, _template_regex(path))
                 for path, ops in docs_api.openapi["paths"].items() for method in ops]

    unmounted: list[str] = []
    mismatched: list[str] = []
    errored: list[str] = []
    for method, path, status_cell, raw in rows:
        concrete = _concrete(path)
        if not any(m == method and regex.match(concrete) for m, _p, regex in templates):
            unmounted.append(f"{method} {path}")
            continue
        body = {"project_id": PROJECT} if method in {"POST", "PUT", "PATCH"} else None
        response = docs_api.client.request(method, concrete, json=body)
        if response.status_code >= 500 and response.status_code != 501:
            errored.append(f"{method} {path} -> {response.status_code} {response.text[:200]!r}")
            continue
        detail = None
        try:
            detail = response.json().get("detail")
        except ValueError:
            pass
        is_stub = response.status_code == 501 and isinstance(detail, dict) and detail.get("code") == "not_implemented"
        says_landed = "landed" in status_cell.lower()
        if is_stub and says_landed:
            mismatched.append(f"{method} {path}: status says {status_cell!r} but an admin still gets "
                              f"501 not_implemented ({detail!r})")
        elif not is_stub and not says_landed:
            mismatched.append(f"{method} {path}: status says {status_cell!r} but the handler is real "
                              f"(an admin gets {response.status_code}, not a 501 stub)")
    if unmounted:
        attributed_fail("docs track: docs/api/v1.md",
                        "Phase B table rows that the app does not mount: " + ", ".join(unmounted))
    if errored:
        attributed_fail("redsim/api/v1 (the route modules)",
                        "Phase B routes raised instead of answering an admin: " + "; ".join(errored))
    if mismatched:
        attributed_fail("docs track: docs/api/v1.md",
                        "Phase B table status column disagrees with the app on "
                        f"{len(mismatched)} of {len(rows)} rows:\n  " + "\n  ".join(mismatched))


@pytest.mark.integration
def test_removed_verify_routes_are_neither_mounted_nor_documented(docs_api: SimpleNamespace) -> None:
    """26.24 after 2026-09-09: the four verify routes left the app, and docs/api/v1.md does not list them.

    The docs half is also covered by the verify-token scan; this test names the
    routes so a resurrected handler or a resurrected table row fails by name.
    """
    templates = [(method.upper(), regex) for path, ops in docs_api.openapi["paths"].items()
                 for method in ops for regex in [_template_regex(path)]]
    mounted = [f"{method} {path}" for method, path in REMOVED_VERIFY_ROUTES
               if any(m == method and regex.match(_concrete(path)) for m, regex in templates)]
    if mounted:
        attributed_fail("redsim/api/app.py (the verify paradigm was removed on 2026-09-09)",
                        "removed routes still mounted: " + ", ".join(mounted))
    documented = [f"{method} {path}" for method, path in _phase_b_table()
                  if any(_template_regex(removed).match(_concrete(path)) and method == m
                         for m, removed in REMOVED_VERIFY_ROUTES)]
    if documented:
        attributed_fail("docs track: docs/api/v1.md", "removed routes still in the Phase B table: " + ", ".join(documented))


# ---------------------------------------------------------------------------
# README open items, stale phrases, mkdocs nav (26.11)
# ---------------------------------------------------------------------------


def test_readme_open_items_name_the_web_ui_the_owner_decisions_and_the_brief() -> None:
    """26.11: the README's open-items list is the single honest list of what is deferred."""
    text = README.read_text(encoding="utf-8")
    section = _section(text, r"^##+ .*Open items", r"^## ")
    if section is None:
        attributed_fail("docs track: README.md", "no 'Open items' section found")
        return
    lowered = section.lower()
    missing = []
    if not re.search(r"web\s+ui", lowered):
        missing.append("the web UI")
    if "owner decision" not in lowered:
        missing.append("the owner decisions")
    if "10-remaining-work-brief" not in lowered and "remaining-work brief" not in lowered:
        missing.append("the remaining-work brief (docs/plans/10-remaining-work-brief.md)")
    if missing:
        attributed_fail("docs track: README.md", "the 'Open items' section does not name: " + ", ".join(missing))


def _scanned_docs() -> list[Path]:
    paths = [REPO_ROOT / name for name in ROOT_DOCS if (REPO_ROOT / name).is_file()]
    paths.extend(sorted(REPO_ROOT.joinpath("docs").rglob("*.md")))
    return [p for p in paths if p.relative_to(REPO_ROOT).as_posix() not in STALE_SCAN_EXCLUDED]


WAVE = re.compile(r"\bB([0-4])\b")
NOT_STARTED = re.compile(r"not\s+started", re.IGNORECASE)
HEADING = re.compile(r"^#+\s+(.*)")


def wave_said_not_started(line: str, heading: str = "") -> str | None:
    """The Phase B wave (``B0`` to ``B4``) ``line`` says is not started, or ``None``.

    The wave is the one the phrase is about: the nearest ``B<n>`` before "not
    started" in the same sentence or table cell, else the subject cell of a table
    row, else the enclosing ``heading``. A wave named after the phrase, or in
    another sentence of the line, is not its subject: "B0, B1, B2 and B3 landed,
    B4 not started" is about B4, and a row whose status cell reads "Not started.
    It owes the e2e files for everything B2 and B3 built" is about the wave in
    its first cell.
    """
    match = NOT_STARTED.search(line)
    if match is None:
        return None
    before = line[:match.start()]
    segment_start = max(before.rfind("|"), before.rfind(". "), before.rfind("; ")) + 1
    waves = WAVE.findall(before[segment_start:])
    if waves:
        return "B" + waves[-1]
    if line.lstrip().startswith("|"):
        cells = line.strip().strip("|").split("|")
        subject = WAVE.findall(cells[0]) if cells else []
        if subject:
            return "B" + subject[-1]
    in_heading = WAVE.findall(heading)
    return "B" + in_heading[-1] if in_heading else None


def test_wave_said_not_started_reads_the_subject_of_the_sentence() -> None:
    """The heuristic's own contract: the subject wave, never a wave that merely shares the line."""
    assert wave_said_not_started("B0, B1, B2 and B3 landed, B4 not started; no route is a stub") == "B4"
    assert wave_said_not_started("| Phase B wave B4 (e2e, gate, docs) | Not started. It owes the files B2 and B3 built |") == "B4"
    assert wave_said_not_started("| evidence | `tests/e2e/x.py` | wave B4 (`e2e-endpoint-llm`), not started. |") == "B4"
    assert wave_said_not_started("Status (2026-09-09): not started. Items B0 and B1 made true.", "### Wave B4: gate") == "B4"
    assert wave_said_not_started("Wave B2 is not started.") == "B2"
    assert wave_said_not_started("| B1 | not started |") == "B1"
    assert wave_said_not_started("Status: not started.", "## 6. Completion checks") is None
    assert wave_said_not_started("B3 landed; the plan-07 rewrite is not started.") is None
    assert wave_said_not_started("nothing to see here B2") is None


def test_no_doc_says_open_pr_23_or_not_started_for_waves_b0_to_b4() -> None:
    """26.11: PR #23 merged (``10650da``) and waves B0 to B4 are on the tree; no page may say otherwise.

    B4 is the wave this gate belongs to: a document that still calls it "not
    started" once the gate passes is exactly the claim 26.11 forbids.
    """
    open_pr: list[str] = []
    not_started: list[str] = []
    for path in _scanned_docs():
        rel = path.relative_to(REPO_ROOT).as_posix()
        heading = ""
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            heading_match = HEADING.match(line)
            if heading_match is not None:
                heading = heading_match.group(1)
            if re.search(r"open\s+PR\s+#23", line, re.IGNORECASE):
                open_pr.append(f"{rel}:{number}")
            wave = wave_said_not_started(line, heading)
            if wave is not None:
                not_started.append(f"{rel}:{number} ({wave})")
    problems = []
    if open_pr:
        problems.append("'open PR #23' at " + ", ".join(open_pr))
    if not_started:
        problems.append("'not started' said of a Phase B wave at " + ", ".join(not_started))
    if problems:
        attributed_fail("docs track (the files listed)", "; ".join(problems))


def _verify_scanned_docs() -> list[Path]:
    """The docs that describe the tree: the root pages and docs/ minus the dated history set."""
    scanned = []
    for path in _scanned_docs():
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel.startswith(VERIFY_HISTORY_EXCLUDED_PREFIXES) or VERIFY_HISTORY_EXCLUDED_PLANS.match(rel):
            continue
        scanned.append(path)
    return scanned


def _sentences(text: str) -> Iterator[tuple[int, str]]:
    """``(first line number, sentence)`` per sentence, paragraphs joined so a wrapped sentence stays whole."""
    lines = text.splitlines()
    start = None
    buffer: list[str] = []
    for number, line in enumerate(lines + [""], start=1):
        if line.strip():
            if start is None:
                start = number
            buffer.append(line.strip())
            continue
        if buffer and start is not None:
            for sentence in re.split(r"(?<=[.!?])\s+", " ".join(buffer)):
                if sentence:
                    yield start, sentence
        start, buffer = None, []


def stale_verify_tokens_in(sentence: str) -> list[str]:
    """The removed-loop tokens ``sentence`` carries, unless it names the 2026-09-09 removal itself."""
    if "2026-09-09" in sentence and REMOVAL_WORDS.search(sentence):
        return []
    return [token for token in STALE_VERIFY_TOKENS if token in sentence]


def test_stale_verify_tokens_reads_the_sentence_not_the_line() -> None:
    """The scan's own contract: a removal sentence is exempt, a present-tense sentence is not."""
    assert stale_verify_tokens_in("A verify campaign re-runs the settings with `feature_squeezing`.") == [
        "feature_squeezing"]
    assert stale_verify_tokens_in("`verify.replay` left the policy on 2026-09-09 (20 members remain).") == []
    assert stale_verify_tokens_in("Since 2026-09-09 `POST /v1/findings/{id}/verify` is the way to measure a fix.") == [
        "/findings/{id}/verify"]
    assert stale_verify_tokens_in("Findings close by reviewer decision.") == []
    joined = list(_sentences("Migration `0012` (2026-09-09) is the head: it drops\n`findings.validation_state`.\n\n"
                             "Next paragraph."))
    assert joined == [(1, "Migration `0012` (2026-09-09) is the head: it drops `findings.validation_state`."),
                      (4, "Next paragraph.")]


def test_no_tree_doc_describes_the_removed_verify_loop() -> None:
    """26.11 after 2026-09-09: no page that describes the tree presents the verify loop as a present feature.

    The verify campaigns, the defense catalog, the finding validation state and
    the delta were removed by product owner decision (``docs/project-brief.md``
    item 16). A sentence that names that removal may carry the old names; any
    other sentence that carries one is a claim about a feature that does not
    exist.
    """
    hits: list[str] = []
    for path in _verify_scanned_docs():
        rel = path.relative_to(REPO_ROOT).as_posix()
        for line, sentence in _sentences(path.read_text(encoding="utf-8", errors="replace")):
            tokens = stale_verify_tokens_in(sentence)
            if tokens:
                hits.append(f"{rel}:{line} {tokens} in {sentence[:120]!r}")
    if hits:
        attributed_fail("docs track (the files listed)",
                        f"{len(hits)} sentence(s) still describe the removed verify loop:\n  " + "\n  ".join(hits))


def test_mkdocs_nav_lists_plans_10_11_and_12() -> None:
    """A page that exists but is not in the nav cannot be found by a reader (docs/dev/ci.md 'Docs build')."""
    text = MKDOCS.read_text(encoding="utf-8")
    nav = _section(text, r"^nav:", r"^[A-Za-z_]+:")
    assert nav is not None, "mkdocs.yml has no nav"
    absent_files = [plan for plan in NAV_PLANS if not (REPO_ROOT / "docs" / plan).is_file()]
    assert not absent_files, f"plan pages missing from docs/: {absent_files}"
    missing = [plan for plan in NAV_PLANS if plan not in nav]
    if missing:
        attributed_fail("mkdocs.yml (no wave B4 track owns it; the assembler adds the nav rows)",
                        "nav does not list " + ", ".join(missing))


# ---------------------------------------------------------------------------
# The gate is provably discriminating (TESTS_DOCS-36)
# ---------------------------------------------------------------------------

BEGIN = "# --- BEGIN PHASE_B_PROBES ---"
END = "# --- END PHASE_B_PROBES ---"


def load_probe_program() -> types.ModuleType:
    """The probe program embedded in scripts/phase_b_gate.sh, executed as a module."""
    text = GATE.read_text(encoding="utf-8")
    start = text.index(BEGIN)
    stop = text.index(END)
    module = types.ModuleType("phase_b_probes")
    exec(compile(text[start:stop], str(GATE), "exec"), module.__dict__)  # noqa: S102 - our own file
    return module


Answer = tuple[int, Any]


class FakeStack:
    """A fake HTTP layer: ``(method, path) -> (status, json or bytes)``; unknown routes are 404."""

    def __init__(self, answers: dict[tuple[str, str], Answer]) -> None:
        self.answers = dict(answers)
        self.calls: list[tuple[str, str, Any]] = []

    def __call__(self, method: str, url: str, headers: dict[str, str] | None = None,
                 body: Any = None) -> tuple[int, dict[str, str], bytes]:
        path = url.split("://", 1)[1].split("/", 1)[1] if "://" in url else url
        path = "/" + path
        self.calls.append((method, path, body))
        assert headers is not None and headers.get("Authorization", "").startswith("Bearer "), "no bearer token sent"
        status, payload = self.answers.get((method, path), (404, {"detail": "not found"}))
        if isinstance(payload, bytes):
            return status, {"content-type": "application/pdf"}, payload
        return status, {"content-type": "application/json"}, json.dumps(payload).encode("utf-8")


def landed_stack() -> dict[tuple[str, str], Answer]:
    """Answers of a stack on which every probed Phase B path is built."""
    available = {"status": "available", "phase": "B"}
    return {
        ("GET", "/v1/ml/capabilities"): (200, {
            "modalities": {"image": {"status": "available", "phase": "A"},
                           "tabular": {"status": "available", "phase": "A"},
                           "text": dict(available), "detection": dict(available), "llm": dict(available)},
            "endpoint_connector": dict(available),
        }),
        ("GET", "/v1/attacks?modality=text"): (200, {"attacks": [{"id": "word_substitution", "domain": "text"}],
                                                     "count": 1}),
        ("GET", "/v1/projects"): (200, {"projects": [{"id": "default", "role": "admin"}], "count": 1}),
        ("POST", "/v1/models"): (422, {"detail": {"code": "endpoint_url_invalid",
                                                  "message": "url is required", "field": "url"}}),
        ("GET", "/v1/runs?limit=25"): (200, {"runs": [{"id": "run-1", "status": "succeeded"},
                                                      {"id": "run-0", "status": "failed"}], "count": 2}),
        ("GET", "/v1/runs/run-1/report.pdf"): (200, b"%PDF-1.7\n%fake\n"),
        ("GET", "/v1/integrations"): (200, {"integrations": {
            "foundry": {"integration": "foundry", "status": "disabled"},
            "lattice": {"integration": "lattice", "status": "not_implemented", "phase": "B",
                        "reason": "D3: no mission-system connections"},
        }}),
    }


def _run(program: types.ModuleType, answers: dict[tuple[str, str], Answer]) -> tuple[list[str], Any, FakeStack]:
    stack = FakeStack(answers)
    api = program.Api("http://stack.test", "dev:admin@test", http=stack)
    passed, failure = program.run_probes(api, out=lambda _line: None)
    return passed, failure, stack


def test_gate_probes_pass_on_a_stack_where_phase_b_is_built() -> None:
    """The positive control: every probe holds and the endpoint probe posted the invalid endpoint body."""
    program = load_probe_program()
    passed, failure, stack = _run(program, landed_stack())
    assert failure is None, str(failure)
    assert passed == ["capabilities", "attacks-text", "endpoint-registration", "report-pdf", "integrations"]
    posted = [body for method, path, body in stack.calls if method == "POST" and path == "/v1/models"]
    assert posted == [{"source": "endpoint", "project_id": "default"}]
    assert program.main(environ={"REDSIM_API_URL": "http://stack.test", "REDSIM_API_TOKEN": "dev:a@b"},
                        http=FakeStack(landed_stack())) == 0
    # Without the two variables the program refuses to run rather than passing vacuously.
    assert program.main(environ={}, http=FakeStack(landed_stack())) == 2


def _with(answers: dict[tuple[str, str], Answer], key: tuple[str, str], answer: Answer) -> dict[tuple[str, str], Answer]:
    changed = dict(answers)
    changed[key] = answer
    return changed


NOT_BUILT = {"detail": {"code": "not_implemented", "message": "not implemented", "phase": "B",
                        "reason": "built in a later wave"}}

STILL_501_CASES: list[tuple[str, tuple[str, str], Answer, str, str]] = [
    # (case id, route, its answer on the defective stack, probe that must fail, criterion it must name)
    ("capabilities-text-not-implemented", ("GET", "/v1/ml/capabilities"), (200, {
        "modalities": {"text": {"status": "not_implemented", "phase": "B"},
                       "detection": {"status": "available"}, "llm": {"status": "available"}},
        "endpoint_connector": {"status": "available"},
    }), "capabilities", "26.24"),
    ("capabilities-endpoint-connector-not-implemented", ("GET", "/v1/ml/capabilities"), (200, {
        "modalities": {"text": {"status": "available"}, "detection": {"status": "available"},
                       "llm": {"status": "available"}},
        "endpoint_connector": {"status": "not_implemented", "phase": "B"},
    }), "capabilities", "26.24"),
    ("text-attack-missing", ("GET", "/v1/attacks?modality=text"), (200, {"attacks": [], "count": 0}),
     "attacks-text", "26.24"),
    ("endpoint-registration-501", ("POST", "/v1/models"), (501, NOT_BUILT), "endpoint-registration", "26.17"),
    ("endpoint-registration-not-a-422", ("POST", "/v1/models"), (201, {"id": "faked"}), "endpoint-registration",
     "26.24"),
    ("report-pdf-501", ("GET", "/v1/runs/run-1/report.pdf"), (501, NOT_BUILT), "report-pdf", "26.9"),
    ("report-pdf-not-a-pdf", ("GET", "/v1/runs/run-1/report.pdf"), (200, b"<html>not a pdf</html>"),
     "report-pdf", "26.9"),
    ("report-pdf-never-rendered", ("GET", "/v1/runs/run-1/report.pdf"), (404, {"detail": "report not yet rendered"}),
     "report-pdf", "26.24"),
    ("lattice-claims-available", ("GET", "/v1/integrations"), (200, {"integrations": {
        "lattice": {"status": "available"}}}), "integrations", "26.24"),
    ("integrations-501", ("GET", "/v1/integrations"), (501, NOT_BUILT), "integrations", "26.24"),
]


@pytest.mark.parametrize(("case", "route", "answer", "probe", "criterion"), STILL_501_CASES,
                         ids=[case[0] for case in STILL_501_CASES])
def test_gate_probes_fail_when_a_phase_b_route_is_still_a_stub(case: str, route: tuple[str, str], answer: Answer,
                                                              probe: str, criterion: str) -> None:
    """TESTS_DOCS-36: the gate exits non-zero on a tree where a Phase B path still answers 501 (or fakes a result)."""
    del case
    program = load_probe_program()
    answers = _with(landed_stack(), route, answer)
    passed, failure, _stack = _run(program, answers)
    assert failure is not None, "the probes passed on a defective stack"
    assert failure.probe == probe, str(failure)
    # The failure names the spec 26 criterion it is the evidence for (26.x, never a bare 'failed').
    assert criterion in failure.criterion, str(failure)
    assert "spec 26 criterion" in str(failure)
    # First failure ends the run: nothing after the failing probe is reported as passed.
    order = ["capabilities", "attacks-text", "endpoint-registration", "report-pdf", "integrations"]
    assert passed == order[:order.index(probe)]
    assert program.main(environ={"REDSIM_API_URL": "http://stack.test", "REDSIM_API_TOKEN": "dev:a@b"},
                        http=FakeStack(answers)) == 1


def test_gate_probes_report_a_refused_token_rather_than_a_missing_route() -> None:
    """A 401/403 is reported as a token or role problem, so an operator does not read it as a 501."""
    program = load_probe_program()
    answers = _with(landed_stack(), ("GET", "/v1/ml/capabilities"), (401, {"detail": "authentication required"}))
    _passed, failure, _stack = _run(program, answers)
    assert failure is not None and failure.probe == "capabilities"
    assert "token" in failure.message


def test_gate_pdf_probe_prefers_the_operators_run_id() -> None:
    """REDSIM_API_RUN_ID names the run to read; the probe then never lists runs."""
    program = load_probe_program()
    answers = _with(landed_stack(), ("GET", "/v1/runs/run-9/report.pdf"), (200, b"%PDF-1.4\n"))
    stack = FakeStack(answers)
    api = program.Api("http://stack.test", "dev:admin@test", http=stack)
    assert program.probe_report_pdf(api, "run-9").startswith("run run-9")
    assert ("GET", "/v1/runs?limit=25", None) not in stack.calls


# ---------------------------------------------------------------------------
# Wiring: the script, the Makefile and CI agree
# ---------------------------------------------------------------------------


def _bash() -> str:
    return "bash"


def test_gate_script_parses_and_lists_the_steps_in_the_brief_order() -> None:
    """The gate runs its steps in the fixed order and names a spec 26 criterion for each (TESTS_DOCS-36)."""
    assert GATE.is_file(), "scripts/phase_b_gate.sh is missing"
    syntax = subprocess.run([_bash(), "-n", str(GATE)], capture_output=True, text=True, check=False)
    assert syntax.returncode == 0, syntax.stderr
    listed = subprocess.run([_bash(), str(GATE), "--list"], capture_output=True, text=True, check=False,
                            cwd=REPO_ROOT)
    assert listed.returncode == 0, listed.stderr
    names = [re.match(r"\s*\d+\.\s+(\S+)", line).group(1)  # type: ignore[union-attr]
             for line in listed.stdout.splitlines() if re.match(r"\s*\d+\.\s+\S+", line)]
    assert tuple(names) == GATE_STEPS
    for line in listed.stdout.splitlines():
        if re.match(r"\s*\d+\.", line):
            assert re.search(r"spec 26 criterion 26\.\d", line), line
    # An unknown step is refused, not silently skipped.
    unknown = subprocess.run([_bash(), str(GATE), "--only", "nope"], capture_output=True, text=True, check=False,
                             cwd=REPO_ROOT)
    assert unknown.returncode == 2
    # The exact commands of the brief are in the script, so local and CI run the same thing.
    text = GATE.read_text(encoding="utf-8")
    for command in (
        "ruff check --select E4,E7,E9,F,I redsim tests",
        "mypy redsim",
        "pytest -q -p no:cacheprovider --ignore=tests/e2e",
        "pytest -q -p no:cacheprovider -m ml tests/ml",
        "pytest -q -p no:cacheprovider -m garak tests",
        "-m e2e tests/e2e",
        "mkdocs build --strict",
        "tests/test_docs_phase_b_consistency.py",
        "audit verify --all",
    ):
        assert command in text, command
    # Exit 5 (nothing collected) was a pass with a notice from wave B0 to wave B1, when no garak
    # test existed; since wave B2 the tree carries them, so the mapping is gone and the listed
    # step says so (the behaviour itself is proven by test_gate_garak_step_fails_unless_tests_ran).
    assert "passes with a notice" not in text, "the garak step must not map pytest exit 5 to a pass"
    garak_row = next(line for line in listed.stdout.splitlines() if re.match(r"\s*5\.\s+garak\b", line))
    assert "exit 5" in garak_row and "fails" in garak_row, garak_row


FAKE_PY = """#!/usr/bin/env bash
# A stand-in interpreter for the gate: answers the version and extra checks, and plays pytest.
case "${1:-}" in
  -c)
    if [[ "${FAKE_GARAK_MISSING:-}" == "1" && "${2:-}" == *garak* ]]; then exit 1; fi
    exit 0 ;;
  -m)
    printf '%s\\n' "${FAKE_SUMMARY:-}"
    exit "${FAKE_RC:-0}" ;;
esac
exit 0
"""

GARAK_STEP_CASES: list[tuple[str, dict[str, str], int, str]] = [
    # (case id, fake interpreter environment, expected gate exit, a line the gate must print)
    ("exit-5-nothing-collected", {"FAKE_RC": "5", "FAKE_SUMMARY": "no tests ran in 0.90s"}, 1,
     "collected no garak-marked test"),
    ("exit-0-all-skipped", {"FAKE_RC": "0", "FAKE_SUMMARY": "16 skipped in 1.02s"}, 1,
     "no garak-marked test passed"),
    ("garak-extra-missing", {"FAKE_RC": "0", "FAKE_SUMMARY": "12 passed in 20.0s", "FAKE_GARAK_MISSING": "1"}, 1,
     "garak extra is not installed"),
    ("one-failure", {"FAKE_RC": "1", "FAKE_SUMMARY": "1 failed, 11 passed, 4 skipped in 21.3s"}, 1,
     "FAIL: step garak"),
    ("tests-ran", {"FAKE_RC": "0", "FAKE_SUMMARY": "12 passed, 4 skipped, 1 warning in 20.10s"}, 0,
     "PASS garak"),
]


@pytest.mark.parametrize(("case", "fake_env", "expected_exit", "expected_line"), GARAK_STEP_CASES,
                         ids=[case[0] for case in GARAK_STEP_CASES])
def test_gate_garak_step_fails_unless_tests_ran(tmp_path: Path, case: str, fake_env: dict[str, str],
                                                expected_exit: int, expected_line: str) -> None:
    """TESTS_DOCS-36 / 26.20: the garak step passes only when garak-marked tests ran and passed.

    ``PY`` is a shell stand-in for the interpreter, so the step's exit-code and
    summary handling is exercised without garak: pytest exit 5, an all-skipped
    exit 0 and a missing extra each fail the gate naming criterion 26.20.
    """
    del case
    fake = tmp_path / "python"
    fake.write_text(FAKE_PY, encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    env = {**os.environ, "PY": str(fake), **fake_env}
    result = subprocess.run([_bash(), str(GATE), "--only", "garak"], capture_output=True, text=True, check=False,
                            cwd=REPO_ROOT, env=env)
    assert result.returncode == expected_exit, result.stdout + result.stderr
    assert expected_line in result.stdout, result.stdout + result.stderr
    if expected_exit != 0:
        assert "spec 26 criterion 26.20" in result.stdout, result.stdout
        assert "FAIL: step garak" in result.stdout, result.stdout


def test_makefile_has_check_phase_b_and_check_keeps_its_meaning() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    target = re.search(r"^check-phase-b:.*\n((?:\t.*\n)+)", text, re.MULTILINE)
    assert target is not None, "Makefile has no check-phase-b target"
    assert "scripts/phase_b_gate.sh" in target.group(1)
    assert re.search(r"^check: lint typecheck test\s*$", text, re.MULTILINE), "`make check` changed meaning"
    assert "check-phase-b" in re.search(r"\.PHONY:(?:.*\\\n)*.*", text).group(0)  # type: ignore[union-attr]


def test_ci_jobs_call_the_same_gate_steps() -> None:
    """The e2e-python and garak-offline jobs run the script, so local and CI agree (TESTS_DOCS-36)."""
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]

    def run_text(job: dict[str, Any]) -> str:
        return "\n".join(str(step.get("run", "")) for step in job.get("steps", []))

    assert "scripts/phase_b_gate.sh --only e2e" in run_text(jobs["e2e-python"])
    assert "scripts/phase_b_gate.sh --only docs-consistency" in run_text(jobs["e2e-python"])
    assert "scripts/phase_b_gate.sh --only garak" in run_text(jobs["garak-offline"])
    # Both lanes hand the script the runner's interpreter, so the step runs as `make check-phase-b` does.
    for job in ("e2e-python", "garak-offline"):
        step_envs = [step.get("env", {}) or {} for step in jobs[job].get("steps", [])
                     if "scripts/phase_b_gate.sh" in str(step.get("run", ""))]
        assert step_envs and all(env.get("PY") == "python" for env in step_envs), (job, step_envs)
    # tests/e2e/test_ml_llm.py is garak-marked and e2e-gated: it runs only where both the garak extra
    # is installed and REDSIM_E2E is set, which is the e2e-python lane. Without the extra there,
    # tests/conftest.py would skip it at collection and the LLM probe evidence would run in no lane.
    assert ".[garak]" in run_text(jobs["e2e-python"]), "e2e-python must install the garak extra"
    assert ".[garak]" in run_text(jobs["garak-offline"])
    # The wave B0 mapping of pytest exit 5 to success is gone from the workflow as well as the script.
    raw = CI_WORKFLOW.read_text(encoding="utf-8")
    assert not re.search(r"exit 5[^\n]*(counts as a pass|= success|to success|nothing selected\))", raw), \
        "the workflow still describes pytest exit 5 as a pass"
    # The garak lane still exports no gateway variable (docs/dev/ci.md "The garak offline job").
    garak_env = {**workflow.get("env", {}), **jobs["garak-offline"].get("env", {})}
    for step in jobs["garak-offline"].get("steps", []):
        garak_env.update(step.get("env", {}) or {})
    assert not any(key.startswith("PYTHIA_") for key in garak_env), garak_env
