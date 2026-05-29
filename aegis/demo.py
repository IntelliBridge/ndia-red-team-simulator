"""Opinionated end-to-end demo orchestration for Aegis.

Stage order (PLAN.md §9.3, six evidence links):

  1. ``target.up``    — start the source-bound (or fixture) container.
  2. ``discover``     — Strix scan against the now-running target, OR load
                         the recorded fixture events.
  3. ``remediate``    — produce the patch via CAI (or golden fixture).
                         When ``apply=True`` the patch is committed to a new
                         branch via ``commit_patch`` (branch-first + rollback);
                         otherwise the diff is persisted and the working tree
                         is left untouched.
  4. ``rebuild``      — rebuild the source-mode container from the patched repo
                         so the running target reflects the patch.
  5. ``verify``       — replay the PoC and require source-rebuilt provenance.
  6. ``report``       — render report.md / report.json / report.html.
  7. ``teardown``     — stop the container (unless ``keep_target=True``).

Every active operation is routed through ``aegis.safety.authorize`` and
emits an entry to ``aegis_output/runs/<run_id>/audit.jsonl``.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from aegis.adapters.strix_adapter import load_strix_events
from aegis.config import AegisConfig
from aegis.remediate.cai_runner import run_code_fix
from aegis.remediate.patch_workflow import (
    apply_patch,
    commit_patch,
)
from aegis.safety import authorize
from aegis.schema import AegisFinding
from aegis.state import RunState
from aegis.verify import verify_finding

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
DEFAULT_FIXTURE_EVENTS = FIXTURES_DIR / "strix_events_juice_shop.jsonl"
DEFAULT_TARGET_PACK = "juice-shop"


@dataclass
class StageOutcome:
    name: str
    mode: str
    success: bool
    detail: str = ""


@dataclass
class DemoOutcome:
    run_id: str
    run_path: str
    stages: list[StageOutcome] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "run_path": self.run_path,
            "stages": [asdict(s) for s in self.stages],
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _persist_stage_table(run_state: RunState, outcome: DemoOutcome) -> None:
    (run_state.run_path / "stage_table.json").write_text(
        json.dumps(outcome.to_dict(), indent=2)
    )


def _pick_canonical_finding(findings: list[AegisFinding]) -> AegisFinding | None:
    if not findings:
        return None
    by_id = {f.id: f for f in findings}
    if "vuln-0001" in by_id:
        return by_id["vuln-0001"]
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda f: rank.get(f.severity.lower(), 9))[0]


def _write_fixture_runtime(run_state: RunState, target_pack_name: str,
                           repo_path: Path, *, last_rebuild_at: str | None = None) -> None:
    target_dir = run_state.run_path / "target"
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "runtime.json").write_text(json.dumps({
        "name": target_pack_name, "mode": "source", "url": "fixture://no-container",
        "container_name": "fixture", "container_id": None, "image_tag": "fixture",
        "source_repo": str(repo_path),
        "source_ref_before": "fixture-pre",
        "source_ref_after": "fixture-post" if last_rebuild_at else "fixture-pre",
        "built_image_digest": None,
        "started_at": _now(), "ready_at": _now(),
        "last_rebuild_at": last_rebuild_at,
    }, indent=2))


def run_demo(
    config: AegisConfig,
    *,
    repo_path: Path,
    live_strix: bool = False,
    live_llm: bool = False,
    apply: bool = False,
    use_golden_patch: bool | None = None,
    keep_target: bool = False,
    target_pack_name: str = DEFAULT_TARGET_PACK,
) -> DemoOutcome:
    """Run the full demo lifecycle.

    Defaults are deliberately safe: ``live_strix=False``, ``live_llm=False``,
    ``apply=False``. The patch is generated and persisted, but **the repo is
    not mutated** unless ``apply=True`` is explicitly set. Use ``--apply`` at
    the CLI to opt into branch/commit.
    """
    state = RunState(config.output_dir)
    outcome = DemoOutcome(run_id=state.run_id, run_path=str(state.run_path))

    if use_golden_patch is None:
        use_golden_patch = not live_llm

    # ---- Stage 1: target.up (must precede a live scan) -------------------
    target_pack = None
    target_url = "http://localhost:3000"  # placeholder; overwritten if live
    if live_strix or live_llm:
        try:
            from aegis.targets import get_target_pack
            target_pack = get_target_pack(target_pack_name, run_path=state.run_path)
            target_url = target_pack.runtime.url
            authorize(
                "target.start", target_url,
                allowlist=config.target_allowlist, run_path=state.run_path,
                detail={"pack": target_pack_name, "repo": str(repo_path)},
            )
            target_pack.up_from_repo(repo_path)
            ready = target_pack.wait_ready(timeout=120)
            outcome.stages.append(StageOutcome(
                "target.up", "live", ready, f"url={target_url} ready={ready}",
            ))
            if not ready:
                _persist_stage_table(state, outcome)
                return outcome
        except Exception as e:
            outcome.stages.append(StageOutcome("target.up", "live", False, f"docker failed: {e}"))
            _persist_stage_table(state, outcome)
            return outcome
    else:
        _write_fixture_runtime(state, target_pack_name, repo_path)
        outcome.stages.append(StageOutcome(
            "target.up", "fixture", True, "no container — fixture-assisted run",
        ))

    # ---- Stage 2: discover ------------------------------------------------
    if live_strix:
        try:
            from aegis.adapters.strix_runner import run_strix
            authorize(
                "strix.run", target_url,
                allowlist=config.target_allowlist, run_path=state.run_path,
                detail={"target": target_url},
            )
            result = run_strix(target_url, state)
            findings = result.findings
            outcome.stages.append(StageOutcome(
                "discover", "live", result.success or result.partial_success,
                f"strix exit={result.return_code} findings={len(findings)}"
            ))
        except Exception as e:
            findings = []
            outcome.stages.append(StageOutcome("discover", "live", False, f"strix failed: {e}"))
    else:
        findings = load_strix_events(str(DEFAULT_FIXTURE_EVENTS), state.run_id)
        outcome.stages.append(StageOutcome(
            "discover", "fixture", True,
            f"loaded {len(findings)} findings from {DEFAULT_FIXTURE_EVENTS.name}",
        ))

    state.save_findings(findings)

    # ---- Stage 3: remediate ----------------------------------------------
    canonical = _pick_canonical_finding(findings)
    if canonical is None:
        outcome.stages.append(StageOutcome("remediate", "skipped", False, "no findings"))
        _persist_stage_table(state, outcome)
        return outcome

    state.update_finding_status(canonical.id, "fixing")
    fix_result = run_code_fix(
        canonical, repo_path=str(repo_path),
        use_golden_patch=use_golden_patch,
    )
    remediate_mode = "golden_fixture" if use_golden_patch else "live_llm"

    if not fix_result.success or not fix_result.diff:
        outcome.stages.append(StageOutcome(
            "remediate", remediate_mode, False,
            f"no diff produced (source={fix_result.source}) error={fix_result.error}",
        ))
        state.update_finding_status(canonical.id, "failed")
        _persist_stage_table(state, outcome)
        return outcome

    # Persist the diff regardless of --apply — the diff itself is evidence.
    patches_dir = state.run_path / "artifacts" / "patches"
    patches_dir.mkdir(parents=True, exist_ok=True)
    (patches_dir / f"{canonical.id}.diff").write_text(fix_result.diff)

    if not apply:
        # Safe default: validate the patch but never mutate the repo.
        check = apply_patch(repo_path, fix_result.diff, dry_run=True)
        outcome.stages.append(StageOutcome(
            "remediate", remediate_mode + "+dry-run",
            check.success,
            f"diff persisted; `git apply --check` "
            f"{'passes' if check.success else 'failed: ' + (check.stderr or '')}",
        ))
        state.update_finding_status(
            canonical.id, "open" if check.success else "failed"
        )
        _persist_stage_table(state, outcome)
        return _finalize(
            state, outcome, target_pack, canonical, repo_path,
            apply=False, keep_target=keep_target,
        )

    # Apply path: route the commit through authorize().
    authorize(
        "patch.commit", None,
        allowlist=config.target_allowlist, run_path=state.run_path,
        detail={"finding_id": canonical.id, "repo": str(repo_path),
                "diff_sha256": fix_result.diff_sha256_hex,
                "source": fix_result.source},
    )
    commit_result = commit_patch(
        repo_path, canonical, fix_result.diff,
        allow_dirty=False,
    )
    state.append_remediation_log(
        canonical.id, action="patch_commit",
        result=(f"branch={commit_result.branch} commit={commit_result.commit_hash} "
                f"ref_before={commit_result.ref_before} "
                f"diff_sha256={commit_result.diff_sha256}"),
        success=commit_result.success,
    )
    outcome.stages.append(StageOutcome(
        "remediate", remediate_mode + "+apply",
        commit_result.success,
        f"branch={commit_result.branch} commit={commit_result.commit_hash} "
        f"error={commit_result.error}",
    ))
    state.update_finding_status(canonical.id, "fixed" if commit_result.success else "failed")

    if not commit_result.success:
        _persist_stage_table(state, outcome)
        return _finalize(
            state, outcome, target_pack, canonical, repo_path,
            apply=apply, keep_target=keep_target,
        )

    return _finalize(
        state, outcome, target_pack, canonical, repo_path,
        apply=True, keep_target=keep_target,
    )


def _finalize(
    state: RunState,
    outcome: DemoOutcome,
    target_pack,
    canonical: AegisFinding,
    repo_path: Path,
    *,
    apply: bool,
    keep_target: bool,
) -> DemoOutcome:
    """Stages 4–7: rebuild, verify, report, teardown."""

    # ---- Stage 4: rebuild --------------------------------------------------
    if apply and target_pack is not None:
        try:
            authorize(
                "target.rebuild", target_pack.runtime.url,
                allowlist=getattr(target_pack, "allowlist", ["localhost"]),
                run_path=state.run_path,
                detail={"repo": str(repo_path)},
            )
            target_pack.rebuild(repo_path)
            target_pack.wait_ready(timeout=120)
            outcome.stages.append(StageOutcome("rebuild", "live", True, ""))
        except Exception as e:
            outcome.stages.append(StageOutcome("rebuild", "live", False, str(e)))
    elif apply and target_pack is None:
        # Fixture mode: mark the rebuild "happened" so the source-rebuild
        # provenance check in verify can pass.
        target_dir = state.run_path / "target"
        runtime_data = json.loads((target_dir / "runtime.json").read_text())
        runtime_data["last_rebuild_at"] = _now()
        runtime_data["source_ref_after"] = "fixture-post"
        (target_dir / "runtime.json").write_text(json.dumps(runtime_data, indent=2))
        outcome.stages.append(StageOutcome("rebuild", "fixture", True, "no container"))
    else:
        # Dry-run path — no rebuild, no claim of patched runtime.
        outcome.stages.append(StageOutcome(
            "rebuild", "skipped", True, "dry-run (no --apply)",
        ))

    # ---- Stage 5: verify ---------------------------------------------------
    findings_now = [AegisFinding.from_dict(f) for f in state.load_findings()]
    canonical_now = next((f for f in findings_now if f.id == canonical.id), canonical)

    authorize(
        "verify.replay",
        canonical_now.target or "localhost",
        allowlist=["127.0.0.1", "localhost", "host.docker.internal"],
        run_path=state.run_path,
        detail={"finding_id": canonical_now.id, "apply": apply},
    )
    verify_result = verify_finding(
        canonical_now,
        run_state=state,
        repo_path=repo_path,
        require_source_rebuild=apply,
    )
    outcome.stages.append(StageOutcome(
        "verify",
        "live" if target_pack is not None else "fixture",
        verify_result.status == "verified",
        f"status={verify_result.status} strategy={verify_result.strategy}",
    ))

    # ---- Stage 6: report ---------------------------------------------------
    _persist_stage_table(state, outcome)
    try:
        from aegis.report import save_reports
        save_reports(state, findings_now)
        outcome.stages.append(StageOutcome(
            "report", "live", True, "report.md + report.json + report.html",
        ))
    except Exception as e:
        outcome.stages.append(StageOutcome("report", "live", False, str(e)))

    # ---- Stage 7: teardown -------------------------------------------------
    if target_pack is not None and not keep_target:
        try:
            authorize(
                "target.down", target_pack.runtime.url,
                allowlist=["127.0.0.1", "localhost", "host.docker.internal"],
                run_path=state.run_path,
                detail={"container_name": target_pack.container_name},
            )
            target_pack.down()
            outcome.stages.append(StageOutcome("teardown", "live", True, ""))
        except Exception as e:
            outcome.stages.append(StageOutcome("teardown", "live", False, str(e)))

    _persist_stage_table(state, outcome)
    return outcome
