"""``redsim audit verify`` reaches the offline single-file chain ``redsim ml attack`` writes.

The offline path lands its whole chain ``run:<run_id>`` in one file,
``<out>/<run_id>/audit.jsonl``, while the default writer only looks at
``<output_dir>/audit/run__<id>.jsonl``. The CLI therefore (a) falls back to
``<output_dir>/<run_id>/audit.jsonl`` for ``--run <id>`` and (b) takes an
explicit ``--run-dir PATH`` (the run directory or the ``.jsonl`` file). Every
test here enters through ``redsim.cli.main.main`` in-process with a real
config file and no patching of the writer resolution. Offline (no DB).
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redsim.audit.chain import JsonlAuditWriter

# ``redsim.cli`` re-exports the ``main`` function, so ``import redsim.cli.main as m``
# would bind the function, not the module: import the names from the module directly.
from redsim.cli.main import build_parser
from redsim.cli.main import main as cli_main

RUN_ID = "run-offline-1234"
ACTIONS = ("attack.run", "score.compute", "job.complete")


@pytest.fixture
def offline_run(tmp_path, monkeypatch):
    """An offline run directory under a config ``output_dir``, exactly as ``redsim ml attack`` lays it out."""
    # No Postgres, no in-memory seam: the default writer resolves to <output_dir>/audit/.
    for var in ("REDSIM_DB_URL", "REDSIM_TEST_AUDIT", "REDSIM_CONFIG", "REDSIM_MODE"):
        monkeypatch.delenv(var, raising=False)
    out = tmp_path / "redsim_output"
    run_dir = out / RUN_ID
    writer = JsonlAuditWriter(run_dir, single_file="audit.jsonl")
    for action in ACTIONS:
        writer.append(
            action=action, actor="cli:test", target=None, allowlist_check="n/a",
            override=False, success=True, detail={"stage": action}, run_id=RUN_ID,
        )
    cfg = tmp_path / "redsim.yaml"
    cfg.write_text(f"output_dir: {out}\n", encoding="utf-8")
    return SimpleNamespace(cfg=str(cfg), out=out, run_dir=run_dir, audit=run_dir / "audit.jsonl")


def _verify(capsys, cfg: str, *argv: str) -> tuple[int, str]:
    with pytest.raises(SystemExit) as exc:
        cli_main(["--config", cfg, "audit", "verify", *argv])
    captured = capsys.readouterr()
    return exc.value.code, captured.out + captured.err


def _tamper(audit_path) -> None:
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["success"] = not record["success"]
    lines[1] = json.dumps(record)
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_run_flag_falls_back_to_the_offline_chain_under_output_dir(offline_run, capsys):
    """The command ``redsim ml attack`` prints, unpatched: ``redsim audit verify --run <run_id>``."""
    code, out = _verify(capsys, offline_run.cfg, "--run", RUN_ID)
    assert code == 0, out
    assert f"{len(ACTIONS)} events verified" in out
    assert str(offline_run.audit) in out           # says where the chain was found
    assert not (offline_run.out / "audit" / f"run__{RUN_ID}.jsonl").exists()


def test_run_dir_flag_accepts_the_run_directory(offline_run, capsys):
    code, out = _verify(capsys, offline_run.cfg, "--run-dir", str(offline_run.run_dir))
    assert code == 0, out
    assert f"chain 'run:{RUN_ID}': {len(ACTIONS)} events verified" in out


def test_run_dir_flag_accepts_the_jsonl_file_and_combines_with_run_and_all(offline_run, capsys):
    code, out = _verify(capsys, offline_run.cfg, "--run-dir", str(offline_run.audit))
    assert code == 0, out
    assert f"{len(ACTIONS)} events verified" in out

    code, out = _verify(capsys, offline_run.cfg, "--run-dir", str(offline_run.run_dir), "--run", RUN_ID)
    assert code == 0, out
    assert f"{len(ACTIONS)} events verified" in out

    code, out = _verify(capsys, offline_run.cfg, "--run-dir", str(offline_run.run_dir), "--all")
    assert code == 0, out
    assert f"chain 'run:{RUN_ID}': {len(ACTIONS)} events verified" in out


def test_run_dir_works_for_a_run_written_with_out_elsewhere(offline_run, tmp_path, capsys):
    """A run under ``--out`` that is not the config output_dir: ``--run`` alone cannot find it, ``--run-dir`` can."""
    elsewhere = tmp_path / "elsewhere" / RUN_ID
    writer = JsonlAuditWriter(elsewhere, single_file="audit.jsonl")
    writer.append(action="attack.run", actor="cli:test", target=None, allowlist_check="n/a",
                  override=False, success=True, detail={}, run_id="run-elsewhere")
    code, out = _verify(capsys, offline_run.cfg, "--run", "run-elsewhere")
    assert code == 1
    assert "no events found" in out and "--run-dir" in out
    code, out = _verify(capsys, offline_run.cfg, "--run-dir", str(elsewhere), "--run", "run-elsewhere")
    assert code == 0, out
    assert "1 events verified" in out


def test_tampered_line_fails_through_both_flags(offline_run, capsys):
    _tamper(offline_run.audit)
    code, out = _verify(capsys, offline_run.cfg, "--run", RUN_ID)
    assert code == 1
    assert "broken at seq=2" in out
    code, out = _verify(capsys, offline_run.cfg, "--run-dir", str(offline_run.run_dir))
    assert code == 1
    assert "broken at seq=2" in out


def test_primary_chain_wins_over_the_offline_fallback(offline_run, capsys):
    """When ``<output_dir>/audit/run__<id>.jsonl`` has the run, that is the chain verified."""
    primary = JsonlAuditWriter(offline_run.out / "audit")
    primary.append(action="scan.start", actor="cli:test", target=None, allowlist_check="pass",
                   override=False, success=True, detail={}, run_id=RUN_ID)
    code, out = _verify(capsys, offline_run.cfg, "--run", RUN_ID)
    assert code == 0, out
    assert "1 events verified" in out
    assert "using offline chain" not in out


def test_missing_run_dir_or_missing_audit_file_is_a_usage_error(offline_run, tmp_path, capsys):
    code, out = _verify(capsys, offline_run.cfg, "--run-dir", str(tmp_path / "nope"))
    assert code == 2
    assert "no such directory or file" in out
    empty = tmp_path / "empty-run"
    empty.mkdir()
    code, out = _verify(capsys, offline_run.cfg, "--run-dir", str(empty))
    assert code == 2
    assert "no audit.jsonl" in out
    assert not (empty / "audit.jsonl").exists()     # validation never creates the file


def test_parser_exposes_run_dir():
    args = build_parser().parse_args(["audit", "verify", "--run-dir", "/x/y"])
    assert args.run_dir == "/x/y"
    args = build_parser().parse_args(["audit", "verify", "--run", "abc"])
    assert args.run_dir is None
