"""`aegis demo` — runs the opinionated end-to-end demo."""

from __future__ import annotations

import sys
from pathlib import Path

from aegis.cli import _console


def cmd_demo(args, config) -> None:
    """Run the opinionated end-to-end demo."""
    from aegis.demo import run_demo

    repo_path = Path(args.repo).resolve()
    if not repo_path.is_dir():
        _console._err(f"--repo path does not exist or is not a directory: {repo_path}")
        sys.exit(1)

    _console._info(f"Aegis demo starting (repo={repo_path})")
    _console._info(f"Mode: strix={'live' if args.live_strix else 'fixture'} "
                   f"llm={'live' if args.live_llm else 'fixture'} "
                   f"apply={'yes' if args.apply else 'dry-run'}")

    outcome = run_demo(
        config,
        repo_path=repo_path,
        live_strix=args.live_strix,
        live_llm=args.live_llm,
        apply=args.apply,
        use_golden_patch=args.use_golden_patch or not args.live_llm,
        keep_target=args.keep_target,
        target_pack_name=args.target_pack,
    )

    print()
    print(f"{_console._BOLD}Demo summary{_console._RESET}")
    for s in outcome.stages:
        mark = _console._GREEN + "✓" + _console._RESET if s.success else _console._RED + "✗" + _console._RESET
        print(f"  {mark} {s.name:<12} mode={s.mode:<14} {s.detail}")
    print(f"\nArtifacts: {outcome.run_path}")
    report_html = Path(outcome.run_path) / "report.html"
    if report_html.exists():
        print(f"Report:    {report_html}")
