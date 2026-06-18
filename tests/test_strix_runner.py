import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.runners.strix_runner import (
    discover_events_path,
    discover_strix_command,
    parse_events_lines,
    run_output_dir,
    run_strix,
    tail_events,
)
from aegis.state import RunState

FIXTURE = Path(__file__).parent / "fixtures" / "strix_events_juice_shop.jsonl"


class TestDiscoverStrixCommand(unittest.TestCase):
    def test_explicit_override_wins(self):
        cmd, env = discover_strix_command(strix_command="/usr/local/bin/strix --verbose")
        self.assertEqual(cmd[0], "/usr/local/bin/strix")
        self.assertEqual(env, {})

    def test_falls_back_to_which(self):
        with patch("aegis.runners.strix_runner.shutil.which", return_value="/fake/strix"):
            cmd, env = discover_strix_command()
        self.assertEqual(cmd, ["/fake/strix"])
        self.assertEqual(env, {})

    def test_falls_back_to_python_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            src.mkdir()
            with patch("aegis.runners.strix_runner.shutil.which", return_value=None):
                cmd, env = discover_strix_command(strix_path=tmp)
            self.assertEqual(cmd[1:3], ["-m", "strix"])
            self.assertEqual(env["PYTHONPATH"], str(src))

    def test_raises_when_nothing_found(self):
        with patch("aegis.runners.strix_runner.shutil.which", return_value=None):
            with self.assertRaises(FileNotFoundError):
                discover_strix_command(strix_path="/definitely/nope")


class TestParseEventsLines(unittest.TestCase):
    def test_parses_payload_report(self):
        lines = FIXTURE.read_text().splitlines()
        seen: set[str] = set()
        findings = parse_events_lines(lines, "run-x", seen)
        ids = {f.id for f in findings}
        self.assertEqual(ids, {"vuln-0001", "vuln-0002", "vuln-0003"})

    def test_dedup_by_id(self):
        seen: set[str] = set()
        lines = FIXTURE.read_text().splitlines()
        first = parse_events_lines(lines, "r", seen)
        second = parse_events_lines(lines, "r", seen)
        self.assertEqual(len(first), 3)
        self.assertEqual(second, [])

    def test_skips_non_finding_events(self):
        lines = [
            json.dumps({"event_type": "scan.started", "payload": {}}),
            json.dumps({"event_type": "finding.created",
                        "payload": {"report": {"id": "x", "title": "y"}}}),
        ]
        findings = parse_events_lines(lines, "r", set())
        self.assertEqual([f.id for f in findings], ["x"])

    def test_ignores_malformed_lines(self):
        lines = ["not json", "", json.dumps({"event_type": "finding.created",
                                              "payload": {"report": {"id": "z", "title": "t"}}})]
        findings = parse_events_lines(lines, "r", set())
        self.assertEqual([f.id for f in findings], ["z"])


class TestTailEvents(unittest.TestCase):
    def test_tail_picks_up_lines_streamed_after_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            events = Path(tmp) / "events.jsonl"
            events.write_text("")  # exists but empty

            done_flag = {"done": False}

            def producer():
                time.sleep(0.05)
                with open(events, "a") as fh:
                    fh.write(json.dumps({
                        "event_type": "finding.created",
                        "payload": {"report": {"id": "a", "title": "A"}},
                    }) + "\n")
                time.sleep(0.05)
                with open(events, "a") as fh:
                    fh.write(json.dumps({
                        "event_type": "finding.created",
                        "payload": {"report": {"id": "b", "title": "B"}},
                    }) + "\n")
                time.sleep(0.05)
                done_flag["done"] = True

            t = threading.Thread(target=producer)
            t.start()
            findings = tail_events(
                events, "r", is_done=lambda: done_flag["done"], interval=0.02,
            )
            t.join()

        ids = [f.id for f in findings]
        self.assertEqual(ids, ["a", "b"])


class TestRunStrixDockerCheck(unittest.TestCase):
    def test_skips_when_docker_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "rx")
            with patch("aegis.runners.strix_runner.docker_available", return_value=False):
                result = run_strix("http://localhost:3000", state)
            self.assertFalse(result.success)
            self.assertIn("docker", (result.error or "").lower())


class TestDiscoverEventsPath(unittest.TestCase):
    def test_returns_none_when_no_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(discover_events_path(Path(tmp)))

    def test_finds_single_events_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            search_dir = Path(tmp)
            events = search_dir / "strix_runs" / "auto-run" / "events.jsonl"
            events.parent.mkdir(parents=True, exist_ok=True)
            events.write_text("")
            self.assertEqual(discover_events_path(search_dir), events)

    def test_resolution_is_deterministic_not_mtime_based(self):
        # The old implementation picked the newest mtime, which is fragile.
        # Discovery is now keyed to a single per-run dir holding exactly one
        # Strix run; if more than one events file somehow appears, resolution
        # must still be deterministic (lexicographically greatest), regardless
        # of mtime ordering.
        with tempfile.TemporaryDirectory() as tmp:
            search_dir = Path(tmp)
            a = search_dir / "strix_runs" / "run-aaa" / "events.jsonl"
            b = search_dir / "strix_runs" / "run-bbb" / "events.jsonl"
            for p in (a, b):
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("")
            # Give the lexicographically-greatest path the OLDER mtime to prove
            # mtime no longer drives the choice.
            os.utime(b, (1_000_000, 1_000_000))
            os.utime(a, (2_000_000, 2_000_000))
            self.assertEqual(discover_events_path(search_dir), b)


class TestRunStrixMockedSubprocess(unittest.TestCase):
    def test_partial_success_when_findings_emitted_but_rc_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "ry")
            strix_dir = state.run_path / "strix"
            # Strix writes its events under strix_runs/<auto-name>/events.jsonl
            # relative to its cwd, which the runner now sets to the per-run
            # run_output_dir (strix_dir/run-<run_id>/).
            run_dir = run_output_dir(strix_dir, state.run_id)
            events_path = run_dir / "strix_runs" / "auto-run" / "events.jsonl"
            events_path.parent.mkdir(parents=True, exist_ok=True)

            # Fake Popen: writes 2 findings then "exits" with rc=2 immediately.
            class FakeProc:
                def __init__(self, *args, **kwargs):
                    self.returncode = None
                    self._t = threading.Thread(target=self._run)
                    self._t.start()

                def _run(self):
                    with open(events_path, "a") as fh:
                        fh.write(json.dumps({"event_type": "finding.created",
                                              "payload": {"report": {"id": "p", "title": "P"}}}) + "\n")
                        fh.write(json.dumps({"event_type": "finding.created",
                                              "payload": {"report": {"id": "q", "title": "Q"}}}) + "\n")
                    time.sleep(0.05)
                    self.returncode = 2

                def poll(self):
                    return self.returncode

                def terminate(self):
                    self.returncode = 2

                def wait(self):
                    while self.returncode is None:
                        time.sleep(0.01)
                    return self.returncode

            with patch("aegis.runners.strix_runner.docker_available", return_value=True), \
                 patch("aegis.runners.strix_runner.subprocess.Popen", side_effect=FakeProc) as popen, \
                 patch("aegis.runners.strix_runner.shutil.which", return_value="/fake/strix"):
                result = run_strix("http://localhost:3000", state)

            self.assertEqual(result.return_code, 2)
            self.assertFalse(result.success)
            self.assertTrue(result.partial_success)
            self.assertEqual({f.id for f in result.findings}, {"p", "q"})
            self.assertTrue((strix_dir / "run.json").exists())
            # events_path points at the discovered strix_runs file, not a fixed path.
            self.assertEqual(result.events_path, str(events_path))

            # Command no longer carries the bogus --output-dir flag and now
            # carries --scan-mode; -n / --target are preserved.
            self.assertNotIn("--output-dir", result.command)
            self.assertIn("--scan-mode", result.command)
            self.assertIn("-n", result.command)
            self.assertIn("--target", result.command)
            self.assertEqual(
                result.command[result.command.index("--scan-mode") + 1],
                "standard",
            )

            # Strix must be launched with cwd=run_dir (the per-run output dir)
            # so its strix_runs/ tree lands in this run's isolated subtree.
            self.assertEqual(popen.call_args.kwargs["cwd"], str(run_dir))

    def test_scan_mode_threaded_into_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "rz")

            class FakeProc:
                def __init__(self, *args, **kwargs):
                    self.returncode = 0

                def poll(self):
                    return 0

                def terminate(self):
                    self.returncode = 0

                def wait(self):
                    return 0

            with patch("aegis.runners.strix_runner.docker_available", return_value=True), \
                 patch("aegis.runners.strix_runner.subprocess.Popen", side_effect=FakeProc), \
                 patch("aegis.runners.strix_runner.shutil.which", return_value="/fake/strix"):
                result = run_strix("http://localhost:3000", state, scan_mode="deep")

            self.assertEqual(
                result.command[result.command.index("--scan-mode") + 1],
                "deep",
            )

    def test_invalid_scan_mode_falls_back_to_standard(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "rz2")

            class FakeProc:
                def __init__(self, *args, **kwargs):
                    self.returncode = 0

                def poll(self):
                    return 0

                def terminate(self):
                    self.returncode = 0

                def wait(self):
                    return 0

            with patch("aegis.runners.strix_runner.docker_available", return_value=True), \
                 patch("aegis.runners.strix_runner.subprocess.Popen", side_effect=FakeProc), \
                 patch("aegis.runners.strix_runner.shutil.which", return_value="/fake/strix"):
                result = run_strix("http://localhost:3000", state, scan_mode="bogus")

            self.assertEqual(
                result.command[result.command.index("--scan-mode") + 1],
                "standard",
            )

    def test_multiple_targets_emit_repeated_target_flags_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "rt-multi")

            class FakeProc:
                def __init__(self, *args, **kwargs):
                    self.returncode = 0

                def poll(self):
                    return 0

                def terminate(self):
                    self.returncode = 0

                def wait(self):
                    return 0

            with patch("aegis.runners.strix_runner.docker_available", return_value=True), \
                 patch("aegis.runners.strix_runner.subprocess.Popen", side_effect=FakeProc), \
                 patch("aegis.runners.strix_runner.shutil.which", return_value="/fake/strix"):
                result = run_strix(
                    "http://primary:3000", state,
                    targets=["./repo", "https://staging.example.com",
                             "https://prod.example.com"],
                )

            cmd = result.command
            # Every effective target appears as its own --target <t>, in order.
            target_values = [cmd[i + 1] for i, tok in enumerate(cmd) if tok == "--target"]
            self.assertEqual(
                target_values,
                ["./repo", "https://staging.example.com", "https://prod.example.com"],
            )
            # The explicit single `target` is ignored once `targets` is provided.
            self.assertNotIn("http://primary:3000", cmd)

    def test_single_target_command_unchanged_when_targets_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "rt-single")

            class FakeProc:
                def __init__(self, *args, **kwargs):
                    self.returncode = 0

                def poll(self):
                    return 0

                def terminate(self):
                    self.returncode = 0

                def wait(self):
                    return 0

            with patch("aegis.runners.strix_runner.docker_available", return_value=True), \
                 patch("aegis.runners.strix_runner.subprocess.Popen", side_effect=FakeProc), \
                 patch("aegis.runners.strix_runner.shutil.which", return_value="/fake/strix"):
                result = run_strix("http://localhost:3000", state)

            cmd = result.command
            # Exactly one --target whose value is the single positional target,
            # immediately followed by -n (target-arg emission unchanged).
            self.assertEqual(cmd.count("--target"), 1)
            idx = cmd.index("--target")
            self.assertEqual(cmd[idx + 1], "http://localhost:3000")
            self.assertEqual(cmd[idx + 2], "-n")

    def test_instruction_file_replaces_instruction(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "rt-ifile")

            class FakeProc:
                def __init__(self, *args, **kwargs):
                    self.returncode = 0

                def poll(self):
                    return 0

                def terminate(self):
                    self.returncode = 0

                def wait(self):
                    return 0

            with patch("aegis.runners.strix_runner.docker_available", return_value=True), \
                 patch("aegis.runners.strix_runner.subprocess.Popen", side_effect=FakeProc), \
                 patch("aegis.runners.strix_runner.shutil.which", return_value="/fake/strix"):
                result = run_strix(
                    "http://localhost:3000", state,
                    instruction="inline text",
                    instruction_file="/tmp/instr.md",
                )

            cmd = result.command
            # instruction_file wins and instruction is suppressed (mutually
            # exclusive at Strix).
            self.assertIn("--instruction-file", cmd)
            self.assertEqual(cmd[cmd.index("--instruction-file") + 1], "/tmp/instr.md")
            self.assertNotIn("--instruction", cmd)

    def test_scope_mode_default_is_auto(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "rt-scope-default")

            class FakeProc:
                def __init__(self, *args, **kwargs):
                    self.returncode = 0

                def poll(self):
                    return 0

                def terminate(self):
                    self.returncode = 0

                def wait(self):
                    return 0

            with patch("aegis.runners.strix_runner.docker_available", return_value=True), \
                 patch("aegis.runners.strix_runner.subprocess.Popen", side_effect=FakeProc), \
                 patch("aegis.runners.strix_runner.shutil.which", return_value="/fake/strix"):
                result = run_strix("http://localhost:3000", state)

            cmd = result.command
            self.assertIn("--scope-mode", cmd)
            self.assertEqual(cmd[cmd.index("--scope-mode") + 1], "auto")

    def test_scope_mode_explicit_values_honored(self):
        for mode in ("diff", "full"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                state = RunState(tmp, f"rt-scope-{mode}")

                class FakeProc:
                    def __init__(self, *args, **kwargs):
                        self.returncode = 0

                    def poll(self):
                        return 0

                    def terminate(self):
                        self.returncode = 0

                    def wait(self):
                        return 0

                with patch("aegis.runners.strix_runner.docker_available", return_value=True), \
                     patch("aegis.runners.strix_runner.subprocess.Popen", side_effect=FakeProc), \
                     patch("aegis.runners.strix_runner.shutil.which", return_value="/fake/strix"):
                    result = run_strix("http://localhost:3000", state, scope_mode=mode)

                cmd = result.command
                self.assertEqual(cmd[cmd.index("--scope-mode") + 1], mode)

    def test_invalid_scope_mode_falls_back_to_auto(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "rt-scope-bad")

            class FakeProc:
                def __init__(self, *args, **kwargs):
                    self.returncode = 0

                def poll(self):
                    return 0

                def terminate(self):
                    self.returncode = 0

                def wait(self):
                    return 0

            with patch("aegis.runners.strix_runner.docker_available", return_value=True), \
                 patch("aegis.runners.strix_runner.subprocess.Popen", side_effect=FakeProc), \
                 patch("aegis.runners.strix_runner.shutil.which", return_value="/fake/strix"):
                result = run_strix("http://localhost:3000", state, scope_mode="sideways")

            cmd = result.command
            self.assertEqual(cmd[cmd.index("--scope-mode") + 1], "auto")

    def test_diff_base_only_emitted_when_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "rt-diff")

            class FakeProc:
                def __init__(self, *args, **kwargs):
                    self.returncode = 0

                def poll(self):
                    return 0

                def terminate(self):
                    self.returncode = 0

                def wait(self):
                    return 0

            with patch("aegis.runners.strix_runner.docker_available", return_value=True), \
                 patch("aegis.runners.strix_runner.subprocess.Popen", side_effect=FakeProc), \
                 patch("aegis.runners.strix_runner.shutil.which", return_value="/fake/strix"):
                without = run_strix("http://localhost:3000", state)
                with_base = run_strix(
                    "http://localhost:3000", state, diff_base="origin/main",
                )

            self.assertNotIn("--diff-base", without.command)
            self.assertIn("--diff-base", with_base.command)
            self.assertEqual(
                with_base.command[with_base.command.index("--diff-base") + 1],
                "origin/main",
            )

    def test_no_events_file_degrades_to_empty_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "rw")

            # Strix "runs" and exits 0 but never writes a strix_runs/ tree.
            class FakeProc:
                def __init__(self, *args, **kwargs):
                    self.returncode = 0

                def poll(self):
                    return 0

                def terminate(self):
                    self.returncode = 0

                def wait(self):
                    return 0

            with patch("aegis.runners.strix_runner.docker_available", return_value=True), \
                 patch("aegis.runners.strix_runner.subprocess.Popen", side_effect=FakeProc), \
                 patch("aegis.runners.strix_runner.shutil.which", return_value="/fake/strix"):
                result = run_strix("http://localhost:3000", state)

            self.assertTrue(result.success)
            self.assertEqual(result.findings, [])
            self.assertFalse(result.partial_success)


class TestRunStrixConcurrentRuns(unittest.TestCase):
    """Two overlapping runs must each discover only their own events file.

    Regression for the old newest-mtime glob, which keyed discovery to a shared
    tree and could hand one run another run's events.jsonl. Each run now owns a
    deterministic per-run output dir (``strix_dir/run-<run_id>/``); discovery is
    keyed to it, so concurrent runs are fully isolated.
    """

    def test_each_concurrent_run_finds_its_own_events_file(self):
        with tempfile.TemporaryDirectory() as tmp_a, \
             tempfile.TemporaryDirectory() as tmp_b:
            state_a = RunState(tmp_a, "run-a")
            state_b = RunState(tmp_b, "run-b")

            # Both runs launch at (close to) the same time so their events
            # files share an mtime window — the exact case the old glob got
            # wrong. A barrier forces the two FakeProcs to overlap.
            barrier = threading.Barrier(2)

            # A FakeProc that writes a finding (whose id is keyed off its own
            # cwd) into <cwd>/strix_runs/auto/events.jsonl — i.e. relative to
            # the per-run dir the runner launches it in, mirroring real Strix.
            class FakeProc:
                def __init__(self, *args, **kwargs):
                    self.returncode = None
                    cwd = Path(kwargs["cwd"])
                    # The finding id encodes the run-<id> dir name so we can
                    # later prove no cross-run leakage.
                    self._marker = cwd.name
                    self._events = cwd / "strix_runs" / "auto" / "events.jsonl"
                    self._t = threading.Thread(target=self._run, daemon=True)
                    self._t.start()

                def _run(self):
                    barrier.wait(timeout=5)
                    self._events.parent.mkdir(parents=True, exist_ok=True)
                    with open(self._events, "a") as fh:
                        fh.write(json.dumps({
                            "event_type": "finding.created",
                            "payload": {"report": {
                                "id": f"vuln-{self._marker}",
                                "title": self._marker,
                            }},
                        }) + "\n")
                    time.sleep(0.03)
                    self.returncode = 0

                def poll(self):
                    return self.returncode

                def terminate(self):
                    self.returncode = 0

                def wait(self):
                    while self.returncode is None:
                        time.sleep(0.01)
                    return self.returncode

            results: dict[str, object] = {}

            def _launch(key: str, state: RunState) -> None:
                results[key] = run_strix("http://localhost:3000", state)

            # Patch once in the main thread (the patches are identical for both
            # runs). unittest.mock.patch mutates shared module globals and is not
            # thread-safe, so applying it *inside* each worker thread could leak
            # a stale mock onto aegis.runners.strix_runner and flake unrelated
            # tests; the worker threads only call run_strix.
            with patch("aegis.runners.strix_runner.docker_available", return_value=True), \
                 patch("aegis.runners.strix_runner.subprocess.Popen", side_effect=FakeProc), \
                 patch("aegis.runners.strix_runner.shutil.which", return_value="/fake/strix"):
                t_a = threading.Thread(target=_launch, args=("a", state_a))
                t_b = threading.Thread(target=_launch, args=("b", state_b))
                t_a.start()
                t_b.start()
                t_a.join()
                t_b.join()

            res_a = results["a"]
            res_b = results["b"]

            run_dir_a = run_output_dir(state_a.run_path / "strix", "run-a")
            run_dir_b = run_output_dir(state_b.run_path / "strix", "run-b")

            # Each run sees exactly its own finding — no cross-contamination.
            # The FakeProc keys each finding id off its cwd (the per-run dir
            # name), so the expected ids follow run_dir.name.
            self.assertEqual({f.id for f in res_a.findings}, {f"vuln-{run_dir_a.name}"})
            self.assertEqual({f.id for f in res_b.findings}, {f"vuln-{run_dir_b.name}"})
            self.assertNotEqual(
                {f.id for f in res_a.findings}, {f.id for f in res_b.findings},
            )

            # And each resolved events_path lives under its own per-run dir.
            self.assertTrue(res_a.events_path.startswith(str(run_dir_a)))
            self.assertTrue(res_b.events_path.startswith(str(run_dir_b)))
            self.assertNotEqual(res_a.events_path, res_b.events_path)


if __name__ == "__main__":
    unittest.main()
