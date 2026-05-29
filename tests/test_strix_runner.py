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

    def test_picks_newest_events_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            strix_dir = Path(tmp)
            old = strix_dir / "strix_runs" / "run-old" / "events.jsonl"
            new = strix_dir / "strix_runs" / "run-new" / "events.jsonl"
            for p in (old, new):
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("")
            # Force `new` to be the most recently modified.
            os.utime(old, (1_000_000, 1_000_000))
            os.utime(new, (2_000_000, 2_000_000))
            self.assertEqual(discover_events_path(strix_dir), new)


class TestRunStrixMockedSubprocess(unittest.TestCase):
    def test_partial_success_when_findings_emitted_but_rc_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(tmp, "ry")
            strix_dir = state.run_path / "strix"
            # Strix writes its events under strix_runs/<auto-name>/events.jsonl
            # relative to its cwd (which the runner sets to strix_dir).
            events_path = strix_dir / "strix_runs" / "auto-run" / "events.jsonl"
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

            # Strix must be launched with cwd=strix_dir so strix_runs/ lands there.
            self.assertEqual(popen.call_args.kwargs["cwd"], str(strix_dir))

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


if __name__ == "__main__":
    unittest.main()
