import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from redsim.targets import (
    JuiceShopPack,
    get_target_pack,
    list_target_packs,
)


def _mock_run_factory(commands_log: list[list[str]]):
    """Return a subprocess.run mock that records calls and fakes useful output."""
    def _mock(cmd, **kwargs):
        commands_log.append(list(cmd))
        if cmd[:3] == ["docker", "run", "-d"]:
            stdout = "container-id-abc123\n"
        elif cmd[:3] == ["docker", "image", "inspect"]:
            stdout = "sha256:deadbeef\n"
        elif cmd[:1] == ["git"] and "rev-parse" in cmd:
            stdout = "abc1234\n"
        else:
            stdout = ""
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")
    return _mock


class TestTargetPackRegistry(unittest.TestCase):
    def test_list_includes_juice_shop_and_dvwa(self):
        names = list_target_packs()
        self.assertIn("juice-shop", names)
        self.assertIn("dvwa", names)

    def test_get_juice_shop_default_port(self):
        pack = get_target_pack("juice-shop")
        self.assertEqual(pack.port, 3000)
        self.assertEqual(pack.runtime.url, "http://localhost:3000")

    def test_container_name_includes_run_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_path = Path(tmp) / "20260527-runA"
            run_path.mkdir()
            pack1 = get_target_pack("juice-shop", run_path=run_path)
            run_path2 = Path(tmp) / "20260527-runB"
            run_path2.mkdir()
            pack2 = get_target_pack("juice-shop", run_path=run_path2)
            self.assertNotEqual(pack1.container_name, pack2.container_name)
            self.assertIn("20260527-runA", pack1.container_name)
            self.assertIn("20260527-runB", pack2.container_name)

    def test_dvwa_image_is_pinned(self):
        from redsim.targets import DvwaPack
        self.assertNotIn(":latest", DvwaPack.image)
        self.assertIn(":", DvwaPack.image, msg="DVWA image must carry an explicit tag")

    def test_underscore_alias(self):
        pack = get_target_pack("juice_shop")
        self.assertIsInstance(pack, JuiceShopPack)

    def test_unknown_pack_raises(self):
        with self.assertRaises(ValueError):
            get_target_pack("nope")


class TestImageModeUp(unittest.TestCase):
    def test_up_runs_pinned_image_and_writes_runtime(self):
        commands: list[list[str]] = []
        with tempfile.TemporaryDirectory() as tmp:
            run_path = Path(tmp)
            pack = JuiceShopPack(run_path=run_path)
            with patch("redsim.targets.subprocess.run", side_effect=_mock_run_factory(commands)):
                runtime = pack.up()

            self.assertEqual(runtime.mode, "image")
            self.assertEqual(runtime.image_tag, "bkimminich/juice-shop:v17.3.0")
            self.assertEqual(runtime.container_id, "container-id-abc123")
            self.assertEqual(runtime.built_image_digest, "sha256:deadbeef")
            self.assertIsNotNone(runtime.started_at)

            run_invocations = [c for c in commands if c[:3] == ["docker", "run", "-d"]]
            self.assertEqual(len(run_invocations), 1)
            self.assertIn("bkimminich/juice-shop:v17.3.0", run_invocations[0])
            self.assertIn("3000:3000", " ".join(run_invocations[0]))

            runtime_path = run_path / "target" / "runtime.json"
            self.assertTrue(runtime_path.exists())
            data = json.loads(runtime_path.read_text())
            self.assertEqual(data["name"], "juice-shop")
            self.assertEqual(data["mode"], "image")


class TestSourceModeLifecycle(unittest.TestCase):
    def test_up_from_repo_builds_and_rebuilds(self):
        commands: list[list[str]] = []
        with tempfile.TemporaryDirectory() as tmp:
            run_path = Path(tmp) / "run"
            run_path.mkdir()
            repo_path = Path(tmp) / "juice-shop"
            repo_path.mkdir()
            pack = JuiceShopPack(run_path=run_path)
            with patch("redsim.targets.subprocess.run", side_effect=_mock_run_factory(commands)):
                runtime = pack.up_from_repo(repo_path)
                self.assertEqual(runtime.mode, "source")
                self.assertEqual(runtime.image_tag, "redsim-juice-shop:local")
                self.assertEqual(runtime.source_repo, str(repo_path.resolve()))
                first_started = runtime.started_at

                pack.rebuild(repo_path)

                builds = [c for c in commands if c[:3] == ["docker", "build", "-t"]]
                self.assertEqual(len(builds), 2)
                for build in builds:
                    self.assertIn("redsim-juice-shop:local", build)
                    self.assertIn(str(repo_path.resolve()), build)

                runs = [c for c in commands if c[:3] == ["docker", "run", "-d"]]
                self.assertEqual(len(runs), 2)

                rms = [c for c in commands if c[:3] == ["docker", "rm", "-f"]]
                self.assertGreaterEqual(len(rms), 2)

                runtime_data = json.loads((run_path / "target" / "runtime.json").read_text())
                self.assertIsNotNone(runtime_data["last_rebuild_at"])
                self.assertEqual(runtime_data["started_at"], first_started)

    def test_rebuild_requires_source_mode(self):
        pack = JuiceShopPack()
        with self.assertRaises(RuntimeError):
            pack.rebuild("/tmp/nope")

    def test_up_from_repo_rejects_missing_path(self):
        pack = JuiceShopPack()
        with self.assertRaises(FileNotFoundError):
            pack.up_from_repo("/nonexistent/path/12345")


class TestDown(unittest.TestCase):
    def test_down_invokes_docker_rm_force(self):
        commands: list[list[str]] = []
        pack = JuiceShopPack()
        with patch("redsim.targets.subprocess.run", side_effect=_mock_run_factory(commands)):
            pack.down()
        self.assertTrue(any(c[:3] == ["docker", "rm", "-f"] for c in commands))


if __name__ == "__main__":
    unittest.main()
