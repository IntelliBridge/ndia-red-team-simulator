"""Tests for the air-gapped submodule mirror helpers (Feature: offline vendor host).

Covers the pure ``aegis.vendor`` rewrite rules, the ``.gitmodules`` mapping,
the ``offline_vendor_host`` config env read, and a ``bash -n`` lint of the
companion plumbing script.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.config import load_config
from aegis.vendor import mirror_url, submodule_mirror_map

REPO_ROOT = Path(__file__).resolve().parent.parent
VENDOR_SCRIPT = REPO_ROOT / "scripts" / "vendor-submodules.sh"

SAMPLE_GITMODULES = """\
[submodule "project_repos/cai"]
\tpath = project_repos/cai
\turl = https://github.com/aliasrobotics/cai.git
[submodule "project_repos/mcp-kali-server"]
\tpath = project_repos/mcp-kali-server
\turl = https://gitlab.com/kalilinux/packages/mcp-kali-server.git
[submodule "project_repos/strix"]
\tpath = project_repos/strix
\turl = git@github.com:usestrix/strix.git
[submodule "project_repos/shadcn-ui"]
\tpath = project_repos/shadcn-ui
\turl = https://github.com/shadcn-ui/ui
"""


class TestMirrorUrl(unittest.TestCase):
    def test_https_with_dot_git(self):
        self.assertEqual(
            mirror_url("https://github.com/aliasrobotics/cai.git", "mirror.int"),
            "https://mirror.int/aliasrobotics/cai.git",
        )

    def test_https_without_dot_git(self):
        # Trailing .git is normalised back on exactly once.
        self.assertEqual(
            mirror_url("https://github.com/shadcn-ui/ui", "mirror.int"),
            "https://mirror.int/shadcn-ui/ui.git",
        )

    def test_ssh_scp_form(self):
        self.assertEqual(
            mirror_url("git@github.com:usestrix/strix.git", "mirror.int"),
            "https://mirror.int/usestrix/strix.git",
        )

    def test_ssh_scp_form_without_dot_git(self):
        self.assertEqual(
            mirror_url("git@github.com:usestrix/strix", "mirror.int"),
            "https://mirror.int/usestrix/strix.git",
        )

    def test_ssh_scheme_form(self):
        self.assertEqual(
            mirror_url("ssh://git@github.com/org/repo.git", "mirror.int"),
            "https://mirror.int/org/repo.git",
        )

    def test_nested_path_preserved(self):
        self.assertEqual(
            mirror_url(
                "https://gitlab.com/kalilinux/packages/mcp-kali-server.git",
                "mirror.int",
            ),
            "https://mirror.int/kalilinux/packages/mcp-kali-server.git",
        )

    def test_host_with_scheme_and_slash_normalised(self):
        self.assertEqual(
            mirror_url("https://github.com/org/repo.git", "https://mirror.int/"),
            "https://mirror.int/org/repo.git",
        )

    def test_https_host_with_port(self):
        self.assertEqual(
            mirror_url("https://github.com:443/org/repo.git", "mirror.int"),
            "https://mirror.int/org/repo.git",
        )


class TestSubmoduleMirrorMap(unittest.TestCase):
    def test_map_over_sample_gitmodules(self):
        mapping = submodule_mirror_map(SAMPLE_GITMODULES, "mirror.int")
        self.assertEqual(
            mapping,
            {
                "https://github.com/aliasrobotics/cai.git":
                    "https://mirror.int/aliasrobotics/cai.git",
                "https://gitlab.com/kalilinux/packages/mcp-kali-server.git":
                    "https://mirror.int/kalilinux/packages/mcp-kali-server.git",
                "git@github.com:usestrix/strix.git":
                    "https://mirror.int/usestrix/strix.git",
                "https://github.com/shadcn-ui/ui":
                    "https://mirror.int/shadcn-ui/ui.git",
            },
        )

    def test_empty_gitmodules(self):
        self.assertEqual(submodule_mirror_map("", "mirror.int"), {})

    def test_real_repo_gitmodules_all_mirrored(self):
        gitmodules = REPO_ROOT / ".gitmodules"
        if not gitmodules.exists():
            self.skipTest("no .gitmodules in repo root")
        mapping = submodule_mirror_map(gitmodules.read_text(), "mirror.int")
        self.assertTrue(mapping)
        for mirrored in mapping.values():
            self.assertTrue(mirrored.startswith("https://mirror.int/"))
            self.assertTrue(mirrored.endswith(".git"))


class TestConfigReadsEnv(unittest.TestCase):
    def test_offline_vendor_host_defaults_none(self):
        with patch.dict("os.environ", {}, clear=True), \
             tempfile.TemporaryDirectory() as tmp:
            cfg = load_config(str(Path(tmp) / "missing.yaml"))
            self.assertIsNone(cfg.offline_vendor_host)

    def test_offline_vendor_host_from_env(self):
        with patch.dict(
            "os.environ", {"AEGIS_OFFLINE_VENDOR_HOST": "mirror.int"}, clear=True
        ), tempfile.TemporaryDirectory() as tmp:
            cfg = load_config(str(Path(tmp) / "missing.yaml"))
            self.assertEqual(cfg.offline_vendor_host, "mirror.int")

    def test_env_overrides_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_file = Path(tmp) / "aegis.yaml"
            cfg_file.write_text("offline_vendor_host: from-yaml\n")
            # YAML alone is honoured.
            with patch.dict("os.environ", {}, clear=True):
                self.assertEqual(
                    load_config(str(cfg_file)).offline_vendor_host, "from-yaml"
                )
            # Env wins over YAML.
            with patch.dict(
                "os.environ",
                {"AEGIS_OFFLINE_VENDOR_HOST": "from-env"},
                clear=True,
            ):
                self.assertEqual(
                    load_config(str(cfg_file)).offline_vendor_host, "from-env"
                )


class TestVendorScript(unittest.TestCase):
    def test_script_exists_and_executable(self):
        self.assertTrue(VENDOR_SCRIPT.exists(), VENDOR_SCRIPT)

    def test_bash_n_clean(self):
        result = subprocess.run(
            ["bash", "-n", str(VENDOR_SCRIPT)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
