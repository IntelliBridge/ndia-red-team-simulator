"""Cloud-target ownership verification + backport base-branch selection.

All offline. The DNS resolver is faked via a stand-in ``dns.resolver`` module
injected into ``sys.modules`` so the tests pass whether or not ``dnspython``
is installed (the verify module imports it lazily and degrades cleanly). The
GitHub check mocks ``GitHubClient`` + ``httpx``; the DB is in-memory sqlite
(JSONB compiled to TEXT), mirroring ``test_finding_tickets.py``.
"""

from __future__ import annotations

import contextlib
import sys
import types
import unittest
from unittest.mock import patch

import pytest

pytest.importorskip("sqlalchemy")

from aegis.config import AegisConfig
from aegis.remediate.patch_workflow import (
    DEFAULT_BASE_BRANCH,
    _parse_release_trains,
    open_pull_request,
    select_base_branch,
)
from aegis.services import target_verify as tv

# ---------------------------------------------------------------------------
# Fake dns.resolver (so DNS tests don't require dnspython to be installed)
# ---------------------------------------------------------------------------

class _FakeTXT:
    def __init__(self, value: str):
        self.strings = [value.encode("utf-8")]


@contextlib.contextmanager
def fake_dns(*, txt_values=None, exc=None):
    """Install a stand-in ``dns.resolver`` whose ``resolve`` is controllable."""
    resolver_mod = types.ModuleType("dns.resolver")

    class NXDOMAIN(Exception):
        pass

    class NoAnswer(Exception):
        pass

    class NoNameservers(Exception):
        pass

    class LifetimeTimeout(Exception):
        pass

    resolver_mod.NXDOMAIN = NXDOMAIN
    resolver_mod.NoAnswer = NoAnswer
    resolver_mod.NoNameservers = NoNameservers
    resolver_mod.LifetimeTimeout = LifetimeTimeout

    def resolve(host, rtype):  # noqa: ARG001
        if exc is not None:
            raise exc(resolver_mod)
        return [_FakeTXT(v) for v in (txt_values or [])]

    resolver_mod.resolve = resolve
    dns_mod = types.ModuleType("dns")
    dns_mod.resolver = resolver_mod

    with patch.dict(sys.modules, {"dns": dns_mod, "dns.resolver": resolver_mod}):
        yield resolver_mod


class _Target:
    """Minimal stand-in for a Target row for the pure token tests."""

    def __init__(self, project_id, value, kind="url", installation_id=None):
        self.project_id = project_id
        self.value = value
        self.kind = kind
        self.installation_id = installation_id


# ---------------------------------------------------------------------------
# expected_dns_token (pure)
# ---------------------------------------------------------------------------

class TestExpectedDnsToken(unittest.TestCase):
    def test_deterministic(self):
        t = _Target("proj-1", "https://app.example.com")
        with patch.dict("os.environ", {"AEGIS_VERIFY_SECRET": "s"}):
            a = tv.expected_dns_token(t)
            b = tv.expected_dns_token(t)
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("aegis-site-verification="))

    def test_changes_with_project(self):
        with patch.dict("os.environ", {"AEGIS_VERIFY_SECRET": "s"}):
            a = tv.expected_dns_token(_Target("proj-1", "https://x.example.com"))
            b = tv.expected_dns_token(_Target("proj-2", "https://x.example.com"))
        self.assertNotEqual(a, b)

    def test_changes_with_value(self):
        with patch.dict("os.environ", {"AEGIS_VERIFY_SECRET": "s"}):
            a = tv.expected_dns_token(_Target("proj-1", "https://a.example.com"))
            b = tv.expected_dns_token(_Target("proj-1", "https://b.example.com"))
        self.assertNotEqual(a, b)

    def test_changes_with_secret(self):
        t = _Target("proj-1", "https://app.example.com")
        with patch.dict("os.environ", {"AEGIS_VERIFY_SECRET": "s1"}):
            a = tv.expected_dns_token(t)
        with patch.dict("os.environ", {"AEGIS_VERIFY_SECRET": "s2"}):
            b = tv.expected_dns_token(t)
        self.assertNotEqual(a, b)

    def test_config_secret_used_when_env_unset(self):
        import os
        t = _Target("proj-1", "https://app.example.com")
        cfg = AegisConfig(verify_secret="from-config")
        env = {k: v for k, v in os.environ.items() if k != "AEGIS_VERIFY_SECRET"}
        with patch.dict("os.environ", env, clear=True):
            from_cfg = tv.expected_dns_token(t, config=cfg)
            from_default = tv.expected_dns_token(t)
        self.assertNotEqual(from_cfg, from_default)

    def test_extract_host(self):
        self.assertEqual(tv.extract_host("https://app.example.com/x"), "app.example.com")
        self.assertEqual(tv.extract_host("app.example.com:8443"), "app.example.com")
        self.assertEqual(tv.extract_host("app.example.com."), "app.example.com")


# ---------------------------------------------------------------------------
# verify_dns_txt
# ---------------------------------------------------------------------------

class TestVerifyDnsTxt(unittest.TestCase):
    def test_matching_txt_returns_true(self):
        token = "aegis-site-verification=abc123"
        with fake_dns(txt_values=["unrelated", token]):
            ok, detail = tv.verify_dns_txt("https://app.example.com", token)
        self.assertTrue(ok)
        self.assertIn("app.example.com", detail)

    def test_no_matching_txt_returns_false(self):
        with fake_dns(txt_values=["something-else"]):
            ok, detail = tv.verify_dns_txt("app.example.com", "aegis-site-verification=x")
        self.assertFalse(ok)
        self.assertIn("none match", detail)

    def test_nxdomain_false_with_reason(self):
        with fake_dns(exc=lambda m: m.NXDOMAIN()):
            ok, detail = tv.verify_dns_txt("nope.example.com", "aegis-site-verification=x")
        self.assertFalse(ok)
        self.assertIn("NXDOMAIN", detail)

    def test_no_answer_false(self):
        with fake_dns(exc=lambda m: m.NoAnswer()):
            ok, detail = tv.verify_dns_txt("app.example.com", "aegis-site-verification=x")
        self.assertFalse(ok)
        self.assertIn("no TXT", detail)

    def test_timeout_false(self):
        with fake_dns(exc=lambda m: m.LifetimeTimeout()):
            ok, detail = tv.verify_dns_txt("app.example.com", "aegis-site-verification=x")
        self.assertFalse(ok)
        self.assertIn("timed out", detail)

    def test_no_nameservers_false(self):
        with fake_dns(exc=lambda m: m.NoNameservers()):
            ok, detail = tv.verify_dns_txt("app.example.com", "aegis-site-verification=x")
        self.assertFalse(ok)
        self.assertIn("nameservers", detail)

    def test_empty_host_false(self):
        ok, detail = tv.verify_dns_txt("", "aegis-site-verification=x")
        self.assertFalse(ok)
        self.assertIn("hostname", detail)

    def test_missing_dnspython_degrades(self):
        # Simulate dnspython absence: no 'dns' module importable.
        with patch.dict(sys.modules, {"dns": None, "dns.resolver": None}):
            ok, detail = tv.verify_dns_txt("app.example.com", "aegis-site-verification=x")
        self.assertFalse(ok)
        self.assertIn("dnspython", detail)


# ---------------------------------------------------------------------------
# verify_github_repo
# ---------------------------------------------------------------------------

class _FakeResp:
    def __init__(self, status_code):
        self.status_code = status_code


class _FakeHttpClient:
    def __init__(self, status_code):
        self._status = status_code
        self.calls: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get(self, url, *, headers=None):  # noqa: ARG002
        self.calls.append(url)
        return _FakeResp(self._status)


class TestVerifyGithubRepo(unittest.TestCase):
    def test_no_installation_id_false(self):
        ok, detail = tv.verify_github_repo("acme/app", None)
        self.assertFalse(ok)
        self.assertIn("installation", detail)

    def test_bad_slug_false(self):
        ok, detail = tv.verify_github_repo("not-a-slug", 42)
        self.assertFalse(ok)
        self.assertIn("owner/name", detail)

    def test_accessible_repo_true(self):
        with patch("aegis.integrations.github_app.GitHubClient") as mk, \
             patch("httpx.Client", return_value=_FakeHttpClient(200)):
            mk.return_value._headers.return_value = {"Authorization": "token x"}
            ok, detail = tv.verify_github_repo("https://github.com/acme/app.git", 42)
        self.assertTrue(ok)
        self.assertIn("acme/app", detail)

    def test_404_false(self):
        with patch("aegis.integrations.github_app.GitHubClient") as mk, \
             patch("httpx.Client", return_value=_FakeHttpClient(404)):
            mk.return_value._headers.return_value = {"Authorization": "token x"}
            ok, detail = tv.verify_github_repo("acme/app", 42)
        self.assertFalse(ok)
        self.assertIn("cannot access", detail)

    def test_500_false(self):
        with patch("aegis.integrations.github_app.GitHubClient") as mk, \
             patch("httpx.Client", return_value=_FakeHttpClient(500)):
            mk.return_value._headers.return_value = {"Authorization": "token x"}
            ok, detail = tv.verify_github_repo("acme/app", 42)
        self.assertFalse(ok)
        self.assertIn("500", detail)

    def test_http_error_wrapped(self):
        import httpx

        class _Boom:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def get(self, url, *, headers=None):  # noqa: ARG002
                raise httpx.ConnectError("dns down")

        with patch("aegis.integrations.github_app.GitHubClient") as mk, \
             patch("httpx.Client", return_value=_Boom()):
            mk.return_value._headers.return_value = {"Authorization": "token x"}
            ok, detail = tv.verify_github_repo("acme/app", 42)
        self.assertFalse(ok)
        self.assertIn("failed", detail)

    def test_client_build_keyerror_degrades(self):
        # GitHubClient.__init__ raises KeyError when AEGIS_GITHUB_APP_ID unset.
        with patch("aegis.integrations.github_app.GitHubClient",
                   side_effect=KeyError("AEGIS_GITHUB_APP_ID")):
            ok, detail = tv.verify_github_repo("acme/app", 42)
        self.assertFalse(ok)
        self.assertIn("not configured", detail)


# ---------------------------------------------------------------------------
# select_base_branch + open_pull_request backport awareness
# ---------------------------------------------------------------------------

class TestSelectBaseBranch(unittest.TestCase):
    def test_no_hint_is_main(self):
        import os
        env = {k: v for k, v in os.environ.items() if k != "AEGIS_RELEASE_TRAINS"}
        with patch.dict("os.environ", env, clear=True):
            self.assertEqual(select_base_branch(None), "main")
            self.assertEqual(select_base_branch(None), DEFAULT_BASE_BRANCH)

    def test_json_mapping_hit(self):
        env = {"AEGIS_RELEASE_TRAINS": '{"2024.1": "release/2024.1"}'}
        with patch.dict("os.environ", env):
            self.assertEqual(select_base_branch("2024.1"), "release/2024.1")

    def test_compact_mapping_hit(self):
        env = {"AEGIS_RELEASE_TRAINS": "lts=release/lts,next=develop"}
        with patch.dict("os.environ", env):
            self.assertEqual(select_base_branch("lts"), "release/lts")
            self.assertEqual(select_base_branch("next"), "develop")

    def test_unknown_hint_falls_back_to_main(self):
        env = {"AEGIS_RELEASE_TRAINS": "lts=release/lts"}
        with patch.dict("os.environ", env):
            self.assertEqual(select_base_branch("bogus"), "main")

    def test_concrete_branch_value_passes_through(self):
        env = {"AEGIS_RELEASE_TRAINS": "lts=release/lts"}
        with patch.dict("os.environ", env):
            self.assertEqual(select_base_branch("release/lts"), "release/lts")

    def test_config_fallback_when_env_unset(self):
        import os
        cfg = AegisConfig(release_trains="lts=release/lts")
        env = {k: v for k, v in os.environ.items() if k != "AEGIS_RELEASE_TRAINS"}
        with patch.dict("os.environ", env, clear=True):
            self.assertEqual(select_base_branch("lts", config=cfg), "release/lts")

    def test_malformed_json_falls_back(self):
        self.assertEqual(_parse_release_trains("{not json"), {})
        self.assertEqual(_parse_release_trains(""), {})
        self.assertEqual(_parse_release_trains(None), {})

    def test_open_pull_request_default_base_unchanged(self):
        calls: list[list[str]] = []

        def fake_run(argv, **kwargs):  # noqa: ARG001
            import subprocess
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, stdout="https://pr/1\n", stderr="")

        with patch("aegis.remediate.patch_workflow.subprocess.run", side_effect=fake_run):
            ok, url = open_pull_request("/tmp/repo", "aegis/fix/x",
                                        title="t", body="b", push=False)
        self.assertTrue(ok)
        pr_call = [c for c in calls if c[:3] == ["gh", "pr", "create"]][0]
        self.assertIn("--base", pr_call)
        self.assertEqual(pr_call[pr_call.index("--base") + 1], "main")

    def test_open_pull_request_hint_derives_base(self):
        calls: list[list[str]] = []

        def fake_run(argv, **kwargs):  # noqa: ARG001
            import subprocess
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, stdout="https://pr/1\n", stderr="")

        env = {"AEGIS_RELEASE_TRAINS": "lts=release/lts"}
        with patch.dict("os.environ", env), \
             patch("aegis.remediate.patch_workflow.subprocess.run", side_effect=fake_run):
            ok, url = open_pull_request("/tmp/repo", "aegis/fix/x",
                                        title="t", body="b",
                                        base_hint="lts", push=False)
        self.assertTrue(ok)
        pr_call = [c for c in calls if c[:3] == ["gh", "pr", "create"]][0]
        self.assertEqual(pr_call[pr_call.index("--base") + 1], "release/lts")


if __name__ == "__main__":
    unittest.main()
