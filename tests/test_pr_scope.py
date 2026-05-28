"""Phase 4 v0.4.1 F23a/b/c — PR scope + restricted mode.

A same-org PR builds a permissive PRScope; a fork PR builds a
restricted one. The webhook receiver dispatches into the handler so
fork detection is part of the structured response.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from aegis.integrations.github_handlers import (
    PRScope,
    on_pull_request_event,
    pr_scope_from_payload,
    restricted_mode_for,
    scope_audit_detail,
)


FIXTURES = Path(__file__).parent / "fixtures" / "github"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class TestPRScopeFromPayload(unittest.TestCase):
    def test_same_org_pr_is_not_fork(self):
        scope = pr_scope_from_payload(_load("pr_opened_same_org.json"))
        self.assertEqual(scope.repo, "acme/widget")
        self.assertEqual(scope.pr_number, 42)
        self.assertEqual(scope.head_ref, "fix-injection")
        self.assertFalse(scope.fork)
        self.assertEqual(scope.installation_id, 7777)

    def test_fork_pr_detected_by_full_name_diff(self):
        scope = pr_scope_from_payload(_load("pr_opened_fork.json"))
        self.assertEqual(scope.repo, "acme/widget")
        self.assertEqual(scope.head_repo_full_name, "outsider/widget")
        self.assertTrue(scope.fork)


class TestRestrictedMode(unittest.TestCase):
    def test_fork_engages_restricted(self):
        scope = pr_scope_from_payload(_load("pr_opened_fork.json"))
        scope.changed_files = ["routes/login.js", "package.json"]
        mode = restricted_mode_for(scope)
        self.assertFalse(mode.apply)
        self.assertFalse(mode.open_pr)
        self.assertEqual(mode.clone_depth, 1)
        self.assertFalse(mode.mount_secrets)
        self.assertEqual(mode.path_allowlist,
                         ["routes/login.js", "package.json"])
        self.assertEqual(mode.reason, "fork.restricted=true")

    def test_trusted_pr_gets_permissive_defaults(self):
        scope = pr_scope_from_payload(_load("pr_opened_same_org.json"))
        mode = restricted_mode_for(scope)
        self.assertFalse(mode.apply)
        self.assertEqual(mode.clone_depth, 0)
        self.assertTrue(mode.mount_secrets)
        self.assertEqual(mode.path_allowlist, [])
        self.assertEqual(mode.reason, "trusted")

    def test_scope_audit_detail_carries_fork_flag(self):
        scope = pr_scope_from_payload(_load("pr_opened_fork.json"))
        mode = restricted_mode_for(scope)
        detail = scope_audit_detail(scope, mode)
        self.assertTrue(detail["fork"])
        self.assertEqual(detail["restricted_mode"]["reason"],
                          "fork.restricted=true")
        self.assertEqual(detail["restricted_mode"]["clone_depth"], 1)


class TestEventDispatch(unittest.TestCase):
    def test_dispatcher_returns_structured_result(self):
        result = on_pull_request_event(_load("pr_opened_fork.json"))
        self.assertEqual(result["action"], "opened")
        self.assertTrue(result["scope"]["fork"])
        self.assertEqual(result["restricted_mode"], "fork.restricted=true")


if __name__ == "__main__":
    unittest.main()
