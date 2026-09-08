"""Effect classification — the spine of the unified human-in-the-loop gate.

Pure functions, no I/O: these run fully offline. They pin the contract that
``active``/``external`` capabilities are gated while ``read`` ones run freely,
and that an unknown domain/tool fails *safe* (gated), never open.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from redsim import effects
from redsim.effects import (
    build_action_plan,
    domain_default_effect,
    requires_approval,
    tool_effect,
)


class TestRequiresApproval(unittest.TestCase):
    def test_read_is_not_gated(self):
        self.assertFalse(requires_approval("read"))

    def test_active_and_external_are_gated(self):
        self.assertTrue(requires_approval("active"))
        self.assertTrue(requires_approval("external"))


class TestDomainDefaultEffect(unittest.TestCase):
    def test_known_domains(self):
        self.assertEqual(domain_default_effect("offensive"), "active")
        self.assertEqual(domain_default_effect("defensive"), "active")
        self.assertEqual(domain_default_effect("remediation"), "read")
        self.assertEqual(domain_default_effect("forensic"), "read")
        self.assertEqual(domain_default_effect("recon"), "read")
        self.assertEqual(domain_default_effect("audit"), "read")

    def test_unknown_and_none_fail_safe_to_active(self):
        # A mis-tagged or third-party domain must be gated, never open.
        self.assertEqual(domain_default_effect("wat"), "active")
        self.assertEqual(domain_default_effect(None), "active")
        self.assertEqual(domain_default_effect(""), "active")


class TestToolEffect(unittest.TestCase):
    """``tool_effect`` is the authoritative name -> effect lookup.

    The pentest Kali-tool table that once populated ``_TOOL_EFFECTS`` was
    removed with the pentest domain, so the table starts empty and the ML
    attack adapters register their own entries. The contract that matters is
    fail-safe: anything unlisted, blank or ``None`` is ``active`` (gated).
    """

    def test_unknown_and_blank_fail_safe_to_active(self):
        self.assertEqual(tool_effect("totally-unknown-tool"), "active")
        self.assertEqual(tool_effect(""), "active")
        self.assertEqual(tool_effect(None), "active")

    def test_table_starts_empty_in_this_fork(self):
        # No pentest tool is pre-classified as harmless.
        self.assertEqual(effects._TOOL_EFFECTS, {})
        for removed in ("nmap", "nikto", "sqlmap", "metasploit"):
            self.assertEqual(tool_effect(removed), "active", removed)

    def test_registered_entry_is_honoured_case_insensitively(self):
        with patch.dict(effects._TOOL_EFFECTS,
                        {"fake-recon": "read", "fake-evasion": "active"}):
            self.assertEqual(tool_effect("fake-recon"), "read")
            self.assertEqual(tool_effect("  FAKE-RECON "), "read")
            self.assertEqual(tool_effect("Fake-Evasion"), "active")

    def test_read_entries_are_not_gated_active_ones_are(self):
        with patch.dict(effects._TOOL_EFFECTS, {"fake-recon": "read"}):
            self.assertFalse(requires_approval(tool_effect("fake-recon")))
        self.assertTrue(requires_approval(tool_effect("unlisted-attack")))


class TestBuildActionPlan(unittest.TestCase):
    def test_plan_marks_gated_and_required_role(self):
        plan = build_action_plan(
            name="red_teamer", domain="offensive", effect="active",
            target="10.0.0.5", intent="pop the box",
        )
        self.assertTrue(plan["gated"])
        self.assertEqual(plan["required_role"], "approver")
        self.assertEqual(plan["agent"], "red_teamer")
        self.assertEqual(plan["domain"], "offensive")
        self.assertEqual(plan["effect"], "active")
        self.assertEqual(plan["target"], "10.0.0.5")
        self.assertEqual(plan["intent"], "pop the box")
        self.assertIn("execute=true", plan["to_execute"])

    def test_note_is_domain_specific(self):
        off = build_action_plan(name="x", domain="offensive", effect="active",
                                target=None, intent="i")
        deff = build_action_plan(name="y", domain="defensive", effect="active",
                                 target=None, intent="i")
        self.assertIn("exploitation", off["note"])
        self.assertIn("hardening", deff["note"])

    def test_note_falls_back_for_other_domains(self):
        plan = build_action_plan(name="z", domain="audit", effect="active",
                                 target=None, intent="i")
        self.assertIn("state-changing", plan["note"])


if __name__ == "__main__":
    unittest.main()
