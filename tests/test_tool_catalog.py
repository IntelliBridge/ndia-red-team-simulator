"""Tests for the unified, honest tool catalog.

These run fully offline: the catalog is a static registry (no CAI/Camoufox at
import time), so we assert its shape, the source subsets (Kali == the mcp-kali
allowlist exactly — nothing snuck past the cap; scanners == the registry), the
conservative effect classification, and that ``build_extended_toolbelt``
degrades to a safe result when CAI is unavailable.
"""

from __future__ import annotations

import unittest

from aegis.effects import kali_tool_effect, requires_approval, tool_effect
from aegis.scanners.registry import list_scanners
from aegis.tools.catalog import (
    TOOL_CATALOG,
    ToolSpec,
    list_tools,
    tool_names,
)
from aegis.tools.catalog import (
    tool_effect as catalog_tool_effect,
)
from aegis.tools.kali_client import KaliClient

_VALID_SOURCES = {"kali", "scanner", "cai", "osint"}
_VALID_CATEGORIES = {
    "recon", "web", "network", "crypto", "exploitation",
    "forensic", "misc", "scanner",
}
_VALID_EFFECTS = {"read", "active", "external"}


class TestCatalogShape(unittest.TestCase):
    def test_at_least_35_tools(self):
        self.assertGreaterEqual(len(list_tools()), 35)

    def test_no_duplicate_names(self):
        names = tool_names()
        self.assertEqual(len(names), len(set(names)))

    def test_every_spec_is_valid(self):
        for spec in TOOL_CATALOG:
            self.assertIsInstance(spec, ToolSpec)
            self.assertTrue(spec.name)
            self.assertIn(spec.source, _VALID_SOURCES, spec.name)
            self.assertIn(spec.category, _VALID_CATEGORIES, spec.name)
            self.assertIn(spec.effect, _VALID_EFFECTS, spec.name)
            self.assertTrue(spec.description)

    def test_list_tools_returns_a_copy(self):
        copy = list_tools()
        copy.clear()
        self.assertGreaterEqual(len(TOOL_CATALOG), 35)


class TestKaliSubset(unittest.TestCase):
    def test_kali_names_equal_allowlist_exactly(self):
        # The Kali subset must equal mcp-kali's ALLOWED_TOOLS exactly: nothing
        # was added beyond what the server supports, and nothing dropped.
        kali = {s.name for s in TOOL_CATALOG if s.source == "kali"}
        self.assertEqual(kali, set(KaliClient.ALLOWED_TOOLS))

    def test_no_extra_kali_tools_sneaked_in(self):
        kali = [s.name for s in TOOL_CATALOG if s.source == "kali"]
        self.assertEqual(len(kali), 10)
        self.assertEqual(len(kali), len(KaliClient.ALLOWED_TOOLS))

    def test_kali_effects_match_kali_tool_effect(self):
        for spec in TOOL_CATALOG:
            if spec.source == "kali":
                self.assertEqual(spec.effect, kali_tool_effect(spec.name), spec.name)


class TestScannerSubset(unittest.TestCase):
    def test_scanner_names_are_a_subset_of_registry(self):
        # TOOL_CATALOG snapshots the registry at import. The full suite may
        # register extra fixture adapters (e.g. ``mock-dast``) into the live
        # global registry afterwards, so the catalog's scanner names must be a
        # *subset* of the current registry (nothing fabricated), and must cover
        # the 14 built-in adapters that exist at import time.
        scanners = {s.name for s in TOOL_CATALOG if s.source == "scanner"}
        self.assertTrue(scanners.issubset(set(list_scanners())))
        builtins = {
            "bandit", "bumblebee", "checkov", "codeql", "deepsec", "grype",
            "nuclei", "semgrep", "sonarqube", "strix", "syft", "trivy",
            "trufflehog", "zap",
        }
        self.assertTrue(builtins.issubset(scanners))

    def test_dast_scanners_are_active(self):
        by_name = {s.name: s for s in TOOL_CATALOG if s.source == "scanner"}
        for dast in ("zap", "nuclei", "strix"):
            if dast in by_name:
                self.assertEqual(by_name[dast].effect, "active", dast)

    def test_non_dast_scanners_are_read(self):
        for spec in TOOL_CATALOG:
            if spec.source == "scanner" and spec.name not in {"zap", "nuclei", "strix"}:
                self.assertEqual(spec.effect, "read", spec.name)


class TestOsintAndCaiTools(unittest.TestCase):
    def test_osint_search_present_and_external(self):
        by_name = {s.name: s for s in TOOL_CATALOG}
        self.assertIn("osint_search", by_name)
        spec = by_name["osint_search"]
        self.assertEqual(spec.source, "osint")
        self.assertEqual(spec.effect, "external")
        self.assertTrue(requires_approval(spec.effect))

    def test_active_cai_tool_is_active_and_gated(self):
        by_name = {s.name: s for s in TOOL_CATALOG}
        spec = by_name["cai_generic_linux_command"]
        self.assertEqual(spec.source, "cai")
        self.assertEqual(spec.effect, "active")
        self.assertTrue(requires_approval(spec.effect))

    def test_read_cai_tool_is_read(self):
        by_name = {s.name: s for s in TOOL_CATALOG}
        self.assertEqual(by_name["cai_curl"].effect, "read")
        self.assertFalse(requires_approval(by_name["cai_curl"].effect))

    def test_shodan_cai_tools_are_external(self):
        by_name = {s.name: s for s in TOOL_CATALOG}
        self.assertEqual(by_name["cai_shodan_search"].effect, "external")
        self.assertEqual(by_name["cai_shodan_host_info"].effect, "external")


class TestToolEffectLookup(unittest.TestCase):
    def test_catalog_and_effects_module_agree(self):
        for spec in TOOL_CATALOG:
            self.assertEqual(catalog_tool_effect(spec.name), spec.effect, spec.name)
            self.assertEqual(tool_effect(spec.name), spec.effect, spec.name)

    def test_tool_effect_agrees_with_kali_tool_effect_for_kali(self):
        for name in KaliClient.ALLOWED_TOOLS:
            self.assertEqual(tool_effect(name), kali_tool_effect(name), name)

    def test_unknown_tool_fails_safe_to_active(self):
        self.assertEqual(catalog_tool_effect("totally-unknown"), "active")
        self.assertEqual(catalog_tool_effect(""), "active")
        self.assertEqual(tool_effect("totally-unknown"), "active")


class TestSourceBreakdown(unittest.TestCase):
    def test_counts_per_source(self):
        counts: dict[str, int] = {}
        for spec in TOOL_CATALOG:
            counts[spec.source] = counts.get(spec.source, 0) + 1
        self.assertEqual(counts["kali"], 10)
        # >= 14 built-ins; the live registry may grow with fixture adapters
        # but the catalog snapshot covers at least the built-in scanners.
        self.assertGreaterEqual(counts["scanner"], 14)
        self.assertGreaterEqual(counts["cai"], 1)
        self.assertEqual(counts["osint"], 1)


class TestExtendedToolbelt(unittest.TestCase):
    def test_degrades_safely_when_cai_unavailable(self):
        # CAI is not importable in the offline test env → the extended toolbelt
        # must return a safe, empty-ish result rather than raising.
        from aegis.tools.cai_tools import build_extended_toolbelt

        belt = build_extended_toolbelt()
        self.assertIsInstance(belt.tools, list)
        self.assertIsInstance(belt.names, list)
        self.assertEqual(len(belt.tools), len(belt.names))


if __name__ == "__main__":
    unittest.main()
