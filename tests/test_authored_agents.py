"""Authored Aegis-native specialist agents.

These agents are *compositions* — a system prompt plus a real toolbelt drawn
from the vendored CAI tool catalog — so the tests verify the composition
contract without a live CAI runtime: CAI is mocked (the bundle and the Agent
class are fabricated, the tool imports are patched), so no Postgres/Redis and no
real model are needed. The offline path (``load_cai`` -> None) is asserted to
degrade to ``status="error"`` rather than crash.
"""

from __future__ import annotations

import sys
import types
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch as mpatch

from aegis.agents.cai import authored
from aegis.agents.registry import AgentContext, dispatch, list_agents

# slot name -> (domain, effect). The 12 authored specialists.
_AUTHORED = {
    "cloud_recon": ("recon", "external"),
    "osint_collector": ("recon", "external"),
    "threat_intel": ("recon", "external"),
    "api_security_tester": ("offensive", "active"),
    "web_surface_mapper": ("offensive", "active"),
    "ssl_tls_auditor": ("offensive", "active"),
    "dns_enumerator": ("recon", "external"),
    "secrets_hunter": ("forensic", "read"),
    "iac_auditor": ("defensive", "read"),
    "container_security": ("defensive", "active"),
    "crypto_analyst": ("forensic", "read"),
    "log_triage": ("forensic", "read"),
}

# Specialists whose effect is read -> invoke without execute=True.
_READ_AGENTS = [n for n, (_d, e) in _AUTHORED.items() if e == "read"]
# Specialists whose effect is gated (active/external) -> need execute=True.
_GATED_AGENTS = [n for n, (_d, e) in _AUTHORED.items() if e != "read"]
# OSINT agents that must wire the Camoufox search tool into their toolbelt.
_OSINT_AGENTS = [s.name for s in authored._SPECS if s.use_osint]


def _mock_bundle(**overrides):
    bundle = MagicMock()
    bundle.cai_version = "deadbeef"
    bundle.Runner.run_sync.return_value = MagicMock(final_output="ok")
    for k, v in overrides.items():
        setattr(bundle, k, v)
    return bundle


def _fake_cai_sdk_module():
    """A stand-in ``cai.sdk.agents`` module so ``_build_agent`` imports work.

    ``Agent`` records its kwargs (so we can assert the toolbelt) and
    ``OpenAIChatCompletionsModel`` is inert; ``openai.AsyncOpenAI`` is stubbed
    too so no real client is constructed.
    """
    captured = {}

    class _Agent:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)
            captured["kwargs"] = kwargs

    sdk = types.ModuleType("cai.sdk.agents")
    sdk.Agent = _Agent
    sdk.OpenAIChatCompletionsModel = lambda **kw: object()
    return sdk, captured


class _PatchCAIImports:
    """Context manager: inject fake ``cai.sdk.agents`` + ``openai`` modules.

    Lets ``authored._build_agent`` run offline without the real CAI/openai
    stack. Tool imports (``cai.tools.*``) are resolved defensively by the code
    under test, so when absent they're simply skipped — the OSINT tool is the
    only toolbelt member asserted, via a patched ``build_osint_search_tool``.
    """

    def __init__(self):
        self.captured = {}
        self._saved = {}

    def __enter__(self):
        sdk, self.captured = _fake_cai_sdk_module()
        fake_openai = types.ModuleType("openai")
        fake_openai.AsyncOpenAI = lambda *a, **k: object()
        for name, mod in (
            ("cai", types.ModuleType("cai")),
            ("cai.sdk", types.ModuleType("cai.sdk")),
            ("cai.sdk.agents", sdk),
            ("openai", fake_openai),
        ):
            self._saved[name] = sys.modules.get(name)
            sys.modules[name] = mod
        return self

    def __exit__(self, *exc):
        for name, prev in self._saved.items():
            if prev is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prev


def _reset_agent_cache():
    """Clear any cached built Agent so each test composes fresh."""
    for spec in authored._SPECS:
        spec._agent = None


class TestAuthoredAgents(unittest.TestCase):
    def setUp(self):
        _reset_agent_cache()

    def tearDown(self):
        _reset_agent_cache()

    def test_twelve_specs_defined(self):
        self.assertEqual(len(authored._SPECS), 12)
        self.assertEqual({s.name for s in authored._SPECS}, set(_AUTHORED))

    def test_all_authored_registered_wired_with_expected_domain_effect(self):
        by_name = {a["name"]: a for a in list_agents()}
        for name, (domain, effect) in _AUTHORED.items():
            self.assertIn(name, by_name, f"{name!r} not registered")
            self.assertTrue(by_name[name]["wired"], f"{name!r} should be wired")
            self.assertEqual(by_name[name]["domain"], domain, name)
            self.assertEqual(by_name[name]["effect"], effect, name)

    def test_specs_have_substantive_instructions(self):
        for spec in authored._SPECS:
            self.assertGreater(len(spec.instructions), 200, spec.name)
            # A real toolbelt: a tool import list, or the OSINT tool, or both.
            self.assertTrue(
                spec.tool_imports or spec.use_osint,
                f"{spec.name!r} has no toolbelt",
            )

    def test_read_agents_dispatch_ok_without_execute(self):
        bundle = _mock_bundle()
        with _PatchCAIImports(), \
             mpatch.object(authored, "load_cai", return_value=bundle), \
             mpatch.object(authored, "load_config", return_value=MagicMock()), \
             mpatch.object(authored, "build_osint_search_tool", return_value=None):
            for name in _READ_AGENTS:
                res = dispatch(name, "x", AgentContext())
                self.assertEqual(res.status, "ok", f"{name}: {res.error}")
                self.assertEqual(res.output, "ok")

    def test_gated_agents_dispatch_ok_with_execute(self):
        bundle = _mock_bundle()
        with _PatchCAIImports(), \
             mpatch.object(authored, "load_cai", return_value=bundle), \
             mpatch.object(authored, "load_config", return_value=MagicMock()), \
             mpatch.object(authored, "build_osint_search_tool", return_value=None):
            for name in _GATED_AGENTS:
                res = dispatch(name, "x", AgentContext(execute=True))
                self.assertEqual(res.status, "ok", f"{name}: {res.error}")
                self.assertEqual(res.output, "ok")

    def test_offline_bundle_none_returns_error_never_crashes(self):
        with mpatch.object(authored, "load_cai", return_value=None), \
             mpatch.object(authored, "load_config", return_value=MagicMock()):
            for name in _AUTHORED:
                res = dispatch(name, "x", AgentContext(execute=True))
                self.assertEqual(res.status, "error", name)
                self.assertIn("not importable", res.error)

    def test_runner_exception_degrades_to_error(self):
        bundle = _mock_bundle()
        bundle.Runner.run_sync.side_effect = RuntimeError("boom")
        with _PatchCAIImports(), \
             mpatch.object(authored, "load_cai", return_value=bundle), \
             mpatch.object(authored, "load_config", return_value=MagicMock()), \
             mpatch.object(authored, "build_osint_search_tool", return_value=None):
            res = dispatch("secrets_hunter", "x", AgentContext())
        self.assertEqual(res.status, "error")
        self.assertIn("RuntimeError: boom", res.error)

    def test_active_authored_agent_requires_approval(self):
        """An active authored agent without execute=True is gated, never runs."""
        bundle = _mock_bundle()
        with mpatch.object(authored, "load_cai", return_value=bundle), \
             mpatch.object(authored, "load_config", return_value=MagicMock()):
            res = dispatch("api_security_tester", "probe", AgentContext())
        self.assertEqual(res.status, "pending_approval")
        self.assertIsNotNone(res.plan)
        self.assertTrue(res.plan["gated"])
        self.assertEqual(res.plan["required_role"], "approver")
        bundle.Runner.run_sync.assert_not_called()

    def test_external_authored_agent_requires_approval(self):
        """An external authored agent (3rd-party egress) is gated too."""
        bundle = _mock_bundle()
        with mpatch.object(authored, "load_cai", return_value=bundle), \
             mpatch.object(authored, "load_config", return_value=MagicMock()):
            res = dispatch("cloud_recon", "map", AgentContext())
        self.assertEqual(res.status, "pending_approval")
        self.assertTrue(res.plan["gated"])
        bundle.Runner.run_sync.assert_not_called()

    def test_osint_agents_include_camoufox_search_tool(self):
        """OSINT agents consult build_osint_search_tool and include its result.

        Patch the builder to return a sentinel and assert it lands in the built
        Agent's toolbelt — proving the Camoufox search tool replaces a Google
        search tool in these compositions.
        """
        sentinel = object()
        self.assertTrue(_OSINT_AGENTS, "expected at least one OSINT agent")
        for name in _OSINT_AGENTS:
            _reset_agent_cache()
            patcher = _PatchCAIImports()
            bundle = _mock_bundle()
            with patcher, \
                 mpatch.object(authored, "load_cai", return_value=bundle), \
                 mpatch.object(authored, "load_config", return_value=MagicMock()), \
                 mpatch.object(
                     authored, "build_osint_search_tool", return_value=sentinel,
                 ) as m_build:
                res = dispatch(name, "x", AgentContext(execute=True))
                self.assertEqual(res.status, "ok", f"{name}: {res.error}")
                m_build.assert_called_once()
                self.assertIn(
                    sentinel, patcher.captured["kwargs"]["tools"],
                    f"{name!r} should wire the camoufox search tool",
                )

    def test_osint_tool_skipped_when_unavailable(self):
        """When build_osint_search_tool returns None, it is filtered out."""
        sample = next(s for s in authored._SPECS if s.use_osint)
        patcher = _PatchCAIImports()
        bundle = _mock_bundle()
        with patcher, \
             mpatch.object(authored, "load_cai", return_value=bundle), \
             mpatch.object(authored, "load_config", return_value=MagicMock()), \
             mpatch.object(authored, "build_osint_search_tool", return_value=None):
            res = dispatch(sample.name, "x", AgentContext(execute=True))
        self.assertEqual(res.status, "ok", res.error)
        self.assertNotIn(None, patcher.captured["kwargs"]["tools"])

    def test_resolve_tools_imports_real_tools_and_skips_failures(self):
        """A resolvable (module, attr) is imported; an unresolvable one is skipped.

        Exercises both branches of ``_resolve_tools`` directly: the success path
        (import + getattr + append) and the defensive skip on a failed import.
        """
        good = types.ModuleType("cai.tools.fake_mod")
        sentinel = object()
        good.good_tool = sentinel
        with mpatch.dict(sys.modules, {
            "cai": types.ModuleType("cai"),
            "cai.tools": types.ModuleType("cai.tools"),
            "cai.tools.fake_mod": good,
        }):
            spec = authored.AuthoredSpec(
                name="t", cai_name="T", domain="recon", effect="read",
                instructions="x",
                tool_imports=[
                    ("cai.tools.fake_mod", "good_tool"),     # resolves -> appended
                    ("cai.tools.fake_mod", "missing_attr"),  # AttributeError -> skip
                    ("cai.tools.no_such_module", "x"),       # ImportError -> skip
                ],
            )
            tools = authored._resolve_tools(spec)
        self.assertEqual(tools, [sentinel])

    def test_agent_is_cached_across_invocations(self):
        """The CAI Agent is built once and reused (per-spec cache)."""
        bundle = _mock_bundle()
        with _PatchCAIImports(), \
             mpatch.object(authored, "load_cai", return_value=bundle), \
             mpatch.object(authored, "load_config", return_value=MagicMock()), \
             mpatch.object(authored, "build_osint_search_tool", return_value=None):
            dispatch("log_triage", "x", AgentContext())
            spec = next(s for s in authored._SPECS if s.name == "log_triage")
            first = spec._agent
            self.assertIsNotNone(first)
            dispatch("log_triage", "y", AgentContext())
            self.assertIs(spec._agent, first)


class TestReadAgentsHaveNoEgress(unittest.TestCase):
    """A read-effect specialist runs without the human-in-the-loop gate, so it
    must not carry any network/egress tool — otherwise a prompt-injected run
    could transmit what it reads (e.g. secrets_hunter must not ship curl)."""

    _EGRESS_TOOLS = {"curl", "wget", "netcat", "nc", "http_request"}

    def test_no_read_agent_ships_an_egress_tool(self):
        for spec in authored._SPECS:
            if spec.effect != "read":
                continue
            tool_names = {name for _mod, name in spec.tool_imports}
            leaked = tool_names & self._EGRESS_TOOLS
            self.assertEqual(
                leaked, set(),
                f"read-effect agent {spec.name!r} ships egress tool(s) {leaked}",
            )
            self.assertFalse(
                spec.use_osint,
                f"read-effect agent {spec.name!r} must not carry external OSINT search",
            )


if __name__ == "__main__":
    unittest.main()
