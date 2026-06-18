"""CAI MCP-client attach + multi-agent pattern adapters (all offline).

CAI is not importable offline (no ``openai``), so every path here either
patches the loader's ``load_cai`` to a fabricated bundle or injects fake
``cai.*`` modules via ``sys.modules``. Nothing requires a live MCP server or a
real CAI runtime.

Two properties matter most and are asserted explicitly:

* **No auto-swarm.** A normal single-agent dispatch never touches the pattern
  module — patterns run only when a caller dispatches one *by name*.
* **The human gate covers patterns too.** Every pattern is ``active``; without
  ``execute=True`` ``dispatch`` returns a proposal and no agent runs.
"""

from __future__ import annotations

import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import ANY, MagicMock
from unittest.mock import patch as mpatch

from aegis.agents.cai import builtins
from aegis.agents.cai import patterns as patterns_mod
from aegis.agents.registry import AgentContext, dispatch
from aegis.integrations import cai_loader
from aegis.integrations.cai_loader import CAIBundle


def _mock_bundle(**overrides):
    """A CAIBundle stand-in whose Runner returns a fixed final_output."""
    attrs = {a: MagicMock() for a in CAIBundle.__dataclass_fields__}
    attrs["cai_version"] = "deadbeef"
    attrs["Runner"] = MagicMock()
    attrs["Runner"].run_sync.return_value = MagicMock(final_output="ok")
    attrs.update(overrides)
    return MagicMock(**attrs)


class TestAttachKaliMcp(unittest.TestCase):
    """``_attach_kali_mcp`` wires the live belt onto active specialists only."""

    URL = "http://kali:8000/sse"

    def test_recon_is_excluded_from_the_kali_belt(self):
        # The belt holds active tools; recon must stay read-only, so it must
        # never be in the attach set.
        self.assertNotIn("recon_agent", cai_loader._KALI_MCP_AGENTS)
        self.assertEqual(
            set(cai_loader._KALI_MCP_AGENTS),
            {"bug_bounter_agent", "redteam_agent", "web_pentester_agent"},
        )

    def test_no_url_attaches_nothing(self):
        agents = {a: SimpleNamespace() for a in cai_loader._KALI_MCP_AGENTS}
        self.assertEqual(cai_loader._attach_kali_mcp(agents, SimpleNamespace()), 0)
        for agent in agents.values():
            self.assertFalse(hasattr(agent, "mcp_servers"))

    def test_unimportable_mcp_client_degrades_to_zero(self):
        agents = {a: SimpleNamespace() for a in cai_loader._KALI_MCP_AGENTS}
        # None in sys.modules makes ``from cai.sdk.agents.mcp import ...`` raise.
        with mpatch.dict(sys.modules, {"cai.sdk.agents.mcp": None}):
            n = cai_loader._attach_kali_mcp(
                agents, SimpleNamespace(mcp_kali_url=self.URL))
        self.assertEqual(n, 0)

    def test_server_construction_failure_degrades_to_zero(self):
        agents = {a: SimpleNamespace() for a in cai_loader._KALI_MCP_AGENTS}
        fake_mod = types.ModuleType("cai.sdk.agents.mcp")
        fake_mod.MCPServerSse = MagicMock(side_effect=RuntimeError("boom"))
        with mpatch.dict(sys.modules, {"cai.sdk.agents.mcp": fake_mod}):
            n = cai_loader._attach_kali_mcp(
                agents, SimpleNamespace(mcp_kali_url=self.URL))
        self.assertEqual(n, 0)

    def test_attaches_one_sse_server_to_each_active_specialist(self):
        server = object()
        fake_mod = types.ModuleType("cai.sdk.agents.mcp")
        fake_mod.MCPServerSse = MagicMock(return_value=server)
        agents = {a: SimpleNamespace() for a in cai_loader._KALI_MCP_AGENTS}
        with mpatch.dict(sys.modules, {"cai.sdk.agents.mcp": fake_mod}):
            n = cai_loader._attach_kali_mcp(
                agents, SimpleNamespace(mcp_kali_url=self.URL))
        self.assertEqual(n, 3)
        for agent in agents.values():
            self.assertEqual(agent.mcp_servers, [server])
        fake_mod.MCPServerSse.assert_called_once_with(
            params={"url": self.URL}, cache_tools_list=True, name="kali-mcp")

    def test_absent_or_none_agents_are_skipped(self):
        server = object()
        fake_mod = types.ModuleType("cai.sdk.agents.mcp")
        fake_mod.MCPServerSse = MagicMock(return_value=server)
        # redteam_agent is None and web_pentester_agent is absent entirely.
        agents = {"bug_bounter_agent": SimpleNamespace(), "redteam_agent": None}
        with mpatch.dict(sys.modules, {"cai.sdk.agents.mcp": fake_mod}):
            n = cai_loader._attach_kali_mcp(
                agents, SimpleNamespace(mcp_kali_url=self.URL))
        self.assertEqual(n, 1)
        self.assertEqual(agents["bug_bounter_agent"].mcp_servers, [server])

    def test_one_agent_failing_to_take_the_server_is_skipped(self):
        class _Stubborn:
            @property
            def mcp_servers(self):  # pragma: no cover - getter never read
                return None

            @mcp_servers.setter
            def mcp_servers(self, value):
                raise RuntimeError("cannot attach")

        server = object()
        fake_mod = types.ModuleType("cai.sdk.agents.mcp")
        fake_mod.MCPServerSse = MagicMock(return_value=server)
        agents = {"bug_bounter_agent": _Stubborn(),
                  "redteam_agent": SimpleNamespace(),
                  "web_pentester_agent": SimpleNamespace()}
        with mpatch.dict(sys.modules, {"cai.sdk.agents.mcp": fake_mod}):
            n = cai_loader._attach_kali_mcp(
                agents, SimpleNamespace(mcp_kali_url=self.URL))
        # The one that rejects the server is skipped; the other two attach.
        self.assertEqual(n, 2)
        self.assertEqual(agents["redteam_agent"].mcp_servers, [server])


class TestCaiResolvers(unittest.TestCase):
    """``load_cai_pattern`` / ``resolve_cai_agent`` degrade offline, resolve live."""

    def test_pattern_resolver_returns_none_offline(self):
        with mpatch.object(cai_loader, "load_cai", return_value=None):
            self.assertIsNone(
                cai_loader.load_cai_pattern(SimpleNamespace(), "offsec_pattern"))

    def test_agent_resolver_returns_none_offline(self):
        with mpatch.object(cai_loader, "load_cai", return_value=None):
            self.assertIsNone(
                cai_loader.resolve_cai_agent(SimpleNamespace(), "redteam_agent"))

    def test_pattern_resolver_calls_get_pattern_when_available(self):
        fake_mod = types.ModuleType("cai.agents.patterns")
        fake_mod.get_pattern = MagicMock(return_value="PATTERN")
        with mpatch.object(cai_loader, "load_cai", return_value=MagicMock()), \
             mpatch.dict(sys.modules, {"cai.agents.patterns": fake_mod}):
            out = cai_loader.load_cai_pattern(SimpleNamespace(), "offsec_pattern")
        self.assertEqual(out, "PATTERN")
        fake_mod.get_pattern.assert_called_once_with("offsec_pattern")

    def test_agent_resolver_calls_get_agent_by_name_when_available(self):
        fake_mod = types.ModuleType("cai.agents")
        fake_mod.get_agent_by_name = MagicMock(return_value="AGENT")
        with mpatch.object(cai_loader, "load_cai", return_value=MagicMock()), \
             mpatch.dict(sys.modules, {"cai.agents": fake_mod}):
            out = cai_loader.resolve_cai_agent(SimpleNamespace(), "redteam_agent")
        self.assertEqual(out, "AGENT")
        fake_mod.get_agent_by_name.assert_called_once_with("redteam_agent")

    def test_pattern_resolver_swallows_import_failure(self):
        with mpatch.object(cai_loader, "load_cai", return_value=MagicMock()), \
             mpatch.dict(sys.modules, {"cai.agents.patterns": None}):
            self.assertIsNone(
                cai_loader.load_cai_pattern(SimpleNamespace(), "x"))

    def test_agent_resolver_swallows_import_failure(self):
        with mpatch.object(cai_loader, "load_cai", return_value=MagicMock()), \
             mpatch.dict(sys.modules, {"cai.agents": None}):
            self.assertIsNone(
                cai_loader.resolve_cai_agent(SimpleNamespace(), "x"))


class TestPatternsRegistered(unittest.TestCase):
    # All wired patterns are active/offensive composites. The first three are
    # the originals; the two red/blue parallel patterns are the breadth added
    # this change. Asserted as a superset (not an exact count) so it stays green
    # if more patterns are wired later.
    _EXPECTED = (
        "offsec_pattern", "redteam_swarm", "bb_triage_swarm",
        "red_blue_shared_context", "red_blue_split_context",
    )

    def test_patterns_registered_as_active_offensive(self):
        from aegis.agents.registry import list_agents
        by_name = {a["name"]: a for a in list_agents()}
        for name in self._EXPECTED:
            self.assertIn(name, by_name, f"{name} not registered")
            self.assertEqual(by_name[name]["domain"], "offensive")
            self.assertEqual(by_name[name]["effect"], "active")

    def test_new_red_blue_patterns_map_to_cai_pattern_names(self):
        """The red/blue patterns resolve via their CAI dict ``name`` keys."""
        wired = {n: cai for n, _d, _e, cai in patterns_mod._PATTERNS}
        self.assertEqual(wired["red_blue_shared_context"],
                         "blue_team_red_team_shared_context")
        self.assertEqual(wired["red_blue_split_context"],
                         "blue_team_red_team_split_context")


class TestPatternGate(unittest.TestCase):
    """Every pattern is active → gated; dispatch proposes, never auto-swarms."""

    def test_pattern_without_execute_is_gated_and_never_resolves(self):
        m_load_cai = MagicMock()
        m_load_pattern = MagicMock()
        m_resolve = MagicMock()
        with mpatch.object(patterns_mod, "load_config", MagicMock()), \
             mpatch.object(patterns_mod, "load_cai", m_load_cai), \
             mpatch.object(patterns_mod, "load_cai_pattern", m_load_pattern), \
             mpatch.object(patterns_mod, "resolve_cai_agent", m_resolve):
            res = dispatch("redteam_swarm", "attack the host",
                           AgentContext(target="host"))
        self.assertEqual(res.status, "pending_approval")
        self.assertIsNotNone(res.plan)
        self.assertTrue(res.plan["gated"])
        self.assertEqual(res.plan["required_role"], "approver")
        # The gate sits upstream of invoke(): nothing in the pattern path ran.
        m_load_cai.assert_not_called()
        m_load_pattern.assert_not_called()
        m_resolve.assert_not_called()

    def test_normal_single_agent_dispatch_never_touches_patterns(self):
        """No auto-swarm: dispatching a plain agent leaves the pattern path cold."""
        m_load_pattern = MagicMock()
        m_resolve = MagicMock()
        bundle = _mock_bundle()
        with mpatch.object(patterns_mod, "load_cai_pattern", m_load_pattern), \
             mpatch.object(patterns_mod, "resolve_cai_agent", m_resolve), \
             mpatch.object(builtins, "load_cai", return_value=bundle), \
             mpatch.object(builtins, "load_config", return_value=MagicMock()):
            res = dispatch("recon", "enumerate", AgentContext())
        self.assertEqual(res.status, "ok")
        m_load_pattern.assert_not_called()
        m_resolve.assert_not_called()


class TestPatternDispatch(unittest.TestCase):
    """With execute=True the gate clears and the pattern actually runs."""

    def _patch(self, *, bundle, pattern, resolve=None):
        ctx = [
            mpatch.object(patterns_mod, "load_config", MagicMock()),
            mpatch.object(patterns_mod, "load_cai", MagicMock(return_value=bundle)),
            mpatch.object(patterns_mod, "load_cai_pattern",
                          MagicMock(return_value=pattern)),
        ]
        if resolve is not None:
            ctx.append(mpatch.object(patterns_mod, "resolve_cai_agent", resolve))
        return ctx

    @staticmethod
    def _enter(ctxs):
        for c in ctxs:
            c.start()

    @staticmethod
    def _exit(ctxs):
        for c in reversed(ctxs):
            c.stop()

    def test_swarm_runs_entry_agent_via_runner(self):
        entry_agent = object()
        pattern = SimpleNamespace(entry_agent=entry_agent)
        bundle = MagicMock()
        bundle.cai_version = "abc123"
        bundle.Runner.run_sync.return_value = MagicMock(final_output="swarm-out")
        ctxs = self._patch(bundle=bundle, pattern=pattern)
        self._enter(ctxs)
        try:
            res = dispatch("redteam_swarm", "attack the host",
                           AgentContext(target="host", execute=True))
        finally:
            self._exit(ctxs)
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.output, "swarm-out")
        self.assertEqual(res.agent_version, "abc123")
        bundle.Runner.run_sync.assert_called_once_with(
            starting_agent=entry_agent, input="attack the host", context=ANY)
        # The CAI context carries the dispatch target through unchanged.
        self.assertEqual(
            bundle.Runner.run_sync.call_args.kwargs["context"]["target"], "host")

    def test_parallel_resolves_each_config_and_concatenates(self):
        pattern = SimpleNamespace(
            entry_agent=None,
            configs=[SimpleNamespace(agent_name="recon_agent"),
                     SimpleNamespace(agent_name="web_pentester_agent")],
        )
        bundle = MagicMock()
        bundle.cai_version = "abc123"
        bundle.Runner.run_sync.side_effect = [
            MagicMock(final_output="a"), MagicMock(final_output="b")]
        resolve = MagicMock(side_effect=[object(), object()])
        ctxs = self._patch(bundle=bundle, pattern=pattern, resolve=resolve)
        self._enter(ctxs)
        try:
            res = dispatch("offsec_pattern", "sweep",
                           AgentContext(target="host", execute=True))
        finally:
            self._exit(ctxs)
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.output, "a\n\nb")
        self.assertEqual(resolve.call_count, 2)
        self.assertEqual(bundle.Runner.run_sync.call_count, 2)

    def test_parallel_skips_unresolvable_configs(self):
        pattern = SimpleNamespace(
            entry_agent=None,
            configs=[SimpleNamespace(agent_name="missing"),
                     SimpleNamespace(agent_name="web_pentester_agent")],
        )
        bundle = MagicMock()
        bundle.cai_version = "abc123"
        bundle.Runner.run_sync.return_value = MagicMock(final_output="b")
        resolve = MagicMock(side_effect=[None, object()])
        ctxs = self._patch(bundle=bundle, pattern=pattern, resolve=resolve)
        self._enter(ctxs)
        try:
            res = dispatch("offsec_pattern", "sweep",
                           AgentContext(target="host", execute=True))
        finally:
            self._exit(ctxs)
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.output, "b")
        self.assertEqual(bundle.Runner.run_sync.call_count, 1)

    def test_error_when_cai_unimportable(self):
        ctxs = [
            mpatch.object(patterns_mod, "load_config", MagicMock()),
            mpatch.object(patterns_mod, "load_cai", MagicMock(return_value=None)),
        ]
        self._enter(ctxs)
        try:
            res = dispatch("redteam_swarm", "attack",
                           AgentContext(execute=True))
        finally:
            self._exit(ctxs)
        self.assertEqual(res.status, "error")
        self.assertIn("not importable", res.error)

    def test_error_when_pattern_unavailable(self):
        bundle = MagicMock()
        ctxs = self._patch(bundle=bundle, pattern=None)
        self._enter(ctxs)
        try:
            res = dispatch("redteam_swarm", "attack",
                           AgentContext(execute=True))
        finally:
            self._exit(ctxs)
        self.assertEqual(res.status, "error")
        self.assertIn("unavailable", res.error)

    def test_error_when_no_runnable_agent_resolves(self):
        pattern = SimpleNamespace(entry_agent=None, configs=[])
        bundle = MagicMock()
        ctxs = self._patch(bundle=bundle, pattern=pattern)
        self._enter(ctxs)
        try:
            res = dispatch("offsec_pattern", "sweep",
                           AgentContext(execute=True))
        finally:
            self._exit(ctxs)
        self.assertEqual(res.status, "error")
        self.assertIn("no runnable agent", res.error)


if __name__ == "__main__":
    unittest.main()
