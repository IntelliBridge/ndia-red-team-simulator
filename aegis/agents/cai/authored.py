"""Aegis-native authored specialist agents.

Where :mod:`aegis.agents.cai.builtins` *wraps* agents CAI already ships, this
module *composes* brand-new specialists out of the vendored CAI tool catalog —
each a substantive system prompt plus a real toolbelt drawn from
``cai.tools.*`` (and the Camoufox OSINT search tool vendored at
:mod:`aegis.tools.osint_search`). They are genuine domain experts, not stubs.

Design mirrors ``builtins._invoke_cai``:

* **Registration is import-safe.** Specs are plain data; every adapter is
  registered ``wired=True`` at import without importing CAI. CAI only matters
  at *invocation*.
* **Invocation degrades, never raises.** ``invoke`` loads CAI through the
  central loader; a ``None`` bundle (submodule missing / offline) surfaces
  ``status="error"``. Otherwise it lazily builds — and caches — the CAI
  ``Agent`` from the spec, resolving each tool import defensively (a tool whose
  import fails is skipped, not fatal), then runs ``Runner.run_sync``. Any
  exception (e.g. ``AsyncOpenAI()`` with no key offline) becomes
  ``status="error"``.
* **OSINT search** is wired via :func:`aegis.tools.osint_search.build_osint_search_tool`,
  which returns a CAI ``@function_tool`` or ``None`` (offline) — ``None`` is
  filtered out of the toolbelt.

The effect column (read/active/external) drives the unified human gate in
:mod:`aegis.effects`; ``active``/``external`` specialists only run their
irreversible step post-approval (``context.execute``), enforced upstream in
``registry.dispatch``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from aegis.agents.registry import (
    AgentContext,
    AgentResult,
    Domain,
    FunctionAgentAdapter,
    register,
)
from aegis.config import load_config
from aegis.effects import Effect
from aegis.integrations.cai_loader import load_cai
from aegis.llm.guardrails import GuardrailViolation, guard_input, guard_output
from aegis.tools.osint_search import build_osint_search_tool


@dataclass
class AuthoredSpec:
    """A declarative recipe for one authored specialist agent.

    ``tool_imports`` is a list of ``(module_path, attribute)`` pairs resolved
    lazily at first invocation. ``use_osint`` appends the Camoufox OSINT search
    tool (built via :func:`build_osint_search_tool`) to the toolbelt.
    """

    name: str
    cai_name: str
    domain: Domain
    effect: Effect
    instructions: str
    tool_imports: list[tuple[str, str]] = field(default_factory=list)
    use_osint: bool = False
    # Cache of the built CAI Agent (built once, reused per process).
    _agent: Any = field(default=None, repr=False, compare=False)


# --- Reusable rules-of-engagement preamble -------------------------------
# Every authored specialist inherits the platform's scope discipline; the
# spec-specific instructions append the domain rules.
_ROE = (
    "You operate only within the authorized engagement scope provided in your "
    "context (target, finding_id, repo_path). Never act outside that scope. "
    "Cite concrete evidence for every finding and rate severity soberly. "
)


def _resolve_tools(spec: AuthoredSpec) -> list[Any]:
    """Resolve a spec's toolbelt, skipping any tool that fails to import.

    A specialist with one unavailable tool is still useful with the rest, so a
    failed import is logged-by-omission rather than fatal. The OSINT search tool
    is appended only when ``build_osint_search_tool`` returns non-None.
    """
    tools: list[Any] = []
    for module_path, attr in spec.tool_imports:
        try:
            module = __import__(module_path, fromlist=[attr])
            tool = getattr(module, attr)
        except Exception:  # noqa: BLE001 - a missing tool degrades gracefully
            continue
        tools.append(tool)
    if spec.use_osint:
        osint_tool = build_osint_search_tool()
        if osint_tool is not None:
            tools.append(osint_tool)
    return tools


def _build_agent(spec: AuthoredSpec, bundle: Any) -> Any:
    """Build (and cache) the CAI ``Agent`` for ``spec``.

    Mirrors ``cai_loader.recon_agent``: a guarded composition that constructs an
    ``OpenAIChatCompletionsModel`` over ``AsyncOpenAI()``. Offline this raises
    (no API key) and the caller turns it into ``status="error"`` — it never
    propagates out of ``invoke``.
    """
    if spec._agent is not None:
        return spec._agent
    from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
    from openai import AsyncOpenAI

    spec._agent = Agent(
        name=spec.cai_name,
        instructions=spec.instructions,
        tools=_resolve_tools(spec),
        model=OpenAIChatCompletionsModel(
            model=os.getenv("CAI_MODEL", "alias1"),
            openai_client=AsyncOpenAI(),
        ),
    )
    return spec._agent


def _invoke(spec: AuthoredSpec, prompt: str, context: AgentContext) -> AgentResult:
    """Run an authored specialist through ``Runner.run_sync``.

    ``None`` bundle (CAI not importable) → ``status="error"``. Otherwise build
    the Agent lazily and run it; any failure (model construction offline, tool
    execution, runner) is wrapped as ``status="error"`` so a single agent can
    never crash the dispatcher.
    """
    config = load_config()
    try:
        guard_input(prompt, config=config)
    except GuardrailViolation as exc:
        return AgentResult(status="error", output="", error=str(exc))
    bundle = load_cai(config)
    if bundle is None:
        return AgentResult(
            status="error",
            output="",
            error="CAI library not importable (submodule missing or env not set up)",
        )
    try:
        agent = _build_agent(spec, bundle)
        cai_context = {
            "finding_id": context.finding_id,
            "target": context.target,
            "repo_path": context.repo_path,
            **context.extra,
        }
        result = bundle.Runner.run_sync(
            starting_agent=agent, input=prompt, context=cai_context,
        )
        output = getattr(result, "final_output", None) or str(result)
        return AgentResult(
            status="ok", output=guard_output(str(output), config=config),
            agent_version=bundle.cai_version,
        )
    except Exception as exc:  # noqa: BLE001 - any failure degrades to error
        return AgentResult(
            status="error", output="", error=f"{type(exc).__name__}: {exc}",
        )


# --- CAI tool module paths (resolved lazily; verified against the vendored
# catalog under project_repos/cai/src/cai/tools/). ---------------------------
_RECON = "cai.tools.reconnaissance"
_WEB = "cai.tools.web"
_MISC = "cai.tools.misc"


# --- The authored specialists -----------------------------------------------
# Each is a real composition: a scoped system prompt + a fitting toolbelt.
_SPECS: list[AuthoredSpec] = [
    AuthoredSpec(
        name="cloud_recon",
        cai_name="CloudRecon",
        domain="recon",
        effect="external",
        instructions=(
            _ROE
            + "You are a cloud-attack-surface reconnaissance specialist. Map a "
            "target organization's externally-reachable cloud footprint: "
            "public buckets, exposed management ports, misattributed DNS, and "
            "internet-facing services. Use Shodan to fingerprint hosts and open "
            "services, curl to fetch banners and metadata endpoints (read-only "
            "GETs), and web search to correlate ASNs, cloud provider ranges, and "
            "leaked infrastructure references. You enumerate and observe only — "
            "you never authenticate, mutate, or exploit. Report each exposure "
            "with the provider, service, and why it is reachable."
        ),
        tool_imports=[
            (_RECON, "shodan_search"),
            (_RECON, "shodan_host_info"),
            (_RECON, "curl"),
        ],
        use_osint=True,
    ),
    AuthoredSpec(
        name="osint_collector",
        cai_name="OSINTCollector",
        domain="recon",
        effect="external",
        instructions=(
            _ROE
            + "You are an open-source intelligence collector. Build a factual "
            "profile of a target organization or person from public sources: "
            "employees, technologies, breach mentions, code leaks, and exposed "
            "assets. Use web search to gather and corroborate claims across "
            "independent sources, and Shodan to tie public assets to the target. "
            "Distinguish confirmed facts from inferences, never fabricate, and "
            "record the source URL for every datum so findings are auditable."
        ),
        tool_imports=[
            (_RECON, "shodan_search"),
            (_RECON, "shodan_host_info"),
        ],
        use_osint=True,
    ),
    AuthoredSpec(
        name="threat_intel",
        cai_name="ThreatIntel",
        domain="recon",
        effect="external",
        instructions=(
            _ROE
            + "You are a threat-intelligence analyst. Given an indicator (CVE, "
            "IP, domain, malware family, or threat actor), research current "
            "public reporting to assess relevance to the target: known "
            "exploitation in the wild, affected versions, IOCs, and recommended "
            "mitigations. Use web search for vendor advisories and security "
            "research, and Shodan to gauge real-world exposure of the affected "
            "service. Summarize with a confidence level and link every claim to "
            "its source; flag stale or unverifiable intelligence."
        ),
        tool_imports=[
            (_RECON, "shodan_search"),
            (_RECON, "shodan_host_info"),
        ],
        use_osint=True,
    ),
    AuthoredSpec(
        name="api_security_tester",
        cai_name="APISecurityTester",
        domain="offensive",
        effect="active",
        instructions=(
            _ROE
            + "You are an API security specialist. Probe REST/GraphQL endpoints "
            "for the OWASP API Top 10: broken object-level authorization, "
            "excessive data exposure, mass assignment, broken authentication, "
            "and injection. Use curl to craft and send targeted requests "
            "(varying methods, headers, tokens, and IDs), the header framework "
            "to inspect auth and security headers, and the JS surface mapper to "
            "discover undocumented endpoints from client code. You actively send "
            "requests to the target, so you operate only post-approval; never "
            "perform destructive writes — prove a flaw with the minimal "
            "non-damaging request and stop."
        ),
        tool_imports=[
            (_RECON, "curl"),
            (_WEB, "web_request_framework"),
            (_WEB, "js_surface_mapper"),
        ],
    ),
    AuthoredSpec(
        name="web_surface_mapper",
        cai_name="WebSurfaceMapper",
        domain="offensive",
        effect="active",
        instructions=(
            _ROE
            + "You are a web attack-surface mapper. Enumerate a web "
            "application's reachable surface: routes, API calls, parameters, "
            "third-party origins, and secrets referenced in client-side "
            "JavaScript. Use the JS surface mapper to parse scripts and extract "
            "endpoints, the header framework to characterize responses and "
            "security posture, and curl to confirm reachability. Produce a "
            "structured map other offensive agents can act on. You actively "
            "fetch from the target (post-approval) but only observe — no "
            "exploitation."
        ),
        tool_imports=[
            (_WEB, "js_surface_mapper"),
            (_WEB, "web_request_framework"),
            (_RECON, "curl"),
        ],
    ),
    AuthoredSpec(
        name="ssl_tls_auditor",
        cai_name="SSLTLSAuditor",
        domain="offensive",
        effect="active",
        instructions=(
            _ROE
            + "You are a TLS/SSL configuration auditor. Assess a target's "
            "transport security: protocol versions, cipher suites, certificate "
            "chain validity and expiry, HSTS, and known issues (weak DH, "
            "expired/self-signed certs, mixed content). Use curl with verbose "
            "TLS options to negotiate and inspect handshakes and certificates, "
            "and the header framework to verify HSTS and related headers. You "
            "connect to the live service (post-approval) but make no changes; "
            "report each weakness with the affected endpoint and a remediation."
        ),
        tool_imports=[
            (_RECON, "curl"),
            (_WEB, "web_request_framework"),
            (_RECON, "netcat"),
        ],
    ),
    AuthoredSpec(
        name="dns_enumerator",
        cai_name="DNSEnumerator",
        domain="recon",
        effect="external",
        instructions=(
            _ROE
            + "You are a DNS reconnaissance specialist. Enumerate a target "
            "domain's DNS surface: subdomains, record types (A/AAAA/MX/TXT/NS/"
            "CNAME), zone-transfer exposure, and dangling records vulnerable to "
            "takeover. Use netcat to probe DNS/zone-transfer endpoints, curl for "
            "DoH/public resolver queries and certificate-transparency lookups, "
            "and web search to discover historical subdomains and passive DNS. "
            "You query third-party infrastructure (external egress) and only "
            "read — never modify zones. Flag misconfigurations and likely "
            "takeover candidates."
        ),
        tool_imports=[
            (_RECON, "netcat"),
            (_RECON, "curl"),
        ],
        use_osint=True,
    ),
    AuthoredSpec(
        name="secrets_hunter",
        cai_name="SecretsHunter",
        domain="forensic",
        effect="read",
        instructions=(
            _ROE
            + "You are a secrets-discovery analyst working read-only over a "
            "codebase or filesystem snapshot. Hunt for hard-coded credentials, "
            "API keys, private keys, tokens, and connection strings in source, "
            "config, history, and dotfiles. Use the filesystem tools to list, "
            "search, and read files. You never write, delete, or transmit any "
            "secret you find — and you carry no network/egress tool, so you "
            "cannot — you locate, classify by sensitivity, and report file path "
            "plus line so it can be rotated."
        ),
        tool_imports=[
            (_RECON, "list_dir"),
            (_RECON, "cat_file"),
            (_RECON, "find_file"),
        ],
    ),
    AuthoredSpec(
        name="iac_auditor",
        cai_name="IaCAuditor",
        domain="defensive",
        effect="read",
        instructions=(
            _ROE
            + "You are an infrastructure-as-code security auditor. Statically "
            "review Terraform, CloudFormation, Kubernetes manifests, and Docker "
            "definitions for misconfigurations: public exposure, missing "
            "encryption, over-broad IAM, disabled logging, and insecure "
            "defaults. Use the filesystem tools to read manifests and the code "
            "interpreter to parse and evaluate structured config (HCL/YAML/JSON) "
            "and compute findings. You only read and analyze — you never apply "
            "or mutate infrastructure. Map each finding to the resource and a "
            "concrete fix."
        ),
        tool_imports=[
            (_RECON, "list_dir"),
            (_RECON, "cat_file"),
            (_RECON, "find_file"),
            (_MISC, "execute_python_code"),
        ],
    ),
    AuthoredSpec(
        name="container_security",
        cai_name="ContainerSecurity",
        domain="defensive",
        effect="active",
        instructions=(
            _ROE
            + "You are a container and host hardening specialist. Inspect "
            "running containers and images for security issues: privileged "
            "mode, host mounts, exposed sockets, root processes, outdated "
            "packages, and capability over-grants. Use the Linux command tool to "
            "query the runtime (docker/podman/kubectl, package state, kernel "
            "params). Because these commands execute against a live host, you "
            "run only post-approval; prefer read-only inspection commands and "
            "never start, stop, or reconfigure workloads. Report each finding "
            "against the CIS container benchmark with a remediation."
        ),
        tool_imports=[
            (_RECON, "generic_linux_command"),
        ],
    ),
    AuthoredSpec(
        name="crypto_analyst",
        cai_name="CryptoAnalyst",
        domain="forensic",
        effect="read",
        instructions=(
            _ROE
            + "You are a cryptography and encoding analyst. Given artifacts "
            "(blobs, captured tokens, suspicious files), identify encodings and "
            "weak cryptography: base64/hex layers, embedded strings, hard-coded "
            "keys, and weak or homegrown schemes. Use the crypto tools to "
            "extract strings, decode base64 and hex, and peel layered encodings. "
            "You analyze supplied artifacts read-only — you never attack a live "
            "system. Explain each decoding step so the result is reproducible "
            "and assess the cryptographic strength of what you find."
        ),
        tool_imports=[
            (_RECON, "strings_command"),
            (_RECON, "decode64"),
            (_RECON, "decode_hex_bytes"),
        ],
    ),
    AuthoredSpec(
        name="log_triage",
        cai_name="LogTriage",
        domain="forensic",
        effect="read",
        instructions=(
            _ROE
            + "You are a log-triage and incident-analysis specialist working "
            "read-only over collected log files. Reconstruct a timeline and "
            "surface indicators of compromise: authentication anomalies, "
            "privilege escalation, lateral movement, data exfiltration, and "
            "error spikes. Use the filesystem tools to list, search, and read "
            "log files (auth, web, syslog, application). You never modify logs "
            "or touch the live system. Correlate events into a chronological "
            "narrative with timestamps and cite the exact log line for every "
            "conclusion."
        ),
        tool_imports=[
            (_RECON, "list_dir"),
            (_RECON, "cat_file"),
            (_RECON, "find_file"),
        ],
    ),
]


def _make_adapter(spec: AuthoredSpec) -> FunctionAgentAdapter:
    def invoke(prompt: str, context: AgentContext) -> AgentResult:
        return _invoke(spec, prompt, context)

    return FunctionAgentAdapter(
        name=spec.name,
        domain=spec.domain,
        effect=spec.effect,
        wired=True,
        fn=invoke,
    )


# Registration happens at import and does NOT require CAI importable — only
# invocation does. This mirrors builtins' import-time registration loop.
for _spec in _SPECS:
    register(_make_adapter(_spec))
