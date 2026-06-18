# ADR 0007 — Native MCP protocol for the Kali toolbelt

- **Status:** Proposed (spike)
- **Date:** 2026-06-18
- **Scope:** the Kali tool seam (`aegis/api/v1/tools.py`, `AEGIS_KALI_URL`,
  the vendored `mcp-kali-server` submodule)

## Context

The Kali toolbelt is consumed today over a **REST bridge**: `mcp-kali-server`
exposes the ~10 allowlisted tools (`nmap`, `sqlmap`, `hydra`, …) as HTTP
endpoints that `aegis/api/v1/tools.py` calls. The upstream is an **MCP** (Model
Context Protocol) server; the REST shim in front of it means we lose the
protocol's native affordances — typed tool discovery, structured streaming
results, and a standard transport an LLM agent can speak directly — and we
maintain a bespoke HTTP contract that drifts from the upstream's MCP surface.

## Options considered

- **Keep the REST bridge.** Zero new work; keeps the bespoke shim and its
  drift risk, and keeps tool discovery hand-maintained against the effect
  catalog (`aegis/tools/catalog.py`).
- **Protocol-native MCP client.** Aegis speaks MCP to the toolbelt directly
  (stdio or the MCP HTTP transport): native tool discovery and streaming, the
  same protocol the agent layer already reasons about, no HTTP shim to keep in
  sync.

## Decision

**Spike a protocol-native MCP client** against `mcp-kali-server`, mapping each
discovered MCP tool back onto the authoritative `read`/`active`/`external`
effect classification so the human gate (ADR-0004) and the catalog never
drift. The migration is **deferred**: it is not on the critical path, the REST
bridge works, and a protocol swap warrants its own validation pass before it
replaces a shipping integration.

## Consequences / follow-up

- Native MCP would let the effect-gate consume upstream tool metadata instead
  of a hand-maintained allowlist, and align the toolbelt transport with the
  agent layer.
- The Kali allowlist stays deliberately small either way — mcp-kali routes
  only those ~10 tools, and breadth grows through the CAI tool catalog, not the
  Kali allowlist.
- Until it ships, REST remains the shipped path; native MCP stays a tracked
  roadmap gap (`SECURITY.md` § "Known gaps").
