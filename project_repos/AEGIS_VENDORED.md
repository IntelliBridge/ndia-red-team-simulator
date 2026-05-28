# Vendored upstream sources

This directory holds source-of-truth clones of the open-source projects
Aegis depends on. Each entry is pinned to a specific SHA so the build,
the design-system component generation, and the security review can
all be reproduced from the repo alone — no upstream availability
required.

| Submodule                         | Upstream                                              | Pinned SHA                                  | Vendored | Used for                                            |
|-----------------------------------|-------------------------------------------------------|---------------------------------------------|----------|-----------------------------------------------------|
| `cai`                             | https://github.com/aliasrobotics/cai                  | (tracked via `.gitmodules` HEAD)            | Phase 1  | CAI agents (codeagent, blueteam_agent) — F10 loader |
| `mcp-kali-server`                 | https://gitlab.com/kalilinux/packages/mcp-kali-server | (tracked via `.gitmodules` HEAD)            | Phase 2  | MCP Kali server backend (kali_client.py)            |
| `vulnerability-fixer`             | https://github.com/OpenHands/vulnerability-fixer      | (tracked via `.gitmodules` HEAD)            | Phase 2  | Vulnfixer export adapter                            |
| `strix`                           | https://github.com/usestrix/strix                     | (tracked via `.gitmodules` HEAD)            | Phase 2  | Strix DAST scanner                                  |
| `shadcn-ui`                       | https://github.com/shadcn-ui/ui                       | `360e8a19c3ee13ac78b656027462007c8bdaa6d5`  | Phase 4 v0.4.0 F15 | `@aegis/design-system` primitives generated via `pnpm dlx shadcn add` |
| `opentelemetry-collector-contrib` | https://github.com/open-telemetry/opentelemetry-collector-contrib | `d7957a20ce54ab42a87b8f9e91eda73f7b3b48e5` | Phase 4 v0.4.1 F19 | Source-of-truth for the OTel Collector image we run under the `obs` compose profile; SLSA / fork target |

## License notes

- `cai` — MIT (see `cai/LICENSE`)
- `mcp-kali-server` — MIT
- `vulnerability-fixer` — Apache-2.0
- `strix` — Apache-2.0
- `shadcn-ui` — MIT (see `shadcn-ui/LICENSE.md`)
- `opentelemetry-collector-contrib` — Apache-2.0 (see
  `opentelemetry-collector-contrib/LICENSE`)

All upstream licenses are preserved in their cloned form.

## Rebase policy

Rebasing any of these submodules to a newer SHA is an explicit operation
that lands as its own commit, with an ADR entry in `docs/adr/` summarising
what changed and why. Routine rebuilds should never bump the submodule
pointers as a side effect.
