# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x (Phase 2)  | yes — security fixes only |
| 0.3.x (Phase 3, planned) | yes |
| < 0.2  | no |

## Reporting a vulnerability

Email **security@agiledefense.com** (or open a private security advisory on GitHub if the repo is hosted there). Do **not** open a public issue.

Include:

1. Affected version / commit.
2. Reproduction steps or PoC.
3. Impact assessment.
4. Suggested remediation if you have one.

We will acknowledge within 3 business days and aim for triage within 10 business days. Coordinated disclosure preferred; we will credit reporters who request it.

## Out of scope

- Findings produced *by* Aegis against deliberately-vulnerable targets (Juice Shop, DVWA). Those are by design.
- The fixture-assisted demo mode's lack of a live LLM / scanner — documented and intentional.
- Submodule vulnerabilities. Report those to the respective upstream projects (strix, cai, mcp-kali-server, vulnerability-fixer).

## Hardening posture

- Active operations route through `aegis.safety.authorize` with CIDR allowlist enforcement.
- Patch workflow is branch-first with automatic rollback (`aegis/remediate/patch_workflow.py`).
- Audit log is hash-chained from Phase 3 (`aegis/audit/chain.py`); `aegis audit verify` confirms integrity.
- No write API endpoint bypasses OIDC auth + RBAC + audit + safety allowlist (Phase 3, `aegis/api/`).
