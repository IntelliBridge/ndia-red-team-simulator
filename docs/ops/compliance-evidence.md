# Compliance evidence pack

`redsim evidence-pack` bundles redsim's audit and controls evidence into a
self-contained directory that a **SOC 2 / ISO 27001 / FedRAMP** reviewer
can inspect offline, with no live access to the platform. It is the
machine-generated counterpart to the security model documented in
[`SECURITY.md`](https://github.com/IntelliBridge/ndia-red-team-simulator/blob/main/SECURITY.md).

```bash
redsim evidence-pack --out ./redsim-evidence
# optional: scope to a single project's audit chain
redsim evidence-pack --out ./redsim-evidence --project acme
```

The command prints the redsim version, the number of audit chains
exported, the file count, and the overall pack hash. `--out DIR` is
required.

---

## What's in the pack

```
<out>/
  audit/<chain_id>.jsonl   one file per hash-chained audit chain
  verification.json        per-chain verify_chain() verdict (verified / count / broken_at)
  controls.json            SOC 2 / ISO 27001 / FedRAMP controls crosswalk
  system.json              redsim version + secret-free enabled-features summary
  manifest.json            sha256 of every file + the overall pack hash
```

- **`audit/`**: every hash-chained audit chain is exported as JSONL, one
  file per chain (per-run, per-project, and the system chain). With
  `--project P` the pack is scoped to that project's chain.
- **`verification.json`**: each chain is replayed through `verify_chain()`
  and its verdict recorded (`verified`, event `count`, `broken_at` if
  tampering is detected). This is the integrity proof: an auditor can
  confirm the exported log is intact and re-verify it independently.
- **`controls.json`**: the auditor-facing crosswalk (see below).
- **`system.json`**: redsim version, generation timestamp, and a
  **secret-free** enabled-features summary (backend names and booleans
  only, for example `auth_mode`, `oidc_configured`, `tenancy_rls`,
  `llm_enabled`). See [No secrets](#no-secrets).
- **`manifest.json`**: the sha256 of every file in the pack plus an overall
  `pack_hash` computed over the sorted `path\0sha256` lines. Any file
  added, removed, or mutated changes the pack hash, so the bundle is itself
  tamper-evident.

---

## Frameworks covered

`controls.json` maps representative controls from three frameworks to the
concrete redsim features that supply evidence:

| Framework | Example controls mapped |
|---|---|
| **SOC 2** (Trust Services Criteria) | CC6.1 access/RBAC, CC6.6 scope boundary, CC7.2 monitoring, CC7.3 tamper-evident audit |
| **ISO/IEC 27001:2022** (Annex A) | A.5.15 access control, A.8.15 logging, A.8.16 monitoring, A.8.8 technical-vulnerability management |
| **FedRAMP** / NIST 800-53 | AC-3 access enforcement, AC-6 least privilege, AU-9 audit protection, AU-10 non-repudiation, SI-2 flaw remediation, SI-7 integrity, SI-10 input validation |

!!! note "Partials are flagged honestly"
    The crosswalk is deliberately conservative: it only maps a control to
    a feature redsim genuinely ships. Anything with deployment-dependent or
    incomplete coverage is marked `"status": "partial"` with a `note`
    explaining the gap (for example monitoring controls depend on the
    operator's SIEM or telemetry backend, and LLM-guardrail input-validation
    coverage scales with the enabled guardrail policies). The pack is meant
    to survive an auditor reading it closely. It does not overclaim.

    The ML vertical adds no control of its own to the crosswalk yet. Once
    campaigns run, the campaign audit events (`model.register`,
    `attack.run`, `explain.run`, `harden.recommend`, `verify.replay`,
    `finding.review`) land on the same chains and are exported with them.

---

## No secrets

The pack carries **no secret material**. `system.json` records only
backend names and booleans derived from config and env, never tokens,
credentials, key material, the Pythia key or URL, or URLs that might embed
credentials. The audit chains contain forensic detail (digests plus blob
refs), not raw tool output, model bytes, dataset rows or secret values. The
bundle is safe to hand to an external auditor as-is.
