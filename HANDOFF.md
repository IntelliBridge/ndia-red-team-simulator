# Handoff — next Aegis session

Read this before doing anything else. It is the only place that
captures session-specific context that the commit history alone
doesn't tell you.

---

## The 30-second picture

Aegis is a full-lifecycle AI security platform that ties Strix, CAI,
mcp-kali-server, and vulnerability-fixer into one multi-user platform
with a hash-chained audit log. It's tagged at **v0.4.1** (May 2026).
The Phase-4 release sequence (v0.3.1 → v0.4.0 → v0.4.1) is complete.

**Current state**: `pytest -q` is **237 passed, 3 skipped** on Python
3.12 and 3.13. Every commit on `main` keeps this green; don't merge
anything that breaks it.

**Documentation**: there is now a full MkDocs Material site that
builds from `docs/`. `mkdocs build --strict` is clean. The README is
rendered as the docs-site homepage via a build hook (`hooks/readme_as_index.py`),
so the README is the single source of truth.

---

## Where to start

Skim, in this order:

1. [`README.md`](README.md) — current snapshot, tagline, capability
   table (✅ Shipped vs 🔨 Roadmap).
2. [`CHANGELOG.md`](CHANGELOG.md) — every release entry with the
   F-numbered milestones. Three Phase-4 entries (`v0.3.1`, `v0.4.0`,
   `v0.4.1`).
3. [`docs/architecture/overview.md`](docs/architecture/overview.md) —
   system context, deployment topology, request flow, ER diagram,
   layered services, release map. Six mermaid diagrams.
4. The four deep-dive architecture docs:
   - [`docs/architecture/auth.md`](docs/architecture/auth.md)
   - [`docs/architecture/audit-chain.md`](docs/architecture/audit-chain.md)
   - [`docs/architecture/observability.md`](docs/architecture/observability.md)
5. [`docs/api/v1.md`](docs/api/v1.md) — every HTTP route grouped by
   RBAC tier.

The docs site renders all of this with native mermaid + dark mode +
search:

```bash
source .venv/bin/activate
make docs-serve     # http://localhost:8001
```

---

## What just happened (this session)

Most-recent first, all on `main`:

| Commit | What |
|---|---|
| `85608c4` | README rewrite — OnePager voice + honest current-state |
| `3884d71` | README link fixes (bare-directory link warnings) |
| `407b8dc` | README rendered as docs-site landing via build hook |
| `cf0e94a` | **Mermaid 11 syntax fixes** across every diagram (20 blocks) |
| `d262cb5` | README mention of docs site + Make targets |
| `fc63284` | `.github/workflows/docs.yml` (strict build + Pages deploy) |
| `f27a411` | Top-level Makefile (`docs-serve` / `docs-build` / `docs-build-strict`) |
| `f8f451d` | MkDocs Material scaffold |
| `ca3b621` | Refresh CONTRIBUTING / SECURITY / local-stack for v0.4.1 |
| `837a438` | `docs/dev/frontend.md` + `docs/adr/0001-vendored-submodules.md` |
| `565cb21` | `docs/api/v1.md` endpoint catalog |
| `f257c93` | `docs/architecture/observability.md` + `docs/ops/deploy.md` |
| `c841522` | `docs/architecture/auth.md` + `audit-chain.md` |
| `60536fd` | `docs/architecture/overview.md` with mermaid |
| `db1284f` | Top-level README with quickstart + doc map |
| `942780f` | Archive `PLAN_PHASE3.md` + `phase3.md` under `docs/architecture/legacy/` |

Net: the entire `docs/` tree was created, every diagram was validated
against the Mermaid 11 parser (`/tmp/merm-validate/`), and the docs
site is live + CI-built on PR + deployed on `main` push.

---

## Known gotchas

### Placeholder GitHub URL

Every cross-tree absolute link uses
`https://github.com/example/aegis/...`. **Replace globally with the
real repo URL** before the docs site is published anywhere external.
Locations: `mkdocs.yml` (`repo_url` + `copyright`), every doc that
links to CONTRIBUTING/SECURITY/CHANGELOG/AEGIS_VENDORED, and the
README. A single find-replace covers it.

```bash
grep -rln "github.com/example/aegis" . \
  --exclude-dir=node_modules --exclude-dir=.venv \
  --exclude-dir=site --exclude-dir=project_repos
```

### GitHub Pages one-time setup

For the workflow to actually deploy: **Settings → Pages → Source →
GitHub Actions**. The workflow has the right perms; the source toggle
is the one manual step.

### Mermaid 11 reserved keywords

`default` is reserved in Mermaid 11 — using it as a subgraph id
silently breaks parsing. We hit this twice. If a new diagram uses
`subgraph X[…]` and X happens to be a keyword (`default`, `end`,
`subgraph`, `direction`, …), it'll parse-error mid-block. Rename to
`p_default` etc.

Other Mermaid gotchas we hit:

- **C4 diagrams** are explicitly experimental upstream and *not*
  supported by mkdocs-material. Use `flowchart` instead.
- **`api[/v1/* HTTP routes]`** is parsed as a parallelogram shape
  because `[/` opens one. Always use the quoted form
  `api["/v1/* HTTP routes"]` when the label has special chars.
- **`<exp>`, `<id>`** in sequence-diagram messages or ER attribute
  comments get parsed as HTML tags. Avoid angle brackets in labels.
- **Edge labels with slashes** (`POST /ingest`) must be quoted:
  `-. "POST /ingest" .->`.

### MkDocs serve doesn't watch the README by default

`mkdocs serve` only watches `docs_dir` + `mkdocs.yml`. We added a
`watch:` block to also watch `README.md` and `hooks/` — without it,
the README-as-index hook only fires on the first build. If you add
new files outside `docs/` that the build reads, add them to `watch:`
in `mkdocs.yml`.

### Zscaler corporate proxy CA

This machine is behind Zscaler. Several commands need the CA bundle:

```bash
SSL_CERT_FILE=$PWD/deploy/certs/zscaler.pem    # Python (uv, pip with --native-tls)
GIT_SSL_CAINFO=$PWD/deploy/certs/zscaler.pem    # git over HTTPS
NODE_EXTRA_CA_CERTS=$PWD/deploy/certs/zscaler.pem  # node / npm / pnpm
```

`deploy/certs/*.pem` and `*.crt` are gitignored — never commit. The
README in `deploy/certs/` documents the setup. `brew livecheck` also
fails on TLS in this shell (its bundled Ruby has its own cert path).

### `claude-code` CLI is on npm, not just brew

Homebrew has `claude-code` 2.1.145 (cask). The npm registry (Anthropic's
primary distribution channel) has newer releases that brew lags
behind. As of session end: brew = 2.1.145, npm = 2.1.154. If you want
the latest CLI:

```bash
brew uninstall --cask claude-code
npm install -g @anthropic-ai/claude-code
```

The model the CLI talks to is independent from the CLI version.

---

## Open threads / things you may want to pick up

### v0.4.2 candidates from the deferred lists

(See `docs/architecture/overview.md` § "What's deferred" and the per-
release CHANGELOG entries for the full list.)

- Storybook test-runner CI gate flip (after the second component
  batch — first batch was the 8 components in `@aegis/design-system`).
- Storybook a11y "serious-or-worse" gate.
- Elasticsearch compose profile (`obs-search`) hardening — currently
  shipped but not battle-tested.
- Dark mode in the design system.
- Audit chain visualisation page (replaces the current static
  `/v1/audit/verify` view).
- Per-finding HTML report (smaller than run-level).
- Wire the 7 registered-but-not-wired CAI agents (memory analysis,
  network traffic analyzer, reverse engineering, android SAST, subghz
  SDR, wifi security tester, replay attack). They currently return
  `status='not_wired_in_phase_3'`.

### Things deliberately NOT done

- The two `INFO`-level mkdocs messages about bare directory links
  were the trigger for converting `docs/adr/` → `docs/adr/0001-…` etc.
  Strict mode was already clean either way.
- We didn't add Postgres-side `pg_audit` for database-level
  append-only enforcement on `audit_events`. Documented in
  `SECURITY.md` as a known gap.
- We didn't bump any vendored submodule to a newer SHA — bumps are
  explicit, per [ADR-0001](docs/adr/0001-vendored-submodules.md).
- We didn't wire the GitHub Pages deploy beyond the workflow file.
  See the one-time setup gotcha above.

---

## Working environment

| Item | Value |
|---|---|
| Primary working directory | `/Users/noah.behrick/Pentest` |
| Python venv | `.venv/` (Python 3.12.13) |
| Node | needed for the web app + mermaid validation |
| Docker | needed for the full stack via `make up` |
| Default branch | `main` |
| Test gate | `pytest -q` → 237 passed, 3 skipped |
| Docs build gate | `make docs-build-strict` clean |
| Lock files | `uv.lock` and `web/pnpm-lock.yaml` are committed; CI fails on drift |

### Useful commands

```bash
# Tests + docs
pytest -q
make docs-serve                 # http://localhost:8001
make docs-build-strict          # CI's exact docs gate

# Local stack
cd deploy && make up            # default profile
docker compose --profile obs up   # + Collector + Loki + Jaeger
docker compose --profile obs-search up

# Validate every mermaid block against the Mermaid 11 parser
#   (the harness from this session lives in /tmp/merm-validate/)
node /tmp/merm-validate/check.mjs
```

### Repo conventions

- **Service layer is sacred.** API write routes call **admission
  services only** (`services.scans.create_scan_job`,
  `services.fixes.create_fix_job`, etc.); Celery tasks call
  **execution services only**. A grep gate fails any new write route
  whose handler doesn't go through `aegis.services.*`. See
  `docs/architecture/overview.md` § "Layered service architecture."
- **Audit-before-enqueue is load-bearing.** `safety.authorize()` runs
  (and emits the chained row) **before** the Run + Job rows exist and
  **before** Celery is touched. A worker crash mid-enqueue must never
  produce a DB row without a matching chain event.
- **Phase 2 offline path is sacred.** Every PR must keep
  `pytest -q` green on a machine with no Postgres, no Redis, no
  Keycloak.
- **Commits are F-numbered + scoped.** `F<num> (v<release>): <subject>`
  for milestone commits, `docs:` / `mkdocs:` / `release:` for the
  other kinds.

---

## File-tree pointers

The files most useful to a fresh session, in priority order:

1. [`README.md`](README.md) — value prop + capability table + quickstart.
2. [`CHANGELOG.md`](CHANGELOG.md) — per-release detail.
3. [`mkdocs.yml`](mkdocs.yml) + [`hooks/readme_as_index.py`](hooks/readme_as_index.py) — docs build config.
4. [`docs/architecture/overview.md`](docs/architecture/overview.md) — system overview.
5. [`docs/api/v1.md`](docs/api/v1.md) — every HTTP route.
6. [`docs/ops/deploy.md`](docs/ops/deploy.md) — env-var matrix + rotation runbook.
7. [`aegis/services/`](aegis/services/) — admission + execution boundary.
8. [`aegis/audit/chain.py`](aegis/audit/chain.py) — the hash chain.
9. [`aegis/api/auth.py`](aegis/api/auth.py) — the 5 auth paths.
10. [`pyproject.toml`](pyproject.toml) — `[docs]`, `[api]`, `[worker]`, `[test]`, `[dev]` extras and pytest markers.

---

## Final state at session end

- Branch: `main`
- Last commit: `85608c4 docs: rewrite README with OnePager voice + honest current-state`
- Tests: **237 passed, 3 skipped** on Python 3.12
- Docs strict build: **clean** (`make docs-build-strict`)
- Mermaid: **20 of 20 blocks parse cleanly** against the Mermaid 11
  library (cross-checked via Anthropic-fetched canonical sources +
  empirical parser run)
- Working tree: clean modulo `web/node_modules/`,
  `web/tsconfig.tsbuildinfo`, and the `project_repos/cai` submodule's
  internal state (gitignored / harmless)

Good luck. The CHANGELOG is the most honest source about what's
shipped; the docs site is the most honest source about how it works.
