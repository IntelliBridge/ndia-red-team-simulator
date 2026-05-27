---
name: stig-init
description: Bootstrap, maintain, or extend DISA STIG checklist tracking for an application repo using the in-tree `stig-check` engine. Use this skill whenever the user mentions STIG, STIG Manager, eMASS, ATO checklists, ASD STIG, Web Server SRG, .cklb files, compliance asset setup, or wants to "set up STIG", "init STIG", "scaffold compliance", "wire CI for STIG", "add the Web Server SRG", "add another benchmark", or migrate to a new STIG tracking pattern -- even if they don't say "stig-init" by name. Also triggers when the user wants to validate a `stig/config.yaml`, audit which STIG assets are covered, fix detection misses (missing keycloak realm, library fan-out, host_name continuity), explain why a starter rule is firing as Open / Not Applicable on a given asset, OR author a new automated check rule for an ASD STIG / Web Server SRG control (e.g. "automate V-222400", "automate V-206434", "write a check for APSC-DV-001400 / SRG-APP-000439-WSR-000151", "add a STIG rule", "extend STIG coverage", "consumer rule override"). For rule authoring the skill walks from the vendored XCCDF control text to a scaffolded `stig/rules/V_NNNNNN.py` + paired pytest.
---

# stig-init

Wizard around the in-tree `stig-check` engine
(`packages/stig-check/`). The CLI alone is fine; the skill exists
because the *review* step between `stig-check init` (which proposes a
config from auto-detection) and `stig-check generate-cklb` (which mints
the eMASS-ready checklists) is where the user has to make calls
auto-detection can't: should these two sub-roles consolidate, what was
this asset called in eMASS before, is the missing keycloak realm a
detection gap or intentional. The skill walks that review with the
user, then orchestrates the rest of the flow end to end.

## When you should NOT use this skill

- The user just wants to run rules on an already-configured repo.
  Direct them to `uv run stig-check run --write-status stig/STATUS.md`
  -- no need for the wizard.
- The user is debugging the engine itself (a starter rule misbehaving,
  a parser bug). Read the engine source, don't follow the skill.

## The flow

1. **Confirm scope.** Use `AskUserQuestion` for branching choices, not
   free text. Ask four things:
   - Target directory (default: cwd if it has `apps/`, `packages/`,
     `pyproject.toml`, or `package.json`).
   - **Which benchmarks apply.** The engine ships two today:
     - `asd` -- ASD STIG, applies to every asset with application code.
       Default and almost always wanted.
     - `websrg` -- Web Server SRG, applies to nginx reverse proxies,
       static-asset frontends, and application HTTP servers (Fastify
       / Express / Uvicorn-fronted FastAPI).
     Pick `asd` only for backend-only services, library packages, or
     CLIs. Pick `asd + websrg` for any repo that ships an HTTP server
     or fronts one with nginx. See "When does Web Server SRG apply?"
     below for the decision rule.
   - Migration vs. greenfield. If migrating, ask for the prior asset
     `host_name`s -- they're the eMASS / STIG Manager primary key,
     and changing them creates duplicate asset records on the server
     instead of updating the existing ones. This is the most common
     source of pain and worth confirming up front.
   - Whether to skip XCCDF download (offline / pinned-version cases
     only).

2. **Run init.** From the repo root:
   ```bash
   # ASD only (preserves the historical default UX):
   uv run stig-check init <target>

   # ASD + Web Server SRG:
   uv run stig-check init <target> \
     --with-benchmark asd \
     --with-benchmark websrg
   ```
   `init` writes `stig/config.yaml` (a *proposal* with provenance comments
   showing what the detector saw and where), vendors the latest DISA
   XCCDF zip + extracted XML to `stig/xccdf/` for **each** benchmark,
   drops a starter `stig/README.md`, and lays down
   `.github/workflows/stig-check.yml`. It does **not** evaluate any
   rules yet -- proposal only.

3. **Validate the proposal.** Don't review by reading the YAML
   yourself; let the engine surface the issues:
   ```bash
   uv run stig-check validate
   ```
   This emits an advisory list -- missing keycloak detection, library
   fan-out, stack/path mismatches, orphan path keys, uncovered
   Dockerfiles, undeclared stacks the detector found. Each advisory
   has a short `code`, a severity, the affected asset (or `repo`), a
   human message, and sometimes a suggested edit. See
   `references/advisory-codes.md` for what each code means and how to
   resolve it.

4. **Walk the advisories with the user.** For each one, state the
   issue, propose the fix, ask for confirmation, then `Edit` the
   config. Two patterns to apply judgment on:
   - **Library fan-out (`library-fan-out`):** auto-detect proposes one
     asset per `packages/*` directory. Often the user wants to
     consolidate to a single `<repo>-libs` asset because libraries
     don't have independent deployment surfaces. Ask which way they
     prefer; either is valid.
   - **Sub-role split:** auto-detect splits `apps/<x>/{backend,
     frontend}` into two assets. Sometimes that matches the
     deployment topology (separate eMASS rows); sometimes the user
     deploys them as one unit and wants one asset. Ask.

   For mechanical fixes (missing keycloak path, orphan path keys),
   the suggested edit in the advisory output is usually correct --
   confirm and apply it.

   After substantive edits, re-run `stig-check validate` and re-walk
   any new advisories. The cycle is cheap.

5. **If migrating, lock down `host_name`s.** Before generating
   checklists, double-check every asset's `host_name` matches what's
   already in STIG Manager / eMASS. Once you generate and re-import,
   any drift creates duplicates that have to be reconciled manually.

6. **Generate checklists.**
   ```bash
   uv run stig-check generate-cklb
   ```
   Produces one `.cklb` per `(asset, benchmark)` pair in
   `stig/checklists/`. Filename layout depends on the config schema:
   - **Legacy single-`xccdf:` config** (back-compat): `<asset>.cklb`.
     Used when a repo hasn't migrated to the `benchmarks:` block.
   - **New `benchmarks:` config** (default for fresh `init`):
     `<asset>__<benchmark_id>.cklb`. So an asset under both ASD and
     Web Server SRG produces two files: `<asset>__asd.cklb` and
     `<asset>__websrg.cklb`. STIG Manager / eMASS expect one
     checklist per (host, STIG) pair, so this layout maps 1:1.

   The default mode is merge, which preserves existing reviewer
   notes on subsequent runs -- don't pass `--no-merge` unless the
   user explicitly wants to throw away review state.

7. **Run rules.**
   ```bash
   uv run stig-check run --write-status stig/STATUS.md
   ```
   The runner walks every `(asset, benchmark)` pair, loads the rules
   tagged with that benchmark, filters by stack and path, evaluates,
   and patches. Today: 8 ASD starter rules (`APSC_DV_*`) + 5 Web
   Server SRG starter rules (`SRG_APP_WSR_*`) + any consumer
   overrides in `stig/rules/` (shadow-by-`vuln_id` semantics: a
   consumer rule with the same `vuln_id` as a starter wins). Use
   `--benchmark <id>` to scope a run to a single benchmark.

8. **Hand off.** Show:
   - Asset count and per-asset rollup (NaF / Open / NA / Not
     Reviewed) **broken out by benchmark**.
   - Real Open findings (vuln_id + benchmark + summary + a one-line
     "fix this by ..." pulled from the rule's finding_details). Use
     `references/starter-rules.md` for context.
   - What to commit (`stig/`, `.github/workflows/stig-check.yml`).
   - For migration: remind to re-import to STIG Manager and verify
     assets *update* in place rather than creating new rows.

## When does Web Server SRG apply?

Apply `websrg` to any asset that:

- **Declares the `nginx` stack** (reverse proxy or static-asset
  hosting). Include the asset's nginx config file or directory at
  the `nginx_config` path key.
- **Declares the `fastify` stack** (Node.js HTTP server). Include
  the file containing the `fastify({...})` constructor at the
  `server_config` path key. If the constructor is in a different
  module than the entrypoint, use a YAML list:
  `server_config: [src/server.ts, src/index.ts]`.
- **Declares any other in-process HTTP server** (Express, Uvicorn,
  Gunicorn, Tomcat) -- the SRG is technology-neutral; you'll likely
  need to write consumer rules at `stig/rules/V_NNNNNN.py` since the
  starter rules currently target nginx + Fastify only.

Do **not** apply `websrg` to:

- Library packages with no HTTP surface (`python-lib`, `nodejs-lib`).
- Pure CLI tools, batch jobs, or workers.
- Frontend source roots that are *built* into static assets but not
  *served* from this asset (those should be a separate nginx asset
  if you ship the bundle behind one).

## Authoring a new automated check rule

The engine ships with 13 starter rules total: 8 against the ASD STIG
(`APSC_DV_*`) and 5 against the Web Server SRG (`SRG_APP_WSR_*`).
Hundreds of controls are still `not_reviewed`. Use this flow when the
user wants to automate one more (typically: a finding came back from
STIG Manager, or they're pushing NaF count up before an audit).

For mechanical details -- the `Rule` contract, `RuleContext` API, the
three rule-shape templates (grep / structural-parse / command-exec),
the paired-pytest template, the worked status-semantics table -- read
`references/rule-authoring.md` (ASD-flavored examples) or
`references/webserver-rule-authoring.md` (nginx + Fastify-flavored).
**Read whichever fits the benchmark once you're past step 3 of the
flow below**; the early steps don't need it.

The `benchmark_id` class attribute on a `Rule` decides which benchmark
the rule is filed under. Defaults to `"asd"`; set
`benchmark_id = "websrg"` for Web Server SRG rules. The runner uses
this to scope which rules run for a given `(asset, benchmark)` pair,
and which `.cklb` file the result is patched into.

**The trap to avoid:** if the XCCDF `check_content` says "interview
the ISSO" / "review the SSP" / "verify in writing", the control is
manual. Don't fake automation -- a `not_a_finding` based on a
file-existence check is worse than leaving the control `not_reviewed`.
Either decline to scaffold (and explain that the evidence lives in
eMASS, not in the repo), or scaffold a placeholder rule whose
`evaluate()` returns `RuleResult.not_reviewed("manual control -- see
SSP §X")`. Both answers are defensible; pick whichever the user
prefers in the moment.

### Flow

1. **Get the control id.** Ask for vuln_id (`V-222400`), stig_id
   (`APSC-DV-001400`), or SRG number. If only English, ask which
   STIG Manager finding they're looking at -- the id is on every
   review screen.

2. **Surface the XCCDF entry to the user.** Pull `rule_title`,
   `discussion`, `check_content`, `fix_text` -- one-liner using
   `stig_check.xccdf.parse_xccdf` does it. Read those four fields
   together before proposing automation; the user often catches
   nuance you'd miss. (Snippet + filename guidance in
   `references/rule-authoring.md`.)

3. **Decide automatable + which shape.** If `check_content` is
   manual-only, see the trap above. Otherwise pick grep /
   structural-parse / command-exec; `references/rule-authoring.md`
   has the criteria + templates. Discuss the shape with the user --
   what sounds like a grep is sometimes a structural-parse.

4. **Pick stacks + path keys.** Reuse an existing path key from
   `stig/config.yaml` if one fits. If the control reads a file
   class no existing key captures, declare a new key and walk the
   `paths:` edit with the user. Repo-wide checks set
   `requires_stacks = ()` and `requires_paths = ()`.

   Use `not_applicable` deliberately -- a fastapi-only rule firing
   NA on the keycloak gateway is correct; a rule that returns
   `not_a_finding` because it found nothing to check is wrong (it
   masks a real gap).

5. **Scaffold rule + paired test.** Files go at
   `stig/rules/V_NNNNNN.py` and `stig/rules/tests/test_V_NNNNNN.py`.
   The class name is descriptive (`LogonBannerRule`, not
   `Rule222400`). Test covers passes / opens / not_applicable;
   create `stig/rules/tests/__init__.py` if it doesn't exist yet.

6. **Run the test, then the rule.**
   ```bash
   uv run pytest stig/rules/tests/test_V_NNNNNN.py -v
   uv run stig-check run --asset <asset-name>
   ```
   Iterate regex/parse logic in the test; only run the full check
   once tests are green. If the rule wrongly fires `open` on a
   particular asset, fix `requires_stacks`/`requires_paths` -- don't
   add asset-name skip lists.

7. **Hand off.** Files created, current per-asset verdict, and a
   reminder to update `stig/README.md` so reviewers see the new
   rule listed.

For a whole SRG family, do them one at a time: scaffold + test +
verify each before moving on. Batching turns into a wall of failures.

## When the user pushes back

- *"Do I really need to consolidate the libs?"* No. Each as its own
  asset is valid -- you'll just see N rows in STIG Manager instead of
  one. Document the choice in the config header comment.
- *"Why is V-XXXXXX firing as Open?"* Look up the rule in
  `references/starter-rules.md` -- it lists what the rule checks,
  when it passes, when it fails. Most opens are real findings the
  user should fix, not false positives -- read the rule's
  `finding_details` in the `.cklb` before suggesting suppression.
- *"Can the rule be wrong?"* Yes, regex-based rules can flap. The
  fix is a consumer override at `stig/rules/V_XXXXXX.py` with the
  same vuln_id, which the runner shadows by id. Don't suppress;
  override.

## Engine quick reference

| Command | What it does |
|---|---|
| `stig-check init <target>` | Detect stacks, propose `stig/config.yaml`, vendor XCCDF |
| `stig-check init <target> --with-benchmark websrg` | Same, plus add Web Server SRG (repeatable for more benchmarks) |
| `stig-check validate` | Audit the proposal against the review checklist |
| `stig-check generate-cklb` | Mint one `.cklb` per `(asset, benchmark)` (merge-by-default) |
| `stig-check run --write-status PATH` | Evaluate rules, patch `.cklb`s, write `STATUS.md` |
| `stig-check run --benchmark websrg` | Limit a run to one benchmark (repeatable) |
| `stig-check upgrade-xccdf --benchmark <id>` | Re-fetch latest DISA release for one benchmark |
| `stig-check status` | Render rollup to stdout (no rule eval) |

The engine source lives at `packages/stig-check/src/stig_check/`;
starter rules at `packages/stig-check/src/stig_check/starters/`.
The benchmark registry (URL templates, inner-zip layouts, rule
prefixes) lives at `packages/stig-check/src/stig_check/benchmarks.py`
-- adding a third DISA benchmark means dropping a new
`BenchmarkRegistration` there and writing rules with the matching
prefix.

## Things that go wrong and how to recognize them

- **`init` says "could not reach DISA download URL"** -- network
  blocked or DISA URL changed. Ask the user for an XCCDF zip
  (`U_ASD_V6Rxx_STIG.zip`); they can drop it into `stig/xccdf/` and
  re-run with `--skip-xccdf`.
- **`generate-cklb` errors with "XCCDF not found for benchmark <id>"**
  -- the `xccdf:` field for that benchmark in `stig/config.yaml`
  doesn't match what's actually in `stig/xccdf/`. Either fix the path
  or run `stig-check upgrade-xccdf --benchmark <id>` to re-download.
- **`run` errors with "checklist for asset X benchmark Y not found"**
  -- a benchmark spec applies to an asset but no `.cklb` file was
  minted yet. Run `stig-check generate-cklb` once first; it materializes
  every required `(asset, benchmark)` cklb.
- **Adding a new benchmark to an existing repo renames `.cklb` files**
  -- moving from the legacy `xccdf:` shorthand to the `benchmarks:`
  block changes the cklb filename layout from `<asset>.cklb` to
  `<asset>__<benchmark>.cklb`. `git mv` the existing files yourself
  (the merge logic preserves their content); the next `generate-cklb`
  run will then materialize the additional benchmark cklbs alongside.
- **STIG Manager rejects the import as "STIG not installed"** --
  classic `stig_id` mismatch (the .cklb's `stig_id` must match
  DISA's `<Benchmark id>` byte-for-byte). The engine has a
  regression test that locks this in; if you're seeing this on a
  fresh repo, check that `stig/xccdf/` actually contains the
  extracted XML, not just the zip.
- **Re-import in STIG Manager creates duplicates** -- `host_name`
  drifted. Hard to recover server-side; preserve `host_name` across
  runs from day one.
