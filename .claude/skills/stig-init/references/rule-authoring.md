# Authoring a `stig-check` consumer rule

This doc backs the "Authoring a new automated check rule" flow in
`SKILL.md`. Read it when you're scaffolding a rule for a control that
isn't covered by the 8 starters.

## The rule contract (recap)

A rule is a Python class that subclasses `stig_check.rules.Rule`,
declares a `vuln_id`, and implements `evaluate(self, ctx) ->
RuleResult`. The runner registers starters first, then walks
`stig/rules/` and registers consumer rules; same `vuln_id` -> consumer
shadows starter.

```python
from stig_check.rules import Rule, RuleContext, RuleResult, register

@register
class MyRule(Rule):
    vuln_id = "V-NNNNNN"           # XCCDF Group id; required
    stig_id = "APSC-DV-NNNNNN"     # human-friendly mapping
    requires_stacks = ("fastapi",) # asset must declare ALL of these
    requires_paths = ("backend_config",)  # asset must have these path keys
    applies_to = ()                # optional explicit asset allowlist

    def evaluate(self, ctx: RuleContext) -> RuleResult:
        ...
```

If an asset doesn't satisfy `requires_stacks` or `requires_paths`, the
runner returns `not_applicable` automatically -- don't re-check inside
`evaluate`. The runner also wraps your `evaluate` in a try/except that
turns unhandled exceptions into `not_reviewed`, so partial failures
(missing files, parse errors) won't crash a CI run, but it's cleaner to
return an explicit `not_reviewed` from your code.

## The RuleContext API

```python
ctx.repo_root: Path                    # absolute path to the repo
ctx.asset: str                         # the asset name being evaluated
ctx.config: Config                     # parsed stig/config.yaml

ctx.paths_for(key: str) -> list[Path]  # absolute paths registered under `key`
ctx.has_stack(stack: str) -> bool      # asset declares `stack`?
ctx.run(*args, cwd=None, timeout=60) -> CommandResult  # subprocess, no shell
ctx.file_contains(path, needle) -> bool
ctx.file_exists(path) -> bool
```

`paths_for` resolves relative paths against `repo_root`. Empty list is
the "no path declared" signal -- treat it as `not_applicable`. The
runner has already filtered for `requires_paths`, so an empty list at
this point usually means the asset declared the key with `~` or an
empty value -- still safer to guard.

The `grep(ctx, pattern, paths=[...])` helper from `stig_check.helpers`
returns `(path, line_no, line)` tuples. Pair with `evidence_lines(...)`
for human-readable evidence in the .cklb. **Pass `paths` as repo-relative
strings** (e.g. `"apps/orders-api/backend/main.py"`), not absolute --
`grep` joins against `ctx.repo_root` internally.

## Reading XCCDF: which field tells you what to check

The XCCDF entry has four fields you care about. They serve different
purposes; mixing them up leads to wrong rules.

| Field | What it tells you |
|---|---|
| `rule_title` | One-line "what" (e.g. "The application must enforce DoD-approved password length"). Useful as the `summary` text in `RuleResult`. |
| `discussion` | The reasoning. Useful for the rule's docstring and for explaining the `open` finding. |
| `check_content` | **The auditor's procedure.** This is the source of truth for what to check. Read it twice. If it says "ask the ISSO" or "review the SSP", the control is manual -- don't automate. If it says "examine the configuration file for X", that's grep. If it says "verify the value is at least N", that's structural-parse. |
| `fix_text` | What the fix looks like. Useful for `finding_details` on `RuleResult.open` -- gives the user a starting point for remediation. |

You can pull these out without leaving the shell:

```bash
uv run python -c "
from pathlib import Path
from stig_check.xccdf import parse_xccdf
b = parse_xccdf(Path('stig/xccdf/U_ASD_STIG_V6R4_Manual-xccdf.xml'))
r = next(r for r in b.rules if r.vuln_id == 'V-NNNNNN')
for field in ('rule_title','discussion','check_content','fix_text'):
    print(f'== {field} =='); print(getattr(r, field)); print()
"
```

Replace the XCCDF filename with whatever's in `stig/xccdf/`.

## Status semantics: which `RuleResult` to return

| Status | Use when |
|---|---|
| `RuleResult.not_a_finding(summary, evidence)` | Evidence proves the control is met. Always include `evidence` -- a reviewer should be able to spot-check by reading it. |
| `RuleResult.open(summary, evidence, finding_details)` | Evidence shows the control is **not** met. `finding_details` is what the user / reviewer reads to know how to fix it; default it from `fix_text`. |
| `RuleResult.not_applicable(summary)` | The control doesn't apply to this asset (e.g. an authorization control on a static-content frontend). Don't use this for "I couldn't find evidence" -- that's `open`. |
| `RuleResult.not_reviewed(summary)` | The check needs human eyes (manual control), or the rule hit an environment problem (parse error on a vendored config) and shouldn't pretend to know the answer. |

The most common authoring mistake: returning `not_a_finding` when the
rule found nothing to grep, instead of `open`. That hides real gaps.
If your rule is "the file must contain X" and the file doesn't exist,
that's either `open` (the file should exist) or `not_applicable` (the
control depends on an optional path). Pick one.

## Three rule templates

### Template A: grep-based

For "the code must reference X" controls. Cheapest; flappiest. Always
anchor patterns and always test the false-positive case.

```python
"""APSC-DV-NNNNNN (V-NNNNNN): <one-line what this checks>.

<2-3 line description of what evidence we look for and why it matters.
Quote relevant phrasing from the XCCDF check_content here.>
"""

from __future__ import annotations

from stig_check.helpers import evidence_lines, grep
from stig_check.rules import Rule, RuleContext, RuleResult, register


@register
class <DescriptiveName>Rule(Rule):
    vuln_id = "V-NNNNNN"
    stig_id = "APSC-DV-NNNNNN"
    requires_stacks = ("fastapi",)
    requires_paths = ("backend_config",)

    def evaluate(self, ctx: RuleContext) -> RuleResult:
        paths = ctx.paths_for("backend_config")
        if not paths:
            return RuleResult.not_applicable(
                summary="asset has no backend_config path declared"
            )
        rel = [str(p.relative_to(ctx.repo_root)) for p in paths]
        hits = grep(ctx, r"<anchored regex>", paths=rel)
        if not hits:
            return RuleResult.open(
                summary="<what is missing, in plain English>",
                evidence="searched: " + ", ".join(rel),
                finding_details=(
                    "<copy fix_text from XCCDF, or rephrase: do X in file Y>"
                ),
            )
        return RuleResult.not_a_finding(
            summary="<what we found, in plain English>",
            evidence=evidence_lines(hits, ctx.repo_root),
        )
```

**Anchoring tips.** `r"\bSESSION_TIMEOUT\b"` not `r"SESSION_TIMEOUT"`
(the latter matches `SESSION_TIMEOUT_SECONDS`). `r"^\s*csrf"` not
`r"csrf"` if you want declarations only. Always mentally walk the
pattern against a file that *shouldn't* match before shipping.

### Template B: structural-parse

For controls that depend on a structured config. Parse, walk, assert.
Catch parse errors as `not_reviewed` -- a malformed YAML isn't your
control's failure, it's a tooling failure.

```python
"""APSC-DV-NNNNNN (V-NNNNNN): <what this checks>."""

from __future__ import annotations

import json

from stig_check.rules import Rule, RuleContext, RuleResult, register


@register
class <DescriptiveName>Rule(Rule):
    vuln_id = "V-NNNNNN"
    stig_id = "APSC-DV-NNNNNN"
    requires_stacks = ("keycloak",)
    requires_paths = ("keycloak_realm",)

    def evaluate(self, ctx: RuleContext) -> RuleResult:
        path = ctx.paths_for("keycloak_realm")[0]
        if not path.is_file():
            return RuleResult.open(
                summary=f"declared realm path missing: {path.name}",
                evidence="(file not found)",
            )
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return RuleResult.not_reviewed(
                summary=f"could not parse {path.name}: {exc}"
            )

        # Walk the structure to extract the evidence.
        # Keep the assertion narrow -- one rule, one invariant.
        actual_value = data.get("someField", {}).get("nestedKey")
        if actual_value is None:
            return RuleResult.open(
                summary="<field absent> -- control unenforced",
                evidence=f"top-level keys: {sorted(data.keys())[:20]}",
            )
        if not <invariant predicate over actual_value>:
            return RuleResult.open(
                summary=f"<field present but wrong>: {actual_value}",
                evidence=json.dumps(actual_value, indent=2)[:1500],
            )
        return RuleResult.not_a_finding(
            summary="<invariant holds>",
            evidence=json.dumps(actual_value, indent=2)[:1500],
        )
```

The MFA rule (`APSC_DV_001580_mfa_required.py`) is a worked example of
this shape -- read it for inspiration on evidence formatting.

### Template C: command-exec

For controls that genuinely live in tooling output (a SARIF file from
a scanner, a CI workflow's exit code). Slow and harder to test; reach
for it last.

```python
"""APSC-DV-NNNNNN (V-NNNNNN): <what this checks>."""

from __future__ import annotations

from stig_check.rules import Rule, RuleContext, RuleResult, register


@register
class <DescriptiveName>Rule(Rule):
    vuln_id = "V-NNNNNN"
    stig_id = "APSC-DV-NNNNNN"
    requires_stacks = ()
    requires_paths = ()  # repo-wide check

    def evaluate(self, ctx: RuleContext) -> RuleResult:
        result = ctx.run("cat", "<path/to/scanner-output.sarif>", timeout=30)
        if result.exit_code != 0:
            return RuleResult.not_reviewed(
                summary=f"scanner output unavailable: exit={result.exit_code}"
            )
        # Parse stdout, derive verdict.
        if "<sentinel for failure>" in result.stdout:
            return RuleResult.open(
                summary="<what the scanner found>",
                evidence=result.stdout[-1500:],
            )
        return RuleResult.not_a_finding(
            summary="<scanner cleared this control>",
            evidence=result.stdout[-1500:],
        )
```

Prefer `ctx.run` over `subprocess.run` directly -- it cwd's into the
repo root, captures both streams, and never raises on non-zero exit.

## The companion pytest template

Drop this at `stig/rules/tests/test_V_NNNNNN.py`. Mirrors the engine's
own `tests/conftest.py` pattern: build a temp repo, point a minimal
`Config` at it, exercise the rule.

If `stig/rules/tests/` doesn't exist yet, also create:
- `stig/rules/tests/__init__.py` (empty file -- makes pytest discovery
  predictable under the consumer's existing pytest config)

```python
"""Unit tests for the V-NNNNNN consumer rule."""

from __future__ import annotations

from pathlib import Path

import pytest
from stig_check.config import Config
from stig_check.rules import RuleContext, get_registry

# Importing the rule module triggers @register, putting the class
# into the global registry. We then look it up by vuln_id.
from stig.rules import V_NNNNNN  # noqa: F401


@pytest.fixture(autouse=True)
def _isolate_registry():
    """Each test starts with an empty registry, then re-imports the rule."""
    registry = get_registry()
    registry.clear()
    # Re-trigger the @register decorator by reloading the module.
    import importlib
    from stig.rules import V_NNNNNN as _mod
    importlib.reload(_mod)
    yield
    registry.clear()


def _rule_cls():
    return next(r for r in get_registry().rules if r.vuln_id == "V-NNNNNN")


def _make_config(stacks: list[str], paths: dict[str, str]) -> Config:
    return Config.model_validate(
        {
            "apiVersion": "stig-check/v1",
            "xccdf": "stig/xccdf/x.xml",
            "checklists_dir": "stig/checklists",
            "rules_dir": "stig/rules",
            "assets": [
                {
                    "name": "test-asset",
                    "host_name": "test-asset",
                    "role": "Member Server",
                    "stacks": stacks,
                    "paths": paths,
                }
            ],
        }
    )


def test_passes_when_evidence_present(tmp_path: Path):
    target = tmp_path / "config.py"
    target.write_text("<content that satisfies the rule>")
    cfg = _make_config(stacks=["fastapi"], paths={"backend_config": "config.py"})
    ctx = RuleContext(repo_root=tmp_path, asset="test-asset", config=cfg)
    result = _rule_cls()().evaluate(ctx)
    assert result.status == "not_a_finding", result.summary


def test_opens_when_evidence_absent(tmp_path: Path):
    target = tmp_path / "config.py"
    target.write_text("<content that fails the rule>")
    cfg = _make_config(stacks=["fastapi"], paths={"backend_config": "config.py"})
    ctx = RuleContext(repo_root=tmp_path, asset="test-asset", config=cfg)
    result = _rule_cls()().evaluate(ctx)
    assert result.status == "open", result.summary


def test_not_applicable_when_path_missing(tmp_path: Path):
    cfg = _make_config(stacks=["fastapi"], paths={})
    ctx = RuleContext(repo_root=tmp_path, asset="test-asset", config=cfg)
    result = _rule_cls()().evaluate(ctx)
    assert result.status == "not_applicable"
```

A note on the `import stig.rules.V_NNNNNN`: this works because the
project root is on `sys.path` under `uv run pytest` from the repo
root. If the consumer's `pyproject.toml` configures pytest with a
`testpaths` or `rootdir` that excludes `stig/`, you may need to add
`stig` to `pythonpath` in `pyproject.toml`'s `[tool.pytest.ini_options]`
-- check first and adjust if needed.

## Common pitfalls

- **Regex flap.** A rule that passes locally and fails in CI usually
  has an over-loose anchor. Test it against a file that *should*
  fail before shipping.
- **`not_a_finding` on empty evidence.** If `grep` returned `[]`, the
  rule found nothing -- that's `open`, not pass. The XSS starter
  rule explicitly checks for the absence of a file *and* the absence
  of a pattern; pattern-not-found is failure.
- **Hardcoded paths.** Don't write `apps/orders-api/backend/main.py`
  in a rule. Use a path key in `stig/config.yaml` so the same rule
  works on a different repo with a different layout. If the path
  doesn't fit any existing key, declare a new one.
- **Forgetting `not_applicable`.** A rule with `requires_stacks =
  ("fastapi",)` automatically returns `not_applicable` on a non-fastapi
  asset -- don't re-check inside `evaluate`. But if the path key is
  optional (e.g. the rule reads `backend_middleware` *or*
  `backend_logging`), you have to check for both being empty
  yourself and return `not_applicable` explicitly.
- **Treating manual controls as automatable.** If the XCCDF
  `check_content` says "interview" / "review the documentation" /
  "verify in writing", that's manual. Author a rule that returns
  `RuleResult.not_reviewed("manual control -- see SSP §X")` and stop
  there. Don't fake an automatable check; fake passes are worse than
  no checks.
- **Importing across the engine boundary.** Rules in `stig/rules/`
  import from `stig_check.*` (the engine). The engine never imports
  from the consumer. Keep it that way; circular imports break
  `discover_consumer_rules`.

## After scaffolding

1. `uv run pytest stig/rules/tests/test_V_NNNNNN.py -v` until green.
2. `uv run stig-check run --asset <name>` to confirm the verdict on
   the real repo matches expectation.
3. Update `stig/README.md` with one line: `V-NNNNNN -- <one-line what
   it checks>`. Reviewers read the README first.
4. Commit `stig/rules/V_NNNNNN.py`, `stig/rules/tests/test_V_NNNNNN.py`,
   any new path key in `stig/config.yaml`, and the README delta.
