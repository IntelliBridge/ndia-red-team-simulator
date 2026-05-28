# Contributing to Aegis

## Dev setup

```bash
git clone --recurse-submodules <repo-url>
cd Pentest
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[test,dev]"     # offline / CLI development
pip install -e ".[test,dev,api,worker]"   # API + worker development (Phase 3)
```

Python 3.12+ is required. The default Mac `python3` (3.9) will not work — use Homebrew's `python3.12` or `python3.13`.

## Run the test suite

```bash
.venv/bin/pytest -q                              # default markers: unit + integration that doesn't need docker
.venv/bin/pytest -m 'not slow' -q                # exclude slow tests
AEGIS_E2E=1 AEGIS_DISABLE_LLM=1 \
  .venv/bin/pytest -q tests/e2e/                 # deterministic fixture-assisted E2E
```

## Code style

- Python 3.12, type hints encouraged.
- `ruff check aegis tests` (non-blocking in CI today).
- `mypy aegis` (loose mode).
- Tests use `unittest`; fixtures via `unittest.mock`.

## Pull request flow

1. Branch off `main`. Use `aegis/<topic>` for plain features; `aegis/fix/<finding_id>` is reserved for Aegis-generated PRs.
2. Write tests with the change. Don't ship behavior without coverage.
3. Keep the offline CLI working at every commit. The 121 Phase 2 tests and the deterministic E2E must stay green.
4. Update `CHANGELOG.md` under `[Unreleased]`.
5. PR template will be enforced once Phase 3 lands `M12`.

## Submodule discipline

`project_repos/{strix,cai,mcp-kali-server,vulnerability-fixer}` are pinned. Don't bump them without an explicit ADR explaining why. CI verifies the pinned SHAs match what's checked in.

## Security

Found a vulnerability in Aegis itself? See `SECURITY.md` — do not file a public issue.
