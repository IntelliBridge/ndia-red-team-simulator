# redsim

Adversarial ML evaluation simulator: ART attacks, SHAP evidence, candidate
hardening recommendations. Non-operational proof of concept.

The repo was stripped out of the IntelliBridge `aegis` codebase, which is why
aegis names still appear in places. Section 6 of the design spec records what
that strip deleted.

## What is authoritative

1. `docs/brief.md` is the foundation document. Where it and the design spec
   disagree, the brief wins. It says so in its own header.
2. `docs/superpowers/specs/2026-09-08-redsim-design.md` is the design spec.
   Every stub in `redsim/` and `web/` has a comment pointing back at a section
   of it.

## What is not authoritative

These files describe Aegis, a different product with Postgres, Keycloak, Kali
and Celery. None of that exists here. Do not treat them as a description of
this codebase or build against them.

| File | Status |
|---|---|
| `README.md` | The "Get started" and "Documentation" sections are current. Everything else is inherited Aegis narrative, including a Topic map whose links mostly 404 and a release history for a different product. |
| `.env.example` | Aegis variables. |
| `deploy/docker-compose.yml` | Aegis service topology: postgres, redis, keycloak, minio, kali, `aegis-api`. None of it applies. |
| `docs/adversarial-ml-redteam-spec.md` and its `.html` | An earlier hackathon spec that assumes building on top of the Aegis platform and its audit chain. Superseded by `docs/brief.md`, which drops the Aegis dependency. Useful for the ART and SHAP framing, not for architecture. |

`deploy/Dockerfile.api` and `deploy/Dockerfile.web` are the exception. Both are
current redsim, and `Dockerfile.api` is worth reading before writing the API
because it already declares the intended entrypoint. See "Adding the backend"
below.

Docstrings in `redsim/registry.py`, `redsim/report.py` and `redsim/state.py`
credit the aegis modules they were inherited from. Those are accurate
provenance notes, leave them alone. The `.aegis-*` CSS classes in
`web/src/app/globals.css` are cosmetic leftovers.

## State of the code

Implemented:

| Module | Lines | What it holds |
|---|---|---|
| `redsim/schema.py` | 188 | The full Pydantic wire contract: `RunConfig`, `RunRecord`, `RunSummary`, `Observation`, `Measurement`, `CandidateRecommendation`, `TargetInfo`, `AttackInfo` |
| `redsim/recommend/guardrails.py` | 361 | Recommendation rules |
| `redsim/recommend/pythia_client.py` | 105 | Gateway client, SDK-compatible wire contract |
| `redsim/state.py` | 101 | `RunStore`, `ArtifactRef`, `new_run_id()` |
| `redsim/report.py` | 99 | XSS-safe Markdown to HTML rendering |
| `redsim/registry.py` | 79 | Generic name-keyed registry |
| `redsim/redact.py` | 78 | Redaction |

Not written yet:

- `redsim/api/__init__.py` is a one-line docstring. There is no FastAPI app
  anywhere in the package. `grep -rn "FastAPI\|APIRouter\|uvicorn" redsim/`
  returns nothing.
- `redsim/cli.py` does not exist, so the `redsim = "redsim.cli:main"` console
  script in `pyproject.toml` is a dangling entry point.
- `redsim/attacks/base.py` and `redsim/targets/base.py` define the
  `AttackAdapter` and `Target` Protocols. There are no concrete
  implementations, so no ART attacks are wired up.
- `redsim/explain/__init__.py` is a one-line stub, so no SHAP.
- `tests/` covers only the Pythia client. Section 7 of the design spec lists
  the eight test modules the project intends.
- `web/src/app/runs/page.tsx` and its siblings are placeholders that render
  "Not implemented yet".

## Development

`make install` then `make dev`. Full target table is in the README.

The venv is pinned to Python 3.12 because `torch` and
`adversarial-robustness-toolbox` do not publish wheels for 3.14 yet. `make
install` prefers pyenv's newest 3.12.x, then `python3.12` on `PATH`, then
`python3`, and only creates `.venv` when it is missing.

Known broken, both pre-existing rather than caused by the Makefile:

- `lint-py` reports nine ruff findings in `redsim/` and `tests/`, seven
  auto-fixable. The old Makefile pointed `ruff` at a nonexistent `aegis`
  path, so this target had never actually run.
- `lint-web` runs `next lint` in a workspace with no ESLint config and no
  `eslint` dev dependency, so it drops into Next's interactive setup prompt
  and hangs or fails. Fixing it means adding `eslint` and `eslint-config-next`.
- `make check` inherits both.

`make test` and `make typecheck` pass.

The `docs-*` targets have no `mkdocs.yml` and no `mkdocs` dependency behind
them. They are kept because the user asked for them, not because they work.

Nothing in CI runs tests. `.github/workflows/deploy-aws.yml` only builds
images and rolls ECS services, so `make check` is the only gate.

## Adding the backend

Three things already commit to the shape of the API before a line of it is
written, so match them rather than inventing a new contract.

1. `deploy/Dockerfile.api` ends with
   `CMD ["uvicorn", "redsim.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]`.
   That means the module is `redsim/api/app.py` and it exposes a `create_app()`
   factory, not a module-level `app`.
2. `web/src/lib/api.ts` defaults `BASE` to `http://localhost:8000`, overridable
   with `NEXT_PUBLIC_REDSIM_API_URL`. It already defines `reportUrl()` and
   `artifactUrl()` against `/v1/runs/...`.
3. `redsim/schema.py` already holds the response models, and section 4 of the
   design spec defines the route surface.

`make dev` runs its services under `make -j`, so wiring it up is a new target
plus one word:

```makefile
dev: require-install
	$(PY) -m pytest -q
	$(MAKE) -j dev-web dev-api

dev-api: require-install
	$(PY) -m uvicorn redsim.api.app:create_app --factory --reload --port 8000
```

One caveat on `make -j`: it returns as soon as the first child exits, so a
uvicorn that dies on startup produces a confusing partial teardown rather than
a clean error. If that gets annoying, a `wait -n` wrapper or a process manager
handles it better than raw `-j`.

Until `redsim/api/app.py` exists, the `api` image that
`.github/workflows/deploy-aws.yml` builds and pushes to ECR will build fine and
then crash on startup, because its `CMD` points at a module that is not there.

## Conventions

Commits are `type(topic): description`. Branch before committing, never commit
to `main` directly. Prose in docs and comments avoids em dashes and semicolons.
