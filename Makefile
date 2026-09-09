SHELL := /bin/bash

# Repo-root Makefile for redsim (Adversarial ML Red-Team Simulator): the
# redsim Python package (redsim/: FastAPI API, Celery workers, alembic
# migrations) plus the Next.js app in web/ (@redsim/web) and
# packages/design-system (@redsim/design-system), joined by
# pnpm-workspace.yaml. The full stack (Postgres, Redis, Keycloak, MinIO,
# api, workers, web) runs from deploy/docker-compose.yml via `make up`.
#
# Recipes invoke the venv interpreter by path instead of assuming an
# activated shell, so `make dev` works from a clean terminal.

VENV    ?= .venv
PY      := $(VENV)/bin/python
WEB     := @redsim/web
# pyproject extras installed by `make install`. `llm` (private pythia-sdk
# git dep), `docs`, `security` and `garak` are opt-in, for example:
#   EXTRAS=api,worker,test,dev,ml,docs make install
EXTRAS  ?= api,worker,test,dev,ml
COMPOSE := docker compose -f deploy/docker-compose.yml

# ---------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------

install:
	@if [ ! -x "$(PY)" ]; then \
	  base=""; \
	  if command -v pyenv >/dev/null 2>&1; then \
	    ver=$$(pyenv versions --bare 2>/dev/null | grep -E '^3\.12\.[0-9]+$$' | sort -V | tail -1); \
	    if [ -n "$$ver" ]; then base="$$(pyenv prefix "$$ver")/bin/python"; fi; \
	  fi; \
	  if [ -z "$$base" ]; then base=$$(command -v python3.12 || true); fi; \
	  if [ -z "$$base" ]; then base=$$(command -v python3 || true); fi; \
	  if [ -z "$$base" ]; then echo "error: no python3 on PATH." >&2; exit 1; fi; \
	  echo "==> creating $(VENV) from $$base ($$("$$base" --version 2>&1))"; \
	  "$$base" -m venv "$(VENV)"; \
	fi
# The venv may have been created by uv, which ships no pip module. Prefer uv
# when it is on PATH (--native-tls trusts the corporate TLS proxy's CA).
# Otherwise bootstrap pip into the venv with ensurepip first.
	@if command -v uv >/dev/null 2>&1; then \
	  echo "==> uv pip install -e '.[$(EXTRAS)]'"; \
	  uv pip install --native-tls --python $(PY) -e '.[$(EXTRAS)]'; \
	else \
	  echo "==> pip install -e '.[$(EXTRAS)]'"; \
	  $(PY) -m ensurepip --upgrade && $(PY) -m pip install --upgrade pip && \
	  $(PY) -m pip install -e '.[$(EXTRAS)]'; \
	fi
	pnpm install

# Every target below needs an installed tree. Checking up front turns a
# confusing mid-recipe "no such file or directory" into one clear line.
require-install:
	@test -x $(PY) || { echo "error: $(VENV) is missing. Run 'make install' first." >&2; exit 1; }
	@test -d node_modules || { echo "error: node_modules is missing. Run 'make install' first." >&2; exit 1; }
	@test -d web/node_modules || { echo "error: web/node_modules is missing. Run 'make install' first." >&2; exit 1; }

# ---------------------------------------------------------------------
# Development
# ---------------------------------------------------------------------
#
# Services run under `$(MAKE) -j` (dev-api + dev-web). Adding another one is
# a new target plus one word on the -j line. Make forwards Ctrl-C to every
# child. Note that -j returns as soon as the first child exits, so a server
# that dies on startup shows up as a partial teardown rather than an error.
#
# Environment for dev-api (read by redsim/api/settings.py, all optional):
#   REDSIM_ENV=dev, REDSIM_AUTH_MODE=dev      defaults. dev auth accepts
#                                            `Bearer dev:<email>`
#   REDSIM_DB_URL                            postgresql+psycopg://... Unset
#                                            is allowed: the app starts,
#                                            /health reports
#                                            db_configured=false, and any
#                                            DB-backed route raises
#                                            "REDSIM_DB_URL is not set"
#   REDSIM_CORS_ORIGINS / REDSIM_WEB_ORIGIN   default http://localhost:3000
#   REDSIM_BLOB_BACKEND=fs, REDSIM_OUTPUT_DIR  default ./redsim_output
#   REDSIM_BROKER_URL / REDSIM_RESULT_BACKEND redis://... Needed only when
#                                            a request enqueues Celery work
# So dev-api boots with no Postgres or Redis running, but anything beyond
# /health, /docs and /metrics needs `make up` (or at least postgres +
# redis from it) and the variables above exported in the shell. Copy
# .env.example to .env and `set -a; source .env; set +a` for a quick start.
#
# dev-web reads its own file: web/src/env.js validates at config load and
# BETTER_AUTH_SECRET (32 characters or more) and BETTER_AUTH_URL are required,
# so copy web/.env.example to web/.env before the first `make dev-web`. Without
# it Next exits at startup naming the missing variable, which reads like a
# broken machine and is not one.
#
# dev-worker is deliberately NOT on the default `dev` line: it needs Redis
# (REDSIM_BROKER_URL, REDSIM_RESULT_BACKEND) and Postgres (REDSIM_DB_URL) up
# front and the ml extra installed. Run it in a second terminal, or use
# `make -j dev-api dev-web dev-worker` once the stack is up.

dev: require-install
	$(PY) -m pytest -q
	@echo "==> api: http://localhost:8000  (/docs, /health)"
	@echo "==> web: http://localhost:3000"
	$(MAKE) -j dev-api dev-web

dev-api: require-install
	$(PY) -m uvicorn redsim.api.app:create_app --factory --reload --port 8000

dev-web: require-install
	pnpm --filter $(WEB) dev

dev-worker: require-install
	$(PY) -m celery -A redsim.workers.celery_app worker -Q scans,default -l info

# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------

test: require-install
	$(PY) -m pytest -q
	pnpm --filter $(WEB) test

test-cov: require-install
	$(PY) -m pytest -q --cov=redsim --cov-report=term-missing

lint: lint-py lint-web

# The same rule selection as the ``Lint (ruff)`` step of redsim-ci.yml. A
# bare ``ruff check`` applies ruff's much wider default set and is not the
# contract (docs/dev/ci.md, "Lint and type gates").
lint-py: require-install
	$(VENV)/bin/ruff check --select E4,E7,E9,F,I redsim tests

# The flat config lives at the repo root (eslint.config.mjs), scoped to web/
# with basePath, because that is where the ESLint binary is installed. Nothing
# to guard for any more: this runs the real lint. Note that `make lint` runs
# lint-py first, so run this target directly while the Python tree is red.
lint-web: require-install
	pnpm run lint

typecheck: typecheck-py typecheck-web

typecheck-py: require-install
	$(VENV)/bin/mypy redsim

typecheck-web: require-install
	pnpm --filter $(WEB) typecheck

# Full local gate, mirroring the lint/typecheck/test jobs in
# .github/workflows/redsim-ci.yml: ruff with the CI selection, mypy, the
# Python default tier, then the web typecheck and vitest (``typecheck-web``
# and the second line of ``test``). A failing vitest test fails this target.
# deploy-aws.yml does not run it: that workflow only builds images and rolls
# ECS services.
check: lint typecheck test

# Phase B completion gate (docs/plans/12-phase-b-plan.md section 6, register
# TESTS_DOCS-36): scripts/phase_b_gate.sh runs, in order and stopping at the
# first failure, ruff (CI selection), mypy, the default tier, the ml tier, the
# garak tier, the e2e tier (Postgres RLS lane when REDSIM_E2E_POSTGRES_URL is
# set), mkdocs --strict, tests/test_docs_phase_b_consistency.py and, when
# REDSIM_API_URL and REDSIM_API_TOKEN name a running stack (`make up`), the
# HTTP probes plus `redsim audit verify --all` (needs REDSIM_DB_URL). Each
# failure names the spec 26 criterion it fails. `make check` keeps its
# meaning above; this target is the Phase B definition of done. Needs the
# ml, docs and garak extras (`EXTRAS=api,worker,test,dev,ml,docs,garak make
# install`): a missing extra fails its step rather than passing vacuously (the
# garak step fails on pytest exit 5 and on an all-skipped run, since the tree
# carries garak-marked tests). From a git worktree the script puts the checkout
# under test first on PYTHONPATH for the e2e step, because the editable install
# points at the main checkout; from the main checkout nothing is needed.
# `scripts/phase_b_gate.sh --list` prints the steps and their criteria.
check-phase-b:
	@test -x $(PY) || { echo "error: $(VENV) is missing. Run 'make install' first." >&2; exit 1; }
	PY=$(PY) scripts/phase_b_gate.sh
# API-level smoke against a live runtime (remaining-work brief E8):
# health, OIDC discovery, 401 unauthenticated, then the authenticated reads
# and an optional campaign when a token or a demo user is in the environment.
# See scripts/smoke_live.sh for the variables.
smoke-live:
	scripts/smoke_live.sh

# ---------------------------------------------------------------------
# Full stack (docker compose)
# ---------------------------------------------------------------------
#
# deploy/docker-compose.yml brings up postgres, redis, keycloak, minio,
# redsim-api (runs `alembic upgrade head` on start), redsim-worker (-Q scans),
# redsim-worker-default (-Q default), redsim-beat, redsim-web (host port 3300)
# and redsim-log-ingest. Optional profiles: --profile obs, obs-search, policy.
# deploy/Makefile has the finer-grained helpers (seed, psql, logs, rebuild).

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

# Scripted spec-24 demo against a running `make up` stack (no UI): seed the
# bundled models, run the image campaign, verify one finding, download the
# report and verify every audit chain. Reads REDSIM_DEMO_API (default
# http://localhost:8000) and REDSIM_DEMO_TOKEN (default the dev bearer token
# for admin@example.com, so the stack must run with REDSIM_AUTH_MODE=dev).
demo:
	bash scripts/demo.sh

# ---------------------------------------------------------------------
# Docs (MkDocs Material)
# ---------------------------------------------------------------------
#
# Activate the venv before running these targets, or pass an explicit
# MKDOCS=…/bin/mkdocs to override. The recipes call `mkdocs` from the
# current PATH so a project venv must be activated.

MKDOCS ?= mkdocs

docs-serve:
	$(MKDOCS) serve

docs-build:
	$(MKDOCS) build

docs-build-strict:
	$(MKDOCS) build --strict

docs-clean:
	rm -rf site/

.PHONY: install require-install smoke-live \
	dev dev-api dev-web dev-worker \
	test test-cov \
	lint lint-py lint-web \
	typecheck typecheck-py typecheck-web \
	check check-phase-b up down demo \
	docs-serve docs-build docs-build-strict docs-clean
