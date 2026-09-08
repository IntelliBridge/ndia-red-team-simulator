SHELL := /bin/bash

# Repo-root Makefile for redsim: the Python package in redsim/ plus the
# Next.js app in web/ (@redsim/web), joined by pnpm-workspace.yaml.
#
# Recipes invoke the venv interpreter by path instead of assuming an
# activated shell, so `make dev` works from a clean terminal.

VENV ?= .venv
PY   := $(VENV)/bin/python
WEB  := @redsim/web

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
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"
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
# Services run under `$(MAKE) -j` so that adding the FastAPI server, once
# redsim/api exposes a real app, is a new dev-api target plus one word on
# the -j line. Make forwards Ctrl-C to every child.

dev: require-install
	$(PY) -m pytest -q
	@echo "==> web: http://localhost:3000"
	$(MAKE) -j dev-web

dev-web: require-install
	pnpm --filter $(WEB) dev

# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------

test: require-install
	$(PY) -m pytest -q
	pnpm --filter $(WEB) test

test-cov: require-install
	$(PY) -m pytest -q --cov=redsim --cov-report=term-missing

lint: lint-py lint-web

lint-py: require-install
	$(VENV)/bin/ruff check redsim tests

lint-web: require-install
	pnpm --filter $(WEB) lint

typecheck: typecheck-py typecheck-web

typecheck-py: require-install
	$(VENV)/bin/mypy redsim

typecheck-web: require-install
	pnpm --filter $(WEB) typecheck

# Full local gate. Nothing in CI runs it: .github/workflows/deploy-aws.yml
# only builds images and rolls ECS services.
check: lint typecheck test

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

.PHONY: install require-install \
	dev dev-web \
	test test-cov \
	lint lint-py lint-web \
	typecheck typecheck-py typecheck-web \
	check \
	docs-serve docs-build docs-build-strict docs-clean
