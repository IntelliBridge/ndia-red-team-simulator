SHELL := /bin/bash

# Repo-root Makefile. Per-area subcommands live in their own
# Makefiles; this one is a convenience layer + the docs targets that
# don't really belong anywhere else.

# ---------------------------------------------------------------------
# Docs (MkDocs Material — see mkdocs.yml + docs/dev/docs.md)
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

# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------

test:
	pytest -q

test-cov:
	pytest -q --cov=aegis --cov-report=term-missing

lint:
	ruff check aegis tests

typecheck:
	mypy aegis

# Local mirror of the CI gate (lint -> type-check -> tests).
check: lint typecheck test

# ---------------------------------------------------------------------
# Forwards to deploy/ Makefile so `make up` etc. still work from root
# ---------------------------------------------------------------------

up up-obs seed token-for whoami psql logs rebuild down down-clean:
	$(MAKE) -C deploy $@

.PHONY: docs-serve docs-build docs-build-strict docs-clean \
	test test-cov \
	up up-obs seed token-for whoami psql logs rebuild down down-clean
