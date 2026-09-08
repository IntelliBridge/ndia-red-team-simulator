"""Shared fixtures for the ML test tier."""

from __future__ import annotations

import pytest

from redsim.llm import pythia


@pytest.fixture
def no_kaggle(monkeypatch: pytest.MonkeyPatch, tmp_path):
    """No Kaggle credentials in the environment and no .env file in reach.

    ``REDSIM_ENV_FILE`` naming an absent file stops the ``./.env`` and
    repo-root fallbacks, so a developer's real token never reaches a test.
    """
    for key in ("KAGGLE_API_TOKEN", "KAGGLE_USERNAME", "KAGGLE_KEY"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv(pythia.ENV_FILE_VAR, str(tmp_path / "absent.env"))
    monkeypatch.setattr(pythia, "_REPO_ROOT", tmp_path)
    return tmp_path
