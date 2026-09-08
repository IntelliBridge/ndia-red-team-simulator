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


@pytest.fixture(autouse=True)
def _no_developer_env_file(monkeypatch: pytest.MonkeyPatch, tmp_path):
    """Keep every ML test away from a developer's real repo-root ``.env``.

    ``redsim.llm.pythia`` discovers ``REDSIM_ENV_FILE``, then ``./.env``, then the
    repo-root ``.env``. Point the explicit override at an absent file and the
    repo-root fallback at ``tmp_path`` so credentials never leak into a test and
    "Pythia is not configured" assertions hold on any checkout.
    """
    monkeypatch.setenv(pythia.ENV_FILE_VAR, str(tmp_path / "absent.env"))
    monkeypatch.setattr(pythia, "_REPO_ROOT", tmp_path)
