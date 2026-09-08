"""``redsim ml build-assets`` is reachable and reports itself as a skeleton."""

from __future__ import annotations

import importlib
from unittest.mock import patch

import pytest

from redsim.cli.ml import BUILD_ASSETS_STATUS, cmd_ml

# ``redsim.cli`` re-exports the ``main`` function under the same name as the
# module, so resolve the module through importlib.
cli_main = importlib.import_module("redsim.cli.main")


def test_parser_has_ml_build_assets():
    args = cli_main.build_parser().parse_args(["ml", "build-assets", "--only", "cifar10_small_cnn"])
    assert args.command == "ml" and args.ml_action == "build-assets"
    assert args.only == ["cifar10_small_cnn"]
    assert "ml" in cli_main._COMMANDS


def test_ml_requires_an_action():
    with pytest.raises(SystemExit):
        cli_main.build_parser().parse_args(["ml"])


def test_build_assets_reports_not_implemented_and_returns(capsys):
    args = cli_main.build_parser().parse_args(["ml", "build-assets"])
    cmd_ml(args, config=None)  # type: ignore[arg-type]
    out = capsys.readouterr()
    text = out.out + out.err
    assert BUILD_ASSETS_STATUS == "not_implemented"
    assert "not_implemented" in text
    assert "No models or datasets were fetched, trained or written" in text


def test_main_dispatches_ml(tmp_path):
    with patch("redsim.config.load_config", return_value=None), \
            patch("redsim.cli.ml.cmd_ml_build_assets") as body:
        cli_main.main(["ml", "build-assets"])
    body.assert_called_once()
