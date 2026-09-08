"""Console output primitives shared by every ``redsim.cli`` command module.

ANSI colour constants, severity colouring, and the ``[*]``/``[!]`` status
writers used to live on ``redsim.cli.main``; the per-command sibling modules
reached back into that entry point (``_main._warn(...)``) purely to reach
them. They now live here so the command modules depend on a small,
purpose-named peer instead of the CLI entry point, and so ``main.py`` can be
narrowed toward "parser + dispatch".
"""

from __future__ import annotations

import sys

_RED = "\033[31m"
_YELLOW = "\033[33m"
_BLUE = "\033[34m"
_GREEN = "\033[32m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

_SEVERITY_COLOR = {
    "critical": _RED,
    "high": _YELLOW,
    "medium": _BLUE,
    "low": "",
}


def _colored_severity(sev: str) -> str:
    color = _SEVERITY_COLOR.get(sev.lower(), "")
    if color:
        return f"{color}{sev.upper()}{_RESET}"
    return sev.upper()


def _info(msg: str) -> None:
    print(f"{_GREEN}[*]{_RESET} {msg}")


def _warn(msg: str) -> None:
    print(f"{_YELLOW}[!]{_RESET} {msg}")


def _err(msg: str) -> None:
    print(f"{_RED}[!]{_RESET} {msg}", file=sys.stderr)
