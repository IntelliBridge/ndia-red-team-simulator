"""CI-0 regression: importing ``redsim.state`` must not pull in SQLAlchemy.

The lightweight ``unit`` CI job installs only ``[test,dev]`` — no ``api``/
``worker`` extras, so SQLAlchemy is absent. ``redsim.state.__init__`` exposes
``PostgresRunState`` lazily (PEP 562) so ``from redsim.state import RunState``
(the filesystem backend) keeps working without it. An eager import here would
re-break the unit job's test collection.

Run in a clean subprocess with SQLAlchemy import blocked, so the result does
not depend on whether another test already imported it into ``sys.modules``.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

_PROBE = textwrap.dedent(
    """
    import sys
    import importlib.abc

    class _Block(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path, target=None):
            if name == "sqlalchemy" or name.startswith("sqlalchemy."):
                raise ModuleNotFoundError("sqlalchemy blocked for test")
            return None

    sys.meta_path.insert(0, _Block())

    import redsim.state as state

    assert state.RunState.__name__ == "FilesystemRunState", state.RunState
    assert "sqlalchemy" not in sys.modules, "redsim.state eagerly imported sqlalchemy"

    try:
        state.PostgresRunState
    except ModuleNotFoundError:
        pass
    else:
        raise AssertionError("PostgresRunState should require sqlalchemy")

    print("OK")
    """
)


def test_import_redsim_state_without_sqlalchemy():
    proc = subprocess.run(
        [sys.executable, "-c", _PROBE],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout
