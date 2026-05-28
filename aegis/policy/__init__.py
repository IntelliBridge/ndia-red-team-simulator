"""Pure-Python policy primitives shared across CLI, API, and workers.

Nothing in this package may import Celery, FastAPI, SQLAlchemy, or any
other heavyweight runtime. Pure inputs in, pure outputs out — so the
default ``pytest -q`` install (the ``test`` extra only) can import these
modules without pulling worker-only dependencies.
"""

from aegis.policy.ci_gate import CIGatePolicy, evaluate

__all__ = ["CIGatePolicy", "evaluate"]
