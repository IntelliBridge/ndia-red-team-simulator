"""Pure-Python policy primitives shared across CLI, API, and workers.

Nothing in this package may import Celery, FastAPI, SQLAlchemy, or any
other heavyweight runtime. Pure inputs in, pure outputs out — so the
default ``pytest -q`` install (the ``test`` extra only) can import these
modules without pulling worker-only dependencies.
"""

from redsim.policy.engine import (
    CedarPolicyEngine,
    OPAPolicyEngine,
    PolicyDecision,
    PolicyEngine,
    PolicyRequest,
    StaticPolicyEngine,
    build_request,
    reset_policy_engine,
    resolve_policy_engine,
)

__all__ = [
    "CedarPolicyEngine",
    "OPAPolicyEngine",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyRequest",
    "StaticPolicyEngine",
    "build_request",
    "reset_policy_engine",
    "resolve_policy_engine",
]
