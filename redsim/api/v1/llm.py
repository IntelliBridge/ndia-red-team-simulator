"""Phase B LLM probe routes (spec 17.4 garak through Pythia), mounted as truthful ``501`` stubs.

Wave B0 of ``docs/plans/12-phase-b-plan.md`` mounts the LLM surface so the tree
is honest about it before the ``llm-core`` and ``llm-api`` tracks of wave B2
build it. Each handler runs the gates its real handler will run (``404`` for
an unknown model, ``403`` for a non-member or an under-ranked role) and only
then answers ``501 not_implemented`` with ``phase`` and a ``reason``. Nothing
is faked: no probe runs, no scorecard is invented, no Pythia call is made.

* ``GET /v1/llm/probes``: the committed ``redsim-core`` probe catalog
  (authenticated).
* ``POST /v1/models/{model_id}/probes``: a probe run against an LLM target
  (membership on the target's project, gate ``llm.probe.run``).
* ``GET /v1/runs/{run_id}/llm-scorecard``: the k/n probe scorecard of a run,
  never an MRI (membership).

Nothing here imports garak, an OpenAI client or any ML library.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import NOT_FOUND, api_error
from redsim.api.policy import Action, check, ensure_project_access, ensure_run_access
from redsim.api.v1.integrations import not_built, phase_b_action

router = APIRouter(tags=["ml-llm"])

_ML_KINDS = frozenset({"ml_model_artifact", "ml_model_endpoint"})


# ``Action.LLM_PROBE_RUN`` ("llm.probe.run", remediator) is added by the
# actions-and-codes track of the same wave (register LLM-25) and is the gate in
# force once both tracks are on the tree. Resolved by name so this module also
# imports on a tree where ``policy.py`` lags; the stand-in is then ``attack.run``
# (scanner tier), the gate LLM-25 names for the no-enum-change case.
LLM_PROBE_RUN: Action = phase_b_action("LLM_PROBE_RUN", Action.ATTACK_RUN)


def _target_project(model_id: str) -> str:
    """The project of an ML ``Target`` row; ``404 not_found`` for anything else."""
    from redsim.db.models import Target
    from redsim.db.session import get_session

    with get_session() as sess:
        target = sess.get(Target, model_id)
        if target is None or target.kind not in _ML_KINDS:
            raise api_error(NOT_FOUND, "model not found")
        return str(target.project_id)


@router.get("/llm/probes")
def list_probes(_user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """The offline ``redsim-core`` probe set (spec 11.6): authenticated, then 501."""
    raise not_built("the LLM probe catalog is not implemented", wave="B2", track="llm-api")


@router.post("/models/{model_id}/probes", status_code=status.HTTP_202_ACCEPTED)
def start_probe_run(model_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """A garak probe run through Pythia (spec 17.4): 404, membership, ``llm.probe.run``, then 501."""
    project_id = _target_project(model_id)
    ensure_project_access(user, project_id)
    check(user, LLM_PROBE_RUN, project_id)
    raise not_built("LLM probe runs (garak through Pythia) are not implemented", wave="B2", track="llm-api")


@router.get("/runs/{run_id}/llm-scorecard")
def llm_scorecard(run_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """The k/n probe scorecard of a run, never an MRI (spec 15.9): membership, then 501."""
    ensure_run_access(user, run_id)
    raise not_built("the LLM probe scorecard is not implemented", wave="B2", track="llm-api")
