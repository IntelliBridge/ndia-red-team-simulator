"""Redsim FastAPI service.

The API never embeds business logic — every route delegates to a function
in ``redsim.services``. The service layer is the single source of truth
across CLI, API, and Celery workers.
"""

from redsim.api.app import create_app

__all__ = ["create_app"]
