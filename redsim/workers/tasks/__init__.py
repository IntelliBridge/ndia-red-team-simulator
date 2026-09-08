"""Celery task modules.

Import boundary (intentional): each task here calls back into the
``redsim.services`` execution halves, while the admission services
enqueue these tasks. To break that cycle the admission services import
``redsim.workers.tasks.*`` **function-level** (inside their enqueue
blocks), never at module scope. See the mirror note in
``redsim.services``.
"""
