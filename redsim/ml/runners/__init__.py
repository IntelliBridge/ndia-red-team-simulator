"""Modality runners behind the shared campaign frame (Phase B, MODALITIES-09).

``base`` holds the ``CampaignFrame`` / ``ModalityRunner`` contract and the ``MODALITY_RUNNERS``
registry; ``classification`` is the image and tabular runner (the pre-refactor ``run_campaign``
body). ``text`` and ``detection`` register ``run_text`` and ``run_detection`` by name from their own
tracks. Nothing is imported here so ``import redsim.ml.runners`` stays free of ML libraries; the
frame imports a runner lazily by modality.
"""
