"""Defensive distillation as a native torch fine-tune (spec 16.6; register ATTACKS_HARDEN-14).

Papernot et al. 2016: the teacher is a frozen copy of the parent; its logits at temperature
``T`` give soft labels ``softmax(teacher / T)``; the student, the same architecture
initialised from the teacher, minimises ``KL(softmax(student / T) || soft) * T^2`` and is then
used at ``T = 1`` (plain logits). ART's ``DefensiveDistillation`` is the cited reference and is
not called: it requires both classifiers to return probabilities (the bundled models return
logits) and has no temperature parameter (verified against art 1.20.1).

Budget and policy match the adversarial trainer: ``backbone_frozen`` trains only the head in
eval mode, the wall budget is checked after every epoch, torch's generator is seeded so the
batch order is reproducible.
"""

from __future__ import annotations

import copy
from typing import Any

import numpy as np

from redsim.ml.defenses import DISTILLATION_ART_NOTE
from redsim.ml.harden.apply import Clock, Log, TrainingOutcome, _now, seed_everything, select_trainable

LOSS_KIND = "mean distillation loss KL(softmax(student/T) || softmax(teacher/T)) * T^2 over the epoch's batches"


def distill(module: Any, x: np.ndarray, y: np.ndarray, *, temperature: float, epochs: int, batch_size: int,
            lr: float, backbone_frozen: bool, wall_budget_s: float, seed: int, log: Log | None = None,
            clock: Clock = _now) -> TrainingOutcome:
    """Distil ``module`` in place from a frozen copy of itself on ``x`` (float32 [0, 1]); ``y`` is unused by the
    loss (the student learns the teacher's soft labels) and kept for the caller's k/n accounting."""
    import torch
    import torch.nn.functional as functional

    if temperature <= 0.0:
        raise ValueError("temperature must be positive")
    if epochs < 1:
        raise ValueError("epochs must be at least 1")
    seed_everything(int(seed))
    say: Log = log if log is not None else (lambda _line: None)
    temp = float(temperature)

    x_t = torch.from_numpy(np.ascontiguousarray(np.asarray(x, dtype=np.float32)))
    n = int(x_t.shape[0])
    teacher = copy.deepcopy(module).eval()
    for p in teacher.parameters():
        p.requires_grad_(False)
    with torch.no_grad():
        soft = torch.cat([torch.softmax(teacher(x_t[s:s + batch_size]) / temp, dim=1)
                          for s in range(0, n, int(batch_size))], dim=0)

    trainable, n_total, n_trainable = select_trainable(module, backbone_frozen)
    training_mode = not backbone_frozen
    module.train(training_mode)
    optimizer = torch.optim.Adam([p for p in module.parameters() if p.requires_grad], lr=float(lr))
    gen = torch.Generator().manual_seed(int(seed))

    losses: list[float] = []
    epochs_run = 0
    exhausted = False
    t0 = clock()
    elapsed = 0.0
    for _ in range(int(epochs)):
        perm = torch.randperm(n, generator=gen)
        total = 0.0
        for s in range(0, n, int(batch_size)):
            idx = perm[s:s + int(batch_size)]
            logits = module(x_t[idx])
            loss = functional.kl_div(functional.log_softmax(logits / temp, dim=1), soft[idx],
                                     reduction="batchmean") * (temp * temp)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total += float(loss.detach()) * int(idx.shape[0])
        epochs_run += 1
        mean_loss = total / max(1, n)
        losses.append(mean_loss)
        elapsed = clock() - t0
        say(f"defense_apply defensive_distillation: epoch {epochs_run}/{epochs} loss {mean_loss:.4f} "
            f"wall {elapsed:.1f}s/{wall_budget_s:.0f}s")
        if elapsed >= float(wall_budget_s) and epochs_run < int(epochs):
            exhausted = True
            say(f"defense_apply defensive_distillation: wall budget reached after {epochs_run} of {epochs} epochs")
            break
    module.eval()
    notes = [f"teacher = frozen copy of the parent; soft labels softmax(teacher / {temp:g}); student evaluated at T = 1",
             DISTILLATION_ART_NOTE,
             "training_mode=False: normalisation statistics and dropout fixed" if backbone_frozen
             else "training_mode=True: every parameter and normalisation statistic trains"]
    return TrainingOutcome(module=module, epochs_run=epochs_run, budget_exhausted=exhausted,
                           wall_time_s=float(elapsed), train_loss_per_epoch=losses, train_loss_kind=LOSS_KIND,
                           trainable_modules=trainable, n_params_total=n_total, n_params_trainable=n_trainable,
                           training_mode="eval (normalisation statistics frozen)" if backbone_frozen else "train",
                           temperature=temp, notes=notes)


__all__ = ["LOSS_KIND", "distill"]
