"""Adversarial fine-tuning with ART's ``AdversarialTrainer`` (spec 16.6; register ATTACKS_HARDEN-12).

The module is wrapped in a training ``PyTorchClassifier`` (cross-entropy, Adam over the
trainable parameters, clip values [0, 1]); the inner attack is ``ProjectedGradientDescent``
(``pgd_iters`` steps, ``eps_step = eps_step_ratio * eps``, no random restarts) or
``FastGradientMethod`` when ``pgd_iters`` is 0, in the campaign norm at ``eps``. ART crafts
fresh adversarial rows for ``ratio`` of every batch on the model as it trains (the attack's
estimator is the training classifier, so nothing is precomputed on stale weights).

``AdversarialTrainerMadryPGD`` is not used: its defaults (eps 8, eps_step 2, 205 epochs) are
on the 0-255 scale and it exposes no budget; ``AdversarialTrainer`` is driven one epoch at a
time so the wall budget is checked after every epoch and the epochs run are recorded.

With ``backbone_frozen`` the classifier fits in eval mode (``training_mode=False``): dropout
is off and normalisation statistics stay those of the parent, so only the head's weights
move. Determinism: numpy's global RNG (ART's shuffles and adversarial-row choice) and torch
are seeded from ``seed``; PGD runs without random init; everything is CPU float32.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from redsim.ml.harden.apply import (
    Clock,
    Log,
    TrainingOutcome,
    _now,
    mean_cross_entropy,
    n_classes,
    one_hot,
    seed_everything,
    select_trainable,
)

LOSS_KIND = "mean clean cross-entropy over the training slice after each epoch (eval mode)"
CPU_NOTE = "CPU float32 training; results may differ across BLAS builds and thread counts"


def adversarial_finetune(module: Any, x: np.ndarray, y: np.ndarray, *, eps: float, norm: str, pgd_iters: int,
                         eps_step_ratio: float, ratio: float, epochs: int, batch_size: int, lr: float,
                         backbone_frozen: bool, wall_budget_s: float, seed: int, log: Log | None = None,
                         clock: Clock = _now) -> TrainingOutcome:
    """Adversarially fine-tune ``module`` in place on ``(x, y)`` (float32 [0, 1], int labels)."""
    import torch
    from art.attacks.evasion import FastGradientMethod, ProjectedGradientDescent
    from art.defences.trainer import AdversarialTrainer
    from art.estimators.classification import PyTorchClassifier
    from torch import nn

    if eps <= 0.0:
        raise ValueError("eps must be positive")
    if epochs < 1:
        raise ValueError("epochs must be at least 1")
    seed_everything(int(seed))
    say: Log = log if log is not None else (lambda _line: None)

    x = np.ascontiguousarray(np.asarray(x, dtype=np.float32))
    k = n_classes(module, x)
    trainable, n_total, n_trainable = select_trainable(module, backbone_frozen)
    training_mode = not backbone_frozen
    module.train(training_mode)
    optimizer = torch.optim.Adam([p for p in module.parameters() if p.requires_grad], lr=float(lr))
    clf = PyTorchClassifier(model=module, loss=nn.CrossEntropyLoss(), optimizer=optimizer,
                            input_shape=tuple(int(d) for d in x.shape[1:]), nb_classes=k, clip_values=(0.0, 1.0),
                            device_type="cpu")
    art_norm: float | int = np.inf if norm == "linf" else 2
    inner: dict[str, Any]
    if pgd_iters == 0:
        attack: Any = FastGradientMethod(estimator=clf, norm=art_norm, eps=float(eps), eps_step=float(eps),
                                         targeted=False, num_random_init=0, batch_size=int(batch_size),
                                         minimal=False)
        inner = {"id": "fgsm", "art_class": "art.attacks.evasion.FastGradientMethod", "eps": float(eps),
                 "eps_step": float(eps), "max_iter": 1, "norm": norm, "num_random_init": 0, "ratio": float(ratio)}
    else:
        step = float(eps_step_ratio) * float(eps)
        attack = ProjectedGradientDescent(estimator=clf, norm=art_norm, eps=float(eps), eps_step=step,
                                          max_iter=int(pgd_iters), num_random_init=0, targeted=False,
                                          batch_size=int(batch_size), verbose=False)
        inner = {"id": "pgd", "art_class": "art.attacks.evasion.ProjectedGradientDescent", "eps": float(eps),
                 "eps_step": step, "max_iter": int(pgd_iters), "norm": norm, "num_random_init": 0,
                 "ratio": float(ratio)}
    trainer = AdversarialTrainer(clf, attack, ratio=float(ratio))
    y_onehot = one_hot(y, k)

    losses: list[float] = []
    epochs_run = 0
    exhausted = False
    t0 = clock()
    elapsed = 0.0
    for _ in range(int(epochs)):
        trainer.fit(x, y_onehot, batch_size=int(batch_size), nb_epochs=1, training_mode=training_mode)
        epochs_run += 1
        loss = mean_cross_entropy(module, x, y, int(batch_size))
        losses.append(loss)
        elapsed = clock() - t0
        say(f"defense_apply adversarial_training: epoch {epochs_run}/{epochs} clean-loss {loss:.4f} "
            f"wall {elapsed:.1f}s/{wall_budget_s:.0f}s")
        if elapsed >= float(wall_budget_s) and epochs_run < int(epochs):
            exhausted = True
            say(f"defense_apply adversarial_training: wall budget reached after {epochs_run} of {epochs} epochs")
            break
    module.eval()
    notes = [f"inner attack {inner['id']} at eps {eps:g} ({norm}), ratio {ratio:g} of every batch adversarial",
             "fresh adversarial rows crafted on the training classifier every batch (ART AdversarialTrainer)",
             "training_mode=False: normalisation statistics and dropout fixed" if backbone_frozen
             else "training_mode=True: every parameter and normalisation statistic trains", CPU_NOTE]
    return TrainingOutcome(module=module, epochs_run=epochs_run, budget_exhausted=exhausted,
                           wall_time_s=float(elapsed), train_loss_per_epoch=losses, train_loss_kind=LOSS_KIND,
                           trainable_modules=trainable, n_params_total=n_total, n_params_trainable=n_trainable,
                           training_mode="eval (normalisation statistics frozen)" if backbone_frozen else "train",
                           inner_attack=inner, notes=notes)


__all__ = ["CPU_NOTE", "LOSS_KIND", "adversarial_finetune"]
