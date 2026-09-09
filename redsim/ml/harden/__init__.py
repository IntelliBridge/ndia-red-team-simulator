"""Training defenses for the verify loop (spec 16.5, 16.6; register ATTACKS_HARDEN-10, -12, -14, -20).

``apply.apply_training_defense(target, defense, ..., config=, sink=, seed=)`` is the
``defense_apply`` stage a verify run executes inside the sandbox child: it re-trains a
deep copy of the target's torch module with a ``kind: training`` catalog defense
(``redsim.ml.defenses.TRAINING_DEFENSES``) over the bundled training slice and returns a
:class:`apply.DerivedTorchTarget` (the derived module behind the ``Target`` protocol) whose
``record`` is the :class:`apply.TrainingRecord` (defense id, resolved params, n_train, epochs
run, wall time, parent and derived weight digests) for provenance; ``apply.train_defense``
returns the bare ``(module, record)`` pair.

* ``adversarial_training``: ART ``AdversarialTrainer`` over a ``PyTorchClassifier`` with
  PGD or FGSM at the campaign's reference eps (``adversarial_training.adversarial_finetune``).
* ``defensive_distillation``: a native torch distillation with a temperature
  (``distillation.distill``); ART's ``DefensiveDistillation`` is the cited reference and is
  not called (it needs probability outputs and has no temperature).

Both are bounded by ``epochs`` / ``train_n`` / ``wall_budget_s``, keep the backbone frozen by
default and are deterministic under the seed. A target without a torch module (the tabular
tree ensembles) is a typed :class:`apply.TrainingUnavailable`, never a fake result. Nothing
here reaches the network: the slice comes from the assets directory or the target itself.
"""

from redsim.ml.harden.apply import (
    DerivedTorchTarget,
    TrainingDefenseUnavailable,
    TrainingOutcome,
    TrainingRecord,
    TrainingUnavailable,
    apply_training_defense,
    assess_training_target,
    distillation_limitation,
    load_train_slice,
    resolve_training_params,
    state_dict_sha256,
    train_defense,
)

__all__ = ["DerivedTorchTarget", "TrainingDefenseUnavailable", "TrainingOutcome", "TrainingRecord",
           "TrainingUnavailable", "apply_training_defense", "assess_training_target", "distillation_limitation",
           "load_train_slice", "resolve_training_params", "state_dict_sha256", "train_defense"]
