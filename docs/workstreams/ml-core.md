# Workstream: ML core: targets, ART attacks, eps sweep, SHAP, MRI scoring, rules

Status: placeholder, work in progress (opened 2026-09-08).

Implements the pure-Python ML vertical under redsim/ml/ per spec sections 9, 12, 13, 15, 16: bundled image target (spec section 11 dataset, CIFAR-10 CI fixture), tabular URL-classifier target skeleton, FGSM/PGD/noise-control/HopSkipJump adapters + registry, eval/campaign with eps sweep and denominators, MRI scoring with D9 constraints, SHAP image/tabular explainers + stability, interpret/rules/narrative (Pythia). Tests under tests/ml with TinyTarget, no network.

Source of truth: docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md.
