# Workstream: ML assets: dataset fetch + bundled model training + manifest

Status: placeholder, work in progress (opened 2026-09-08).

Implements aegis ml build-assets per spec section 11 and 20: fetch the selected aerial-vehicle dataset and CIFAR-10 fixture from the HuggingFace hub, the malicious-URLs sample (Kaggle token required for the full set), train the bundled CNN and the URL classifier on CPU, write assets/MANIFEST.json with dataset ids, revision hashes, weights sha256 and clean metrics. Committed small samples for CI.

Source of truth: docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md.
