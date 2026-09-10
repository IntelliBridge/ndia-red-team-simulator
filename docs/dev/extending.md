# Extending redsim

redsim has two extension surfaces. The **platform registry seam** is the
generic `name -> item` table (`redsim.registry.Registry[T]`) that backs the
scanner registry in
[`redsim/scanners/registry.py`](https://github.com/IntelliBridge/ndia-red-team-simulator/blob/main/redsim/scanners/registry.py):
duplicate detection, a structural protocol check, opt-in entry-point
discovery, an allowlist, Ed25519 signatures and an out-of-process sandbox.
The **ML vertical** adds two protocols of its own, `Target` and
`AttackAdapter`, plus explainers and recommendation rules, and
registers into the same seam.

This page says what exists on `main` and what the product spec assigns to the
open ML pull requests (#8 `feat/ml-core`, #9 `feat/ml-assets`). Nothing
described as "PR #8" or "planned" may be presented as working until it merges
(`CLAUDE.md`, working rules).

## What is on `main`

| Piece | Where | State |
|---|---|---|
| `Registry[T]` (register, get, list, entry-point scan, conformance check, allowlist, signatures) | `redsim/registry.py` | exists |
| Scanner registry: `ScannerAdapter` protocol, `ScanOptions`, `ScanResult`, `dispatch`, `KNOWN_CAPABILITIES`, `maybe_load_entry_points`, sandbox wrap | `redsim/scanners/registry.py`, `redsim/scanners/sandbox.py`, `sandbox_worker.py` | exists, **no adapter registered** |
| Plugin discovery report and signing | `redsim/plugins.py`, `redsim/supply_chain/signing.py`, `redsim plugins list|sign` | exists |
| Effect-class gate (`read` / `active` / `external`) | `redsim/effects.py` | exists, unused by any route today |
| `Target` protocol and `Sample` | `redsim/ml/targets/base.py` | exists |
| `AttackAdapter` protocol and `AttackOutput` | `redsim/ml/attacks/base.py` | exists |
| `AttackInfo`, `ParamSpec`, `TargetInfo` and the rest of the evidence schema | `redsim/ml/schema.py` | exists, **frozen by P0** |
| `TinyTarget` test double | `tests/ml/fakes.py` | exists |
| Concrete targets, attack adapters and their registries, `campaign.py`, `eval.py`, `scoring.py`, `datasets/`, explainers, recommendation rules | `redsim/ml/…` | PR #8 / #9, not on `main` |

## The ML protocols

### `Target` (`redsim/ml/targets/base.py`)

A target is a model plus the public dataset slice it is evaluated on.

| Member | Purpose |
|---|---|
| `id: str` | Registry key. |
| `info() -> TargetInfo` | Name, modality, dataset, class names, `status` (`available` or `not_implemented` with a reason). Stubs report `not_implemented` so the UI can show them honestly. |
| `load() -> None` | Load weights and data. Idempotent. Raises `NotImplementedError` for stubs. |
| `sample(n, seed) -> Sample` | Stratified, seeded slice of the evaluation split. `Sample` carries `x` (float32 in [0, 1], NCHW for images), `y`, the source `indices` and `class_names`. |
| `predict_proba(x) -> ndarray` | Class probabilities, shape `(n, n_classes)`. |
| `art_classifier() -> Any` | An ART estimator over the model (`PyTorchClassifier` for images, `SklearnClassifier` / `XGBoostClassifier` for the tabular tree ensemble). |
| `torch_model() -> Any` | The `torch.nn.Module` in eval mode, for SHAP `GradientExplainer`. |
| `manifest() -> dict` | Dataset and weights provenance: names, versions, sha256, training config. |

The spec (section 8.3) assigns the concrete implementations to
`redsim/ml/targets/bundled.py` (bundled catalog and asset manifest reader),
`artifact.py` (ONNX, `state_dict`, `safetensors`, XGBoost-JSON loaders),
`architectures.py` (the in-tree architecture catalog that `state_dict`
uploads must name), `tabular.py`, and `endpoint.py` (Phase B stub). Loaders
are imported **only inside the sandbox child** (section 9). A `Target` that
needs a download must never fetch at import time.

### `AttackAdapter` (`redsim/ml/attacks/base.py`)

Every attack is an adapter over the Adversarial Robustness Toolbox.

| Member | Purpose |
|---|---|
| `id: str` | Registry key and the `attack_id` clients send. |
| `info() -> AttackInfo` | `id`, `name`, `domain` (`image` / `tabular` / `llm`), `family` (`evasion` / `control`), `description`, `params_schema` (a list of `ParamSpec`: name, type, default, min, max, description), `references`. |
| `resolve_params(params) -> dict` | Fill defaults, coerce types, reject out-of-range values with `ValueError` (mapped to HTTP 422 at admission). The worker calls it again before running so a stale client cannot widen a bound. |
| `run(target, x, y, params, seed) -> AttackOutput` | Produce `x_adv`, the mean L∞ and L2 norms, wall time, the resolved params, `library_versions` and free-text `notes`. |

`params_schema` is the single source of parameter bounds: the launcher UI
renders from it, admission validates against it, the worker re-validates.
Attack ids are declarative references to registered, bounded ART adapters.
The repository stores no attack recipes or executable payloads.

Phase A catalog (spec section 12.2), carried by PR #8:

| Adapter id | Modality | ART class | Access |
|---|---|---|---|
| `fgsm` | image | `FastGradientMethod` | white-box |
| `pgd` | image, tabular (via a build-time differentiable surrogate) | `ProjectedGradientDescent` | white-box |
| `hopskipjump` | tabular (image in Phase B) | `HopSkipJump` | black-box |
| `noise_control` | image, tabular | none, adapter-native benign noise at the same ε | control, never creates a Finding |

Phase B rows (`cw_l2`, `deepfool`, `zoo`, text and detection attacks) are
registered only when their adapter, estimator support and tests exist. Until
then `GET /v1/attacks` will not list them and the UI shows the modality as
unavailable with the reason.

### Registration

- Attack adapters register in an instance of `redsim.registry.Registry`
  (`redsim/ml/attacks/registry.py` in PR #8), with duplicate-id detection and
  the protocol check. Third-party attack adapters use the entry-point group
  `redsim.ml.attacks`, gated by `REDSIM_PLUGINS=1` and the same allowlist and
  signature controls as scanner plugins.
- A campaign façade, `CampaignScannerAdapter` (`redsim/ml/campaign.py`,
  `name="ml-campaign"`, `capabilities={"adversarial_ml", "explainability"}`),
  is a built-in `ScannerAdapter` registered in `redsim.scanners.registry`, so
  `list_scanners()`, `GET /v1/scanners`, `dispatch()` and the offline CLI see
  the vertical. `KNOWN_CAPABILITIES` gains `adversarial_ml` and
  `explainability` with it. `POST /v1/scans` is **not** the ML entry point
  and stays unmounted, campaigns start with `POST /v1/models/{id}/attacks`.
- The stage pipeline inside the sandbox child is
  `load_target → sample → clean_eval → attack×eps → control → explain →
  score → interpret → recommend → report`, the `STAGES` tuple in
  `redsim/ml/schema.py`.

### Adding an attack adapter (once PR #8 is in)

1. Write `redsim/ml/attacks/<id>.py` with a class that satisfies
   `AttackAdapter`. Declare every parameter in `params_schema` with bounds
   and a default. Record `library_versions` from ART and torch.
2. Register it in `redsim/ml/attacks/registry.py`. A duplicate id raises at
   import.
3. Add its row to spec section 12.2 (adapter id, ART class, parameters,
   phase) and to the `GET /v1/attacks` fixture.
4. Test it in-process against `tests/ml/fakes.py::TinyTarget` under the `ml`
   marker, with `pytest.importorskip("torch")` at module top so the 3.13 CI
   lane still collects the module.
5. Keep it deterministic for a given seed, and list every nondeterminism
   source in `AttackOutput.notes` so it lands in `Provenance`.

## Explainers and rules

- **Explainers** (`redsim/ml/explain/`, package exists empty on `main`):
  `shap_image.py` (`GradientExplainer` on `Target.torch_model()`),
  `shap_tabular.py` (`TreeExplainer` on the tree ensemble), `stability.py`
  (`expl_shift`, the centre-mass heuristic), `summary.py` (the deterministic
  SHAP text summary that is the only thing the LLM writer receives). Outputs
  are `Observation` records with `metric_kind: "heuristic"` and artifact
  rows. SHAP is supporting evidence, never causal proof.
- **Interpretation and recommendation rules**
  (`redsim/ml/recommend/{interpret,rules,narrative}.py`): deterministic rules
  that cite measurement ids and produce `Interpretation` (`kind: "inferred"`)
  and `CandidateRecommendation` (`status: "candidate"`) records. The Pythia
  writer in `narrative.py` adds prose only, with `narrative_source = "rules"`
  when Pythia is not configured. A recommendation carries `status:
  "candidate"` and nothing more. It may cite ART classes and papers as plain
  text. Nothing is applied to the model. The verify paradigm was removed on
  2026-09-09 (product owner decision, `docs/project-brief.md`).

## The platform registry seam

### `ScannerAdapter` (`redsim/scanners/registry.py`)

| Member | Type | Purpose |
|---|---|---|
| `name` | `str` | Registry key. Used by `dispatch(name, ...)`. |
| `capabilities` | `set[str]` | Capability tags. Drives capability-based dispatch. |
| `default_timeout` | `int` | Fallback timeout in seconds. |
| `adapter_version()` | `-> str` | Version string for the wrapped tool. |
| `health_check()` | `-> bool` | Whether the adapter is usable (for the campaign façade: the `ml` extra imports and the sandbox child launches). |
| `scan(run_state, options)` | `-> ScanResult` | Run and return findings plus metadata. |

`KNOWN_CAPABILITIES` is an open vocabulary: a capability in the set registers
silently, one outside it logs a warning and still registers. Promoting one is
a one-line append. The subprocess helpers `run_cli_scan`, `run_cli_scan_jsonl`,
`cli_version` and `which_available` remain for adapters that wrap a CLI tool.

Findings are Pydantic v2 models (`redsim/schema.py::RedsimFinding`) validated
at construction, so an out-of-vocabulary `severity` raises at the adapter
instead of persisting a malformed row. `from_dict` stays lenient for reads.

### Third-party plugins {#third-party-plugins-marketplace}

A plugin declares an entry point in its own `pyproject.toml`. The group
selects the registry, the value is a zero-arg factory:

```toml
[project.entry-points."redsim.scanners"]
myscanner = "my_pkg:create_scanner"

[project.entry-points."redsim.ml.attacks"]   # once PR #8 lands
myattack = "my_pkg:create_attack"
```

Discovery is **off by default** and per-process: set `REDSIM_PLUGINS=1` on
the API, the worker and the CLI. `pytest` runs without it, so an installed
plugin can never perturb the built-in registry during tests. The seam is
`Registry.maybe_load_entry_points`, called by each package `__init__` after
the built-ins are imported.

#### Allowlist, signatures and sandbox {#security-the-redsim_plugins_allow-allowlist}

Controls, all read on every process that discovers plugins:

| Var | Purpose |
|---|---|
| `REDSIM_PLUGINS` | `1` enables discovery. |
| `REDSIM_PLUGINS_ALLOW` | Comma-separated **distribution** names. Set: only those load, others are `skipped`. Unset: everything loads with a warning. Treat as a production control. |
| `REDSIM_PLUGINS_REQUIRE_SIGNATURE` | `1` requires a valid Ed25519 signature bound to the factory module's source before registration. Unsigned or invalid plugins are `rejected`. |
| `REDSIM_PLUGINS_TRUSTED_KEYS` | `*.pem` public-key files and/or directories. |
| `REDSIM_PLUGINS_SIG_DIR` | Directories holding `<dist>-<version>.sig` files. |
| `REDSIM_PLUGINS_SANDBOX` | Default `1`: plugin `scan()` runs out-of-process (see below). |

A plugin author signs with
`redsim plugins sign --dist <dist> --version <v> --entry-point <group>:<name> --key <ed25519.pem> --out ./signing`.
The trust model and the operator runbook are in
[Supply-chain integrity](../security/supply-chain.md#signed-third-party-plugins).
The upstream example plugin directory is not carried in this fork.

Validation: a plugin whose factory raises, whose object misses the protocol,
or whose `name` is empty is rejected and logged without crashing discovery.
`redsim plugins list [--json]` prints name, kind, distribution, version,
status (`loaded`, `rejected`, `skipped`) and the reason. With discovery off it
prints a hint rather than an empty table.

!!! danger "Loading a plugin runs its code in your process"
    The factory and the module's top-level code run in-process at discovery,
    before the signature check. Only `scan()` is sandboxed. Treat installing a
    plugin as installing any dependency and pin the distributions you trust.

### The plugin sandbox and the ML sandbox

`redsim/scanners/sandbox.py` runs a plugin's `scan()` in a short-lived child
(`python -m redsim.scanners.sandbox_worker --entry-point <ep>`, list argv,
never `shell=True`) with POSIX rlimits, its own process group and a
wall-clock kill, a minimal allowlisted environment that never carries the
parent's secrets, and a private fd result channel. It is process isolation,
not a network or filesystem jail.

The ML vertical builds `redsim/ml/sandbox.py` and `sandbox_worker.py` on the
same primitives with deliberate differences (spec section 9.4): the child
imports only in-tree `redsim.ml` code and the untrusted input is the model
file, there is no in-process path for model bytes and no network switch, the
parent populates a per-job work directory with the digest-checked model file
and the evaluation slice, and every list element of the child's envelope is
re-validated with its Pydantic model before anything is persisted. Bundled
models take the same path on every run. These files are not on `main` yet.

## Effect classes

`redsim/effects.py` classifies an action as `read`, `active` or `external`
and drives the approver gate (`requires_approval`). It was written for the
pentest agents and tools ([ADR 0004](../adr/0004-unified-effect-class-gate.md))
and no mounted route consults it today. The ML routes gate on the `Action`
members in `redsim/api/policy.py` instead. No route applies anything to a
model.
