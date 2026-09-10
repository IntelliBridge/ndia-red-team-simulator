"""Register and scan open-weights Hugging Face models through the real upload path.

Runs the e2e harness (real API, real admission, eager Celery, the real sandbox
child, one sqlite database) against a built ``assets/`` tree and the model files
downloaded by ``scripts/hf_open_weights_fetch.sh``. Nothing here is a test double:
the same route, worker task, loader and campaign code the deployed stack runs.

    REDSIM_ML_ASSETS_DIR=assets .venv/bin/python scripts/hf_open_weights_demo.py \
        --models assets/hf --out assets/hf/runs

Writes, per model, the registration answer, the validated record, the campaign
record, the Markdown report and the audit verification into ``--out``. Prints a
short table. Exit status 1 when a model that should validate did not, or a
campaign did not succeed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

LICENSES = {
    "SamAdamDay_resnet18_cifar10": "MIT (model card, huggingface.co/SamAdamDay/resnet18_cifar10)",
    "FredMell_resnet18-cifar10": "Apache-2.0 (model card, huggingface.co/FredMell/resnet18-cifar10)",
    "ketiswp_mlcommons-ResNet8-CIFAR10-fp32-onnx": (
        "Apache-2.0 (model card, huggingface.co/ketiswp/mlcommons-ResNet8-CIFAR10-fp32-onnx)"),
    "edadaltocg_resnet18_cifar10": "MIT (model card, huggingface.co/edadaltocg/resnet18_cifar10)",
}

#: What each checkpoint was trained on, read from its model card / config.json, never guessed.
MODELS: list[dict[str, Any]] = [
    {
        "dir": "SamAdamDay_resnet18_cifar10", "file": "model.safetensors",
        "declared_format": "safetensors_state_dict", "architecture_id": "resnet18",
        "fields": {"input_resize": "224", "input_mean": "0.49139968,0.4821582,0.44653124",
                   "input_std": "0.24703233,0.24348505,0.26158768"},
        "expect": "available",
    },
    {
        "dir": "FredMell_resnet18-cifar10", "file": "model.safetensors",
        "declared_format": "safetensors_state_dict", "architecture_id": "resnet18",
        "fields": {"input_resize": "224", "input_mean": "0.485,0.456,0.406", "input_std": "0.229,0.224,0.225"},
        "expect": "available",
    },
    {
        "dir": "ketiswp_mlcommons-ResNet8-CIFAR10-fp32-onnx", "file": "model.onnx",
        "declared_format": "onnx", "architecture_id": None,
        "fields": {"input_scale": "255"},
        "expect": "available",
    },
    {
        # The negative row: a ``pytorch_model.bin`` (torch.save archive) of the CIFAR variant of ResNet-18,
        # whose 3x3 stem does not fit the catalog architecture. Whatever the pipeline answers is recorded.
        "dir": "edadaltocg_resnet18_cifar10", "file": "pytorch_model.bin",
        "declared_format": "torch_state_dict", "architecture_id": "resnet18",
        "fields": {"input_mean": "0.4914,0.4822,0.4465", "input_std": "0.2023,0.1994,0.201"},
        "expect": "refused",
    },
]

CIFAR10 = "hf:uoft-cs/cifar10"


def _campaign_body(n_samples: int) -> dict[str, Any]:
    return {
        "attack_ids": ["fgsm", "pgd"],
        "attack_params": {"pgd": {"max_iter": 10}},
        "eps_grid": [0.01, 0.03, 0.1],
        "reference_eps": 0.03,
        "n_samples": n_samples,
        "seed": 0,
        "explain_k": 2,
        "include_control": True,
        "llm_narrative": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--models", type=Path, default=REPO / "assets" / "hf")
    parser.add_argument("--assets", type=Path, default=Path(os.environ.get("REDSIM_ML_ASSETS_DIR", REPO / "assets")))
    parser.add_argument("--out", type=Path, default=REPO / "assets" / "hf" / "runs")
    parser.add_argument("--n-samples", type=int, default=100)
    parser.add_argument("--only", action="append", default=[], help="model directory name(s) to run")
    parser.add_argument("--no-campaign", action="store_true")
    args = parser.parse_args()

    import pytest

    from tests.e2e import harness as h

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out = args.out / stamp
    out.mkdir(parents=True, exist_ok=True)
    harness_dir = out / "harness"
    harness_dir.mkdir()

    mp = pytest.MonkeyPatch()
    mp.setenv(h.E2E_ENV, "1")
    h.sanitize_environment(mp, harness_dir)
    mp.setenv("REDSIM_ML_ASSETS_DIR", str(args.assets.resolve()))
    mp.setenv("REDSIM_ML_SANDBOX_TIMEOUT_S", os.environ.get("REDSIM_ML_SANDBOX_TIMEOUT_S", "3600"))
    mp.setenv("REDSIM_ML_SANDBOX_CPU_SECONDS", os.environ.get("REDSIM_ML_SANDBOX_CPU_SECONDS", "36000"))
    mp.setenv("REDSIM_ML_SANDBOX_MEMORY_MB", os.environ.get("REDSIM_ML_SANDBOX_MEMORY_MB", "12288"))
    mp.setenv("REDSIM_ML_SANDBOX_THREADS", os.environ.get("REDSIM_ML_SANDBOX_THREADS", str(os.cpu_count() or 4)))
    h.unload_bundled_targets()
    app = h.build_harness(mp, harness_dir, assets_dir=args.assets.resolve(), sandbox_mode="child")
    org = h.seed_org(app)
    remediator = org.client("remediator")
    scanner = org.client("scanner")
    admin = org.client("admin")           # ``audit.verify`` is an admin action

    rows: list[dict[str, Any]] = []
    failures = 0
    for spec in MODELS:
        if args.only and spec["dir"] not in args.only:
            continue
        path = args.models / spec["dir"] / spec["file"]
        if not path.is_file():
            print(f"skip {spec['dir']}: {path} is not present (run scripts/hf_open_weights_fetch.sh)")
            continue
        model_out = out / spec["dir"]
        model_out.mkdir()
        fields = {
            "source": "upload", "project_id": org.project_id, "name": spec["dir"].replace("_", "/", 1),
            "declared_format": spec["declared_format"], "modality": "image",
            "license_statement": LICENSES[spec["dir"]], "dataset_id": CIFAR10, "dataset_split": "test",
            **({"architecture_id": spec["architecture_id"]} if spec["architecture_id"] else {}),
            **spec["fields"],
        }
        t0 = time.monotonic()
        response = remediator.post("/v1/models", data=fields,
                                   files={"file": (spec["file"], path.read_bytes(), "application/octet-stream")})
        (model_out / "register.json").write_text(json.dumps(
            {"status_code": response.status_code, "fields": {k: v for k, v in fields.items()}, "body": response.json()},
            indent=2))
        row: dict[str, Any] = {"model": spec["dir"], "register": response.status_code, "expect": spec["expect"]}
        if response.status_code != 201:
            row["status"] = f"refused at the API: {response.json().get('detail', {}).get('code')}"
            row["ok"] = spec["expect"] == "refused"
            rows.append(row)
            failures += 0 if row["ok"] else 1
            print(json.dumps(row))
            continue
        model_id = str(response.json()["id"])
        record = h.model_record(remediator, model_id)
        (model_out / "model.json").write_text(json.dumps(record, indent=2))
        manifest = record.get("manifest") or {}
        validation = record.get("validation") or {}
        row.update({
            "model_id": model_id, "status": record.get("status"), "gradients": manifest.get("gradients"),
            "format": manifest.get("format"), "state_dict_layout": manifest.get("state_dict_layout"),
            "input_layout": (manifest.get("onnx") or {}).get("input_layout"),
            "clean_accuracy": validation.get("clean_accuracy", manifest.get("clean_accuracy")),
            "refusal_reason": validation.get("refusal_reason") or record.get("refusal_reason"),
            "validate_s": round(time.monotonic() - t0, 1),
        })
        row["ok"] = record.get("status") == spec["expect"]
        if not row["ok"]:
            failures += 1
        if record.get("status") == "available" and not args.no_campaign:
            t1 = time.monotonic()
            try:
                result = h.run_campaign_via_api(scanner, model_id, _campaign_body(args.n_samples),
                                                project_id=org.project_id, timeout_s=3600.0)
            except h.CampaignLaunchRefused as exc:
                row["campaign"] = f"refused: {exc.detail}"
                failures += 1
                rows.append(row)
                print(json.dumps(row, default=str))
                continue
            row["campaign"] = result.status
            row["run_id"] = result.run_id
            row["campaign_s"] = round(time.monotonic() - t1, 1)
            (model_out / "run.json").write_text(json.dumps(result.run, indent=2, default=str))
            if result.campaign is not None:
                (model_out / "campaign.json").write_text(json.dumps(result.campaign, indent=2, default=str))
                score = result.campaign.get("score") or {}
                row["mri"] = score.get("mri")
                row["grade"] = score.get("grade")
                row["subscores"] = score.get("subscores")
                row["score_status"] = result.campaign.get("score_status")
                row["findings"] = len(result.findings)
                clean = [m for m in result.campaign.get("measurements", []) if m.get("family") == "clean"]
                row["clean_accuracy_campaign"] = clean[0].get("accuracy") if clean else None
            else:
                row["campaign_error"] = result.campaign_error
            for fmt in ("md", "json"):
                report = scanner.get(f"/v1/runs/{result.run_id}/report.{fmt}")
                if report.status_code == 200:
                    (model_out / f"report.{fmt}").write_bytes(report.content)
            audit = admin.get(f"/v1/audit/verify?run={result.run_id}")
            (model_out / "audit_verify.json").write_text(audit.text)
            row["audit_verify"] = audit.status_code
            if result.status != "succeeded":
                failures += 1
        rows.append(row)
        print(json.dumps(row, default=str))

    (out / "summary.json").write_text(json.dumps(rows, indent=2, default=str))
    print(f"\nwrote {out}")
    app.close()
    mp.undo()
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
