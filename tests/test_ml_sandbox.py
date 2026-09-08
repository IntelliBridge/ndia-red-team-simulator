from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("art")
pytest.importorskip("torch")

from redsim.ml.reporting import render_campaign_reports
from redsim.ml.sandbox import _persist_child_artifacts, run_campaign_sandboxed
from redsim.ml.schema import CampaignConfig, CampaignRecord


class _Sink:
    def __init__(self) -> None:
        self.rows: list[tuple[str, bytes, str]] = []

    def put(
        self,
        name: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> str:
        self.rows.append((name, data, content_type))
        return f"test:{name}"

    def sha256(self, _name: str) -> str:
        return "0" * 64


def _config() -> CampaignConfig:
    detail: dict[str, Any] = {
        "name": "sandbox test model",
        "status": "available",
        "modality": "image",
        "format": "torch_state_dict",
        "architecture_id": "smallcnn",
        "dataset_id": "missing-test-dataset",
        "dataset_split": "test",
        "sha256": "0" * 64,
    }
    return CampaignConfig(
        target_id="sandbox-test-model",
        modality="image",
        attack_ids=["fgsm"],
        eps_grid=[0.03],
        reference_eps=0.03,
        n_samples=10,
        dataset_id="missing-test-dataset",
        target_snapshot={
            "id": "sandbox-test-model",
            "kind": "ml_model_artifact",
            "value": "test",
            "detail": detail,
        },
    )


def test_sandbox_returns_partial_record_when_child_fails(tmp_path: Path) -> None:
    model = tmp_path / "model.pt"
    model.write_bytes(b"PK\x03\x04not-a-model")

    config = _config()
    record = run_campaign_sandboxed(
        config,
        _Sink(),
        target_file=model,
        target_detail=config.target_snapshot["detail"],
    )

    assert record.status == "failed"
    assert record.completeness == "partial"
    assert record.score is None
    assert record.score_status is not None
    assert "ML sandbox exited" in (record.error or "")


def test_sandbox_kills_process_group_when_cancelled(
    monkeypatch: Any,
) -> None:
    real_popen = subprocess.Popen

    def sleeping_child(_argv: list[str], **kwargs: Any) -> subprocess.Popen[str]:
        return real_popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            **kwargs,
        )

    monkeypatch.setattr("redsim.ml.sandbox.subprocess.Popen", sleeping_child)
    record = run_campaign_sandboxed(
        _config(),
        _Sink(),
        is_cancelled=lambda: True,
    )

    assert record.status == "cancelled"
    assert "cancelled while sandbox child" in (record.error or "")


def test_campaign_report_renders_canonical_measurements() -> None:
    fixture = Path(__file__).parent / "ml" / "fixtures" / "run_record.json"
    record = CampaignRecord.model_validate_json(fixture.read_bytes())

    reports = {name: data for name, data, _content_type in render_campaign_reports(record)}

    markdown = reports["report.md"].decode()
    assert "| fgsm | 0.03 |" in markdown
    assert "| Attack | Epsilon | N | Clean correct |" in markdown
    assert json.loads(reports["report.json"])["run_id"] == record.run_id


def test_parent_verifies_and_maps_child_artifacts(tmp_path: Path) -> None:
    work = tmp_path / "work"
    artifact_root = work / "artifacts" / "evidence"
    artifact_root.mkdir(parents=True)
    data = b"trusted evidence"
    (artifact_root / "sample.json").write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    reference = f"sandbox:evidence/sample.json:{digest}"
    (work / "artifacts.json").write_text(json.dumps([{
        "name": "evidence/sample.json",
        "content_type": "application/json",
        "sha256": digest,
        "reference": reference,
    }]))
    sink = _Sink()

    mapping = _persist_child_artifacts(work, sink)

    assert mapping == {reference: "test:evidence/sample.json"}
    assert sink.rows == [
        ("evidence/sample.json", data, "application/json")
    ]