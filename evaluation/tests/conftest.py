"""Synthetic contract fixtures; no real GT reaches the fixture producer."""

from pathlib import Path
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "backend/tests"))

from test_analysis_service import service, write_input, request_for
from test_wazuh_adapter import synthetic_record
from evaluation.io.snapshot import load_snapshot


@pytest.fixture
def production_snapshot(tmp_path):
    svc = service(tmp_path)
    rows = [synthetic_record(id=f"synthetic-{i}", timestamp=f"2022-01-21T00:00:{i:02d}Z",
                            data={"host": "synthetic-host", "user": f"synthetic-user-{i%2}"}) for i in range(8)]
    path = write_input(tmp_path, rows)
    aid = svc.create(request_for(path), background=False)
    return load_snapshot(tmp_path, aid)


@pytest.fixture
def evaluation_config(tmp_path):
    path = tmp_path / "evaluation/configs/evaluation.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(yaml.safe_dump({"version": "evaluation-v1", "split": "observational_unsplit_no_tuning",
        "noise": {"base_representatives": 2, "ratios": [0, 0.5, 1], "seed": 42}, "limitations": []}), encoding="utf-8")
    return path
