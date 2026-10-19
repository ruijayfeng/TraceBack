"""GT metadata/provenance tests, exclusively within evaluation."""

import json
from pathlib import Path

import pytest
import yaml

from evaluation.io.ait_ads import load_ait_ads_ground_truth
from app.services.storage import file_digest


def source(root, content):
    base = root / "data/ait_ads"
    path = base / "evaluation/labels.csv"
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")
    (base / "dataset.yaml").write_text(yaml.safe_dump({"scenes": {"fox": {}, "shaw": {}},
        "evaluation": {"official_labels": {"path": "evaluation/labels.csv"}}}), encoding="utf-8")
    return path


def test_temporal_metadata_only_provenance_no_inferred_truth(tmp_path):
    path = source(tmp_path, "scenario,attack,start,end\nfox,synthetic_window,1642993260.1,1642993261.2\n")
    before = file_digest(path)
    report = load_ait_ads_ground_truth(tmp_path)
    assert file_digest(path) == before == report["sha256"]
    assert report["row_count"] == 1 and report["missing_scene_labels"] == ["shaw"]
    row = report["records"][0]
    assert row["dataset_id"] == "ait_ads" and row["scene_id"] == "fox"
    assert row["start_time"] == "2022-01-24T03:01:00.100000Z"
    assert row["attack_label"] == "synthetic_window" and row["attack_stage"] is None
    assert row["time_label"] is None and row["event_label"] is None and row["source"] is None
    assert row["raw_label_reference"]["csv_row"] == 2 and row["raw_label_reference"]["sha256"] == before
    assert report["capabilities"]["temporal_ground_truth"]
    for kind in ("event", "alert", "incident", "correlation_edge", "chain_edge"):
        assert report["capabilities"][kind + "_ground_truth"] is False
    assert "attack_id" not in json.dumps(report) and "alert_ids" not in json.dumps(report)


@pytest.mark.parametrize("body", ["scenario,attack,start,end\nfox,a,NaN,1\n",
    "scenario,attack,start,end\nfox,a,2,1\n", "scenario,attack,start,end\nfox,,1,2\n",
    "scenario,attack,start,end\nfox,a,1,2\nfox,a,1,2\n", "time_label,event_label\nx,y\n"])
def test_invalid_source_never_creates_gt(tmp_path, body):
    source(tmp_path, body)
    with pytest.raises(ValueError):
        load_ait_ads_ground_truth(tmp_path)


def test_missing_official_gt_is_explicit(tmp_path):
    path = source(tmp_path, "scenario,attack,start,end\n")
    path.unlink()
    assert load_ait_ads_ground_truth(tmp_path)["status"] == "missing_ground_truth"


def test_actual_local_official_schema_and_coverage():
    root = Path(__file__).resolve().parents[2]
    report = load_ait_ads_ground_truth(root)
    assert report["columns"] == ["scenario", "attack", "start", "end"]
    assert report["row_count"] == 79 and not report["missing_scene_labels"]
    assert len(report["scenes"]) == 8
