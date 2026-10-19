import json
from pathlib import Path
import shutil

import pytest

from app.models import EvaluationSummaryExport
from app.services.queries import QueryService
from evaluation.framework.runner import evaluate, load_evaluation_config
from evaluation.io.snapshot import load_snapshot, protect_output


def test_full_evaluation_temporal_context_no_fake_quality_and_api_export(production_snapshot,evaluation_config,tmp_path,monkeypatch):
    s = production_snapshot
    gt = tmp_path/"labels.csv"
    gt.write_text("scenario,attack,start,end\ns,synthetic-window,1642723200,1642723204\n",encoding="utf-8")
    digest = gt.read_bytes()
    import evaluation.framework.runner as runner
    original_loader = runner.load_windows
    def guarded_loader(*args):
        destination = Path(args[0]).parent/"outputs/evaluation"/s.record.analysis_id
        assert (destination/"prediction_freeze.json").is_file()
        assert (destination/"noise_predictions.json").is_file()
        return original_loader(*args)
    monkeypatch.setattr(runner,"load_windows",guarded_loader)
    summary = evaluate(tmp_path,s.record.analysis_id,gt,"s",config_path=evaluation_config)
    d = tmp_path/"outputs/evaluation"/s.record.analysis_id
    metrics = json.loads((d/"metrics.json").read_text(encoding="utf-8"))
    assert metrics["precision"] is None and metrics["metric_status"]["precision"] == "unavailable"
    mapping = json.loads((d/"ground_truth_mapping.json").read_text(encoding="utf-8"))
    assert mapping["temporal_overlap_alert_count"] == 4 and mapping["quality_evaluation_coverage"] == 0
    assert gt.read_bytes() == digest
    assert (d/"TASK_06_EVALUATION_REPORT.md").exists()
    export = EvaluationSummaryExport.model_validate_json((tmp_path/"data/processed/evaluation_exports"/(summary["run_id"]+".json")).read_text(encoding="utf-8"))
    assert export.evaluation_coverage == 0
    assert QueryService(tmp_path).evaluation(s.record.analysis_id,summary["run_id"])
    assert "synthetic-window" not in export.model_dump_json() and "1642723200" not in export.model_dump_json()
    s.assert_unchanged()
    repeated = evaluate(tmp_path,s.record.analysis_id,gt,"s",config_path=evaluation_config)
    assert repeated["run_id"] == summary["run_id"]
    assert repeated["prediction_before_gt"] == summary["prediction_before_gt"]
    relocated = tmp_path.parent/(tmp_path.name+"_relocated")
    shutil.copytree(tmp_path,relocated)
    moved = evaluate(relocated,s.record.analysis_id,relocated/"labels.csv","s",config_path=relocated/"evaluation/configs/evaluation.yaml")
    assert moved["run_id"] == summary["run_id"]
    assert moved["prediction_before_gt"] == summary["prediction_before_gt"]


def test_incomplete_snapshot_rejected_before_gt(production_snapshot,tmp_path):
    s = production_snapshot
    p = s.store.domain/"analysis.json"
    value = json.loads(p.read_text(encoding="utf-8"))
    value.update(status="incomplete",is_complete=False,incomplete_reason="synthetic_resource_truncation",errors=["synthetic_resource_truncation"])
    p.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        load_snapshot(tmp_path,s.record.analysis_id)


def test_output_paths_cannot_overwrite_production(tmp_path):
    with pytest.raises(ValueError):
        protect_output(tmp_path,tmp_path/"data/processed",tmp_path/"labels.csv")


def test_unknown_evaluation_config_rejected(evaluation_config):
    import yaml
    cfg = yaml.safe_load(evaluation_config.read_text())
    cfg["production_threshold"] = .1
    evaluation_config.write_text(yaml.safe_dump(cfg))
    with pytest.raises(ValueError):
        load_evaluation_config(evaluation_config)
