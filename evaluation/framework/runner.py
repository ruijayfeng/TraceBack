"""python -m evaluation.framework.runner --root ... --analysis-id ... --gt ..."""

import argparse
from collections import Counter
import json
from pathlib import Path
import platform
import sys
import time

import yaml

from app.correlation.edges import peak_memory_mb
from app.models import EvaluationSummaryExport
from app.services.storage import file_digest
from app.utils.stable_id import content_digest
from evaluation.ablation.experiments import run_ablation
from evaluation.baselines.methods import baseline_counts
from evaluation.io.diagnostics import extract_scores, score_distribution
from evaluation.io.ground_truth import load_windows, map_windows
from evaluation.io.snapshot import load_snapshot, protect_output
from evaluation.metrics.classification import unavailable_quality
from evaluation.metrics.structure import structural_metrics
from evaluation.robustness.experiments import NoiseConfig, run_noise
from evaluation.sensitivity.experiments import run_sensitivity
from .report import write_report


METHOD_VERSION = "task06-attack-window-evaluation-v1"


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def prediction_digest(rows):
    # Runtime and memory are observations, not deterministic algorithm outputs.
    return content_digest([{k: v for k, v in row.items() if k not in {"runtime_seconds", "process_peak_memory_mb"}} for row in rows])


def frozen_files(root):
    names = [root / "AGENTS.md", *sorted((root / "docs").glob("*.md")), *sorted((root / "configs").rglob("*.yaml")),
             *sorted((root / "backend/app").rglob("*.py"))]
    return {p.relative_to(root).as_posix(): file_digest(p) for p in names if p.is_file()}


def load_evaluation_config(path):
    cfg = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if type(cfg) is not dict or set(cfg) != {"version", "split", "noise", "limitations"} or cfg["version"] != "evaluation-v1":
        raise ValueError("invalid_evaluation_config")
    if cfg["split"] != "observational_unsplit_no_tuning" or type(cfg["limitations"]) is not list:
        raise ValueError("invalid_evaluation_split")
    if type(cfg["noise"]) is not dict or set(cfg["noise"]) != {"base_representatives", "ratios", "seed"}:
        raise ValueError("invalid_noise_config")
    noise = NoiseConfig(cfg["noise"]["base_representatives"], tuple(cfg["noise"]["ratios"]), cfg["noise"]["seed"])
    return cfg, noise


def evaluate(root, analysis_id, gt_path, scenario, destination=None, config_path=None, mode="all", progress=lambda _: None):
    started = time.perf_counter()
    root = Path(root).resolve()
    gt_path = Path(gt_path).resolve()
    destination = protect_output(root, destination or root / "outputs/evaluation" / analysis_id, gt_path)
    destination.mkdir(parents=True, exist_ok=True)
    config_path = Path(config_path or root / "evaluation/configs/evaluation.yaml")
    cfg, noise_cfg = load_evaluation_config(config_path)
    if mode not in {"all", "evaluate", "baseline", "ablation", "sensitivity", "noise"}:
        raise ValueError("unknown_evaluation_mode")
    protected = frozen_files(root)
    snapshot = load_snapshot(root, analysis_id)
    progress({"stage": "completed_snapshot_verified", "analysis_id": analysis_id, "alerts": len(snapshot.alerts)})
    db, extracted = extract_scores(snapshot, destination, progress)
    threshold = snapshot.config.algorithm.score.correlation_threshold
    evaluation_cfg = snapshot.config.algorithm.evaluation
    # All prediction experiments finish before the only real GT loader call.
    baselines = baseline_counts(snapshot, evaluation_cfg.baseline_window_seconds) if mode in {"all", "baseline"} else []
    ablation = run_ablation(db, threshold) if mode in {"all", "ablation"} else []
    sensitivity = run_sensitivity(db, threshold, evaluation_cfg.thresholds) if mode in {"all", "sensitivity"} else []
    noise = run_noise(snapshot, destination, noise_cfg, progress) if mode in {"all", "noise"} else []
    prediction_frozen = {"analysis_id": analysis_id, "score_digest": content_digest(extracted),
        "baseline_predictions_digest": prediction_digest(baselines), "ablation_predictions_digest": prediction_digest(ablation),
        "sensitivity_predictions_digest": prediction_digest(sensitivity), "noise_predictions_digest": prediction_digest(noise),
        "order": "production completed snapshot -> prediction experiments frozen -> GT loader"}
    save(destination / "prediction_freeze.json", prediction_frozen)
    gt = load_windows(gt_path, scenario)
    mapping = map_windows(gt, snapshot)
    progress({"stage": "attack_window_mapping_only", "selected_gt_rows": gt["selected_rows"], "overlap_alerts": mapping["temporal_overlap_alert_count"]})
    quality = unavailable_quality()
    structure = structural_metrics(snapshot, mapping)
    distribution = score_distribution(db, threshold)
    # Query labels are deliberately NULL: time windows cannot label scored pairs.
    # Bulk bind compact vectors; per-alert SQL execution dominates this scale.
    alert_ids = list(snapshot.alerts)
    db.execute("CREATE OR REPLACE TABLE temporal_alert_context AS SELECT "
               "unnest(?::VARCHAR[]) AS alert_id, unnest(?::BOOLEAN[]) AS overlaps_attack_window",
               [alert_ids, [i in mapping["alert_windows"] for i in alert_ids]])
    temporal_scores = db.execute("SELECT l.overlaps_attack_window,r.overlaps_attack_window,count(*),max(s.score),avg(s.score) "
        "FROM selected_scores s JOIN temporal_alert_context l ON s.left_alert_id=l.alert_id "
        "JOIN temporal_alert_context r ON s.right_alert_id=r.alert_id GROUP BY ALL ORDER BY ALL").fetchall()
    distribution["temporal_context_distributions"] = [{"left_overlaps_window": l, "right_overlaps_window": r,
        "count": n, "max_score": mx, "mean_score": mean, "is_pair_truth": False} for l,r,n,mx,mean in temporal_scores]
    candidates = {**snapshot.manifest["summary"].get("potential_pair_stats", {}),
                  **snapshot.manifest["summary"].get("candidate_admission_stats", {}),
                  "policy_pruned_count": snapshot.manifest["summary"].get("policy_pruned_count"),
                  "resource_truncated_count": snapshot.manifest["summary"].get("resource_truncated_count"),
                  "gt_positive_pairs": None, "gt_positive_admitted": None, "gt_positive_policy_pruned": None,
                  "gt_positive_resource_truncated": None, "candidate_recall": None, "candidate_miss_count": None,
                  "metric_status": "unavailable", "reason": "no_alert_pair_labels; temporal coincidence cannot identify positive pairs"}
    curves = {"pr_curve": None, "average_precision": None, "roc_curve": None, "roc_auc": None,
              "status": "unavailable", "reason": "no_reliable_pair_positive_negative_gt"}
    full = {"method": "traceback_full", "predicted_edge_count": extracted["accepted_edge_count"], "threshold": threshold,
            "quality": quality, "candidate_recall": None, "candidate_policy": "frozen production v1.1"}
    for row in noise:
        row["quality"] = unavailable_quality()
        row["temporally_overlapping_alert_count"] = sum(i in mapping["alert_windows"] for i in row["input_alert_ids"])
    maximum = distribution["maximum"]
    weights = snapshot.config.algorithm.score.weights.model_dump()
    capacity_bound = min(1.0, weights["time"] + weights["entity"] + sum(
        weights[k] * (distribution["components"][k]["max"] or 0.0) for k in ("relation", "behavior", "source")))
    conclusion = {"candidate_admission_loss": {"policy_pruned": candidates["policy_pruned_count"], "gt_positive_loss": None, "status": "quality_loss_unknown_without_pair_gt"},
        "scoring_loss": {"max_valid_score": maximum,
                         "conservative_admitted_evidence_capacity_bound": capacity_bound,
                         "capacity_bound_definition": "T/E theoretical maximum 1; observed admitted R/B/S component limits; penalties ignored. Upper bound only, never a constructed support_pair score.",
                         "missing_relation_component_count": distribution["member_pair_count"] - distribution["components"]["relation"]["nonzero_member_count"],
                         "missing_source_component_count": distribution["member_pair_count"] - distribution["components"]["source"]["nonzero_member_count"]},
        "threshold_loss": {"production_threshold": threshold, "valid_candidates_below_threshold": distribution["valid_candidate_count"] - distribution["valid_candidates_at_or_above_threshold"],
                           "all_valid_scores_below_threshold": maximum is not None and maximum < threshold},
        "guard_loss": {"invalid_member_pairs": distribution["invalid_member_pair_count"], "rejection_codes": extracted["member_guard_rejections"]},
        "gt_mapping_limitation": "attack intervals have no alert identity, pair relation, benign labels, incident membership or causal edges",
        "data_limitation": {"category_distribution": structure["category_distribution"], "source_independence": extracted["source_independence_distribution"]},
        "scope": "explains observed admitted-score decisions; cannot estimate how many true relations were missed",
        "recommendation": "retain frozen production config; obtain independently reviewed alert/pair/incident/chain annotations for quality evaluation"}
    before_integrity = time.perf_counter()
    snapshot.assert_unchanged()
    if file_digest(gt_path) != gt["gt_sha256"]:
        raise ValueError("ground_truth_changed_during_evaluation")
    if frozen_files(root) != protected:
        raise ValueError("frozen_production_or_contract_files_changed")
    runtime = {"total_seconds": time.perf_counter() - started, "final_integrity_verification_seconds": time.perf_counter() - before_integrity,
               "process_peak_memory_mb": peak_memory_mb()}
    files_to_save = {"gt_schema.json": gt, "ground_truth_mapping.json": mapping, "metrics.json": quality,
        "candidate_metrics.json": candidates, "score_distribution.json": distribution, "baselines.json": [full, *baselines],
        "ablation.json": ablation, "sensitivity.json": sensitivity, "noise_robustness.json": noise,
        "structural_metrics.json": structure, "curves.json": curves, "conclusion.json": conclusion,
        "frozen_state.json": {"before_hashes": protected, "after_hashes": frozen_files(root), "all_unchanged": True,
            "production_threshold_changed": False, "scoring_weights_changed": False, "candidate_admission_changed": False,
            "guard_changed": False, "clustering_changed": False, "chain_reconstruction_changed": False, "gt_isolation_changed": False}}
    evaluator_hashes = {p.relative_to(root).as_posix(): file_digest(p) for p in sorted((root / "evaluation").rglob("*")) if p.suffix in {".py", ".yaml", ".md"}}
    portable_identity = {k: v for k, v in snapshot.identity.items() if k != "prediction_snapshot"}
    run_identity = {"prediction_identity": portable_identity, "gt_sha256": gt["gt_sha256"], "scenario": scenario,
                    "evaluation_config": cfg, "method_version": METHOD_VERSION, "evaluation_code_hashes": evaluator_hashes, "mode": mode}
    run_id = "evr_" + content_digest(run_identity)
    summary = {"run_id": run_id, "run_identity": run_identity, "mode": mode, "prediction_identity": snapshot.identity,
        "ground_truth_kind": "attack_windows_only", "gt_sha256": gt["gt_sha256"], "quality_evaluation_coverage": 0.0,
        "temporal_overlap_fraction": mapping["temporal_overlap_fraction"], "split": cfg["split"], "seed": noise_cfg.seed,
        "runtime": runtime, "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "production_runtime": snapshot.manifest["summary"].get("runtime"),
        "score_extraction": extracted, "prediction_before_gt": prediction_frozen,
        "limitations": ["No verified pair/group/chain GT: precision/recall/F1 and PR/ROC unavailable.",
                         "Attack-window overlap is external temporal context, never evidence of relation accuracy.",
                         "No development/test split supplied: observational experiments only, no tuning or optimality claims.",
                         "Noise uses a fixed real-alert subset and unlabelled additions; not full-data benign robustness.",
                         "Ablations and threshold scans are score-only; no new incidents/chains published.",
                         *cfg["limitations"]]}
    for name, value in files_to_save.items():
        save(destination / name, value)
    # Production API consumes only this strict aggregate whitelist, never GT paths/rows.
    export = EvaluationSummaryExport.model_validate({"run_id": run_id, "config_hash": snapshot.record.config_hash,
        "algorithm_version": snapshot.record.algorithm_version, "split": cfg["split"],
        "metrics": {"precision": None, "recall": None, "f1": None, "singleton_incident_ratio": structure["singleton_incident_ratio"],
                    "node_traceability_rate": structure["node_traceability_rate"]},
        "metric_status": {"precision": "unavailable", "recall": "unavailable", "f1": "unavailable",
                          "singleton_incident_ratio": "available", "node_traceability_rate": "available"},
        "evaluation_coverage": 0.0, "counts": {"canonical_alert_count": len(snapshot.alerts), "representative_count": len(snapshot.groups),
            "scored_candidate_count": extracted["candidate_count"], "correlation_edge_count": extracted["accepted_edge_count"],
            "incident_count": structure["incident_count"]}, "runtime": runtime, "limitations": summary["limitations"]})
    export_dir = root / "data/processed/evaluation_exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    save(export_dir / (run_id + ".json"), export.model_dump(mode="json"))
    summary["output_files"] = {name: file_digest(destination / name) for name in files_to_save}
    save(destination / "summary.json", summary)
    write_report(destination, summary, mapping, candidates, distribution, structure, [full, *baselines], ablation, sensitivity, noise, conclusion)
    db.close()
    progress({"stage": "evaluation_completed", "run_id": run_id, "wall_seconds": runtime["total_seconds"]})
    return summary


def main():
    parser = argparse.ArgumentParser(description="Task 06 independent completed-snapshot evaluation; no production tuning")
    parser.add_argument("--root", default=".")
    parser.add_argument("--analysis-id", required=True)
    parser.add_argument("--gt", required=True)
    parser.add_argument("--scenario", required=True, help="Explicit scenario scope; never guessed from filename")
    parser.add_argument("--output")
    parser.add_argument("--config")
    parser.add_argument("--mode", default="all", choices=("all", "evaluate", "baseline", "ablation", "sensitivity", "noise"))
    args = parser.parse_args()
    result = evaluate(args.root, args.analysis_id, args.gt, args.scenario, args.output, args.config, args.mode,
                      lambda row: print(json.dumps(row, ensure_ascii=False), file=sys.stderr, flush=True))
    print(json.dumps({"run_id": result["run_id"], "analysis_id": args.analysis_id, "quality_gt": "unavailable", "runtime": result["runtime"]}))


if __name__ == "__main__":
    main()
