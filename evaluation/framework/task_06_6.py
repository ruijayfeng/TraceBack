"""Cross-dataset verification; missing data produces a blocked, auditable report."""

import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import time

from app.services.storage import file_digest
from app.utils.stable_id import content_digest
from evaluation.io.cross_dataset import assert_frozen, compatibility, core_parameters, load_dataset, raw_inventory
from evaluation.io.snapshot import load_snapshot
from evaluation.io.ground_truth import load_windows
from evaluation.metrics.classification import evaluate_pairs
from .cross_dataset_pipeline import FIELDS, STAGES, run_pipeline, unavailable
from .runner import frozen_files, save
from .task_06_6_report import write_report


VERSION = "task06.6-cross-dataset-v1"
QUALITY = ("pairwise_precision", "pairwise_recall", "pairwise_f1", "incident_precision", "incident_recall",
           "incident_f1", "false_merge_rate", "false_split_rate", "node_precision", "node_recall", "node_f1",
           "edge_precision", "edge_recall", "edge_f1", "direction_accuracy")


def quality_metrics(prediction, path=None, kind=None, scenario=None):
    """Called only after prediction_freeze.json has been persisted."""
    reason = "ground_truth_not_provided" if path is None else "ground_truth_granularity_not_supported_by_existing_metrics"
    metrics = {key: unavailable(reason) for key in QUALITY}
    metadata = {"status": "not_provided", "quality_evaluation_coverage": None}
    if path is None:
        return {"metrics": metrics, "ground_truth": metadata}
    path = Path(path)
    before = file_digest(path)
    if kind == "attack_windows":
        gt = load_windows(path, scenario)
        metadata = {"status": "attack_windows_only", "sha256": before,
                    "selected_rows": gt["selected_rows"], "quality_evaluation_coverage": 0.0,
                    "reason": "time overlap cannot establish alert/pair/incident/chain labels"}
    elif kind == "pair_labels":
        with path.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != ["left_alert_id", "right_alert_id", "positive"]:
                raise ValueError("unsupported_pair_gt_schema")
            labels = []
            known = set()
            with (Path(prediction) / "canonical.jsonl").open(encoding="utf-8") as alerts:
                known = {json.loads(line)["alert_id"] for line in alerts}
            for row in reader:
                if set(row) != set(reader.fieldnames) or row["positive"] not in {"true", "false"}:
                    raise ValueError("invalid_pair_gt")
                if row["left_alert_id"] not in known or row["right_alert_id"] not in known:
                    raise ValueError("pair_gt_unknown_alert")
                labels.append((row["left_alert_id"], row["right_alert_id"], row["positive"] == "true"))
        # A formal representative edge covers its full original member groups.
        owner = {i: [i] for i in known}
        with (Path(prediction) / "dedupe.jsonl").open(encoding="utf-8") as handle:
            for line in handle:
                g = json.loads(line)
                owner[g["representative_alert_id"]] = g["alert_ids"]
        predicted = set()
        with (Path(prediction) / "correlation_edges.jsonl").open(encoding="utf-8") as handle:
            for line in handle:
                e = json.loads(line)
                predicted.update(tuple(sorted((a,b))) for a in owner[e["source_alert_id"]] for b in owner[e["target_alert_id"]])
        result = evaluate_pairs(predicted, labels)
        for key in ("precision", "recall", "f1"):
            metrics["pairwise_"+key] = {"value": result[key], "status": result["metric_status"][key],
                                        "reason": None if result[key] is not None else "empty_denominator"}
        labelled_ids = {i for a,b,_ in labels for i in (a,b)}
        metadata = {"status": "explicit_pair_labels", "sha256": before, "counts": result,
                    "quality_evaluation_coverage": len(labelled_ids)/len(known) if known else None,
                    "coverage_definition": "unique labelled alert endpoints / all CanonicalAlerts; unlabelled pairs excluded"}
    else:
        raise ValueError("unsupported_gt_kind")
    if file_digest(path) != before:
        raise ValueError("ground_truth_changed_during_evaluation")
    return {"metrics": metrics, "ground_truth": metadata}


def baseline_values(snapshot, root):
    directory = Path(root) / "outputs/evaluation/task_06_5"
    p = json.loads((directory / "production_baseline.json").read_text(encoding="utf-8"))
    scores = json.loads((directory / "score_distribution.json").read_text(encoding="utf-8"))
    bound = json.loads((directory / "reachability.json").read_text(encoding="utf-8"))
    binding = json.loads((directory / "reproducibility.json").read_text(encoding="utf-8"))
    if binding["cache_binding"]["binding"]["analysis_id"] != snapshot.record.analysis_id:
        raise ValueError("task_06_5_baseline_binding_mismatch")
    counts = snapshot.manifest["summary"]["counts"]
    if (p["canonical_alert_count"] != len(snapshot.alerts) or p["representative_count"] != len(snapshot.groups)
        or p["scored"] != counts["scored_candidate_count"] or scores["edge_threshold"] != snapshot.config.algorithm.score.correlation_threshold):
        raise ValueError("task_06_5_baseline_counts_mismatch")
    summary = snapshot.manifest["summary"]
    singleton = sum(len({snapshot.owner[i] for i in inc["alert_ids"]}) == 1 for inc in snapshot.records("incidents"))
    values = {"raw_records": counts["input_count"], "accepted_records": counts["accepted_count"],
              "canonical_alerts": len(snapshot.alerts), "representatives": len(snapshot.groups), "entities": len(snapshot.entities),
              "entity_coverage": sum(bool(a["entity_ids"]) for a in snapshot.alerts.values())/len(snapshot.alerts),
              "potential_pairs": p["unique_potential_pairs"], "policy_pruned": p["policy_pruned"], "admitted": p["admitted"],
              "scored": p["scored"], "resource_truncated": p["resource_truncated"], "max_score": scores["max"],
              "threshold_reachable_pairs": scores["near_threshold_counts"][0]["actual_admissible_pair"],
              "max_reachable_score_upper_bound": bound["dataset_constrained_maximum_reachable_score"],
              "correlation_edges": counts["correlation_edge_count"], "incidents": counts["incident_count"],
              "singleton_incidents": singleton, "multi_alert_incidents": counts["incident_count"]-singleton,
              "chain_nodes": counts["chain_node_count"], "chain_edges": counts["chain_edge_count"],
              "runtime_seconds": snapshot.record.metrics.total_runtime_seconds, "peak_memory_mb": snapshot.record.metrics.peak_memory_mb}
    return values, summary.get("runtime", {}), {p.name: file_digest(p) for p in directory.glob("*.json")}


def run(root, analysis_id, dataset_path=None, destination=None, gt_path=None, gt_kind=None, scenario=None):
    started = time.perf_counter()
    root = Path(root).resolve()
    output = Path(destination or root / "outputs/evaluation/task_06_6").resolve()
    if not output.is_relative_to(root / "outputs/evaluation") or output == root / "outputs/evaluation" or (
        root / "outputs/evaluation/task_06_5" == output or output.is_relative_to(root / "outputs/evaluation/task_06_5")
    ) or (output / "TASK_06_EVALUATION_REPORT.md").exists():
        raise ValueError("task_06_6_output_must_be_independent")
    if gt_path and Path(gt_path).resolve().is_relative_to(output):
        raise ValueError("ground_truth_cannot_be_in_output")
    output.mkdir(parents=True, exist_ok=True)
    protected = frozen_files(root)
    initial_path = output / "initial_frozen_files.json"
    if initial_path.exists():
        initial = json.loads(initial_path.read_text(encoding="utf-8"))
        protected.update({p: h for p,h in initial.items() if p != "evaluation/README.md"})
    save(output / "run_start_freeze.json", protected)
    snapshot = load_snapshot(root, analysis_id)
    # Bind prior evaluation outputs as well as production to the completed
    # Task 06.5 audit. Existing external mutations fail visibly before analysis.
    prior_audit_path = root / "outputs/evaluation/task_06_5/reproducibility.json"
    prior_audit = json.loads(prior_audit_path.read_text(encoding="utf-8"))
    for key in ("protected_hashes", "raw_input_hashes", "production_artifact_hashes", "task06_output_hashes"):
        protected.update(prior_audit.get(key, {}))
    baseline, baseline_runtime, baseline_bindings = baseline_values(snapshot, root)
    inventory = raw_inventory(root)
    baseline_inputs = {i["path"] for i in snapshot.manifest["summary"]["input_files"]}
    independent = [i for i in inventory if i["path"] not in baseline_inputs]
    readiness = {"status": "blocked_by_missing_dataset" if not independent else "blocked_by_missing_source_metadata",
                 "inventory": inventory, "independent_raw_candidates": independent,
                 "excluded": ["production snapshots are outputs, not new datasets", "test fixtures are contract examples",
                              "noise/subsets/repeats of russellmitchell are not independent scenarios"],
                 "required_inputs": ["independent real security alert file(s), dataset name and provenance",
                                     "independence evidence (not a random partition of the baseline)",
                                     "source namespace, timezone, vendor format reference and AMiner profile/version where relevant",
                                     "evaluation-only source config and source-to-existing-Canonical mappings",
                                     "optional independently reviewed GT with explicit granularity"]}
    binding = {"input_fingerprint": None, "source_config_hash": None, "mapping_digest": None,
               "algorithm_config_hash": None, "core_algorithm_parameters_hash": None}
    missing_reason = readiness["status"]
    dataset = {"name": None, "origin": None, "files": [], "record_count": None,
               "has_gt": None, "input_fingerprint": None, "status": missing_reason}
    prediction = None
    if dataset_path:
        metadata, inputs, binding = load_dataset(root, dataset_path, snapshot.config)
        readiness["status"] = "ready"
        # Save the complete config/input/code binding BEFORE invoking any core call.
        save(output / "run_input_binding.json", {**binding, "evaluation_version": VERSION,
            "metadata_sha256": file_digest(Path(dataset_path)), "core_files": protected,
            "effective_config_snapshot": inputs[0][0].config.snapshot})
        prediction = run_pipeline(inputs, output / "prediction")
        for relative, digest in binding["input_files"].items():
            if file_digest(root / relative) != digest:
                raise ValueError("dataset_input_changed_during_prediction")
        dataset = {"name": metadata["dataset"], "origin": metadata["origin"],
                   "independence_evidence": metadata["independence_evidence"], "files": binding["input_files"],
                   "record_count": prediction["adapter_coverage"]["total_records"], "has_gt": bool(gt_path),
                   "input_fingerprint": binding["input_fingerprint"], "status": prediction["status"]}
        save(output / "prediction_freeze.json", {"prediction_digest": prediction["prediction_digest"],
             "dataset_digest": prediction.get("dataset_digest"), "binding": binding,
             "order": "all production predictions frozen -> evaluation GT loader"})
        metrics = quality_metrics(output / "prediction", gt_path, gt_kind, scenario)
        coverage = prediction["adapter_coverage"]
        classification = "adapter_incomplete" if coverage["rejected_records"] else (
            "portable_with_data_limitations" if any(v["missing_by_source"] or v["mapping_failure"] for v in coverage["canonical_fields"].values())
            else "portable")
        if prediction["status"] == "incomplete":
            classification = None
        conclusion = {"status": "assessed" if classification else "not_computable", "classification": classification,
                      "evidence": {"pipeline_status": prediction["status"], "grounding": prediction.get("grounding"),
                                   "missing_field_counts": {k:v["missing_by_source"] for k,v in coverage["canonical_fields"].items()},
                                   "mapping_uncovered_counts": {k:v["mapping_failure"] for k,v in coverage["canonical_fields"].items()}},
                      "limitation": "engineering portability only; zero edges alone do not establish a core generalization issue"}
    else:
        metrics = {"metrics": {k: unavailable(missing_reason) for k in QUALITY}, "ground_truth": {"status": "not_available", "quality_evaluation_coverage": None}}
        conclusion = {"status": "not_computable", "classification": None, "reason": missing_reason,
                      "allowed_classes": ["portable", "portable_with_data_limitations", "adapter_incomplete", "core_generalization_issue"]}
    status = "evaluation_"+missing_reason if prediction is None else prediction["status"]
    stages = prediction["stages"] if prediction else {name: {"input_count": None, "output_count": None,
        "rejected_count": None, "runtime_seconds": None, "status": "blocked", "blocked_stage": "adapter", "blocked_reason": missing_reason} for name in STAGES}
    coverage = prediction["adapter_coverage"] if prediction else {**unavailable(missing_reason), "total_records": None,
        "accepted_records": None, "rejected_records": None, "acceptance_rate": None,
        "canonical_fields": {k: unavailable(missing_reason) for k in FIELDS}}
    entities = prediction["entity_coverage"] if prediction else {**unavailable(missing_reason),
        "entity_total": None, "alerts_with_entity": None, "alerts_without_entity": None, "entity_coverage_rate": None,
        "entity_type_distribution": {k: unavailable(missing_reason) for k in ("IP","HOST","ACCOUNT","SESSION","PROCESS","URL","DOMAIN","FILE","COMMAND")}}
    cross_values = dict(prediction["counts"]) if prediction else {}
    if prediction:
        cross_values.update(entity_coverage=entities["entity_coverage_rate"], max_score=prediction["scores"].get("max"),
            threshold_reachable_pairs=prediction["scores"].get("threshold_reachable_pairs"),
            max_reachable_score_upper_bound=prediction["reachability"].get("dataset_constrained_maximum_reachable_score"),
            runtime_seconds=prediction["runtime"]["total_seconds"], peak_memory_mb=prediction["runtime"].get("peak_memory_mb"))
    comparison = [{"metric": k, "RussellMitchell": v, "CrossDataset": cross_values.get(k),
                   "reason": missing_reason if prediction is None else ("not_available_for_this_input" if cross_values.get(k) is None else None)} for k,v in baseline.items()]
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True).stdout.strip() or None
    except OSError:
        commit = None
    summary = {"task": "06.6", "evaluation_version": VERSION, "framework_status": "framework_completed",
        "run_status": status, "dataset": dataset, "baseline_identity": snapshot.identity, "binding": binding,
        "baseline_core_algorithm_parameters_hash": content_digest(core_parameters(snapshot.config)),
        "core_algorithm_changed": False, "core_algorithm_config_equal": None if prediction is None else True,
        "full_config_hash_equality_note": "Full Analysis config hashes include source settings/mappings and may differ; all core algorithm parameters must match.",
        "generalization": conclusion, "comparison": comparison,
        "research_questions": {"RQ"+str(i): unavailable(missing_reason) if prediction is None else {"status": "see_coverage_pipeline_reachability_and_conclusion"} for i in range(1,7)},
        "code_version": {"git_commit": commit, "reason": None if commit else "workspace_is_not_a_git_checkout",
                         "production_sha256_digest": content_digest({k:v for k,v in protected.items() if k.startswith("backend/app/")})},
        "files_changed": ["evaluation/io/cross_dataset.py", "evaluation/framework/cross_dataset_pipeline.py",
                          "evaluation/framework/task_06_6.py", "evaluation/framework/task_06_6_report.py",
                          "evaluation/tests/test_task_06_6.py", "evaluation/README.md", "evaluation/configs/task_06_6_core_freeze.json"],
        "threshold_changed": False, "weights_changed": False, "candidate_policy_changed": False,
        "guard_changed": False, "incident_chain_rules_changed": False,
        "gt_isolation": "prediction API accepts no GT; GT loader runs after persisted prediction freeze; automated tripwire tests",
        "dataset_specific_hardcoding": "no production changes; core hash equivalence plus repository isolation checks",
        "tests": {"status": "pending_actual_regression"}}
    runtime = prediction["runtime"] if prediction else {"pipeline_total_seconds": None, "stages": {k:None for k in STAGES},
        "status": "not_computable", "reason": missing_reason, "peak_memory": "not_available"}
    runtime.update(baseline_pipeline=baseline_runtime, framework_wall_seconds=time.perf_counter()-started)
    files = {"dataset_readiness.json": readiness, "adapter_compatibility.json": compatibility(root),
        "adapter_coverage.json": coverage, "entity_coverage.json": entities, "pipeline_stage_stats.json": stages,
        "score_distribution.json": prediction["scores"] if prediction else unavailable(missing_reason),
        "score_reachability.json": prediction["reachability"] if prediction else unavailable(missing_reason),
        "runtime.json": runtime, "cross_dataset_metrics.json": metrics,
        "baseline_metrics.json": {"values": baseline, "frozen_task_06_5_files": baseline_bindings}}
    for name, value in files.items():
        save(output / name, value)
    with (output / "baseline_comparison.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("metric", "RussellMitchell", "CrossDataset", "reason"))
        writer.writeheader()
        writer.writerows({**r, "CrossDataset": r["CrossDataset"] if r["CrossDataset"] is not None else "N/A"} for r in comparison)
    snapshot.assert_unchanged()
    summary["freeze_verification"] = assert_frozen(root, protected)
    save(output / "cross_dataset_summary.json", summary)
    write_report(output, summary, files)
    finalize_manifest(output, summary)
    return summary


def finalize_manifest(output, summary):
    output = Path(output)
    save(output / "manifest.json", {"task": "06.6", "evaluation_version": VERSION, "dataset": summary["dataset"],
         "dataset_fingerprint": summary["dataset"]["input_fingerprint"], "code_version": summary["code_version"],
         "baseline_config_hash": summary["baseline_identity"]["config_hash"],
         "baseline_mapping_digest": summary["baseline_identity"]["mapping_digest"], "binding": summary["binding"],
         "production_algorithm_changed": False, "gt_isolation_status": summary["gt_isolation"],
         "run_timestamp": datetime.now(timezone.utc).isoformat(), "run_status": summary["run_status"],
         "evaluation_code_sha256": {p.relative_to(Path(__file__).parents[2]).as_posix(): file_digest(p)
            for p in sorted(Path(__file__).parents[1].rglob("*")) if p.suffix in {".py", ".yaml", ".md"}},
         "output_file_sha256": {p.relative_to(output).as_posix(): file_digest(p) for p in sorted(output.rglob("*"))
            if p.is_file() and p.name != "manifest.json"},
         "manifest_self_hash": "excluded to avoid recursive self-reference"})


def main():
    p = argparse.ArgumentParser(description="Task 06.6 frozen-core cross-dataset verification")
    p.add_argument("--root", default=".")
    p.add_argument("--analysis-id", required=True)
    p.add_argument("--dataset-metadata")
    p.add_argument("--output")
    p.add_argument("--gt")
    p.add_argument("--gt-kind", choices=("attack_windows", "pair_labels"))
    p.add_argument("--scenario")
    args = p.parse_args()
    if bool(args.gt) != bool(args.gt_kind) or (args.gt_kind == "attack_windows" and not args.scenario):
        p.error("GT requires explicit kind; attack windows also require scenario")
    summary = run(args.root, args.analysis_id, args.dataset_metadata, args.output, args.gt, args.gt_kind, args.scenario)
    print(json.dumps({"framework_status": summary["framework_status"], "run_status": summary["run_status"],
                      "core_algorithm_changed": summary["core_algorithm_changed"]}))


if __name__ == "__main__":
    main()
