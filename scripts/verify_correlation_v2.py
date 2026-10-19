"""Full russellmitchell production replay and v2 receipt; no ground truth or AI."""

from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from app.services.analysis import AnalysisService
from app.services.datasets import load_dataset
from app.services.storage import MODELS, SnapshotStore, atomic_json, file_digest
from app.models import Incident, CorrelationEdge
from demo_support import truth_guard


def run(root=ROOT):
    root = Path(root).resolve()
    destination = root / "outputs/correlation_v2"
    destination.mkdir(parents=True, exist_ok=True)
    baseline = json.loads((root / "outputs/task09_1/score_diagnostics.json").read_text(encoding="utf-8"))
    old = SnapshotStore(root, baseline["analysis_id"])
    protected = [old.details / "manifest.json", old.domain / "analysis.json", old.domain / "run.json"]
    protected += [old.domain / (kind + ".jsonl") for kind in MODELS]
    before = {str(p.relative_to(root)): file_digest(p) for p in protected}
    loaded = load_dataset(root, scene_id="russellmitchell", config_version="v2")
    if loaded.missing_files:
        raise ValueError("real_input_missing")
    request = {"config_version": "v2", "inputs": loaded.inputs}
    def progress(value):
        print(json.dumps(value, ensure_ascii=False), flush=True)
    with truth_guard(root):
        service = AnalysisService(root, configs={"v2": loaded.config}, sources=loaded.sources,
            allowed_files=[v["path"] for v in loaded.inputs], progress=progress)
        try:
            identity = service.create(request, background=False)
        finally:
            service.close()
        store = SnapshotStore(root, identity)
        run = json.loads((store.domain / "run.json").read_text(encoding="utf-8"))
        if run["status"] != "completed":
            atomic_json(destination / "REAL_DATA_RESULT.json", {"analysis_id":identity,"status":run["status"],"errors":run["errors"]})
            raise ValueError("full_real_replay_not_completed:" + ";".join(run["errors"]))
        record, _, manifest = store.read_metadata()
        incident_sizes, representative_sizes, risk_levels = [], [], Counter()
        dedupe_owner = {}
        for group in store.read_records("dedupe_groups"):
            for aid in group.alert_ids:
                dedupe_owner[aid] = group.representative_alert_id
        triaged = 0
        for incident in store.read_records("incidents"):
            incident_sizes.append(len(incident.alert_ids))
            representative_sizes.append(len({dedupe_owner.get(aid,aid) for aid in incident.alert_ids}))
            if incident.single_alert_triage is not None:
                triaged += 1
                risk_levels[incident.single_alert_triage.risk_level] += 1
        score = json.loads((store.details / "correlation_v2_scores.json").read_text(encoding="utf-8"))
        counts = {**run["counts"], "singleton_count": sum(n == 1 for n in incident_sizes),
            "multi_alert_incident_count": sum(n > 1 for n in incident_sizes),
            "representative_singleton_count": sum(n == 1 for n in representative_sizes),
            "correlated_multi_alert_incident_count": sum(n > 1 for n in representative_sizes),
            "largest_incident_representatives": max(representative_sizes), "triaged_singleton_count": triaged}
        source_counts, categories, fields = Counter(), Counter(), Counter()
        for alert in store.read_records("alerts"):
            source_counts[alert.source_type.value] += 1
            categories[alert.category.value] += 1
            for field in ("host","account","session","process","src_ip","dst_ip","rule_id","signature"):
                if getattr(alert,field) is not None:
                    fields[field] += 1
        result = {"analysis_id": identity, "snapshot_identity": manifest["execution"]["snapshot_identity"],
            "status":run["status"],"is_complete":record.is_complete,"config_hash":record.config_hash,
            "dataset_digest":record.dataset_digest,"mapping_digest":record.mapping_digest,
            "ground_truth_used":False,"ai_used":False,"counts":counts,"source_counts":dict(source_counts),
            "mapped_categories":dict(categories),"observable_fields":dict(fields),"runtime":run["runtime"],
            "peak_memory_mb":record.metrics.peak_memory_mb,"grounding":run["grounding"],"scores":score,
            "singleton_risk_distribution":dict(risk_levels),
            "old_algorithm":{"actual_max":baseline["observed_max"],"data_loose_bound":.58,
                "configured_joint_supremum":baseline["theoretical_config_max"],
                "score_receipt_sha256":file_digest(root/"outputs/task09_1/score_diagnostics.json")},
            "new_algorithm":{"algebraic_upper_bound":1.0,"activated_config_upper_bound":.965,
                "bound_kind":"conservative upper bound, not a proven jointly attainable supremum",
                "threshold":loaded.config.algorithm.score.correlation_threshold},
            "protected_legacy_files":before,
            "diagnostics_ref":record.diagnostics_ref,"manifest_ref":run["manifest_ref"]}
        result["protected_legacy_unchanged"] = before == {p:file_digest(root/p) for p in before}
        result["diagnosis"] = ("ALGORITHM_FIXED_DATA_HAS_RELATIONS" if counts["correlation_edge_count"] else
            "ALGORITHM_FIXED_DATA_STILL_LACKS_RELATION_EVIDENCE")
        if not result["protected_legacy_unchanged"]:
            raise ValueError("historical_snapshot_changed")
        atomic_json(destination/"REAL_DATA_RESULT.json",result)
        print(json.dumps({"analysis_id":identity,"counts":counts,"scores":{k:v for k,v in score.items() if k!='top_20'},
                          "diagnosis":result["diagnosis"]},ensure_ascii=False),flush=True)
        return result


if __name__ == "__main__":
    run()
