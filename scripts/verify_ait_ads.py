"""Cold production verification for exactly two explicitly selected scenes."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from app.services.analysis import AnalysisService
from app.services.datasets import load_dataset
from app.services.storage import MODELS, SnapshotStore, atomic_json, file_digest
from demo_support import truth_guard
from verify_demo import choose_snapshot


BASELINE_COUNTS = {"input_count": 45544, "canonical_alert_count": 45510, "representative_count": 45501,
    "incident_count": 45501, "singleton_count": 45492, "multi_alert_count": 9,
    "correlation_edge_count": 0, "chain_edge_count": 0}


def run_scene(root, scene_id):
    loaded = load_dataset(root, scene_id=scene_id)
    context = {"root": root, "config": loaded.config, "sources": loaded.sources, "request": loaded.request}
    previous = choose_snapshot(context) if scene_id == "russellmitchell" else None
    previous_hashes = ({k: file_digest(SnapshotStore(root, previous).domain / (k + ".jsonl")) for k in MODELS}
                       if previous else {})
    def progress(value):
        if value.get("stage") in {"finished", "candidates", "scoring", "clustering", "chain"}:
            print(json.dumps({"scene": scene_id, **value}), flush=True)
    with truth_guard(root):
        service = AnalysisService(root, configs={"v0": loaded.config}, sources=loaded.sources,
                                  allowed_files=[i["path"] for i in loaded.inputs], progress=progress)
        try:
            identity = service.create(loaded.request, background=False)
        finally:
            service.close()
        store = SnapshotStore(root, identity)
        run = json.loads((store.domain / "run.json").read_text(encoding="utf-8"))
        report = {"scene_id": scene_id, "analysis_id": identity, "status": run["status"],
                  "dataset_metadata": run.get("dataset_metadata"), "counts": run["counts"],
                  "input_files": run["input_files"], "runtime": run["runtime"], "ground_truth_used": False,
                  "errors": run["errors"], "previous_baseline": previous}
        if run["status"] in {"completed", "incomplete"} and (store.domain / "incidents.jsonl").is_file():
            with (store.domain / "incidents.jsonl").open(encoding="utf-8") as handle:
                sizes = [len(json.loads(line)["alert_ids"]) for line in handle]
            report["counts"].update(singleton_count=sum(n == 1 for n in sizes), multi_alert_count=sum(n > 1 for n in sizes))
            record, _, manifest = store.read_metadata()
            report.update(snapshot_identity=manifest["execution"]["snapshot_identity"], config_hash=record.config_hash,
                          dataset_digest=record.dataset_digest, grounding=run["grounding"])
            report["domain_sha256"] = {k: file_digest(store.domain / (k + ".jsonl")) for k in MODELS}
        if scene_id == "russellmitchell":
            report["expected_counts"] = BASELINE_COUNTS
            report["count_regression_passed"] = all(report["counts"].get(k) == v for k, v in BASELINE_COUNTS.items())
            report["domain_regression_passed"] = bool(previous_hashes) and report.get("domain_sha256") == previous_hashes
            report["passed"] = run["status"] == "completed" and report["count_regression_passed"] and report["domain_regression_passed"]
        else:
            report["passed"] = run["status"] == "completed"
        directory = root / "outputs/ait_ads"
        directory.mkdir(parents=True, exist_ok=True)
        atomic_json(directory / (scene_id + "_PRODUCTION_VERIFICATION.json"), report)
        print(json.dumps(report, ensure_ascii=False), flush=True)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scene", choices=["russellmitchell", "shaw"], required=True)
    args = parser.parse_args()
    return 0 if run_scene(ROOT, args.scene)["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
