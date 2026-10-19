"""Bounded-memory raw preflight; never reads evaluation metadata or labels."""

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.adapters import AMinerAdapter, WazuhAdapter
from app.adapters.base import reject_truth
from app.services.datasets import load_dataset, read_registry
from app.services.storage import atomic_json, file_digest


def records(path):
    with path.open(encoding="utf-8-sig") as handle:
        first = next((c for c in iter(lambda: handle.read(1), "") if not c.isspace()), "")
        handle.seek(0)
        if first == "[":
            value = json.load(handle)
            if type(value) is not list:
                raise ValueError("invalid_json_array")
            yield from value
        else:
            for line in handle:
                if line.strip():
                    yield json.loads(line)


def inspect_file(root, item, config, setting, *, smoke_limit=100):
    path = root / item["path"]
    result = {"path": item["path"], "exists": path.is_file(), "size_bytes": None, "empty": None,
              "sha256": None, "count": None, "parseable": None, "schema_valid": False,
              "min_timestamp": None, "max_timestamp": None, "schema": {}, "errors": {},
              "adapter_smoke": {"sample_count": 0, "accepted_count": 0, "rejected_count": 0}}
    if not path.is_file():
        result["status"] = "missing_raw_data"
        return result
    result.update(size_bytes=path.stat().st_size, empty=path.stat().st_size == 0, sha256=file_digest(path))
    adapter = (AMinerAdapter if item["source"] == "aminer" else WazuhAdapter)(config, setting)
    count, errors, schema, samples, sampled_shapes = 0, Counter(), {}, [], set()
    earliest = latest = None
    try:
        for raw in records(path):
            count += 1
            try:
                if type(raw) is not dict or not raw:
                    raise ValueError("invalid_record_structure")
                reject_truth(raw)
                for key, value in raw.items():
                    schema.setdefault(key, set()).add(type(value).__name__)
                if item["source"] == "aminer":
                    component, data = raw.get("AnalysisComponent"), raw.get("LogData")
                    if type(component) is not dict or type(data) is not dict:
                        raise ValueError("invalid_aminer_structure")
                    times = data.get("DetectionTimestamp")
                    if not isinstance(times, list) or not times:
                        raise ValueError("missing_detection_timestamp")
                    stamp = adapter.parse_time(times[-1])
                    shape = component.get("AnalysisComponentType")
                else:
                    if type(raw.get("rule")) is not dict:
                        raise ValueError("missing_wazuh_rule")
                    stamp = adapter.parse_time(raw.get("@timestamp") or raw.get("timestamp"))
                    shape = str(raw["rule"].get("id"))
                earliest = stamp if earliest is None else min(earliest, stamp)
                latest = stamp if latest is None else max(latest, stamp)
                # First records plus diverse detector/rule shapes, bounded.
                if len(samples) < smoke_limit and (len(samples) < 20 or shape not in sampled_shapes):
                    samples.append(raw)
                    sampled_shapes.add(shape)
            except (ValueError, TypeError, KeyError) as exc:
                errors[str(exc)[:100]] += 1
        result.update(count=count, parseable=True, schema_valid=bool(count) and not errors)
    except (ValueError, OSError, TypeError) as exc:
        errors["json_parse_or_read_error:" + type(exc).__name__] += 1
        result.update(parseable=False, parsed_records_before_error=count)
    batch = adapter.batch(samples)
    result["adapter_smoke"] = {"sample_count": len(samples), "accepted_count": batch.accepted_count,
        "rejected_count": len(batch.rejected), "rejection_reasons": batch.rejection_reasons,
        "coverage": "bounded sample; structural schema and time parsing cover every raw record"}
    if file_digest(path) != result["sha256"]:
        errors["input_changed_during_inventory"] += 1
        result["schema_valid"] = False
    result.update(schema={k: sorted(v) for k, v in sorted(schema.items())}, errors=dict(sorted(errors.items())),
                  min_timestamp=earliest, max_timestamp=latest)
    result["status"] = "ready" if result["schema_valid"] and not batch.rejected and not errors else "invalid_raw_data"
    return result


def inventory(root, *, dataset_id="ait_ads"):
    root = Path(root).resolve()
    registry = read_registry(root, dataset_id)
    scenes = []
    for scene_id, declaration in registry.scenes.items():
        if not declaration.enabled:
            scenes.append({"scene_id": scene_id, "status": "disabled", "ready_for_analysis": False})
            continue
        loaded = load_dataset(root, dataset_id, scene_id)
        files = {item["source"]: inspect_file(root, item, loaded.config, loaded.sources[item["source_ref"]][1])
                 for item in loaded.inputs}
        stamps_min = [f["min_timestamp"] for f in files.values() if f["min_timestamp"]]
        stamps_max = [f["max_timestamp"] for f in files.values() if f["max_timestamp"]]
        ready = all(f["status"] == "ready" for f in files.values())
        row = {"scene_id": scene_id, "files": files,
            **{s + "_exists": f["exists"] for s, f in files.items()},
            **{s + "_count": f["count"] for s, f in files.items()},
            "total_count": sum(f["count"] for f in files.values()) if all(f["count"] is not None for f in files.values()) else None,
            "min_timestamp": min(stamps_min) if stamps_min else None, "max_timestamp": max(stamps_max) if stamps_max else None,
            "schema_valid": all(f["schema_valid"] for f in files.values()), "ready_for_analysis": ready,
            "status": "ready" if ready else "missing_raw_data" if loaded.missing_files else "invalid_raw_data",
            "dataset_metadata": loaded.metadata}
        scenes.append(row)
        print(json.dumps({k: row[k] for k in ("scene_id", "aminer_count", "wazuh_count", "total_count", "status")}), flush=True)
    return {"dataset_id": dataset_id, "framework_status": "framework_ready", "scenes": scenes,
            "schema_validation_scope": "JSON objects, source envelope, annotation isolation and timestamp validity for every record; CanonicalAlert smoke is sampled",
            "data_ingestion_status": "ready" if all(s["ready_for_analysis"] for s in scenes) else "data_ingestion_blocked",
            "limitations": ["Local user-supplied AIT-ADS files; SHA-256 records local bytes, not independent distribution authenticity.",
                             "Adapter smoke samples are bounded; full production adaptation runs only for selected scenes."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="ait_ads")
    args = parser.parse_args()
    report = inventory(ROOT, dataset_id=args.dataset)
    output = ROOT / "outputs" / args.dataset
    output.mkdir(parents=True, exist_ok=True)
    atomic_json(output / "SCENE_INVENTORY.json", report)
    return 0 if report["data_ingestion_status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
