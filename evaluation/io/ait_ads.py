"""Official AIT-ADS interval metadata adapter; no inferred alert/group/edge GT."""

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from app.config import _UniqueKeyLoader
from app.services.storage import atomic_json, file_digest
from evaluation.io.ground_truth import load_windows


@dataclass(frozen=True)
class GroundTruthRecord:
    dataset_id: str
    scene_id: str
    source: str | None
    start_time: str
    end_time: str
    time_label: str | None
    event_label: str | None
    attack_stage: str | None
    attack_label: str
    raw_label_reference: dict


def utc(microseconds):
    return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=microseconds)).isoformat(timespec="microseconds").replace("+00:00", "Z")


def load_ait_ads_ground_truth(root):
    root = Path(root).resolve()
    base = root / "data/ait_ads"
    with (base / "dataset.yaml").open(encoding="utf-8") as handle:
        manifest = yaml.load(handle, Loader=_UniqueKeyLoader)
    reference = manifest["evaluation"]["official_labels"]["path"]
    path = base / reference
    if path.resolve() != path.absolute() or not path.resolve().is_relative_to(base):
        raise ValueError("invalid_ground_truth_reference")
    # This declared source path is retained verbatim; the adapter never edits it.
    if not path.is_file():
        return {"status": "missing_ground_truth", "path": reference, "records": [], "capabilities": {}}
    before = file_digest(path)
    import csv
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ["scenario", "attack", "start", "end"]:
            raise ValueError("unsupported_gt_schema")
        raw_rows = list(reader)
    scenes = sorted({r["scenario"] for r in raw_rows})
    windows = {scene: load_windows(path, scene) for scene in scenes}
    if file_digest(path) != before or any(w["gt_sha256"] != before for w in windows.values()):
        raise ValueError("ground_truth_changed_during_load")
    by_content = {(r["scenario"], r["attack"], r["start_us"], r["end_us"]): r
                  for loaded in windows.values() for r in loaded["windows"]}
    from evaluation.io.ground_truth import epoch_microseconds
    records = []
    digest = before
    for row_number, raw in enumerate(raw_rows, start=2):
        key = (raw["scenario"], raw["attack"], epoch_microseconds(raw["start"]), epoch_microseconds(raw["end"]))
        row = by_content[key]
        records.append(asdict(GroundTruthRecord("ait_ads", raw["scenario"], None,
            utc(row["start_us"]), utc(row["end_us"]), None, None, None, raw["attack"],
            {"path": reference, "sha256": digest, "csv_row": row_number, "raw_fields": raw})))
    return {"status": "available", "path": reference, "sha256": digest, "columns": ["scenario", "attack", "start", "end"],
        "row_count": len(raw_rows), "scene_field": "scenario", "scenes": scenes,
        "scene_rows": {s: windows[s]["selected_rows"] for s in scenes},
        "missing_scene_labels": sorted(set(manifest["scenes"]) - set(scenes)),
        "time_fields": {"start": "Unix epoch seconds", "end": "Unix epoch seconds"},
        "interval_policy": "[start,end), UTC, truncate to microseconds",
        "capabilities": {"temporal_ground_truth": bool(records), "event_ground_truth": False,
            "attack_window_metadata": bool(records), "alert_ground_truth": False, "incident_ground_truth": False,
            "correlation_edge_ground_truth": False, "chain_edge_ground_truth": False},
        "records": records,
        "limitations": ["attack is an official window label, not an attack ID or a normalized stage.",
            "No source, time_label, event_label, alert ID, incident membership, causal edges or direction fields.",
            "Time overlap alone does not label an alert malicious or prove common incident membership."]}


def main():
    root = Path(__file__).resolve().parents[2]
    output = root / "outputs/ait_ads"
    output.mkdir(parents=True, exist_ok=True)
    report = load_ait_ads_ground_truth(root)
    atomic_json(output / "GT_ANALYSIS.json", report)
    print({k: v for k, v in report.items() if k != "records"})
    return 0 if report["status"] == "available" else 1


if __name__ == "__main__":
    raise SystemExit(main())
