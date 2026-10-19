"""Attack-window GT only: temporal overlap never implies pair/group truth."""

from bisect import bisect_left
import csv
from decimal import Decimal, InvalidOperation, ROUND_FLOOR
from pathlib import Path

from app.services.storage import file_digest
from app.utils.stable_id import content_digest


def epoch_microseconds(value):
    try:
        number = Decimal(value)
        if not number.is_finite():
            raise ValueError("non_finite_gt_time")
        return int((number * 1000000).to_integral_value(rounding=ROUND_FLOOR))
    except InvalidOperation as exc:
        raise ValueError("invalid_gt_time") from exc


def load_windows(path, scenario):
    path = Path(path)
    digest = file_digest(path)
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ["scenario", "attack", "start", "end"]:
            raise ValueError("unsupported_gt_schema")
        rows = []
        for raw in reader:
            if None in raw or any(v is None or not v.strip() for v in raw.values()):
                raise ValueError("malformed_gt_row")
            start, end = epoch_microseconds(raw["start"]), epoch_microseconds(raw["end"])
            if start >= end:
                raise ValueError("invalid_gt_interval")
            row = {"scenario": raw["scenario"], "attack": raw["attack"], "start_us": start, "end_us": end}
            row["window_id"] = "win_" + content_digest(row)
            rows.append(row)
    if len({r["window_id"] for r in rows}) != len(rows):
        raise ValueError("duplicate_gt_window")
    selected = sorted((r for r in rows if r["scenario"] == scenario), key=lambda r: r["window_id"])
    if not selected:
        raise ValueError("gt_scenario_not_found")
    if file_digest(path) != digest:
        raise ValueError("ground_truth_changed_during_load")
    return {"schema": {"scenario": "string", "attack": "string", "start": "decimal epoch seconds",
                       "end": "decimal epoch seconds"}, "gt_sha256": digest,
            "total_rows": len(rows), "selected_rows": len(selected), "out_of_scope_rows": len(rows) - len(selected),
            "scenario": scenario, "interval_policy": "UTC epoch seconds; [start,end); truncate to microseconds",
            "granularity": "scenario_attack_time_interval", "windows": selected,
            "capabilities": {"attack_window": True, "alert_labels": False, "pair_labels": False,
                             "incident_membership": False, "chain_nodes_edges_direction": False}}


def map_windows(gt, snapshot):
    ordered = sorted((a["time_us"], aid) for aid, a in snapshot.alerts.items())
    times = [t for t, _ in ordered]
    overlaps, windows = {}, []
    for window in gt["windows"]:
        lo, hi = bisect_left(times, window["start_us"]), bisect_left(times, window["end_us"])
        ids = sorted(aid for _, aid in ordered[lo:hi])
        reps = sorted({snapshot.owner[aid] for aid in ids})
        windows.append({**window, "status": "mapped" if ids else "unmapped", "mapping_kind": "temporal_overlap_only",
                        "alert_ids": ids, "representative_alert_ids": reps, "alert_count": len(ids), "representative_count": len(reps)})
        for aid in ids:
            overlaps.setdefault(aid, []).append(window["window_id"])
    ambiguous_alerts = {aid: sorted(ids) for aid, ids in overlaps.items() if len(ids) > 1}
    return {"total_rows": gt["total_rows"], "selected_rows": gt["selected_rows"], "out_of_scope_rows": gt["out_of_scope_rows"],
            "mapped": sum(bool(w["alert_ids"]) for w in windows), "unmapped": sum(not w["alert_ids"] for w in windows),
            "ambiguous": sum(any(i in ambiguous_alerts for i in w["alert_ids"]) for w in windows),
            "ambiguous_definition": "selected interval has alerts overlapping multiple selected windows (count overlaps mapped)",
            "ambiguous_alert_count": len(ambiguous_alerts), "ambiguous_alerts": ambiguous_alerts,
            "direct_alert_id_mapped": 0, "temporal_overlap_alert_count": len(overlaps),
            "outside_window_alert_count": len(snapshot.alerts) - len(overlaps),
            "quality_evaluation_coverage": 0.0, "temporal_overlap_fraction": len(overlaps) / len(snapshot.alerts),
            "windows": windows, "alert_windows": {aid: sorted(ids) for aid, ids in sorted(overlaps.items())},
            "limitation": "mapped means time overlap only; outside-window alerts are unlabelled, never assumed benign"}
