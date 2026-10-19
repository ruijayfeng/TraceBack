"""Offline threshold scan on the already scored, valid production candidates."""

import math
from evaluation.metrics.classification import unavailable_quality


def threshold_counts(scores, thresholds):
    if any(not math.isfinite(s) or not 0 <= s <= 1 for s in scores):
        raise ValueError("invalid_score")
    if any(type(t) not in (float, int) or not math.isfinite(t) or not 0 <= t <= 1 for t in thresholds):
        raise ValueError("invalid_threshold")
    return [{"threshold": t, "predicted_edge_count": sum(s >= t for s in scores)} for t in sorted(set(thresholds))]


def run_sensitivity(db, frozen_threshold, configured):
    maximum, p50, p90, p99 = db.execute("SELECT max(score),quantile_cont(score,.5),quantile_cont(score,.9),quantile_cont(score,.99) FROM selected_scores").fetchone()
    thresholds = sorted(set([frozen_threshold, *configured, *(s for s in (maximum, p50, p90, p99) if s is not None)]))
    rows = []
    for t in thresholds:
        if not math.isfinite(t) or not 0 <= t <= 1:
            raise ValueError("invalid_threshold")
        count = db.execute("SELECT count(*) FROM selected_scores WHERE score>=?", [t]).fetchone()[0]
        rows.append({"threshold": t, "is_production_threshold": t == frozen_threshold, "predicted_edge_count": count,
                     "quality": unavailable_quality(), "scope": "score-only; same admitted pairs and hard guards",
                     "changes_production_configuration": False})
    if any(a["predicted_edge_count"] < b["predicted_edge_count"] for a, b in zip(rows, rows[1:])):
        raise ValueError("threshold_scan_not_monotonic")
    return rows
