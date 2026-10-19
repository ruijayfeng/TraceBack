"""Exact baseline pair counts using range bitsets, never dense pair lists."""

from collections import defaultdict
from types import SimpleNamespace
import time

from app.correlation.index import TemporalPosting
from evaluation.metrics.classification import unavailable_quality


def baseline_counts(snapshot, window_seconds=300, overlap_alert_ids=None):
    if type(window_seconds) not in (int, float) or window_seconds <= 0:
        raise ValueError("invalid_baseline_window")
    started = time.perf_counter()
    reps = sorted(snapshot.groups)
    index = SimpleNamespace(times={i: a["time_us"] for i, a in snapshot.alerts.items()},
                            positions={r: p for p, r in enumerate(reps)}, owner=snapshot.owner)
    postings = defaultdict(list)
    for aid, a in snapshot.alerts.items():
        for eid in a["entity_ids"]:
            postings[eid].append(aid)
    by_entity = {eid: TemporalPosting(ids, index) for eid, ids in postings.items()}
    time_posting = TemporalPosting(snapshot.alerts, index)
    ip_ids = {eid for eid, e in snapshot.entities.items() if e["type"] == "IP"}
    inside_reps = {snapshot.owner[i] for i in (overlap_alert_ids or ())}
    inside_mask = sum(1 << index.positions[r] for r in inside_reps)
    width = int(window_seconds * 1000000)
    totals = dict.fromkeys(("time_only", "time_ip", "time_all_entities"), 0)
    inside = totals.copy()
    for rep in reps:
        masks = dict.fromkeys(totals, 0)
        for aid in snapshot.groups[rep]:
            center = index.times[aid]
            masks["time_only"] |= time_posting.mask(center - width, center + width)
            for eid in snapshot.alerts[aid]["entity_ids"]:
                mask = by_entity[eid].mask(center - width, center + width)
                masks["time_all_entities"] |= mask
                if eid in ip_ids:
                    masks["time_ip"] |= mask
        for method, mask in masks.items():
            mask &= ~(1 << index.positions[rep])
            totals[method] += mask.bit_count()
            if rep in inside_reps:
                inside[method] += (mask & inside_mask).bit_count()
    return [{"method": method, "window_seconds": window_seconds, "predicted_edge_count": n // 2,
             "endpoint_groups_overlapping_windows": inside[method] // 2 if overlap_alert_ids is not None else None, "runtime_seconds": time.perf_counter() - started,
             "quality": unavailable_quality(), "candidate_recall": None,
             "scope": "same full input, normalization, dedupe groups; any actual member pair qualifies",
             "candidate_policy": "all baseline window matches counted exactly by bitsets; no production Top-K",
             "direction_assumption": "no causal chain published; equal timestamps have no inferred direction",
             "limitation": "window overlap is temporal context, not attack/benign pair labels"}
            for method, n in totals.items()]
