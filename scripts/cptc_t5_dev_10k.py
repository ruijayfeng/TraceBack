"""Standalone deterministic development selection; no production scoring imports.

Only explicit native IDS fields enter selection. Wrappers are copied unchanged.
Run from the repository root with .venv/Scripts/python.exe scripts/cptc_t5_dev_10k.py.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from fractions import Fraction
import gzip
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.adapters.cptc import load_cptc_dataset, read_cptc_file

VERSION = "cptc-t5-quality-dev-10k-v1"
SOURCE = ROOT / "data/cptc_2018/raw/suricata/suricata_alert_t5.json.gz"
DEST = ROOT / "data/cptc_2018/dev/suricata_alert_t5_dev_10k.json.gz"
OUT = ROOT / "outputs/cptc_t5_dev_10k"
FIELDS = ("timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "flow_id",
          "alert.signature", "alert.signature_id", "alert.category", "alert.severity")
DIMS = ("src_ip", "dst_ip", "src->dst", "src_port", "dst_port", "signature", "signature_id", "category", "flow_id")
PROTECT = ("signature", "src_ip", "dst_ip", "src->dst", "dst_port", "category")


def dumps(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1048576), b""):
            h.update(block)
    return h.hexdigest()


def features(record):
    """Allowlist projection: payload, wrapper metadata and labels never rank records."""
    e = record.eve
    a = e.get("alert", {})
    f = {k: e.get(k) for k in ("timestamp", "src_ip", "src_port", "proto", "flow_id")}
    f.update(dst_ip=e.get("dest_ip"), dst_port=e.get("dest_port"))
    f.update({"alert." + k: a.get(k) for k in ("signature", "signature_id", "category", "severity")})
    for k in ("signature", "signature_id", "category"):
        f[k] = a.get(k)
    f["src->dst"] = (f["src_ip"], f["dst_ip"]) if f["src_ip"] and f["dst_ip"] else None
    t = datetime.fromisoformat(f["timestamp"].replace("Z", "+00:00"))
    if t.tzinfo is None:
        raise ValueError("timestamp_requires_timezone")
    f["time"] = t.astimezone(timezone.utc)
    f["second"] = int(f["time"].timestamp())
    f["fingerprint"] = tuple(f[k] for k in ("signature_id", "src_ip", "dst_ip", "src_port", "dst_port", "proto"))
    f["exact"] = (f["time"].isoformat(), *f["fingerprint"], f["flow_id"])
    has = lambda k: f.get(k) is not None and f.get(k) != ""
    f["quality"] = 6 + sum(w * has(k) for k, w in (
        ("src_ip", 3), ("dst_ip", 3), ("src_port", 1), ("dst_port", 1),
        ("flow_id", 2), ("signature", 3), ("signature_id", 3), ("category", 1),
        ("alert.severity", 1), ("proto", 1))) + 2 * (has("src_ip") and has("dst_ip")) + (has("src_port") and has("dst_port"))
    # Core evidence stays distinct from optional network context. No invented missingness.
    core = all(has(k) for k in ("timestamp", "src_ip", "dst_ip", "signature", "signature_id"))
    context = sum(has(k) for k in ("src_port", "dst_port", "flow_id", "category"))
    f["evidence"] = "High" if core and context >= 2 else "Medium" if core else "Sparse"
    f["index"] = record.ordinal
    # Only allowlisted fields participate in identity tie-breaks.
    f["feature_hash"] = hashlib.sha256(dumps({k: f[k] for k in FIELDS}).encode()).hexdigest()
    return f


def distributions(fs):
    return {k: Counter(f[k] for f in fs if f[k] is not None and f[k] != "") for k in DIMS}


def top(counter, n=30):
    return [{"value": k, "count": v} for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], dumps(kv[0])))[:n]]


def audit(fs):
    d = distributions(fs)
    times = [f["time"] for f in fs]
    buckets = {str(s): Counter(f["second"] // s * s for f in fs) for s in (60, 300, 3600)}
    return {"alerts": len(fs), "time_range": {"min": min(times).isoformat(), "max": max(times).isoformat(),
            "duration_seconds": (max(times) - min(times)).total_seconds()},
        "coverage": {k: {"present": sum(f[k] is not None and f[k] != "" for f in fs),
                         "missing": sum(f[k] is None or f[k] == "" for f in fs),
                         "coverage_ratio": sum(f[k] is not None and f[k] != "" for f in fs) / len(fs)} for k in FIELDS},
        "unique": {k: len(v) for k, v in d.items()},
        "top30": {k: top(d[k]) for k in ("signature", "src_ip", "dst_ip", "src->dst", "dst_port")},
        "evidence": {k: {"count": sum(f["evidence"] == k for f in fs),
                           "ratio": sum(f["evidence"] == k for f in fs) / len(fs)} for k in ("High", "Medium", "Sparse")},
        "quality_distribution": dict(sorted(Counter(f["quality"] for f in fs).items())),
        "exact_duplicate_excess": sum(n - 1 for n in Counter(f["exact"] for f in fs).values()),
        "high_frequency_fingerprints_ge100": [{"value": k, "count": n} for k, n in sorted(Counter(f["fingerprint"] for f in fs).items(), key=lambda kv: (-kv[1], dumps(kv[0]))) if n >= 100],
        "buckets": {s: [{"start_utc": datetime.fromtimestamp(t, timezone.utc).isoformat(), "count": n}
                         for t, n in sorted(b.items())] for s, b in buckets.items()},
        "active_buckets": {s: len(b) for s, b in buckets.items()}}


def select(fs, count=10000):
    d = distributions(fs)
    exact = {}
    burst = Counter((f["fingerprint"], f["second"] // 5) for f in fs)
    fp_counts = Counter(f["fingerprint"] for f in fs)
    for f in fs:
        f["diversity"] = sum((Fraction(1, d[k][f[k]]) for k in PROTECT if f[k] is not None), Fraction())
        f["redundancy"] = burst[f["fingerprint"], f["second"] // 5] + fp_counts[f["fingerprint"]]
    def rank(f):
        return (-f["quality"], -f["diversity"], f["redundancy"], f["time"], f["index"], f["feature_hash"])
    for f in sorted(fs, key=rank):
        exact.setdefault(f["exact"], f)
    pool = list(exact.values())
    if len(pool) < count:
        raise ValueError("insufficient_nonduplicate_records")
    chosen, reasons = {}, defaultdict(set)
    def add(f, reason):
        chosen[f["index"]] = f
        reasons[f["index"]].add(reason)
    # Rare signatures retain every nonduplicate observation. Other rare entities
    # protect their first/last; every value receives at least one representative.
    for f in pool:
        if d["signature"][f["signature"]] <= 10:
            add(f, "rare_signature_le10")
        if f["evidence"] != "High":
            add(f, "non_high_evidence")
    for k in PROTECT:
        groups = defaultdict(list)
        for f in pool:
            if f[k] is not None:
                groups[f[k]].append(f)
        for value, group in groups.items():
            add(min(group, key=rank), "diversity:" + k)
            if d[k][value] <= 10:
                add(min(group, key=lambda f: (f["time"], f["index"])), "rare_first:" + k)
                add(max(group, key=lambda f: (f["time"], f["index"])), "rare_last:" + k)
    # Preserve overall endpoints and 1-minute active coverage.
    for func in (min, max):
        add(func(pool, key=lambda f: (f["time"], f["index"])), "time_endpoint")
    minutes = defaultdict(list)
    for f in pool:
        minutes[f["second"] // 60].append(f)
    for group in minutes.values():
        add(min(group, key=rank), "active_minute")
    # Fingerprint burst endpoints are protected when feasible. Never silently
    # discard required protections to reach a nominal size.
    bursts = defaultdict(list)
    for f in pool:
        bursts[f["fingerprint"], f["second"] // 5].append(f)
    endpoints = set()
    for group in bursts.values():
        if len(group) > 1:
            endpoints.update((min(group, key=lambda f: (f["time"], f["index"]))["index"],
                              max(group, key=lambda f: (f["time"], f["index"]))["index"]))
    fingerprints = defaultdict(list)
    for f in pool:
        fingerprints[f["fingerprint"]].append(f)
    fingerprint_endpoints = set()
    for group in fingerprints.values():
        if len(group) > 1:
            fingerprint_endpoints.update((min(group, key=lambda f: (f["time"], f["index"]))["index"],
                                         max(group, key=lambda f: (f["time"], f["index"]))["index"]))
    for f in pool:
        if f["index"] in endpoints:
            add(f, "burst_endpoint")
        if f["index"] in fingerprint_endpoints:
            add(f, "fingerprint_endpoint")
    if len(chosen) > count:
        raise ValueError("mandatory_protection_exceeds_budget")
    # Equalized temporal/signature strata: repeatedly fill the least represented
    # (minute, signature) cell, then the least represented signature globally.
    cells = defaultdict(list)
    for f in pool:
        if f["index"] not in chosen:
            cells[f["second"] // 60, f["signature"]].append(f)
    for group in cells.values():
        group.sort(key=lambda f: (f["index"] not in endpoints, rank(f)), reverse=True)
    cc = Counter((f["second"] // 60, f["signature"]) for f in chosen.values())
    sc = Counter(f["signature"] for f in chosen.values())
    mc = Counter(f["second"] // 60 for f in chosen.values())
    import heapq
    heap = [(cc[k], sc[k[1]], mc[k[0]], k) for k, g in cells.items() if g]
    heapq.heapify(heap)
    while len(chosen) < count:
        old_c, old_s, old_m, k = heapq.heappop(heap)
        current = (cc[k], sc[k[1]], mc[k[0]], k)
        if (old_c, old_s, old_m, k) != current:
            heapq.heappush(heap, current)
            continue
        f = cells[k].pop()
        add(f, "temporal_signature_quota")
        cc[k] += 1
        sc[k[1]] += 1
        mc[k[0]] += 1
        if cells[k]:
            heapq.heappush(heap, (cc[k], sc[k[1]], mc[k[0]], k))
    ordered = sorted(chosen.values(), key=lambda f: (f["time"], f["index"], f["feature_hash"]))
    return ordered, reasons, {"burst_endpoint_candidates": len(endpoints),
        "burst_endpoints_retained": len(endpoints & set(chosen)), "nonduplicate_pool": len(pool),
        "fingerprint_endpoint_candidates": len(fingerprint_endpoints),
        "fingerprint_endpoints_retained": len(fingerprint_endpoints & set(chosen))}


def write_dataset(records, selected, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    by_index = {r.ordinal: r.wrapper for r in records}
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as out:
            out.write(b"[")
            for i, f in enumerate(selected):
                if i:
                    out.write(b",")
                out.write(dumps(by_index[f["index"]]).encode("utf8"))
            out.write(b"]\n")


def validate(path):
    adapter = load_cptc_dataset(ROOT).adapters["t5"]
    raw = parsed = converted = rejected = 0
    ids = set()
    errors = Counter()
    for r in read_cptc_file(path):
        raw += 1
        if r.error:
            rejected += 1
            errors[r.error] += 1
            continue
        parsed += 1
        try:
            a = adapter.convert(r.eve)
        except (ValueError, TypeError, KeyError) as exc:
            rejected += 1
            errors[str(exc)] += 1
        else:
            converted += 1
            ids.add(a.alert_id)
    return {"raw": raw, "parsed": parsed, "rejected": rejected, "canonical_records": converted,
            "canonical_unique_ids": len(ids), "errors": dict(errors)}


def run():
    before_hash = sha(SOURCE)
    records = list(read_cptc_file(SOURCE))
    if any(r.error for r in records):
        raise ValueError("source_reader_rejection_requires_review")
    fs = [features(r) for r in records]
    before = audit(fs)
    selected, reasons, protection = select(fs)
    after = audit(selected)
    OUT.mkdir(parents=True, exist_ok=True)
    write_dataset(records, selected, DEST)
    first_hash = sha(DEST)
    again, _, _ = select([features(r) for r in records])
    second_path = OUT / "determinism_run2.json.gz"
    write_dataset(records, again, second_path)
    second_hash = sha(second_path)
    validation = validate(DEST)
    assert len(selected) == 10000 and first_hash == second_hash
    assert before_hash == sha(SOURCE)
    assert validation["raw"] == validation["parsed"] == validation["canonical_records"] == 10000
    assert validation["rejected"] == 0
    bd, ad = distributions(fs), distributions(selected)
    retention = {k: {"before": len(bd[k]), "after": len(ad[k]), "ratio": len(ad[k]) / len(bd[k]) if bd[k] else None} for k in DIMS}
    rare = {s for s, n in bd["signature"].items() if n <= 10}
    rare_info = {"unique_before": len(rare), "unique_after": len(rare & set(ad["signature"])),
                 "records_before": sum(bd["signature"][s] for s in rare),
                 "records_after": sum(ad["signature"][s] for s in rare)}
    limitations = []
    if not after["evidence"]["Sparse"]["count"] or after["evidence"]["Medium"]["ratio"] < .01:
        limitations.append("Source has only four optional-context-missing alerts and zero Sparse alerts; no fields were removed. The requested visible Medium/Sparse composition cannot be met from t5.")
    if protection["burst_endpoints_retained"] != protection["burst_endpoint_candidates"]:
        limitations.append("Not all 5-second fingerprint burst endpoints fit the diversity-balanced 10k sample; endpoint retention is reported explicitly. Full protection requires review of the capacity tradeoff.")
    result = "CPTC_T5_DEV_10K_REQUIRES_REVIEW" if limitations else "CPTC_T5_DEV_10K_ACCEPTED"
    manifest = {"dataset": "CPTC-2018", "partition": "t5", "purpose": "TraceBack correlation algorithm development",
        "selection_version": VERSION, "raw_count": len(fs), "selected_count": len(selected),
        "selection_uses_correlation_result": False, "selection_uses_attack_labels": False, "random_sampling": False,
        "source_sha256": before_hash, "output_sha256": first_hash, "source_time_range": before["time_range"],
        "selected_time_range": after["time_range"], "result": result, "limitations": limitations,
        "source_file": SOURCE.relative_to(ROOT).as_posix(), "output_file": DEST.relative_to(ROOT).as_posix(),
        "parameters": {"target": 10000, "time_bucket_seconds": 60, "burst_seconds": 5, "rare_max_count": 10,
                       "high_context_min": 2, "exact_duplicate_copies": 1},
        "reader_adapter_validation": validation, "retention": retention, "rare_signatures": rare_info,
        "protection": protection, "determinism": {"run1_sha256": first_hash, "run2_sha256": second_hash},
        "source_unchanged": True, "script_sha256": sha(Path(__file__))}
    manifest_path = DEST.parent / "t5_dev_10k_manifest.json"
    manifest_path.write_text(dumps(manifest) + "\n", encoding="utf8")
    (OUT / "audit_before_after.json").write_text(dumps({"before": before, "after": after}) + "\n", encoding="utf8")
    with (OUT / "selection_audit.jsonl").open("w", encoding="utf8") as handle:
        chosen_ids = {f["index"] for f in selected}
        for f in fs:
            handle.write(dumps({"raw_index": f["index"], "selected": f["index"] in chosen_ids,
                "selection_quality_score": f["quality"], "diversity_value": str(f["diversity"]),
                "redundancy_score": f["redundancy"], "evidence": f["evidence"],
                "reasons": sorted(reasons.get(f["index"], ()))}) + "\n")
    rows = ["# CPTC t5 development selection report", "", "## 1. Task Result", "", result, "",
        "This 10k artifact is a review candidate, not an accepted development baseline." if limitations else "Accepted development baseline.",
        "", "\n".join(limitations), "", "## 2. Source Dataset", "", SOURCE.relative_to(ROOT).as_posix(),
        "", "SHA256: " + before_hash, "", "## 3. Selection Method", "",
        "Quality-aware, Diversity-aware, Temporal-preserving, Deterministic. No Correlation leakage; no ground-truth leakage.",
        "Only the eleven allowlisted native fields are projected. Splunk wrappers and _raw strings are preserved; no field masking.",
        "Quality uses requested additive weights (flow_id intentionally contributes twice), max 28. Timestamp must parse with timezone; reader-invalid records abort rather than enter selection.",
        "Diversity is the exact rational sum of inverse source frequencies across signature, src, dst, pair, destination port and category. Redundancy is 5-second fingerprint count plus global fingerprint count.",
        "Exact key: normalized timestamp, signature_id, src/dst, ports, protocol, flow_id; one best-ranked copy. No claim that distinct payloads are identical.",
        "Protect rare signatures <=10, every entity/signature/category value, rare entity endpoints, all non-High records, active minutes and global time endpoints. Stop if mandatory protections exceed capacity.",
        "Fill least represented (minute, signature) cells, then global signature/minute counts. Prefer short-burst endpoints, then quality DESC, diversity DESC, redundancy ASC, timestamp, source ordinal, allowlist hash. No randomness.",
        "All multi-record 5-second fingerprint burst endpoints and multi-record fingerprint first/last observations are mandatory protections; selection aborts if these protections exceed capacity. Singleton fingerprints/bursts remain eligible under quotas.",
        "", "## 4. Before / After", "", "|Metric|Before|After|", "|---|---:|---:|", f"|Alerts|{len(fs)}|{len(selected)}|"]
    rows += [f"|{k}|{v['before']}|{v['after']}|" for k, v in retention.items()]
    rows += ["", "Time ranges: " + dumps({"before": before["time_range"], "after": after["time_range"]}),
        "", "## 5. Signature Retention", "", dumps(retention["signature"]), "", "Rare signatures: " + dumps(rare_info),
        "", "## 6. Entity Retention", "", dumps({k: retention[k] for k in ("src_ip", "dst_ip", "src->dst", "dst_port")}),
        "", "## 7. Temporal Retention", "", dumps({"before": before["active_buckets"], "after": after["active_buckets"]}),
        "Per-minute, 5-minute and hourly counts (UTC fixed buckets) are in audit_before_after.json, including every active bucket.",
        "", "## 8. Evidence Completeness", "", "High: all five core fields + >=2 of src_port/dst_port/flow_id/category. Medium: core complete with <2 context fields. Sparse: incomplete core. These are selection-only classes.",
        "", dumps({"before": before["evidence"], "after": after["evidence"]}),
        "", "## 9. Duplicate / Noise Reduction", "", dumps({"exact_excess_before": before["exact_duplicate_excess"], "exact_excess_after": after["exact_duplicate_excess"], "protection": protection}),
        "High-frequency fingerprint groups (>=100 records), Top30 signature/src/dst/pair/port counts and complete field coverage are in audit_before_after.json.",
        "", "## 10. Bias Audit", "", "Correlation Score used: NO\n\nCorrelationEdge used: NO\n\nIncident used: NO\n\nChainEdge used: NO\n\nGround-truth attack labels used: NO\n\nRandom sampling used: NO",
        "Selection uses no severity importance, stage, attack identity, labels, algorithm outputs or payload text. No production correlation imports/calls. Existing reader rejects annotation contamination; no truth files are opened.",
        "", "## 11. Reader / Adapter Validation", "", dumps(validation),
        "Canonical records and unique stable IDs are reported separately; no dedupe/correlation/clustering pipeline was run.",
        "", "## 12. Reproduction and Files", "", "`.venv/Scripts/python.exe scripts/cptc_t5_dev_10k.py`", "",
        "Two separate selection/write runs produce identical gzip SHA256 (mtime=0, empty gzip filename). Source hash is checked before/after.",
        "", dumps(manifest["determinism"]), "", "Outputs: development gzip and manifest; this report; audit_before_after.json; selection_audit.jsonl; determinism_run2.json.gz. Script and backend/tests/test_cptc_t5_dev_10k.py are the only implementation/test additions.",
        "", "The development selection intentionally rebalances signatures and time; it is not an unbiased prevalence estimate or an independent test split. Do not report performance on it as independent generalization.",
        "", "DEVELOPMENT_DATASET = suricata_alert_t5_dev_10k.json.gz\n\nSELECTED_COUNT = 10000\n\nCORRELATION_ALGORITHM_MODIFIED = NO\n\nCORRELATION_RESULT_USED_FOR_SELECTION = NO\n\nATTACK_LABEL_USED_FOR_SELECTION = NO\n\nRANDOM_SAMPLING_USED = NO", ""]
    rows += ["## 13. Field Coverage", "", "|Field|Before present/missing/ratio|After present/missing/ratio|",
             "|---|---:|---:|"]
    for k in FIELDS:
        b, a = before["coverage"][k], after["coverage"][k]
        rows.append(f"|{k}|{b['present']}/{b['missing']}/{b['coverage_ratio']:.6f}|{a['present']}/{a['missing']}/{a['coverage_ratio']:.6f}|")
    rows += ["", "## 14. Top 30 Before / After", ""]
    for k in ("signature", "src_ip", "dst_ip", "src->dst", "dst_port"):
        rows += ["### " + k, "", "|Value|Before|After|", "|---|---:|---:|"]
        values = list(dict.fromkeys([item["value"] if not isinstance(item["value"], list) else tuple(item["value"])
                                    for item in before["top30"][k] + after["top30"][k]]))
        for value in values:
            label = dumps(value).replace("|", "\\|")
            rows.append(f"|{label}|{bd[k][value]}|{ad[k][value]}|")
        rows.append("")
    rows += ["## 15. High-frequency Fingerprints", "",
        "Fingerprint frequency >=100: " + dumps({"before": before["high_frequency_fingerprints_ge100"],
                                                 "after": after["high_frequency_fingerprints_ge100"]}), "",
        "## 16. Tests", "", "Executed test evidence is recorded in TEST_RESULTS.md and pytest_results.xml beside this report.", ""]
    (OUT / "CPTC_T5_DEV_10K_SELECTION_REPORT.md").write_text("\n".join(rows), encoding="utf8")
    print(dumps(manifest))
    return manifest


if __name__ == "__main__":
    run()
