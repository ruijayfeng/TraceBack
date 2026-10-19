"""Deterministic, label-free AIT-ADS derivatives. Runs adapters only.

Audit is a separate first phase. Build requires its unchanged-source receipt.
No production registry, configuration, identity or algorithm is modified.
"""

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import re
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.adapters import AMinerAdapter, WazuhAdapter
from app.adapters.base import reject_truth
from app.models.base import resolve_pointer
from app.services.capacity import json_array_records
from app.services.datasets import load_dataset, read_registry, source_contexts
from app.services.storage import file_digest
from app.utils.stable_id import content_digest, id_for, raw_fingerprint, utc_text

ROLES = {"russellmitchell": "development", "fox": "validation"}
NAMES = {"russellmitchell": "russellmitchell_dev_small", "fox": "fox_validation_small"}
SELECTION_RULE = {
    "version": "midpoint_symmetric_minutes_v1",
    "anchor": "floor_to_minute(midpoint_of_aminer_wazuh_observed_time_overlap)",
    "window": "inclusive [anchor - n minutes, anchor + n minutes], n >= 1",
    "order": "increasing n; never move anchor or omit in-window records",
    "initial_size": "first window with at least 7500 raw records and both sources present",
    "adapter_adjustment": "only if unique CanonicalAlert count < 5000, increase n until >= 5000",
    "preferred_canonical_range": [5000, 10000],
    "permitted_canonical_range": [3000, 12000],
    "oversize": "fail if canonical count > 12000; no content-based reselection",
    "inputs": "timestamps, raw counts, source presence, adapter counts and integrity only",
}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                               allow_nan=False) + "\n", encoding="utf-8")


def source_format(path):
    with path.open(encoding="utf-8-sig") as handle:
        first = next((c for c in iter(lambda: handle.read(1), "") if not c.isspace()), "")
    if not first:
        raise ValueError("empty_source_file")
    return "json_array" if first == "[" else "jsonl"


def records(path):
    """Bounded array/JSONL reader; malformed/mixed input fails the audit."""
    if source_format(path) == "json_array":
        with path.open(encoding="utf-8-sig") as handle:
            yield from json_array_records(handle)
    else:
        with path.open(encoding="utf-8-sig") as handle:
            for line in handle:
                if line.strip():
                    yield json.loads(line)


def adapter_for(loaded, source):
    namespace = next(k for k, (s, _) in loaded.sources.items() if s == source)
    setting = loaded.sources[namespace][1]
    return (AMinerAdapter if source == "aminer" else WazuhAdapter)(loaded.config, setting)


def raw_timestamp(raw, source, adapter):
    reject_truth(raw)
    if source == "aminer":
        values = raw["LogData"]["DetectionTimestamp"]
        if type(values) is not list or not values:
            raise ValueError("missing_detection_timestamp")
        value, pointer = values[-1], f"/LogData/DetectionTimestamp/{len(values) - 1}"
    else:
        pointer = "/@timestamp" if raw.get("@timestamp") not in (None, "") else "/timestamp"
        value = resolve_pointer(raw, pointer)
    return adapter.parse_time(value), value, pointer


def timestamp_shape(value, adapter):
    if type(value) in (int, float):
        digits = max(0, -Decimal(str(value)).as_tuple().exponent)
        return f"epoch_{adapter.settings.epoch_unit}:fraction_digits={digits}"
    match = re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?", str(value))
    return (f"ISO8601:fraction_digits={len(match[1] or '')}:offset={match[2] or 'configured_timezone'}"
            if match else "other_explicitly_adapter_parsed_format")


def selected_inputs(root, dataset):
    if dataset not in ROLES:
        raise ValueError("hold_out_content_access_forbidden")
    loaded = load_dataset(root, scene_id=dataset, config_version="v4")
    if loaded.missing_files:
        raise ValueError("missing_sources:" + str(loaded.missing_files))
    return loaded, {i["source"]: root / i["path"] for i in loaded.inputs}


def audit_source(root, path, source, adapter):
    before = file_digest(path)
    hourly, daily, shapes, pointers = Counter(), Counter(), Counter(), Counter()
    earliest = latest = None
    count = 0
    for raw in records(path):
        if type(raw) is not dict or not raw:
            raise ValueError("malformed_or_mixed_json")
        stamp, value, pointer = raw_timestamp(raw, source, adapter)
        count += 1
        earliest = stamp if earliest is None else min(earliest, stamp)
        latest = stamp if latest is None else max(latest, stamp)
        hourly[stamp[:13] + ":00:00Z"] += 1
        daily[stamp[:10]] += 1
        shapes[timestamp_shape(value, adapter)] += 1
        pointers[pointer] += 1
    if not count or file_digest(path) != before:
        raise ValueError("empty_or_changed_source")
    duration = (parse_time(latest) - parse_time(earliest)).total_seconds()
    return {"source": source, "path": path.relative_to(root).as_posix(), "raw_count": count,
            "first_timestamp": earliest, "last_timestamp": latest, "duration_seconds": duration,
            "timezone": loaded_timezone(adapter), "source_namespace": adapter.settings.source_namespace,
            "adapter_settings": adapter.settings.snapshot(), "format": source_format(path),
            "timestamp_formats": dict(sorted(shapes.items())), "timestamp_paths": dict(sorted(pointers.items())),
            "timestamp_parse_success_count": count, "timestamp_parse_error_count": 0,
            "records_per_hour": count * 3600 / duration if duration else None,
            "records_per_day": count * 86400 / duration if duration else None,
            "hourly_counts": dict(sorted(hourly.items())), "daily_counts": dict(sorted(daily.items())),
            "sha256": before}


def loaded_timezone(adapter):
    return adapter.normalization.source_timezones[adapter.settings.source_namespace]


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def audit(root):
    """Read exactly the four requested raw files, never hold-out or labels."""
    result = {"audit_version": "v1", "selection_rule_precommitted": SELECTION_RULE,
              "ground_truth": "NOT_USED", "datasets": {}, "hold_out": {}}
    registry = read_registry(root)
    for dataset in sorted(ROLES):
        loaded, paths = selected_inputs(root, dataset)
        result["datasets"][dataset] = {
            s: audit_source(root, p, s, adapter_for(loaded, s)) for s, p in sorted(paths.items())}
        print(json.dumps({"phase": "audit", "dataset": dataset,
                          "counts": {s: f["raw_count"] for s, f in result["datasets"][dataset].items()}}), flush=True)
    for dataset in registry.scenes:
        if dataset not in ROLES:
            result["hold_out"][dataset] = {"directory_exists": (root / "data/ait_ads" / dataset).is_dir(),
                                           "content_read": False}
    output = root / "outputs/ait_ads_slices"
    write_json(output / "DATASET_TIME_PROFILE.json", result)
    lines = ["# AIT-ADS time profile", "", "Phase 1/2 only; no slice generated by audit.", "",
             "Labels: NOT USED. Hold-out: directory existence only. Times and bins are UTC.", "",
             "Software generator versions remain unknown; the existing confirmed AIT-ADS dataset/profile version is 1.", "",
             "Mean rates = count / observed elapsed duration; hourly/daily tables include zero bins.", "",
             "| dataset | source | raw_count | first_timestamp | last_timestamp | duration seconds | timezone | records/hour | records/day |",
             "| --- | --- | ---: | --- | --- | ---: | --- | ---: | ---: |"]
    for dataset, sources in sorted(result["datasets"].items()):
        for source, f in sorted(sources.items()):
            lines.append(f"| {dataset} | {source} | {f['raw_count']} | {f['first_timestamp']} | {f['last_timestamp']} | {f['duration_seconds']} | {f['timezone']} | {f['records_per_hour']} | {f['records_per_day']} |")
    for dataset, sources in sorted(result["datasets"].items()):
        lines += ["", f"## {dataset}", ""]
        for source, f in sorted(sources.items()):
            lines += [f"- {source}: `{f['path']}`; {f['format']}; namespace `{f['source_namespace']}`.",
                      f"  Timestamp paths/counts: `{json.dumps(f['timestamp_paths'], sort_keys=True)}`.",
                      f"  Formats/precision/counts: `{json.dumps(f['timestamp_formats'], sort_keys=True)}`.",
                      "  UTC output uses existing adapter microsecond normalization; original values are retained."]
        for kind, step in (("hourly", timedelta(hours=1)), ("daily", timedelta(days=1))):
            lines += ["", f"### {kind} raw alert counts", "", "| UTC bin | AMiner | Wazuh (includes embedded Suricata) | total |", "| --- | ---: | ---: | ---: |"]
            start = min(parse_time(f["first_timestamp"]) for f in sources.values())
            end = max(parse_time(f["last_timestamp"]) for f in sources.values())
            start = start.replace(minute=0, second=0, microsecond=0)
            if kind == "daily":
                start = start.replace(hour=0)
            while start <= end:
                key = start.strftime("%Y-%m-%dT%H:00:00Z" if kind == "hourly" else "%Y-%m-%d")
                counts = [sources[s][kind + "_counts"].get(key, 0) for s in ("aminer", "wazuh")]
                lines.append(f"| {key} | {counts[0]} | {counts[1]} | {sum(counts)} |")
                start += step
    (output / "DATASET_TIME_PROFILE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return result


def choose_window(stamps, profiles, *, target=7500):
    overlap_start = max(parse_time(f["first_timestamp"]) for f in profiles.values())
    overlap_end = min(parse_time(f["last_timestamp"]) for f in profiles.values())
    if overlap_start >= overlap_end:
        raise ValueError("no_cross_source_time_overlap")
    anchor = (overlap_start + (overlap_end - overlap_start) / 2).replace(second=0, microsecond=0)
    max_minutes = int(min((anchor - overlap_start).total_seconds(), (overlap_end - anchor).total_seconds()) // 60)
    from bisect import bisect_left, bisect_right
    for n in range(1, max_minutes + 1):
        start, end = utc_text(anchor - timedelta(minutes=n)), utc_text(anchor + timedelta(minutes=n))
        counts = {s: bisect_right(times, end) - bisect_left(times, start) for s, times in stamps.items()}
        if sum(counts.values()) >= target and all(counts.values()):
            return start, end, anchor, n, max_minutes
    raise ValueError("no_complete_midpoint_window_reaches_target")


def write_window(path, source_path, source, adapter, start, end):
    """Keep every in-window original object in its original physical order."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fmt = source_format(source_path)
    count, identities = 0, {}
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        if fmt == "json_array":
            handle.write("[\n")
        for raw in records(source_path):
            stamp, _, _ = raw_timestamp(raw, source, adapter)
            if start <= stamp <= end:
                alert = adapter.convert(raw)
                if alert.timestamp != stamp or alert.raw_alert != raw or alert.raw_fingerprint != raw_fingerprint(raw):
                    raise ValueError("source_raw_traceability_failure")
                if alert.alert_id != id_for("CanonicalAlert", alert):
                    raise ValueError("source_stable_id_failure")
                value = alert.canonical_json()
                if alert.alert_id in identities and identities[alert.alert_id] != value:
                    raise ValueError("same_alert_id_conflicting_content")
                identities[alert.alert_id] = value
                text = json.dumps(raw, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
                if fmt == "json_array" and count:
                    handle.write(",\n")
                handle.write(text + ("\n" if fmt == "jsonl" else ""))
                count += 1
        if fmt == "json_array":
            handle.write("\n]\n")
    return count, identities


def validate_slice(path, adapter, identities, start, end):
    # Real existing file ingress, not a substitute implementation.
    batch = adapter.read_file(path)
    if batch.rejected or not batch.alerts or len(batch.alerts) != len(identities):
        raise ValueError("adapter_slice_failure:" + str(batch.rejection_reasons))
    for alert in batch.alerts:
        if not start <= alert.timestamp <= end:
            raise ValueError("out_of_window_record")
        if alert.source_namespace != adapter.settings.source_namespace:
            raise ValueError("source_namespace_changed")
        if alert.canonical_json() != identities.get(alert.alert_id):
            raise ValueError("full_vs_slice_identity_or_content_changed")
        if alert.raw_fingerprint != raw_fingerprint(alert.raw_alert):
            raise ValueError("raw_traceability_failure")
        for provenance in alert.field_provenance.values():
            resolve_pointer(alert.raw_alert, provenance.raw_pointer)
    return batch


def protected_hashes(root):
    files = [root / "AGENTS.md", root / "data/ait_ads/dataset.yaml"]
    for folder in ("backend/app", "configs", "docs", "frontend/src"):
        files += [p for p in (root / folder).rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    return {p.relative_to(root).as_posix(): file_digest(p) for p in sorted(files) if p.is_file()}


def publish_immutable(staged, destination):
    """Existing identical derivatives are reused; different ones are refused."""
    paths = [p for p in staged.rglob("*") if p.is_file()]
    if destination.exists():
        expected = {p.relative_to(staged).as_posix(): file_digest(p) for p in paths}
        actual = {p.relative_to(destination).as_posix(): file_digest(p)
                  for p in destination.rglob("*") if p.is_file()}
        if expected != actual:
            raise ValueError("existing_slice_differs_refusing_overwrite")
        return
    staged.rename(destination)
    for p in destination.rglob("*"):
        if p.is_file():
            p.chmod(stat.S_IREAD)


def build(root, dataset, profile):
    loaded, paths = selected_inputs(root, dataset)
    profiles = profile["datasets"][dataset]
    if profile["selection_rule_precommitted"] != SELECTION_RULE:
        raise ValueError("audit_selection_rule_mismatch")
    before = {s: file_digest(p) for s, p in paths.items()}
    if before != {s: f["sha256"] for s, f in profiles.items()}:
        raise ValueError("source_changed_since_audit")
    adapters = {s: adapter_for(loaded, s) for s in paths}
    if {s: p.relative_to(root).as_posix() for s, p in paths.items()} != {s: f["path"] for s, f in profiles.items()}:
        raise ValueError("audit_source_path_mismatch")
    stamps = {s: sorted(raw_timestamp(raw, s, adapters[s])[0] for raw in records(p)) for s, p in paths.items()}
    start, end, anchor, n, maximum = choose_window(stamps, profiles)
    output_base = root / "data/ait_ads/slices"
    output_base.mkdir(parents=True, exist_ok=True)
    attempts = []
    with tempfile.TemporaryDirectory(prefix=".slice-build-", dir=output_base) as temporary:
        staged = Path(temporary) / NAMES[dataset]
        for minute in range(n, maximum + 1):
            start, end = utc_text(anchor - timedelta(minutes=minute)), utc_text(anchor + timedelta(minutes=minute))
            counts, full_ids, batches = {}, {}, {}
            for source, path in sorted(paths.items()):
                target = staged / "raw" / (source + ".json")
                counts[source], full_ids[source] = write_window(target, path, source, adapters[source], start, end)
                if source_format(target) != profiles[source]["format"]:
                    raise ValueError("source_format_changed")
                batches[source] = validate_slice(target, adapters[source], full_ids[source], start, end)
            alerts = [a for s in sorted(batches) for a in batches[s].alerts]
            canonical_count = len(alerts)
            attempts.append({"start_timestamp": start, "end_timestamp": end, "raw_counts": counts,
                             "canonical_alert_count": canonical_count})
            if canonical_count >= 5000:
                break
        else:
            raise ValueError("canonical_target_not_reached")
        if canonical_count > 12000:
            raise ValueError("canonical_window_exceeds_permitted_size")
        if not all(counts.values()):
            raise ValueError("missing_source_in_window")
        slice_hashes = {s: file_digest(staged / "raw" / (s + ".json")) for s in sorted(paths)}
        # Independent second filtering pass, byte-for-byte comparison.
        for source, path in sorted(paths.items()):
            repeat_path = Path(temporary) / "repeat" / "raw" / (source + ".json")
            repeated_count, repeated_ids = write_window(repeat_path, path, source, adapters[source], start, end)
            if repeated_count != counts[source] or repeated_ids != full_ids[source] or file_digest(repeat_path) != slice_hashes[source]:
                raise ValueError("non_deterministic_slice")
        if choose_window(stamps, profiles)[:2] != (attempts[0]["start_timestamp"], attempts[0]["end_timestamp"]):
            raise ValueError("non_deterministic_selection")
        if {s: file_digest(p) for s, p in paths.items()} != before:
            raise ValueError("original_files_changed")
        unique_stamps = sorted({a.timestamp for a in alerts})
        max_gap = max(((parse_time(b) - parse_time(a)).total_seconds()
                       for a, b in zip(unique_stamps, unique_stamps[1:])), default=0)
        distribution = lambda field: dict(sorted(Counter(getattr(a, field).value for a in alerts).items()))
        entity_proxy = {}
        for field in ("host", "account", "session", "src_ip", "dst_ip", "src_port", "dst_port", "url", "domain", "file", "command"):
            frequencies = Counter(str(getattr(a, field)) for a in alerts if getattr(a, field) is not None)
            entity_proxy[field] = {"present_alert_count": sum(frequencies.values()), "distinct_values": len(frequencies),
                                   "singleton_values": sum(c == 1 for c in frequencies.values()),
                                   "repeated_values": sum(c > 1 for c in frequencies.values()),
                                   "max_frequency": max(frequencies.values(), default=0)}
        duplicate_shapes = Counter(content_digest({"source_namespace": a.source_namespace, "source_type": a.source_type.value,
            "rule_id": a.rule_id, "alert_type": a.alert_type, "host": a.host, "src_ip": a.src_ip, "dst_ip": a.dst_ip,
            "src_port": a.src_port, "dst_port": a.dst_port, "account": a.account, "signature": a.signature}) for a in alerts)
        manifest = {
            "slice_version": "v1", "source_dataset": dataset,
            "purpose": "correlation_" + ROLES[dataset], "selection_method": "continuous_time_window",
            "selection_rule": SELECTION_RULE, "window_semantics": "inclusive [start_timestamp,end_timestamp]",
            "start_timestamp": start, "end_timestamp": end, "timezone": "UTC",
            "duration_seconds": (parse_time(end) - parse_time(start)).total_seconds(),
            "selection_anchor": utc_text(anchor), "selection_attempts": attempts,
            "selection_reason": "Fixed midpoint of the two observed source ranges; smallest symmetric minute window reaching size target. Both sources included; no labels or correlation outputs consulted.",
            "raw_counts": counts, "canonical_alert_count": canonical_count,
            "source_type_counts": distribution("source_type"), "severity_counts": distribution("severity"),
            "category_counts": distribution("category"), "alert_type_counts": dict(sorted(Counter(a.alert_type or "<missing>" for a in alerts).items())),
            "source_namespace_counts": dict(sorted(Counter(a.source_namespace for a in alerts).items())),
            "source_files": {s: p.relative_to(root).as_posix() for s, p in sorted(paths.items())},
            "source_sha256": before, "slice_sha256": slice_hashes,
            "slice_content_sha256": content_digest(slice_hashes),
            "source_formats": {s: source_format(p) for s, p in paths.items()},
            "adapter_config_hash": loaded.config.config_hash, "adapter_settings": {s: a.settings.snapshot() for s, a in adapters.items()},
            "canonical_identity_sha256": content_digest(sorted([a.alert_id, a.raw_fingerprint] for a in alerts)),
            "duplicate_import_count": sum(b.duplicate_import_count for b in batches.values()),
            "adapter_rejected_count": sum(len(b.rejected) for b in batches.values()),
            "adapter_input_counts": {s: b.input_count for s, b in batches.items()},
            "max_observed_inter_alert_gap_seconds": max_gap,
            "observed_field_frequency_statistics": entity_proxy,
            "repeated_observed_alert_shape_count": sum(c > 1 for c in duplicate_shapes.values()),
            "read_only_experimental_derivative": True, "auto_registered": False,
            "ground_truth": "NOT_USED", "correlation_executed": False,
            "limitations": ["Unlabelled temporal midpoint is a sampling rule, not proof of benign activity or global statistical representativeness.",
                "Field frequencies and repeated shapes are integrity/context descriptions only; no entity extraction, dedupe, candidate, scoring or singleton classification was run.",
                "Full-versus-slice check adapts every selected record directly from its full source, not all out-of-window records.",
                "Validation slice is frozen for independent validation after development; repeated parameter tuning is prohibited."] if dataset == "fox" else [
                "Unlabelled temporal midpoint is a sampling rule, not proof of benign activity or global statistical representativeness.",
                "Field frequencies and repeated shapes are context descriptions only; no entity extraction, dedupe, candidate, scoring or singleton classification was run.",
                "Full-versus-slice check adapts every selected record directly from its full source, not all out-of-window records."],
        }
        write_json(staged / "slice_manifest.json", manifest)
        publish_immutable(staged, output_base / NAMES[dataset])
    return {**manifest, "slice_name": NAMES[dataset], "manifest_sha256": file_digest(output_base / NAMES[dataset] / "slice_manifest.json"),
            "validation": {key: "PASS" for key in ("timestamp_parse", "source_json", "adapter", "canonical_schema",
                "no_out_of_window_records", "source_namespace", "raw_traceability", "stable_id", "full_vs_slice_stable_id",
                "deterministic_build", "original_data_hash", "source_format")}}


def reports(root, results, protected):
    output = root / "outputs/ait_ads_slices"
    registry = read_registry(root)
    contexts = source_contexts(root)
    excluded = not any("/slices/" in p for scene in registry.scenes.values() for p in scene.raw.values())
    excluded &= not any("/slices/" in c["path"] for c in contexts.values())
    protection_pass = protected_hashes(root) == protected
    if not excluded or not protection_pass:
        raise ValueError("registry_or_protected_files_changed")
    if {r["source_dataset"] for r in results} != set(ROLES):
        raise ValueError("both_development_and_validation_slices_required")
    for result in results:
        check_receipt(root, result)
    selection = ["# Slice selection report", "", "Rule fixed in audit before any slice adaptation; applied independently to both scenes.", "", "```json", json.dumps(SELECTION_RULE, indent=2), "```", "",
        "Every record in the inclusive window is retained in its original order, across both sources. Wazuh-embedded Suricata follows the Wazuh alert timestamp.", "",
        "No source/category/severity/entity diversity or algorithm outcome is an admission/ranking criterion. Descriptive distributions are calculated after selection.", "",
        "The fixed time midpoint avoids optimizing density or correlation. It cannot prove normal/benign status without labels; labels are NOT USED.", "",
        "Reproduce from repository root (Python 3.11):", "", "```text",
        "python scripts/build_ait_ads_slices.py --phase audit",
        "python scripts/build_ait_ads_slices.py --phase build", "```", "",
        "Optional per-slice build: add --dataset russellmitchell --purpose development or --dataset fox --purpose validation. Overall READY requires both receipts. Identical existing derivatives are reused; differing derivatives are never overwritten.", ""]
    validation = ["# Slice validation report", "", "AIT_ADS_SLICE_RESULT = READY", "", "Production algorithms/configuration/frontend/baselines: unchanged SHA-256. Dataset registry: unchanged; explicit source paths exclude slices.", "",
        "Labels: NOT USED. Hold-out: only directory existence checked. No correlation, clustering, reconstruction or AI invocation.", "",
        "Validation gates below cover every selected record through the existing Adapter.read_file and CanonicalAlert schema. Stable IDs and full canonical contents match direct conversions from original source records.", ""]
    for result in results:
        filename = "RUSSELLMITCHELL_DEV_SMALL_RESULT.json" if result["source_dataset"] == "russellmitchell" else "FOX_VALIDATION_SMALL_RESULT.json"
        write_json(output / filename, result)
        selection += [f"## {result['slice_name']}", "", f"- Window (UTC, inclusive): {result['start_timestamp']} to {result['end_timestamp']}; duration {result['duration_seconds']} seconds.",
            f"- Raw: {result['raw_counts']}; CanonicalAlert: {result['canonical_alert_count']}.",
            f"- Source types: {result['source_type_counts']}; severity: {result['severity_counts']}; category: {result['category_counts']}.",
            f"- Maximum observed consecutive-alert gap: {result['max_observed_inter_alert_gap_seconds']} seconds (no records omitted inside window).",
            "- Gaps are observations, not verified collector outages. Sparse AMiner coverage and unknown categories are retained as observed; no diversity-based reselection occurs.",
            f"- Size-only selection attempts: {json.dumps(result['selection_attempts'], sort_keys=True)}.",
            "- Field frequency, role coverage, repeated shapes and missing fields are detailed in manifest. No relation/edge/singleton claims are inferred.", ""]
        validation += [f"## {result['slice_name']}", "", "| check | status |", "| --- | --- |"]
        validation += [f"| {k} | {v} |" for k, v in sorted(result["validation"].items())]
        validation += ["", f"- Original source SHA-256: `{json.dumps(result['source_sha256'], sort_keys=True)}`.",
                       f"- Slice SHA-256: `{json.dumps(result['slice_sha256'], sort_keys=True)}`.",
                       f"- Adapter rejection count: {result['adapter_rejected_count']}; duplicate imports: {result['duplicate_import_count']}.", ""]
    validation += ["DETERMINISTIC_SLICE_BUILD = PASS", "", "Independent repeated full-source filtering produced identical counts, canonical identities and raw file bytes. Immutable existing slices are refused if any content differs.", "",
        "Correlation Small-Dev Optimization gate: YES after READY; this builder does not start it. Fox remains an independent validation dataset.", ""]
    (output / "SLICE_SELECTION_REPORT.md").write_text("\n".join(selection) + "\n", encoding="utf-8")
    (output / "SLICE_VALIDATION_REPORT.md").write_text("\n".join(validation) + "\n", encoding="utf-8")
    write_json(output / "PROTECTED_FILES_HASH_CHECK.json", {"status": "PASS", "sha256_before": protected,
        "sha256_after": protected_hashes(root), "slice_auto_discovery_excluded": excluded})


def check_receipt(root, result):
    """Prevent stale or edited per-slice receipts from publishing global READY."""
    dataset = result["source_dataset"]
    loaded, source_paths = selected_inputs(root, dataset)
    base = root / "data/ait_ads/slices" / NAMES[dataset]
    manifest_path = base / "slice_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest != {k: result[k] for k in manifest}:
        raise ValueError("slice_receipt_manifest_mismatch")
    if result["manifest_sha256"] != file_digest(manifest_path):
        raise ValueError("slice_manifest_hash_mismatch")
    if result["adapter_config_hash"] != loaded.config.config_hash:
        raise ValueError("slice_adapter_config_changed")
    if result["purpose"] != "correlation_" + ROLES[dataset] or result["selection_rule"] != SELECTION_RULE:
        raise ValueError("slice_role_or_rule_changed")
    if any(v != "PASS" for v in result["validation"].values()):
        raise ValueError("slice_validation_not_passed")
    for source, original in source_paths.items():
        if result["source_sha256"][source] != file_digest(original):
            raise ValueError("original_source_hash_changed")
        if result["slice_sha256"][source] != file_digest(base / "raw" / (source + ".json")):
            raise ValueError("published_slice_hash_changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("audit", "build"), required=True)
    parser.add_argument("--dataset", choices=tuple(ROLES))
    parser.add_argument("--purpose", choices=("development", "validation"))
    args = parser.parse_args()
    if args.purpose and (not args.dataset or args.purpose != ROLES[args.dataset]):
        parser.error("purpose must match the fixed dataset role")
    try:
        if args.phase == "audit":
            audit(ROOT)
        else:
            protected = protected_hashes(ROOT)
            profile = json.loads((ROOT / "outputs/ait_ads_slices/DATASET_TIME_PROFILE.json").read_text(encoding="utf-8"))
            for dataset in ([args.dataset] if args.dataset else sorted(ROLES)):
                result = build(ROOT, dataset, profile)
                write_json(ROOT / "outputs/ait_ads_slices" / ("RUSSELLMITCHELL_DEV_SMALL_RESULT.json" if dataset == "russellmitchell" else "FOX_VALIDATION_SMALL_RESULT.json"), result)
                print(json.dumps({"dataset": dataset, "canonical_alert_count": result["canonical_alert_count"], "window": [result["start_timestamp"], result["end_timestamp"]]}), flush=True)
            results = [json.loads((ROOT / "outputs/ait_ads_slices" / filename).read_text(encoding="utf-8")) for filename in ("RUSSELLMITCHELL_DEV_SMALL_RESULT.json", "FOX_VALIDATION_SMALL_RESULT.json")]
            reports(ROOT, results, protected)
            print("AIT_ADS_SLICE_RESULT = READY", flush=True)
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        output = ROOT / "outputs/ait_ads_slices"
        output.mkdir(parents=True, exist_ok=True)
        (output / "SLICE_VALIDATION_REPORT.md").write_text(
            "# Slice validation report\n\nAIT_ADS_SLICE_RESULT = NOT_READY\n\nBlocker: " + str(exc) + "\n", encoding="utf-8")
        print("AIT_ADS_SLICE_RESULT = NOT_READY\nblocker: " + str(exc), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
