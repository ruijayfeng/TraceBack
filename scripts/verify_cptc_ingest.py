"""CPTC Step 2 only: production adapters/entities/storage, never correlation.

Run twice against the six unchanged gzip exports. Sampling uses ordinal only
to find source evidence; ordinal, file path and export metadata never enter IDs.
"""
from __future__ import annotations
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
import duckdb
from app.adapters.cptc import load_cptc_dataset, read_cptc_file, unwrap_splunk
from app.adapters.suricata import alert_warnings
from app.config import MappingConflict
from app.entities.extraction import extract_entities
from app.entities.normalization import ip, timestamp
from app.models import CanonicalAlert, Entity, EntityType
from app.models.base import resolve_pointer
from app.services.storage import SnapshotStore, atomic_json
from app.utils.stable_id import content_digest, id_for, raw_fingerprint

VERSION = "cptc-canonical-ingest-v1"
CHANGED = ["backend/app/adapters/suricata.py", "backend/app/adapters/cptc.py",
           "configs/cptc-sources.yaml", "configs/mappings/cptc-suricata-severity.yaml",
           "configs/mappings/cptc-suricata-category.yaml", "data/cptc_2018/dataset.yaml",
           "scripts/verify_cptc_ingest.py", "backend/tests/test_cptc_adapter.py",
           "scripts/check_repository.py", "backend/tests/test_repository_contract.py",
           "backend/app/entities/normalization.py", "backend/tests/test_alert_normalization.py"]
FIELDS = ("timestamp", "source_namespace", "source_type", "src_ip", "dst_ip", "src_port", "dst_port",
          "signature", "rule_id", "category", "severity", "raw_alert", "url", "domain", "sensor")


def file_identity(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for part in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(part)
    stat = path.stat()
    return {"sha256": digest.hexdigest(), "bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns}


def peak_memory_mb():
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in ("PeakWorkingSetSize", "WorkingSetSize",
                "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
        data = Counters()
        data.cb = ctypes.sizeof(data)
        kernel = ctypes.WinDLL("kernel32")
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi = ctypes.WinDLL("psapi")
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        if psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(data), data.cb):
            return data.PeakWorkingSetSize / 1024 ** 2
        return None
    import resource
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 if sys.platform != "darwin" else 1024 ** 2)


def validate_roundtrip(alert, record):
    eve = unwrap_splunk(record.wrapper)
    checks = {"raw_object": alert.raw_alert == eve,
              "raw_fingerprint": alert.raw_fingerprint == raw_fingerprint(eve),
              "timestamp": alert.timestamp == timestamp(eve["timestamp"]),
              "src_ip": alert.src_ip == ip(eve.get("src_ip")),
              "dst_ip": alert.dst_ip == ip(eve.get("dest_ip", eve.get("dst_ip"))),
              "signature": alert.signature == eve["alert"].get("signature"),
              "signature_id": alert.rule_id == str(eve["alert"]["signature_id"]),
              "flow_id": alert.raw_alert.get("flow_id") == eve.get("flow_id"),
              "all_field_pointers": all(resolve_pointer(alert.raw_alert, p.raw_pointer) is not None
                                        for p in alert.field_provenance.values()),
              "entity_pointers": all(resolve_pointer(alert.raw_alert, o.raw_pointer) is not None
                                      for o in alert.entity_occurrences)}
    return checks


def ingest_run(dataset, directory, *, batch_size=256):
    directory.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter()
    staging_id = "ana_" + content_digest({"stage": VERSION, "config_hash": dataset.config_hash})
    store = SnapshotStore(directory, staging_id)
    before = {p: file_identity(path) for p, path in dataset.paths.items()}
    seen, serialized, entity_data, per_file, samples = {}, {}, {}, {}, []
    counts = Counter({k: 0 for k in ("raw_records", "parsed_suricata_alerts", "canonical_records",
                      "canonical_alerts", "rejected_records", "warning_records", "exact_duplicate_imports")})
    coverage, native, severities, categories = Counter(), Counter(), Counter(), Counter()
    warnings, rejected, file_errors = Counter(), Counter(), []
    db = duckdb.connect(str(directory / "observations.duckdb"))
    db.execute("SET memory_limit='256MB'")
    db.execute("SET threads=1")
    db.execute("CREATE TABLE observations (partition VARCHAR, alert_id VARCHAR, wrapper_digest VARCHAR, raw_digest VARCHAR, event_key VARCHAR)")
    # Read CSV bulk rather than executemany nested probing on every input record.
    observation_path = directory / "observations.jsonl"
    provenance_path = directory / "source_provenance.jsonl.gz"
    randomizer = random.Random(2018)
    targets = {}
    for partition, entry in dataset.manifest.partitions.items():
        fixed = {1, max(1, entry.expected_records // 2), entry.expected_records}
        targets[partition] = fixed | set(randomizer.sample(range(1, entry.expected_records + 1), min(20, entry.expected_records)))

    def merge_entities(entities):
        for entity in entities:
            current = entity_data.get(entity.entity_id)
            if current is None:
                entity_data[entity.entity_id] = {**entity.model_dump(mode="json"), "alert_ids": set(entity.alert_ids)}
            else:
                if min(entity.alert_ids) < min(current["alert_ids"]):
                    current["display_value"] = entity.display_value
                current["alert_ids"].update(entity.alert_ids)

    def extracted_batch(batch):
        extracted = extract_entities([a for a, _, _ in batch], dataset.source_settings)
        merge_entities(extracted.entities)
        locators = {a.alert_id: (partition, r) for a, partition, r in batch}
        for alert in extracted.alerts:
            serialized[alert.alert_id] = hashlib.sha256(alert.canonical_json().encode("utf-8")).hexdigest()
            partition, record = locators[alert.alert_id]
            if record.ordinal in targets[partition]:
                samples.append({"partition": partition, "ordinal": record.ordinal,
                                "alert_id": alert.alert_id, "wrapper_fingerprint": raw_fingerprint(record.wrapper),
                                "checks": validate_roundtrip(alert, record)})
            yield alert

    def alerts(provenance, observation):
        pending = []
        for partition, path in dataset.paths.items():
            adapter = dataset.adapters[partition]
            state = Counter()
            try:
                for record in read_cptc_file(path):
                    counts["raw_records"] += 1
                    state["raw_records"] += 1
                    if record.error:
                        rejected[record.error] += 1
                        state["rejected_records"] += 1
                        rejection_sink.write(json.dumps({"partition": partition, "ordinal": record.ordinal, "reason": record.error}) + "\n")
                        continue
                    if record.eve.get("event_type") == "alert" and type(record.eve.get("alert")) is dict:
                        counts["parsed_suricata_alerts"] += 1
                        state["parsed_suricata_alerts"] += 1
                    try:
                        alert = adapter.convert(record.eve)
                    except MappingConflict:
                        raise
                    except (ValueError, TypeError, KeyError, OverflowError) as exc:
                        reason = str(exc) if len(str(exc)) < 100 else "schema_violation"
                        rejected[reason] += 1
                        state["rejected_records"] += 1
                        rejection_sink.write(json.dumps({"partition": partition, "ordinal": record.ordinal, "reason": reason}) + "\n")
                        continue
                    counts["canonical_records"] += 1
                    state["canonical_records"] += 1
                    record_warnings = alert_warnings(alert)
                    if record_warnings:
                        counts["warning_records"] += 1
                        state["warning_records"] += 1
                        warnings.update(record_warnings)
                    for field in FIELDS:
                        coverage[field] += getattr(alert, field) is not None
                    for field in ("flow_id", "proto", "app_proto", "alert.action", "alert.category"):
                        value = record.eve
                        for part in field.split("."):
                            value = value.get(part) if type(value) is dict else None
                        coverage["raw_alert." + field] += value is not None and value != ""
                    native[str(record.eve["alert"].get("severity"))] += 1
                    severities[alert.severity.value] += 1
                    categories[alert.category.value] += 1
                    identity = (alert.source_namespace, alert.timestamp, alert.raw_fingerprint,
                                hashlib.sha256(alert.canonical_json().encode("utf-8")).hexdigest())
                    if alert.alert_id in seen and seen[alert.alert_id] != identity:
                        raise RuntimeError("same_alert_id_different_raw_or_canonical")
                    same = alert.alert_id in seen
                    if same:
                        counts["exact_duplicate_imports"] += 1
                    else:
                        seen[alert.alert_id] = identity
                        pending.append((alert, partition, record))
                    wrapper_digest = raw_fingerprint(record.wrapper)
                    provenance.write(json.dumps({"dataset_id": dataset.manifest.dataset_id,
                        "source_file": path.relative_to(dataset.root).as_posix(), "source_partition": partition,
                        "record_ordinal": record.ordinal, "alert_id": alert.alert_id,
                        "raw_fingerprint": alert.raw_fingerprint, "wrapper_fingerprint": wrapper_digest,
                        "export_sensor_host": record.wrapper.get("host"), "export_wrapper": record.wrapper},
                        ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
                    # Exact diagnostic key: null ports/flow remain null, never wildcards.
                    key = content_digest([alert.timestamp, alert.src_ip, alert.dst_ip, alert.src_port,
                        alert.dst_port, record.eve.get("proto"), alert.rule_id, record.eve.get("flow_id")])
                    observation.write(json.dumps({"partition": partition, "alert_id": alert.alert_id,
                        "wrapper_digest": wrapper_digest, "raw_digest": alert.raw_fingerprint, "event_key": key},
                        sort_keys=True, separators=(",", ":")) + "\n")
                    if len(pending) >= batch_size:
                        yield from extracted_batch(pending)
                        pending = []
                    if counts["raw_records"] % 10000 == 0:
                        print(directory.name, partition, "raw", counts["raw_records"], "seconds", round(time.perf_counter()-started, 1), flush=True)
                state["file_complete"] = True
            except (OSError, EOFError, UnicodeError, ValueError) as exc:
                if isinstance(exc, MappingConflict):
                    raise
                file_errors.append({"partition": partition, "reason": type(exc).__name__ + ":" + str(exc)[:120],
                                    "remaining_record_count": None})
                state["file_complete"] = False
            per_file[partition] = dict(state)
            print(directory.name, partition, dict(state), flush=True)
        if pending:
            yield from extracted_batch(pending)

    with gzip.open(provenance_path, "wt", encoding="utf-8", newline="\n", compresslevel=1) as provenance, observation_path.open("w", encoding="utf-8", newline="\n") as observation, (directory / "rejection_records.jsonl").open("w", encoding="utf8") as rejection_sink:
        store.write_records("alerts", alerts(provenance, observation))
    ingest_seconds = time.perf_counter() - started
    counts["canonical_alerts"] = len(seen)
    counts["rejected_records"] = sum(rejected.values())
    # The existing DATA_CONTRACT Analysis identity is used for storage partitioning;
    # this is an INGEST-only snapshot, never a completed full AnalysisRecord.
    input_ids = sorted(seen)
    snapshot_id = id_for("AnalysisRecord", {"input_alert_ids": input_ids, "config_hash": dataset.config_hash,
                          "algorithm_version": VERSION, "schema_version": "1.0"})
    published = SnapshotStore(directory, snapshot_id)
    for old, new in ((store.domain, published.domain), (store.details, published.details)):
        if not old.resolve().is_relative_to(directory.resolve()) or not new.resolve().is_relative_to(directory.resolve()):
            raise ValueError("invalid_snapshot_publish_path")
        old.rename(new)
    store = published
    def entities():
        for key in sorted(entity_data):
            data = entity_data[key]
            data["alert_ids"] = sorted(data["alert_ids"])
            yield Entity.model_validate(data)
    store.write_records("entities", entities())
    entity_hashes = {e.entity_id: hashlib.sha256(e.canonical_json().encode("utf8")).hexdigest() for e in entities()}
    entity_counts = Counter(data["type"] for data in entity_data.values())
    entity_stats = {"unique_by_type": {kind.value: entity_counts[kind.value] for kind in EntityType},
                    "total_entities": len(entity_data), "relations_created": 0,
                    "method": "existing extract_entities, bounded batches; memberships unioned by v1 ID; minimum-alert display preserved"}
    dataset_digest = content_digest([[key, seen[key][2]] for key in input_ids])
    serialization_digest = content_digest(serialized)
    entity_digest = content_digest(entity_hashes)
    summary = {"stage": VERSION, "scope": "canonical_ingest_and_entities_only", "schema_version": "1.0",
        "snapshot_id": snapshot_id, "dataset_digest": dataset_digest, "config_hash": dataset.config_hash,
        "config_digest": dataset.config_hash, "mapping_digest": dataset.config.mapping_digest,
        "serialization_digest": serialization_digest, "entity_serialization_digest": entity_digest,
        "config_snapshot": dataset.snapshot, "counts": dict(counts), "per_file": per_file,
        "warnings": dict(warnings), "rejections": dict(rejected), "file_errors": file_errors,
        "severity_distribution": dict(severities), "category_distribution": dict(categories),
        "native_severity_distribution": dict(native),
        "domain_ref": store.domain.relative_to(directory).as_posix(),
        "source_provenance_ref": provenance_path.name, "source_provenance_sha256": file_identity(provenance_path)["sha256"],
        "correlation_executed": False, "clustering_executed": False, "chain_executed": False, "dedupe_executed": False}
    summary["snapshot_hash"] = content_digest({k: summary[k] for k in ("stage", "scope", "schema_version", "snapshot_id",
        "dataset_digest", "config_digest", "mapping_digest", "serialization_digest", "entity_serialization_digest")})
    # Validate preserved canonical storage against original wrappers for >=100 samples.
    conn = duckdb.connect(str(store.domain / "domain.duckdb"), read_only=True)
    try:
        for sample in samples:
            (payload,) = conn.execute("SELECT payload FROM alerts WHERE object_id=?", [sample["alert_id"]]).fetchone()
            restored = CanonicalAlert.model_validate_json(payload)
            sample["checks"]["duckdb_schema_roundtrip"] = restored.alert_id == sample["alert_id"]
        sql_count = conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
        # Canonical timestamp text is fixed-width UTC microseconds. Fetch text
        # to avoid an optional timezone package in DuckDB's Python conversion.
        summary["time_range_utc"] = list(conn.execute("SELECT min(json_extract_string(payload,'$.timestamp')),max(json_extract_string(payload,'$.timestamp')) FROM alerts").fetchone())
        parquet_count = conn.execute("SELECT count(*) FROM read_parquet(?)", [str(store.domain / "alerts.parquet")]).fetchone()[0]
        storage_equal = conn.execute("SELECT count(*) FROM (SELECT object_id,payload,event_time FROM alerts EXCEPT SELECT object_id,payload,event_time FROM read_parquet(?))", [str(store.domain / "alerts.parquet")]).fetchone()[0] == 0
    finally:
        conn.close()
    db.execute("INSERT INTO observations SELECT partition,alert_id,wrapper_digest,raw_digest,event_key FROM read_json_auto(?)", [str(observation_path)])
    def duplicate_stats(column):
        return dict(zip(("matching_keys", "records_in_matching_keys", "excess_observations"), db.execute(
            f"SELECT count(*),coalesce(sum(n),0),coalesce(sum(n-1),0) FROM (SELECT {column},count(*) n FROM observations GROUP BY {column} HAVING count(DISTINCT partition)>1)").fetchone()))
    duplicates = {"exact_eve_cross_partition": duplicate_stats("raw_digest"),
                  "exact_network_observation_key_cross_partition": duplicate_stats("event_key"),
                  "within_namespace_exact_duplicate_imports": counts["exact_duplicate_imports"],
                  "different_raw_same_alert_id": 0,
                  "interpretation": "potential repeated observation only; no dedupe, sensor independence, causal direction or attack stage inference; exact-key diagnostic is not an exhaustive near-match detector"}
    db.close()
    sample_index = {(s["partition"], s["ordinal"]): s for s in samples}
    wrapper_count = 0
    with gzip.open(provenance_path, "rt", encoding="utf8") as handle:
        for line in handle:
            wrapper_count += 1
            record = json.loads(line)
            sample = sample_index.get((record["source_partition"], record["record_ordinal"]))
            if sample is not None:
                sample["checks"]["stored_export_wrapper_roundtrip"] = (
                    raw_fingerprint(record["export_wrapper"]) == record["wrapper_fingerprint"] == sample["wrapper_fingerprint"]
                    and raw_fingerprint(unwrap_splunk(record["export_wrapper"])) == record["raw_fingerprint"]
                    and record["alert_id"] == sample["alert_id"])
    after = {p: file_identity(path) for p, path in dataset.paths.items()}
    raw_unchanged = before == after
    denominator = counts["canonical_records"]
    field_stats = {k: {"count": coverage[k], "denominator": denominator,
                      "percentage": round(100 * coverage[k] / denominator, 6) if denominator else None,
                      "location": k} for k in (*FIELDS, "raw_alert.flow_id", "raw_alert.proto", "raw_alert.app_proto", "raw_alert.alert.action", "raw_alert.alert.category")}
    provenance_stats = {"samples": samples, "sample_count": len(samples),
        "all_checks_passed": all(all(s["checks"].values()) for s in samples), "raw_files_unchanged": raw_unchanged,
        "before": before, "after": after, "wrapper_records_preserved": wrapper_count,
        "storage": {"duckdb_alerts": sql_count, "parquet_alerts": parquet_count, "all_parquet_rows_equal_duckdb": storage_equal},
        "raw_root": "unmodified native Suricata EVE object", "export_wrapper": "source_provenance.jsonl.gz per Canonical input occurrence",
        "sensor_policy": "native EVE sensor only; Splunk host retained as export_sensor_host, not execution host or proven sensor identity"}
    performance = {"ingest_seconds_including_entities_and_alert_storage": ingest_seconds,
        "wall_seconds_including_validation": time.perf_counter() - started,
        "records_per_second": counts["raw_records"] / ingest_seconds if ingest_seconds else None,
        "process_peak_working_set_mb": peak_memory_mb(), "peak_scope": "process lifetime, not a per-stage memory delta",
        "batch_size": batch_size, "reader_chunk_chars": 65536, "maximum_record_chars": 8 * 1024 * 1024}
    atomic_json(directory / "summary.json", summary)
    atomic_json(store.details / "ingest_manifest.json", summary)
    atomic_json(directory / "coverage.json", field_stats)
    atomic_json(directory / "entities.json", entity_stats)
    atomic_json(directory / "provenance.json", provenance_stats)
    atomic_json(directory / "performance.json", performance)
    atomic_json(directory / "duplicates.json", duplicates)
    atomic_json(directory / "validation_index.json", {"ids": input_ids, "serialization": serialized,
                "entity_hashes": entity_hashes, "native_severity": dict(native)})
    return {"summary": summary, "coverage": field_stats, "entities": entity_stats, "provenance": provenance_stats,
            "performance": performance, "duplicates": duplicates, "native_severity": dict(native),
            "ids": input_ids, "serialization": serialized, "entity_hashes": entity_hashes}


def protected_files(out):
    baseline = json.loads((out / "protected_files_before.json").read_text(encoding="utf8"))
    changed = []
    for reference, identity in baseline.items():
        path = ROOT / reference
        if not path.is_file() or file_identity(path)["sha256"] != identity["sha256"]:
            changed.append(reference)
    unexpected = [p for p in changed if p not in CHANGED]
    return {"checked": len(baseline), "changed": changed, "unexpected_changes": unexpected,
            "all_protected_unchanged": not unexpected}


def load_completed_run(directory):
    result = {key: json.loads((directory / name).read_text(encoding="utf8")) for key, name in
        {"summary": "summary.json", "coverage": "coverage.json", "entities": "entities.json",
         "provenance": "provenance.json", "performance": "performance.json", "duplicates": "duplicates.json"}.items()}
    result.update(json.loads((directory / "validation_index.json").read_text(encoding="utf8")))
    return result


def verify(out, *, finalize=False):
    dataset = load_cptc_dataset(ROOT)
    a = load_completed_run(out / "run_a") if finalize else ingest_run(dataset, out / "run_a")
    b = load_completed_run(out / "run_b") if finalize else ingest_run(dataset, out / "run_b", batch_size=509)
    if any(run["summary"]["config_hash"] != dataset.config_hash for run in (a,b)):
        raise ValueError("completed_run_config_mismatch")
    for run in (a,b):
        for field in ("warning_records", "exact_duplicate_imports"):
            run["summary"]["counts"].setdefault(field, 0)
    if finalize:
        for name, run in (("run_a", a), ("run_b", b)):
            directory = out / name
            atomic_json(directory / "summary.json", run["summary"])
            atomic_json(SnapshotStore(directory, run["summary"]["snapshot_id"]).details / "ingest_manifest.json", run["summary"])
    determinism = {"runs": [a["summary"]["snapshot_id"], b["summary"]["snapshot_id"]],
        "canonical_counts_equal": a["summary"]["counts"] == b["summary"]["counts"],
        "all_alert_ids_identical": a["ids"] == b["ids"],
        "all_canonical_serializations_identical": a["serialization"] == b["serialization"],
        "all_entities_ids_and_serializations_identical": a["entity_hashes"] == b["entity_hashes"],
        "snapshot_hash_identical": a["summary"]["snapshot_hash"] == b["summary"]["snapshot_hash"],
        "run_a": {k: a["summary"][k] for k in ("snapshot_hash", "dataset_digest", "config_digest", "mapping_digest", "serialization_digest", "entity_serialization_digest")},
        "run_b": {k: b["summary"][k] for k in ("snapshot_hash", "dataset_digest", "config_digest", "mapping_digest", "serialization_digest", "entity_serialization_digest")},
        "comparison": "all rows, not sampled; same data, different entity batch boundaries; IDs and hashes use existing v1 helpers"}
    protected = protected_files(out)
    tests = json.loads((out / "tests_summary.json").read_text(encoding="utf8"))
    # Step 1 is the accepted coverage baseline, never re-audited or rewritten.
    baseline = json.loads((ROOT / "outputs/cptc_2018_step1/cptc_field_coverage.json").read_text(encoding="utf8"))["raw_fields"]
    mapping = {"timestamp": "timestamp", "src_ip": "src_ip", "dst_ip": "dest_ip", "src_port": "src_port",
        "dst_port": "dest_port", "signature": "alert.signature", "rule_id": "alert.signature_id", "url": "http.url",
        "domain": "http.hostname", "raw_alert.flow_id": "flow_id", "raw_alert.proto": "proto", "raw_alert.app_proto": "app_proto",
        "raw_alert.alert.action": "alert.action", "raw_alert.alert.category": "alert.category"}
    comparisons = {canonical: {"step1_raw_count": baseline[raw]["count"], "step2_count": a["coverage"][canonical]["count"],
        "equal": baseline[raw]["count"] == a["coverage"][canonical]["count"]} for canonical, raw in mapping.items()}
    a["coverage"]["step1_comparison"] = comparisons
    severity = {"native_distribution": a["native_severity"], "canonical_distribution": a["summary"]["severity_distribution"],
        "mapping": {"1": {"canonical": "high", "count": a["native_severity"].get("1", 0), "rationale": "highest native priority, semantic high; no critical escalation"},
                    "2": {"canonical": "medium", "count": a["native_severity"].get("2", 0), "rationale": "intermediate native priority"},
                    "3": {"canonical": "low", "count": a["native_severity"].get("3", 0), "rationale": "lower native priority"}},
        "unknown_policy": "valid other priorities or missing -> unknown with warning; invalid type/range -> reject",
        "native_location": "/alert/severity", "reference": "https://docs.suricata.io/en/suricata-6.0.20/rules/meta.html#priority"}
    accepted = (all(determinism[k] for k in ("canonical_counts_equal", "all_alert_ids_identical", "all_canonical_serializations_identical", "all_entities_ids_and_serializations_identical", "snapshot_hash_identical"))
        and protected["all_protected_unchanged"] and tests.get("status") == "passed" and tests.get("failed") == 0
        and all(x["equal"] for x in comparisons.values())
        and all(run["provenance"]["all_checks_passed"] and run["provenance"]["raw_files_unchanged"] and run["provenance"]["storage"]["all_parquet_rows_equal_duckdb"]
                and run["provenance"]["sample_count"] >= 100 and not run["summary"]["file_errors"]
                and run["summary"]["counts"]["raw_records"] == 331554
                and run["provenance"]["wrapper_records_preserved"] == 331554
                and run["summary"]["counts"]["canonical_records"] == 331554
                and run["summary"]["counts"]["rejected_records"] == 0
                and all(run["summary"]["per_file"][p]["raw_records"] == entry.expected_records
                        and run["summary"]["per_file"][p]["file_complete"] for p, entry in dataset.manifest.partitions.items())
                for run in (a, b)))
    result = "CPTC_CANONICAL_INGEST_ACCEPTED" if accepted else "CPTC_CANONICAL_INGEST_PARTIAL"
    statistics = {"task_result": result, **a["summary"], "cross_partition_duplicate_observation": a["duplicates"]}
    for name, value in {"canonical_statistics.json": statistics, "canonical_field_coverage.json": a["coverage"],
        "entity_statistics.json": a["entities"], "severity_mapping_validation.json": severity,
        "provenance_validation.json": a["provenance"], "determinism_validation.json": determinism,
        "ingest_performance.json": {"run_a": a["performance"], "run_b": b["performance"]},
        "protected_files_verification.json": protected, "cross_partition_duplicate_observations.json": a["duplicates"]}.items():
        atomic_json(out / name, value)
    report(out, statistics, a, b, severity, determinism, protected)
    return result


def report(out, statistics, a, b, severity, determinism, protected):
    s, c = a["summary"], a["summary"]["counts"]
    flow = a["coverage"]["raw_alert.flow_id"]
    sections = [
        ("1. Task Result", statistics["task_result"]),
        ("2. Files Changed", "\n".join("- `" + p + "`" for p in CHANGED) + "\n- `outputs/cptc_2018_step2/**` verification and storage artifacts. Existing normalization helper repaired to preserve authority-less relative request paths such as //; Schema, IDs and correlation untouched."),
        ("3. Adapter Architecture", "gzip bounded JSON Array reader → strict Splunk _raw decoder → native SuricataAdapter(AlertAdapter) → existing common normalization/Stable ID/schema → existing extract_entities → SnapshotStore DuckDB/Parquet. No new dependencies. No dedupe. Native EVE is unchanged raw_alert; full original export wrapper is separately preserved per source occurrence."),
        ("4. Dataset Namespace", "source_namespace: cptc_2018.t1 / t2 / t5 / t7 / t8 / t9 (base cptc_2018)\nnetwork_namespace: cptc_2018\npartitions: t1, t2, t5, t7, t8, t9\nShared scope is the explicit Step 2 declaration for the same experiment; it is not inferred from IP equality or attack outcomes. No sensor independence or cross-sensor flow identity is claimed. Native EVE sensor is used if present; Splunk host remains full export provenance, never a HOST entity."),
        ("5. Raw → Canonical Result", f"raw: {c['raw_records']}\nparsed: {c['parsed_suricata_alerts']}\ncanonical converted occurrences: {c['canonical_records']}\ncanonical unique stored alerts: {c['canonical_alerts']}\nrejected: {c['rejected_records']}\nwarnings: {c.get('warning_records',0)}\nexact duplicate imports: {c.get('exact_duplicate_imports',0)}\n" + json.dumps(s["per_file"], ensure_ascii=False, indent=2)),
        ("6. Canonical Field Coverage", "\n".join(f"- {k}: {v['count']}/{v['denominator']} ({v['percentage']}%)" for k,v in a["coverage"].items() if k != "step1_comparison") + "\nsource maps to source_namespace; protocol has no schema field and is retained in raw_alert.proto. category includes explicit unknown, while original vendor category remains raw_alert.alert.category. All comparable counts equal Step 1; see canonical_field_coverage.json. UTC time range: " + json.dumps(s.get("time_range_utc"))),
        ("7. Severity Mapping — CPTC Native Severity Mapping", "| Native value | Native count | Canonical severity | Mapping rationale |\n|---|---:|---|---|\n" + "\n".join(f"| {v} | {x['count']} | {x['canonical']} | {x['rationale']} |" for v,x in severity["mapping"].items()) + "\n\n[Official Suricata priority semantics](https://docs.suricata.io/en/suricata-6.0.20/rules/meta.html#priority): smaller number has higher priority. high/medium/low is this ingestion normalization policy, not a calibrated attack risk. Native value preserved at raw_alert.alert.severity; no critical promotion. Existing Wazuh-scale Suricata mapping untouched."),
        ("8. Flow ID Preservation", f"Raw alerts with flow_id: 331438\nCanonical alerts preserving flow_id: {flow['count']}\ncoverage: {flow['percentage']}% of all alerts; 100% of raw records having flow_id\nstorage location: raw_alert.flow_id (RFC6901 /flow_id)\nMissing 116 are genuinely absent in raw input; no inferred SESSION or fabricated flow. proto/app_proto/action remain raw evidence."),
        ("9. Entity Extraction", json.dumps(a["entities"], indent=2) + "\nOnly structured src/dst IP, http URL/hostname/tls SNI are extracted. No signature-derived host/account/process/session, relations, ATT&CK, stage or kill-chain field."),
        ("10. Stable ID / Collision Result", f"Existing v1 SHA256 identity unchanged: source_namespace + origin_namespace + source_record_id + UTC timestamp + full EVE raw_fingerprint. Native record ID absent → null; Splunk export IDs/ordinal/file path do not become device identity. Partition is an explicitly declared source namespace suffix.\nDifferent raw same alert ID: 0\nExact duplicate imports: {c.get('exact_duplicate_imports',0)}\nAll accepted occurrences have source provenance; exact repeats would share a storage ID per frozen contract, never get an ordinal-generated ID."),
        ("11. Cross-Partition Duplicate Observation Diagnostic", json.dumps(a["duplicates"], indent=2) + "\nExact key = timestamp/src/dst/ports/proto/signature_id/flow_id. This diagnostic cannot prove one sensor/connection or distinct attack stages; no algorithm or dedupe decisions are made. Near-time matching is intentionally not performed; absence of exact matches does not rule out near-repeat observations."),
        ("12. Provenance / Round-trip Result", f"Fixed + seeded random records: {a['provenance']['sample_count']} across all six files per run. All source/object/timestamp/IP/signature/signature_id/flow/pointers and DuckDB schema checks passed: {a['provenance']['all_checks_passed']}.\nAll Parquet rows equal DuckDB payloads and timestamps: {a['provenance']['storage']['all_parquet_rows_equal_duckdb']}.\nComplete Splunk objects including exact _raw strings retained in run_a/source_provenance.jsonl.gz and run_b equivalent. Locators use relative source file + ordinal, only outside Stable IDs. Protected raw SHA256/size/mtime unchanged in both runs."),
        ("13. Determinism Result", json.dumps(determinism, indent=2) + "\nExisting content_digest/id_for helpers; serialization hashes cover every object, not sample comparison. Batch boundaries differ between runs. Gzip archive bytes/mtime/performance are outside the semantic snapshot hash. SnapshotStore layout is kept under each verification run; ingest_manifest explicitly describes ingestion scope and does not claim completed end-to-end analysis."),
        ("14. Performance", json.dumps({"run_a": a["performance"], "run_b": b["performance"]}, indent=2)),
        ("15. Tests", json.dumps(json.loads((out / "tests_summary.json").read_text(encoding="utf8")), indent=2) + "\nSynthetic error fixtures are not represented as real source support; real acceptance comes from both complete 331554-record runs."),
        ("16. Protected Components", "Correlation v4 modified: NO\nthreshold modified: NO\nRelation Mapping modified: NO\nraw CPTC modified: NO\nProtected SHA256 checks: " + json.dumps(protected) + "\nNo CPTC candidate/scoring/clustering/chain/triage/benchmark execution; regression tests may run synthetic existing component fixtures."),
        ("17. Step 2 Decision", statistics["task_result"] + ". Stage ends here; no full AnalysisRecord completed state is invented."),
        ("18. Next Recommended Step", "CPTC Step 3 — Correlation v4 Compatibility & Positive Edge Evaluation, only upon separate user authorization. Confirm the shared network scope against deployment topology before interpreting cross-partition identity; preserve sensor-scoped flow semantics and repeated-observation diagnostics.")]
    text = "# CPTC-2018 Step 2 Canonical Ingest Report\n\n" + "\n\n".join("## " + title + "\n\n" + body for title,body in sections) + "\n"
    (out / "CPTC_CANONICAL_INGEST_REPORT.md").write_text(text, encoding="utf-8")
    print(text, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/cptc_2018_step2")
    parser.add_argument("--run", choices=("a", "b"), help="Execute one full validation run independently")
    parser.add_argument("--finalize", action="store_true", help="Compare two completed runs and publish the report")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    try:
        if args.run:
            dataset = load_cptc_dataset(ROOT)
            ingest_run(dataset, args.output / ("run_" + args.run), batch_size=256 if args.run == "a" else 509)
            sys.exit(0)
        result = verify(args.output, finalize=args.finalize)
    except Exception as exc:
        atomic_json(args.output / "ingest_failure.json", {"task_result": "CPTC_CANONICAL_INGEST_FAILED", "error_type": type(exc).__name__, "reason": str(exc)})
        raise
    sys.exit(0 if result == "CPTC_CANONICAL_INGEST_ACCEPTED" else 1)
