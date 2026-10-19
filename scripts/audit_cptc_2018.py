"""Read-only CPTC Step 1 audit. No correlation, clustering or chain execution.

Bounded gzip/JSON decoding; compact observations spill to a temporary DuckDB.
File ordinals locate audit evidence only and NEVER form production Stable IDs.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.adapters import AdapterSettings, WazuhAdapter
from app.adapters.base import reject_truth
from app.config import load_config
from app.entities.normalization import integer, ip, timestamp
from app.models import CanonicalAlert
from app.models.base import resolve_pointer
from app.utils.stable_id import id_for, raw_fingerprint

FILES = tuple(f"suricata_alert_t{n}.json.gz" for n in (1, 2, 5, 7, 8, 9))
FIELDS = ("timestamp", "event_type", "flow_id", "in_iface", "src_ip", "src_port",
          "dest_ip", "dst_ip", "dest_port", "dst_port", "proto", "app_proto",
          "alert.signature", "alert.signature_id", "alert.rev", "alert.category",
          "alert.severity", "alert.action", "flow", "community_id", "tx_id", "direction",
          "host", "sensor", "account", "session", "process", "parent_process",
          "command", "http.url", "http.hostname", "tls.sni", "dns", "files")
ALIASES = {"dst_ip": ("dest_ip", "dst_ip"), "dst_port": ("dest_port", "dst_port")}
WINDOWS = (60, 300, 900, 1800, 3600)


def strict_json(text):
    def invalid(value):
        raise ValueError("non_finite_json_number:" + value)
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError("duplicate_json_key:" + k)
            result[k] = v
        return result
    return json.loads(text, parse_constant=invalid, object_pairs_hook=pairs)


@dataclass
class Record:
    ordinal: int
    value: object = None
    error: str | None = None


def stream_records(handle, state, *, chunk_size=65536, max_record_chars=8 * 1024 * 1024):
    """Decode an array item at a time, including a single-line giant array.

    JSONL errors are isolated by line. A corrupt array tail cannot be safely
    resynchronized: preserve the valid prefix, report incomplete parsing, stop.
    A framed item is limited to 8 Mi characters; no unbounded read/readline.
    """
    buffer = ""
    while not buffer.strip():
        part = handle.read(chunk_size)
        if not part:
            state.update(format="empty", parse_complete=True)
            return
        buffer += part
        if len(buffer) > max_record_chars:
            raise ValueError("excessive_leading_whitespace")
    buffer = buffer.lstrip("\ufeff \r\n\t")
    ordinal = 0
    if not buffer.startswith("["):
        state["format"] = "JSON Lines"
        while True:
            while "\n" not in buffer:
                part = handle.read(chunk_size)
                if not part:
                    break
                buffer += part
                if len(buffer) > max_record_chars:
                    raise ValueError("record_size_limit")
            if not buffer:
                break
            line, sep, buffer = buffer.partition("\n")
            if line.strip():
                ordinal += 1
                try:
                    yield Record(ordinal, strict_json(line))
                except ValueError as exc:
                    yield Record(ordinal, error="invalid_json:" + str(exc)[:120])
            if not sep:
                break
        state["parse_complete"] = True
        return
    state["format"] = "single JSON Array"
    buffer = buffer[1:]
    eof = False
    expect_item, first = True, True
    decoder = json.JSONDecoder()
    while True:
        buffer = buffer.lstrip()
        if not buffer and not eof:
            part = handle.read(chunk_size)
            eof = not part
            buffer += part
            continue
        if expect_item and buffer.startswith("]") and first:
            buffer = buffer[1:]
            break
        if expect_item:
            try:
                # raw_decode finds the bounded framing; strict_json verifies
                # duplicate keys/non-finite values without losing item framing.
                _, end = decoder.raw_decode(buffer)
            except ValueError:
                if eof or len(buffer) > max_record_chars:
                    ordinal += 1
                    state["parse_complete"] = False
                    yield Record(ordinal, error="invalid_array_tail_or_record_size_limit")
                    return
                part = handle.read(chunk_size)
                eof = not part
                buffer += part
                continue
            # A scalar ending at a chunk boundary could be a partial number.
            if end == len(buffer) and not eof:
                part = handle.read(chunk_size)
                eof = not part
                buffer += part
                continue
            ordinal += 1
            if end > max_record_chars:
                state["parse_complete"] = False
                yield Record(ordinal, error="record_size_limit")
                return
            try:
                yield Record(ordinal, strict_json(buffer[:end]))
            except ValueError as exc:
                yield Record(ordinal, error="invalid_json:" + str(exc)[:120])
            buffer = buffer[end:]
            expect_item, first = False, False
        elif buffer.startswith(","):
            buffer = buffer[1:]
            expect_item = True
        elif buffer.startswith("]"):
            buffer = buffer[1:]
            break
        else:
            state["parse_complete"] = False
            yield Record(ordinal + 1, error="invalid_array_separator_or_missing_close")
            return
    # Drain the gzip trailer to verify CRC; reject any non-whitespace suffix.
    while True:
        if buffer.strip():
            state["parse_complete"] = False
            yield Record(ordinal + 1, error="trailing_content_after_array")
            return
        buffer = handle.read(chunk_size)
        if not buffer:
            break
    state["parse_complete"] = True


def unwrap(value):
    if type(value) is not dict or not value:
        raise ValueError("record_not_nonempty_object")
    reject_truth(value)
    if "_raw" in value:
        if type(value["_raw"]) is not str:
            raise ValueError("_raw_not_json_string")
        eve = strict_json(value["_raw"])
        profile = "Splunk envelope + _raw JSON string"
    else:
        eve, profile = value, "native JSON object"
    if type(eve) is not dict or not eve:
        raise ValueError("eve_not_nonempty_object")
    reject_truth(eve)
    return eve, profile


def get(obj, field):
    for key in field.split("."):
        if type(obj) is not dict or key not in obj:
            return None
        obj = obj[key]
    return obj


def nonempty(value):
    return value is not None and value != "" and value != {} and value != []


def detect_mapping(eve):
    values = {name: get(eve, name) for name in ("src_ip", "src_port")}
    pointers = {name: "/" + name for name in values if nonempty(values[name])}
    for name, paths in ALIASES.items():
        observed = [(p, get(eve, p)) for p in paths if nonempty(get(eve, p))]
        if len(observed) == 2 and observed[0][1] != observed[1][1]:
            raise ValueError("conflicting_alias:" + name)
        values[name] = observed[0][1] if observed else None
        if observed:
            pointers[name] = "/" + observed[0][0]
    for name, field in (("rule_id", "alert.signature_id"), ("signature", "alert.signature"),
                        ("alert_type", "event_type"), ("url", "http.url")):
        values[name] = get(eve, field)
        if nonempty(values[name]):
            pointers[name] = "/" + field.replace(".", "/")
    for field in ("http.hostname", "tls.sni"):
        if nonempty(get(eve, field)):
            values["domain"] = get(eve, field)
            pointers["domain"] = "/" + field.replace(".", "/")
            break
    return values, pointers


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for part in iter(lambda: f.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def identity(path):
    s = path.stat()
    return dict(compressed_size=s.st_size, mtime_ns=s.st_mtime_ns, sha256=digest(path))


def coverage(counts, denominator):
    return {field: {"count": counts[field], "denominator": denominator,
                    "percentage": round(100 * counts[field] / denominator, 4) if denominator else None}
            for field in sorted(counts)}


def label(value):
    return "<missing>" if value is None else str(value)


def flat_fields(obj, prefix=""):
    for k, v in obj.items():
        field = prefix + k
        yield field, v
        if type(v) is dict:
            yield from flat_fields(v, field + ".")


def microseconds(utc):
    dt = datetime.fromisoformat(utc.replace("Z", "+00:00"))
    delta = dt - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds


def select_samples(pool, count=12):
    """Deterministic greedy coverage of observed facts, never signature semantics."""
    unique = {(x["file"], x["ordinal"]): x for x in pool.values()}
    remaining = sorted(unique.values(), key=lambda x: (x["file"], x["ordinal"]))
    result, seen = [], set()
    def traits(item):
        e = item["eve"]
        return {(k, label(v)) for k, v in (
            ("file", item["file"]), ("signature", get(e, "alert.signature")),
            ("category", get(e, "alert.category")), ("severity", get(e, "alert.severity")),
            ("src", e.get("src_ip")), ("dst", e.get("dest_ip", e.get("dst_ip"))),
            ("hour", str(e.get("timestamp"))[:13]))}
    while remaining and len(result) < count:
        best = min(remaining, key=lambda x: (-len(traits(x) - seen), x["file"], x["ordinal"]))
        remaining.remove(best)
        result.append(best)
        seen.update(traits(best))
    return result


def mapping_preview(sample):
    """Schema proof only, with an explicitly provisional diagnostic namespace.

    Native category/severity remain unknown until a source mapping is approved.
    The raw EVE object is the pointer root; /_raw/timestamp cannot traverse a string.
    """
    eve = sample["eve"]
    values, pointers = detect_mapping(eve)
    values = {k: v for k, v in values.items() if nonempty(v)}
    values["timestamp"] = timestamp(eve["timestamp"])
    values["source_type"] = "suricata"
    values["source_namespace"] = "diagnostic.cptc.pending." + sample["file"].removesuffix(".json.gz")
    pointers.update(timestamp="/timestamp", source_type="/event_type")
    for name in ("src_ip", "dst_ip"):
        if name in values:
            values[name] = ip(values[name])
    for name in ("src_port", "dst_port"):
        if name in values:
            values[name] = integer(values[name], maximum=65535)
    if "rule_id" in values:
        values["rule_id"] = str(values["rule_id"])
    values.update(raw_alert=eve, raw_fingerprint=raw_fingerprint(eve))
    values["alert_id"] = id_for("CanonicalAlert", values)
    values["field_provenance"] = {k: {"raw_pointer": p, "transform": "cptc-step1-diagnostic-only-v1"}
                                   for k, p in pointers.items() if k in values}
    model = CanonicalAlert(**values)
    for p in model.field_provenance.values():
        resolve_pointer(model.raw_alert, p.raw_pointer)
    return {"status": "DIAGNOSTIC_ONLY_SOURCE_NAMESPACE_PENDING", "file": sample["file"],
            "ordinal": sample["ordinal"], "schema_validated": True,
            "mapping": {k: {"raw_pointer": p, "canonical_value": getattr(model, k)} for k, p in pointers.items() if k in values},
            "canonical_alert": model.model_dump(mode="json"),
            "raw_only_fields": [k for k in ("flow_id", "community_id", "proto", "app_proto", "tx_id", "flow", "in_iface", "direction") if k in eve],
            "pending": ["deployment source_namespace/network_namespace", "native severity/category versioned mappings",
                        "sensor metadata semantics; envelope host is not automatically target host"]}


TABLE = {"file": "VARCHAR", "ordinal": "BIGINT", "ts": "BIGINT", "utc": "VARCHAR",
         "src_ip": "VARCHAR", "dst_ip": "VARCHAR", "src_port": "BIGINT", "dst_port": "BIGINT",
         "signature": "VARCHAR", "signature_id": "VARCHAR", "category": "VARCHAR", "severity": "VARCHAR",
         "flow_id": "VARCHAR", "community_id": "VARCHAR", "host": "VARCHAR", "proto": "VARCHAR"}


def flush(db, rows):
    if rows:
        # Binding nested Python dict arrays is costly in DuckDB 1.4.1. A single
        # bounded JSON parameter lets DuckDB parse/vectorize the same facts.
        columns = ",".join(f"cast(json_extract_string(value,'$.{k}') AS {v})" for k, v in TABLE.items())
        db.execute(f"INSERT INTO alerts SELECT {columns} FROM json_each(?)", [json.dumps(rows, ensure_ascii=False, allow_nan=False)])
        rows.clear()


def scan_file(path, db, adapter, pool):
    before = identity(path)
    state = {"file": path.name, **before, "parse_complete": False, "gzip_valid": False}
    counts = Counter({k: 0 for k in FIELDS})
    types, all_fields = defaultdict(Counter), Counter()
    event_types, hosts, profiles, issues = Counter(), Counter(), Counter(), Counter()
    counters = Counter(record_count=0, valid_json_count=0, invalid_json_count=0,
                       valid_eve_count=0, invalid_eve_count=0, alert_count=0,
                       invalid_alert_structure_count=0, invalid_timestamp_count=0,
                       timestamp_descents=0, timestamp_ascents=0, timestamp_ties=0)
    offsets, adapter_rejects, raw_quality = Counter(), Counter(), Counter()
    previous, first_in_file, last_in_file, rows = None, None, None, []
    minima = maxima = None
    try:
        with gzip.open(path, "rt", encoding="utf-8-sig", errors="strict") as handle:
            for rec in stream_records(handle, state):
                counters["record_count"] += 1
                if rec.error:
                    counters["invalid_json_count"] += 1
                    issues[rec.error] += 1
                    continue
                counters["valid_json_count"] += 1
                try:
                    eve, profile = unwrap(rec.value)
                except (ValueError, TypeError) as exc:
                    counters["invalid_eve_count"] += 1
                    issues[str(exc)] += 1
                    continue
                counters["valid_eve_count"] += 1
                profiles[profile] += 1
                event_types[label(eve.get("event_type"))] += 1
                hosts[label(rec.value.get("host"))] += 1
                for candidate, raw in (("envelope", rec.value), ("decoded_eve", eve)):
                    try:
                        adapter.convert(raw)
                        adapter_rejects[candidate + ":accepted"] += 1
                    except (ValueError, TypeError, KeyError) as exc:
                        adapter_rejects[candidate + ":" + str(exc)[:80]] += 1
                if eve.get("event_type") != "alert":
                    continue
                if type(eve.get("alert")) is not dict or not eve["alert"]:
                    counters["invalid_alert_structure_count"] += 1
                    continue
                counters["alert_count"] += 1
                for field in FIELDS:
                    value = get(eve, field)
                    if nonempty(value):
                        counts[field] += 1
                        types[field][type(value).__name__] += 1
                for field, value in flat_fields(eve):
                    if nonempty(value):
                        all_fields[field] += 1
                try:
                    values, _ = detect_mapping(eve)
                except ValueError as exc:
                    raw_quality[str(exc)] += 1
                    values = {k: None for k in ("src_ip", "dst_ip", "src_port", "dst_port")}
                for k in ("src_ip", "dst_ip"):
                    try:
                        values[k] = ip(values[k])
                    except (ValueError, TypeError):
                        raw_quality["invalid_" + k] += 1
                        values[k] = None
                for k in ("src_port", "dst_port"):
                    if nonempty(values[k]):
                        try:
                            values[k] = integer(values[k], maximum=65535)
                        except ValueError:
                            raw_quality["invalid_" + k] += 1
                            values[k] = None
                    else:
                        values[k] = None
                utc, ts = None, None
                try:
                    utc = timestamp(eve.get("timestamp"))
                    ts = microseconds(utc)
                    match = re.search(r"(Z|[+-]\d{2}:?\d{2})$", eve["timestamp"])
                    offsets[match[1] if match else "missing"] += 1
                    first_in_file = first_in_file or utc
                    last_in_file = utc
                    minima = utc if minima is None else min(minima, utc)
                    maxima = utc if maxima is None else max(maxima, utc)
                    if previous is not None:
                        counters["timestamp_descents" if ts < previous else "timestamp_ascents" if ts > previous else "timestamp_ties"] += 1
                    previous = ts
                except (ValueError, OverflowError, TypeError):
                    counters["invalid_timestamp_count"] += 1
                    offsets["unparseable_or_missing"] += 1
                # Keep only compact selection traits. Full raw examples are
                # recovered by locator in a second streaming pass after SQL.
                item = {"file": path.name, "ordinal": rec.ordinal, "eve": {
                    **{k: eve.get(k) for k in ("timestamp", "src_ip", "dest_ip", "dst_ip") if k in eve},
                    "alert": {k: eve["alert"].get(k) for k in ("signature", "category", "severity")}}}
                # Bounded factual strata, no labels or hand-picked signatures.
                keys = [("sig", path.name, label(get(eve, "alert.signature"))),
                        ("severity", path.name, label(get(eve, "alert.severity"))),
                        ("hour", path.name, (utc or "missing")[:13])]
                for key in keys:
                    if key not in pool and len(pool) < 2000:
                        pool[key] = item
                pool[("last", path.name)] = item
                rows.append({"file": path.name, "ordinal": rec.ordinal, "ts": ts, "utc": utc,
                    **{k: values[k] for k in ("src_ip", "dst_ip", "src_port", "dst_port")},
                    **{k: None if get(eve, "alert." + k) is None else str(get(eve, "alert." + k))
                       for k in ("signature", "signature_id", "category", "severity")},
                    **{k: None if eve.get(k) is None else str(eve[k]) for k in ("flow_id", "community_id", "proto")},
                    "host": rec.value.get("host") if type(rec.value.get("host")) is str else None})
                if len(rows) >= 2048:
                    flush(db, rows)
            state["gzip_valid"] = True
    except (OSError, EOFError, UnicodeError, ValueError) as exc:
        issues["stream_failure:" + type(exc).__name__ + ":" + str(exc)[:80]] += 1
        state["parse_complete"] = False
    flush(db, rows)
    after = identity(path)
    state.update(counters)
    state.update(raw_unchanged=before == after, identity_after=after,
                 event_type_distribution=dict(sorted(event_types.items())),
                 envelope_host_distribution=dict(sorted(hosts.items())),
                 schema_profiles=dict(profiles), timestamp_offsets=dict(offsets),
                 first_timestamp=minima, last_timestamp=maxima,
                 first_timestamp_in_file_order=first_in_file, last_timestamp_in_file_order=last_in_file,
                 duration_seconds=(microseconds(maxima)-microseconds(minima))/1e6 if minima else None,
                 issues=dict(issues), normalization_quality_issues=dict(raw_quality),
                 current_wazuh_adapter_diagnostics=dict(adapter_rejects))
    return state, counts, types, all_fields


def query_rows(db, sql, args=None):
    cur = db.execute(sql, args or [])
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row)) for row in cur.fetchall()]


def entity_stats(db):
    result = {}
    for field in ("src_ip", "dst_ip", "src_port", "dst_port", "signature_id", "signature", "category", "flow_id", "community_id"):
        result["unique_" + field] = db.execute(f"SELECT count(DISTINCT {field}) FROM alerts").fetchone()[0]
        if field in ("src_ip", "dst_ip", "signature", "category"):
            result["top20_" + field] = query_rows(db, f'SELECT {field} AS "value",count(*) AS "count" FROM alerts WHERE {field} IS NOT NULL GROUP BY {field} ORDER BY "count" DESC,"value" LIMIT 20')
    addresses = [r[0] for r in db.execute("SELECT src_ip FROM alerts WHERE src_ip IS NOT NULL UNION SELECT dst_ip FROM alerts WHERE dst_ip IS NOT NULL").fetchall()]
    result["unique_ip_total"] = len(addresses)
    classes = Counter()
    for addr in addresses:
        obj = ipaddress.ip_address(addr)
        classes["IPv" + str(obj.version)] += 1
        classes["private_by_ipaddress"] += obj.is_private
        classes["public_global"] += obj.is_global
        classes["link_local"] += obj.is_link_local
        classes["multicast"] += obj.is_multicast
        classes["neither_private_nor_global"] += not obj.is_private and not obj.is_global
        if obj.version == 4:
            classes["rfc1918"] += any(obj in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    result["ip_classification"] = dict(classes)
    result["ip_classification_note"] = "Python ipaddress.is_private includes non-global special ranges; RFC1918, global, link-local are reported separately."
    result["scoped_uniques"] = {field: db.execute(f"SELECT count(*) FROM (SELECT DISTINCT file,host,{field} FROM alerts WHERE {field} IS NOT NULL)").fetchone()[0] for field in ("flow_id", "community_id")}
    result["namespace_note"] = "Literal global IP/flow counts describe values, not cross-file identity. File partitions remain separate; sensor host scopes flow diagnostics."
    return result


def time_stats(db, files):
    result = {"files": files, "timezone_policy": "Use inner _raw.timestamp offset; normalize +0000 to UTC Z, preserve microseconds; do not use Splunk _indextime or rounded _time.",
              "first_timestamp": min((f["first_timestamp"] for f in files if f["first_timestamp"]), default=None),
              "last_timestamp": max((f["last_timestamp"] for f in files if f["last_timestamp"]), default=None)}
    result["largest_adjacent_gaps"] = query_rows(db, """WITH q AS (SELECT file,ts,utc,
        lag(ts) OVER(PARTITION BY file ORDER BY ts,ordinal) prev_ts,
        lag(utc) OVER(PARTITION BY file ORDER BY ts,ordinal) prev_utc FROM alerts WHERE ts IS NOT NULL)
        SELECT file,prev_utc,utc,(ts-prev_ts)/1000000.0 gap_seconds FROM q WHERE prev_ts IS NOT NULL
        ORDER BY gap_seconds DESC,file,utc LIMIT 20""")
    result["gap_counts"] = query_rows(db, """WITH q AS (SELECT file,ts-lag(ts) OVER(PARTITION BY file ORDER BY ts,ordinal) gap FROM alerts WHERE ts IS NOT NULL)
        SELECT file,count(*) FILTER(WHERE gap>60000000) gaps_over_1min,
        count(*) FILTER(WHERE gap>300000000) gaps_over_5min,
        count(*) FILTER(WHERE gap>3600000000) gaps_over_1hour FROM q GROUP BY file ORDER BY file""")
    result["pairwise_interval_relationships"] = []
    for i, a in enumerate(files):
        for b in files[i + 1:]:
            if not a["first_timestamp"] or not b["first_timestamp"]:
                continue
            signed = min(microseconds(a["last_timestamp"]), microseconds(b["last_timestamp"])) - max(microseconds(a["first_timestamp"]), microseconds(b["first_timestamp"]))
            result["pairwise_interval_relationships"].append({"a": a["file"], "b": b["file"],
                "relationship": "overlap" if signed >= 0 else "disjoint", "overlap_seconds": max(0, signed)/1e6, "gap_seconds": max(0, -signed)/1e6})
    return result


def continuity(db):
    specifications = {"same_src_ip": ["file", "src_ip"], "same_dst_ip": ["file", "dst_ip"],
                      "same_ip_pair": ["file", "src_ip", "dst_ip"],
                      "same_sensor_flow": ["file", "host", "flow_id"],
                      "same_sensor_host": ["file", "host"]}
    summaries, group_candidates, windows = {}, {}, {}
    partitions = [r[0] for r in db.execute("SELECT DISTINCT file FROM alerts ORDER BY file").fetchall()]
    for name, keys in specifications.items():
        cols = ",".join(keys)
        present = " AND ".join(k + " IS NOT NULL" for k in keys)
        groups_sql = f"""SELECT {cols},count(*) alert_count,count(DISTINCT signature) signature_count,
            count(DISTINCT category) category_count,count(DISTINCT ts) timestamp_count,
            count(DISTINCT (dst_ip,dst_port,proto)) destination_service_count,
            min(utc) first_timestamp,max(utc) last_timestamp FROM alerts WHERE {present} GROUP BY {cols}"""
        # Distinct aggregation state can exceed a small memory limit even
        # though raw input streams. Each file is already a separate scope, so
        # aggregate one file at a time and spill only compact group summaries.
        table = "audit_groups_" + name
        db.execute(f"CREATE TEMP TABLE {table} AS SELECT * FROM ({groups_sql}) LIMIT 0")
        for partition in partitions:
            partition_sql = groups_sql.replace(f"WHERE {present}", f"WHERE {present} AND file=?")
            db.execute(f"INSERT INTO {table} {partition_sql}", [partition])
        summaries[name] = query_rows(db, f"""SELECT count(*) distinct_keys,
            count(*) FILTER(WHERE alert_count>1) repeated_keys,
            coalesce(sum(alert_count) FILTER(WHERE alert_count>1),0) alerts_in_repeated_keys,
            count(*) FILTER(WHERE signature_count>1) multi_signature_keys,
            count(*) FILTER(WHERE signature_count>1 AND timestamp_count>1) multi_signature_multi_time_keys
            FROM {table}""")[0]
        group_candidates[name] = query_rows(db, f"SELECT * FROM {table} WHERE signature_count>1 AND timestamp_count>1 ORDER BY signature_count DESC,alert_count DESC,{cols} LIMIT 6")
        db.execute(f"DROP TABLE {table}")
        lag_sql = f"""SELECT file,ts,ts-lag(ts) OVER(PARTITION BY {cols} ORDER BY ts,ordinal) gap
            FROM alerts WHERE {present} AND ts IS NOT NULL"""
        windows[name] = {}
        for seconds in WINDOWS:
            # Each later alert counted once if an earlier occurrence exists in
            # the inclusive window; this is not all-pair enumeration or scoring.
            windows[name][str(seconds)] = query_rows(db, f"SELECT file,count(*) eligible_timed_alerts,count(*) FILTER(WHERE gap BETWEEN 0 AND ?) later_alerts_with_prior_same_key FROM ({lag_sql}) GROUP BY file ORDER BY file", [seconds * 1000000])
    selected, evidence = set(), []
    for name in specifications:
        for row in group_candidates[name]:
            keys = specifications[name]
            where = " AND ".join(k + "=?" for k in keys)
            rows = query_rows(db, f"""SELECT * EXCLUDE(rn) FROM (SELECT *,row_number() OVER(PARTITION BY signature ORDER BY ts,ordinal) rn
                FROM alerts WHERE {where} AND ts IS NOT NULL) WHERE rn=1 ORDER BY ts,ordinal LIMIT 6""", [row[k] for k in keys])
            locators = tuple((r["file"], r["ordinal"]) for r in rows)
            if len(rows) < 2 or locators in selected:
                continue
            selected.add(locators)
            evidence.append({"type": "Potential Multi-Alert Evidence Group", "criterion": name,
                             "key": {k: row[k] for k in keys}, "summary": row, "alerts": rows})
            break
    return {"status": "RAW_CONTINUITY_ONLY_NO_CORRELATION", "group_count": len(evidence), "groups": evidence,
            "full_scan_statistics": summaries, "window_seconds": list(WINDOWS), "window_statistics": windows,
            "window_definition": "Later records with a prior same scoped key in inclusive [t-window,t], counted once; adjacent sorted lag suffices. No scoring/candidates/edges.",
            "scope": "file partitions are not merged; flow additionally uses envelope host; src/dst IP repetition is a literal diagnostic, not an asserted host or attack identity.",
            "limitations": ["Repeated signatures/entities are not confirmed attack stages, causality, or ground truth.",
                            "Splunk host is observed collector metadata; not automatically CanonicalAlert.host.",
                            "Single Suricata source cannot prove endpoint process/account activity or independent source corroboration."]}


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def run_audit(input_dir, output_dir):
    import duckdb
    input_dir, output_dir = Path(input_dir).resolve(), Path(output_dir).resolve()
    if input_dir == output_dir or input_dir in output_dir.parents or output_dir in input_dir.parents:
        raise ValueError("output_must_be_separate_from_raw_input")
    output_dir.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    config = load_config(ROOT / "configs/algorithm-v0.yaml", deployment_override=ROOT / "configs/sources.yaml")
    adapter = WazuhAdapter(config, AdapterSettings(source_namespace="diagnostic.cptc.pending", format_profile="wazuh_json_v1", generator="Wazuh"))
    stats, by_file, pooled_counts, field_types, field_inventory, pool = [], {}, Counter({k: 0 for k in FIELDS}), defaultdict(Counter), Counter(), {}
    with tempfile.TemporaryDirectory(prefix="audit_work_", dir=output_dir) as work:
        db = duckdb.connect(str(Path(work) / "observations.duckdb"))
        try:
            db.execute("SET memory_limit='256MB'")
            db.execute("SET threads=1")
            db.execute("SET preserve_insertion_order=false")
            db.execute("CREATE TABLE alerts (" + ",".join(k + " " + v for k, v in TABLE.items()) + ")")
            for filename in FILES:
                path = input_dir / filename
                if not path.is_file():
                    stats.append({"file": filename, "missing": True, "parse_complete": False, "first_timestamp": None, "last_timestamp": None, "alert_count": 0})
                    continue
                state, counts, types, inventory = scan_file(path, db, adapter, pool)
                stats.append(state)
                pooled_counts.update(counts)
                field_inventory.update(inventory)
                for k, v in types.items():
                    field_types[k].update(v)
                by_file[filename] = coverage(counts, state["alert_count"])
                print(filename, "records=", state["record_count"], "alerts=", state["alert_count"], "complete=", state["parse_complete"], flush=True)
            total = sum(f["alert_count"] for f in stats)
            logical = Counter(pooled_counts)
            for field in ALIASES:
                logical[field] = db.execute(f"SELECT count({field}) FROM alerts").fetchone()[0]
            field_data = {"denominator": "valid parsed records with event_type=alert and nonempty alert object; all files scanned",
                          "alert_count": total, "raw_fields": coverage(pooled_counts, total), "canonical_logical_fields": coverage(logical, total),
                          "by_file": by_file, "field_types": {k: dict(v) for k, v in field_types.items()}, "all_observed_field_counts": dict(field_inventory)}
            entities, times, potential = entity_stats(db), time_stats(db, stats), continuity(db)
            samples = select_samples(pool)
            # Recover exactly the raw evidence locators chosen by factual SQL.
            wanted = defaultdict(set)
            for group in potential["groups"]:
                for row in group["alerts"]:
                    wanted[row["file"]].add(row["ordinal"])
            for sample in samples:
                wanted[sample["file"]].add(sample["ordinal"])
            evidence_raw = {}
            for filename, ordinals in sorted(wanted.items()):
                with gzip.open(input_dir / filename, "rt", encoding="utf-8-sig") as handle:
                    for rec in stream_records(handle, {}):
                        if rec.ordinal in ordinals and rec.error is None:
                            eve, _ = unwrap(rec.value)
                            evidence_raw[(filename, rec.ordinal)] = {"raw_suricata": eve, "raw_envelope": rec.value}
                        if rec.ordinal >= max(ordinals):
                            break
            for group in potential["groups"]:
                for row in group["alerts"]:
                    row.update(evidence_raw[(row["file"], row["ordinal"])])
            for sample in samples:
                full = evidence_raw[(sample["file"], sample["ordinal"])]
                sample.update(eve=full["raw_suricata"], envelope=full["raw_envelope"])
            previews, preview_errors = [], []
            for sample in samples:
                try:
                    previews.append(mapping_preview(sample))
                except (ValueError, TypeError, KeyError) as exc:
                    preview_errors.append({"file": sample["file"], "ordinal": sample["ordinal"], "error": str(exc)})
            valid = total > 0 and all(f.get("parse_complete") and f.get("gzip_valid") and f.get("raw_unchanged") and not f.get("invalid_json_count") and not f.get("invalid_eve_count") and not f.get("invalid_alert_structure_count") for f in stats)
            task_result = "CPTC_ADAPTER_CHANGES_REQUIRED" if valid else "CPTC_RAW_DATA_INVALID"
            result = {"task_result": task_result, "adapter_decision": "CPTC_ADAPTER_REQUIRED", "alert_count": total,
                      "files": stats, "existing_config_hash": config.config_hash, "runtime_seconds": round(time.perf_counter() - started, 3),
                      "parser_limits": {"chunk_chars": 65536, "max_record_chars": 8388608, "compact_insert_batch": 2048, "sample_strata_limit": 2000, "duckdb_memory_limit": "256MB"},
                      "scope": "CPTC-2018 Step 1 only; no production writes, no GT, no correlation/triage/clustering/chain execution"}
            write_json(output_dir / "cptc_file_statistics.json", result)
            write_json(output_dir / "cptc_field_coverage.json", field_data)
            write_json(output_dir / "cptc_entity_statistics.json", entities)
            write_json(output_dir / "cptc_time_summary.json", times)
            write_json(output_dir / "cptc_sample_alerts.json", {"selection": "deterministic greedy diversity over first observed file/signature/severity/hour strata and last records; no attack labels or semantic ranking", "samples": samples, "canonical_mapping_previews": previews, "preview_errors": preview_errors})
            write_json(output_dir / "cptc_potential_continuity.json", potential)
            write_report(output_dir, result, field_data, entities, times, potential, previews)
        finally:
            db.close()
    return result


def write_report(out, result, fields, entities, times, potential, previews):
    files = result["files"]
    lines = ["# CPTC-2018 Step 1 原始告警审计与接入诊断", "", result["task_result"], "", 
             "本报告仅描述完整扫描的设备告警字段与跨告警复用。未运行 Correlation v4、去重、实体生产流程、聚类、攻击链、triage 或评测；未读取 GT。", "",
             "## 方法与原始文件保护", "",
             "gzip 文本按 64 Ki 字符分块、单个数组元素解析（单条上限 8 Mi 字符），没有整体 json.load、长期解压文件。外层和 _raw 分别严格校验 JSON（拒绝重复 key、非有限数）。JSONL 可逐条隔离；数组尾损坏时报告未完成，不猜测剩余条数。gzip 读至 EOF 核验 CRC。紧凑统计落临时 DuckDB，256MB 内存上限，结束自动清理。抽样池仅存最多 2000 组紧凑字段，最终样例按 locator 二次流式回读完整原文。",
             "SHA256/字节大小/mtime_ns 在扫描前后核对，见 cptc_file_statistics.json。数据不改动、不重新下载。文件内 ordinal 仅定位审计样例，不作为生产 alert_id。", "",
             "## Q1–Q5：格式、数量与时间", "", f"Q1：全部正常解析：{all(f.get('parse_complete') and f.get('gzip_valid') for f in files)}。",
             "", "| 文件 | 压缩字节 | 记录 | 有效外层 JSON | 无效外层 JSON | alert | 最早 UTC | 最晚 UTC | 跨度秒 | 倒序相邻 | 升序相邻 |",
             "|---|---:|---:|---:|---:|---:|---|---|---:|---:|---:|"]
    for f in files:
        lines.append("| " + " | ".join(str(f.get(k)) for k in ("file", "compressed_size", "record_count", "valid_json_count", "invalid_json_count", "alert_count", "first_timestamp", "last_timestamp", "duration_seconds", "timestamp_descents", "timestamp_ascents")) + " |")
    lines += ["", f"Q2/Q3：总计 {result['alert_count']} 条有效 alert，文件计数按原始记录统计，未去重。",
              f"Q4：{times['first_timestamp']} — {times['last_timestamp']}。", "",
              "Q5：实际格式见下表。外层 Splunk 导出数组不等于原生 EVE JSONL；内层 _raw 为 JSON 字符串，保存 EVE 风格安全告警。", "",
              "| 文件 | 实际外层格式 | 内层 profile | 实测 event_type | 无效 _raw / EVE | 原始时区 |", "|---|---|---|---|---:|---|"]
    for f in files:
        lines.append(f"| {f['file']} | {f.get('format')} | {f.get('schema_profiles')} | {f.get('event_type_distribution')} | {f.get('invalid_eve_count')} | {f.get('timestamp_offsets')} |")
    lines += ["", "时间与字段质量异常（完整扫描）：", "", "```json", json.dumps({f['file']: {
        'unparseable_timestamps': f.get('invalid_timestamp_count'), 'normalization_quality_issues': f.get('normalization_quality_issues'),
        'issues': f.get('issues'), 'timestamp_ties': f.get('timestamp_ties')} for f in files}, ensure_ascii=False, indent=2), "```"]
    lines += ["", "六份文件的时间区间关系逐对记录于 cptc_time_summary.json，不能把 t1/t2/t5/t7/t8/t9 当作连续时间分片或攻击阶段。相邻降序是输入导出顺序事实，不自动代表时间损坏。最早/最晚按全扫描极值计算，不取第一/最后条冒充。", "", "```text"]
    for f in files:
        lines.append(f"{f['file']}: [{f['first_timestamp']} -------- {f['last_timestamp']}]")
    lines += ["```", "", "最大 20 个文件内相邻时间空洞（升序排序后计算）：", "", "| 文件 | 前一条 UTC | 后一条 UTC | 空洞秒 |", "|---|---|---|---:|"]
    for row in times["largest_adjacent_gaps"]:
        lines.append(f"| {row['file']} | {row['prev_utc']} | {row['utc']} | {row['gap_seconds']} |")
    lines += ["", "## Q6–Q8：字段与 CanonicalAlert", "",
              "当前最低必需字段：alert_id、timestamp、source_type、source_namespace、raw_alert、raw_fingerprint、field_provenance；schema_version 默认 1.0。entity_ids/occurrences/relations 可为空；不存在事实字段保持 null，category/severity 可 unknown。",
              "AdapterSettings 要求 source_namespace、format_profile、generator；AlertAdapter.extract 返回 facts/pointers/context，convert 负责 raw fingerprint、Stable ID、IP/port 和映射校验。",
              "", "| 原生 EVE 字段 | 真实 CanonicalAlert 目标 / 策略 |", "|---|---|",
              "| timestamp | timestamp；公共 timestamp helper 支持 +0000 → UTC 微秒 |",
              "| src_ip/src_port | src_ip/src_port；公共 ip/integer helper |",
              "| dest_ip/dest_port | dst_ip/dst_port；显式别名冲突拒绝 |",
              "| alert.signature/alert.signature_id | signature/rule_id（数值规则 ID 转文本） |",
              "| event_type | alert_type；验证 alert 对象之后设置 source_type=suricata |",
              "| alert.category | vendor_category context → 独立版本化 Category 映射，禁止直接放入枚举 |",
              "| alert.severity | raw_severity context → 原生 Suricata 量纲的独立 YAML，尚未确认映射时 unknown |",
              "| http.url/http.hostname/tls.sni | url/domain；保留路径、query 及真实 pointer |",
              "| flow_id/community_id/proto/app_proto/tx_id/flow/in_iface/direction | 只保留于 raw_alert；当前模型无 source_context/proto/flow_id 顶层字段 |",
              "| Splunk host | 采集元数据；可作为待核验 sensor 展示名，不能直接推为目标 host |",
              "| _cd/_bkt/_serial/_indextime | 导出元数据；未证明是设备原生告警 ID，source_record_id 保持 null |",
              "", "字段覆盖率：分母为完整扫描所得有效 alert；0、false 为存在值，null/空串/空对象/空数组不计非空覆盖。原生路径与有效别名覆盖分别输出。", "",
              "| 字段 | 非空数量 / alert 分母 | 覆盖率 |", "|---|---:|---:|"]
    for k, v in fields["raw_fields"].items():
        lines.append(f"| {k} | {v['count']} / {v['denominator']} | {v['percentage']}% |")
    lines += ["", "Q7：完全缺失字段：" + ", ".join(k for k, v in fields["raw_fields"].items() if not v["count"]),
              "部署 source_namespace/network_namespace 没有由安全告警声明，须外部配置确认；不从文件名、team 号、私网 IP 或 Splunk index 推断部署身份。", "",
              "Q8：flow_id/community_id 覆盖率如上；flow_id 只在 sensor/部署范围内作诊断，不能把裸值相等视为跨文件同连接。保留网络上下文不证明传播关系。现有 configs/algorithm-v4.yaml 已为 suricata 声明 /flow_id、/tx_id、/proto、/timestamp 原生 event_pointers；ObservationMatcher 可从 raw_alert 根解析这些字段，因此采用原生 EVE 作为 raw_alert 根可兼容已有指针配置，无需为了本数据改算法。本阶段仅核查代码和路径，未调用 ObservationMatcher 或评分。", "",
              "三条以上 Raw → CanonicalAlert 的完整 schema 校验示例见 cptc_sample_alerts.json。下例仅是诊断投影，namespace 带 pending，category/severity=unknown，没有发布生产告警。", ""]
    for preview in previews[:3]:
        lines += [f"### {preview['file']} ordinal {preview['ordinal']}（诊断）", "", "```json", json.dumps(preview["mapping"], ensure_ascii=False, indent=2), "```", ""]
    lines += ["指针设计：若 canonical.raw_alert 采用解码后的原生 EVE 对象，则 /timestamp、/alert/signature、/dest_ip 均可直接解析。原始 Splunk envelope 完整保留在审计样例；不能构造 /_raw/timestamp，因为 _raw 是字符串。后续若坚持 envelope 为 raw_alert，只能绑定 /_raw 并显式记录解析变换，不能伪造可穿透字符串的 JSON Pointer。", "",
              "## 实体质量与频率", "", "```json", json.dumps({k: v for k, v in entities.items() if not k.startswith('top20')}, ensure_ascii=False, indent=2), "```", ""]
    for field in ("src_ip", "dst_ip", "signature", "category"):
        lines += [f"### Top20 {field}", "", "| 值 | 次数 |", "|---|---:|"]
        for row in entities["top20_" + field]:
            lines.append(f"| {str(row['value']).replace('|', '/')} | {row['count']} |")
        lines.append("")
    lines += ["## Q9–Q10：跨告警连续性与潜在序列", "", "```json", json.dumps(potential["full_scan_statistics"], ensure_ascii=False, indent=2), "```", "",
              "1/5/15/30/60 min 全量窗口统计见 cptc_potential_continuity.json。每条后续告警最多计一次：窗口内存在同 file scoped key 的较早/同时间记录；相邻 lag 即可验证。没有复制或执行 Correlation 候选/评分。", "",
              f"Q9：抽出 {potential['group_count']} 组真实跨告警实体复用示例。Q10：可以观察到同实体、不同 signature、不同时间的告警序列；它们只是潜在多告警证据，不证明多个攻击阶段或成功攻击，不按 signature 名称编排攻击链。", ""]
    for i, group in enumerate(potential["groups"], 1):
        lines += [f"### Potential Multi-Alert Evidence Group {i}: {group['criterion']}", "", str(group["key"]), "",
                  "| UTC | src_ip:port | dst_ip:port | signature | category | flow_id | raw source file / ordinal |", "|---|---|---|---|---|---|---|"]
        for r in group["alerts"]:
            lines.append(f"| {r['utc']} | {r['src_ip']}:{r['src_port']} | {r['dst_ip']}:{r['dst_port']} | {str(r['signature']).replace('|', '/')} | {r['category']} | {r['flow_id']} | {r['file']} / {r['ordinal']} |")
        lines.append("")
    lines += ["## Q11：现有 Adapter 兼容性结论", "", "CPTC_ADAPTER_REQUIRED", "",
              "生产注册表 backend/app/services/analysis.py 当前仅 wazuh/aminer。WazuhAdapter 需要 /rule、从 /data/* 抽取 Suricata，只有 rule.groups 包含 suricata + data.event_type=alert + data.alert 对象时识别产品。CPTC envelope 与解码 EVE 均缺 Wazuh rule，全量逐条 convert 诊断如下：", "", "```json",
              json.dumps({f['file']: f.get('current_wazuh_adapter_diagnostics') for f in files}, ensure_ascii=False, indent=2), "```", "",
              "AlertAdapter.read_file 只允许 .json/.jsonl/.ndjson，并不接受 .gz。现有 Suricata severity YAML 实际仍为 Wazuh rule.level 的 0–15 区间；不能直接用于原生 alert.severity。category YAML 仅匹配 Wazuh rule_groups，CPTC 不具备该 context，不应虚构组名。",
              "可复用：AlertAdapter.convert、timestamp/IP/port/text/URL helpers、Stable ID/raw_fingerprint、严格 Schema、Mapping v1 加载、去重/实体契约。已存在的 Wazuh Suricata 解析仅是 envelope 专用代码，尚无可直接调用的独立原生 Suricata Adapter。",
              "## Q12：后续独立 Adapter 设计文件清单（本次未实现）", "",
              "- backend/app/adapters/suricata.py：通用 native EVE AlertAdapter，不按数据集 IP/时间/signature 分支；显式原生字段 pointers。",
              "- backend/app/adapters/cptc.py 或独立 ingress profile：流式解码 Splunk 导出 + _raw；确认原始告警根与 export metadata 保存策略。",
              "- backend/app/adapters/__init__.py、backend/app/services/analysis.py、backend/app/services/datasets.py：最小 source/profile 注册；须下一阶段显式授权。",
              "- configs/mappings/cptc-suricata-severity.yaml / cptc-suricata-category.yaml / cptc-suricata-payload.yaml：独立映射并由部署 profile 选择，保留现有 AIT 映射；原生 severity 量纲先核验。",
              "- data/cptc_2018/dataset.yaml：仅候选配置，确认 dataset identity、source_namespace、sensor、network scope、原生/导出 ID 血缘；不猜文件是否同网络。",
              "- backend/tests/test_suricata_adapter.py / test_cptc_adapter.py：真实格式、gzip、时区、Stable ID、pointer、别名冲突、隔离及既有 AIT 回归。",
              "", "CanonicalAlert 模型无需修改，不新增 source_context、proto、flow_id；不改算法配置、评分、阈值、guard 或 chain relation。保存 flow 在 raw_alert 与接入算法如何使用它是不同能力，本次只诊断保存方式。", "",
              "## 验证与停止点", "", "实际测试日志、只读保护清单另存本目录。无 Git 元数据，文件保护使用摘要/元数据快照核验，不能提供 git diff。",
              "复现：`.venv/Scripts/python.exe -B scripts/audit_cptc_2018.py`。本目录 7 个必需产物均来自扫描；临时 DuckDB 自动删除。下一步建议是在明确部署 namespace/网络隔离与原生 severity 映射后实施独立 Adapter，并单独验收真实接入；本次停在 Step 1。"]
    (out / "CPTC_RAW_AUDIT_REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=ROOT / "data/cptc_2018/raw/suricata")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "outputs/cptc_2018_step1")
    args = parser.parse_args()
    answer = run_audit(args.input_dir, args.output_dir)
    print(answer["task_result"], flush=True)
