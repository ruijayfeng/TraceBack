"""Synthetic boundary tests plus read-only real-source mapping proof; no GT."""
import copy
import gzip
import io
import json
from pathlib import Path
import sys

import pytest

from app.adapters.base import AdapterSettings
from app.adapters.cptc import json_array_items, load_cptc_dataset, read_cptc_file, strict_json, unwrap_splunk
from app.adapters.suricata import SuricataAdapter, alert_warnings
from app.entities.extraction import extract_entities
from app.models import CanonicalAlert
from app.models.base import resolve_pointer
from app.utils.stable_id import id_for, raw_fingerprint

ROOT = Path(__file__).resolve().parents[2]


def synthetic_eve(**changes):
    eve = {"timestamp": "2018-11-03T10:00:00.123456+0000", "event_type": "alert",
        "src_ip": "192.0.2.1", "dest_ip": "198.51.100.1", "src_port": 0, "dest_port": 80,
        "proto": "TCP", "flow_id": 2 ** 60 + 1, "tx_id": 0,
        "alert": {"signature": "synthetic SCAN wording", "signature_id": 12345,
                  "severity": 2, "category": "synthetic unknown class", "action": "allowed"},
        "http": {"hostname": "Synthetic.EXAMPLE.", "url": "/a?b=1"}}
    eve.update(changes)
    return eve


def wrapper(eve):
    return {"_raw": json.dumps(eve), "host": "synthetic-real-export-host", "_cd": "export locator", "_serial": 999}


@pytest.fixture
def dataset():
    return load_cptc_dataset(ROOT)


@pytest.fixture
def adapter(dataset):
    return dataset.adapters["t1"]


def write_gzip(path, data):
    with gzip.open(path, "wt", encoding="utf8") as handle:
        handle.write(data)
    return path


class BoundedReader(io.StringIO):
    def read(self, size=-1):
        assert 0 < size <= 32
        return super().read(size)
    def readline(self, *args):
        raise AssertionError("must not read the entire single-line array")


def test_gzip_array_reader_preserves_wrapper_and_raw(tmp_path):
    eve = synthetic_eve()
    source = wrapper(eve)
    path = write_gzip(tmp_path / "synthetic.json.gz", json.dumps([source, source]))
    before = path.read_bytes()
    records = list(read_cptc_file(path, chunk_size=32))
    assert records[0].wrapper == source and records[0].eve == eve
    assert [r.ordinal for r in records] == [1, 2]
    assert path.read_bytes() == before


def test_array_is_incremental_with_bom_escapes_chunk_boundaries():
    data = [wrapper(synthetic_eve(packet='brackets ], } and "quote"'))] * 100
    text = "\ufeff  \n" + json.dumps(data)
    reader = BoundedReader(text)
    iterator = json_array_items(reader, chunk_size=32)
    first = strict_json(next(iterator))
    assert reader.tell() < len(text)
    assert first == data[0]
    assert [first] + [strict_json(item) for item in iterator] == data


@pytest.mark.parametrize("data", ["", "{}", "[", "[{},]", "[{}", "[{}]junk", "[{} {}]", "[1foo]"])
def test_malformed_outer_json_aborts_explicitly(data):
    with pytest.raises(ValueError):
        list(json_array_items(io.StringIO(data), chunk_size=16, max_record_chars=64))


def test_bounded_record_limit():
    with pytest.raises(ValueError, match="record_size_limit"):
        list(json_array_items(BoundedReader(json.dumps([{"long": "x" * 500}])), chunk_size=32, max_record_chars=64))


def test_gzip_crc_failure_is_not_hidden_by_successful_prefix(tmp_path):
    path = write_gzip(tmp_path / "synthetic.json.gz", json.dumps([wrapper(synthetic_eve())]))
    payload = bytearray(path.read_bytes())
    payload[-8] ^= 1
    path.write_bytes(payload)
    with pytest.raises((OSError, EOFError)):
        list(read_cptc_file(path, chunk_size=32))


@pytest.mark.parametrize("record,reason", [({}, "invalid_splunk_object"), ({"host": "x"}, "missing_raw"),
    ({"_raw": {}}, "raw_not_json_string"), ({"_raw": "broken"}, "raw_json_malformed"),
    ({"_raw": "[]"}, "invalid_eve_object"), ({"_raw": '{"a":NaN}'}, "raw_json_malformed"),
    ({"_raw": '{"a":1,"a":2}'}, "raw_json_malformed")])
def test_bad_record_is_explicitly_isolated(tmp_path, record, reason):
    path = write_gzip(tmp_path / "synthetic.json.gz", json.dumps([record, wrapper(synthetic_eve())]))
    results = list(read_cptc_file(path))
    assert results[0].error == reason
    assert results[0].wrapper is None
    assert results[1].error is None


def test_duplicate_outer_json_key_and_annotation_contamination(tmp_path):
    path = write_gzip(tmp_path / "synthetic.json.gz", '[{"_raw":"{}","_raw":"{}"}]')
    assert list(read_cptc_file(path))[0].error == "duplicate_json_key"
    for raw in (dict(wrapper(synthetic_eve()), label="synthetic truth"), wrapper(synthetic_eve(labels=["synthetic truth"]))):
        with pytest.raises(ValueError, match="annotation_contamination"):
            unwrap_splunk(raw)


def test_native_normalization_schema_flow_and_evidence(adapter):
    eve = synthetic_eve()
    original = copy.deepcopy(eve)
    alert = adapter.convert(eve)
    assert alert.timestamp == "2018-11-03T10:00:00.123456Z"
    assert alert.src_ip == "192.0.2.1" and alert.dst_ip == "198.51.100.1"
    assert alert.src_port == 0 and alert.dst_port == 80
    assert alert.rule_id == "12345" and alert.signature == eve["alert"]["signature"]
    assert alert.category.value == "unknown"  # SCAN wording cannot create stages/categories.
    assert alert.raw_alert == original == eve
    assert alert.raw_alert["flow_id"] == 2 ** 60 + 1
    assert alert.raw_fingerprint == raw_fingerprint(eve)
    assert alert.alert_id == id_for("CanonicalAlert", alert)
    assert alert.field_provenance["dst_ip"].raw_pointer == "/dest_ip"
    assert all(resolve_pointer(alert.raw_alert, p.raw_pointer) is not None for p in alert.field_provenance.values())
    assert CanonicalAlert.model_validate_json(alert.canonical_json()) == alert
    assert not {"protocol", "flow_id", "metadata"} & CanonicalAlert.model_fields.keys()


@pytest.mark.parametrize("native,expected", [(1, "high"), (2, "medium"), (3, "low"), (4, "unknown"), (255, "unknown"), (None, "unknown")])
def test_native_severity_mapping_and_unknown_warning(adapter, native, expected):
    eve = synthetic_eve()
    eve["alert"]["severity"] = native
    alert = adapter.convert(eve)
    assert alert.severity.value == expected
    assert alert.raw_alert["alert"]["severity"] == native
    assert ("severity_unknown" in alert_warnings(alert)) == (expected == "unknown")


@pytest.mark.parametrize("native", [0, -1, 256, True, "1", 1.5])
def test_invalid_severity_rejected(adapter, native):
    eve = synthetic_eve()
    eve["alert"]["severity"] = native
    with pytest.raises(ValueError, match="invalid_severity"):
        adapter.convert(eve)


@pytest.mark.parametrize("changes", [{"event_type": "flow"}, {"timestamp": None}, {"timestamp": "bad"},
    {"src_ip": "bad"}, {"dest_ip": "999.0.0.1"}, {"src_port": True}, {"dest_port": 65536},
    {"dest_port": 1.5}, {"dst_ip": "192.0.2.5"}, {"dst_port": 81}, {"alert": None}])
def test_invalid_native_record_rejected(adapter, changes):
    with pytest.raises(ValueError):
        adapter.convert(synthetic_eve(**changes))


def test_missing_optional_fields_are_not_fabricated(adapter):
    eve = {"timestamp": "2018-11-03T10:00:00Z", "event_type": "alert", "alert": {}}
    alert = adapter.convert(eve)
    assert set(alert_warnings(alert)) == {"missing_signature", "missing_rule_id", "missing_src_ip", "missing_dst_ip", "severity_unknown"}
    assert alert.sensor is alert.host is alert.session is None
    assert alert.entity_ids == []


def test_double_slash_request_path_survives_adapter_and_entity_extraction(adapter):
    eve = synthetic_eve(http={"url": "//", "hostname": "synthetic.example"})
    alert = adapter.convert(eve)
    assert alert.url == "//" and alert.raw_alert["http"]["url"] == "//"
    extracted = extract_entities([alert], {adapter.settings.source_namespace: adapter.settings})
    assert not any(e.type.value == 'URL' for e in extracted.entities)
    assert extracted.alerts[0].url == '//'
    assert extracted.alerts[0].raw_evidence['http']['url'] == '//'


def test_identity_uses_native_content_namespace_not_export_locator(dataset):
    eve = synthetic_eve()
    first, second = wrapper(eve), wrapper(eve)
    second.update(_cd="changed locator", _serial=1, host="changed export host")
    a = dataset.adapters["t1"].convert(unwrap_splunk(first))
    b = dataset.adapters["t1"].convert(unwrap_splunk(second))
    assert a.alert_id == b.alert_id
    assert a.alert_id == dataset.adapters["t1"].convert(dict(reversed(list(eve.items())))).alert_id
    ids = {adapter.convert(eve).alert_id for adapter in dataset.adapters.values()}
    assert len(ids) == 6
    changed = synthetic_eve(flow_id=999)
    assert dataset.adapters["t1"].convert(changed).alert_id != a.alert_id


def test_shared_network_scope_and_no_invented_entities(dataset):
    alerts = [adapter.convert(synthetic_eve()) for adapter in dataset.adapters.values()]
    extracted = extract_entities(alerts, dataset.source_settings)
    assert not extracted.entities  # Endpoints remain context, not core entities.
    assert all(a.src_ip and a.dst_ip for a in extracted.alerts)
    assert all(a.url and a.domain for a in extracted.alerts)
    assert all(a.relations == [] for a in extracted.alerts)
    shuffled = extract_entities(list(reversed(alerts)), dataset.source_settings)
    assert [e.canonical_json() for e in extracted.entities] == [e.canonical_json() for e in shuffled.entities]


def test_all_six_real_partition_first_records_read_only(dataset):
    for partition, path in dataset.paths.items():
        before = path.stat()
        record = next(read_cptc_file(path))
        assert not record.error
        alert = dataset.adapters[partition].convert(record.eve)
        assert alert.source_namespace == "cptc_2018." + partition
        assert alert.raw_alert == strict_json(record.wrapper["_raw"])
        assert alert.raw_alert["alert"]["signature_id"] == int(alert.rule_id)
        assert path.stat().st_size == before.st_size and path.stat().st_mtime_ns == before.st_mtime_ns


def test_profile_and_config_boundary(dataset):
    with pytest.raises(ValueError, match="unsupported_suricata_format_profile"):
        SuricataAdapter(dataset.config, AdapterSettings("synthetic", "wazuh_json_v1", "Suricata"))
    assert len(dataset.config.snapshot["normalization"]["severity_mapping_files"]) == 1
    assert dataset.config.snapshot["normalization"]["severity_mapping_files"][0]["rules"][0]["id"].startswith("native-priority")


def test_ingest_storage_and_entities_determinism_with_two_batch_sizes(tmp_path, dataset):
    sys.path.insert(0, str(ROOT / "scripts"))
    from dataclasses import replace
    from verify_cptc_ingest import ingest_run
    eve = synthetic_eve()
    entries = [{**eve, "flow_id": i} for i in range(8)]
    path = write_gzip(tmp_path / "synthetic.json.gz", json.dumps([wrapper(e) for e in entries]))
    entry = dataset.manifest.partitions["t1"].model_copy(update={"expected_records": 8})
    manifest = dataset.manifest.model_copy(update={"partitions": {"t1": entry}})
    synthetic = replace(dataset, root=tmp_path, manifest=manifest, paths={"t1": path}, adapters={"t1": dataset.adapters["t1"]})
    a = ingest_run(synthetic, tmp_path / "a", batch_size=3)
    b = ingest_run(synthetic, tmp_path / "b", batch_size=5)
    assert a["summary"]["counts"]["canonical_alerts"] == 8
    assert a["summary"]["snapshot_hash"] == b["summary"]["snapshot_hash"]
    assert a["serialization"] == b["serialization"] and a["entity_hashes"] == b["entity_hashes"]
    assert a["provenance"]["all_checks_passed"]
    assert a["provenance"]["storage"]["all_parquet_rows_equal_duckdb"]


def test_reader_refuses_truth_path_and_unsafe_manifest_reference(tmp_path):
    from app.adapters.cptc import declared_path
    with pytest.raises(ValueError):
        list(read_cptc_file(tmp_path / "evaluation" / "synthetic.json.gz"))
    for reference in ("../data/x", "/data/x", "data/evaluation/x", "data/../x", "data\\x", "C:/data/x"):
        with pytest.raises(ValueError):
            declared_path(tmp_path, reference, "data")
