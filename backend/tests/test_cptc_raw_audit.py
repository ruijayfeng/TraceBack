"""Synthetic parser boundaries and read-only integration, never real GT."""
import ast
import gzip
import io
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import audit_cptc_2018 as audit


def synthetic_eve(second=0, signature="synthetic signature", severity=2):
    return {"timestamp": f"2018-11-03T10:00:{second:02d}.123456+0000", "event_type": "alert",
            "src_ip": "192.0.2.1", "src_port": 0, "dest_ip": "198.51.100.1", "dest_port": 80,
            "proto": "TCP", "flow_id": 123, "tx_id": 0,
            "alert": {"signature": signature, "signature_id": 12345, "severity": severity,
                      "category": "synthetic vendor category", "action": "allowed"}}


def envelope(eve):
    return {"_raw": json.dumps(eve), "host": "synthetic-collector", "_time": "rounded export time"}


class BoundedReader(io.StringIO):
    def read(self, size=-1):
        assert 0 < size <= 64, "unbounded/full-file read"
        return super().read(size)

    def readline(self, size=-1):
        raise AssertionError("single-line array must not be loaded by readline")


def test_single_line_array_is_incremental_and_handles_escaped_brackets():
    records = [envelope(synthetic_eve(signature='text } ], " quote')) for _ in range(30)]
    state = {}
    result = list(audit.stream_records(BoundedReader(json.dumps(records)), state, chunk_size=64))
    assert [r.value for r in result] == records
    assert state == {"format": "single JSON Array", "parse_complete": True}


def test_parser_yields_before_reading_full_array():
    text = json.dumps([{"a": 1}] * 1000)
    reader = BoundedReader(text)
    parser = audit.stream_records(reader, {}, chunk_size=64)
    assert next(parser).value == {"a": 1}
    assert reader.tell() < len(text)


def test_jsonl_bad_record_is_isolated():
    state = {}
    rows = list(audit.stream_records(BoundedReader('{"a":1}\nbroken\n{"b":2}\n'), state, chunk_size=64))
    assert rows[0].value == {"a": 1}
    assert rows[1].error.startswith("invalid_json")
    assert rows[2].value == {"b": 2}
    assert state["parse_complete"]


@pytest.mark.parametrize("text", ['[{"a":1},broken]', '[{"a":1},]', '[{"a":1}', '[{"a":1}]junk', '[{"a":1} {"a":2}]'])
def test_corrupt_array_reports_incomplete_without_inventing_records(text):
    state = {}
    rows = list(audit.stream_records(BoundedReader(text), state, chunk_size=64))
    assert any(r.error for r in rows)
    assert not state["parse_complete"]


def test_duplicate_keys_and_nonfinite_numbers_are_invalid():
    rows = list(audit.stream_records(BoundedReader('[{"a":1,"a":2},{"x":NaN}]'), {}, chunk_size=64))
    assert len(rows) == 2
    assert all(r.error for r in rows)


def test_record_size_bound():
    rows = list(audit.stream_records(BoundedReader(json.dumps([{"s": "x" * 200}])), {}, chunk_size=64, max_record_chars=80))
    assert rows[0].error


def test_native_field_mapping_and_alias_conflict():
    values, pointers = audit.detect_mapping(synthetic_eve())
    assert values["dst_ip"] == "198.51.100.1"
    assert values["dst_port"] == 80
    assert values["src_port"] == 0
    assert pointers["dst_ip"] == "/dest_ip"
    assert pointers["rule_id"] == "/alert/signature_id"
    raw = synthetic_eve()
    raw["dst_ip"] = "192.0.2.2"
    with pytest.raises(ValueError, match="conflicting_alias"):
        audit.detect_mapping(raw)


def test_native_timestamp_uses_existing_contract_microseconds():
    assert audit.timestamp("2018-11-03T10:00:00.123456+0000") == "2018-11-03T10:00:00.123456Z"
    assert audit.timestamp("2018-11-03T18:00:00.123456+0800") == "2018-11-03T10:00:00.123456Z"
    assert audit.microseconds(audit.timestamp("1970-01-01T00:00:00.000001Z")) == 1
    with pytest.raises(ValueError, match="missing_timezone"):
        audit.timestamp("2018-11-03T10:00:00")
    with pytest.raises(ValueError):
        audit.timestamp("bad")


def test_raw_string_is_decoded_and_bad_or_contaminated_records_rejected():
    e = synthetic_eve()
    assert audit.unwrap(envelope(e))[0] == e
    assert audit.unwrap(e)[0] == e
    for raw in ({"_raw": "bad"}, {"_raw": []}, {"_raw": "[]"}, [], {}):
        with pytest.raises(ValueError):
            audit.unwrap(raw)
    contaminated = {**e, "ground_truth": "synthetic forbidden marker"}
    with pytest.raises(ValueError, match="annotation_contamination"):
        audit.unwrap(envelope(contaminated))


def test_existing_production_reader_rejects_gzip_without_opening_raw(tmp_path):
    config = audit.load_config(audit.ROOT / "configs/algorithm-v0.yaml", deployment_override=audit.ROOT / "configs/sources.yaml")
    adapter = audit.WazuhAdapter(config, audit.AdapterSettings(source_namespace="synthetic.audit", format_profile="wazuh_json_v1", generator="Wazuh"))
    path = tmp_path / "synthetic.json.gz"
    path.write_bytes(gzip.compress(json.dumps([envelope(synthetic_eve())]).encode()))
    before = audit.identity(path)
    with pytest.raises(ValueError, match="input_path_not_security_alert"):
        adapter.read_file(path)
    assert audit.identity(path) == before


def test_schema_mapping_preview_has_valid_pointers_and_stable_id():
    sample = {"eve": synthetic_eve(), "file": "synthetic.json.gz", "ordinal": 1}
    preview = audit.mapping_preview(sample)
    assert preview["schema_validated"]
    canonical = preview["canonical_alert"]
    assert canonical["category"] == canonical["severity"] == "unknown"
    assert canonical["source_record_id"] is None
    assert canonical["host"] is None
    assert "source_context" not in canonical and "flow_id" not in canonical
    sample["ordinal"] = 999
    assert audit.mapping_preview(sample)["canonical_alert"]["alert_id"] == canonical["alert_id"]
    assert canonical["raw_alert"] == sample["eve"]


def test_sample_diversity_does_not_repeat_same_raw_record():
    item = {"file": "synthetic.gz", "ordinal": 1, "eve": synthetic_eve()}
    assert audit.select_samples({"a": item, "b": item}) == [item]


def test_gzip_crc_failure_is_detected(tmp_path):
    path = tmp_path / "synthetic.gz"
    compressed = gzip.compress(b'[{"event_type":"stats"}]')
    path.write_bytes(compressed[:-5])
    with pytest.raises(EOFError):
        with gzip.open(path, "rt") as handle:
            list(audit.stream_records(handle, {}))


def test_streaming_audit_end_to_end_preserves_raw_and_never_executes_algorithm(tmp_path, monkeypatch):
    raw_dir, out = tmp_path / "raw", tmp_path / "out"
    raw_dir.mkdir()
    for name in audit.FILES:
        values = [envelope(synthetic_eve(10, "synthetic B", 3)), envelope(synthetic_eve(0, "synthetic A", 1))]
        values.append({"_raw": json.dumps({"event_type": "stats"}), "host": "synthetic-collector"})
        with gzip.open(raw_dir / name, "wt", encoding="utf-8") as handle:
            json.dump(values, handle)
    before = {p.name: audit.identity(p) for p in raw_dir.iterdir()}
    import app.correlation.edges as edges
    def forbidden(*args, **kwargs):
        raise AssertionError("Step 1 must never score or generate edges")
    for name in dir(edges):
        if name.startswith("generate"):
            monkeypatch.setattr(edges, name, forbidden)
    result = audit.run_audit(raw_dir, out)
    assert result["task_result"] == "CPTC_ADAPTER_CHANGES_REQUIRED"
    assert result["alert_count"] == 12
    assert all(f["record_count"] == 3 and f["timestamp_descents"] == 1 and f["raw_unchanged"] for f in result["files"])
    assert {p.name: audit.identity(p) for p in raw_dir.iterdir()} == before
    assert not list(out.glob("audit_work_*"))
    field_data = json.loads((out / "cptc_field_coverage.json").read_text(encoding="utf-8"))
    assert field_data["canonical_logical_fields"]["dst_ip"]["count"] == 12
    assert field_data["raw_fields"]["community_id"]["count"] == 0
    potential = json.loads((out / "cptc_potential_continuity.json").read_text(encoding="utf-8"))
    assert potential["group_count"] == 5
    assert potential["window_statistics"]["same_src_ip"]["60"][0]["later_alerts_with_prior_same_key"] == 1
    assert all(r["raw_suricata"]["alert"]["signature"] == r["signature"] for g in potential["groups"] for r in g["alerts"])


def test_audit_source_has_no_algorithm_or_evaluation_imports():
    tree = ast.parse(Path(audit.__file__).read_text(encoding="utf-8"))
    names = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    names += [a.name for node in ast.walk(tree) if isinstance(node, ast.Import) for a in node.names]
    assert not any(n.startswith(("evaluation", "app.correlation", "app.incidents", "app.chains", "app.dedup")) for n in names)


def test_output_cannot_overlap_raw_directory(tmp_path):
    with pytest.raises(ValueError, match="separate"):
        audit.run_audit(tmp_path, tmp_path / "out")
