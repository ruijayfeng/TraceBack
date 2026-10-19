"""Real alert fixtures plus explicitly synthetic validation boundaries."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from app.adapters import AdapterSettings, WazuhAdapter
from app.config import load_config
from app.models import CanonicalAlert, Severity, SourceType
from app.models.base import resolve_pointer
from app.utils.stable_id import raw_fingerprint

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def config():
    return load_config(ROOT / "configs/algorithm-v0.yaml", deployment_override=ROOT / "configs/sources.yaml")


def settings(namespace="synthetic.wazuh", **kwargs):
    return AdapterSettings(namespace, "wazuh_json_v1", "Wazuh", **kwargs)


def synthetic_record(**overrides):
    raw = {"timestamp": "2022-01-21T00:00:00Z", "id": "synthetic-record",
           "rule": {"id": "synthetic-rule", "level": 6, "groups": [], "description": "Synthetic alert"}}
    raw.update(overrides)
    return raw


@pytest.mark.parametrize("name", ["freshclam", "json", "snort", "auditd", "dovecot"])
def test_real_wazuh_fixture(config, name):
    raw = json.loads((ROOT / "backend/tests/fixtures/alerts/wazuh" / (name + ".json")).read_text(encoding="utf-8"))
    adapter = WazuhAdapter(config, settings())
    alert = adapter.convert(raw)
    assert alert.raw_alert == raw
    assert alert.raw_fingerprint == raw_fingerprint(raw)
    assert CanonicalAlert.model_validate_json(alert.canonical_json()) == alert
    for p in alert.field_provenance.values():
        resolve_pointer(alert.raw_alert, p.raw_pointer)
    assert alert.source_type == (SourceType.SURICATA if name == "json" else SourceType.WAZUH)
    assert alert.origin_namespace is None and alert.origin_record_id is None
    if name == "snort":
        assert alert.dst_port == 80 and alert.dst_ip == "91.189.95.85"


@pytest.mark.parametrize("level,expected", [(0,"informational"),(2,"informational"),(3,"low"),(5,"low"),
    (6,"medium"),(9,"medium"),(10,"high"),(12,"high"),(13,"critical"),(15,"critical"),
    (None,"unknown"),("unrecognized","unknown")])
def test_levels_use_mapping(config, level, expected):
    raw = synthetic_record()
    raw["rule"]["level"] = level
    assert WazuhAdapter(config, settings()).convert(raw).severity == Severity(expected)


def test_sparse_and_key_order_identity(config):
    raw = synthetic_record()
    del raw["id"]
    adapter = WazuhAdapter(config, settings())
    a = adapter.convert(raw)
    b = adapter.convert(dict(reversed(list(raw.items()))))
    assert a.source_record_id is None
    assert a.alert_id == b.alert_id and a.raw_fingerprint == b.raw_fingerprint
    changed = deepcopy(raw); changed["rule"]["description"] += " changed"
    assert adapter.convert(changed).raw_fingerprint != a.raw_fingerprint
    assert adapter.convert(changed).alert_id != a.alert_id
    assert a.category.value == "unknown"


@pytest.mark.parametrize("value,field,reason", [
    ("invalid", "timestamp", "timestamp"), ("2022-01-21T00:00:00", "timestamp", "missing_timezone"),
    ({"srcip":"999.2.3.4"}, "data", "invalid_ip"), ({"src_port":65536}, "data", "invalid_port"),
    ({"src_port":1.5}, "data", "invalid_port"), ({"src_port":True}, "data", "invalid_port"),
    ({"src_port":"nan"}, "data", "invalid_port"), ([], "rule", "missing_wazuh_rule"),
])
def test_batch_bad_records_are_isolated(config, value, field, reason):
    adapter = WazuhAdapter(config, settings())
    good = synthetic_record()
    bad = synthetic_record(**{field:value})
    result = adapter.batch([bad, good])
    assert (result.input_count, result.accepted_count, len(result.rejected)) == (2,1,1)
    assert reason in result.rejected[0].reason


@pytest.mark.parametrize("level", [-1,16,float("inf")])
def test_invalid_severity_rejected(config, level):
    raw = synthetic_record();raw["rule"]["level"] = level
    result = WazuhAdapter(config, settings()).batch([raw])
    assert result.accepted_count == 0


def test_duplicates_and_input_permutations(config):
    adapter = WazuhAdapter(config, settings())
    a = synthetic_record();b = synthetic_record(id="synthetic-second")
    first, second = adapter.batch([a,b,a]), adapter.batch([b,a,a])
    assert first.accepted_count == 3 and first.duplicate_import_count == 1
    assert first.alerts == second.alerts and len(first.alerts) == 2


def test_annotations_rejected_before_raw_preservation(config):
    raw = synthetic_record();raw["nested"] = {"ground_truth": "synthetic annotation"}
    result = WazuhAdapter(config, settings()).batch([raw])
    assert result.alerts == []
    assert result.rejection_reasons == {"annotation_contamination":1}


def test_real_namespace_naive_timestamp_utc(config):
    adapter = WazuhAdapter(config, settings("ait_ads.russellmitchell.wazuh"))
    alert = adapter.convert(synthetic_record(timestamp="2022-01-21T01:00:00.123456789"))
    assert alert.timestamp == "2022-01-21T01:00:00.123456Z"
    assert "timezone=UTC" in alert.field_provenance["timestamp"].transform


def test_explicit_lineage_only(config):
    raw = synthetic_record(origin_namespace="synthetic.origin", origin_record_id="native")
    alert = WazuhAdapter(config, settings()).convert(raw)
    assert alert.origin_namespace == "synthetic.origin" and alert.origin_record_id == "native"
    del raw["origin_record_id"]
    assert WazuhAdapter(config, settings()).batch([raw]).rejection_reasons == {"schema_violation":1}


def test_annotation_file_denied_before_open(config, monkeypatch, tmp_path):
    def tripwire(*args, **kwargs):
        pytest.fail("forbidden input was opened")
    monkeypatch.setattr(Path, "open", tripwire)
    adapter = WazuhAdapter(config, settings())
    for path in (tmp_path/"labels.csv", tmp_path/"evaluation"/"input.json"):
        with pytest.raises(ValueError,match="input_path"):
            adapter.read_file(path)


def test_file_batch_jsonl_partial_failure(config, tmp_path):
    path = tmp_path/"alerts.jsonl"
    path.write_text(json.dumps(synthetic_record())+"\n{bad json\n",encoding="utf-8")
    result = WazuhAdapter(config, settings()).read_file(path)
    assert result.input_count == 2 and result.accepted_count == 1 and len(result.rejected) == 1


def test_numeric_native_identifier_normalized_before_identity(config):
    raw=synthetic_record(id=123)
    raw["rule"]["id"]=456
    alert=WazuhAdapter(config,settings()).convert(raw)
    assert alert.source_record_id=="123" and alert.rule_id=="456"


def test_product_names_do_not_infer_forwarding_lineage(config):
    raw=synthetic_record(data={"alert":{"signature":"Synthetic IDS signature"}})
    alert=WazuhAdapter(config,settings()).convert(raw)
    assert alert.source_type==SourceType.WAZUH
    assert alert.origin_namespace is None and alert.origin_record_id is None


def test_missing_timestamp_and_invalid_scoped_ipv6(config):
    raw=synthetic_record();del raw["timestamp"]
    adapter=WazuhAdapter(config,settings())
    assert adapter.batch([raw]).rejection_reasons=={"invalid_timestamp":1}
    assert adapter.batch([synthetic_record(data={"src_ip":"fe80::1%eth0"})]).rejection_reasons=={"invalid_ip":1}
