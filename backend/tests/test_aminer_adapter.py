"""Confirmed real AMiner profile and synthetic malformed-record boundaries."""

from copy import deepcopy
import json

import pytest

from app.adapters import AMinerAdapter, AdapterSettings
from app.models import Severity
from test_wazuh_adapter import ROOT, config


def aminer_settings(namespace="synthetic.aminer", **kwargs):
    return AdapterSettings(namespace,"ait_ads_v1_aminer_json","AMiner",dataset_version=1,epoch_unit="seconds",**kwargs)


def aminer_record():
    return {"AMiner":{"ID":"synthetic.sensor"}, "AnalysisComponent":{"AnalysisComponentIdentifier":1,
            "AnalysisComponentName":"Synthetic detector","AnalysisComponentType":"NewMatchPathDetector"},
            "LogData":{"DetectionTimestamp":[1642723201],"RawLogData":[],"LogResources":[]}}


@pytest.mark.parametrize("name", ["NewMatchPathDetector","NewMatchPathValueDetector"])
def test_real_aminer_fixture(config, name):
    raw=json.loads((ROOT/"backend/tests/fixtures/alerts/aminer"/(name+".json")).read_text(encoding="utf-8"))
    adapter=AMinerAdapter(config,aminer_settings())
    alert=adapter.convert(raw)
    assert alert.raw_alert == raw and alert.source_record_id is None
    assert alert.sensor == raw["AMiner"]["ID"]
    assert alert.severity == Severity.UNKNOWN
    assert "generator_version" in alert.field_provenance["source_type"].transform
    assert "unknown" in alert.field_provenance["source_type"].transform
    assert adapter.convert(raw).alert_id == alert.alert_id


def test_optional_fields_and_last_detection_timestamp(config):
    raw=aminer_record();del raw["AMiner"]
    raw["LogData"]["DetectionTimestamp"]=[1642723200,1642723201.1234567]
    alert=AMinerAdapter(config,aminer_settings()).convert(raw)
    assert alert.timestamp == "2022-01-21T00:00:01.123456Z"
    assert alert.field_provenance["timestamp"].raw_pointer == "/LogData/DetectionTimestamp/1"
    assert alert.sensor is None and alert.source_record_id is None


@pytest.mark.parametrize("value", [[],None,["bad"],[True],[float("nan")]])
def test_bad_time_partial_batch(config,value):
    good=aminer_record();bad=deepcopy(good);bad["LogData"]["DetectionTimestamp"]=value
    result=AMinerAdapter(config,aminer_settings()).batch([bad,good])
    assert result.input_count == 2 and result.accepted_count == 1 and len(result.rejected) == 1


def test_invalid_profile_and_unit_rejected(config):
    with pytest.raises(ValueError,match="unsupported"):
        AMinerAdapter(config,AdapterSettings("synthetic","unspecified","AMiner",epoch_unit="seconds",dataset_version=1))
    with pytest.raises(ValueError,match="unsupported"):
        AMinerAdapter(config,AdapterSettings("synthetic","ait_ads_v1_aminer_json","AMiner",dataset_version=1))


def test_component_severity_not_guessed(config):
    raw=aminer_record();raw["AnalysisComponent"]["AnomalyScores"]=[999]
    adapter=AMinerAdapter(config,aminer_settings())
    assert adapter.convert(raw).severity == Severity.UNKNOWN
    raw["Severity"]="high"
    assert adapter.convert(raw).severity == Severity.HIGH


def test_annotation_and_exact_duplicate_import(config):
    adapter=AMinerAdapter(config,aminer_settings())
    raw=aminer_record()
    batch=adapter.batch([raw,raw])
    assert batch.accepted_count == 2 and len(batch.alerts) == 1 and batch.duplicate_import_count == 1
    raw["event_label"]="synthetic"
    assert adapter.batch([raw]).rejection_reasons == {"annotation_contamination":1}
