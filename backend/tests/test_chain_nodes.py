"""Synthetic node construction; every fact retains its original evidence."""

import pytest

from app.chains.nodes import build_nodes
from app.correlation.scoring import CorrelationScorer
from app.models import Incident
from app.utils.stable_id import id_for
from test_correlation_score import alert, config, configured, group, inputs, process


def incident(index):
    alerts = list(index.alerts.values())
    data = {"alert_ids": list(index.alerts), "start_time": min(a.timestamp for a in alerts),
            "end_time": max(a.timestamp for a in alerts), "severity": "unknown"}
    data["incident_id"] = id_for("Incident", data)
    return Incident.model_validate(data)


def test_single_alert_unknown_confidence_and_evidence(config):
    index, settings = inputs([alert("node-singleton")])
    nodes = build_nodes(incident(index), index, CorrelationScorer(index, config, settings))
    assert len(nodes) == 1
    node = nodes[0]
    assert node.alert_ids == list(index.alerts)
    assert node.category.value == "unknown" and node.confidence == .5
    assert node.start_time == node.end_time
    assert node.reasons[0].code.value == "node_basis"
    assert index.alerts[node.alert_ids[0]].raw_alert["synthetic_fixture"] == "node-singleton"


def test_one_node_per_group_category_priority_and_nonrepeated_bonus(config):
    values = [alert("node-a", category="process_execution", host="h", session="s", process=process(1)),
              alert("node-b", 1, category="command_execution", host="h", session="s", process=process(1))]
    g = group(values)
    index, settings = inputs(values, groups=[g])
    scorer = CorrelationScorer(index, config, settings)
    diagnostics = []
    nodes = build_nodes(incident(index), index, scorer, diagnostics.append)
    assert len(nodes) == 1 and nodes[0].alert_ids == g.alert_ids
    assert nodes[0].category.value == "command_execution"
    assert nodes[0].confidence == .75
    assert diagnostics[0]["confidence_components"]["context"] == .1
    assert diagnostics[0]["confidence_components"]["independent_source"] == 0
    reversed_index, reversed_settings = inputs(list(reversed(values)), groups=[g])
    assert [n.canonical_json() for n in nodes] == [n.canonical_json() for n in build_nodes(
        incident(reversed_index), reversed_index, CorrelationScorer(reversed_index, config, reversed_settings))]


def test_member_coverage_severity_and_no_synonymous_merge(config):
    index, settings = inputs([alert("node-one", category="process_execution", host="h", severity="low"),
                              alert("node-two", 1, category="process_execution", host="h", severity="critical")])
    nodes = build_nodes(incident(index), index, CorrelationScorer(index, config, settings))
    assert len(nodes) == 2
    assert {aid for n in nodes for aid in n.alert_ids} == set(index.alerts)
    assert {n.severity.value for n in nodes} == {"low", "critical"}


def test_missing_alert_and_split_group_rejected(config):
    values = [alert("node-left"), alert("node-right", 1)]
    index, settings = inputs(values, groups=[group(values)])
    scorer = CorrelationScorer(index, config, settings)
    broken = incident(index).model_copy(update={"alert_ids": [values[0].alert_id]})
    with pytest.raises(ValueError, match="splits_dedupe"):
        build_nodes(broken, index, scorer)
    broken = broken.model_copy(update={"alert_ids": ["alt_" + "f" * 64]})
    with pytest.raises(ValueError, match="missing_alert"):
        build_nodes(broken, index, scorer)


def test_independent_source_bonus_cap_and_same_origin_no_bonus(tmp_path):
    import yaml
    mapping = {"schema_version": "1.0", "mapping_type": "source_independence", "source_type": "waf",
               "default": "unknown", "rules": [{"id": "synthetic-detector-topology", "match": {"all": [
                   {"field": "left.sensor", "op": "eq", "value": "synthetic-web-detector"},
                   {"field": "right.sensor", "op": "eq", "value": "synthetic-host-detector"}]},
                   "output": "confirmed_independent"}]}
    (tmp_path / "independent.yaml").write_text(yaml.safe_dump(mapping), encoding="utf-8")
    cfg = configured(tmp_path, source={"independence_mapping_files": ["independent.yaml"]})
    for same_origin, expected in ((False, .85), (True, .75)):
        origin = {"origin_namespace": "synthetic-origin", "origin_record_id": "same"} if same_origin else {}
        values = [alert("independent-web", source_type="waf", sensor="synthetic-web-detector", category="web_attack", host="h", **origin),
                  alert("independent-host", 1, source_type="edr", sensor="synthetic-host-detector", category="process_execution", host="h", **origin)]
        g = group(values)
        index, settings = inputs(values, groups=[g])
        node = build_nodes(incident(index), index, CorrelationScorer(index, cfg, settings))[0]
        assert node.confidence == expected
