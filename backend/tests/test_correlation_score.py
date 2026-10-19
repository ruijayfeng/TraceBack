"""Synthetic, hand-calculable scoring boundaries; no dataset labels."""

from datetime import datetime, timedelta, timezone
import math
from pathlib import Path

import pytest
import yaml

from app.adapters.base import AdapterSettings
from app.config import load_config, read_yaml
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.entities.extraction import extract_entities
from app.models import CanonicalAlert, DedupeGroup
from app.utils.stable_id import id_for, raw_fingerprint, utc_text


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def config():
    return load_config(ROOT / "configs/algorithm-v0.yaml")


def configured(tmp_path, **sections):
    data = read_yaml(ROOT / "configs/algorithm-v0.yaml")
    for section, changes in sections.items():
        data[section].update(changes)
    path = tmp_path / "synthetic-algorithm.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return load_config(path)


def alert(name, seconds=0, namespace="synthetic", category="unknown", **fields):
    stamp = utc_text(datetime(2022, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds))
    raw = {"synthetic_fixture": name, "timestamp": stamp, "source_type": "wazuh", "category": category, **fields}
    facts = {"timestamp": stamp, "source_type": fields.pop("source_type", "wazuh"), "source_namespace": namespace,
             "source_record_id": name, "category": category, **fields}
    raw.update(source_type=facts["source_type"], source_record_id=name)
    facts.update(raw_alert=raw, raw_fingerprint=raw_fingerprint(raw),
                 field_provenance={key: {"raw_pointer": "/" + key, "transform": "synthetic-fixture-v1"}
                                   for key, value in facts.items() if key != "source_namespace" and value is not None})
    facts["alert_id"] = id_for("CanonicalAlert", facts)
    return CanonicalAlert.model_validate(facts)


def inputs(alerts, settings=None, groups=()):
    settings = settings or {a.source_namespace: AdapterSettings(a.source_namespace, "synthetic", "synthetic") for a in alerts}
    # This fixture verifies frozen historical scoring/candidate semantics.
    extracted = extract_entities(alerts, settings, contract='legacy-v1')
    return AlertIndex(extracted.alerts, groups, extracted.entities), settings


def group(alerts):
    from app.correlation.reasons import make_reason
    ids = sorted(a.alert_id for a in alerts)
    data = {"alert_ids": ids, "representative_alert_id": ids[0], "duplicate_score": 1.0,
            "reasons": [make_reason("duplicate", ids, {"rule_id": "synthetic-group", "similarity": 1.0})]}
    data["group_id"] = id_for("DedupeGroup", data)
    return DedupeGroup.model_validate(data)


def process(pid, seconds=0):
    return {"pid": pid, "name": "synthetic-process", "start_time": utc_text(datetime(2022, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds))}


def parent_child():
    return [alert("parent", category="process_execution", host="h", account="u", session="s", process=process(1)),
            alert("child", 1, category="privilege_escalation", host="h", account="u", session="s", parent_process=process(1), process=process(2, 1))]


def test_time_half_life_same_timestamp_and_formula(config):
    index, settings = inputs([alert("a", host="h"), alert("b", 300, host="h")])
    scorer = CorrelationScorer(index, config, settings)
    result = scorer.score_pair(*list(index.alerts))
    assert result.values["time"] == pytest.approx(0.5)
    assert result.values["entity"] == pytest.approx(0.055)
    assert result.score == pytest.approx(0.1 + 0.3 * 0.055)
    assert scorer.breakdown(result).final_score == round(result.score, 6)
    index, settings = inputs([alert("a", host="h"), alert("b", host="h")])
    assert CorrelationScorer(index, config, settings).score_pair(*index.alerts).values["time"] == 1


def test_parent_child_instance_gate_and_no_name_causality(config):
    index, settings = inputs(parent_child())
    result = CorrelationScorer(index, config, settings).score_pair(*index.alerts)
    assert result.values["relation"] == 1
    assert {r.relation_type for r in result.relations} == {"parent_child_process"}
    index, settings = inputs([alert("a", host="h", process={"name": "sh"}),
                              alert("b", 1, host="h", parent_process={"name": "sh"}, process={"name": "cmd"})])
    result = CorrelationScorer(index, config, settings).score_pair(*index.alerts)
    assert result.values["relation"] == 0
    assert next(f for f in result.diagnostics["entity_features"] if f["type"] == "PROCESS")["descriptor_factor"] == 0.25


def test_host_time_category_session_do_not_prove_request_to_process(config):
    index, settings = inputs([alert("web", category="web_attack", host="h", session="same"),
                              alert("process", 18, category="process_execution", host="h", session="same", process=process(1))])
    result = CorrelationScorer(index, config, settings).score_pair(*index.alerts)
    assert result.values["relation"] == 0 and result.relations == []
    assert result.values["behavior"] == 1
    assert result.diagnostics["half_life_seconds"] == 60


def test_rarity_roles_multifeature_and_contributor_cap(tmp_path):
    config = configured(tmp_path, entity={"rarity_enabled": False, "max_contributors_per_type": 1})
    index, settings = inputs([alert("a", src_ip="192.0.2.1", dst_ip="192.0.2.2", host="h", account="u"),
                              alert("b", dst_ip="192.0.2.1", src_ip="192.0.2.2", host="h", account="u")])
    result = CorrelationScorer(index, config, settings).score_pair(*index.alerts)
    assert len([f for f in result.diagnostics["entity_features"] if f["type"] == "IP"]) == 1
    assert result.values["entity"] == pytest.approx(1 - (1 - .2) * (1 - .55) * (1 - .7))
    assert {f["role_factor"] for f in result.diagnostics["entity_features"] if f["type"] == "IP"} == {.8}


def test_behavior_reverse_unknown_and_beyond_window(config):
    index, settings = inputs([alert("web", category="web_attack", host="h"),
                              alert("proc", 301, category="process_execution", host="h")])
    result = CorrelationScorer(index, config, settings).score_pair(*index.alerts)
    assert result.values["conflict"] == .6
    index, settings = inputs([alert("proc", category="process_execution", host="h"),
                              alert("web", 1, category="web_attack", host="h")])
    result = CorrelationScorer(index, config, settings).score_pair(*index.alerts)
    assert result.values["behavior"] == .1


def test_source_name_difference_is_unknown_and_zero(config):
    index, settings = inputs([alert("waf", source_type="waf", category="web_attack", host="h", src_ip="192.0.2.1"),
                              alert("edr", 1, source_type="edr", category="process_execution", host="h", process=process(1))])
    result = CorrelationScorer(index, config, settings).score_pair(*index.alerts)
    assert result.source_independence == "unknown" and result.values["source"] == 0


def test_independent_source_requires_both_context_and_sides(tmp_path):
    mapping = {"schema_version": "1.0", "mapping_type": "source_independence", "source_type": "waf", "default": "unknown",
               "rules": [{"id": "synthetic-independent-detectors", "match": {"all": [
                   {"field": "left.sensor", "op": "eq", "value": "web-detector"},
                   {"field": "right.sensor", "op": "eq", "value": "process-detector"}]}, "output": "confirmed_independent"}]}
    (tmp_path / "independent.yaml").write_text(yaml.safe_dump(mapping), encoding="utf-8")
    config = configured(tmp_path, source={"independence_mapping_files": ["independent.yaml"]})
    a = alert("w", source_type="waf", sensor="web-detector", category="web_attack", host="h", src_ip="192.0.2.1")
    b = alert("e", 1, source_type="edr", sensor="process-detector", category="process_execution", host="h", process=process(1))
    index, settings = inputs([a, b])
    result = CorrelationScorer(index, config, settings).score_pair(*index.alerts)
    assert result.source_independence == "confirmed_independent" and result.values["source"] == 1
    b = alert("e", 1, source_type="edr", sensor="process-detector", category="unknown", host="h", process=process(1))
    index, settings = inputs([a, b])
    result = CorrelationScorer(index, config, settings).score_pair(*index.alerts)
    assert result.source_independence == "confirmed_independent" and result.values["source"] == 0


def test_same_origin_precedence_duplicate_penalty_and_hard_scope(config):
    index, settings = inputs([alert("a", host="h", origin_namespace="origin", origin_record_id="o"),
                              alert("b", 1, host="h", origin_namespace="origin", origin_record_id="o")])
    result = CorrelationScorer(index, config, settings).score_pair(*index.alerts)
    assert result.source_independence == "confirmed_same_origin"
    assert result.values["duplicate"] == 1
    a, b = alert("a", namespace="a", src_ip="192.0.2.1"), alert("b", namespace="b", src_ip="192.0.2.1")
    settings = {n: AdapterSettings(n, "synthetic", "synthetic", network_namespace=n) for n in ("a", "b")}
    index, settings = inputs([a, b], settings)
    result = CorrelationScorer(index, config, settings).score_pair(*index.alerts)
    assert "cross_namespace_without_bridge" in result.rejection_codes
    assert not result.valid


@pytest.mark.parametrize("sessions", [(None,None),("same","same"),("a","b")])
def test_no_verified_session_conflict_without_contract_proof(config,sessions):
    index, settings=inputs([alert("a",host="h",session=sessions[0]),alert("b",1,host="h",session=sessions[1])])
    result=CorrelationScorer(index,config,settings).score_pair(*index.alerts)
    assert "verified_incompatible_session" not in result.rejection_codes
    assert result.diagnostics["conflicts"]["session_compatibility"]["status"]=="unproven"
    assert not result.diagnostics["conflicts"]["session_compatibility"]["verified"]


@pytest.mark.parametrize("kind,expected,source_category,target_category",[
    ("target_to_process","REQUEST_TO_PROCESS","web_attack","process_execution"),
    ("account_host_pivot","ACCOUNT_PIVOT","authentication","lateral_movement"),
    ("network_pivot","NETWORK_PIVOT","initial_access","lateral_movement"),
    ("session_continuity","SESSION_FLOW","authentication","process_execution"),
])
def test_existing_attested_relation_type_gate_direction_mapping(config,kind,expected,source_category,target_category):
    from app.models import AlertRelation
    from app.utils.stable_id import canonical_json
    # Synthetic upstream AlertRelation attestation; no raw extraction is added
    # to production. Relation fields document the observed request/operation.
    a=alert("a",category=source_category,host="h",account="u",session="s",dst_ip="192.0.2.2",dst_port=80)
    b=alert("b",1,category=target_category,host="other" if kind=="account_host_pivot" else "h",
            account="u",session="s",src_ip="192.0.2.2",process=process(2))
    settings={"synthetic":AdapterSettings("synthetic","synthetic","synthetic",session_scope="application")}
    # A structured operation in raw_alert attests the relation, rather than
    # promoting co-occurring context fields into a relation.
    for item,side in ((a,"source"),(b,"target")):
        raw={**item.raw_alert,"operation":{"observed_relation":kind,"side":side,"request_id":"request",
                                          "started_process":process(2) if kind=="target_to_process" else None,
                                          "order":1 if side=="source" else 2}}
        data=item.model_dump();data.update(raw_alert=raw,raw_fingerprint=raw_fingerprint(raw))
        data["alert_id"]=id_for("CanonicalAlert",data)
        if side=="source":a=CanonicalAlert.model_validate(data)
        else:b=CanonicalAlert.model_validate(data)
    index,settings=inputs([a,b],settings)
    def eid(aid,role):
        return next(e for e,roles in index.roles[aid].items() if role in roles)
    roles={"target_to_process":("host","process"),"account_host_pivot":("account","host"),
           "network_pivot":("dst_ip","src_ip"),"session_continuity":("session","session")}
    src_role,dst_role=roles[kind]
    relation=AlertRelation.model_validate({"relation_type":kind,"source_entity_id":eid(a.alert_id,src_role),
                 "target_entity_id":eid(b.alert_id,dst_role),"raw_pointers":[
                     {"alert_id":a.alert_id,"pointer":"/operation","side":"src"},
                     {"alert_id":b.alert_id,"pointer":"/operation","side":"dst"}]})
    updated=index.alerts[b.alert_id].model_dump();updated["relations"]=[relation.model_dump()]
    index.alerts[b.alert_id]=CanonicalAlert.model_validate(updated,context={"alerts":index.alerts})
    scored=CorrelationScorer(index,config,settings).score_pair(a.alert_id,b.alert_id)
    assert scored.values["relation"]==config.algorithm.relation.scores[kind]
    assert len(scored.relations)==1
    assert scored.relations[0].source_alert_id==a.alert_id and scored.relations[0].target_alert_id==b.alert_id
    assert config.algorithm.chain.relation_type_mapping[scored.relations[0].relation_type]==expected
