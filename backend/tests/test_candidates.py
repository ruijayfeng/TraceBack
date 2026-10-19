"""Candidate windows, union, scopes and complete small-input oracle."""

from itertools import combinations
import pytest

from app.adapters.base import AdapterSettings
from app.correlation.candidates import CandidateGenerator, generate_candidates
from app.correlation.scoring import CorrelationScorer
from test_correlation_score import alert, config, configured, group, inputs, parent_child


@pytest.mark.parametrize("gap,from_category,to_category,present", [
    (1800,"unknown","unknown", True), (1800.000001,"unknown","unknown", False),
    (5000,"initial_access","lateral_movement", True), (7200,"initial_access","lateral_movement", True),
    (7200.000001,"initial_access","lateral_movement", False), (5000,"unknown","lateral_movement", False),
    (300,"web_attack","process_execution", True), (301,"web_attack","process_execution", False),
])
def test_host_retrieval_override_then_effective_window(config,gap,from_category,to_category,present):
    index, _ = inputs([alert("a", category=from_category, host="h"), alert("b",gap,category=to_category,host="h")])
    got = generate_candidates(index,config)
    assert bool(got.pairs) == present
    if present:
        assert "HOST" in got.pairs[0].channels
        evidence = next(e for e in got.pairs[0].evidence if e["channel"] == "HOST")
        assert evidence["retrieval_window_seconds"] == 7200
        assert evidence["effective_window_seconds"] >= gap


@pytest.mark.parametrize("gap,present", [(60,True),(60.000001,False)])
def test_time_only_no_entities_source_name_not_a_channel(config,gap,present):
    index, _ = inputs([alert("a"), alert("b",gap,source_type="aminer")])
    got = generate_candidates(index,config)
    assert not got.pairs
    assert got.potential_pair_stats["unique_potential_pairs"] == int(present)
    assert got.policy_pruned_count == int(present)
    assert not got.candidate_truncated


def test_scope_mismatch_pair_unique_and_dedupe_exclusion(config):
    settings = {n: AdapterSettings(n,"synthetic","synthetic",network_namespace=n) for n in ("a","b")}
    values = [alert("a",namespace="a",src_ip="192.0.2.1"), alert("b",61,namespace="b",src_ip="192.0.2.1")]
    index,_ = inputs(values,settings)
    assert generate_candidates(index,config).pairs == []
    values = [alert(str(i),i,host="h",account="u",session="s") for i in range(3)]
    g = group(values[:2])
    index,_ = inputs(values,groups=[g])
    result = generate_candidates(index,config)
    assert len(result.pairs) == 1
    assert set(result.pairs[0].support_key) == {g.representative_alert_id,values[2].alert_id}
    assert {"HOST","ACCOUNT","SESSION"} <= set(result.pairs[0].channels)


def test_filter_before_top_k_does_not_hide_valid_far_override(tmp_path):
    config = configured(tmp_path,candidate={"per_channel_neighbors":1,"time_only_neighbors":1})
    values = [alert("initial",category="initial_access",host="h"),
              *[alert(str(i),2000+i,host="h") for i in range(40)],
              alert("lateral",5000,category="lateral_movement",host="h")]
    index,_ = inputs(values)
    result = generate_candidates(index,config)
    pair = tuple(sorted((values[0].alert_id,values[-1].alert_id)))
    assert pair in {p.support_key for p in result.pairs}


def test_no_budget_candidates_match_exhaustive_oracle(tmp_path):
    config = configured(tmp_path,candidate={"per_channel_neighbors":1000,"time_only_neighbors":1000,"max_neighbors_per_alert":1000})
    values = [alert(str(i),i*130,host="h" if i%3 else "other",src_ip="192.0.2.1" if i%2 else "192.0.2.2") for i in range(18)]
    index,_ = inputs(values)
    generator = CandidateGenerator(index,config)
    expected = set()
    for a,b in combinations(index.alerts.values(),2):
        channels = [index.entities[eid].type.value for eid in set(a.entity_ids)&set(b.entity_ids)]
        gap = abs(index.times[a.alert_id]-index.times[b.alert_id])/1000000
        for channel in channels:
            first,second = (a,b) if a.timestamp<=b.timestamp else (b,a)
            windows = generator.windows(channel,first.category.value,second.category.value)
            effective = next((w for side,w,_ in windows if side in ("after","both")),None)
            if gap<=effective:
                expected.add(tuple(sorted((a.alert_id,b.alert_id))))
    result = generator.generate()
    assert {p.support_key for p in result.pairs} == expected
    assert not result.candidate_truncated


def test_explicit_relation_channel_and_input_reordering(config):
    index,settings = inputs(parent_child())
    first = generate_candidates(index,config,CorrelationScorer(index,config,settings))
    index2 = type(index)(reversed(list(index.alerts.values())),[],reversed(list(index.entities.values())))
    second = generate_candidates(index2,config,CorrelationScorer(index2,config,settings))
    assert first == second
    assert "explicit_relation" in first.pairs[0].channels


def test_source_channel_filters_before_budget_and_excludes_same_origin(tmp_path):
    import yaml
    from test_correlation_score import process
    mapping={"schema_version":"1.0","mapping_type":"source_independence","source_type":"waf","default":"unknown",
             "rules":[{"id":"independent-detectors","match":{"all":[
                 {"field":"left.sensor","op":"eq","value":"web"},
                 {"field":"right.sensor","op":"eq","value":"proc"}]},"output":"confirmed_independent"}]}
    (tmp_path/"independence.yaml").write_text(yaml.safe_dump(mapping),encoding="utf-8")
    config=configured(tmp_path,source={"independence_mapping_files":["independence.yaml"]},candidate={"per_channel_neighbors":1})
    web=alert("web",source_type="waf",sensor="web",category="web_attack",host="h",src_ip="192.0.2.1",
              origin_namespace="original",origin_record_id="same")
    forwarded=alert("forwarded",1,source_type="edr",sensor="proc",category="process_execution",host="h",process=process(1),
                    origin_namespace="original",origin_record_id="same")
    legitimate=alert("legitimate",100,source_type="edr",sensor="proc",category="process_execution",host="h",process=process(2))
    filler=[alert(str(i),i+2,source_type="edr",sensor="unconfirmed",host="h") for i in range(40)]
    index,settings=inputs([web,forwarded,legitimate,*filler])
    result=generate_candidates(index,config,CorrelationScorer(index,config,settings))
    target=tuple(sorted((web.alert_id,legitimate.alert_id)))
    assert "source_complement" in next(p.channels for p in result.pairs if p.support_key==target)
    same=tuple(sorted((web.alert_id,forwarded.alert_id)))
    assert not any(p.support_key==same and "source_complement" in p.channels for p in result.pairs)


def test_multi_entity_channel_keeps_strongest_rarity_priority(config):
    # Both IPs hit the same pair. Channel distance and endpoint priority are
    # independent: retaining the nearest hit must not discard its rarer IP.
    pair_alerts=[alert("multi-left",src_ip="192.0.2.1",dst_ip="192.0.2.2"),
                 alert("multi-right",1,src_ip="192.0.2.1",dst_ip="192.0.2.2")]
    index,_=inputs(pair_alerts+[alert("common-"+str(i),100+i,src_ip="192.0.2.1") for i in range(20)])
    result=generate_candidates(index,config)
    pair=tuple(sorted(a.alert_id for a in pair_alerts))
    candidate=next(item for item in result.pairs if item.support_key==pair)
    ip_ids={e.entity_id for e in candidate.evidence if e.channel=="IP"}
    assert len(ip_ids)==2
    expected=max(index.rarity(eid,config.algorithm.entity) for eid in ip_ids)
    assert candidate.priority[:2]==(2,-config.algorithm.entity.weights["IP"]*expected)
