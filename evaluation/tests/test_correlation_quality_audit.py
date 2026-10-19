"""Synthetic audit math, deterministic review selection and read-only boundary."""

import ast
from copy import deepcopy
import json
from pathlib import Path

import pytest

from evaluation.framework.correlation_quality_audit.correlation_quality import (SCORE_BOUNDS, TIME_BOUNDS, bucket,
    capture_integrity, classify, compare_integrity, effective_contributions,
    entity_frequency, graph_statistics, hot_entities, offline_evaluation,
    sampled, source_pair, observation_proxies)
from evaluation.framework.correlation_quality_audit.correlation_run import aggregate_contributions, scan_diagnostics


ROOT = Path(__file__).resolve().parents[2]


def test_bounded_diagnostic_reader_uses_exact_aggregates_not_sample_counts(tmp_path):
    path=tmp_path/'diagnostics.jsonl'
    summary=dict(exact=True,counts=dict(candidate=12345,correlation_decision=12345,
        reject=12345,member_score=54321,clustering=7),source_candidate_decisions=[
        dict(source_pair='one ↔ two',decision='reject',count=12345)],clustering_guards=[
        dict(decision='reject',rule_id='unchanged_guard',count=7)])
    path.write_text(json.dumps(dict(stage='bounded_diagnostics_summary',summary=summary),
        separators=(',',':'))+'\n',encoding='utf8')
    accepted,stats=scan_diagnostics(path,[],{})
    assert not accepted
    assert stats['scored_candidates']==12345 and stats['rejected_candidates']==12345
    assert stats['member_scores']==54321 and stats['candidate_records']==12345
    assert stats['clustering_decision_records']==7
    assert stats['source_candidate_decisions']==summary['source_candidate_decisions']


@pytest.mark.parametrize("score,expected", [(.649999,"outside"),(.65,"[0.65,0.7)"),
    (.699999,"[0.65,0.7)"),(.70,"[0.7,0.75)"),(.75,"[0.75,0.8)"),
    (.95,"[0.95,1)"),(1,"[0.95,1)")])
def test_score_bucket_has_half_open_boundaries_and_includes_one(score, expected):
    assert bucket(score,SCORE_BOUNDS)==expected


@pytest.mark.parametrize("seconds,expected",[(0,"[0,10)"),(10,"[10,30)"),
    (60,"[60,300)"),(3600,"[3600,inf)")])
def test_time_bucket(seconds,expected):
    assert bucket(seconds,TIME_BOUNDS)==expected


def test_degree_components_duplicates_and_singletons():
    adjacency,components=graph_statistics(["a","b","c","d","e"],
        [("a","b"),("b","a"),("b","c"),("a","c"),("a","a")])
    assert {n:len(v) for n,v in adjacency.items()}=={"a":2,"b":2,"c":2,"d":0,"e":0}
    assert [c["node_count"] for c in components]==[3,1,1]
    assert components[0]["edge_count"]==3 and components[0]["density"]==1
    assert components[0]["possible_max_edges"]==3
    assert graph_statistics(["c","b","e","a","d"],[("c","a"),("b","c"),("a","b")])[1]==components


def test_entity_frequency_counts_fact_groups_once_and_hot_has_two_conditions():
    entities={"common":{"alert_ids":["a","b","c"]},"rare":{"alert_ids":["b"]},
              "relative_only":{"alert_ids":["d"]}}
    frequency=entity_frequency(entities,{"a":"a","b":"a","c":"c","d":"d"})
    assert frequency=={"common":2,"rare":1,"relative_only":1}
    assert hot_entities(frequency,3,{"hot_entity_min_count":2,"hot_entity_ratio":.5})=={"common"}
    assert hot_entities(frequency,30,{"hot_entity_min_count":2,"hot_entity_ratio":.5})==set()


def synthetic_edge():
    families={"time":.2,"entity":.3,"relation":.2,"behavior":.2,"source":.1}
    strengths={"time":1,"entity":.8,"relation":.5,"behavior":0,"source":0}
    ev={"family_weights":families,"family_strengths":strengths,"available_weight":.7,
        "total_configured_weight":1,"quality_factor":.65,"mass_factor":.35,
        "matched_evidence":["time.distance","entity.HOST","entity.ACCOUNT","topology.network_continuity"],
        "dimensions":[{"dimension":"time.distance","family":"time","state":"AVAILABLE_MATCH","weight":1,"strength":1,"entity_ids":[]},
            {"dimension":"entity.HOST","family":"entity","state":"AVAILABLE_MATCH","weight":1,"strength":.6,"entity_ids":["common"]},
            {"dimension":"entity.ACCOUNT","family":"entity","state":"AVAILABLE_MATCH","weight":1,"strength":1,"entity_ids":["rare"]},
            {"dimension":"topology.network_continuity","family":"relation","state":"AVAILABLE_MATCH","weight":1,"strength":.5,"entity_ids":["common"]},
            {"dimension":"topology.attested_relation","family":"relation","state":"AVAILABLE_MISMATCH","weight":1,"strength":0,"entity_ids":[]}]}
    factor=.65/.7+.35
    contributions={"time":.2,"entity":.24,"relation":.1,"behavior":0,"source":0,"conflict":0,"duplicate":-.04}
    return {"edge_id":"synthetic-edge","score":.54*factor-.04,"reasons":[],
            "score_breakdown":{"evidence_v2":ev,"raw_total":.54*factor-.04,"contributions":contributions}}


def test_v2_contributions_use_actual_normalization_not_legacy_sum():
    edge=synthetic_edge()
    families,dims,penalties=effective_contributions(edge)
    assert sum(families.values())+sum(penalties.values())==pytest.approx(edge["score"])
    assert dims["entity.ACCOUNT"]==pytest.approx(dims["entity.HOST"]/.6)
    assert dims["topology.network_continuity"]==pytest.approx(families["relation"])
    assert sum(edge["score_breakdown"]["contributions"].values())!=pytest.approx(edge["score"])
    stats,combos,rows,error=aggregate_contributions([edge,deepcopy(edge)])
    assert error<1e-12
    entity=next(r for r in stats if r["contribution_type"]=="v2.family.entity")
    assert entity["nonzero_count"]==2 and entity["edge_ratio"]==1
    assert entity["mean_all_edges"]==pytest.approx(families["entity"])
    assert sum(combos.values())==2


def test_relation_max_ties_share_attribution_without_double_counting():
    edge=synthetic_edge()
    edge["score_breakdown"]["evidence_v2"]["dimensions"][-1]["strength"]=.5
    edge["score_breakdown"]["evidence_v2"]["dimensions"][-1]["state"]="AVAILABLE_MATCH"
    families,dims,_=effective_contributions(edge)
    assert dims["topology.attested_relation"]==pytest.approx(families["relation"]/2)
    assert dims["topology.network_continuity"]==pytest.approx(families["relation"]/2)


def test_deterministic_sampling_is_order_invariant_and_not_always_top_score():
    rows=[{"edge_id":f"edge-{i}","score":i} for i in range(100)]
    chosen=sampled(rows,42,"same_source",20)
    assert chosen==sampled(list(reversed(rows)),42,"same_source",20)
    assert chosen!=sampled(rows,42,"cross_source",20)
    assert len(chosen)==20 and len({r["edge_id"] for r in chosen})==20
    assert sampled([],42,"empty")==[]


def test_source_pair_is_undirected_and_uses_namespace_not_product():
    a={"source_namespace":"wazuh-deployment","source_type":"wazuh"}
    b={"source_namespace":"wazuh-deployment","source_type":"suricata"}
    assert source_pair(a,b)=="wazuh-deployment ↔ wazuh-deployment"
    c={"source_namespace":"aminer-deployment"}
    assert source_pair(a,c)==source_pair(c,a)


def test_repeated_embedded_observation_is_inflation_proxy_not_ground_truth():
    a={"source_namespace":"synthetic","timestamp":"2022-01-01T00:00:00Z",
       "src_ip":"192.0.2.1","dst_ip":"192.0.2.1","session":"synthetic-session",
       "raw_alert":{"full_log":"synthetic embedded alert text","id":"a","location":"one"}}
    b=deepcopy(a);b["raw_alert"].update(id="b",location="two")
    evidence={"matched_evidence":["topology.network_continuity"]}
    result=observation_proxies(a,b,evidence)
    assert result["repeated_observation_proxy"] and result["network_continuity_same_endpoint_proxy"]
    assert a["raw_alert"]["id"]=="a" and b["raw_alert"]["id"]=="b"
    b["session"]="different-session"
    assert not observation_proxies(a,b,evidence)["repeated_observation_proxy"]
    b["raw_alert"].pop("full_log")
    assert not observation_proxies(a,b,evidence)["identical_embedded_payload"]


def synthetic_config():
    return {"score":{"correlation_threshold":.65,"evidence_v2":{"gate":{
        "specific_minimum_rarity":.5,"strong_entity_types":["HOST","ACCOUNT","SESSION"],
        "semantic_support_minimum":.7,"temporal_support_minimum":.5}}},
        "entity":{"rarity_floor":.1},"chain":{"relation_type_mapping":{"parent_child_process":"PROCESS_CAUSAL"}},
        "clustering":{"edge_threshold":.7}}


def test_hub_proxy_does_not_override_verified_strong_relation():
    edge=synthetic_edge()
    entities={"common":{"type":"HOST"},"rare":{"type":"ACCOUNT"}}
    edge["reasons"]=[{"code":"explicit_relation","params":{"relation_type":"parent_child_process"}}]
    result=classify(edge,entities,{"common":99,"rare":90},100,{"common"},synthetic_config(),hub=True,giant=True)
    assert result["classification"]=="strong"
    assert "hub_endpoint" in result["risk_flags"]
    assert result["relation_support"]=="relation_supported"


def test_low_discrimination_hub_is_suspicious_and_rare_context_is_not():
    edge=synthetic_edge()
    entities={"common":{"type":"HOST"},"rare":{"type":"ACCOUNT"}}
    result=classify(edge,entities,{"common":99,"rare":90},100,{"common"},synthetic_config(),hub=True)
    assert result["classification"]=="suspicious"
    assert "no_high_discrimination_context" in result["risk_flags"]
    result=classify(edge,entities,{"common":99,"rare":1},100,{"common"},synthetic_config(),hub=True)
    assert result["classification"]=="weak" # context remains, hub only demotes review tier


def test_interval_labels_cannot_be_guessed_into_pair_ground_truth(monkeypatch):
    import evaluation.io.ait_ads as loader
    monkeypatch.setattr(loader,"load_ait_ads_ground_truth",lambda root:{"path":"synthetic.csv",
        "columns":["scenario","attack","start","end"],"records":[{"scene_id":"russellmitchell",
        "start_time":"2022-01-01T00:00:00Z","end_time":"2022-01-01T00:05:00Z"}],
        "capabilities":{"correlation_edge_ground_truth":False},"interval_policy":"[start,end)"})
    result=offline_evaluation(Path("synthetic"),{"a":{"timestamp":"2022-01-01T00:00:01Z"}})
    assert result["status"]=="evaluation_not_computable"
    assert result["pair_precision"] is None and result["pair_recall"] is None
    assert result["evaluation_coverage"]==0 and not result["production_consumed_ground_truth"]


def test_audit_calculations_preserve_snapshot_configuration_and_freeze(tmp_path):
    protected={"data/processed/ana_synthetic/alerts.jsonl":"[]\n",
        "configs/algorithm-v2.yaml":"synthetic: true\n",
        "outputs/analyses/ana_synthetic/manifest.json":"{}\n",
        "outputs/history/freeze_manifest.json":"{}\n","AGENTS.md":"synthetic"}
    for name,text in protected.items():
        p=tmp_path/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
    before=capture_integrity(tmp_path)
    graph_statistics(["a","b"],[("a","b")])
    aggregate_contributions([synthetic_edge()])
    sampled([{"edge_id":"a"}],42,"synthetic")
    assert compare_integrity(before,capture_integrity(tmp_path))["unchanged"]
    (tmp_path/"configs/algorithm-v2.yaml").write_text("synthetic: changed\n")
    result=compare_integrity(before,capture_integrity(tmp_path))
    assert not result["unchanged"] and result["changed_paths"]==["configs/algorithm-v2.yaml"]


def test_full_diagnostic_scan_matches_exact_score_and_rejects_duplicate(tmp_path):
    path=tmp_path/"diagnostics.jsonl"
    rows=[{"stage":"member_score","score":.65},
          {"stage":"candidate","support_key":["a","b"]},
          {"stage":"correlation_decision","decision":"accept","edge_id":"e",
           "support_pair":["a","b"],"support_key":["a","b"],"score":.699999999},
          {"stage":"correlation_decision","decision":"reject","support_key":["a","c"]}]
    path.write_text("\n".join(json.dumps(r,separators=(",",":")) for r in rows),encoding="utf-8")
    edges=[{"edge_id":"e","support_pair":{"alert_id_src":"a","alert_id_dst":"b"}}]
    alerts={k:{"source_namespace":"synthetic"} for k in "abc"}
    accepted,result=scan_diagnostics(path,edges,alerts)
    assert accepted["e"]["score"]<.7
    assert result["scored_candidates"]==2 and result["rejected_candidates"]==1
    assert result["member_scores"]==1 and result["candidate_records"]==1
    path.write_text(path.read_text()+"\n"+json.dumps(rows[2],separators=(",",":")),encoding="utf-8")
    with pytest.raises(ValueError,match="duplicate_or_unknown"):
        scan_diagnostics(path,edges,alerts)


def test_production_never_imports_audit_and_audit_never_calls_analysis_create():
    for file in (ROOT/"backend/app").rglob("*.py"):
        tree=ast.parse(file.read_text(encoding="utf-8"))
        assert not any(isinstance(n,ast.ImportFrom) and n.module and n.module.startswith("evaluation.framework.correlation_quality_audit") for n in ast.walk(tree))
    code=(ROOT/"evaluation/framework/correlation_quality_audit/correlation_run.py").read_text(encoding="utf-8")
    assert "AnalysisService" not in code and ".create(" not in code and "score_pair(" not in code
