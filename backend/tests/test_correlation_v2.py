"""Synthetic upgrade acceptance fixtures, kept separate from historical v0 tests."""

from pathlib import Path
import random

import pytest
import yaml

from app.config import load_config, read_yaml
from app.correlation.edges import run_correlation
from app.correlation.candidates import generate_candidates
from app.correlation.scoring import CorrelationScorer
from app.chains.assembly import run_reconstruction
from app.models import ScoreBreakdown
from app.services.storage import restore_config
from test_correlation_score import alert, inputs, parent_child, process, group


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def v2():
    return load_config(ROOT / "configs/algorithm-v2.yaml")


def scored(alerts, cfg, settings=None, groups=()):
    index, settings = inputs(alerts, settings, groups)
    scorer = CorrelationScorer(index, cfg, settings)
    pair = scorer.score_pair(alerts[0].alert_id, alerts[1].alert_id)
    return pair, scorer


def test_sparse_missing_is_not_mismatch_and_crosses_unchanged_threshold(v2):
    a, b = alert("a", host="web01", account="admin"), alert("b", 60, host="web01")
    pair, scorer = scored([a, b], v2)
    audit = pair.diagnostics["evidence_v2"]
    assert "entity.ACCOUNT" in audit["unavailable_evidence"]
    assert "entity.HOST" in audit["matched_evidence"]
    assert pair.valid and pair.score >= .65
    assert audit["evidence_gate_passed"] and audit["decision"] == "ACCEPT"
    mismatch, _ = scored([a, alert("c", 60, host="web01", account="other")], v2)
    assert "entity.ACCOUNT" in mismatch.diagnostics["evidence_v2"]["mismatched_evidence"]
    assert mismatch.score < pair.score
    assert v2.algorithm.score.correlation_threshold == .65
    assert scorer.breakdown(pair).evidence_v2.normalized_quality == pytest.approx(audit["matched_weight"]/audit["available_weight"])


def test_host_exploit_process_association_does_not_create_causal_relation(v2):
    a = alert("exploit", category="web_attack", host="web01", src_ip="192.0.2.1", dst_ip="192.0.2.2")
    b = alert("process", 5, category="process_execution", host="web01", process=process(1))
    pair, scorer = scored([a, b], v2)
    assert pair.valid and pair.score > .7
    assert pair.relations == [] and pair.values["relation"] == 0
    c = run_correlation(scorer.index.alerts.values(), (), scorer.index.entities.values(), v2, scorer.settings)
    assert len(c.edges) == 1
    r = run_reconstruction(scorer.index.alerts.values(), (), scorer.index.entities.values(), c.edges, v2,
                           scorer.settings, upstream_record=c.record)
    assert len(r.incidents) == 1 and len(r.chains[0].edges) == 0
    assert r.chains[0].unresolved_correlation_edge_ids == [c.edges[0].edge_id]


def test_network_continuity_is_undirected_until_attested(v2):
    a = alert("net-a", category="initial_access", src_ip="192.0.2.1", dst_ip="192.0.2.2")
    b = alert("net-b", 10, category="lateral_movement", src_ip="192.0.2.2", dst_ip="192.0.2.3")
    pair, _ = scored([a, b], v2)
    audit = pair.diagnostics["evidence_v2"]
    assert "topology.network_continuity" in audit["matched_evidence"]
    assert pair.score >= .65 and pair.valid and pair.relations == []


@pytest.mark.parametrize("fields", [dict(), {"rule_id":"same"}, {"category":"authentication"},
    {"signature":"same"}, {"sensor":"same"}, {"alert_type":"same"}, {"dst_ip":"198.51.100.53"},
    {"domain":"public.example"}])
@pytest.mark.parametrize("seconds", [0, 1])
def test_weak_only_is_never_an_edge(v2, fields, seconds):
    a, b = alert("a", **fields), alert("b", seconds, **fields)
    pair, scorer = scored([a,b], v2)
    assert not pair.valid and not pair.diagnostics["evidence_v2"]["evidence_gate_passed"]
    r = run_correlation(scorer.index.alerts.values(), (), scorer.index.entities.values(), v2, scorer.settings)
    assert r.edges == []


def test_high_quality_time_only_still_rejected(v2):
    pair, _ = scored([alert("a"),alert("b")], v2)
    audit = pair.diagnostics["evidence_v2"]
    assert audit["normalized_quality"] == 1
    assert audit["decision"] == "REJECT_INSUFFICIENT_EVIDENCE"
    assert audit["gate_reason"] == "minimum_evidence_mass"
    amplified, _ = scored([alert("a", dst_ip="198.51.100.53"), alert("b", dst_ip="198.51.100.53")], v2)
    assert amplified.score >= .65 and not amplified.valid


def test_high_risk_does_not_prove_correlation(v2):
    pair, _ = scored([alert("a", host="one", severity="critical", src_ip="192.0.2.1"),
                      alert("b", host="two", severity="critical", src_ip="192.0.2.2")], v2)
    assert not pair.valid and pair.diagnostics["evidence_v2"]["decision"] != "ACCEPT"


def test_hot_host_and_public_destination_do_not_create_giant_incident(v2):
    alerts = [alert(str(i), i, host="gateway", dst_ip="198.51.100.53") for i in range(105)]
    idx, settings = inputs(alerts)
    result = run_correlation(idx.alerts.values(), (), idx.entities.values(), v2, settings)
    assert result.record.is_complete and result.edges == []
    assert result.summary["correlation_v2"]["gate_passed_candidate_count"] == 0
    assert len(result.candidates.pairs) < 105*50


def test_continuous_monotonic_time_and_soft_penalties(v2):
    scores = [scored([alert("a",host="h"),alert("b",gap,host="h")],v2)[0] for gap in (0,1,30,60,300)]
    assert all(x.values["time"] > y.values["time"] for x,y in zip(scores,scores[1:]))
    assert all(x.score > y.score for x,y in zip(scores,scores[1:]))
    assert scores[-1].values["time"] == pytest.approx(.5)


def test_attested_lineage_and_breakdown_roundtrip(v2):
    pair, scorer = scored(parent_child(), v2)
    audit = pair.diagnostics["evidence_v2"]
    assert audit["gate_reason"] == "C_verified_identifier_or_attested_relation"
    assert pair.values["relation"] == 1 and pair.valid
    bd = scorer.breakdown(pair)
    assert ScoreBreakdown.model_validate_json(bd.canonical_json()) == bd
    changed = bd.model_dump()
    changed["evidence_v2"]["matched_weight"] += .1
    with pytest.raises(ValueError):
        ScoreBreakdown.model_validate(changed)


def test_entity_free_semantic_candidates_bounded_but_not_edges(v2):
    alerts = [alert(str(i), i, rule_id="shared", signature="same") for i in range(110)]
    idx, settings = inputs(alerts)
    scorer = CorrelationScorer(idx, v2, settings)
    candidates = generate_candidates(idx, v2, scorer)
    assert candidates.pairs and all(p.channels == ("semantic",) for p in candidates.pairs)
    assert len(candidates.pairs) <= 110*10*2
    assert not candidates.candidate_truncated and candidates.policy_pruned_count > 0
    assert all(not scorer.score_pair(*p.support_key).valid for p in candidates.pairs)


def test_candidate_version_preserves_entity_path_and_order(v2):
    alerts = [alert(str(i), i, host="h", account="u") for i in range(7)]
    original = None
    for seed in range(3):
        order = alerts[:];random.Random(seed).shuffle(order)
        idx, settings = inputs(order)
        c = generate_candidates(idx, v2, CorrelationScorer(idx,v2,settings))
        data = [(p.support_key, p.channels, p.priority, [e.json_data() for e in p.evidence]) for p in c.pairs]
        assert original is None or data == original
        original = data
    old = load_config(ROOT/"configs/algorithm-v0.yaml")
    c0 = generate_candidates(idx, old, CorrelationScorer(idx,old,settings))
    assert [p.support_key for p in c0.pairs] == [p.support_key for p in c.pairs]


def test_old_hashes_and_serialization_unchanged(v2):
    old = load_config(ROOT/"configs/algorithm-v0.yaml")
    assert "evidence_v2" not in old.snapshot["score"] and "single_alert_triage" not in old.snapshot
    assert restore_config(old.snapshot).snapshot == old.snapshot
    assert restore_config(v2.snapshot).config_hash == v2.config_hash
    pair,scorer = scored([alert("a",host="h"),alert("b",host="h")],old)
    assert "evidence_v2" not in scorer.breakdown(pair).model_dump()


@pytest.mark.parametrize("change", [{"quality_factor":.9}, {"gate":{"minimum_mass":-1}},
                                  {"semantic_candidate_window_seconds":99999}, {"extra":True}])
def test_invalid_v2_config_rejected(tmp_path,change):
    data=read_yaml(ROOT/"configs/algorithm-v2.yaml")
    data["score"]["evidence_v2"].update(change)
    p=tmp_path/"v2.yaml";p.write_text(yaml.safe_dump(data),encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(p)


def test_v2_hard_scope_guard_and_session_difference_remain_honest(v2):
    from app.adapters.base import AdapterSettings
    a,b=alert('a',namespace='a',src_ip='192.0.2.1'),alert('b',1,namespace='b',src_ip='192.0.2.1')
    settings={n:AdapterSettings(n,'synthetic','synthetic',network_namespace=n) for n in ('a','b')}
    pair,_=scored([a,b],v2,settings)
    assert not pair.valid and pair.diagnostics['evidence_v2']['decision']=='REJECT_GUARD'
    assert 'cross_namespace_without_bridge' in pair.rejection_codes
    pair,_=scored([alert('a',host='h',session='one'),alert('b',1,host='h',session='two')],v2)
    assert 'verified_incompatible_session' not in pair.rejection_codes
    assert pair.diagnostics['conflicts']['session_compatibility']['status']=='unproven'


def test_v2_full_member_scoring_stable_support_and_formal_gate(v2,tmp_path):
    from app.models import CorrelationEdge
    from app.services.storage import SnapshotStore
    left=[alert('g1-a',5000,host='unused'),alert('g1-b',host='h',account='u')]
    right=[alert('g2-a',1,host='h',account='u'),alert('g2-b',5001,host='other')]
    groups=[group(left),group(right)]
    index,settings=inputs(left+right,groups=groups)
    rows=[]
    r=run_correlation(index.alerts.values(),groups,index.entities.values(),v2,settings,diagnostic_sink=rows.append)
    assert r.summary['verified_member_pair_count']==4
    assert len([row for row in rows if row['stage']=='member_score'])==4
    assert len(r.edges)==1
    e=r.edges[0]
    assert e.support_pair.alert_ids()=={left[1].alert_id,right[0].alert_id}
    assert all(set(reason.alert_ids)==e.support_pair.alert_ids() for reason in e.reasons)
    reordered=run_correlation(list(reversed(list(index.alerts.values()))),list(reversed(groups)),
        list(reversed(list(index.entities.values()))),v2,settings)
    assert r.record.analysis_id==reordered.record.analysis_id
    assert [e.canonical_json() for e in r.edges]==[e.canonical_json() for e in reordered.edges]
    store=SnapshotStore(tmp_path,r.record.analysis_id)
    store.write_records('correlation_edges',r.edges)
    assert list(store.read_records('correlation_edges',parquet=True))==r.edges
    bad=e.model_dump()
    bad['score_breakdown']['evidence_v2'].update(evidence_gate_passed=False,decision='REJECT_INSUFFICIENT_EVIDENCE')
    with pytest.raises(ValueError,match='formal v2'):
        CorrelationEdge.model_validate(bad)


def test_v2_api_storage_and_score_receipt_integrity(tmp_path,monkeypatch):
    from fastapi.testclient import TestClient
    from app.api.workbench import create_workbench_app
    from app.services.storage import SnapshotStore,MODELS
    from test_analysis_service import deployment,edge_records,write_input,tripwire
    from test_wazuh_adapter import synthetic_record
    _,settings=deployment(tmp_path,edge=True)
    cfg=load_config(ROOT/'configs/algorithm-v2.yaml',deployment_override=ROOT/'configs/sources.yaml',
        experiment_override=tmp_path/'experiment.yaml')
    records=edge_records()+[synthetic_record(id='isolated',rule={'id':'other','level':15},data={'host':'other-host'})]
    relative=write_input(tmp_path,records)
    tripwire(monkeypatch)
    app=create_workbench_app(tmp_path,configs={'v2':cfg},sources=settings)
    ids=[]
    with TestClient(app) as client:
        for _ in range(2):
            response=client.post('/api/v1/analyses',json={'config_version':'v2',
                'inputs':[{'source':'wazuh','source_ref':'w','path':relative}]})
            assert response.status_code==202,response.text
            aid=response.json()['analysis_id'];ids.append(aid)
            app.state.analyses.wait(aid,timeout=30)
            detail=client.get('/api/v1/analyses/'+aid)
            assert detail.status_code==200,detail.text
            assert detail.json()['status']=='completed',detail.text
            assert detail.json()['counts']['correlation_edge_count']==1
            assert detail.json()['counts']['chain_edge_count']==1
            store=SnapshotStore(tmp_path,aid)
            assert store.validate_reconstruction(parquet=True).valid
            incidents=client.get('/api/v1/incidents',params={'analysis_id':aid}).json()['items']
            singles=[i for i in incidents if len(i['alert_ids'])==1]
            assert len(singles)==1 and singles[0]['single_alert_triage']['risk_level']=='critical'
            from app.ai.explanation import load_context
            for incident in incidents:
                context=load_context(app.state.queries,aid,incident['incident_id'])
                assert 'single_alert_triage' not in context.data['incident']
                assert 'raw_alert' not in str(context.data['facts']['alerts'])
            diagnostic=client.get(f'/api/v1/analyses/{aid}/score-diagnostics')
            assert diagnostic.status_code==200,diagnostic.text
            assert diagnostic.json()['status']=='available' and diagnostic.json()['version']=='v2'
        for kind in MODELS:
            assert list(SnapshotStore(tmp_path,ids[0]).read_records(kind))==list(SnapshotStore(tmp_path,ids[1]).read_records(kind))
        # Read-only receipt verification rejects edits independently of domain IO.
        report=SnapshotStore(tmp_path,ids[1]).details/'correlation_v2_scores.json'
        report.write_text('{}',encoding='utf-8')
        assert client.get(f'/api/v1/analyses/{ids[1]}/score-diagnostics').status_code==409
