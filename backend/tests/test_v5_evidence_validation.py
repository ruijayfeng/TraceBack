from evaluation.framework.preformula_baseline.boundary import development_config, development_cptc, verify_historical_inventory, verify_current
"""Offline prototype safety tests. Artificial views are synthetic unit fixtures.

No synthetic alert is admitted to real dataset validation artifacts.
"""
from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import v5_design_diagnostic as d
import v5_validation_evidence as e
import v5_evidence_validation as runner
import v5_validation_report as report


def view():
    dims=[dict(dimension=n,family=f,state=st,strength=s,weight=w,entity_ids=[],v4_state='AVAILABLE_MATCH',basis='synthetic unit fixture')
        for n,f,st,s,w in [('time.distance','time','SUPPORTED',1.,1.),
            ('entity.URL','entity','SUPPORTED',.9,.85),('entity.IP','entity','SUPPORTED',.3,.25),
            ('metadata.detector_identity','behavior','SUPPORTED',.08,1.),
            ('topology.attested_relation','relation','UNOBSERVABLE',0.,1.),
            ('context.independent_complement','source','UNKNOWN',0.,1.)]]
    facts=[dict(dimension=x['dimension'],family=f,fact_key=x['dimension'],strength=x['strength'],
        role='primary' if f=='RESOURCE_CONTEXT' else 'supporting',evidence_refs=[])
        for x,f in zip(dims,['TEMPORAL','RESOURCE_CONTEXT','ENTITY_IDENTITY','RULE_METADATA'])]
    return dict(dimensions=dims,facts=facts,reliability=[],weights=dict(time=.2,entity=.3,relation=.36,behavior=.04,source=.1),
        hard=[],duplicate_risk=False,penalty=0.,half_life=300.,pair=['synthetic-a','synthetic-b'],v4_score=.4)


def test_unavailable_by_source_not_treated_as_negative():
    assert e.capability(0,100,schema_excludes=True)=='UNAVAILABLE_BY_SOURCE'
    assert e.capability(0,100)=='UNKNOWN'
    v=view();missing=deepcopy(v);negative=deepcopy(v)
    missing['dimensions'][1].update(state='UNOBSERVABLE',strength=0.)
    negative['dimensions'][1].update(state='CONTRADICTED',strength=0.)
    a=e.compare(missing,d.design())['b'];b=e.compare(negative,d.design())['b']
    assert a['negative_weight']==0 < b['negative_weight']
    assert a['confidence']==b['confidence']
    assert a['score']>b['score']
    # No real schema attestation: driver must not promote unobserved to U.
    assert a['unavailable_weight']==0


def test_available_but_nonmatching_remains_negative():
    v=view();v['dimensions'][2].update(state='CONTRADICTED',strength=0.)
    assert e.pair_states(v)['entity.IP']['state']=='PRESENT_BUT_NONMATCHING'
    scores=e.compare(v,d.design())
    assert all(r['negative_weight']>0 for r in scores.values())
    assert all(r['score']<e.compare(view(),d.design())[k]['score'] for k,r in scores.items())


def test_unknown_capability_is_conservative():
    v=view();before=e.compare(v,d.design())['b']
    v['dimensions'][1].update(state='UNKNOWN',strength=0.)
    after=e.compare(v,d.design())['b']
    assert after['confidence']<before['confidence']
    assert 'no_frozen_primary_evidence' in after['admission_reasons']
    assert not after['admitted']
    assert e.capability(0,1)=='UNKNOWN'
    assert e.capability(1,2)=='OPTIONAL'
    assert e.capability(2,2)=='AVAILABLE'


@pytest.mark.parametrize('keep',['time','entity','behavior'])
def test_single_evidence_match_not_enough(keep):
    v=view()
    for dim in v['dimensions']:
        if dim['family']!=keep:dim.update(state='UNOBSERVABLE',strength=0.)
    assert all(not r['admitted'] for r in e.compare(v,d.design()).values())


def sparse_view():
    v=view()
    for dim in v['dimensions']:
        if dim['family']=='entity':dim.update(state='UNOBSERVABLE',strength=0.)
    return v


def test_sparse_pair_not_auto_promoted():
    assert all(not r['admitted'] for r in e.compare(sparse_view(),d.design()).values())


def test_same_signature_different_attack_not_promoted():
    # Synthetic metadata match, no context. No campaign answer is a score input.
    v=sparse_view();v['dimensions'][3]['strength']=.2
    assert all(not r['admitted'] for r in e.compare(v,d.design()).values())


def test_common_ip_not_over_correlated():
    v=view();v['dimensions'][1].update(state='UNOBSERVABLE',strength=0.)
    v['facts']=[dict(x,role='supporting') for x in v['facts']]
    assert all(not r['admitted'] for r in e.compare(v,d.design()).values())


def test_transport_only_not_promoted():
    # Transport alone has no independent family weight or primary fact.
    v=sparse_view();v['dimensions'][3].update(state='UNOBSERVABLE',strength=0.)
    assert all(not r['admitted'] for r in e.compare(v,d.design()).values())


def test_repeated_observation_not_chain():
    v=view();v['duplicate_risk']=True
    assert all(not r['admitted'] for r in e.compare(v,d.design()).values())
    assert report.cluster_evidence([dict(correlation_supported=False,chain_progression_supported=False,
        pair=['synthetic-a','synthetic-b'],candidate_id='synthetic')])['potential_multi_edge_clusters']==0


def test_preformula_identity_and_historical_v4_artifacts_unchanged():
    config,receipt,_=development_config()
    assert d.correlation_version(config)=='alert-correlation-v5-preformula-candidate-v1'
    assert config.algorithm.score.correlation_threshold==.65
    assert config.mapping_digest=='aba87d612711cc4cb67998df9604b62b61a3fb72b01c165d1745594b8a538658'
    before=d.read(ROOT/'outputs/v5_design_diagnostic/protected_before.json')
    assert verify_historical_inventory(before, anchor=ROOT/'outputs/v5_design_diagnostic/protected_before.json')['status'] == 'PASS'


def test_completeness_uses_actual_scoring_prerequisites():
    assert e.evidence_profile(dict(timestamp='real-time',rule_id='r'))['evidence_completeness']=='SPARSE'
    assert e.evidence_profile(dict(timestamp='real-time',host='host-a'))['evidence_completeness']=='MEDIUM'
    network=dict(src_ip='192.0.2.1',dst_ip='192.0.2.2',src_port=0,dst_port=80,protocol='TCP')
    assert e.evidence_profile(network)['evidence_completeness']=='HIGH'
    network['dst_port']=None
    assert e.evidence_profile(network)['evidence_completeness']=='MEDIUM'
    # Metadata/category abundance cannot compensate missing contextual fields.
    assert e.evidence_profile(dict(signature='bad',category='initial_access',rule_id='r',protocol='TCP'))['evidence_completeness']=='SPARSE'


def test_formula_candidates_are_exact_previous_policy():
    v=view();expected=d.compare(v,d.design());actual=e.compare(v,d.design())
    for k in d.CANDIDATES:
        assert {key:actual[k][key] for key in expected[k]}==expected[k]
        assert actual[k]['score_delta_vs_v4']==actual[k]['score']-.4
        assert actual[k]['available_weight']+actual[k]['unknown_weight']+actual[k]['missing_observation_weight']==pytest.approx(1)


def test_real_schema_card_roundtrip_and_score_label_separation():
    from test_correlation_score import parent_child,inputs
    from app.correlation.scoring import CorrelationScorer
    cfg,_,_=development_config()
    alerts=parent_child();idx,settings=inputs(alerts)
    scorer=CorrelationScorer(idx,cfg,settings)
    before=[a.canonical_json() for a in alerts]
    ids=sorted(idx.alerts)
    card,projection=e.make_card(ids,scorer,d.design(),'synthetic_fixture',{'unit'})
    assert card['ground_truth_used_for_scoring']=='NO'
    assert card['alert_a']['timestamp']==idx.alerts[ids[0]].timestamp
    assert json.loads(json.dumps(card))['v4_score']==scorer.score_pair(*ids).score
    assert [a.canonical_json() for a in alerts]==before
    restored=e.replay_view(card)
    replay=e.compare(restored,d.design())
    for key in d.CANDIDATES:
        assert replay[key]['score']==pytest.approx(card['prototypes'][key]['score'],abs=1e-12)
        assert replay[key]['admitted']==card['prototypes'][key]['admitted']


def test_ablation_removes_fact_votes_and_never_changes_alerts():
    v=view();before=deepcopy(v)
    rows=e.ablate(v,'entity',d.design())
    assert all(not r['primary'] and not r['admitted'] for r in rows.values())
    assert v==before


def test_label_free_scoring_input_has_no_semantic_review_fields():
    v=view();a=e.compare(v,d.design())
    v['semantic_relation']='ATTACK_PROGRESSION';v['ground_truth']='synthetic-answer'
    assert e.compare(v,d.design())==a


def test_truth_read_tripwire(tmp_path):
    path=tmp_path/'labels.csv';path.write_text('synthetic forbidden truth')
    with d.truth_guard(tmp_path):
        with pytest.raises(RuntimeError,match='Ground Truth access rejected'):path.read_text()


def test_production_does_not_import_validation():
    for path in (ROOT/'backend/app').rglob('*.py'):
        source=path.read_text(encoding='utf8')
        assert 'v5_evidence_validation' not in source
        assert 'v5_validation_evidence' not in source
        assert 'v5_validation_report' not in source


def test_deterministic_undirected_path_witness():
    rows=[dict(correlation_supported=True,chain_progression_supported=False,pair=[a,b],candidate_id=a+b)
          for a,b in [('a','b'),('b','c'),('c','a'),('c','d')]]
    assert report.cluster_evidence(rows)==report.cluster_evidence(list(reversed(rows)))
    result=report.cluster_evidence(rows)
    assert result['potential_multi_edge_clusters']==1
    path=result['clusters'][0]['witness_path']
    assert len(path)==len(set(path))
    assert result['directional_progression_pairs']==0


def test_canonical_sparse_is_not_certified_raw_sparse(tmp_path,monkeypatch):
    from app.utils.stable_id import raw_fingerprint
    monkeypatch.setattr(d,'ROOT',tmp_path)
    raw={'AnalysisComponent':{'AnalysisComponentType':'synthetic-detector'},
        'LogData':{'RawLogData':['synthetic alert snippet with unextracted context']}}
    path=tmp_path/'data/input/alerts/synthetic.json';path.parent.mkdir(parents=True)
    path.write_text(json.dumps([raw]),encoding='utf8')
    out=tmp_path/'outputs';out.mkdir()
    d.atomic_json(out/'sparse_sample_manifest.json',dict(count=1,records=[dict(
        path='data/input/alerts/synthetic.json',ordinal=1,raw_fingerprint=raw_fingerprint(raw))]))
    audit=report.qualify_sparse(out)
    assert audit['canonical_sparse']==1 and audit['verified_raw_sparse']==0
    assert audit['records'][0]['missing_in_raw']=='NOT_ESTABLISHED'
    assert audit['records'][0]['attached_evidence_pointers']==['/LogData/RawLogData/0']
    # A repeated report replay must retain the original audited denominator.
    assert report.qualify_sparse(out)==audit


def test_sparse_review_requires_exact_original_fingerprint(tmp_path,monkeypatch):
    from app.utils.stable_id import raw_fingerprint
    monkeypatch.setattr(d,'ROOT',tmp_path)
    raw={'LogData':{'RawLogData':['synthetic sparse observation']}}
    path=tmp_path/'data/input/alerts/synthetic.json';path.parent.mkdir(parents=True)
    path.write_text(json.dumps([raw]),encoding='utf8')
    out=tmp_path/'outputs';out.mkdir()
    row=dict(alert_id='synthetic-a',path='data/input/alerts/synthetic.json',ordinal=1,raw_fingerprint=raw_fingerprint(raw))
    d.atomic_json(out/'sparse_sample_manifest.json',dict(count=1,records=[row]))
    annotation=dict(**row,decision='RAW_SPARSE_CONFIRMED',evidence_scope='frozen_v4_dependency_fields')
    d.atomic_json(out/'raw_sparse_agent_review.json',dict(records=[dict(annotation,raw_fingerprint='invalid')]))
    assert report.qualify_sparse(out)['verified_raw_sparse']==0
    d.atomic_json(out/'raw_sparse_agent_review.json',dict(records=[annotation]))
    assert report.qualify_sparse(out)['verified_raw_sparse']==1


def test_single_semantic_pair_path_is_one_edge():
    result=report.cluster_evidence([dict(correlation_supported=True,chain_progression_supported=False,
        pair=['synthetic-a','synthetic-b'],candidate_id='synthetic')])
    assert result['potential_multi_edge_clusters']==0
    assert result['longest_semantically_plausible_candidate_path_edges']==1
