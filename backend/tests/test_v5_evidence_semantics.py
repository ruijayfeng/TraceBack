"""Label-free witnesses for five-state support, independence and hard guards."""
from copy import deepcopy
from types import SimpleNamespace as NS
from pathlib import Path
import pytest
from app.config import load_config
from app.correlation.formula_v5 import aggregate
from app.correlation.evidence_semantics import state_for
from app.models.correlation_v5 import V5Feature

ROOT=Path(__file__).resolve().parents[2]

@pytest.fixture
def cfg(): return load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml')

def f(name='entity.HOST',strength=.7,reliability=.7,state='OBSERVED_SUPPORT',role='generic',hot=False,ids=()):
    return dict(name=name,family='entity',state=state,strength=strength,reliability=reliability,
                role=role,hot=hot,entity_ids=list(ids),provenance=[])

def calc(cfg,fs,**kw):
    return aggregate(fs,cfg.algorithm.score.evidence_v5.model_dump(),
        **{'hard':False,'duplicate_risk':False,'duplicate':0.,**kw})

@pytest.mark.parametrize('state',['MISSING','UNOBSERVABLE','OBSERVED_NEUTRAL'])
def test_three_independent_moderate_supports_not_diluted(cfg,state):
    fs=[f('entity.IP'),f('entity.DOMAIN'),f('entity.ACCOUNT')]
    before=calc(cfg,fs)
    assert before['final_score']>.65 and before['quality']==pytest.approx(.7)
    assert not before['weak_only']
    assert calc(cfg,fs+[f('entity.SESSION',0.,.8,state)])==before

def test_single_weak_common_entity_low_confidence(cfg):
    result=calc(cfg,[f('entity.IP',1.,.15)])
    assert result['gate']['passed'] and result['final_score']<=.15

def test_single_context_ceiling_remains(cfg):
    assert calc(cfg,[f('entity.HOST',1.,1.)])['final_score']==.45

def test_two_moderate_non_role_clues_can_accumulate(cfg):
    result=calc(cfg,[f('entity.IP',.9,.6),f('entity.DOMAIN',.9,.6)])
    assert result['final_score']>.6 and not result['weak_only']

def test_explicit_contradiction_penalizes_and_hard_guard_rejects(cfg):
    fs=[f('entity.HOST'),f('entity.ACCOUNT'),f('entity.SESSION')]
    contradiction=f('conflict.reversed',0.,1.,'OBSERVED_CONTRADICTION')
    contradiction['family']='conflict'
    assert calc(cfg,fs+[contradiction])['final_score']<calc(cfg,fs)['final_score']-.4
    for kw in ({'hard':True},{'duplicate_risk':True}):
        assert calc(cfg,fs,**kw)['final_score']==0.

def test_dependency_views_do_not_receive_duplicated_credit(cfg):
    base=[f('entity.IP',ids=['asset']),f('entity.DOMAIN',ids=['resource'])]
    derived=base+[f('entity.HOST',ids=['asset']),f('entity.URL',ids=['resource'])]
    flow=f('topology.network_continuity',role='flow',ids=['asset']);flow['family']='relation'
    assert calc(cfg,base)==calc(cfg,derived+[flow])
    assert calc(cfg,derived+[flow])==calc(cfg,list(reversed(derived+[flow])))

def test_hot_supports_never_escape_weak_ceiling(cfg):
    assert calc(cfg,[f('entity.HOST',1.,1.,hot=True),f('entity.ACCOUNT',1.,1.,hot=True)])['final_score']<=.45

@pytest.mark.parametrize('family',['time','behavior','source'])
def test_metadata_transport_or_time_cannot_create_context(cfg,family):
    feature=f(family);feature['family']=family
    assert calc(cfg,[feature])['final_score']==0.

def test_state_missing_unobservable_and_neutral_are_distinct():
    fields=dict(src_ip=None,dst_ip=None,host=None,account=None,session=None,process=None,parent_process=None,
                url=None,domain=None,file=None,command=None)
    a=NS(**fields,source_namespace='a');b=NS(**fields,source_namespace='b')
    settings={'a':NS(account_realm=None),'b':NS(account_realm=None)}
    feature=f('entity.ACCOUNT',0.,state='OBSERVED_ZERO')
    assert state_for(feature,a,b,settings,{})=='MISSING'
    a.account=b.account='user'
    assert state_for(feature,a,b,settings,{})=='UNOBSERVABLE'
    settings['a'].account_realm=settings['b'].account_realm='realm'
    assert state_for(feature,a,b,settings,{})=='OBSERVED_NEUTRAL'

@pytest.mark.parametrize('state',['MISSING','UNOBSERVABLE','OBSERVED_NEUTRAL','OBSERVED_CONTRADICTION'])
def test_non_support_cannot_carry_positive_strength(state):
    with pytest.raises(ValueError): V5Feature.model_validate(f(state=state))

def test_new_contract_roundtrip_grounding_and_stable_id(cfg,tmp_path):
    from fixtures.chains.synthetic import linear_fixture
    from app.chains.assembly import run_reconstruction
    from app.models import CorrelationEdge
    from app.services.storage import SnapshotStore
    index,settings,_,correlation=linear_fixture(cfg)
    assert len(correlation.edges)>=2
    assert all(e.score_breakdown.schema_version=='5.1' for e in correlation.edges)
    result=run_reconstruction(index.alerts.values(),[],index.entities.values(),correlation.edges,cfg,settings,
        upstream_record=correlation.record,output_root=tmp_path,existing_index=index)
    assert result.grounding.valid and any(len(c.edges)>=2 for c in result.chains)
    store=SnapshotStore(tmp_path,result.record.analysis_id)
    store.write_records('correlation_edges',correlation.edges)
    assert [e.canonical_json() for e in store.read_records('correlation_edges')]==[e.canonical_json() for e in correlation.edges]
    bad=correlation.edges[0].model_dump(mode='json');bad['score_breakdown']['algorithm_version']='alert-correlation-v5-f3-independent-support-v1'
    with pytest.raises(ValueError): CorrelationEdge.model_validate(bad)

def test_new_service_identity_and_api_contract(tmp_path):
    from fastapi.testclient import TestClient
    from app.main import create_app
    from test_analysis_service import deployment,edge_records,write_input,request_for
    _,sources=deployment(tmp_path,edge=True)
    config=load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml',deployment_override=ROOT/'configs/sources.yaml',
        experiment_override=tmp_path/'experiment.yaml')
    app=create_app(tmp_path,configs={'v5sem':config},sources=sources)
    with TestClient(app) as client:
        body=request_for(write_input(tmp_path,edge_records()));body['config_version']='v5sem'
        response=client.post('/api/v1/analyses',json=body);assert response.status_code==202
        aid=response.json()['analysis_id'];app.state.analyses.wait(aid,timeout=30)
        detail=client.get('/api/v1/analyses/'+aid).json()
        assert detail['status']=='completed'
        assert detail['algorithm_version']=='analysis-service-v5-evidence-semantics-v1'
        incident=client.get('/api/v1/incidents',params={'analysis_id':aid}).json()['items'][0]
        chain=client.get('/api/v1/incidents/'+incident['incident_id']+'/chain',params={'analysis_id':aid}).json()['chain']
        assert chain['edges'] and chain['edges'][0]['score_breakdown']['schema_version']=='5.1'

def test_explicit_reversed_relation_is_a_hard_semantic_gate(cfg):
    from app.correlation.evidence_semantics import repair
    old=dict(f('entity.HOST',1.,.7,role='host'),state='SUPPORTED')
    policy=cfg.algorithm.score.evidence_v5.model_dump()
    result=repair([old],NS(settings={}),None,None,{'duplicate_observation_risk':False},policy,
        {'duplicate':0.},{'hard':[],'reversed_relation':True})
    assert result['gate']['hard_contradiction'] and not result['gate']['passed']
    assert result['final_score']==0.

def test_plain_ip_domain_context_is_scored_without_role_whitelist(cfg):
    from test_correlation_score import alert,inputs
    from app.correlation.scoring import CorrelationScorer
    aa=[alert('ordinary-a',src_ip='192.0.2.11',domain='example.invalid'),
        alert('ordinary-b',3,src_ip='192.0.2.11',domain='example.invalid')]
    index,settings=inputs(aa)
    pair=CorrelationScorer(index,cfg,settings).score_pair(*index.alerts)
    v=pair.diagnostics['evidence_v5']
    assert pair.valid and v['gate']['passed'] and pair.score>0
    assert set(v['group_support'])=={'asset','resource'}
    assert not pair.relations  # Undirected context cannot manufacture propagation.
    assert all(f['state']!='OBSERVED_CONTRADICTION' for f in v['features'])

def test_known_namespace_isolation_still_rejects_ordinary_shared_domain(cfg):
    from test_correlation_score import alert,inputs
    from app.adapters.base import AdapterSettings
    from app.correlation.scoring import CorrelationScorer
    aa=[alert('isolated-a',namespace='a',domain='example.invalid'),
        alert('isolated-b',3,namespace='b',domain='example.invalid')]
    settings={n:AdapterSettings(n,'synthetic','synthetic',network_namespace=n) for n in ('a','b')}
    index,settings=inputs(aa,settings)
    pair=CorrelationScorer(index,cfg,settings).score_pair(*index.alerts)
    assert not pair.valid and pair.score==0
    assert pair.diagnostics['evidence_v5']['gate']['hard_contradiction']
