"""Synthetic V5 safety, contract, dispatch and real downstream integration."""
from copy import deepcopy
from pathlib import Path
import pytest
from app.config import load_config
from app.correlation.formula_v5 import aggregate, ALGORITHM_VERSION
from app.correlation.scoring import CorrelationScorer
from app.correlation.edges import correlation_version, run_correlation
from app.models import CorrelationEdge, AttackChain
from app.models.correlation_v5 import ScoreBreakdownV5
from app.services.storage import restore_config, SnapshotStore

ROOT=Path(__file__).resolve().parents[2]


@pytest.fixture
def cfg():
    return load_config(ROOT/'configs/algorithm-v5.yaml')


def fact(name='entity.HOST',role='host',strength=.8,reliability=.7,state='SUPPORTED',hot=False):
    return dict(name=name,family='entity',state=state,strength=strength,reliability=reliability,
        role=role,hot=hot,entity_ids=[],provenance=[])


def calc(cfg,features,**kw):
    return aggregate(features,cfg.algorithm.score.evidence_v5.model_dump(),
        **dict(hard=False,duplicate_risk=False,duplicate=0.,**kw))


def test_missing_and_alternative_zero_do_not_dilute_independent_support(cfg):
    base=[fact(),fact('entity.ACCOUNT','account',.8,.75)]
    original=calc(cfg,base)
    assert original['final_score']>.65
    for state in ('UNOBSERVABLE','OBSERVED_ZERO'):
        assert calc(cfg,base+[fact('entity.PROCESS','generic',0.,.8,state)])==original


def test_contradiction_is_not_missing(cfg):
    base=[fact(),fact('entity.ACCOUNT','account',.8,.75)]
    contradiction=fact('conflict.reversed','generic',0.,1.,'CONTRADICTED')
    assert calc(cfg,base+[contradiction])['final_score']<calc(cfg,base)['final_score']


@pytest.mark.parametrize('feature',[fact('entity.IP','generic',1.,.15),fact('entity.ACCOUNT','account',1.,.75),fact()])
def test_single_context_cannot_be_inflated(cfg,feature):
    r=calc(cfg,[feature])
    assert r['gate']['passed'] and r['final_score']<=.45


def test_time_metadata_source_cannot_create_semantic_context(cfg):
    fs=[dict(fact(),name=f,family=f) for f in ('time','behavior','source')]
    assert calc(cfg,fs)['final_score']==0
    assert not calc(cfg,fs)['gate']['passed']


def test_asset_and_monitored_ip_count_once_and_order_stable(cfg):
    base=[fact(),fact('entity.ACCOUNT','account',.8,.75)]
    extended=base+[fact('entity.IP','endpoint',.5,.55)]
    assert calc(cfg,base)==calc(cfg,extended)==calc(cfg,list(reversed(extended)))


def test_direct_proof_is_sufficient_but_never_bypasses_hard_guard(cfg):
    f=dict(fact('topology.attested_relation','direct',.9,1.),family='relation')
    assert calc(cfg,[f])['final_score']==.9
    assert aggregate([f],cfg.algorithm.score.evidence_v5.model_dump(),hard=True,duplicate_risk=False,duplicate=0)['final_score']==0
    assert aggregate([f],cfg.algorithm.score.evidence_v5.model_dump(),hard=False,duplicate_risk=True,duplicate=0)['final_score']==0


def test_hot_context_is_not_strong(cfg):
    assert calc(cfg,[fact(hot=True),fact('entity.ACCOUNT','account',1.,.75,hot=True)])['final_score']<=.45


def test_v4_snapshot_and_serialization_unchanged(cfg):
    old=load_config(ROOT/'configs/algorithm-v4.yaml')
    assert 'evidence_v5' not in old.snapshot['score']
    assert restore_config(old.snapshot).snapshot==old.snapshot
    assert cfg.algorithm.version=='v4'  # Only canonical feature/candidate profile.
    assert correlation_version(cfg)==ALGORITHM_VERSION
    assert correlation_version(old)!=ALGORITHM_VERSION


def test_v5_actual_multistep_reconstruction_storage_and_schema(cfg,tmp_path):
    from fixtures.chains.synthetic import linear_fixture
    from app.chains.assembly import run_reconstruction
    index,settings,_,correlation=linear_fixture(cfg)
    assert len(correlation.edges)>=2
    assert all(isinstance(e.score_breakdown,ScoreBreakdownV5) for e in correlation.edges)
    from app.correlation.edges import run_correlation
    reordered=run_correlation(list(reversed(list(index.alerts.values()))),[],
        list(reversed(list(index.entities.values()))),cfg,settings)
    assert [e.canonical_json() for e in reordered.edges]==[e.canonical_json() for e in correlation.edges]
    result=run_reconstruction(index.alerts.values(),[],index.entities.values(),correlation.edges,cfg,settings,
        upstream_record=correlation.record,output_root=tmp_path,existing_index=index)
    assert result.grounding.valid
    chain=next(c for c in result.chains if len(c.edges)>=2)
    assert AttackChain.model_validate_json(chain.canonical_json())==chain
    edge=correlation.edges[0]
    assert CorrelationEdge.model_validate_json(edge.canonical_json())==edge
    store=SnapshotStore(tmp_path,result.record.analysis_id)
    store.write_records('correlation_edges',correlation.edges)
    assert [e.canonical_json() for e in store.read_records('correlation_edges')]==[e.canonical_json() for e in correlation.edges]
    # Reconstruct from persisted (six-decimal public score) data as a new reader.
    replay=run_reconstruction(index.alerts.values(),[],index.entities.values(),
        list(store.read_records('correlation_edges')),cfg,settings,existing_index=index)
    assert replay.grounding.valid
    bad=edge.model_dump(mode='json')
    bad['score_breakdown']['positive_support']+=.1
    with pytest.raises(ValueError):CorrelationEdge.model_validate(bad)
    bad=edge.model_dump(mode='json');bad['score_breakdown']['schema_version']='4.0'
    with pytest.raises(ValueError):CorrelationEdge.model_validate(bad)
    bad=edge.model_dump(mode='json')
    feature=next(f for f in bad['score_breakdown']['features'] if f['provenance'])
    feature['provenance'][0]['alert_id']='alt_'+'f'*64
    with pytest.raises(ValueError):CorrelationEdge.model_validate(bad)


def test_v5_service_post_to_edge_evidence_api(tmp_path):
    from fastapi.testclient import TestClient
    from app.main import create_app
    from test_analysis_service import deployment,edge_records,write_input,request_for
    _,sources=deployment(tmp_path,edge=True)
    cfg=load_config(ROOT/'configs/algorithm-v5.yaml',deployment_override=ROOT/'configs/sources.yaml',
        experiment_override=tmp_path/'experiment.yaml')
    app=create_app(tmp_path,configs={'v5':cfg},sources=sources)
    with TestClient(app) as client:
        body=request_for(write_input(tmp_path,edge_records()))
        body['config_version']='v5'
        response=client.post('/api/v1/analyses',json=body)
        assert response.status_code==202,response.text
        aid=response.json()['analysis_id'];app.state.analyses.wait(aid,timeout=30)
        detail=client.get('/api/v1/analyses/'+aid)
        assert detail.json()['status']=='completed',detail.text
        assert detail.json()['algorithm_version']=='analysis-service-v5-f3-independent-support-v1'
        scope={'analysis_id':aid}
        incident=client.get('/api/v1/incidents',params=scope).json()['items'][0]
        chain=client.get('/api/v1/incidents/'+incident['incident_id']+'/chain',params=scope).json()['chain']
        assert chain['edges']
        data=client.get('/api/v1/edges/'+chain['edges'][0]['edge_id'],params=scope)
        assert data.status_code==200,data.text
        score=data.json()['edge']['score_breakdown']
        assert score['schema_version']=='5.0' and score['implementation_version']=='v5-formula-f3-v1'
        for alert_id in data.json()['edge']['alert_ids']:
            assert client.get('/api/v1/alerts/'+alert_id,params=scope).json()['alert']['raw_alert']
        schema=client.get('/openapi.json').json()
        assert 'ScoreBreakdownV5' in schema['components']['schemas']


