"""Prospective synthetic witnesses; no semisynthetic GT or dataset values."""
from copy import deepcopy
from pathlib import Path
import pytest
from app.config import read_yaml,load_config
from app.correlation.separation_direction.models import Policy,PairResult,DirectionEvidence
from app.correlation.separation_direction.formula import aggregate
from app.correlation.separation_direction.evidence import transition,alias_groups
from app.correlation.separation_direction.direction import decide
from app.utils.stable_id import content_digest,id_for,raw_fingerprint
from test_correlation_score import alert,inputs

ROOT=Path(__file__).resolve().parents[2]

@pytest.fixture
def policy():
    return Policy.model_validate(read_yaml(ROOT/'configs/algorithm-v5-separation-direction.yaml')).model_dump(by_alias=True)

def base(groups,weak=True,**updates):
    return dict(group_support=groups,direct_support=0.,temporal_factor=1.,weak_only=weak,
        conflict_penalty=0.,duplicate_penalty=0.,gate=dict(passed=True,hard_contradiction=False,
        duplicate_observation=False,non_temporal_support=True),**updates)

def synthetic_transition(specificity=.9,compatibility=.9):
    return dict(context=dict(kind='HOST'),specificity=specificity,compatibility=compatibility)

def test_s1_specific_transition_beats_common_asset(policy):
    common=aggregate(base({'asset':.2}),{'asset':.2},None,policy)
    specific=aggregate(base({'asset':.2}),{'asset':.2},synthetic_transition(),policy)
    assert specific['final_score']>common['final_score']+.4
    assert set(specific['upgraded_group_support'])=={'asset'} # no extra independent clue

def test_s2_hot_common_context_remains_low(policy):
    assert aggregate(base({'asset':.05}),{'asset':.05},None,policy)['final_score']==pytest.approx(.05)
    assert aggregate(base({'asset':.8}),{'asset':.8},None,policy)['final_score']==.45

def test_s3_independent_moderate_evidence_accumulates(policy):
    groups={'asset':.5,'entity.ACCOUNT':.5,'execution':.5}
    assert aggregate(base(groups,False),groups,None,policy)['final_score']==.875

def test_s4_incompatible_transition_gets_no_promotion(policy):
    aa=[alert('synthetic-incompatible-a',host='unit-host',category='web_attack'),
        alert('synthetic-incompatible-b',2,host='unit-host',category='reconnaissance')]
    idx,settings=inputs(aa)
    cfg=load_config(ROOT/'configs/algorithm-v0.yaml')
    assert transition(aa[0],aa[1],idx,settings,policy,cfg.algorithm.entity) is None
    assert aggregate(base({'asset':.8}),{'asset':.8},None,policy)['final_score']<=.45

def test_s5_missing_is_not_contradiction(policy):
    idx,settings=inputs([alert('sparse-one'),alert('sparse-two',1)])
    a,b=idx.alerts.values();cfg=load_config(ROOT/'configs/algorithm-v0.yaml')
    assert transition(a,b,idx,settings,policy,cfg.algorithm.entity) is None
    result=decide(a,b,idx,policy)
    assert result['status']=='AMBIGUOUS_DIRECTION' and not result['contradiction']

def with_raw(a,extra):
    data=a.model_dump();data['raw_alert']={**a.raw_alert,**extra};data['raw_fingerprint']=raw_fingerprint(data['raw_alert'])
    data['alert_id']=id_for('CanonicalAlert',data)
    return type(a).model_validate(data)

def flow_pair(reverse=False):
    from app.adapters.wazuh import WazuhAdapter
    from app.adapters.base import AdapterSettings
    cfg=load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml',deployment_override=ROOT/'configs/sources.yaml')
    setting=AdapterSettings('unit','wazuh_json_v1','unit-test',
        semantic_profile='wazuh_local_v1',network_namespace='unit-net',asset_namespace='unit-assets')
    first=with_raw(alert('unit-connection',10 if reverse else 0,namespace='unit',source_type='suricata',
        src_ip='192.0.2.10',dst_ip='192.0.2.20',dst_port=4444),{'flow_id':1234})
    second=WazuhAdapter(cfg,setting).convert(dict(timestamp='2022-01-01T00:00:01Z',id='unit-receive',
        rule=dict(id='unit',description='synthetic receive observation',level=8),
        agent=dict(id='unit-agent',name='unit-host',ip='192.0.2.20'),
        data=dict(flow_id=1234,action='receive')))
    idx,_=inputs([first,second],{'unit':setting})
    return idx,idx.alerts[first.alert_id],idx.alerts[second.alert_id]

def test_d1_matching_connection_receive_direction(policy):
    idx,a,b=flow_pair();r=decide(a,b,idx,policy)
    assert r['status']=='DERIVED_VERIFIED_DIRECTION' and r['source_alert_id']==a.alert_id
    assert r['direction_confidence']==.9 and len(r['forward_evidence'])==2
    DirectionEvidence.model_validate(r)

def test_d2_same_entity_time_only_is_ambiguous(policy):
    idx,_=inputs([alert('time-a',host='h'),alert('time-b',1,host='h')]);a,b=idx.alerts.values()
    assert decide(a,b,idx,policy)['status']=='AMBIGUOUS_DIRECTION'

def test_d3_two_forward_channels_survive_endpoint_order_swap(policy):
    idx,a,b=flow_pair()
    r=decide(b,a,idx,policy)
    assert r['source_alert_id']==a.alert_id and r['reverse_support']==.9 and not r['forward_support']

def test_d4_conflicting_field_proofs_are_ambiguous(policy):
    idx,a,b=flow_pair()
    relation=dict(source_alert_id=b.alert_id,target_alert_id=a.alert_id,source_entity_id=a.entity_ids[0],
        target_entity_id=b.entity_ids[0],raw_pointers=[dict(alert_id=b.alert_id,pointer='/data/flow_id',side='src')])
    r=decide(a,b,idx,policy,explicit_relations=[relation])
    assert r['status']=='AMBIGUOUS_DIRECTION' and r['contradiction']

def test_d5_reverse_chronology_rejects_forward_proof(policy):
    idx,a,b=flow_pair(reverse=True);r=decide(a,b,idx,policy)
    assert r['source_alert_id'] is None and r['rejection_reason']=='explicit_reverse_chronology'

def test_one_directional_channel_cannot_pass(policy):
    idx,a,b=flow_pair();b=with_raw(b,{'data':{'flow_id':9999,'action':'receive'}})
    idx,_=inputs([a,b]);a,b=idx.alerts.values()
    assert decide(a,b,idx,policy)['status']=='AMBIGUOUS_DIRECTION'

def test_hard_guard_duplicate_and_penalty_protection(policy):
    b=base({'asset':.2});b['gate']['passed']=False;b['gate']['duplicate_observation']=True
    assert aggregate(b,b['group_support'],synthetic_transition(),policy)['final_score']==0
    b=base({'asset':.2});b['conflict_penalty']=.45
    assert aggregate(b,b['group_support'],synthetic_transition(),policy)['final_score']<.3
    idx,a,b=flow_pair()
    assert decide(a,b,idx,policy,hard=True)['source_alert_id'] is None

def test_ip_literal_domain_alias_not_independent_resource(policy):
    aa=[alert('alias-a',src_ip='192.0.2.1',dst_ip='192.0.2.2',domain='192.0.2.2'),
        alert('alias-b',1,src_ip='192.0.2.1',dst_ip='192.0.2.2',domain='192.0.2.2')]
    idx,_=inputs(aa)
    assert alias_groups({'asset':.3,'resource':.2},*aa,idx)=={'asset':.3}

def test_false_file_name_does_not_infer_credential_theft(policy):
    from app.correlation.separation_direction.evidence import behavior
    a=alert('resource-path',file='/tmp/credentials/secret',host='h')
    assert 'resource_access' not in behavior(a,policy)

def test_pair_schema_recomputation_tamper_and_roundtrip(policy):
    idx,_=inputs([alert('schema-a'),alert('schema-b',1)]);a,b=idx.alerts.values()
    baseline=base({'asset':.2});r=aggregate(baseline,baseline['group_support'],None,policy)
    data=dict(support_pair=[a.alert_id,b.alert_id],support_key=sorted(idx.alerts),baseline_score=.2,valid=True,
        baseline=baseline,policy_hash=content_digest(policy),groups=baseline['group_support'],transition=None,
        score_breakdown={**r,'policy':policy},score=r['final_score'],direction=decide(a,b,idx,policy))
    obj=PairResult.model_validate(data)
    assert PairResult.model_validate_json(obj.model_dump_json())==obj
    bad=deepcopy(data);bad['score']=.8
    with pytest.raises(ValueError):PairResult.model_validate(bad)
    assert id_for('CorrelationEdge',dict(source_alert_id=min(idx.alerts),target_alert_id=max(idx.alerts)))==id_for(
        'CorrelationEdge',dict(source_alert_id=max(idx.alerts),target_alert_id=min(idx.alerts)))

@pytest.mark.parametrize('change',[{'unexpected':1},{'direction_support':1.1},{'direction_margin':float('nan')},
    {'wazuh_fields':{'execution_type':'/ground_truth'}}])
def test_policy_fail_fast(policy,change):
    with pytest.raises(ValueError):Policy.model_validate({**policy,**change})


def test_account_pivot_graph_grounding_and_determinism(policy):
    from app.adapters.wazuh import WazuhAdapter
    from app.adapters.base import AdapterSettings
    from app.correlation.scoring import CorrelationScorer
    from app.correlation.separation_direction.models import CandidateCorrelationEdge
    from app.correlation.separation_direction.graph import reconstruct
    cfg=load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml',deployment_override=ROOT/'configs/sources.yaml')
    s=AdapterSettings('unit','wazuh_json_v1','unit-test',semantic_profile='wazuh_local_v1',
        network_namespace='unit-net',asset_namespace='unit-assets',account_realm='unit-realm')
    adapter=WazuhAdapter(cfg,s)
    def raw(name,ip,stamp,data,groups):
        return dict(timestamp=stamp,id=name,agent=dict(id=name,name=name,ip=ip),
            rule=dict(id='unit',description='synthetic observation',groups=groups,level=8),data=data)
    a=adapter.convert(raw('synthetic-source-host','192.0.2.10','2022-01-01T00:00:00Z',
        dict(audit=dict(auid='actor',operation='read',file='/unit/resource',type='SYSCALL',exe='/bin/cat'),target_user='user'),['audit']))
    b=adapter.convert(raw('synthetic-target-host','192.0.2.20','2022-01-01T00:00:03Z',
        dict(dstuser='user',srcip='192.0.2.10',status='success'),['authentication']))
    idx,_=inputs([a,b],{'unit':s});a,b=[idx.alerts[i.alert_id] for i in (a,b)]
    d=decide(a,b,idx,policy)
    assert d['source_alert_id']==a.alert_id and len(d['forward_evidence'])==2
    baseline=base({'asset':.6,'entity.ACCOUNT':.5},False);calc=aggregate(baseline,baseline['group_support'],None,policy)
    obj=PairResult.model_validate(dict(support_pair=[a.alert_id,b.alert_id],support_key=sorted(idx.alerts),
        baseline_score=.8,valid=True,baseline=baseline,policy_hash=content_digest(policy),groups=baseline['group_support'],
        transition=None,score_breakdown={**calc,'policy':policy},score=calc['final_score'],direction=d))
    data=dict(source_alert_id=min(idx.alerts),target_alert_id=max(idx.alerts),score=obj.score,support=obj)
    data['edge_id']=id_for('CorrelationEdge',data);edge=CandidateCorrelationEdge.model_validate(data)
    scorer=CorrelationScorer(idx,cfg,{'unit':s})
    one=reconstruct(idx,[edge],scorer,policy)
    two=reconstruct(idx,list(reversed([edge])),scorer,policy)
    assert one==two and len(one[2])==1 and one[2][0]['relation_type']=='ACCOUNT_PIVOT'
    assert set(one[2][0]['alert_ids'])==set(idx.alerts)
    assert one[2][0]['direction_confidence']!=one[2][0]['correlation_score']
    assert len({aid for n in one[1] for aid in n.alert_ids})==2


def test_hot_specificity_blocks_transition_promotion(policy):
    from app.correlation.index import AlertIndex
    aa=[alert('hot-'+str(i),i,category='web_attack' if i==0 else 'process_execution',host='hot-host') for i in range(105)]
    idx,settings=inputs(aa);cfg=load_config(ROOT/'configs/algorithm-v0.yaml')
    assert transition(idx.alerts[aa[0].alert_id],idx.alerts[aa[1].alert_id],idx,settings,policy,cfg.algorithm.entity) is None
