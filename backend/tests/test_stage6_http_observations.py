"""Synthetic HTTP boundary cases motivated by the independent GT-S02 audit."""
from collections import Counter
from dataclasses import replace

import pytest
from pydantic import ValidationError

from app.stages import aggregate_stages,StageResult
from test_community_builder import cfg,normalization,record
from test_stage_aggregation import policy,stage_run
from test_source_bound_projection import settings


def ids(i,tx=1,time=0,path='/synthetic/search'):
    return record(i,'ids',time=time,event_type='alert',src_ip='192.0.2.10',dest_ip='192.0.2.20',
        src_port=43210,dest_port=443,proto='TCP',flow_id=123,tx_id=tx,
        alert=dict(signature='Synthetic generic HTTP detector',signature_id=991,severity=2),
        http=dict(url=path,http_method='GET',hostname='example.test'))


def waf(i,tx=1,time=0,path='/synthetic/search',query='q=sample',**extra):
    row=record(i,'waf',time=time,client_ip='192.0.2.10',server_ip='192.0.2.20',
        client_port=43210,server_port=443,protocol='TCP',flow_id=123,tx_id=tx,
        uri=path,query=query,method='GET',host='example.test',
        request_id='synthetic-request-'+str(i),rule_id='942100',rule_name='SQL injection pattern')
    row.update(extra);return row


def native_members(source,result):
    aa={a.alert_id:a for a in source.alerts}
    return sorted(sorted(aa[i].raw_alert['event_id'] for i in s.alert_ids) for s in result.stages)


def test_exact_http_observation_retains_specific_and_unknown_annotations(cfg,normalization,policy):
    source,result=stage_run([ids('ids'),waf('waf')],cfg,normalization,policy)
    assert native_members(source,result)==[['ids','waf']]
    assert result.stages[0].behavior=='WEB_EXPLOIT'
    assert {b.behavior for b in result.behaviors}=={'UNKNOWN','WEB_EXPLOIT'}
    assert any('http_transaction' in e.evidence_types for e in result.stages[0].aggregation_basis)
    assert StageResult.model_validate_json(result.model_dump_json())==result
    assert Counter(i for s in result.stages for i in s.alert_ids)==Counter(a.alert_id for a in source.alerts)


def test_repeated_request_ids_are_not_different_application_actions(cfg,normalization,policy):
    rows=[waf(i,tx=i+1,time=i*10) for i in range(3)]
    source,result=stage_run(rows,cfg,normalization,policy)
    assert len(result.stages)==1
    assert len(result.stages[0].request_bindings)==3
    assert any('http_activity' in e.evidence_types for e in result.stages[0].aggregation_basis)


def test_precise_http_edges_precede_coarse_flow_series(cfg,normalization,policy):
    rows=[ids('a',tx=1),waf('b',tx=1),
          ids('c',tx=2,time=10,path='/synthetic/download'),
          waf('d',tx=2,time=10,path='/synthetic/download',query='file=sample',rule_name='Path traversal',rule_id='930100')]
    source,result=stage_run(rows,cfg,normalization,policy)
    assert native_members(source,result)==[['a','b'],['c','d']]
    _,reverse=stage_run(rows[::-1],cfg,normalization,policy)
    assert result==reverse


@pytest.mark.parametrize('change',[
    dict(query='q=different'),dict(method='POST'),dict(rule_name='Different detector',rule_id='different'),
    dict(client_port=43211),dict(application_session_id='different'),
])
def test_repeated_request_rule_keeps_real_action_and_session_conflicts(cfg,normalization,policy,change):
    first=waf(1,application_session_id='same')
    second=waf(2,tx=2,time=5,application_session_id='same');second.update(change)
    _,result=stage_run([first,second],cfg,normalization,policy)
    assert len(result.stages)==2


@pytest.mark.parametrize('change',[
    dict(tx_id=2),dict(tx_id=None),dict(client_port=43211),dict(uri='/different'),
    dict(timestamp='2026-01-01T00:00:01+00:00'),dict(method='POST'),
])
def test_tx_token_or_url_alone_cannot_align_observations(cfg,normalization,policy,change):
    second=waf(2);second.update(change)
    _,result=stage_run([ids(1),second],cfg,normalization,policy)
    assert len(result.stages)==2


def test_specific_semantic_conflict_survives_unknown_http_bridge(cfg,normalization,policy):
    rows=[ids('i'),waf('a'),waf('b')]
    source,_=stage_run(rows,cfg,normalization,policy)
    target=next(a.alert_id for a in source.alerts if a.raw_alert['event_id']=='b')
    source=replace(source,behaviors=[b.model_copy(update=dict(behavior='PERSISTENCE')) if b.alert_id==target else b for b in source.behaviors])
    result=aggregate_stages(source,{a.source_namespace:settings(a.raw_alert['source_type']) for a in source.alerts},cfg,policy)
    assert native_members(source,result)==[['a','i'],['b']]


def test_sparse_observation_does_not_erase_query_conflict(cfg,normalization,policy):
    # One IDS observation must not bridge two incompatible fully observed queries.
    rows=[ids('i'),waf('a'),waf('b',query='q=different')]
    source,result=stage_run(rows,cfg,normalization,policy)
    assert len(result.stages)==2
    assert not any({'a','b'}<=set(g) for g in native_members(source,result))


def test_http_proof_keeps_all_raw_witnesses(cfg,normalization,policy):
    source,result=stage_run([ids('i'),waf('w')],cfg,normalization,policy)
    assert len(result.stages)==1
    edge=result.stages[0].aggregation_basis[0]
    aa={a.alert_id:a for a in source.alerts}
    refs={i:{p.pointer for p in edge.evidence if p.alert_id==i} for i in edge.alert_ids}
    for aid in edge.alert_ids:
        assert '/tx_id' in refs[aid]
        assert any('method' in p for p in refs[aid])
    assert any('/query' in p for pp in refs.values() for p in pp)
    for pointer in edge.evidence: assert pointer.resolve(aa) is not None
    tampered=result.model_dump()
    for e in tampered['stages'][0]['aggregation_basis']: e['evidence_types']=['flow']
    with pytest.raises(ValidationError,match='stage_annotation'):
        StageResult.model_validate(tampered)


@pytest.mark.parametrize('token',[-1,'unknown',True])
def test_placeholder_transaction_ids_are_not_positive_proof(cfg,normalization,policy,token):
    _,result=stage_run([ids(1,tx=token),waf(2,tx=token)],cfg,normalization,policy)
    assert len(result.stages)==2


def test_non_text_http_method_cannot_relax_request_conflicts(cfg,normalization,policy):
    _,result=stage_run([waf(1,method=7),waf(2,tx=2,time=5,method=7)],cfg,normalization,policy)
    assert len(result.stages)==2
