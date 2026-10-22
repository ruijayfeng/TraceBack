"""Synthetic counterexamples for ⑥; no fixture is an ATTACK125 record."""
from collections import Counter
from dataclasses import replace

import pytest

from app.stages import aggregate_stages, StageResult
from test_community_builder import cfg, normalization, record
from test_stage_aggregation import policy, stage_run


def flow(**kw):
    return dict(client_ip='192.0.2.10', server_ip='192.0.2.20', client_port=43210,
                server_port=443, protocol='TCP', **kw)


def action(i, source='edr', **kw):
    fields = dict(hostname='synthetic-host', process_id=700,
        process_start_time='2026-01-01T00:00:00Z',
        command_line='sh /tmp/synthetic-job.sh', file_path='/tmp/synthetic-job.sh', **kw)
    if source == 'host_audit':
        for old,new in [('hostname','host'),('process_id','pid'),('command_line','command')]:
            fields[new]=fields.pop(old)
    return record(i, source, **fields)


def test_cross_source_same_process_action_keeps_annotations(cfg, normalization, policy):
    rows = [action('s1', operation='ProcessStart'),
            action('s2', 'host_audit', operation='FileRead', time=2)]
    community, result = stage_run(rows, cfg, normalization, policy)
    assert len(result.stages) == 1
    assert result.stages[0].behavior == 'EXECUTION'
    assert {b.behavior for b in result.behaviors} == {'EXECUTION', 'FILE_ACTIVITY'}
    assert StageResult.model_validate_json(result.model_dump_json()) == result
    assert Counter(i for s in result.stages for i in s.alert_ids) == Counter(a.alert_id for a in community.alerts)


def test_optional_action_field_missing_with_instance_and_command(cfg, normalization, policy):
    first = action('s1', operation='ProcessStart')
    second = action('s2', operation='FileRead', time=1)
    second.pop('file_path')
    _, result = stage_run([first,second], cfg, normalization, policy)
    assert len(result.stages) == 1


def test_observed_request_series_url_is_not_action_identity(cfg, normalization, policy):
    rows = [record(i, 'waf', time=i*10, rule_name='Synthetic probing observation',
                   uri='/synthetic/'+str(i), **flow()) for i in range(4)]
    _, result = stage_run(rows,cfg,normalization,policy)
    assert len(result.stages) == 1


def test_missing_query_is_a_partial_url_observation(cfg, normalization, policy):
    rows=[record(1,'waf',uri='/synthetic/upload',**flow()),
          record(2,'waf',uri='/synthetic/upload?file=sample',**flow())]
    _,result=stage_run(rows,cfg,normalization,policy)
    assert len(result.stages)==1


def test_identity_and_action_proof_uses_existing_stage_horizon(cfg, normalization, policy):
    rows=[action(i, time=i*25, operation='FileRead' if i%2 else 'ProcessStart') for i in range(9)]
    _,result=stage_run(rows,cfg,normalization,policy)
    assert len(result.stages)==1
    assert any(e.temporal_check.get('policy')=='bound_action_horizon' for e in result.stages[0].aggregation_basis)


@pytest.mark.parametrize('change',[
    dict(request_id='different'),dict(application_session_id='different'),dict(client_port=12345),
    dict(uri='/other',rule_name='Different synthetic action'),
])
def test_request_series_keeps_explicit_conflicts(cfg,normalization,policy,change):
    first=record(1,'waf',uri='/synthetic',rule_name='Synthetic action',request_id='r',application_session_id='s',**flow())
    _,result=stage_run([first,dict(first,event_id='2',**change)],cfg,normalization,policy)
    assert len(result.stages)==2


@pytest.mark.parametrize('change',[
    dict(process_id=701),dict(command_line='different'),dict(file_path='/other'),
    dict(hostname='other-host'),dict(user='other'),
])
def test_mixed_observations_cannot_override_action_conflicts(cfg,normalization,policy,change):
    first=action(1,operation='ProcessStart',user='alice')
    second=dict(first,event_id='2',operation='FileRead',**change)
    _,result=stage_run([first,second],cfg,normalization,policy)
    assert len(result.stages)==2


def test_same_host_time_and_generic_semantics_without_action_proof(cfg,normalization,policy):
    rows=[record(1,hostname='same',user='alice',operation='ProcessStart'),
          record(2,hostname='same',user='alice',operation='FileRead')]
    _,result=stage_run(rows,cfg,normalization,policy)
    assert len(result.stages)==2


def test_sparse_process_cannot_absorb_specific_attack_label(cfg,normalization,policy):
    rows=[action(1,operation='ProcessStart'),action(2,operation='FileRead'),
          action(3,operation='FileRead',behavior='PERSISTENCE')]
    community,result=stage_run(rows,cfg,normalization,policy)
    # Preserve behavior annotations supplied by ④; use a specific valid annotation
    # to isolate ⑥'s semantic gate from mapping precedence.
    annotations=list(community.behaviors)
    third=next(a.alert_id for a in community.alerts if a.raw_alert['event_id']=='3')
    annotations=[b.model_copy(update={'behavior':'PERSISTENCE'}) if b.alert_id==third else b for b in annotations]
    source=replace(community,behaviors=annotations)
    from test_source_bound_projection import settings
    result=aggregate_stages(source,{a.source_namespace:settings(a.raw_alert['source_type']) for a in source.alerts},cfg,policy)
    assert sorted(s.alert_count for s in result.stages)==[1,2]


def test_reordered_synthetic_observations_and_singletons(cfg,normalization,policy):
    rows=[action(i,time=i,operation='ProcessStart' if i%2 else 'FileRead') for i in range(6)]
    community,result=stage_run(rows,cfg,normalization,policy)
    _,reverse=stage_run(rows[::-1],cfg,normalization,policy)
    assert result==reverse
    assert len(result.stages)==1
    _,single=stage_run(rows[:1],cfg,normalization,policy)
    assert single.stages[0].alert_count==1


def test_same_request_disagreeing_paths_still_conflict(cfg,normalization,policy):
    first=record(1,'waf',uri='/synthetic/one',rule_name='Same detector',request_id='r',**flow())
    _,result=stage_run([first,dict(first,event_id='2',uri='/synthetic/two')],cfg,normalization,policy)
    assert len(result.stages)==2


def test_bound_action_horizon_is_bounded(cfg,normalization,policy):
    _,result=stage_run([action(1,operation='ProcessStart'),
                       action(2,operation='FileRead',time=121)],cfg,normalization,policy)
    assert len(result.stages)==2


def test_generic_transport_and_application_observations_need_full_tuple(cfg,normalization,policy):
    transport=record(1,'firewall',src_ip='192.0.2.10',dst_ip='192.0.2.20',
        src_port=43210,dst_port=443,protocol='TCP',action='allow')
    application=record(2,'waf',uri='/synthetic/poll',time=2,**flow())
    _,result=stage_run([transport,application],cfg,normalization,policy)
    assert len(result.stages)==1
    application.pop('client_port')
    _,result=stage_run([transport,application],cfg,normalization,policy)
    assert len(result.stages)==2
