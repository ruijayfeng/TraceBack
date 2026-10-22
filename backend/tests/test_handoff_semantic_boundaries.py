"""Unlabelled synthetic scene/identity boundaries through the formal handoff."""
from collections import Counter
import pytest

from app.community.evidence import evidence_tier
from app.services.alert_pipeline import prepare_alerts
from app.services.stage_pipeline import prepare_stage_pipeline
from test_community_builder import normalization, record
from test_context_identity_handoff import extract, contract
from test_identity_projection import HOST


def formal(rows,normalization):
    policies={s:dict(host=HOST,contexts=[contract('request')]) for s in {r['source_type'] for r in rows}}
    bound,settings=extract(rows,normalization,policies)
    prepared=prepare_alerts(bound.alerts,source_settings=settings,entities=bound.entities,
                            identity_projection=bound.identity_projection)
    run=prepare_stage_pipeline(prepared)
    bound.identity_projection.validate_trace(bound.alerts,bound.entities)
    run.statistics
    for c in run.community.result.incident_candidates:
        for e in c.matching_evidence:
            for p in e.supporting_evidence:
                assert p.resolve({a.alert_id:a for a in bound.alerts}) is not None
    return run


def series(count,bridge_command=None):
    start='2025-12-31T23:00:00Z'
    rows=[record(i,time=i,hostname='worker',host_id='asset',process_id=7,process_start_time=start,
                 request_id=f'request-{i}',command_line=f'command-{i}',file_path=f'/tmp/item-{i}',operation='CommandExecution') for i in range(count)]
    rows.append(record('observer','host_audit',time=count+1,host='worker',host_id='asset',pid=7,
                       process_start_time=start,**({'command':bridge_command,'file_path':'/tmp/item-0','operation':'exec'} if bridge_command else {})))
    return rows


@pytest.mark.parametrize('count',[2,5])
def test_identity_only_observer_cannot_merge_independent_request_regions(normalization,count):
    run=formal(series(count),normalization)
    communities=run.community.result.incident_candidates
    assert sorted(c.member_count for c in communities)==[1]*(count-1)+[2]
    # Complete cross-source identity is retained for every observation even
    # though it cannot certify an unconditional merge of all scene regions.
    current=[{o.entity_id for o in a.entity_occurrences if o.role.value=='process'} for a in run.normalized.alerts]
    assert len(set.union(*current))==1 and all(current)
    decisions=[d for c in communities for d in c.membership_decisions]
    observer=next(a.alert_id for a in run.normalized.alerts if a.raw_alert['event_id']=='observer')
    assert next(d for d in decisions if d.alert_id==observer).action=='JOIN'
    assert not any(evidence_tier(e.identity_kind)=='A' and observer in e.alert_ids for c in communities for e in c.matching_evidence)


def test_action_corroboration_can_admit_without_absorbing_other_request(normalization):
    run=formal(series(2,'command-0'),normalization)
    assert sorted(c.member_count for c in run.community.result.incident_candidates)==[1,2]
    aa={a.alert_id:a for a in run.normalized.alerts}
    proof=[e for c in run.community.result.incident_candidates for e in c.matching_evidence
           if e.identity_kind=='cross_source_process_instance']
    assert len(proof)==1
    assert {aa[i].raw_alert['event_id'] for i in proof[0].alert_ids}=={'0','observer'}
    assert {'/command','/command_line','/file_path'}<={p.pointer for p in proof[0].supporting_evidence}


@pytest.mark.parametrize('partial_action',['command','file'])
def test_partial_action_does_not_upgrade_identity_to_merge_authority(normalization,partial_action):
    rows=series(2)
    for row in rows[:2]: row['command_line']='server worker'
    if partial_action=='command': rows[-1]['command']='server worker'
    else: rows[-1]['file_path']='/tmp/item-0'
    run=formal(rows,normalization)
    assert sorted(c.member_count for c in run.community.result.incident_candidates)==[1,2]
    assert all(e.identity_kind!='cross_source_process_instance' for c in run.community.result.incident_candidates
               for e in c.matching_evidence)


def test_valid_process_identity_and_observed_action_boundary_coexist(normalization):
    rows=series(1,'a different command')
    run=formal(rows,normalization)
    assert sorted(c.member_count for c in run.community.result.incident_candidates)==[2]
    assert len(run.stages.stages)==2
    assert len({o.entity_id for a in run.normalized.alerts for o in a.entity_occurrences if o.role.value=='process'})==1
    assert any(d.relation_type=='UNDIRECTED_EDGE' for d in run.evidence_result.decisions)
    assert Counter(i for s in run.stages.stages for i in s.alert_ids)==Counter(a.alert_id for a in run.normalized.alerts)


def test_frozen_stage6_cannot_certify_phase_equality_from_process_and_command(normalization):
    fields=dict(hostname='worker',host_id='asset',process_id=7,process_start_time='2025-12-31T23:00:00Z',command_line='runner')
    rows=[record(1,operation='ProcessStart',**fields),record(2,time=5,operation='NetworkConnection',
        src_ip='192.0.2.1',src_port=1234,dst_ip='192.0.2.2',dst_port=443,protocol='TCP',**fields)]
    run=formal(rows,normalization)
    # No real stage labels are supplied; the original safety assertion stands.
    assert len(run.stages.stages)==2
