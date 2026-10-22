"""Evidence tier, containment, identity, scale and production isolation checks."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import builtins
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.adapters.multisource import MultiSourceAdapter
from app.community import load_community_config, prepare_communities, IncidentCandidate
from app.config import load_config
from test_source_bound_projection import settings

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def cfg():
    return load_community_config(ROOT/'configs/community-v1.yaml')


@pytest.fixture(scope='module')
def normalization():
    return load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml',
                       deployment_override=ROOT/'configs/front-data-sources.yaml')


def record(i, source='edr', time=0, **fields):
    t = datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(seconds=time)
    return dict(timestamp=t.isoformat(), source_type=source, event_id=str(i), **fields)


def run(raws, cfg, normalization, overrides=None, *, behavior_config=None, resolver=None):
    ss = {s: replace(settings(s), **(overrides or {}).get(s, {})) for s in {r['source_type'] for r in raws}}
    aa = [MultiSourceAdapter(normalization, ss[r['source_type']], r['source_type']).convert(r) for r in raws]
    return prepare_communities(aa, {s.source_namespace:s for s in ss.values()}, cfg,
                               behavior_config=behavior_config, resolver=resolver)


def sizes(r):
    return sorted(c.member_count for c in r.result.incident_candidates)


@pytest.mark.parametrize('field', ['request_id', 'session_id', 'trace_id', 'correlation_id', 'transaction_id'])
def test_direct_binding(cfg, normalization, field):
    r = run([record(1, **{field:'same'}), record(2, time=5, **{field:'same'})],cfg,normalization)
    assert sizes(r) == [2]
    c = r.result.incident_candidates[0]
    assert c.matching_evidence[0].match_level == 1
    for e in c.matching_evidence:
        for p in e.supporting_evidence:
            assert p.resolve({a.alert_id:a for a in r.alerts}) is not None
    assert IncidentCandidate.model_validate_json(c.model_dump_json()) == c


def test_direct_native_reference_and_no_wrapper_dependency(cfg, normalization):
    assert sizes(run([record('native'), record('second', parent_event_id='native')],cfg,normalization)) == [2]
    # Record IDs that merely coincide do not themselves create a binding.
    assert sizes(run([record('same'), record('same',time=1)],cfg,normalization)) == [1,1]


def test_context_scopes_and_typed_ids_do_not_collide(cfg, normalization):
    r = run([record(1,flow_id='x'),record(2,connection_id='x')],cfg,normalization)
    assert sizes(r) == [1,1]
    r = run([record(1,'waf',request_id='x'),record(2,request_id='x')],cfg,normalization)
    assert sizes(r) == [1,1]
    r = run([record(1,'waf',request_id='x'),record(2,request_id='x')],cfg,normalization,
            {s:dict(session_scope='declared-shared') for s in ('waf','edr')})
    assert sizes(r) == [2]


def test_strong_process_and_parent_lineage_but_no_siblings(cfg, normalization):
    a=record(1,hostname='h',process_id=12,process_start_time='2025-12-31T23:59:00Z')
    assert sizes(run([a,dict(a,event_id='2')],cfg,normalization)) == [2]
    child=record(2,hostname='h',process_id=13,process_start_time='2026-01-01T00:00:00Z',
                 parent_process_id=12,parent_process_start_time='2025-12-31T23:59:00Z')
    assert sizes(run([a,child],cfg,normalization)) == [2]
    sibling=dict(child,event_id='3',process_id=14)
    assert sizes(run([child,sibling],cfg,normalization)) == [1,1]
    assert sizes(run([a,dict(a,event_id='2',process_start_time='2025-12-31T23:58:00Z')],cfg,normalization)) == [1,1]
    assert sizes(run([a,dict(a,event_id='2',hostname='other')],cfg,normalization)) == [1,1]


def test_host_process_combination_requires_identity_and_context(cfg, normalization):
    a=record(1,hostname='h',process_id=7,process_name='worker',user='Alice')
    r=run([a,dict(a,event_id='2')],cfg,normalization)
    assert sizes(r) == [2]
    assert r.result.incident_candidates[0].matching_evidence[0].match_level == 3
    evidence=r.result.incident_candidates[0].matching_evidence[0]
    assert any(p.pointer=='/user' for p in evidence.supporting_evidence)
    assert sizes(run([a,dict(a,event_id='2',process_id=8)],cfg,normalization)) == [1,1]
    names=[record(i,hostname='h',process_name='powershell.exe') for i in range(4)]
    assert sizes(run(names,cfg,normalization)) == [1]*4


def test_host_account_with_operation_continuity_and_distinct_sessions(cfg, normalization):
    a=record(1,'authentication',host='h',account='Alice',service='sshd',operation='login')
    r=run([a,dict(a,event_id='2')],cfg,normalization)
    assert sizes(r) == [2]
    assert r.result.incident_candidates[0].matching_evidence[0].match_reason == 'HOST_ACCOUNT_CONTINUITY'
    assert sizes(run([dict(a,session_id='s1'),dict(a,event_id='2',session_id='s2')],cfg,normalization)) == [1,1]
    # Host + Account is now an explicit two-factor context rule.
    assert sizes(run([record(1,hostname='h',user='Alice'),record(2,hostname='h',user='Alice')],cfg,normalization)) == [2]


def test_time_severity_signature_port_source_and_ip_cannot_group(cfg, normalization):
    sparse=[record(i,time=i,src_ip='192.0.2.1',dst_port=443,severity='high',process_name='bash') for i in range(50)]
    assert sizes(run(sparse,cfg,normalization)) == [1]*50


def test_host_and_semantic_continuity_require_independent_context(cfg, normalization):
    a=record(1,'waf',server_host='h',rule_id='942100',rule_name='SQL injection pattern')
    # Known mapped category supplied via the existing source mapping, not an inferred stage.
    r=run([a,dict(a,event_id='2')],cfg,normalization)
    assert r.alerts[0].category.value == 'web_attack'
    assert sizes(r) == [1, 1]
    assert r.result.statistics['rejection_counts']['HOST_REQUIRES_INDEPENDENT_CONTEXT'] > 0
    assert sizes(run([a,dict(a,event_id='2',timestamp='2026-01-01T02:00:00Z')],cfg,normalization)) == [1,1]


def test_complete_flow_uses_five_tuple_without_inferred_roles(cfg, normalization):
    a=record(1,'firewall',src_ip='192.0.2.1',dst_ip='192.0.2.2',src_port=1234,dst_port=443,
             protocol='TCP',direction='inbound',source_role='client',destination_role='service')
    r=run([a,dict(a,event_id='2')],cfg,normalization)
    assert sizes(r) == [2]
    assert r.result.incident_candidates[0].matching_evidence[0].match_level == 1
    assert r.result.incident_candidates[0].matching_evidence[0].identity_kind == 'flow'
    assert sizes(run([{k:v for k,v in a.items() if k!='source_role'},
                  {k:v for k,v in dict(a,event_id='2').items() if k!='source_role'}],cfg,normalization)) == [2]
    assert sizes(run([a,dict(a,event_id='2',direction='outbound')],cfg,normalization)) == [2]
    assert sizes(run([a,dict(a,event_id='2',dst_port=80)],cfg,normalization)) == [1,1]


def test_task_and_object_handoff(cfg, normalization):
    assert sizes(run([record(1,task_id='task'),record(2,task_id='task')],cfg,normalization)) == [2]
    assert sizes(run([record(1,hostname='h',response_object_id='obj'),
                      record(2,hostname='h',request_object_id='obj')],cfg,normalization)) == [2]
    assert sizes(run([record(1,hostname='h',file_hash='common'),
                      record(2,hostname='h',file_hash='common')],cfg,normalization)) == [1,1]


def test_strong_bridge_merges_existing_groups(cfg, normalization):
    rows=[record(1,time=0,request_id='r'),record(2,time=1,request_id='r'),
          record(3,time=2,task_id='f'),record(4,time=3,task_id='f'),
          record(5,time=4,request_id='r',task_id='f')]
    r=run(rows,cfg,normalization)
    assert sizes(r) == [5] and r.result.statistics['merge_operations'] == 1
    assert r.result.incident_candidates[0].membership_decisions[-1].action == 'MERGE'
    assert len(r.result.incident_candidates[0].matching_evidence) == 4


def test_weak_bridge_cannot_union_existing_communities(cfg, normalization):
    rows=[record(1,time=0,hostname='h1',user='Alice',service='svc',operation='op'),
          record(2,time=1,hostname='h2',user='Alice',service='svc',operation='op'),
          record(3,time=2,hostname='h1',user='Alice',service='svc',operation='op')]
    assert sizes(run(rows,cfg,normalization)) == [1,2]
    rows=[record(1,time=0,hostname='h',user='Alice',session_id='s1',service='svc',operation='op'),
          record(2,time=1,hostname='h',user='Alice',session_id='s1',service='svc',operation='op'),
          record(3,time=2,hostname='h',user='Alice',session_id='s2',service='svc',operation='op'),
          record(4,time=3,hostname='h',user='Alice',session_id='s2',service='svc',operation='op'),
          record(5,time=4,hostname='h',user='Alice',service='svc',operation='op')]
    result=run(rows,cfg,normalization)
    assert sizes(result) == [2,3]
    assert result.result.statistics['rejection_counts']['WEAK_EVIDENCE_CANNOT_MERGE'] > 0


@pytest.mark.parametrize('source',['ids','waf','edr','firewall','authentication','host_audit'])
def test_all_six_sources_enter_same_public_builder(source,cfg,normalization):
    from test_source_bound_projection import body
    a=body(source)
    r=run([a,dict(a,event_id='different-native-record',timestamp='2026-01-01T00:00:01Z')],cfg,normalization)
    assert sum(sizes(r)) == 2
    assert all(c.member_count >= 1 for c in r.result.incident_candidates)


def test_hard_negative_shape_rejects_close_shared_background_fields(cfg,normalization):
    attack=record(1,hostname='host',user='Alice',session_id='activity',process_name='bash',
                  process_id=12,process_start_time='2026-01-01T00:00:00Z',src_ip='192.0.2.1',dst_port=443)
    unrelated=record(2,time=1,hostname='host',user='Alice',session_id='different-session',process_name='bash',
                     process_id=13,process_start_time='2026-01-01T00:00:01Z',src_ip='192.0.2.1',dst_port=443)
    r=run([attack,unrelated],cfg,normalization)
    assert sizes(r) == [1,1]
    assert r.result.statistics['rejection_counts']['DISTINCT_CONTEXTS_BLOCK_WEAK_MATCH'] > 0


def test_caps_and_lifetime_override_shared_strong_id(cfg, normalization):
    small=cfg.model_copy(update=dict(max_community_members=3,max_weak_members=3))
    rows=[record(i,time=i,request_id='r') for i in range(8)]
    r=run(rows,small,normalization)
    assert max(sizes(r)) == 3 and sum(sizes(r)) == 8
    assert sizes(run([record(1,request_id='r'),record(2,time=4000,request_id='r')],cfg,normalization)) == [1,1]


def test_determinism_duplicates_and_input_not_mutated(cfg, normalization):
    rows=[record(i,time=i,request_id=str(i%2)) for i in range(20)]
    first=run(rows,cfg,normalization)
    second=run(list(reversed(rows)),cfg,normalization)
    assert first.result == second.result
    duplicate=run(rows+rows,cfg,normalization)
    assert duplicate.result.incident_candidates == first.result.incident_candidates
    assert duplicate.result.statistics['duplicate_imports'] == 20
    assert sum(sizes(first)) == len(rows)


def test_empty_singleton_and_schema_rejects_invented_fields(cfg, normalization):
    r=prepare_communities([],{},cfg)
    assert not r.result.incident_candidates
    r=run([record(1)],cfg,normalization)
    c=r.result.incident_candidates[0]
    assert not c.matching_evidence and c.membership_decisions[0].action == 'CREATE'
    assert c.to_incident({a.alert_id:a for a in r.alerts}).alert_ids == c.alert_ids
    for changed in (dict(member_count=2),dict(community_id='com_'+'0'*64),dict(stage='fake')):
        with pytest.raises(ValidationError):
            IncidentCandidate.model_validate({**c.model_dump(),**changed})


def test_no_evaluation_scoring_chain_or_ai_imports(cfg, normalization, monkeypatch):
    original=builtins.__import__
    def guarded(name,*args,**kwargs):
        assert not name.startswith(('evaluation','app.correlation.scoring','app.chains','app.ai'))
        return original(name,*args,**kwargs)
    monkeypatch.setattr(builtins,'__import__',guarded)
    assert sizes(run([record(1,request_id='r'),record(2,request_id='r')],cfg,normalization)) == [2]
    with pytest.raises(ValueError,match='annotation_contamination'):
        run([record(1,label='ATTACK')],cfg,normalization)


def test_dense_key_policy_is_bounded(cfg, normalization):
    # A shared high-frequency key cannot turn indexed matching into all pairs.
    small=cfg.model_copy(update=dict(max_witnesses_per_key=4,max_candidates_per_alert=4))
    r=run([record(i,request_id='hot') for i in range(1000)],small,normalization)
    assert r.result.statistics['examined_index_witnesses'] < 5000
    assert r.result.statistics['policy_pruned_witnesses_or_neighbors'] > 0
    assert sum(sizes(r)) == 1000 and max(sizes(r)) <= small.max_community_members


def test_configuration_fail_fast(cfg):
    for change in (dict(windows_seconds={'1':1}),dict(max_weak_members=9999),dict(unknown=True),
                   dict(projections={'multisource_native_v1':{'object':['']}})):
        with pytest.raises(ValidationError):
            type(cfg).model_validate({**cfg.model_dump(),**change})
