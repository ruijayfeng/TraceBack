"""Authority declarations are synthetic; no labels, native IDs or GT fixtures."""
from dataclasses import replace
import pytest

from app.adapters.multisource import MultiSourceAdapter
from app.entities.extraction import extract_entities
from test_community_builder import normalization, record
from test_source_bound_projection import settings

HOST = dict(authority_domain='inventory', deployment_scope='test', network_scope='net',
            max_alias_age_seconds=60)
SESSION = dict(authority_domain='host-logons', deployment_scope='test', session_type='logon',
               token_pointer='/logon_id', start_operations=['session_open'],
               close_operations=['logout'], lifecycle_semantics='host_token_until_close')


def extract(rows, normalization, contracts=None):
    policies = contracts or {s:dict(host=HOST, auth_session=SESSION) for s in ('edr','authentication')}
    ss = {s:replace(settings(s), asset_namespace=None, account_realm=None, network_namespace=None,
                  identity_authorities=policies.get(s, {})) for s in {r['source_type'] for r in rows}}
    aa = [MultiSourceAdapter(normalization, ss[r['source_type']], r['source_type']).convert(r) for r in rows]
    return extract_entities(aa, {s.source_namespace:s for s in ss.values()}, contract='front-data-v1')


def ids(result, kind):
    return {e.entity_id for e in result.entities if e.type.value == kind}


def test_host_alias_positive_trace_and_order(normalization):
    rows=[record(1, hostname='h', host_id='asset'),record(2,time=-10,hostname='h')]
    r=extract(rows,normalization)
    assert len(ids(r,'HOST')) == 1
    b=r.identity_projection.host_alias_bindings[0]
    assert b.status=='BOUND' and b.canonical_host_entity_id in ids(r,'HOST')
    assert len(b.observations)==2
    r.identity_projection.validate_trace(r.alerts,r.entities)
    assert r==extract(rows[::-1],normalization)


def test_auth_session_cross_source_preserves_source_contexts(normalization):
    rows=[record(1,'authentication',host='h',host_id='asset',logon_id='X',operation='session_open'),
          record(2,hostname='h',host_id='asset',logon_id='X',operation='ProcessStart',time=10)]
    r=extract(rows,normalization)
    assert len(ids(r,'SESSION'))==1
    assert len(r.identity_projection.auth_session_bindings)==1
    b=r.identity_projection.auth_session_bindings[0]
    assert len(b.source_namespaces)==2
    for a in r.alerts:
        assert any(a.source_namespace in c.scope for o in b.observations if o.alert_id==a.alert_id for c in o.source_contexts)
        assert any('auth_session_projection' in c.scope for c in a.contexts)
        assert a.raw_alert==next(row for row in rows if row['event_id']==a.source_record_id)


@pytest.mark.parametrize('mode', ['ambiguous','no_authority','ip_only','scope','expired'])
def test_host_hard_negatives(normalization,mode):
    rows=[record(1,hostname='h',host_id='A',host_ip='192.0.2.1'),
          record(2,hostname='h',host_id='B',host_ip='192.0.2.1')]
    policies=None
    if mode=='no_authority': policies={'edr':{}}
    if mode=='ip_only': rows[1]['hostname']='other'
    if mode=='scope':
        rows[1].update(source_type='authentication',host='h')
        policies={'edr':dict(host=HOST),'authentication':dict(host={**HOST,'deployment_scope':'elsewhere'})}
    if mode=='expired': rows=[rows[0],record(3,hostname='h',time=121)]
    r=extract(rows,normalization,policies)
    assert len(ids(r,'HOST'))==2
    if mode=='ambiguous':
        assert any(b.status=='AMBIGUOUS_ALIAS' for b in r.identity_projection.host_alias_bindings)


@pytest.mark.parametrize('mode',['host','authority','close','epoch','account','undeclared'])
def test_session_hard_negatives(normalization,mode):
    rows=[record(1,'authentication',host='h',host_id='A',logon_id='X',operation='session_open',account='u'),
          record(2,hostname='h',host_id='A',logon_id='X',user='u',time=10)]
    policies={s:dict(host=HOST,auth_session=SESSION) for s in ('edr','authentication')}
    if mode=='host': rows[1]['host_id']='B'
    if mode=='authority': policies['edr']['auth_session']={**SESSION,'authority_domain':'other'}
    if mode=='undeclared': policies['edr'].pop('auth_session')
    if mode=='account': rows[1]['user']='other'
    if mode=='epoch': rows[0]['boot_id']='boot1';rows[1]['boot_id']='boot2'
    if mode=='close': rows.insert(1,record(3,'authentication',host='h',host_id='A',logon_id='X',operation='logout',time=5))
    r=extract(rows,normalization,policies)
    a,b=next(a for a in r.alerts if a.source_record_id=='1'),next(a for a in r.alerts if a.source_record_id=='2')
    assert {o.entity_id for o in a.entity_occurrences if o.role.value=='session'}.isdisjoint(
        {o.entity_id for o in b.entity_occurrences if o.role.value=='session'})


def test_pid_only_and_different_lifetimes_never_project(normalization):
    rows=[record(1,hostname='h',host_id='A',process_id=801),
          record(2,hostname='h',host_id='A',process_id=801,process_start_time='2025-12-31T23:00:00Z'),
          record(3,hostname='h',host_id='A',process_id=801,process_start_time='2026-01-01T01:00:00Z')]
    r=extract(rows,normalization)
    assert len(ids(r,'PROCESS'))==3
    assert not r.identity_projection.process_bindings
    assert 'PROCESS_PID_REUSE_RISK' in {d.code for d in r.identity_projection.diagnostics}
    assert 'PROCESS_LIFETIME_CONFLICT' in {d.code for d in r.identity_projection.diagnostics}


def test_alias_does_not_bridge_gaps_between_native_observations(normalization):
    r=extract([record(1,hostname='h',host_id='A'),record(2,hostname='h',time=150),
               record(3,hostname='h',host_id='A',time=300)],normalization)
    assert len(ids(r,'HOST'))==2


def test_conflicting_native_asset_fields_refuse_alias(normalization):
    r=extract([record(1,hostname='h',host_id='A',asset_id='B'),record(2,hostname='h')],normalization)
    assert len(ids(r,'HOST'))==2
    assert r.identity_projection.host_alias_bindings[0].status=='AMBIGUOUS_ALIAS'


def test_repeated_incomplete_pid_is_observation_local(normalization):
    r=extract([record(1,hostname='h',host_id='A',process_id=1),
               record(2,hostname='h',host_id='A',process_id=1)],normalization)
    assert len(ids(r,'PROCESS'))==2


def test_lifecycle_reuse_cannot_escape_via_original_contexts(normalization):
    from app.community import load_community_config
    from app.community.evidence import profile
    from test_community_builder import ROOT
    rows=[record(1,'authentication',host='h',host_id='A',logon_id='X',session_id='X',operation='session_open'),
          record(2,'authentication',host='h',host_id='A',logon_id='X',session_id='X',operation='logout',time=10),
          record(3,'authentication',host='h',host_id='A',logon_id='X',session_id='X',operation='session_open',time=20)]
    policies={'authentication':dict(host=HOST,auth_session={**SESSION,'equivalent_token_pointers':['/session_id']})}
    r=extract(rows,normalization,policies)
    ee={e.entity_id:e for e in r.entities}
    ss=replace(settings('authentication'),identity_authorities=policies['authentication'])
    cfg=load_community_config(ROOT/'configs/community-v1.yaml')
    pp={a.source_record_id:profile(a,ee,ss,cfg) for a in r.alerts}
    keys=lambda p:{b.key for b in p.bindings if b.kind=='session'}
    assert keys(pp['1']).isdisjoint(keys(pp['3']))
    archived=[c for b in r.identity_projection.auth_session_bindings for o in b.observations for c in o.source_contexts]
    assert len(archived)==6


def test_projection_evidence_survives_noise_archive(normalization):
    from app.services.alert_pipeline import prepare_alerts
    from app.noise_filter import NoiseFilterConfig
    rows=[record(1,hostname='h',host_id='A',operation='inventory'),record(2,hostname='h',operation='activity',time=10)]
    r=extract(rows,normalization)
    policy=NoiseFilterConfig.model_validate(dict(background_rules=[dict(rule_id='inventory-noise',
        match=dict(source_type='edr',alert_type='inventory'))]))
    normalized=prepare_alerts(r.alerts,entities=r.entities,identity_projection=r.identity_projection,noise_config=policy)
    normalized.validate_handoff()
    assert normalized.noise_filter.statistics['REMOVED_ALERTS']==1
    assert normalized.identity_projection==r.identity_projection


def test_dangling_binding_rejected(normalization):
    r=extract([record(1,hostname='h',host_id='A')],normalization)
    a=r.alerts[0].model_copy(update=dict(identity_binding_ids=['missing']))
    with pytest.raises(ValueError,match='dangling_identity_binding'):
        r.identity_projection.validate_trace([a],r.entities)


def test_ambiguous_close_and_use_at_same_time_are_separate(normalization):
    r=extract([record(1,'authentication',host='h',host_id='A',logon_id='X',operation='session_open'),
               record(2,'authentication',host='h',host_id='A',logon_id='X',operation='logout',time=10),
               record(3,hostname='h',host_id='A',logon_id='X',time=10)],normalization)
    session=lambda source:{o.entity_id for a in r.alerts if a.source_record_id==source for o in a.entity_occurrences if o.role.value=='session'}
    assert session('1').isdisjoint(session('3'))


@pytest.mark.parametrize('bad', [dict(token_pointer='/connection_id'),dict(equivalent_token_pointers=['/connection_id']),
                               dict(start_operations=['logout']),dict(close_operations='logout')])
def test_invalid_authority_contract_fails_closed(bad):
    with pytest.raises(ValueError):
        replace(settings('edr'),identity_authorities=dict(auth_session={**SESSION,**bad}))
