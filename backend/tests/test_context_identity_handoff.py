"""Synthetic issuer contracts exercise ②→⑤ without real labels or IDs."""
from dataclasses import replace
import pytest

from app.adapters.multisource import MultiSourceAdapter
from app.community import load_community_config, prepare_communities
from app.entities.extraction import extract_entities
from app.services.alert_pipeline import prepare_alerts
from test_community_builder import normalization, record, ROOT
from test_source_bound_projection import settings
from test_identity_projection import HOST


def contract(kind='connection', **kw):
    return dict(kind=kind,authority_domain='synthetic-issuer',deployment_scope='test',network_scope='test-net',
                token_pointer='/'+('request_id' if kind=='request' else 'connection_id'),max_age_seconds=600,**kw)


def extract(rows, normalization, policies=None):
    ss={s:replace(settings(s),asset_namespace=None,account_realm=None,network_namespace=None,
        identity_authorities=(policies or {}).get(s,dict(host=HOST,contexts=[{**contract(),
            **({'destination_ip_pointer':'/host_ip'} if s=='authentication' else {})}]))) for s in {r['source_type'] for r in rows}}
    adapters={s:MultiSourceAdapter(normalization,p,s) for s,p in ss.items()}
    result=extract_entities([adapters[r['source_type']].convert(r) for r in rows],
                            {p.source_namespace:p for p in ss.values()},contract='front-data-v1')
    return result,{p.source_namespace:p for p in ss.values()}


def pair():
    return [record(1,'firewall',connection_id='native-X',src_ip='192.0.2.1',src_port=1234,
                   dst_ip='192.0.2.2',dst_port=22,protocol='TCP'),
            record(2,'authentication',host='server',host_id='asset',host_ip='192.0.2.2',
                   connection_id='native-X',source_ip='192.0.2.1',source_port=1234,destination_port=22,time=5)]


def projected(r):
    return [{c.scope for c in a.contexts if c.raw_pointer=='/connection_id'} for a in r.alerts]


def test_partial_auth_network_identity_reaches_community(normalization):
    r,ss=extract(pair(),normalization)
    assert set.intersection(*projected(r))
    r.identity_projection.validate_trace(r.alerts,r.entities)
    prepared=prepare_alerts(r.alerts,source_settings=ss,entities=r.entities,identity_projection=r.identity_projection)
    run=prepare_communities(prepared,ss,load_community_config(ROOT/'configs/community-v1.yaml'))
    assert [c.member_count for c in run.result.incident_candidates]==[2]
    assert len(r.identity_projection.context_bindings)==1
    for b in r.identity_projection.context_bindings:
        assert len(b.observations)==2
        assert all(o.source_contexts for o in b.observations)


@pytest.mark.parametrize('mode',['endpoint','port','protocol','sparse','authority','undeclared','age','epoch','token'])
def test_connection_conflicts_keep_source_scopes(normalization,mode):
    rows=pair()
    policies=None
    if mode=='endpoint': rows[1]['source_ip']='192.0.2.9'
    if mode=='port': rows[1]['source_port']=999
    if mode=='protocol': rows[1]['protocol']='UDP'
    if mode=='sparse': rows[1].pop('source_ip');rows[1].pop('source_port')
    if mode=='authority': policies={'authentication':dict(host=HOST,contexts=[{**contract(),'authority_domain':'other'}])}
    if mode=='undeclared': policies={'authentication':dict(host=HOST)}
    if mode=='age': rows[1]['timestamp']='2026-01-01T00:20:00Z'
    if mode=='epoch': rows[0]['boot_id']='a';rows[1]['boot_id']='b'
    if mode=='token': rows[1]['connection_id']='other'
    r,_=extract(rows,normalization,policies)
    assert not set.intersection(*projected(r))


def test_competing_full_tuples_cannot_absorb_partial_observation(normalization):
    rows=pair()
    rows.append(record(3,'edr',connection_id='native-X',src_ip='192.0.2.3',src_port=1234,
                       dst_ip='192.0.2.2',dst_port=22,protocol='TCP'))
    r,_=extract(rows,normalization)
    assert not r.identity_projection.context_bindings


def test_request_same_host_and_issuer_handoff(normalization):
    rows=[record(1,'waf',server_host='server',server_host_id='asset',request_id='request-X'),
          record(2,'edr',hostname='server',host_id='asset',request_id='request-X')]
    policies={s:dict(host=HOST,contexts=[contract('request')]) for s in ('waf','edr')}
    r,_=extract(rows,normalization,policies)
    assert len({c.scope for a in r.alerts for c in a.contexts if c.kind=='request'})==1
    assert r==extract(rows[::-1],normalization,policies)[0]
    rows[1]['host_id']='different'
    r,_=extract(rows,normalization,policies)
    assert len({c.scope for a in r.alerts for c in a.contexts if c.kind=='request'})==2


def test_connection_never_aliases_logon_or_session(normalization):
    rows=pair()
    for r in rows: r['session_id']='native-X';r['logon_id']='native-X'
    r,_=extract(rows,normalization)
    assert all(c.raw_pointer=='/connection_id' for b in r.identity_projection.context_bindings
               for o in b.observations for c in o.source_contexts)


@pytest.mark.parametrize('complete',[True,False])
def test_bound_process_can_join_component_with_other_network_endpoint(normalization,complete):
    process=dict(process_id=7,process_start_time='2025-12-31T23:00:00Z') if complete else dict(process_id=7)
    rows=[record(1,hostname='a',host_id='A',connection_id='bridge',**process),
          record(2,time=5,hostname='b',host_id='B',connection_id='bridge'),
          record(3,'host_audit',time=10,host='a',host_id='A',pid=7,
                 **({'process_start_time':process['process_start_time']} if complete else {}))]
    for row in rows[:2]:
        row.update(src_ip='192.0.2.1',src_port=1234,dst_ip='192.0.2.2',dst_port=22,protocol='TCP')
    # A source-local native connection joins two observed endpoints. The third
    # observation needs the complete process instance to join that component.
    r,ss=extract(rows,normalization)
    prepared=prepare_alerts(r.alerts,source_settings=ss,entities=r.entities,identity_projection=r.identity_projection)
    run=prepare_communities(prepared,ss,load_community_config(ROOT/'configs/community-v1.yaml'))
    assert sorted(c.member_count for c in run.result.incident_candidates)==([3] if complete else [1,2])


@pytest.mark.parametrize('conflict',['account','host','start','common_parent'])
def test_cross_source_process_tier_keeps_pair_conflicts(normalization,conflict):
    start='2025-12-31T23:00:00Z'
    rows=[record(1,hostname='a',host_id='A',process_id=7,process_start_time=start,user='u'),
          record(2,'host_audit',time=5,host='a',host_id='A',pid=7,process_start_time=start,account='u')]
    if conflict=='account': rows[1]['account']='other'
    if conflict=='host': rows[1].update(host='b',host_id='B')
    if conflict=='start': rows[1]['process_start_time']='2025-12-31T23:30:00Z'
    if conflict=='common_parent':
        rows[0].update(parent_process_id=7,parent_process_start_time=start,process_id=8)
        rows[1].update(ppid=7,parent_process_start_time=start,pid=9)
    r,ss=extract(rows,normalization)
    prepared=prepare_alerts(r.alerts,source_settings=ss,entities=r.entities,identity_projection=r.identity_projection)
    run=prepare_communities(prepared,ss,load_community_config(ROOT/'configs/community-v1.yaml'))
    assert sorted(c.member_count for c in run.result.incident_candidates)==[1,1]
