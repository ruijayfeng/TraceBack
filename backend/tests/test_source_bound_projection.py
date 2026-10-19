"""Label-free native schema witnesses; no dataset/scenario/GT imports."""
from copy import deepcopy
from dataclasses import replace
import pytest
from app.adapters.multisource import MultiSourceAdapter
from app.adapters.base import AdapterSettings
from app.config import load_config
from app.entities.extraction import extract_entities
from app.services.storage import restore_config
from pathlib import Path

T='2026-01-01T00:00:00Z'
ROOT=Path(__file__).resolve().parents[2]

def config():
    c=load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml',deployment_override=ROOT/'configs/sources.yaml')
    s=c.snapshot
    for kind in ('category','severity'):
        for source in ('waf','edr','other'):
            s['normalization'][kind+'_mapping_files'].append(dict(schema_version='1.0',mapping_type=kind,source_type=source,default='unknown',rules=[]))
    return restore_config(s)

def settings(s):
    return AdapterSettings(source_namespace='sensor.'+s,format_profile='multisource_native_v1',generator='synthetic',
                           network_namespace='network',asset_namespace='assets',account_realm='realm')

def body(s):
    x=dict(timestamp=T,source_type=s,event_id='native-1')
    if s=='ids': x.update(event_type='alert',src_ip='192.0.2.1',dest_ip='192.0.2.2',src_port=3456,dest_port=443,proto='TCP',flow_id=51,
                         alert=dict(signature='test',signature_id=1,severity=2),http=dict(hostname='EXAMPLE.test',url='/hello',http_method='GET'))
    if s=='waf': x.update(client_ip='192.0.2.1',server_ip='192.0.2.2',client_port=3456,server_port=443,server_host='HOST',host='EXAMPLE.test',
                         uri='/hello',method='GET',request_id='request',worker_process_id=12,worker_process_start_time=T)
    if s=='edr': x.update(hostname='HOST',host_ip='192.0.2.2',user='Alice',process_id=12,process_start_time=T,process_name='worker',
                         file_path='/tmp/object',connection_id='connection',request_id='request',logon_id='auth')
    if s=='firewall': x.update(src_ip='192.0.2.1',dst_ip='192.0.2.2',src_port=3456,dst_port=443,protocol='TCP',session_id='connection',connection_id='connection',action='deny',direction='inbound')
    if s=='authentication': x.update(host='HOST',host_ip='192.0.2.2',account='Alice',source_ip='192.0.2.1',session_id='auth',service='sshd')
    if s=='host_audit': x.update(host='HOST',host_ip='192.0.2.2',account='Alice',pid=12,process_start_time=T,executable='/bin/worker',file_path='/tmp/object',audit_type='EXECVE',operation='EXECVE',session='auth')
    return x

def convert(s,x=None,setting=None):
    st=setting or settings(s)
    return MultiSourceAdapter(config(),st,s).convert_record(dict(event_id='outer',source_type=s,timestamp=T,raw_pointer={'line':42},event=x or body(s))),st

@pytest.mark.parametrize('source',['ids','waf','edr','firewall','authentication','host_audit'])
def test_six_native_profiles_and_roundtrip(source):
    a,st=convert(source); result=extract_entities([a],{st.source_namespace:st});a=result.alerts[0]
    assert a.raw_alert==body(source)
    assert type(a).model_validate_json(a.canonical_json())==a
    if source in ('ids', 'firewall'):
        assert not result.entities  # Network endpoints remain weak context.
    else:
        assert result.entities
    assert not any('outer' in e.value or 'raw_pointer' in e.value for e in result.entities)
    if source=='ids': assert a.domain=='example.test' and a.dst_port==443 and 'native.proto' in a.field_provenance
    if source=='waf': assert a.host=='host' and a.domain=='example.test' and a.process.pid==12 and 'native.method' in a.field_provenance
    if source=='edr': assert a.account=='Alice' and a.process.start_time and a.file=='/tmp/object'
    if source=='firewall': assert a.src_port==3456 and 'native.action' in a.field_provenance and 'native.direction' in a.field_provenance
    if source=='authentication': assert a.account=='Alice' and a.src_ip=='192.0.2.1' and 'native.service' in a.field_provenance
    if source=='host_audit': assert a.process.pid==12 and 'native.audit_type' in a.field_provenance

def test_wrapper_identity_and_locators_cannot_change_any_canonical_fact():
    st=settings('waf');adapter=MultiSourceAdapter(config(),st,'waf')
    r=dict(source_type='waf',event_id='a',raw_pointer={'line':1},event=body('waf'))
    a=adapter.convert_record(r)
    r.update(event_id='randomized',raw_pointer='randomized');b=adapter.convert_record(r)
    r.pop('raw_pointer');c=adapter.convert_record(r)
    assert a.canonical_json()==b.canonical_json()==c.canonical_json()
    assert a.source_record_id=='native-1'

def test_missing_and_unknown_fields_create_no_entities_or_relations():
    a,st=convert('edr',dict(timestamp=T,source_type='edr',unknown_process='invented',unknown_session='invented'))
    r=extract_entities([a],{st.source_namespace:st})
    assert r.entities==[] and r.alerts[0].relations==[]

def test_namespace_isolation_shared_scope_and_typed_bindings():
    alerts=[];ss={}
    for s in ('waf','edr','authentication','host_audit'):
        a,st=convert(s);alerts.append(a);ss[st.source_namespace]=st
    r=extract_entities(alerts,ss)
    entities={e.entity_id:e for e in r.entities}; aa={a.source_namespace:a for a in r.alerts}
    waf,edr=aa['sensor.waf'],aa['sensor.edr']
    shared=set(waf.entity_ids)&set(edr.entity_ids)
    assert any(entities[e].type.value=='PROCESS' for e in shared)
    assert not any(entities[e].type.value=='SESSION' for e in shared)
    assert any(c.kind=='request' and c.value=='request' for c in waf.contexts)
    assert any(c.kind=='request' and c.value=='request' for c in edr.contexts)
    assert {c.scope for c in waf.contexts}.isdisjoint(c.scope for c in edr.contexts)
    assert not waf.relations # Worker handling does not attest process creation.
    st=replace(settings('waf'),network_namespace='isolated',asset_namespace='isolated')
    isolated,_=convert('waf',setting=st)
    rr=extract_entities([isolated],{st.source_namespace:st})
    assert not any(e.type.value=='IP' and e.entity_id in waf.entity_ids for e in rr.entities)

def test_projection_is_idempotent_and_order_independent():
    alerts=[];ss={}
    for s in ('ids','waf','edr','firewall','authentication','host_audit'):
        a,st=convert(s);alerts.append(a);ss[st.source_namespace]=st
    a=extract_entities(alerts,ss);b=extract_entities(list(reversed(alerts)),ss);c=extract_entities(a.alerts,ss)
    assert [e.canonical_json() for e in a.entities]==[e.canonical_json() for e in b.entities]==[e.canonical_json() for e in c.entities]
    assert [x.canonical_json() for x in a.alerts]==[x.canonical_json() for x in c.alerts]

def test_wrapper_native_timestamp_conflict_rejected():
    st=settings('ids');adapter=MultiSourceAdapter(config(),st,'ids')
    with pytest.raises(ValueError,match='timestamp_conflict'):
        adapter.convert_record(dict(source_type='ids',timestamp='2026-01-02T00:00:00Z',event=body('ids')))

def test_separate_query_preserved_and_http_authority_interoperates():
    w=body('waf');w['query']='token=A&n=1'
    i=body('ids');i['http']['url']='/hello?token=A&n=1'
    a,sa=convert('waf',w);b,sb=convert('ids',i)
    assert a.url=='/hello?token=A&n=1'
    r=extract_entities([a,b],{sa.source_namespace:sa,sb.source_namespace:sb})
    assert not any(e.type.value=='URL' for e in r.entities)
    assert a.url == b.url and a.raw_alert['query'] == 'token=A&n=1'
    w['uri']='/hello?different=1'
    with pytest.raises(ValueError,match='conflicting_http_query'): convert('waf',w)

def test_native_file_hash_preserved_without_inventing_hash_algorithm():
    x=body('edr');x['file_hash']='native-hash'
    a,sa=convert('edr',x);r=extract_entities([a],{sa.source_namespace:sa})
    assert not any(e.type.value=='FILE' for e in r.entities)
    assert r.alerts[0].raw_evidence['file_hash']=='native-hash'
