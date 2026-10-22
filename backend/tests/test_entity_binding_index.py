"""Identity, typed recall and evidence regressions; no labels or later stages."""
from dataclasses import replace
import json

import pytest

from app.community.evidence import Binding, profile
from app.community.index import CommunityIndex
from test_community_builder import cfg, normalization, record, run, sizes


def profiles(result, cfg, overrides=None):
    from test_source_bound_projection import settings
    entities = {e.entity_id:e for e in result.entities}
    return [profile(a, entities, replace(settings(a.raw_alert['source_type']), **(overrides or {})), cfg)
            for a in sorted(result.alerts, key=lambda a:(a.timestamp, a.alert_id))]


NO_FALLBACK = dict(asset_namespace=None,network_namespace=None,account_realm=None)


def test_host_account_identity_without_synthetic_realm(cfg, normalization):
    rows = [record(1,hostname='h1',user='root'),record(2,hostname='h2',user='root'),
            record(3,'host_audit',host='h1',account='root')]
    r = run(rows,cfg,normalization,{s:NO_FALLBACK for s in ('edr','host_audit')})
    accounts = [e for e in r.entities if e.type.value=='ACCOUNT']
    assert len(accounts)==2 and sorted(len(e.alert_ids) for e in accounts)==[1,2]
    assert len([e for e in r.entities if e.type.value=='HOST'])==2
    assert all('source_namespace' not in e.scope for e in accounts)


def test_unscoped_account_is_not_a_global_user(cfg, normalization):
    r = run([record(1,user='admin'),record(2,user='admin')],cfg,normalization,{'edr':NO_FALLBACK})
    assert len([e for e in r.entities if e.type.value=='ACCOUNT'])==2
    assert sizes(r)==[1,1]


def test_real_domain_account_can_span_hosts(cfg, normalization):
    rows=[record(1,hostname='h1',user='LAB\\admin'),record(2,hostname='h2',user='LAB\\admin')]
    r=run(rows,cfg,normalization,{'edr':NO_FALLBACK})
    accounts=[e for e in r.entities if e.type.value=='ACCOUNT']
    assert len(accounts)==1 and accounts[0].scope=='LAB' and accounts[0].value=='admin'
    assert sizes(r)==[1,1]  # Shared entity recalls; it cannot itself admit membership.


def test_monitored_ip_host_is_distinct_from_network_context(cfg, normalization):
    rows=[record(1,host_ip='192.0.2.5'),record(2,src_ip='192.0.2.5'),record(3,dst_ip='192.0.2.5')]
    r=run(rows,cfg,normalization,{'edr':NO_FALLBACK})
    hosts=[e for e in r.entities if e.type.value=='HOST']
    assert len(hosts)==1 and len(hosts[0].alert_ids)==1
    assert not any(e.type.value=='IP' for e in r.entities)
    assert sizes(r)==[1,1,1]
    ps=profiles(r,cfg,NO_FALLBACK)
    keys={b.kind for p in ps for b in p.bindings}
    assert {'core_host','context.src_ip','context.dst_ip'} <= keys
    assert len({b.key for p in ps for b in p.bindings if b.kind in ('core_host','context.src_ip','context.dst_ip')})==3


def test_asset_id_precedes_hostname_and_process_fallback_is_host_local(cfg, normalization):
    rows=[record(1,hostname='old',asset_id='asset',process_name='powershell.exe'),
          record(2,hostname='new',asset_id='asset',process_name='powershell.exe'),
          record(3,hostname='other',process_name='powershell.exe'),record(4,process_name='powershell.exe')]
    r=run(rows,cfg,normalization,{'edr':NO_FALLBACK})
    processes=[e for e in r.entities if e.type.value=='PROCESS']
    assert len(processes)==2 and sorted(len(e.alert_ids) for e in processes)==[1,2]
    assert all(json.loads(e.value).get('descriptor')=='powershell.exe' for e in processes)
    assert sizes(r)==[1]*4
    assert all(not any(b.kind=='process_instance' for b in p.bindings) for p in profiles(r,cfg,NO_FALLBACK))


def test_guid_without_host_is_observed_identity(cfg, normalization):
    r=run([record(1,process_guid='observed-guid'),record(2,process_guid='observed-guid')],cfg,normalization)
    assert len([e for e in r.entities if e.type.value=='PROCESS'])==1
    # Identity is retained, but Process alone no longer admits membership.
    assert sizes(r)==[1,1]


@pytest.mark.parametrize('missing', ['src_ip','src_port','dst_ip','dst_port','protocol'])
def test_partial_five_tuple_is_audited_and_cannot_strong_bind(cfg, normalization, missing):
    fields=dict(src_ip='192.0.2.1',src_port=0,dst_ip='192.0.2.2',dst_port=443,protocol='TCP',flow_id='flow')
    fields.pop(missing)
    r=run([record(1,**fields),record(2,**fields)],cfg,normalization)
    assert sizes(r)==[1,1]
    for p in profiles(r,cfg):
        partial=[b for b in p.bindings if b.kind=='incomplete_flow']
        assert len(partial)==1 and not partial[0].complete and missing in partial[0].missing_fields
        assert not any(b.kind=='flow' for b in p.bindings)


def test_full_tuple_across_sources_uses_protocol_normalization_not_sensor(cfg, normalization):
    f=dict(src_ip='192.0.2.1',src_port=0,dst_ip='192.0.2.2',dst_port=443,protocol='TCP')
    r=run([record(1,**f),record(2,'firewall',**dict(f,protocol='tcp'))],cfg,normalization,
          {s:NO_FALLBACK for s in ('edr','firewall')})
    assert sizes(r)==[2]
    assert r.result.incident_candidates[0].matching_evidence[0].identity_kind=='flow'
    assert not r.entities


@pytest.mark.parametrize('field,kind', [('job_id','task'),('operation_id','task'),('execution_id','task'),
                                     ('auth_session_id','session'),('connection_id','connection')])
def test_explicit_binding_aliases_are_observed_and_typed(cfg, normalization, field, kind):
    r=run([record(1,**{field:'same'}),record(2,**{field:'same'})],cfg,normalization)
    assert sizes(r)==[2]
    assert r.result.incident_candidates[0].matching_evidence[0].identity_kind==kind
    mixed=run([record(1,**{field:'same'}),record(2,request_id='same')],cfg,normalization)
    assert sizes(mixed)==[1,1]


def test_equal_url_and_hash_recall_without_request_or_session(cfg, normalization):
    rows=[record(1,file_hash='hash',file_path='/tmp/a',src_ip='192.0.2.1',hostname='h'),
          record(2,file_hash='hash',file_path='/tmp/a',src_ip='192.0.2.1',hostname='h')]
    r=run(rows,cfg,normalization)
    assert sizes(r)==[1,1] and all(not a.contexts for a in r.alerts)
    ps=profiles(r,cfg)
    index=CommunityIndex(cfg)
    index.add(ps[0])
    found=index.query(ps[1])
    assert any(row[2].kind=='context.file_hash' for row in found)
    assert all(not any(b.kind=='file_hash' for b in p.bindings) for p in ps)
    # Even a forged identical string cannot cross the typed posting partition.
    a=Binding(1,'request','same',('/event_id',))
    b=replace(a,projection='context')
    ps[0].bindings=[a];ps[1].bindings=[b]
    index=CommunityIndex(cfg);index.add(ps[0])
    assert index.query(ps[1])==[]


def test_context_identity_field_and_all_projection_pointers_are_preserved(cfg, normalization):
    rows=[record(1,hostname='h',user='root',realm='R',trace_id='x',file_hash='hash',task_id='x'),
          record(2,hostname='h',user='root',realm='R',request_id='x',file_hash='hash',job_id='x')]
    first=run(rows,cfg,normalization)
    second=run(list(reversed(rows)),cfg,normalization)
    assert first.result==second.result and first.entities==second.entities
    assert sizes(first)==[2]
    # Distinct typed request/task aliases still do not bind. The two alerts
    # now meet via the explicitly permitted Host + Account context rule.
    assert all(e.identity_kind == 'host_account' for c in first.result.incident_candidates for e in c.matching_evidence)
    for p in profiles(first,cfg):
        from app.models.base import resolve_pointer
        for b in p.bindings:
            assert b.pointers
            for pointer in b.pointers:
                assert resolve_pointer(p.alert.raw_alert,pointer) is not None


def test_formal_profiles_have_no_manufactured_shared_namespaces():
    from app.config import read_yaml
    from test_community_builder import ROOT
    settings=read_yaml(ROOT/'configs/front-data-profiles.yaml')['sources']
    assert all(not {'network_namespace','asset_namespace','account_realm'} & s.keys() for s in settings.values())
