"""Current contract: source evidence, bounded identity, lookup and handoff."""
from dataclasses import replace
import builtins
import json
from pathlib import Path

import pytest

from app.adapters.multisource import MultiSourceAdapter
from app.correlation.candidates import CandidateGenerator, candidate_diagnosis, generate_candidates
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.entities.extraction import extract_entities
from app.entities.context import context_key
from app.incidents.clustering import cluster_incidents
from app.models import CanonicalAlert
from app.services.front_data import prepare_front_data, index_front_data
from app.config import load_config
from test_source_bound_projection import body, settings, T, ROOT


@pytest.fixture
def cfg():
    return load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml',
                       deployment_override=ROOT/'configs/front-data-sources.yaml')


def adapter(cfg, source, **overrides):
    return MultiSourceAdapter(cfg, replace(settings(source), **overrides), source)


def result(cfg, source, *records, **overrides):
    a = adapter(cfg, source, **overrides)
    alerts = [a.convert(raw) for raw in records]
    extracted = extract_entities(alerts, {a.settings.source_namespace:a.settings})
    return extracted, AlertIndex(extracted.alerts, [], extracted.entities), a


@pytest.mark.parametrize('source', ['ids','waf','edr','firewall','host_audit','authentication'])
def test_adapter_and_file_ingress_preserve_evidence(cfg, source, tmp_path):
    raw = body(source)
    raw.update(product='observed-product', title='Observed alert')
    a = adapter(cfg, source)
    envelope = dict(source_type=source, event=raw)
    p = tmp_path/'alerts.jsonl'
    p.write_text(json.dumps(envelope)+'\n', encoding='utf8')
    batch = a.read_file(p)
    assert not batch.rejected and batch.accepted_count == 1
    alert = batch.alerts[0]
    assert alert.source_product == 'observed-product' and alert.title == 'Observed alert'
    assert alert.timestamp == '2026-01-01T00:00:00.000000Z'
    assert alert.source_type and alert.severity and alert.source_namespace
    assert alert.raw_evidence == raw
    assert CanonicalAlert.model_validate_json(alert.canonical_json()) == alert


@pytest.mark.parametrize('field,kind', [('request_id','request'),('flow_id','flow'),('session_id','session'),('task_id','task')])
def test_context_normalization_lookup_and_missing(cfg, field, kind):
    raw = dict(timestamp=T,source_type='edr',event_id='1',**{field:'  Case-A  '})
    other = dict(raw,event_id='2',**{field:'Case-A'})
    extracted, index, _ = result(cfg, 'edr', raw, other)
    assert extracted.entities == []
    ref = extracted.alerts[0].contexts[0]
    assert ref.kind == kind and ref.value == 'Case-A'
    assert len(index.query_context(kind, ref.value, ref.scope)) == 2
    assert len(generate_candidates(index,cfg).pairs) == 1
    assert context_key(ref) in index.by_context
    sparse, index, _ = result(cfg,'edr',dict(timestamp=T,source_type='edr'))
    assert not sparse.entities and not sparse.alerts[0].contexts
    assert not generate_candidates(index,cfg).pairs


def test_native_realm_overrides_fallback_and_case_is_preserved(cfg):
    raw = dict(timestamp=T,source_type='authentication',account=' Alice ',realm='DOMAIN-A')
    records = [raw,dict(raw,realm='DOMAIN-B'),dict(raw,account='alice')]
    extracted, _, _ = result(cfg,'authentication',*records)
    accounts = [e for e in extracted.entities if e.type.value=='ACCOUNT']
    assert len(accounts)==3 and {e.scope for e in accounts}=={'DOMAIN-A','DOMAIN-B'}
    assert {e.value for e in accounts}=={'Alice','alice'}


def test_process_name_descriptor_and_pid_are_host_scoped(cfg):
    base = dict(timestamp=T,source_type='edr',process_name='worker')
    sparse, _, _ = result(cfg,'edr',base,dict(base,event_id='2',hostname='host'))
    descriptors = [e for e in sparse.entities if e.type.value=='PROCESS']
    assert len(descriptors) == 1 and json.loads(descriptors[0].value)['descriptor'] == 'worker'
    assert len(descriptors[0].alert_ids) == 1  # Hostless name creates no entity.
    records = [dict(base,hostname=h,process_id=p,event_id=str((h,p)))
               for h,p in [('h1',1),('h1',2),('h2',1)]]
    extracted, _, _ = result(cfg,'edr',*records)
    assert len([e for e in extracted.entities if e.type.value=='PROCESS'])==3
    # Stable GUID takes priority over a reused/changed PID.
    a = dict(base,hostname='h',process_guid='GUID',process_id=1)
    b = dict(a,process_id=2,event_id='2')
    extracted, _, _ = result(cfg,'edr',a,b)
    assert len([e for e in extracted.entities if e.type.value=='PROCESS'])==1
    guid_only=dict(timestamp=T,source_type='edr',hostname='h',process_guid='GUID')
    extracted,_,_=result(cfg,'edr',guid_only)
    assert len([e for e in extracted.entities if e.type.value=='PROCESS'])==1


def test_stable_asset_id_and_namespace_isolation(cfg):
    raw = dict(timestamp=T,source_type='edr',hostname='OLD.',host_id='asset-1',user='Alice',src_ip='2001:DB8::1')
    a, b = adapter(cfg,'edr'), adapter(cfg,'edr', source_namespace='another',network_namespace='another',asset_namespace='another',account_realm='another')
    values = [a.convert(raw),b.convert(raw),a.convert(dict(raw,hostname='NEW.',event_id='2'))]
    extracted = extract_entities(values,{x.settings.source_namespace:x.settings for x in (a,b)})
    assert len([e for e in extracted.entities if e.type.value=='HOST']) == 2
    assert not any(e.type.value=='IP' for e in extracted.entities)
    assert all(a.src_ip == '2001:db8::1' for a in extracted.alerts)
    assert all(e.value=='asset-1' for e in extracted.entities if e.type.value=='HOST')


def test_every_ordinary_field_stays_evidence_and_cannot_nominate(cfg):
    raw = dict(timestamp=T,source_type='edr',file_path='/tmp/same',command_line='same',url='/same',
        domain='same',dst_port=443,rule_id='same',signature='same',file_hash='same',process_name='same')
    extracted, index, _ = result(cfg,'edr',*[dict(raw,event_id=str(i)) for i in range(40)])
    assert not extracted.entities
    assert not generate_candidates(index,cfg).pairs
    assert all(a.raw_evidence==dict(raw,event_id=a.raw_alert['event_id']) for a in extracted.alerts)


def test_shared_context_requires_declared_scope_and_preserves_kind(cfg):
    aa = [adapter(cfg,s,session_scope='declared-binding-scope') for s in ('waf','edr')]
    records = [dict(timestamp=T,source_type=s,request_id='same') for s in ('waf','edr')]
    extracted = extract_entities([a.convert(r) for a,r in zip(aa,records)],{a.settings.source_namespace:a.settings for a in aa})
    index = AlertIndex(extracted.alerts,[],extracted.entities)
    assert len(index.by_context)==1 and len(generate_candidates(index,cfg).pairs)==1
    assert not index.query_context('flow','same',extracted.alerts[0].contexts[0].scope)


def test_determinism_and_explicit_legacy_replay(cfg):
    raws = [dict(body('edr'),event_id=str(i),request_id='r') for i in range(3)]
    a = adapter(cfg,'edr'); ss = {a.settings.source_namespace:a.settings}
    values = [a.convert(raw) for raw in raws]
    first = extract_entities(values,ss)
    assert first==extract_entities(list(reversed(values)),ss)==extract_entities(first.alerts,ss)
    index = AlertIndex(first.alerts,[],first.entities)
    second = AlertIndex(list(reversed(first.alerts)),[],list(reversed(first.entities)))
    assert generate_candidates(index,cfg)==generate_candidates(second,cfg)
    legacy = extract_entities(values,ss,contract='legacy-v1')
    assert any(e.type.value=='FILE' for e in legacy.entities)


def test_priority_and_no_global_time_lookup(cfg, monkeypatch):
    raws = [dict(timestamp=T,source_type='edr',event_id=str(i),src_ip='192.0.2.'+str(i+1)) for i in range(150)]
    _, index, _ = result(cfg,'edr',*raws)
    def forbidden(*args,**kwargs):
        raise AssertionError('global time lookup')
    for p in index.time.values():
        monkeypatch.setattr(p,'mask',forbidden)
        monkeypatch.setattr(p,'nearest',forbidden)
    generator=CandidateGenerator(index,cfg)
    assert generator.rank('request',None,1,'x') < generator.rank('HOST',None,0,'x') < generator.rank('IP',None,0,'x')
    output=generator.generate()
    assert not output.pairs and output.examined_neighbors==0
    assert output.potential_pair_stats['unique_potential_pairs']==0


def test_production_handoff_and_truth_tripwire(cfg, monkeypatch):
    original = builtins.__import__
    def guarded(name,*args,**kwargs):
        assert name.split('.')[0]!='evaluation'
        return original(name,*args,**kwargs)
    monkeypatch.setattr(builtins,'__import__',guarded)
    adapters = {s:adapter(cfg,s) for s in ('ids','waf','edr','firewall','host_audit','authentication')}
    r=prepare_front_data([dict(source_type=s,event=body(s)) for s in adapters],adapters,cfg)
    assert r.summary['total_alerts']==6
    scorer=CorrelationScorer(r.index,cfg,{a.settings.source_namespace:a.settings for a in adapters.values()})
    # No edges are fabricated by extraction, index or candidate handoff.
    clusters=cluster_incidents(r.index,[],scorer)
    assert len(clusters.incidents)==6
    for candidate in r.candidates.pairs:
        assert candidate.support_key == tuple(sorted(candidate.support_key))
        assert candidate.evidence and candidate.channels


def test_legacy_sparse_alert_reprojection(cfg):
    a=adapter(cfg,'edr')
    alert=a.convert(dict(timestamp=T,source_type='edr',request_id='existing'))
    data=alert.model_dump();data.pop('context_candidates',None)
    r=index_front_data([CanonicalAlert.model_validate(data)],{a.settings.source_namespace:a.settings},cfg)
    assert r.summary['context_counts']['request']==1


def test_core_and_auxiliary_index_queries_resolve_real_alerts(cfg):
    raw=dict(body('edr'),src_ip='192.0.2.1',dst_ip='192.0.2.2')
    extracted,index,_=result(cfg,'edr',raw,dict(raw,event_id='2'))
    assert {e.type.value for e in extracted.entities}=={'HOST','ACCOUNT','PROCESS'}
    for entity in extracted.entities:
        hits=index.query_entity(entity.entity_id,'2025-01-01T00:00:00.000000Z','2027-01-01T00:00:00.000000Z')
        assert {a.alert_id for a in hits}==set(entity.alert_ids)


def test_hot_ip_is_bounded_and_cannot_displace_strong_context(cfg, monkeypatch):
    from app.services.storage import restore_config
    snapshot=cfg.snapshot
    snapshot['candidate'].update(per_channel_neighbors=2,hot_entity_neighbors=1,max_neighbors_per_alert=1,
                                 hot_entity_min_count=2,hot_entity_ratio=0.01)
    limited=restore_config(snapshot)
    raws=[dict(timestamp=T,source_type='edr',event_id=str(i),src_ip='192.0.2.1',request_id='shared' if i<2 else str(i))
          for i in range(120)]
    extracted,index,_=result(limited,'edr',*raws)
    output=generate_candidates(index,limited)
    pair=tuple(sorted(a.alert_id for a in extracted.alerts if a.raw_alert['event_id'] in {'0','1'}))
    assert pair in {p.support_key for p in output.pairs}
    assert output.examined_neighbors < len(raws)*5
    assert len(output.pairs)<=len(raws)


def test_incremental_candidate_cache_tracks_context_postings(cfg,tmp_path):
    from app.services.incremental import IncrementalService
    from app.services.incremental_dependencies import json_value
    from app.utils.stable_id import canonical_json
    a=adapter(cfg,'edr');ss={a.settings.source_namespace:a.settings}
    values=[a.convert(dict(timestamp=T,source_type='edr',event_id=str(i),request_id='r')) for i in range(3)]
    svc=IncrementalService(tmp_path/'front.duckdb',cfg,ss)
    try:
        svc.bootstrap(values[:2])
        svc.increment(values[2:])
        extracted=extract_entities(values,ss)
        idx=AlertIndex(extracted.alerts,[],extracted.entities)
        expected=generate_candidates(idx,cfg)
        actual=svc.records()['candidates']
        assert set(actual)=={canonical_json(list(p.support_key)) for p in expected.pairs}
        for pair in expected.pairs:
            row=actual[canonical_json(list(pair.support_key))]
            assert row['evidence']==json_value([e.json_data() for e in pair.evidence])
        assert svc.increment(values[2:])['idempotent_replay']
        assert svc.increment([extracted.alerts[0]])['idempotent_replay']
    finally:
        svc.close()
