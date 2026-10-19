from evaluation.framework.preformula_baseline.boundary import development_config
"""Synthetic source-semantic boundaries; no scenario or GT inputs."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import json
import pytest

from app.adapters.base import AdapterSettings
from app.adapters.wazuh import WazuhAdapter
from app.correlation.candidates import generate_candidates
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.entities.extraction import extract_entities
from app.models import CanonicalAlert
from app.services.storage import restore_config
from app.config import load_config

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def cfg():
    return development_config()[0]


def settings(ns='synthetic.local', **kw):
    return AdapterSettings(ns, 'wazuh_json_v1', 'Wazuh', semantic_profile='wazuh_local_v1', **kw)


def raw(i='a', host='node', ip='192.0.2.8', data=None, seconds=0):
    return {'id': i, 'timestamp': f'2024-01-01T00:00:{seconds:02d}Z',
            'rule': {'id':'90001','level':7,'groups':['audit']},
            'agent': {'id':'5','name':host,'ip':ip}, 'manager':{'name':'manager'},
            'decoder':{'name':'auditd'}, 'data': data or {}}


def index_of(cfg, records, ss):
    aa = [WazuhAdapter(cfg, ss[ns]).convert(r) for ns,r in records]
    result = extract_entities(aa, ss)
    return AlertIndex(result.alerts, (), result.entities)


def test_projection_preserves_roles_and_no_endpoint_overload(cfg):
    ss = settings()
    r = raw(data={'target_user':'alice','dstuser':'bob','audit':{'auid':'carol','exe':'/bin/sh','parent_name':'sshd'}})
    a = WazuhAdapter(cfg,ss).convert(r)
    assert a.host == 'node' and a.sensor == 'manager'
    assert a.src_ip is None and a.dst_ip is None and a.account == 'bob'
    assert {o.role.value for o in a.semantic_observations} == {'monitored_host_ip','target_account','authenticated_account','audit_account'}
    assert a.parent_process.name == 'sshd' and a.parent_process.pid is None
    result = extract_entities([a],{ss.source_namespace:ss})
    assert not result.alerts[0].relations
    assert CanonicalAlert.model_validate_json(result.alerts[0].canonical_json()) == result.alerts[0]
    assert extract_entities(result.alerts,{ss.source_namespace:ss}) == result


def test_legacy_bytes_settings_and_identity(cfg):
    ss=settings(); old=replace(ss,semantic_profile=None)
    r=raw()
    a,b=WazuhAdapter(cfg,old).convert(r),WazuhAdapter(cfg,ss).convert(r)
    assert a.alert_id == b.alert_id and a.raw_alert == b.raw_alert
    assert 'semantic_profile' not in old.snapshot()
    assert 'semantic_observations' not in a.model_dump()
    assert a.host is None and a.sensor == 'node'


@pytest.mark.parametrize('field,value', [('predecoder',{'hostname':'remote'}),('data',{'host':'remote'})])
def test_remote_collector_never_becomes_execution_host(cfg,field,value):
    r=raw(); r[field]=value
    a=WazuhAdapter(cfg,settings()).convert(r)
    assert a.host == 'remote'
    assert not any(o.role.value=='monitored_host_ip' for o in a.semantic_observations)


@pytest.mark.parametrize('uid', ['-1','4294967295','unset','(unset)'])
def test_unset_audit_id_not_entity(cfg,uid):
    a=WazuhAdapter(cfg,settings()).convert(raw(data={'audit':{'auid':uid}}))
    assert not any(o.role.value=='audit_account' for o in a.semantic_observations)


def test_numeric_audit_uid_is_host_local_and_not_username(cfg):
    ss=settings(account_realm='shared')
    idx=index_of(cfg,[(ss.source_namespace,raw('a',host='one',data={'audit':{'auid':'1001'}})),
                     (ss.source_namespace,raw('b',host='two',data={'audit':{'auid':'1001'}})),
                     (ss.source_namespace,raw('c',host='one',data={'dstuser':'1001'}))], {ss.source_namespace:ss})
    accounts=[e for e in idx.entities.values() if e.type.value=='ACCOUNT']
    assert len(accounts)==3 and len({e.scope for e in accounts})==3


@pytest.mark.parametrize('shared,expected', [(False,False),(True,True)])
def test_cross_source_named_account_requires_realm(cfg,shared,expected):
    ss={n:settings(n,account_realm='realm' if shared else None) for n in ['left','right']}
    idx=index_of(cfg,[('left',raw('a',host='one',ip='192.0.2.1',data={'target_user':'alice'})),
                     ('right',raw('b',host='two',ip='192.0.2.2',data={'audit':{'auid':'alice'}}))],ss)
    assert bool(generate_candidates(idx,cfg).pairs)==expected


@pytest.mark.parametrize('shared,expected', [(False,False),(True,True)])
def test_monitored_endpoint_bridge_requires_network(cfg,shared,expected):
    from app.adapters.suricata import SuricataAdapter
    host=settings('host',network_namespace='net' if shared else None)
    net=AdapterSettings('network','suricata_eve_v1','Suricata',network_namespace='net' if shared else None)
    endpoint={'timestamp':'2024-01-01T00:00:01Z','event_type':'alert','src_ip':'198.51.100.5','dest_ip':'192.0.2.8',
              'alert':{'signature_id':1,'signature':'generic','severity':2}}
    aa=[WazuhAdapter(cfg,host).convert(raw()),SuricataAdapter(cfg,net).convert(endpoint)]
    result=extract_entities(aa,{'host':host,'network':net}); idx=AlertIndex(result.alerts,(),result.entities)
    candidates=generate_candidates(idx,cfg)
    assert bool(candidates.pairs)==expected
    if shared:
        scorer=CorrelationScorer(idx,cfg,{'host':host,'network':net})
        score=scorer.score_pair(*candidates.pairs[0].support_key)
        assert not score.relations


def test_observation_forgery_and_extra_keys_rejected(cfg):
    a=WazuhAdapter(cfg,settings()).convert(raw())
    for mutation in [{'value':'203.0.113.99'},{'role':'audit_account'},{'extra':'bad'},{'raw_pointer':'/missing'}]:
        data=a.model_dump();data['semantic_observations'][0].update(mutation)
        with pytest.raises(ValueError): CanonicalAlert.model_validate(data)


def test_hot_entity_capacity_and_input_order_stability(cfg):
    ss=settings(); records=[(ss.source_namespace,raw(str(i),host='h'+str(i))) for i in range(110)]
    idx=index_of(cfg,records,{ss.source_namespace:ss})
    a=generate_candidates(idx,cfg)
    b=generate_candidates(index_of(cfg,list(reversed(records)),{ss.source_namespace:ss}),cfg)
    assert a.pairs==b.pairs and not a.candidate_truncated
    assert len(a.pairs)<=110*cfg.algorithm.candidate.hot_entity_neighbors
    assert all(e.hot and e.admission_limit==10 for p in a.pairs for e in p.evidence if e.channel=='IP')
