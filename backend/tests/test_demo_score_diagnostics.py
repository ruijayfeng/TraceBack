"""Read-only production score diagnostics with synthetic and real receipt checks."""
from copy import deepcopy
import importlib.util
import json
import math
from pathlib import Path

import pytest
from app.api.score_diagnostics import ScoreAudit, stream_diagnostics, theoretical_config_max, theoretical_config_details, read_score_diagnostic, IMPLEMENTATION_PATHS
from app.correlation.scoring import CorrelationScorer
from app.services.storage import file_digest
from test_correlation_score import config, alert, inputs, parent_child, configured
from test_workbench import api
from test_api import create_run
from test_analysis_service import tripwire

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('task091',ROOT/'outputs/task09_1/run_diagnostics.py')
diagnostic=importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)


def row(pair,key=None):
    return dict(stage='member_score',support_key=key or sorted([pair.source_member_id,pair.target_member_id]),
        support_pair=[pair.source_member_id,pair.target_member_id],score=pair.score,raw_total=pair.raw_total,
        values=pair.values,contributions=pair.contributions,valid=pair.valid,rejection_codes=pair.rejection_codes,
        source_independence=pair.source_independence,evidence=pair.diagnostics)


def decision(r):
    return dict(stage='correlation_decision',support_key=r['support_key'],support_pair=r['support_pair'],
        score=r['score'],decision='accept' if r['score']>=.65 and r['valid'] else 'reject')


def test_config_max_includes_field_cardinality_and_frozen_mapping_gate(config):
    e=config.algorithm.entity
    complement=math.prod((1-w)**(2 if k=='IP' else 1) for k,w in e.weights.items() if k!='PROCESS')
    bound=1-complement*(1-e.weights['PROCESS']*e.role_factors.other_role)**2
    assert theoretical_config_max(config)==pytest.approx(.2+.3*bound+.2+.2)
    assert .65<theoretical_config_max(config)<1


def test_fixed_deployment_mapping_joint_bound_and_legal_synthetic_witness():
    from app.config import load_config
    from app.adapters import WazuhAdapter
    from test_wazuh_adapter import settings,synthetic_record
    cfg=load_config(ROOT/'configs/algorithm-v0.yaml',deployment_override=ROOT/'configs/sources.yaml')
    declaration=settings();adapter=WazuhAdapter(cfg,declaration)
    p=dict(pid=1,name='synthetic-p',start_time='2022-01-21T00:00:00Z')
    q=dict(pid=2,name='synthetic-q',start_time='2022-01-21T00:00:00Z')
    common=dict(host='synthetic-host',account='synthetic-account',session='synthetic-session',
                src_ip='192.0.2.1',dest_ip='192.0.2.2',dest_port=80,url='https://synthetic.invalid/op',
                file='/synthetic/file',command='synthetic-command',http={'hostname':'synthetic.invalid'})
    records=[synthetic_record(id=f'synthetic-{i}',rule={'id':str(i),'level':6,'groups':['authentication']},
        data={**common,'src_port':1000+i,'process':x,'parent_process':y}) for i,(x,y) in enumerate(((p,q),(q,p)))]
    records.extend(synthetic_record(id=f'background-{i}',data={'host':f'synthetic-background-{i}'}) for i in range(500))
    alerts=[adapter.convert(r) for r in records];idx,declarations=inputs(alerts,{declaration.source_namespace:declaration})
    scored=CorrelationScorer(idx,cfg,declarations).score_pair(*[a.alert_id for a in alerts[:2]])
    assert scored.valid and .65<scored.score<theoretical_config_max(cfg)
    assert scored.values['relation']==1 and scored.values['behavior']==.4
    assert scored.values['conflict']==scored.values['duplicate']==0
    assert all(f['role_factor']==cfg.algorithm.entity.role_factors.other_role for f in scored.diagnostics['entity_features'] if f['type']=='PROCESS')
    proof=theoretical_config_details(cfg)
    assert proof['normalization_categories']==['authentication','unknown']
    assert proof['normalization_behavior_max']==.4
    assert theoretical_config_max(cfg)==pytest.approx(.779999200378125)


def test_legal_production_fixture_above_threshold_and_decomposition(config):
    alerts=parent_child()+[alert(str(i),host=f'background-{i}') for i in range(100)]
    idx,settings=inputs(alerts)
    scorer=CorrelationScorer(idx,config,settings)
    pair=scorer.score_pair(*[a.alert_id for a in alerts[:2]])
    assert pair.valid and pair.score>.65
    audit=ScoreAudit(config);r=row(pair);audit.member(r);audit.decision(decision(r));result=audit.result()
    assert result['observed_max']==pair.score
    assert result['passed_threshold_count']==1
    assert sum(r['contributions'].values())==pair.raw_total==pair.score
    assert result['threshold_gap']==0


def test_top_n_order_gap_and_no_featurewise_invented_max(config):
    alerts=[alert('a',host='h',account='u'),alert('b',10,host='h',account='u'),alert('c',1,host='h')]
    idx,settings=inputs(alerts);scorer=CorrelationScorer(idx,config,settings)
    rows=[row(scorer.score_pair(a.alert_id,b.alert_id)) for a,b in [(alerts[0],alerts[1]),(alerts[0],alerts[2]),(alerts[1],alerts[2])]]
    audit=ScoreAudit(config,top_n=2)
    for r in reversed(rows): audit.member(r);audit.decision(decision(r))
    result=audit.result();expected=sorted(rows,key=lambda r:(-r['score'],r['support_key']))[:2]
    assert result['top_candidates']==expected
    assert result['observed_max']==max(r['score'] for r in rows)
    assert result['threshold_gap']==.65-result['observed_max']
    assert result['observed_max']<sum(max(r['contributions'][k] for r in rows) for k in rows[0]['contributions'])


def test_stream_rejects_bad_winner_or_decomposition(config,tmp_path):
    idx,settings=inputs([alert('a',host='h'),alert('b',1,host='h')])
    r=row(CorrelationScorer(idx,config,settings).score_pair(*idx.alerts))
    p=tmp_path/'diagnostics.jsonl'
    p.write_text(json.dumps(r,separators=(',',':'))+'\n'+json.dumps(decision(r),separators=(',',':'))+'\n',encoding='utf-8')
    before=file_digest(p)
    result=stream_diagnostics(p,config)
    assert file_digest(p)==before and result['scored_candidate_count']==1
    bad=deepcopy(r);bad['raw_total']+=.1
    with pytest.raises(ValueError,match='decomposition'):ScoreAudit(config).member(bad)


def test_counterfactual_production_and_snapshot_remain_unchanged(config):
    alerts=[alert('a',category='authentication',host='h',account='u',session='s'),
            alert('b',category='authentication',host='h',account='u',session='s')]
    alerts.extend(alert(str(i),host=f'h-{i}') for i in range(200))
    idx,settings=inputs(alerts);scorer=CorrelationScorer(idx,config,settings)
    ids=[a.alert_id for a in alerts[:2]];before={i:a.canonical_json() for i,a in idx.alerts.items()}
    pair=scorer.score_pair(*ids)
    cf=diagnostic.counterfactual(scorer,row(pair))
    assert cf['status']=='verified_hypothetical' and cf['hypothetical_score']>.65
    assert cf['values']['relation']==.9 and cf['contribution_delta']==pytest.approx(.18)
    assert before=={i:a.canonical_json() for i,a in idx.alerts.items()}
    assert scorer.score_pair(*ids).score==pair.score and not cf['production_writes']


def test_unpruned_oracle_obeys_cooccurrence(config):
    alerts=[alert('a',category='authentication',host='h',account='u'),alert('b',category='authentication',host='h',account='u'),
            alert('c',session='s',host='other'),alert('d',session='s',host='other')]
    alerts.extend(alert(str(i),host=f'background-{i}') for i in range(50))
    idx,settings=inputs(alerts);scorer=CorrelationScorer(idx,config,settings)
    oracle=max(scorer.score_pair(a,b).score for i,a in enumerate(idx.alerts) for b in list(idx.alerts)[i+1:] if set(idx.alerts[a].entity_ids)&set(idx.alerts[b].entity_ids))
    result=diagnostic.reachable(scorer,oracle-.01)
    assert result['status']=='exact' and result['max']==oracle


def test_diagnostic_get_is_readonly_no_production_calls(api,monkeypatch):
    client,app,root=api;aid=create_run(api,[alert_record()])
    paths=[p for folder in (root/'data/processed'/aid,root/'outputs/analyses'/aid) for p in folder.glob('*') if p.is_file()]
    before={p:file_digest(p) for p in paths};tripwire(monkeypatch)
    def forbidden(*a,**kw):raise AssertionError('production scoring must not run in GET')
    monkeypatch.setattr(CorrelationScorer,'score_pair',forbidden)
    response=client.get(f'/api/v1/analyses/{aid}/score-diagnostics')
    assert response.status_code==200 and response.json()['status']=='unavailable'
    assert client.get(f'/api/v1/analyses/{aid}/score-diagnostics?other=1').status_code==400
    assert before=={p:file_digest(p) for p in paths}


def alert_record():
    from test_wazuh_adapter import synthetic_record
    return synthetic_record()


@pytest.mark.parametrize('tamper',['none','analysis','config','diagnostics','implementation_path','implementation_digest'])
def test_receipt_scope_integrity_and_readonly_get(api,monkeypatch,tamper):
    client,app,root=api;aid=create_run(api,[alert_record()]);q=app.state.queries;store=q.ready(aid)
    for name in IMPLEMENTATION_PATHS:
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes((ROOT/name).read_bytes())
    manifest=json.loads((store.details/'manifest.json').read_text(encoding='utf-8'))
    data=dict(analysis_id=aid,config_hash=manifest['config_hash'],snapshot_manifest_sha256=file_digest(store.details/'manifest.json'),
        diagnostics_sha256=manifest['diagnostics_digest'],diagnostic_implementation_hashes={p:file_digest(root/p) for p in IMPLEMENTATION_PATHS})
    if tamper=='analysis':data['analysis_id']='wrong'
    elif tamper=='config':data['config_hash']='0'*64
    elif tamper=='diagnostics':data['diagnostics_sha256']='0'*64
    elif tamper=='implementation_path':data['diagnostic_implementation_hashes']['../outside']='0'*64
    elif tamper=='implementation_digest':data['diagnostic_implementation_hashes'][IMPLEMENTATION_PATHS[0]]='0'*64
    path=root/'outputs/task09_1'/aid/'score_diagnostics.json';path.parent.mkdir(parents=True);path.write_text(json.dumps(data),encoding='utf-8')
    before={p:file_digest(p) for folder in (store.domain,store.details) for p in folder.glob('*') if p.is_file()}
    tripwire(monkeypatch)
    monkeypatch.setattr(CorrelationScorer,'score_pair',lambda *a,**k:pytest.fail('GET called production scorer'))
    response=client.get(f'/api/v1/analyses/{aid}/score-diagnostics')
    assert response.status_code==(200 if tamper=='none' else 409)
    assert before=={p:file_digest(p) for p in before}
