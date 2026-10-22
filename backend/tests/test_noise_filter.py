"""Synthetic evidence controls and real downstream isolation; no protected data."""
from pathlib import Path
import gzip
import importlib
import json
import shutil
import sys

import pytest
from pydantic import ValidationError

from app.adapters.multisource import MultiSourceAdapter
from app.community import prepare_communities
from app.evidence_trace import EvidenceTraceIndex
from app.noise_filter import NoiseAuditRecord, NoiseFilterConfig, filter_alerts, load_noise_config, resolve_raw_evidence
from app.stage_chains import StageGraphSnapshot, assemble_attack_chains, validate_assembly
from app.stage_relations import analyze_stage_relations, load_relation_config
from app.stages import aggregate_stages, load_stage_config
from test_community_builder import cfg, normalization, record
from test_source_bound_projection import settings

ROOT = Path(__file__).resolve().parents[2]


def canonical(rows, normalization):
    sources = {s:settings(s) for s in {r['source_type'] for r in rows}}
    alerts = [MultiSourceAdapter(normalization, sources[r['source_type']], r['source_type']).convert(r) for r in rows]
    return alerts, {s.source_namespace:s for s in sources.values()}


def duplicates(n=10, **extra):
    return [record('same-native-observation', time=i/10, hostname='h', operation='CommandExecution',
                   command_line='whoami', **extra) for i in range(n)]


def test_ten_duplicates_have_one_representative_and_full_raw_archive(normalization):
    alerts, _ = canonical(duplicates(), normalization)
    before = [a.canonical_json() for a in alerts]
    result = filter_alerts(alerts)
    assert result.statistics == dict(INPUT_ALERTS=10, KEPT_ALERTS=1, REMOVED_ALERTS=9,
        NOISE_REDUCTION_RATE=0.9, DUPLICATE_NOISE_COUNT=9, KNOWN_BACKGROUND_NOISE_COUNT=0, INVALID_NOISE_COUNT=0)
    assert result.kept_alerts == [alerts[0]]
    assert {a.duplicate_count for a in result.audit_records} == {10}
    assert len({a.duplicate_group_id for a in result.audit_records}) == 1
    assert {a.representative_alert_id for a in result.audit_records} == {alerts[0].alert_id}
    for audit in result.audit_records:
        assert result.raw_evidence(audit) == alerts[audit.input_index].raw_alert
        assert NoiseAuditRecord.model_validate_json(audit.model_dump_json()) == audit
    assert [a.canonical_json() for a in alerts] == before
    reverse = filter_alerts(reversed(alerts))
    assert reverse.kept_alerts == result.kept_alerts
    assert {a.duplicate_group_id for a in reverse.audit_records} == {a.duplicate_group_id for a in result.audit_records}


@pytest.mark.parametrize('changes', [dict(hostname='other'), dict(dst_ip='192.0.2.9'),
    dict(timestamp='2026-01-01T00:00:10Z'), dict(request_id='other'), dict(process_id=99),
    dict(command_line='id'), dict(event_id='different-observation'), dict(extra_security_detail='new')])
def test_similar_observations_are_not_duplicates(changes, normalization):
    first = duplicates(1, dst_ip='192.0.2.2')[0]
    alerts, _ = canonical([first, dict(first, **changes)], normalization)
    assert filter_alerts(alerts).statistics['KEPT_ALERTS'] == 2


def test_window_is_bounded_by_representative_not_transitive(normalization):
    rows = [dict(duplicates(1)[0], timestamp=record(1,time=t)['timestamp']) for t in (0,1.5,3)]
    alerts, _ = canonical(rows, normalization)
    r = filter_alerts(alerts)
    assert r.statistics['KEPT_ALERTS'] == 2
    assert sorted(a.duplicate_count or 1 for a in r.audit_records) == [1,2,2]


def background_policy(match=None, **extra):
    return NoiseFilterConfig.model_validate(dict(background_rules=[dict(rule_id='declared-healthcheck',
        match=match or dict(source_type='edr', host='h', alert_type='CommandExecution'), **extra)]))


@pytest.mark.parametrize('field,value', [('source_type','edr'), ('source_namespace','sensor.edr'),
    ('alert_type','CommandExecution'), ('host','h'), ('process','probe'), ('path','/opt/probe'),
    ('src_ip','192.0.2.1'), ('dst_ip','192.0.2.2')])
def test_background_exact_fields_and_nonmatch(field, value, normalization):
    rows = [record('health', hostname='h', operation='CommandExecution', process_name='probe',
        file_path='/opt/probe', src_ip='192.0.2.1',dst_ip='192.0.2.2')]
    alerts, _ = canonical(rows, normalization)
    match = dict(source_type='edr', host='h', **{field:value}) if field not in ('source_type','host') else dict(source_type='edr',host='h')
    policy = background_policy(match)
    r = filter_alerts(alerts, policy)
    assert r.audit_records[0].reason_code == 'KNOWN_BACKGROUND_NOISE'
    assert r.audit_records[0].rule_id == 'declared-healthcheck'
    assert r.statistics['KNOWN_BACKGROUND_NOISE_COUNT'] == 1
    match[field] = 'not-a-match'
    assert filter_alerts(alerts, background_policy(match)).kept_alerts == alerts


@pytest.mark.parametrize('field,value', [('signature','SQL injection pattern'), ('rule_id','942100')])
def test_signature_and_rule_background_fields(field,value,normalization):
    alerts,_ = canonical([record(1,'waf',server_host='h',rule_id='942100',rule_name='SQL injection pattern')],normalization)
    r = filter_alerts(alerts,background_policy(dict(source_type='waf',**{field:value})))
    assert r.statistics['REMOVED_ALERTS'] == 1


def test_time_patterns_are_UTC_and_overnight_weekday_is_start_day(normalization):
    base = duplicates(1)[0]
    rows = [dict(base,timestamp=t) for t in ('2026-01-05T23:30:00Z','2026-01-06T00:30:00Z','2026-01-06T23:30:00Z')]
    alerts,_=canonical(rows,normalization)
    policy=background_policy(time_pattern=dict(weekdays=[0],start='23:00:00',end='01:00:00'))
    r=filter_alerts(alerts,policy)
    assert [a.keep for a in r.audit_records] == [False,False,True]
    day=background_policy(time_pattern=dict(weekdays=[0],start='23:00:00',end='23:59:59'))
    assert filter_alerts(alerts,day).statistics['REMOVED_ALERTS'] == 1


@pytest.mark.parametrize('policy', [dict(background_rules=[dict(rule_id='bad',match={})]),
    dict(background_rules=[dict(rule_id='bad',match=dict(source_type='edr'))]),
    dict(background_rules=[dict(rule_id='bad',match=dict(source_type='edr',source_namespace='sensor.edr'))]),
    dict(background_rules=[dict(rule_id='bad',match=dict(severity='low',source_type='edr'))]),
    dict(duplicate_window_seconds=-1), dict(unknown_option=True)])
def test_policy_rejects_empty_broad_and_unknown_rules(policy):
    with pytest.raises(ValidationError): NoiseFilterConfig.model_validate(policy)


def test_yaml_duplicate_keys_are_rejected_by_existing_config_loader(tmp_path):
    from app.config import ConfigurationError
    policy=tmp_path/'noise.yaml'
    policy.write_text('version: noise-filter-v1\nbackground_rules: []\nbackground_rules: []\n',encoding='utf8')
    with pytest.raises(ConfigurationError,match='unique'):
        load_noise_config(policy)


def test_missing_optional_fields_low_severity_unknown_and_isolated_IP_are_kept(normalization):
    rows=[record(1),record(2,src_ip='192.0.2.1',severity='low'),record(3,hostname='alone')]
    alerts,_=canonical(rows,normalization)
    assert filter_alerts(alerts).statistics['KEPT_ALERTS'] == 3
    assert not load_noise_config().background_rules


@pytest.mark.parametrize('update', [dict(timestamp=None),dict(source_namespace=''),dict(source_type=None),dict(field_provenance={})])
def test_only_broken_canonical_contract_is_invalid(update,normalization):
    alerts,_=canonical(duplicates(1),normalization)
    broken=alerts[0].model_copy(update=update)
    r=filter_alerts([broken])
    assert r.audit_records[0].reason_code == 'INVALID_FOR_RECONSTRUCTION'
    assert r.statistics['INVALID_NOISE_COUNT'] == 1
    assert r.raw_evidence(r.audit_records[0]) == alerts[0].raw_alert


def test_repeated_imports_are_accounted_individually_and_empty_is_valid(normalization):
    alerts,_=canonical([record(1)],normalization)
    r=filter_alerts(alerts*10)
    assert r.statistics['INPUT_ALERTS'] == 10 and r.statistics['KEPT_ALERTS'] == 1
    assert all(a.duplicate_count == 10 for a in r.audit_records)
    assert filter_alerts([]).statistics['NOISE_REDUCTION_RATE'] == 0


def test_removed_alerts_never_reach_real_binding_community_stage_relation_or_chain(cfg,normalization,monkeypatch):
    rows=duplicates()+[record('background',hostname='health',operation='CommandExecution'),
        record('child',time=5,hostname='h',parent_event_id='same-native-observation',operation='FileWrite',file_path='/tmp/x')]
    alerts,sources=canonical(rows,normalization)
    # Include a malformed model at the canonical boundary, while keeping raw intact.
    alerts.append(alerts[-1].model_copy(update=dict(timestamp=None)))
    policy=background_policy(dict(source_type='edr',host='health'))
    import app.community.builder as builder
    real_extract=builder.extract_entities
    seen=[]
    def extraction(aa,*args,**kwargs):
        seen.extend(a.alert_id for a in aa)
        return real_extract(aa,*args,**kwargs)
    monkeypatch.setattr(builder,'extract_entities',extraction)
    # Use a distinct alert identity for invalid input to avoid conflicting ID protection.
    alerts[-1]=alerts[-1].model_copy(update=dict(alert_id='alt_'+'f'*64))
    run=prepare_communities(alerts,sources,cfg,noise_config=policy)
    noise=run.noise_filter
    removed={a.alert_id for a in noise.audit_records if not a.keep}
    kept={a.alert_id for a in run.alerts}
    assert len(kept)==2 and removed.isdisjoint(kept)
    assert set(seen)==kept
    assert {a for e in run.entities for a in e.alert_ids} <= kept
    assert {a for c in run.result.incident_candidates for a in c.alert_ids} == kept
    stages=aggregate_stages(run,sources,cfg,load_stage_config(ROOT/'configs/behavior-stage-v1.yaml'))
    assert {a for s in stages.stages for a in s.alert_ids} == kept
    relations=analyze_stage_relations(stages,run.alerts,run.entities,run.result.incident_candidates,sources,cfg,
        load_relation_config(ROOT/'configs/stage-relations-v1.yaml'))
    assert relations.relations  # Exercise actual relation and chain evidence.
    assert {a for r in relations.relations for a in r.witness_alert_ids} <= kept
    index=EvidenceTraceIndex('ana_'+'b'*64,run.alerts,stages.stages,stages.behaviors,relations.relations)
    traces=[index.stage_trace(s) for s in index.stage_ids]+[index.relation_trace(r) for r in index.relation_ids]
    graph=StageGraphSnapshot(stages.stages,relations.relations,traces,index)
    chains=assemble_attack_chains(graph)
    assert chains.chains and validate_assembly(chains,graph).valid
    for chain in chains.chains:
        trace=graph.chain_trace(chain)
        assert {a for t in trace.stage_traces+trace.relation_traces for a in t.witness_alert_ids} <= kept
    assert noise.statistics['INPUT_ALERTS']==noise.statistics['KEPT_ALERTS']+noise.statistics['REMOVED_ALERTS']
    assert all(noise.raw_evidence(a)==alerts[a.input_index].raw_alert for a in noise.audit_records)


def test_all_removed_produces_empty_downstream_without_losing_audit(cfg,normalization):
    alerts,sources=canonical(duplicates(1),normalization)
    run=prepare_communities(alerts,sources,cfg,noise_config=background_policy())
    assert not run.alerts and not run.entities and not run.result.incident_candidates
    stage=aggregate_stages(run,sources,cfg,load_stage_config(ROOT/'configs/behavior-stage-v1.yaml'))
    assert not stage.stages
    assert run.noise_filter.raw_evidence(run.noise_filter.audit_records[0])


@pytest.mark.parametrize('entry',['community','stage'])
def test_public_snapshot_exports_seal_full_noise_archive_and_only_kept_members(entry,tmp_path,monkeypatch):
    sys.path.insert(0,str(ROOT/'scripts'))
    community=importlib.import_module('run_community_builder')
    stage=importlib.import_module('run_stage_aggregation')
    from app.ai.provider import ProviderConfig
    # Reproduce real script exports inside a wholly separate synthetic root.
    shutil.copytree(ROOT/'configs',tmp_path/'configs',ignore=shutil.ignore_patterns('llm*.yaml'))
    (tmp_path/'scripts').mkdir()
    for name in ('run_community_builder.py','run_stage_aggregation.py'):
        shutil.copyfile(ROOT/'scripts'/name,tmp_path/'scripts'/name)
    monkeypatch.setattr(community,'ROOT',tmp_path)
    monkeypatch.setattr(stage,'ROOT',tmp_path)
    rows=duplicates(3)+[record('background',hostname='health',operation='CommandExecution'),
        record('child',time=5,hostname='h',parent_event_id='same-native-observation',operation='FileWrite')]
    source=tmp_path/'native.jsonl'
    source.write_text(''.join(json.dumps(dict(source_type='edr',event=r))+'\n' for r in rows),encoding='utf8')
    # JSON is a valid YAML document, loaded through the public policy loader.
    policy=tmp_path/'background.yaml'
    policy.write_text(background_policy(dict(source_type='edr',host='health')).model_dump_json(),encoding='utf8')
    out=tmp_path/'outputs'/entry
    if entry=='community':
        manifest=community.execute(source,out,tmp_path/'configs/front-data-profiles.yaml',
            tmp_path/'configs/algorithm-v5-evidence-semantics.yaml',tmp_path/'configs/community-v1.yaml',noise_policy_path=policy)
    else:
        manifest=stage.execute(source,out,provider_config=ProviderConfig(),noise_policy_path=policy)
    domain=tmp_path/'data/processed'/manifest['analysis_id']
    def read(name):
        with gzip.open(domain/name,'rt',encoding='utf8') as stream:
            return [json.loads(line) for line in stream]
    audits=[NoiseAuditRecord.model_validate(v) for v in read('noise_audit.jsonl.gz')]
    assert len(read('noise_source_alerts.jsonl.gz'))==len(audits)==5
    assert sum(a.keep for a in audits)==2
    assert all(resolve_raw_evidence(domain/'noise_source_alerts.jsonl.gz',a)==rows[a.input_index] for a in audits)
    filtered_name='community_alerts.jsonl.gz' if entry=='community' else 'stage_source_alerts.jsonl.gz'
    kept={a['alert_id'] for a in read(filtered_name)}
    removed={a.alert_id for a in audits if not a.keep}
    assert len(kept)==2 and kept.isdisjoint(removed)
    assert manifest['summary']['INPUT_ALERTS']==5
    assert manifest['summary']['KEPT_ALERTS']==2 and manifest['summary']['REMOVED_ALERTS']==3
    assert manifest['config_snapshot']['noise_filter']['background_rules']
    for relative,digest in manifest['artifacts'].items():
        assert community.sha(tmp_path/relative)==digest
    assert source.read_text(encoding='utf8').count('\n')==5


def test_invalid_archive_still_resolves_and_tampering_is_rejected(normalization,tmp_path):
    alerts,_=canonical(duplicates(1),normalization)
    broken=alerts[0].model_copy(update=dict(timestamp=None))
    r=filter_alerts([broken])
    path=tmp_path/'noise_source_alerts.jsonl.gz'
    with gzip.open(path,'wt',encoding='utf8') as stream:
        stream.write(broken.model_dump_json()+'\n')
    assert resolve_raw_evidence(path,r.audit_records[0])==alerts[0].raw_alert
    row=broken.model_dump(mode='json')
    row['raw_alert']['command_line']='tampered'
    with gzip.open(path,'wt',encoding='utf8') as stream: stream.write(json.dumps(row)+'\n')
    with pytest.raises(ValueError,match='archive_mismatch'):
        resolve_raw_evidence(path,r.audit_records[0])
