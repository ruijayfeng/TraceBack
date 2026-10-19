"""Production acceptance against the unchanged independent Full pipeline."""

from dataclasses import asdict
import json
from pathlib import Path

import pytest

from app.adapters.base import AdapterSettings
from app.config import load_config
from app.correlation.edges import run_correlation
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.dedup.grouping import deduplicate
from app.entities.extraction import extract_entities
from app.incidents.clustering import cluster_incidents
from app.incidents.triage import triage_singletons
from app.services.incremental import IncrementalService, pair_key
from app.services.storage import SnapshotStore
from app.services.incremental_dependencies import json_value
from app.utils.stable_id import canonical_json
from test_correlation_score import alert, parent_child

ROOT=Path(__file__).resolve().parents[2]


def configuration():
    return load_config(ROOT/'configs/algorithm-v3.yaml')


def settings(alerts):
    return {a.source_namespace:AdapterSettings(a.source_namespace,'synthetic','synthetic') for a in alerts}


def full(alerts,cfg,source):
    groups=deduplicate(alerts,cfg,source).groups
    extracted=extract_entities(alerts,source)
    outcomes={}
    def capture(row):
        if row['stage']=='correlation_decision':
            outcomes[pair_key(row['support_key'])]=row
    cor=run_correlation(extracted.alerts,groups,extracted.entities,cfg,source,diagnostic_sink=capture)
    cor.outcomes=outcomes
    idx=AlertIndex(extracted.alerts,groups,extracted.entities)
    sc=CorrelationScorer(idx,cfg,source,cor.record.config_hash)
    clustered=cluster_incidents(idx,cor.edges,sc)
    incidents=triage_singletons(clustered.incidents,idx,cfg,cor.summary,search_complete=cor.record.is_complete)
    from app.chains.assembly import assemble_chain
    edge_map={e.edge_id:e for e in cor.edges}
    chains=[assemble_chain(i,idx,sc,[edge_map[k] for k in i.correlation_edge_ids],support_cache=clustered.support_cache)
        for i in incidents]
    return dict(alerts=extracted.alerts, dedupe_groups=groups, entities=extracted.entities,
        correlation_edges=cor.edges, incidents=incidents,attack_chains=chains),cor


def assert_equivalent(service,alerts,cfg,source):
    expected,cor=full(alerts,cfg,source)
    actual=service.records()
    for kind,rows in expected.items():
        left=sorted(canonical_json(row) for row in actual[kind])
        right=sorted(row.canonical_json() for row in rows)
        assert left==right,kind
    expected_pairs={pair_key(p.support_key):p for p in cor.candidates.pairs}
    assert actual['candidates'].keys()==expected_pairs.keys()
    for key,pair in expected_pairs.items():
        state=actual['candidates'][key]
        assert canonical_json(json_value(state['priority']))==canonical_json(json_value(pair.priority))
        assert state['channels']==list(pair.channels)
        assert canonical_json(state['evidence'])==canonical_json([e.json_data() for e in pair.evidence])
        outcome=cor.outcomes[key]
        assert state['unrounded_score']==outcome['score']
        assert state['support_pair']==outcome['support_pair']
        assert bool(state['edge_id'])==(outcome['decision']=='accept')
        if cfg.algorithm.version in {'v2','v3'}:
            assert state['gate_passed']==outcome['evidence_gate_passed']
            assert state['decision']==outcome['evidence_decision']
    return cor


def test_fixture_b_historical_merge_without_delta_candidate(tmp_path):
    from test_incremental_dependency_audit import audit
    base,delta=audit.synthetic_inputs()
    cfg,source=configuration(),settings(base+delta)
    service=IncrementalService(tmp_path/'workspace.duckdb',cfg,source)
    try:
        service.bootstrap(base)
        receipt=service.increment(delta)
        assert_equivalent(service,base+delta,cfg,source)
        stats=receipt['stats']
        assert stats['direct_delta_neighbors']==1
        assert stats['historical_pairs_rescored']==1
        assert stats['incidents_merged']==1
        assert stats['dependency_only_affected_representatives']==1000
    finally:
        service.close()


def test_fixture_a_hot_transition_and_historical_candidates(tmp_path):
    from test_incremental_dependency_audit import audit
    base,delta=audit.synthetic_inputs(hot=True)
    cfg,source=configuration(),settings(base+delta)
    service=IncrementalService(tmp_path/'workspace.duckdb',cfg,source)
    try:
        service.bootstrap(base)
        receipt=service.increment(delta)
        assert_equivalent(service,base+delta,cfg,source)
        assert receipt['stats']['hot_state_transition_count']==1
        assert receipt['stats']['historical_candidates_added']==2310
    finally:
        service.close()


def test_restart_idempotency_publication_and_transaction_rollback(tmp_path):
    base=parent_child()+[alert('untouched',86400)]
    delta=[alert('delta',172800)]
    cfg,source=configuration(),settings(base+delta)
    path=tmp_path/'workspace.duckdb'
    service=IncrementalService(path,cfg,source,snapshot_root=tmp_path/'snapshots')
    before=service.bootstrap(base)
    parent=SnapshotStore(tmp_path/'snapshots',before['analysis_id'])
    parent_bytes=(parent.details/'manifest.json').read_bytes()
    def crash(stage):
        if stage=='table:formal_edges':
            raise RuntimeError('injected')
    with pytest.raises(RuntimeError,match='injected'):
        service.increment(delta,fault=crash)
    assert service.store.head()['generation_id']==before['generation_id']
    service.close()
    service=IncrementalService(path,cfg,source,snapshot_root=tmp_path/'snapshots')
    receipt=service.increment(delta)
    assert_equivalent(service,base+delta,cfg,source)
    assert service.increment(delta)['idempotent_replay']
    assert service.increment([])['stats']['candidate_pairs_scored']==0
    assert (parent.details/'manifest.json').read_bytes()==parent_bytes
    derived=SnapshotStore(tmp_path/'snapshots',receipt['analysis_id'])
    _,_,manifest=derived.read_metadata()
    assert manifest['incremental_generation']['parent_analysis_id']==before['analysis_id']
    from app.services.queries import QueryService
    query=QueryService(tmp_path/'snapshots')
    assert query.analysis(receipt['analysis_id'])['status']=='completed'
    assert query.get(receipt['analysis_id'],'alerts',delta[0].alert_id).alert_id==delta[0].alert_id
    assert len(list(derived.read_records('alerts',parquet=True)))==4
    assert derived.validate_reconstruction().valid
    service.close()


@pytest.mark.parametrize('crash_at',['after_commit','before_publication'])
def test_restart_recovers_committed_unpublished_generation(tmp_path,crash_at):
    base,delta=[alert('a',host='h')],[alert('b',1,host='h')]
    cfg,source=configuration(),settings(base+delta)
    path=tmp_path/'workspace.duckdb'
    service=IncrementalService(path,cfg,source,snapshot_root=tmp_path/'snapshots')
    service.bootstrap(base)
    def crash(stage):
        if stage==crash_at:
            raise RuntimeError('injected')
    with pytest.raises(RuntimeError):
        service.increment(delta,fault=crash)
    identity=service.store.head()['analysis_id']
    service.close()
    service=IncrementalService(path,cfg,source,snapshot_root=tmp_path/'snapshots')
    assert_equivalent(service,base+delta,cfg,source)
    SnapshotStore(tmp_path/'snapshots',identity).read_metadata()
    assert service.increment(delta)['idempotent_replay']
    service.close()


def test_truly_unaffected_incident_never_replayed(tmp_path,monkeypatch):
    base=[alert('a',host='h'),alert('b',1,host='h'),alert('quiet',86400)]
    delta=[alert('delta',172800)]
    cfg,source=configuration(),settings(base+delta)
    service=IncrementalService(tmp_path/'workspace.duckdb',cfg,source)
    service.bootstrap(base)
    from app import services
    import app.services.incremental as module
    original=module.cluster_incidents
    replayed=[]
    def observe(index,*args,**kwargs):
        replayed.extend(index.representatives)
        return original(index,*args,**kwargs)
    monkeypatch.setattr(module,'cluster_incidents',observe)
    receipt=service.increment(delta)
    assert base[2].alert_id not in replayed
    assert_equivalent(service,base+delta,cfg,source)
    assert receipt['stats']['incident_representatives_replayed']<=3
    service.close()


def test_topk_both_endpoints_budget_and_multi_batch_permutations(tmp_path):
    from app.services.storage import restore_config
    snapshot=configuration().snapshot
    snapshot['candidate'].update(per_channel_neighbors=2,max_neighbors_per_alert=2,max_candidate_pairs=4)
    cfg=restore_config(snapshot)
    alerts=[alert('n'+str(i),i*3,host='shared',rule_id=str(i)) for i in range(10)]
    source=settings(alerts)
    service=IncrementalService(tmp_path/'workspace.duckdb',cfg,source)
    try:
        service.bootstrap(alerts[:4])
        for end in (6,8,10):
            service.increment(list(reversed(alerts[end-2:end])))
            assert_equivalent(service,alerts[:end],cfg,source)
        assert service.head['record']['status']=='incomplete'
    finally:
        service.close()


def test_representative_mutation_replays_complete_duplicate_component(tmp_path):
    cfg=configuration()
    duplicates=[alert(name,host='h',account='u',origin_namespace='upstream',origin_record_id='same')
        for name in ('a','b','c')]
    duplicates.sort(key=lambda a:a.alert_id,reverse=True)
    neighbor=alert('neighbor',1,host='h',account='u')
    source=settings(duplicates+[neighbor])
    service=IncrementalService(tmp_path/'workspace.duckdb',cfg,source)
    try:
        service.bootstrap([duplicates[0],neighbor])
        service.increment([duplicates[1]])
        service.increment([duplicates[2]])
        assert_equivalent(service,duplicates+[neighbor],cfg,source)
        group=next(iter(service.records()['dedupe_groups']))
        assert group['representative_alert_id']==duplicates[2].alert_id
        assert len(group['alert_ids'])==3
    finally:
        service.close()


def test_historical_only_incident_split_after_frequency_change(tmp_path):
    from test_incremental_dependency_audit import audit
    base,delta=audit.synthetic_inputs()
    late=[alert('df-change',259200,host='h',account='u',rule_id='df-change')]
    cfg,source=configuration(),settings(base+delta+late)
    service=IncrementalService(tmp_path/'workspace.duckdb',cfg,source)
    try:
        service.bootstrap(base)
        service.increment(delta)
        receipt=service.increment(late)
        assert_equivalent(service,base+delta+late,cfg,source)
        assert receipt['stats']['incidents_split']==1
        assert receipt['stats']['historical_pairs_rescored']==1
    finally:
        service.close()


def test_increment_cannot_call_full_entry_points(tmp_path,monkeypatch):
    cfg=configuration()
    base=parent_child()
    delta=[alert('new',172800)]
    source=settings(base+delta)
    service=IncrementalService(tmp_path/'workspace.duckdb',cfg,source)
    service.bootstrap(base)
    def forbidden(*args,**kwargs):
        raise AssertionError('silent_full_fallback')
    from app.services.analysis import AnalysisService
    import app.correlation.edges as edges
    import app.chains.assembly as assembly
    monkeypatch.setattr(AnalysisService,'_execute',forbidden)
    monkeypatch.setattr(edges,'run_correlation',forbidden)
    monkeypatch.setattr(assembly,'run_reconstruction',forbidden)
    service.increment(delta)
    service.close()


def test_nearest_boundary_avoids_historical_endpoint_retrieval(tmp_path):
    from app.services.storage import restore_config
    snapshot=configuration().snapshot
    snapshot['candidate'].update(per_channel_neighbors=2,max_neighbors_per_alert=2)
    cfg=restore_config(snapshot)
    base=[alert('dense'+str(i),i,host='h',rule_id=str(i)) for i in range(30)]
    delta=[alert('late',400,host='h',rule_id='late')]
    source=settings(base+delta)
    service=IncrementalService(tmp_path/'workspace.duckdb',cfg,source)
    try:
        service.bootstrap(base)
        receipt=service.increment(delta)
        assert receipt['stats']['candidate_proposals_replayed']<receipt['stats']['direct_delta_neighbors']
        assert_equivalent(service,base+delta,cfg,source)
    finally:
        service.close()


@pytest.mark.parametrize('version',['v0','v2','v3'])
def test_randomized_batches_match_full_with_all_entity_types(tmp_path,version):
    import random
    rng=random.Random(402)
    cfg=load_config(ROOT/f'configs/algorithm-{version}.yaml')
    rows=[]
    for number in range(36):
        group=number%6
        values={name:value for name,value in {'host':f'h{group}', 'account':f'u{group}',
            'session':f's{group}', 'src_ip':f'10.0.0.{group+1}', 'dst_ip':f'10.0.0.{group+11}',
            'domain':f'd{group}.example', 'url':f'/r{group}', 'file':f'/f{group}',
            'command':f'command{group}', 'process':{'name':f'proc{group}'}}.items() if rng.random()<.6}
        rows.append(alert('random'+str(number),number*23,rule_id=str(number%4),**values))
    rng.shuffle(rows)
    source=settings(rows)
    service=IncrementalService(tmp_path/'workspace.duckdb',cfg,source)
    try:
        service.bootstrap(rows[:12])
        for end in (20,28,36):
            service.increment(rows[end-8:end])
            assert_equivalent(service,rows[:end],cfg,source)
    finally:
        service.close()


def test_adapter_delta_ingestion_and_ground_truth_tripwire(tmp_path,monkeypatch):
    from app.adapters import WazuhAdapter
    from test_wazuh_adapter import settings as wazuh_settings, synthetic_record
    from test_analysis_service import tripwire
    cfg=load_config(ROOT/'configs/algorithm-v3.yaml',deployment_override=ROOT/'configs/sources.yaml')
    setting=wazuh_settings()
    source={setting.source_namespace:setting}
    adapter=WazuhAdapter(cfg,setting)
    path=tmp_path/'data/input/alerts/delta.jsonl'
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(synthetic_record(id='b'))+'\n',encoding='utf-8')
    base=adapter.convert(synthetic_record(id='a'))
    service=IncrementalService(tmp_path/'workspace.duckdb',cfg,source,snapshot_root=tmp_path)
    try:
        reads=tripwire(monkeypatch)
        service.bootstrap([base])
        service.ingest([('wazuh',path)],{'wazuh':adapter})
        assert reads
        assert len(service.records()['alerts'])==2
        contaminated=synthetic_record(id='c')
        contaminated['ground_truth']='forbidden'
        path.write_text(json.dumps(contaminated)+'\n',encoding='utf-8')
        with pytest.raises(ValueError,match='rejected_input'):
            service.ingest([('wazuh',path)],{'wazuh':adapter})
    finally:
        service.close()


@pytest.mark.parametrize('stage',['table:formal_edges','before_commit','after_commit','before_publication',
    'after_domain_publication','after_manifest_publication'])
def test_actual_process_exit_and_duckdb_wal_recovery(tmp_path,stage):
    import subprocess
    import sys
    cfg=configuration()
    base=[alert('base',host='h')]
    delta=[alert('crashdelta',1,host='h')]
    source=settings(base+delta)
    path=tmp_path/'workspace.duckdb'
    root=tmp_path/'snapshots'
    service=IncrementalService(path,cfg,source,snapshot_root=root)
    before=service.bootstrap(base)
    service.close()
    code=f'''import os,sys
sys.path.insert(0,{str(ROOT/'backend')!r})
sys.path.insert(0,{str(ROOT/'backend/tests')!r})
from test_incremental_correlation import configuration,settings
from test_correlation_score import alert
from app.services.incremental import IncrementalService
base=[alert('base',host='h')]
delta=[alert('crashdelta',1,host='h')]
service=IncrementalService({str(path)!r},configuration(),settings(base+delta),snapshot_root={str(root)!r})
def crash(point):
    if point=={stage!r}: os._exit(73)
service.increment(delta,fault=crash)
'''
    child=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True)
    assert child.returncode==73,child.stderr
    service=IncrementalService(path,cfg,source,snapshot_root=root)
    try:
        committed=stage in {'after_commit','before_publication','after_domain_publication','after_manifest_publication'}
        assert (service.head['generation_id']!=before['generation_id'])==committed
        if not committed:
            service.increment(delta)
        assert_equivalent(service,base+delta,cfg,source)
        SnapshotStore(root,service.head['analysis_id']).read_metadata()
        pointer=json.loads((path.parent/'published_head.json').read_text(encoding='utf-8'))
        assert pointer['generation_id']==service.head['generation_id']
    finally:
        service.close()


def test_stale_writer_is_rejected_without_lost_alerts(tmp_path):
    cfg=configuration()
    rows=[alert('base'),alert('first',1),alert('second',2)]
    source=settings(rows)
    path=tmp_path/'workspace.duckdb'
    first=IncrementalService(path,cfg,source)
    first.bootstrap(rows[:1])
    second=IncrementalService(path,cfg,source)
    try:
        first.increment(rows[1:2])
        with pytest.raises(ValueError,match='concurrent_generation'):
            second.increment(rows[2:])
        second.increment(rows[2:])
        assert_equivalent(second,rows,cfg,source)
    finally:
        first.close()
        second.close()


def test_generations_are_deterministic_and_config_bound(tmp_path):
    from app.services.storage import restore_config
    rows=[alert('base',host='h'),alert('one',1,host='h'),alert('two',2,host='h')]
    cfg,source=configuration(),settings(rows)
    identities=[]
    for number,delta in enumerate((rows[1:],list(reversed(rows[1:])))):
        service=IncrementalService(tmp_path/f'{number}.duckdb',cfg,source)
        try:
            before=service.bootstrap(rows[:1])
            assert service.increment([])['generation_id']==before['generation_id']
            receipt=service.increment(delta)
            identities.append((receipt['generation_id'],receipt['analysis_id'],receipt['batch_hash']))
        finally:
            service.close()
    assert identities[0]==identities[1]
    snapshot=cfg.snapshot
    snapshot['candidate']['max_neighbors_per_alert']+=1
    with pytest.raises(ValueError,match='config_mismatch'):
        IncrementalService(tmp_path/'0.duckdb',restore_config(snapshot),source)


def test_idempotent_receipt_cannot_hide_conflicting_canonical_facts(tmp_path):
    rows=[alert('base',host='h'),alert('delta',1,host='h',severity='high')]
    cfg,source=configuration(),settings(rows)
    service=IncrementalService(tmp_path/'workspace.duckdb',cfg,source)
    try:
        service.bootstrap(rows[:1])
        receipt=service.increment(rows[1:])
        changed=rows[1].model_copy(update={'severity':type(rows[1].severity)('critical')})
        with pytest.raises(ValueError,match='same_id_conflict'):
            service.increment([changed])
        assert service.head['generation_id']==receipt['generation_id']
        assert service.increment(rows[1:])['idempotent_replay']
    finally:
        service.close()


def test_production_cli_bootstrap_and_raw_delta(tmp_path):
    import subprocess
    import sys
    from app.adapters import WazuhAdapter
    from test_wazuh_adapter import settings as wazuh_settings,synthetic_record
    cfg=load_config(ROOT/'configs/algorithm-v3.yaml',deployment_override=ROOT/'configs/sources.yaml')
    setting=wazuh_settings()
    source={setting.source_namespace:setting}
    adapter=WazuhAdapter(cfg,setting)
    base=adapter.convert(synthetic_record(id='cli-base'))
    delta=adapter.convert(synthetic_record(id='cli-delta'))
    parent=IncrementalService(tmp_path/'parent.duckdb',cfg,source,snapshot_root=tmp_path)
    receipt=parent.bootstrap([base])
    parent.close()
    raw=tmp_path/'data/input/alerts/delta.jsonl'
    raw.parent.mkdir(parents=True)
    raw.write_text(json.dumps(delta.raw_alert)+'\n',encoding='utf-8')
    path=tmp_path/'cli.duckdb'
    command=[sys.executable,str(ROOT/'scripts/incremental_correlation.py'),'--root',str(tmp_path),
        '--workspace',str(path),'--parent-analysis-id',receipt['analysis_id'],
        '--input',setting.source_namespace,str(raw)]
    child=subprocess.run(command,capture_output=True,text=True)
    assert child.returncode==0,child.stderr
    service=IncrementalService(path,cfg,source,snapshot_root=tmp_path)
    try:
        assert_equivalent(service,[base,delta],cfg,source)
        head=service.head['generation_id']
    finally:
        service.close()
    child=subprocess.run(command,capture_output=True,text=True)
    assert child.returncode==0,child.stderr
    service=IncrementalService(path,cfg,source,snapshot_root=tmp_path)
    try:
        assert service.head['generation_id']==head
    finally:
        service.close()
