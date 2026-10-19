"""Synthetic execution equivalence, spill lifecycle and exact pointer fixtures."""
import io
import json
from pathlib import Path
import random
import pytest
from app.config import load_config
from app.correlation.index import AlertIndex
from app.correlation.edges import run_correlation
from app.chains.assembly import run_reconstruction
from app.entities.extraction import extract_entities
from app.services.capacity import (bounded_execution, BoundedCache, json_array_records,
    DiskMasks, DiskVector)
from app.incidents.triage import triage_singletons
from app.services.storage import SnapshotStore
from test_correlation_score import alert, inputs, parent_child

ROOT = Path(__file__).resolve().parents[2]


def objects(records):
    return [r.canonical_json() for r in records]


@pytest.mark.parametrize('chunk', [1, 3, 17, 65536])
@pytest.mark.parametrize('text', ['[]', '[1,22,3.1415,null,true,{"a":[1,2]}]',
    '[{"unicode":"中文","escaped":"a\\nb"}]', '[1,]', '[1] trailing', '[{"a":1}, invalid]'])
def test_stream_array_matches_all_or_nothing_json_load(chunk, text):
    try:
        expected = json.loads(text)
    except ValueError:
        expected = ['invalid JSON array']
    assert list(json_array_records(io.StringIO(text),chunk)) == expected


def test_spill_cache_eviction_and_exact_model_dump(tmp_path):
    aa = [alert(str(i), host='host', account='account') for i in range(135)]
    with bounded_execution(tmp_path/'spill') as state:
        packed = state.alerts()
        for a in aa:
            packed.add(a)
        for a in aa:
            assert packed[a.alert_id].model_dump() == a.model_dump()
            assert packed[a.alert_id].canonical_json() == a.canonical_json()
        assert len(state.cache) <= 128 and state.cache.evictions > 0
        for a in reversed(aa):
            assert packed[a.alert_id].raw_alert == a.raw_alert
    assert not (tmp_path/'spill').exists()


def test_failure_cleanup_and_cache_recompute(tmp_path):
    with pytest.raises(RuntimeError):
        with bounded_execution(tmp_path/'spill') as state:
            state.alerts().add(alert('a'))
            state.database()
            raise RuntimeError('partial_batch_failure')
    assert not (tmp_path/'spill').exists()
    cache = BoundedCache(2)
    for i in range(5):
        cache[i] = i*i
    assert list(cache) == [3,4] and cache.evictions == 3


def test_disk_bitsets_preserve_arbitrary_width_and_zero_rows(tmp_path):
    with bounded_execution(tmp_path/'spill') as state:
        vector = DiskVector(DiskMasks(state.database(),'rows'), 4)
        vector[2] = (1 << 500000) | 7
        assert list(vector) == [0,0,(1 << 500000)|7,0]


@pytest.mark.parametrize('reverse', [False, True])
def test_full_standard_bounded_semantics_and_grounding(tmp_path, reverse):
    config = load_config(ROOT/'configs/algorithm-v4.yaml')
    raw = parent_child() + [alert(str(i), i, host='noise'+str(i)) for i in range(12)]
    original, settings = inputs(raw)
    aa, groups, entities = list(original.alerts.values()), [], list(original.entities.values())
    standard = run_correlation(aa, groups, entities, config, settings)
    expected = run_reconstruction(aa, groups, entities, standard.edges, config, settings, upstream_record=standard.record)
    expected.incidents = triage_singletons(expected.incidents, AlertIndex(aa,groups,entities),config,
        standard.summary,search_complete=True)
    with bounded_execution(tmp_path/'spill') as state:
        mapping = state.alerts()
        for a in reversed(aa) if reverse else aa:
            mapping.add(a)
        packed = mapping.sequence()
        index = AlertIndex(packed,groups,entities)
        actual = run_correlation(packed,groups,entities,config,settings)
        assert list(actual.candidates.pairs) == standard.candidates.pairs
        assert actual.candidates.potential_pair_stats == standard.candidates.potential_pair_stats
        assert list(actual.candidates.diagnostics) == standard.candidates.diagnostics
        assert objects(actual.edges) == objects(standard.edges)
        result = run_reconstruction(packed,groups,entities,actual.edges,config,settings,
            upstream_record=actual.record,existing_index=index)
        result.incidents = triage_singletons(result.incidents,index,config,actual.summary,search_complete=True)
        assert objects(result.incidents) == objects(expected.incidents)
        assert objects(result.chains) == objects(expected.chains)
        assert result.grounding.valid
        store = SnapshotStore(tmp_path,actual.record.analysis_id)
        store.write_records('alerts',packed)
        assert objects(store.read_records('alerts')) == objects(aa)


def test_entity_extraction_packed_roundtrip(tmp_path):
    original,settings = inputs(parent_child())
    aa = list(original.alerts.values())
    expected = extract_entities(aa,settings)
    with bounded_execution(tmp_path/'spill') as state:
        mapping = state.alerts()
        for a in aa:
            mapping.add(a)
        result = extract_entities(mapping.sequence(),settings)
        assert objects(result.alerts) == objects(expected.alerts)
        assert objects(result.entities) == objects(expected.entities)


@pytest.mark.parametrize('batch', [1,3,17,256])
def test_diagnostic_batch_boundaries_preserve_candidate_payload(tmp_path,monkeypatch,batch):
    from dataclasses import asdict
    from app.services import bounded_diagnostics as diag
    config=load_config(ROOT/'configs/algorithm-v4.yaml')
    original,settings=inputs([alert(str(i),i,host='h',account='u') for i in range(12)])
    aa,entities=list(original.alerts.values()),list(original.entities.values())
    expected=run_correlation(aa,[],entities,config,settings)
    monkeypatch.setattr(diag,'BATCH',batch)
    details=tmp_path/'diagnostics'
    details.mkdir()
    with bounded_execution(tmp_path/'spill') as state:
        mapping=state.alerts()
        for a in aa:
            mapping.add(a)
        with (details/'diagnostics.jsonl').open('w',encoding='utf8') as handle:
            sink=diag.BoundedDiagnostics(details,handle)
            actual=run_correlation(mapping.sequence(),[],entities,config,settings,diagnostic_sink=sink)
            sink.close()
        assert [asdict(p) for p in actual.candidates.pairs]==[asdict(p) for p in expected.candidates.pairs]
        assert objects(actual.edges)==objects(expected.edges)


def test_resource_budget_is_preserved_in_bounded_mode(tmp_path):
    from app.services.storage import restore_config
    config=load_config(ROOT/'configs/algorithm-v4.yaml')
    snapshot=config.snapshot
    snapshot['candidate']['max_candidate_pairs']=2
    config=restore_config(snapshot)
    original,settings=inputs([alert(str(i),i,host='h') for i in range(8)])
    aa,entities=list(original.alerts.values()),list(original.entities.values())
    expected=run_correlation(aa,[],entities,config,settings)
    with bounded_execution(tmp_path/'spill') as state:
        mapping=state.alerts()
        for a in aa:
            mapping.add(a)
        actual=run_correlation(mapping.sequence(),[],entities,config,settings)
        assert list(actual.candidates.pairs)==expected.candidates.pairs
        assert actual.record.status.value=='incomplete'
        assert actual.candidates.resource_truncated_count==expected.candidates.resource_truncated_count


@pytest.mark.parametrize('array_input',[False,True])
def test_ingress_public_snapshot_and_truth_isolation_equivalence(tmp_path,monkeypatch,array_input):
    from app.services.analysis import AnalysisService
    from app.services.storage import MODELS,file_digest
    from test_analysis_service import deployment,edge_records,write_input,tripwire
    _,sources=deployment(tmp_path,edge=True)
    config=load_config(ROOT/'configs/algorithm-v4.yaml',deployment_override=ROOT/'configs/sources.yaml',
        experiment_override=tmp_path/'experiment.yaml')
    rows=edge_records()
    rows += [rows[0],{'labels':'contaminated synthetic fixture'}]
    path=write_input(tmp_path,rows)
    if array_input:
        (tmp_path/path).write_text(json.dumps(rows),encoding='utf8')
    tripwire(monkeypatch)
    stores=[]
    for mode in ('standard','bounded'):
        service=AnalysisService(tmp_path,configs={'v4':config},sources=sources,execution_mode=mode)
        try:
            identity=service.create({'config_version':'v4','inputs':[{'source':'wazuh','source_ref':'w','path':path}]},background=False)
        finally:
            service.close()
        stores.append(SnapshotStore(tmp_path,identity))
    for kind in MODELS:
        assert file_digest(stores[0].domain/(kind+'.jsonl'))==file_digest(stores[1].domain/(kind+'.jsonl'))
    before,_,_=stores[0].read_metadata()
    after,_,_=stores[1].read_metadata()
    assert before.config_hash==after.config_hash and before.dataset_digest==after.dataset_digest
    assert before.status==after.status and not after.is_complete
    assert not (stores[1].details/'execution_spill').exists()


def test_service_partial_batch_failure_leaves_no_completed_snapshot(tmp_path):
    from app.services.analysis import AnalysisService
    from test_analysis_service import deployment,edge_records,write_input
    _,sources=deployment(tmp_path,edge=True)
    config=load_config(ROOT/'configs/algorithm-v4.yaml',deployment_override=ROOT/'configs/sources.yaml',
        experiment_override=tmp_path/'experiment.yaml')
    path=write_input(tmp_path,edge_records())
    checks=0
    def stop():
        nonlocal checks
        checks+=1
        if checks>=2:
            raise MemoryError('synthetic resource guard')
    service=AnalysisService(tmp_path,configs={'v4':config},sources=sources,execution_mode='bounded',resource_check=stop)
    try:
        identity=service.create({'config_version':'v4','inputs':[{'source':'wazuh','source_ref':'w','path':path}]},background=False)
    finally:
        service.close()
    store=SnapshotStore(tmp_path,identity)
    run=json.loads((store.domain/'run.json').read_text(encoding='utf8'))
    assert run['status']=='incomplete' and not run['is_complete']
    assert not (store.domain/'analysis.json').exists()
    assert not (store.details/'execution_spill').exists()


def test_grouped_member_candidate_provenance_and_scoring_equivalence(tmp_path):
    from test_correlation_score import group
    config=load_config(ROOT/'configs/algorithm-v4.yaml')
    alerts=[alert(str(i),i,host='h',account='u',rule_id=str(i%3)) for i in range(10)]
    groups=[group(alerts[:3]),group(alerts[5:8])]
    original,settings=inputs(alerts,groups=groups)
    aa,entities=list(original.alerts.values()),list(original.entities.values())
    expected=run_correlation(aa,groups,entities,config,settings)
    with bounded_execution(tmp_path/'spill') as state:
        mapping=state.alerts()
        for a in aa:
            mapping.add(a)
        actual=run_correlation(mapping.sequence(),groups,entities,config,settings)
        assert list(actual.candidates.pairs)==expected.candidates.pairs
        assert actual.candidates.potential_pair_stats==expected.candidates.potential_pair_stats
        assert objects(actual.edges)==objects(expected.edges)
        assert actual.summary['verified_member_pair_count']==expected.summary['verified_member_pair_count']


def test_capacity_monitor_accepts_algorithm_elapsed_time(tmp_path,monkeypatch):
    import importlib.util
    spec=importlib.util.spec_from_file_location('capacity_runner_test',ROOT/'scripts/verify_correlation_capacity.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module,'memory',lambda: {'rss_mb':1})
    monitor=module.Monitor(tmp_path)
    monitor.progress({'stage':'candidates','count':1,'elapsed_seconds':12.5})
    assert monitor.events[0]['reported_elapsed_seconds']==12.5
    assert monitor.events[0]['elapsed_seconds']>=0
    monitor.abort=True
    with pytest.raises(MemoryError):
        monitor.progress({'stage':'scoring'})
    monitor.progress({'stage':'finished','status':'incomplete'})
    assert monitor.events[-1]['status']=='incomplete'


def test_bounded_parquet_writer_limits_row_groups_and_preserves_records(tmp_path):
    import duckdb
    from app.services.storage import file_digest
    alerts = sorted([alert(str(i), host='h') for i in range(2050)], key=lambda a: a.alert_id)
    standard = SnapshotStore(tmp_path, 'ana_' + '1' * 64)
    bounded = SnapshotStore(tmp_path, 'ana_' + '2' * 64)
    standard.write_records('alerts', alerts)
    with bounded_execution(tmp_path/'spill'):
        bounded.write_records('alerts', alerts)
    assert file_digest(standard.domain/'alerts.jsonl') == file_digest(bounded.domain/'alerts.jsonl')
    assert objects(bounded.read_records('alerts', parquet=True)) == objects(alerts)
    db = duckdb.connect(':memory:')
    try:
        groups = db.execute('SELECT DISTINCT row_group_num_rows FROM parquet_metadata(?)',
                            [str(bounded.domain/'alerts.parquet')]).fetchall()
        assert max(row[0] for row in groups) <= 2048
        assert len(groups) == 2
    finally:
        db.close()
