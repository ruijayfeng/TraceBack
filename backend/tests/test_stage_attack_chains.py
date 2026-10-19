"""Graph assembly only. All special topologies use synthetic test snapshots."""
import builtins
from copy import deepcopy
import io
import json
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError

from app.evidence_trace import EvidenceTraceIndex
from app.stage_chains import (StageAttackChain, StageChainResult, StageGraphSnapshot,
    TraceReference, assemble_attack_chains, validate_assembly)
from app.stage_chains.models import chain_id
from app.stage_chains.snapshot import load_stage_graph
from app.stage_relations import load_relation_config
from app.utils.stable_id import canonical_json
from test_community_builder import cfg, normalization, record
from test_stage_relations import analyze, lineage, snapshot

ROOT = Path(__file__).resolve().parents[2]
ANALYSIS = 'ana_' + 'b'*64


def graph(rows, cfg, normalization):
    data = snapshot(rows, cfg, normalization)
    result = analyze(data, cfg, load_relation_config(ROOT/'configs/stage-relations-v1.yaml'))
    stages, alerts = data[0], data[1]
    index = EvidenceTraceIndex(ANALYSIS, alerts, stages.stages, stages.behaviors, result.relations)
    traces = [index.stage_trace(s) for s in index.stage_ids] + [index.relation_trace(r) for r in index.relation_ids]
    return StageGraphSnapshot(stages.stages, result.relations, traces, index)


@pytest.fixture(params=['STRONG_DIRECTED', 'STRONG_UNDIRECTED', 'WEAK_DIRECTED'])
def pair(request, cfg, normalization):
    kind = request.param
    rows = ([record(1, hostname='h'), record(2, time=5, hostname='h')] if kind == 'WEAK_DIRECTED'
            else lineage(100 if kind == 'STRONG_UNDIRECTED' else 0, 5))
    return graph(rows, cfg, normalization)


def test_each_relation_type_connects_without_changing_semantics(pair):
    before = deepcopy(pair.relations)
    result = assemble_attack_chains(pair)
    chain, = result.chains
    relation, = pair.relations.values()
    assert chain.stage_count == 2 and chain.relation_count == 1
    assert chain.relation_ids == [relation.relation_id]
    assert pair.relations == before
    report = validate_assembly(result, pair)
    assert report.valid and report.raw_alerts_verified == 2
    assert report.dangling_stage_reference_count == report.dangling_relation_reference_count == report.dangling_evidence_reference_count == 0
    actual = pair.chain_trace(chain).relation_traces[0]
    assert actual.relation_type == relation.relation_type
    assert actual.direction_basis == relation.direction_basis
    assert (actual.source_stage_id, actual.target_stage_id) == (relation.from_stage_id, relation.to_stage_id)
    assert actual.primary_evidence == relation.primary_evidence
    assert actual.supporting_evidence == relation.supporting_evidence
    assert actual.temporal_order_is_causal_evidence is False
    if relation.relation_type == 'STRONG_UNDIRECTED':
        assert actual.source_stage_id is actual.target_stage_id is None
        assert chain.entry_stage_ids == chain.exit_stage_ids == chain.stage_ids
        assert chain.strong_undirected_count == 1 and chain.strong_directed_count == chain.weak_directed_count == 0
    else:
        assert chain.entry_stage_ids == [relation.from_stage_id]
        assert chain.exit_stage_ids == [relation.to_stage_id]
    assert StageAttackChain.model_validate_json(chain.canonical_json()) == chain
    assert StageChainResult.model_validate_json(result.canonical_json()) == result


def mixed_rows():
    # Three strong semantic arrows, one of which conflicts with observed time;
    # a typed shared host supplies weak links. No production result is forged.
    return [record('a', time=0, hostname='h'), record('b', time=5, hostname='h', parent_event_id='a'),
            record('c', time=100, hostname='h', parent_event_id='b'),
            record('d', time=10, hostname='h', parent_event_id='c'),
            record('e', time=15, hostname='h')]


def test_mixed_relation_chain_keeps_all_ids_and_original_evidence(cfg, normalization):
    source = graph(mixed_rows(), cfg, normalization)
    assert {r.relation_type for r in source.relations.values()} == {'STRONG_DIRECTED', 'STRONG_UNDIRECTED', 'WEAK_DIRECTED'}
    before = canonical_json(dict(stages=[s.model_dump(mode='json') for s in source.stages.values()],
        relations=[r.model_dump(mode='json') for r in source.relations.values()],
        traces=[t.model_dump(mode='json') for t in source.traces.values()]))
    result = assemble_attack_chains(source)
    chain, = result.chains
    assert chain.stage_count == 5 and chain.relation_count == len(source.relations)
    assert chain.relation_ids == sorted(source.relations)
    assert {r.subject_id for r in chain.evidence_refs} == set(source.stages) | set(source.relations)
    trace = source.chain_trace(chain)
    for t in [*trace.stage_traces, *trace.relation_traces]:
        assert t == source.traces[t.subject_id]
        for ref in t.raw_evidence_refs:
            assert source.trace_index.raw_evidence(ref)
    assert validate_assembly(result, source).valid
    after = canonical_json(dict(stages=[s.model_dump(mode='json') for s in source.stages.values()],
        relations=[r.model_dump(mode='json') for r in source.relations.values()],
        traces=[t.model_dump(mode='json') for t in source.traces.values()]))
    assert before == after


def test_components_are_graph_components_not_the_community_bucket(cfg, normalization):
    rows = [record('a', time=0, hostname='left'), record('b', time=5, hostname='left'),
            record('c', time=0, hostname='right'), record('d', time=5, hostname='right'), record('isolated')]
    source = graph(rows, cfg, normalization)
    assert len({s.community_id for s in source.stages.values()}) == 1
    result = assemble_attack_chains(source)
    assert sorted(c.stage_count for c in result.chains) == [1, 2, 2]
    assert sorted(c.relation_count for c in result.chains) == [0, 1, 1]
    assert sum(c.single_stage for c in result.chains) == 1
    singleton = next(c for c in result.chains if c.single_stage)
    assert singleton.entry_stage_ids == singleton.exit_stage_ids == singleton.stage_ids
    assert not singleton.has_directed_cycle
    assert validate_assembly(result, source).valid


def test_all_isolated_stages_and_empty_graph_are_retained(cfg, normalization):
    source = graph([record(i, time=i) for i in range(3)], cfg, normalization)
    result = assemble_attack_chains(source)
    assert len(result.chains) == 3 and all(c.single_stage and not c.relation_ids for c in result.chains)
    assert validate_assembly(result, source).valid
    index = EvidenceTraceIndex(ANALYSIS, [], [], [], [])
    empty = StageGraphSnapshot([], [], [], index)
    assert assemble_attack_chains(empty).chains == []


def test_existing_directed_cycle_is_kept_not_broken(cfg, normalization):
    source = graph([record('a', time=0, parent_event_id='c'), record('b', time=5, parent_event_id='a'),
                    record('c', time=10, parent_event_id='b')], cfg, normalization)
    assert len(source.relations) == 3
    assert all(r.relation_type == 'STRONG_DIRECTED' for r in source.relations.values())
    result = assemble_attack_chains(source)
    chain, = result.chains
    assert chain.has_directed_cycle and chain.relation_count == 3
    assert chain.relation_ids == sorted(source.relations)
    assert not chain.entry_stage_ids and not chain.exit_stage_ids
    assert validate_assembly(result, source).valid


def test_entry_exit_is_based_on_existing_arrows_not_timestamps(cfg, normalization):
    # Upstream semantic A->B remains valid inside the existing skew tolerance,
    # although A occurs later. Assembly must not use timestamps to reverse it.
    source = graph(lineage(5, 0), cfg, normalization)
    relation, = source.relations.values()
    assert source.stages[relation.from_stage_id].start_time > source.stages[relation.to_stage_id].start_time
    chain, = assemble_attack_chains(source).chains
    assert chain.entry_stage_ids == [relation.from_stage_id]
    assert chain.exit_stage_ids == [relation.to_stage_id]


def test_branch_is_not_collapsed_to_a_main_path(cfg, normalization):
    source = graph([record('a'), record('b',time=5,parent_event_id='a'),
                    record('c',time=10,parent_event_id='a')], cfg, normalization)
    result = assemble_attack_chains(source)
    chain, = result.chains
    assert chain.stage_count == 3 and chain.relation_count == 2
    assert len(chain.entry_stage_ids) == 1 and len(chain.exit_stage_ids) == 2
    assert 'main_path' not in chain.model_dump()


def test_reversed_input_gives_identical_membership_ids_metadata_and_digest(pair):
    result = assemble_attack_chains(pair)
    repeated = StageGraphSnapshot(list(reversed(list(pair.stages.values()))),
        list(reversed(list(pair.relations.values()))), list(reversed(list(pair.traces.values()))), pair.trace_index)
    assert repeated.input_digest == pair.input_digest
    assert assemble_attack_chains(repeated) == result
    chain, = result.chains
    assert chain.chain_id == chain_id(chain.community_id, list(reversed(chain.stage_ids)), list(reversed(chain.relation_ids)))


def test_mixed_multiple_components_are_stable_under_all_input_reordering(cfg, normalization):
    source = graph([*mixed_rows(), record('other-a',hostname='other'),
                    record('other-b',time=5,hostname='other'), record('single')], cfg, normalization)
    first = assemble_attack_chains(source)
    assert len(first.chains) == 3
    reverse = StageGraphSnapshot(list(reversed(list(source.stages.values()))),
        list(reversed(list(source.relations.values()))), list(reversed(list(source.traces.values()))), source.trace_index)
    assert assemble_attack_chains(reverse) == first


@pytest.mark.parametrize('missing', ['stage', 'relation', 'evidence'])
def test_dangling_references_have_distinct_nonzero_counts(pair, missing):
    result = assemble_attack_chains(pair)
    chain, = result.chains
    if missing == 'stage':
        bad = chain.model_copy(update=dict(stage_ids=[*chain.stage_ids, 'stg_'+'0'*64]))
    elif missing == 'relation':
        bad = chain.model_copy(update=dict(relation_ids=[*chain.relation_ids, 'str_'+'0'*64]))
    else:
        ref = TraceReference(analysis_id=ANALYSIS, subject_type='STAGE', subject_id='stg_'+'0'*64)
        bad = chain.model_copy(update=dict(evidence_refs=[*chain.evidence_refs, ref]))
    report = validate_assembly(result.model_copy(update=dict(chains=[bad])), pair)
    assert not report.valid
    assert getattr(report, 'dangling_'+missing+'_reference_count') == 1
    with pytest.raises(ValueError, match='validation_failed'):
        report.require_valid()


def test_dropped_relation_or_stage_component_is_a_validation_failure(pair):
    result = assemble_attack_chains(pair)
    report = validate_assembly(result.model_copy(update=dict(chains=[])), pair)
    assert not report.valid
    assert {e['code'] for e in report.errors} >= {'stage_partition_mismatch', 'relation_partition_mismatch'}


def test_missing_underlying_raw_evidence_is_reported(pair, monkeypatch):
    result = assemble_attack_chains(pair)
    def missing_raw(ref):
        raise ValueError('raw_alert_removed')
    monkeypatch.setattr(pair.trace_index, 'raw_evidence', missing_raw)
    report = validate_assembly(result, pair)
    assert not report.valid and report.dangling_evidence_reference_count > 0


def test_missing_source_trace_or_bad_existing_trace_is_rejected(pair):
    traces = list(pair.traces.values())
    with pytest.raises(ValueError, match='coverage'):
        StageGraphSnapshot(list(pair.stages.values()), list(pair.relations.values()), traces[:-1], pair.trace_index)
    wrong = traces[0].model_copy(update=dict(evidence_summary='invented unsupported statement'))
    with pytest.raises(ValueError, match='differs_from_source'):
        StageGraphSnapshot(list(pair.stages.values()), list(pair.relations.values()), [wrong, *traces[1:]], pair.trace_index)


def test_structural_metadata_and_identity_tamper_is_rejected(pair):
    result = assemble_attack_chains(pair)
    chain, = result.chains
    for change in (dict(stage_count=99), dict(chain_id='sch_'+'0'*64), dict(entry_stage_ids=[]),
                   dict(has_directed_cycle=not chain.has_directed_cycle)):
        bad = chain.model_copy(update=change)
        assert not validate_assembly(result.model_copy(update=dict(chains=[bad])), pair).valid
    for change in (dict(chain_id='sch_'+'0'*64), dict(weak_directed_count=99), dict(single_stage=True)):
        with pytest.raises(ValidationError):
            StageAttackChain.model_validate(dict(chain.model_dump(), **change))


def test_no_raw_payload_is_copied_into_chain_graph_container(pair):
    chain, = assemble_attack_chains(pair).chains
    assert set(chain.model_dump()) >= {'chain_id', 'stage_ids', 'relation_ids', 'evidence_refs'}
    assert not {'nodes', 'edges', 'raw_alert', 'raw_payload', 'witness_alerts', 'score'} & set(chain.model_dump())
    first = pair.chain_graph(chain)
    assert first['relations'] == list(pair.relations.values())
    first['stages'][0].alert_ids.clear()
    assert pair.chain_graph(chain)['stages'][0].alert_ids


def test_no_gt_io_ai_or_upstream_business_algorithm_calls(pair, monkeypatch):
    before = sys.getprofile()
    forbidden = ('app.adapters.', 'app.correlation.', 'app.chains.', 'app.incidents.', 'app.ai.',
                 'app.entities.extraction', 'app.entities.front_data', 'app.entities.context',
                 'app.community.builder', 'app.community.index', 'app.stage_relations.analysis',
                 'app.stage_relations.evidence', 'app.stage_relations.time', 'app.stages.aggregation',
                 'app.stages.behavior', 'app.stages.resolver')
    def trace_call(frame, event, arg):
        if event == 'call':
            assert not frame.f_globals.get('__name__', '').startswith(forbidden)
    def no_io(*args, **kwargs):
        raise AssertionError('pure_assembly_must_not_read_any_file')
    monkeypatch.setattr(builtins, 'open', no_io)
    monkeypatch.setattr(io, 'open', no_io)
    sys.setprofile(trace_call)
    try:
        result = assemble_attack_chains(pair)
        validate_assembly(result, pair).require_valid()
    finally:
        sys.setprofile(before)


def write_sealed_sources(tmp_path, source):
    """Minimal new fixture artifacts; no formal Stage/Relation snapshots touched."""
    import gzip
    from app.evidence_trace.snapshot import file_sha256
    domain = tmp_path/'data/processed'/ANALYSIS
    relation_dir, evidence_dir = tmp_path/'outputs/relation_fixture', tmp_path/'outputs/evidence_fixture'
    domain.mkdir(parents=True)
    relation_dir.mkdir(parents=True)
    (evidence_dir/'validated').mkdir(parents=True)
    index = source.trace_index
    # Construct fixtures from existing in-memory synthetic witnesses only.
    alerts = list(index._alerts.values())
    behaviors = list(index._behaviors.values())
    files = {}
    for name, objects in (('stage_source_alerts.jsonl.gz', alerts), ('behaviors.jsonl.gz', behaviors),
                          ('stages.jsonl.gz', list(source.stages.values()))):
        path = domain/name
        with gzip.open(path, 'wt', encoding='utf8') as stream:
            stream.write(''.join(o.canonical_json()+'\n' for o in objects))
        files[path.relative_to(tmp_path).as_posix()] = file_sha256(path)
    rpath = domain/'stage_relations.jsonl'
    rpath.write_text(''.join(r.canonical_json()+'\n' for r in source.relations.values()), encoding='utf8')
    artifacts = {rpath.relative_to(tmp_path).as_posix():file_sha256(rpath)}
    relation_manifest = relation_dir/'manifest.json'
    relation_manifest.write_text(canonical_json(dict(status='sealed', algorithm_version='stage-relations-v1',
        analysis_id=ANALYSIS, source_artifacts=files, artifacts=artifacts)), encoding='utf8')
    receipt = {str(relation_manifest):file_sha256(relation_manifest),
               **{str(tmp_path/p):h for p,h in {**files, **artifacts}.items()}}
    for name, values in (('stage_traces.jsonl', [source.traces[s] for s in source.stages]),
                          ('relation_traces.jsonl', [source.traces[r] for r in source.relations])):
        (evidence_dir/'validated'/name).write_text(''.join(t.canonical_json()+'\n' for t in values), encoding='utf8')
    (evidence_dir/'validated/source_receipt.json').write_text(canonical_json(receipt), encoding='utf8')
    evidence_manifest = evidence_dir/'manifest.json'
    evidence_manifest.write_text(canonical_json(dict(status='sealed', contract_version='evidence-trace-v1',
        validated_output_sha256={p.name:file_sha256(p) for p in (evidence_dir/'validated').iterdir()})), encoding='utf8')
    return relation_manifest, evidence_manifest


def test_sealed_runner_roundtrip_trace_and_no_source_mutation(pair, tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT/'scripts'))
    import run_attack_chain_reconstruction as runner
    monkeypatch.setattr(runner, 'ROOT', tmp_path)
    relations, evidence = write_sealed_sources(tmp_path, pair)
    loaded, receipt = load_stage_graph(tmp_path, relations, evidence)
    output = tmp_path/'outputs/assembled'
    result = runner.execute(relations, evidence, output)
    assert result == assemble_attack_chains(loaded)
    assert runner.verify(output)['CHAIN_TRACE_RAW_RESOLUTION_PASSED'] is True
    from app.evidence_trace.snapshot import file_sha256
    assert all(file_sha256(p) == h for p,h in receipt.items())
    summary = json.loads((output/'summary.json').read_text())
    assert summary['PRODUCTION_GT_READS'] == summary['PROHIBITED_ALGORITHM_IMPORTS'] == 0
    with pytest.raises(ValueError, match='new_output'):
        runner.execute(relations, evidence, output)


def test_sealed_loader_rejects_tamper_or_wrong_source_snapshot(pair, tmp_path):
    relations, evidence = write_sealed_sources(tmp_path, pair)
    load_stage_graph(tmp_path, relations, evidence)
    path = evidence.parent/'validated/stage_traces.jsonl'
    path.write_text(path.read_text()+'\n', encoding='utf8')
    with pytest.raises(ValueError, match='hash_mismatch'):
        load_stage_graph(tmp_path, relations, evidence)


def test_relocated_snapshot_preserves_chain_and_analysis_identity(cfg, normalization, tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT/'scripts'))
    import run_attack_chain_reconstruction as runner
    source = graph(mixed_rows(), cfg, normalization)
    results, manifests = [], []
    for name in ('first-location', 'different-location'):
        root = tmp_path/name
        relations, evidence = write_sealed_sources(root, source)
        monkeypatch.setattr(runner, 'ROOT', root)
        out = root/'outputs/assembled'
        results.append(runner.execute(relations, evidence, out))
        manifests.append(json.loads((out/'manifest.json').read_text()))
    assert results[0] == results[1]
    assert manifests[0]['analysis_id'] == manifests[1]['analysis_id']
    assert manifests[0]['config_hash'] == manifests[1]['config_hash']
    # Provenance can differ after a move, without contaminating core identities.
    assert manifests[0]['source_manifest_sha256'] != manifests[1]['source_manifest_sha256']


def test_reloaded_graph_rejects_export_tamper(pair, tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT/'scripts'))
    import run_attack_chain_reconstruction as runner
    monkeypatch.setattr(runner, 'ROOT', tmp_path)
    relations, evidence = write_sealed_sources(tmp_path, pair)
    output = tmp_path/'outputs/assembled'
    runner.execute(relations, evidence, output)
    path = output/'chains.json'
    path.write_text(path.read_text()+'\n', encoding='utf8')
    with pytest.raises(ValueError, match='artifact_hash_mismatch'):
        runner.verify(output)


def test_prior_trace_receipt_must_match_relation_snapshot(pair, tmp_path):
    from app.evidence_trace.snapshot import file_sha256
    relations, evidence = write_sealed_sources(tmp_path, pair)
    path = evidence.parent/'validated/source_receipt.json'
    path.write_text('{}', encoding='utf8')
    payload = json.loads(evidence.read_text())
    payload['validated_output_sha256']['source_receipt.json'] = file_sha256(path)
    evidence.write_text(json.dumps(payload), encoding='utf8')
    with pytest.raises(ValueError, match='source_snapshot_mismatch'):
        load_stage_graph(tmp_path, relations, evidence)


def test_production_guard_denies_gt_and_existing_output_write(tmp_path):
    sys.path.insert(0, str(ROOT/'scripts'))
    from run_attack_chain_reconstruction import assembly_guard
    with assembly_guard([tmp_path/'new']):
        with pytest.raises(AssertionError, match='truth_io'):
            (tmp_path/'ground_truth.json').read_text()
        with pytest.raises(AssertionError, match='write_outside'):
            (tmp_path/'old_relation.json').write_text('no')
        with pytest.raises(AssertionError, match='import_forbidden'):
            __import__('app.chains.assembly')
