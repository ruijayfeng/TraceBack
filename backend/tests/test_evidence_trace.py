"""Synthetic trace witnesses; no experiment input is ever modified by tests."""
import builtins
from copy import deepcopy
import gzip
import io
import json
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError

from app.evidence_trace import ChainReference, ChainTrace, EvidenceTrace, EvidenceTraceIndex
from app.evidence_trace.snapshot import file_sha256, load_trace_snapshot
from app.models.alerts import EvidencePointer
from app.stage_relations import load_relation_config
from app.stages import load_stage_config
from app.utils.stable_id import canonical_json
from test_community_builder import cfg, normalization, record
from test_stage_relations import snapshot, analyze, lineage

ROOT = Path(__file__).resolve().parents[2]
ANALYSIS = 'ana_' + 'a' * 64


@pytest.fixture(params=['STRONG_DIRECTED', 'STRONG_UNDIRECTED', 'WEAK_DIRECTED'])
def source(request, cfg, normalization):
    kind = request.param
    rows = ([record(1, hostname='host'), record(2, time=5, hostname='host')]
            if kind == 'WEAK_DIRECTED' else lineage(100 if kind == 'STRONG_UNDIRECTED' else 0, 5))
    data = snapshot(rows, cfg, normalization)
    result = analyze(data, cfg, load_relation_config(ROOT/'configs/stage-relations-v1.yaml'))
    return data, result


def index_for(source, **changes):
    data, result = source
    values = dict(analysis_id=ANALYSIS, alerts=data[1], stages=data[0].stages,
                  behaviors=data[0].behaviors, relations=result.relations)
    values.update(changes)
    return EvidenceTraceIndex(**values)


def test_all_relation_kinds_preserve_single_winner_and_original_direction(source):
    index = index_for(source)
    relation, = source[1].relations
    trace = index.relation_trace(relation.relation_id)
    assert trace.primary_evidence == relation.primary_evidence
    assert trace.supporting_evidence == relation.supporting_evidence
    assert trace.winning_witness_alert_ids == relation.primary_evidence.alert_ids
    assert trace.witness_alert_ids == relation.witness_alert_ids
    assert trace.direction_basis == relation.direction_basis
    assert (trace.source_stage_id, trace.target_stage_id) == (relation.from_stage_id, relation.to_stage_id)
    assert trace.temporal_order_is_causal_evidence is False
    assert EvidenceTrace.model_validate_json(trace.model_dump_json()) == trace
    assert index.validate()['dangling_reference_count'] == 0
    for ref in trace.raw_evidence_refs:
        expected = next(a.raw_alert for a in source[0][1] if a.alert_id == ref.alert_id)
        assert index.raw_evidence(ref) == expected


def test_stage_behavior_and_full_alert_metadata_are_bound_to_raw(source):
    index = index_for(source)
    for sid in index.stage_ids:
        trace = index.stage_trace(sid)
        assert trace.witness_alert_ids == trace.stage.alert_ids
        for witness, behavior in zip(trace.witness_alerts, trace.behaviors):
            alert = next(a for a in source[0][1] if a.alert_id == witness.alert_id)
            assert witness.source_type == alert.source_type.value
            assert witness.timestamp == alert.timestamp
            assert witness.alert_type == alert.alert_type and witness.signature == alert.signature
            assert witness.behavior == behavior.behavior == trace.stage.behavior
            assert index.raw_evidence(witness.raw_ref) == alert.raw_evidence
        assert EvidenceTrace.model_validate_json(trace.model_dump_json()) == trace


def test_multi_alert_stage_exposes_every_member_and_existing_aggregation_proof(cfg, normalization):
    from test_stage_aggregation import stage_run
    policy = load_stage_config(ROOT/'configs/behavior-stage-v1.yaml')
    community, result = stage_run([record(i, time=i, hostname='h', request_id='r', operation='FileRead')
                                   for i in range(3)], cfg, normalization, policy)
    assert max(s.alert_count for s in result.stages) > 1
    index = EvidenceTraceIndex(ANALYSIS, community.alerts, result.stages, result.behaviors, [])
    for stage in result.stages:
        trace = index.stage_trace(stage.stage_id)
        assert trace.stage.aggregation_basis == stage.aggregation_basis
        assert len(trace.witness_alerts) == stage.alert_count
        for p in trace.evidence_pointers:
            index.resolve_evidence(p)


def test_multiple_witnesses_do_not_replace_or_reselect_the_single_winner(cfg, normalization):
    from test_stage_aggregation import stage_run
    parent, child = lineage()
    rows = [dict(parent, event_id='p0'), dict(parent, event_id='p2', timestamp=record(0,time=2)['timestamp']),
            dict(child, event_id='c5'), dict(child, event_id='c7', timestamp=record(0,time=7)['timestamp'])]
    community, stages = stage_run(rows, cfg, normalization, load_stage_config(ROOT/'configs/behavior-stage-v1.yaml'))
    from test_source_bound_projection import settings
    ss = {a.source_namespace:settings(a.raw_alert['source_type']) for a in community.alerts}
    data = (stages, community.alerts, community.entities, community.result.incident_candidates, ss)
    result = analyze(data, cfg, load_relation_config(ROOT/'configs/stage-relations-v1.yaml'))
    relation, = result.relations
    index = EvidenceTraceIndex(ANALYSIS, community.alerts, stages.stages, stages.behaviors, result.relations)
    trace = index.relation_trace(relation.relation_id)
    assert len(trace.winning_witness_alert_ids) == 2
    assert len(trace.witness_alert_ids) == 4
    assert trace.primary_evidence == relation.primary_evidence
    assert trace.primary_evidence.evidence_strength == relation.confidence
    assert trace.supporting_evidence == relation.supporting_evidence


def test_no_mutation_and_reverse_input_order_produce_identical_traces(source):
    before = deepcopy(source)
    index = index_for(source)
    data, result = source
    reverse = index_for(source, alerts=list(reversed(data[1])), stages=list(reversed(data[0].stages)),
                        behaviors=list(reversed(data[0].behaviors)), relations=list(reversed(result.relations)))
    assert [index.stage_trace(s) for s in index.stage_ids] == [reverse.stage_trace(s) for s in reverse.stage_ids]
    assert [index.relation_trace(r) for r in index.relation_ids] == [reverse.relation_trace(r) for r in reverse.relation_ids]
    trace = index.stage_trace(index.stage_ids[0])
    trace.stage.alert_ids.clear()
    raw = index.raw_evidence(index.stage_trace(index.stage_ids[0]).raw_evidence_refs[0])
    raw['new_field'] = 'not allowed to affect snapshot'
    assert 'new_field' not in index.raw_evidence(index.stage_trace(index.stage_ids[0]).raw_evidence_refs[0])
    assert index.stage_trace(index.stage_ids[0]).stage.alert_ids
    assert source == before


def test_missing_and_duplicate_references_rejected(source):
    with pytest.raises(ValueError, match='partition'):
        index_for(source, alerts=[])
    with pytest.raises(ValueError, match='partition'):
        index_for(source, behaviors=[])
    with pytest.raises(ValueError, match='duplicate'):
        index_for(source, alerts=[*source[0][1], source[0][1][0]])
    index = index_for(source)
    for method in (index.stage_trace, index.relation_trace, index.chain_trace):
        with pytest.raises(KeyError):
            method('missing')
    relation = source[1].relations[0]
    forged = relation.model_copy(update=dict(stage_a_id='stg_'+'0'*64))
    with pytest.raises(ValueError):
        index_for(source, relations=[forged])


def test_bad_witness_pointer_and_cross_alert_pointer_are_rejected(source):
    data, result = source
    relation = result.relations[0]
    primary = relation.primary_evidence
    from app.stage_relations.models import stable
    for aid, pointer in ((primary.alert_ids[0], '/does_not_exist'), ('alt_'+'0'*64, '/timestamp')):
        p = EvidencePointer(alert_id=aid, pointer=pointer, side='shared')
        evidence = primary.model_dump()
        evidence['pointers'] = [p, *primary.pointers]
        from app.models.alerts import canonical_pointers
        evidence['pointers'] = canonical_pointers(evidence['pointers'])
        evidence['evidence_id'] = stable('sre', 'StageRelationEvidence', dict(
            evidence_type=primary.evidence_type, alert_ids=primary.alert_ids, identity_key=primary.identity_key,
            pointers=[x.model_dump(mode='json') for x in evidence['pointers']],
            semantic_direction=primary.semantic_direction.model_dump(mode='json') if primary.semantic_direction else None))
        forged = relation.model_dump()
        forged['primary_evidence'] = evidence
        with pytest.raises(ValueError):
            index_for(source, relations=[forged])


def test_raw_reference_is_bound_to_analysis_alert_and_fingerprint(source):
    index = index_for(source)
    ref = index.stage_trace(index.stage_ids[0]).raw_evidence_refs[0]
    for field, value in (('analysis_id', 'ana_'+'0'*64), ('alert_id', 'alt_'+'0'*64), ('raw_fingerprint', '0'*64)):
        with pytest.raises(ValueError):
            index.raw_evidence(ref.model_copy(update={field:value}))
    with pytest.raises(ValidationError):
        index.raw_evidence(dict(ref.model_dump(), path='/external/file'))


def test_minimal_chain_compatibility_uses_only_supplied_references(source):
    index = index_for(source)
    chain = ChainReference(chain_id='synthetic_existing_chain', stage_ids=list(index.stage_ids),
                           relation_ids=list(index.relation_ids))
    index = index_for(source, chains=[chain])
    traced = index.chain_trace(chain.chain_id)
    assert traced.chain == chain
    def assert_no_raw_payload(value):
        if isinstance(value, dict):
            assert 'raw_alert' not in value
            for child in value.values():
                assert_no_raw_payload(child)
        elif isinstance(value, list):
            for child in value:
                assert_no_raw_payload(child)
    assert_no_raw_payload(traced.model_dump(mode='json'))
    assert [t.subject_id for t in traced.stage_traces] == chain.stage_ids
    assert [t.subject_id for t in traced.relation_traces] == chain.relation_ids
    assert ChainTrace.model_validate_json(traced.model_dump_json()) == traced
    with pytest.raises(ValueError, match='dangling_chain'):
        index_for(source, chains=[chain.model_copy(update=dict(relation_ids=['str_'+'0'*64]))])
    with pytest.raises(ValueError, match='endpoint_missing'):
        index_for(source, chains=[chain.model_copy(update=dict(stage_ids=chain.stage_ids[:1]))])


def test_trace_runs_without_io_ai_or_any_algorithm_replay(source, monkeypatch):
    original_import = builtins.__import__
    def guarded_import(name, *args, **kwargs):
        assert not name.startswith(('evaluation', 'app.ai', 'app.chains', 'app.correlation',
                                    'app.incidents', 'app.stage_relations.analysis', 'app.stages.aggregation'))
        return original_import(name, *args, **kwargs)
    def no_io(*args, **kwargs):
        raise AssertionError('trace_must_be_in_memory')
    monkeypatch.setattr(builtins, '__import__', guarded_import)
    monkeypatch.setattr(builtins, 'open', no_io)
    monkeypatch.setattr(io, 'open', no_io)
    index = index_for(source)
    assert index.validate()['relation_count'] == 1


def sealed(tmp_path, source):
    data, result = source
    domain = tmp_path/'data/processed'/ANALYSIS
    output = tmp_path/'outputs/baseline'
    domain.mkdir(parents=True)
    output.mkdir(parents=True)
    sources = {}
    for name, objects in (('stage_source_alerts.jsonl.gz', data[1]), ('stages.jsonl.gz', data[0].stages),
                          ('behaviors.jsonl.gz', data[0].behaviors)):
        path = domain/name
        with gzip.open(path, 'wt', encoding='utf8') as stream:
            stream.write(''.join(x.canonical_json()+'\n' for x in objects))
        sources[path.relative_to(tmp_path).as_posix()] = file_sha256(path)
    path = domain/'stage_relations.jsonl'
    path.write_text(''.join(r.canonical_json()+'\n' for r in result.relations), encoding='utf8')
    artifacts = {path.relative_to(tmp_path).as_posix():file_sha256(path)}
    manifest = output/'manifest.json'
    manifest.write_text(canonical_json(dict(status='sealed', algorithm_version='stage-relations-v1',
        analysis_id=ANALYSIS, source_artifacts=sources, artifacts=artifacts)), encoding='utf8')
    return manifest


def test_sealed_loader_rejects_tamper_and_never_overwrites_snapshot(source, tmp_path):
    manifest = sealed(tmp_path, source)
    index, receipt = load_trace_snapshot(tmp_path, manifest)
    assert index.validate()['relation_count'] == 1
    assert all(file_sha256(p) == h for p, h in receipt.items())
    data = json.loads(manifest.read_text())
    path = tmp_path/next(iter(data['artifacts']))
    path.write_text(path.read_text()+'\n', encoding='utf8')
    with pytest.raises(ValueError, match='hash_mismatch'):
        load_trace_snapshot(tmp_path, manifest)


def test_loader_denies_truth_and_path_escape_before_open(source, tmp_path):
    manifest = sealed(tmp_path, source)
    original = json.loads(manifest.read_text())
    for ref in ('outputs/evaluation/secret.json', 'outputs/ground_truth.json', '../outside.json'):
        content = deepcopy(original)
        content['artifacts'] = {ref:'0'*64}
        manifest.write_text(json.dumps(content), encoding='utf8')
        with pytest.raises(ValueError, match='forbidden|outside_snapshot'):
            load_trace_snapshot(tmp_path, manifest)


def test_runner_exports_refs_only_and_reports_chain_unavailable(source, tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT/'scripts'))
    import run_evidence_trace as runner
    monkeypatch.setattr(runner, 'ROOT', tmp_path)
    manifest = sealed(tmp_path, source)
    baseline = file_sha256(manifest)
    output = tmp_path/'outputs/new_trace'
    summary = runner.execute(manifest, output)
    assert summary['EVIDENCE_TRACE_COMPLETE'] is True
    assert summary['CHAIN_TRACE_SUPPORTED'] is False
    assert summary['CHAIN_TRACE_BLOCKED_BY'] == 'ATTACK_CHAIN_RECONSTRUCTION_NOT_YET_AVAILABLE'
    assert summary['ATTACK_CHAIN_RECONSTRUCTION_STARTED'] is False
    assert summary['prohibited_reads'] == summary['prohibited_imports'] == 0
    assert file_sha256(manifest) == baseline
    assert not (output/'chain_traces.jsonl').read_text()
    for line in (output/'relation_traces.jsonl').read_text().splitlines():
        assert 'raw_alert' not in json.loads(line)
        EvidenceTrace.model_validate_json(line)
    import verify_evidence_trace as verifier
    monkeypatch.setattr(verifier, 'ROOT', tmp_path)
    checked = verifier.verify(manifest, output)
    assert checked['EXACT_EXISTING_DECISIONS_PRESERVED'] is True
    assert checked['DANGLING_REFERENCE_COUNT'] == 0
    # A schema-valid but altered export must still fail the source comparison.
    path = output/'relation_traces.jsonl'
    altered = json.loads(path.read_text())
    altered['evidence_summary'] = 'invented unsupported statement'
    path.write_text(json.dumps(altered)+'\n', encoding='utf8')
    with pytest.raises(ValueError, match='differs_from_existing_decision'):
        verifier.verify(manifest, output)
    with pytest.raises(ValueError, match='new_directory'):
        runner.execute(manifest, output)


def test_projection_schema_refuses_causality_and_forged_basis(source):
    trace = index_for(source).relation_trace(source[1].relations[0].relation_id)
    for values in (dict(temporal_order_is_causal_evidence=True), dict(direction_basis='causal'),
                   dict(winning_witness_alert_ids=[]), dict(evidence_pointers=[])):
        with pytest.raises(ValidationError):
            EvidenceTrace.model_validate(dict(trace.model_dump(), **values))
