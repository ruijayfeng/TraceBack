"""Regressions for ⑤ Community and ⑥ Stage; synthetic observations only."""
import builtins
import json

import pytest

from app.adapters.base import reject_truth
from app.stages.models import AggregationBasis
from test_community_builder import cfg, normalization, record, run, sizes
from test_stage_aggregation import policy, stage_run


def partition(run, selected):
    return sorted(sorted(set(c.alert_ids) & selected) for c in run.result.incident_candidates
                  if set(c.alert_ids) & selected)


@pytest.mark.parametrize('fields', [dict(src_ip='192.0.2.1'), dict(hostname='shared'), dict(user='shared')])
def test_public_entity_membership_survives_unrelated_dilution(cfg, normalization, fields):
    rows = [record(i, time=i, behavior='probe', dst_ip=f'198.51.100.{i+1}', **fields) for i in range(20)]
    original = run(rows, cfg, normalization)
    selected = {a.alert_id for a in original.alerts}
    unrelated = [record(1000+i, time=i, hostname=f'unrelated-{i}') for i in range(200)]
    diluted = run(rows + unrelated, cfg, normalization)
    assert sizes(original) == [1] * 20
    assert partition(original, selected) == partition(diluted, selected)
    assert original.result.statistics['high_degree_entities'] == diluted.result.statistics['high_degree_entities']


def test_rare_ip_behavior_requires_independent_context(cfg, normalization):
    rows = [record(i, time=i, src_ip='192.0.2.1', dst_ip=f'198.51.100.{i+1}', behavior='probe') for i in range(2)]
    assert sizes(run(rows, cfg, normalization)) == [1, 1]


def test_host_behavior_does_not_hide_distinct_process_guids(cfg, normalization):
    rows = [record(i, time=i, hostname='h', process_guid=f'process-{i}', operation='ProcessStart') for i in range(2)]
    assert sizes(run(rows, cfg, normalization)) == [1, 1]


def test_ip_time_cannot_override_different_entities(cfg, normalization):
    rows = [record(i, time=i, src_ip='192.0.2.1', hostname=f'h-{i}', user=f'user-{i}',
                   process_guid=f'p-{i}', behavior='probe') for i in range(2)]
    assert sizes(run(rows, cfg, normalization)) == [1, 1]


@pytest.mark.parametrize('fields', [dict(request_id='r'), dict(session_id='s'), dict(connection_id='c'),
    dict(application_session_id='a'), dict(task_id='t'),
    dict(src_ip='192.0.2.1', dst_ip='192.0.2.2', src_port=1234, dst_port=443, protocol='tcp')])
def test_strong_bindings_survive_public_entity_policy(cfg, normalization, fields):
    rows = [record(i, time=i, hostname='shared', behavior='probe', **fields) for i in range(20)]
    result = run(rows, cfg, normalization)
    assert sizes(result) == [20]
    assert result.result.statistics['STRONG_RELATION_COUNT'] == 19


def weak_rows(times):
    return [record(i, time=t, hostname='h', process_name='worker', operation='ProcessStart',
                   behavior='execute') for i, t in enumerate(times)]


def test_real_production_weak_bridge_is_removed(cfg, normalization, policy):
    _, result = stage_run(weak_rows([0, 20, 40]), cfg, normalization, policy)
    assert sorted(s.alert_count for s in result.stages) == [1, 2]
    assert result.statistics['WEAK_BRIDGE_REMOVED_COUNT'] == 1
    removed = [d for d in result.diagnostics if d['decision'] == 'remove_weak_bridge']
    proof = AggregationBasis.model_validate(removed[0]['edge'])
    assert proof.edge_strength == 'WEAK' and proof.behavior_compatible
    assert not proof.binding_evidence
    assert removed[0]['component_check']['reason'] == 'dynamic_time_conflict'


@pytest.mark.parametrize('times', [[0, 20], [0, 10, 20], [0, 5, 10, 15]])
def test_weak_context_is_not_unconditionally_split(cfg, normalization, policy, times):
    _, result = stage_run(weak_rows(times), cfg, normalization, policy)
    assert [s.alert_count for s in result.stages] == [len(times)]
    assert all(e.edge_strength == 'WEAK' for s in result.stages for e in s.aggregation_basis)
    assert result.statistics['WEAK_BRIDGE_REMOVED_COUNT'] == 0


def test_hard_conflict_precedes_weak_bridge(cfg, normalization, policy):
    rows = [record(1, operation='ProcessStart', request_id='r', session_id='a'),
            record(2, time=1, operation='ProcessStart', request_id='r'),
            record(3, time=2, operation='ProcessStart', request_id='r', session_id='b')]
    _, result = stage_run(rows, cfg, normalization, policy)
    assert sorted(s.alert_count for s in result.stages) == [1, 2]
    assert result.statistics['COMPONENT_CONFLICT_REJECT_COUNT'] == 1


def test_strong_binding_chain_is_not_cut_as_a_weak_bridge(cfg, normalization, policy):
    rows = [record(i, time=t, operation='ProcessStart', request_id='r') for i, t in enumerate([0, 20, 40])]
    _, result = stage_run(rows, cfg, normalization, policy)
    assert [s.alert_count for s in result.stages] == [3]
    assert result.statistics['WEAK_BRIDGE_REMOVED_COUNT'] == 0
    assert all(e.edge_strength == 'STRONG' for s in result.stages for e in s.aggregation_basis)


@pytest.mark.parametrize('key', ['stage_id', 'attack_stage', 'expected_community', 'attack_path',
                               'stageId', 'Attack-Stage', 'expectedCommunity', 'attack path'])
def test_truth_guard_rejects_additional_annotations(key):
    with pytest.raises(ValueError, match='annotation_contamination'):
        reject_truth({'metadata': {key: 'synthetic-truth'}})


def test_official_pipeline_runs_in_numbered_order_once_and_stops(tmp_path, monkeypatch):
    from app.services import alert_pipeline as ingress
    from app.services.stage_pipeline import load_stage_pipeline
    import app.community.builder as community
    import app.entities.extraction as entities
    import app.stages.aggregation as stages
    import app.services.stage_pipeline as pipeline
    events = []
    for module, name, event in [(entities, 'extract_entities', '②'), (ingress, 'filter_alerts', '③'),
            (ingress, 'normalize_behaviors', '④'), (community, 'build_communities', '⑤'),
            (stages, 'aggregate_stages', '⑥'), (pipeline, 'generate_stage_pair_candidates', '⑦'),
            (pipeline, 'validate_stage_pair_candidates', '⑧')]:
        original = getattr(module, name)
        def observed(*args, _original=original, _event=event, **kwargs):
            events.append(_event)
            return _original(*args, **kwargs)
        monkeypatch.setattr(module, name, observed)
    original_import = builtins.__import__
    def guarded(name, *args, **kwargs):
        assert not name.startswith(('app.stage_relations', 'app.stage_chains', 'app.chains',
                                    'app.evidence_trace', 'app.api', 'evaluation'))
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', guarded)
    path = tmp_path/'native.jsonl'
    raw = [record(i, time=i, hostname='h', request_id='r', operation='ProcessStart') for i in range(3)]
    data = ''.join(json.dumps(dict(source_type='edr', event=r))+'\n' for r in raw).encode()
    path.write_bytes(data)
    result = load_stage_pipeline(path)
    assert events == ['②', '③', '④', '⑤', '⑥', '⑦', '⑧']
    assert [s.alert_count for s in result.stages.stages] == [3]
    assert result.normalized.entities and result.community.entities == result.normalized.entities
    assert path.read_bytes() == data and list(tmp_path.iterdir()) == [path]
    assert result.statistics['CURRENT_PIPELINE_STAGE'] == 'STAGE_8_RELATION_SEMANTICS_REPAIRED'
    assert result.statistics['NEXT_STAGE_STARTED'] is False


def test_precomputed_handoff_does_not_repeat_frontend_algorithms(tmp_path, monkeypatch):
    from app.services.alert_pipeline import load_alert_pipeline
    from app.services.stage_pipeline import prepare_stage_pipeline
    import app.services.alert_pipeline as ingress
    import app.entities.extraction as entities
    import app.community.builder as builder
    path = tmp_path/'native.jsonl'
    raw = record(1, hostname='h', operation='ProcessStart')
    path.write_text(json.dumps(dict(source_type='edr', event=raw))+'\n', encoding='utf8')
    prepared = load_alert_pipeline(path)
    def forbidden(*args, **kwargs):
        raise AssertionError('⑤ repeated a completed precursor')
    for module, name in [(ingress, 'filter_alerts'), (ingress, 'normalize_behaviors'),
                         (entities, 'extract_entities'), (builder, 'extract_entities'),
                         (builder, 'project_candidates')]:
        monkeypatch.setattr(module, name, forbidden)
    result = prepare_stage_pipeline(prepared)
    assert len(result.stages.stages) == 1
    assert result.normalized.behaviors is prepared.behaviors


def test_official_noise_handoff_prunes_removed_entity_members(tmp_path):
    from app.services.stage_pipeline import load_stage_pipeline
    from app.noise_filter import NoiseFilterConfig
    rows = [record('same', time=t, hostname='h', operation='ProcessStart') for t in (0, .5)]
    rows.append(record('background', hostname='health', operation='ProcessStart'))
    path = tmp_path/'native.jsonl'
    path.write_text(''.join(json.dumps(dict(source_type='edr', event=r))+'\n' for r in rows), encoding='utf8')
    policy = NoiseFilterConfig.model_validate(dict(background_rules=[dict(rule_id='health',
        match=dict(source_type='edr', host='health'))]))
    result = load_stage_pipeline(path, noise_config=policy)
    assert result.statistics['INPUT_ALERTS'] == 3 and result.statistics['KEPT_ALERTS'] == 1
    kept = {a.alert_id for a in result.normalized.alerts}
    assert {i for e in result.normalized.entities for i in e.alert_ids} == kept
    assert {b.alert_id for b in result.normalized.behaviors} == kept
    assert {i for s in result.stages.stages for i in s.alert_ids} == kept
    for audit in result.normalized.noise_filter.audit_records:
        assert result.normalized.noise_filter.raw_evidence(audit) in rows


def test_official_empty_input_and_corrupt_entity_handoff(tmp_path):
    from app.services.alert_pipeline import load_alert_pipeline
    from app.services.stage_pipeline import load_stage_pipeline, prepare_stage_pipeline
    path = tmp_path/'native.jsonl'
    path.write_text('', encoding='utf8')
    result = load_stage_pipeline(path)
    assert result.statistics['STAGE_COUNT'] == result.statistics['COMMUNITY_COUNT'] == 0
    path.write_text(json.dumps(dict(source_type='edr', event=record(1, hostname='h')))+'\n', encoding='utf8')
    prepared = load_alert_pipeline(path)
    prepared.entities = []
    with pytest.raises(ValueError, match='normalized_entity_partition_mismatch'):
        prepare_stage_pipeline(prepared)

