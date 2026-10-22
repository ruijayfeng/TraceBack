"""Graph membership, bridge safety, conflicts and input integrity."""
import builtins
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import hashlib
import sys

import pytest
from pydantic import ValidationError

from app.stages.graph import bridge_pairs, connected_components, weak_bridge_check
from app.stages import aggregate_stages, Stage
from test_community_builder import cfg, normalization, record
from test_stage_aggregation import policy, stage_run
from test_source_bound_projection import settings


def edge(a, b, strength='STRONG', compatible=True, binding=True):
    return SimpleNamespace(alert_ids=sorted([a, b]), edge_strength=strength,
                           behavior_compatible=compatible, binding_evidence=['request'] if binding else [])


def test_components_and_singletons():
    assert connected_components('ABCDEF', [edge('A', 'B'), edge('B', 'C'), edge('D', 'E')]) == [list('ABC'), list('DE'), ['F']]
    assert connected_components(['A'], []) == [['A']]
    assert connected_components([], []) == []


def test_graph_bridge_requires_cross_component_support_and_preserves_strong():
    # Generic graph plumbing only; production-model removal is covered by
    # test_stage56_repair.test_real_production_weak_bridge_is_removed.
    edges = [edge('A', 'B'), edge('B', 'C', 'WEAK', True, False), edge('C', 'D')]
    kept, bridges, removed = weak_bridge_check('ABCD', edges)
    assert bridges == {('A', 'B'), ('B', 'C'), ('C', 'D')}
    assert removed == [edges[1]]
    assert connected_components('ABCD', kept) == [list('AB'), list('CD')]
    for replacement in (edge('B', 'C'), edge('B', 'C', 'WEAK', True, True)):
        edges[1] = replacement
        assert not weak_bridge_check('ABCD', edges)[2]
        assert connected_components('ABCD', edges) == [list('ABCD')]
    edges[1] = edge('B', 'C', 'WEAK', True, False)
    assert not weak_bridge_check('ABCD', edges, pair_support=lambda a, b: (True, None))[2]


def test_tarjan_cycles_disconnected_and_deep():
    assert bridge_pairs('ABCDE', [edge('A', 'B'), edge('B', 'C'), edge('A', 'C'), edge('D', 'E')]) == {('D', 'E')}
    nodes = [f'{i:04}' for i in range(1500)]
    assert len(bridge_pairs(nodes, [edge(a, b) for a, b in zip(nodes, nodes[1:])])) == 1499


def test_real_sparse_graph_connectivity_and_schema(cfg, normalization, policy):
    # A-B share request, B-C share session; A-C have no direct binding.
    rows = [record(1, operation='ProcessStart', request_id='r'),
            record(2, time=1, operation='ProcessStart', request_id='r', session_id='s'),
            record(3, time=2, operation='ProcessStart', session_id='s')]
    run, result = stage_run(rows, cfg, normalization, policy)
    assert [s.alert_count for s in result.stages] == [3]
    stage = result.stages[0]
    assert len(stage.aggregation_basis) == 2
    assert all(e.edge_strength == 'STRONG' and e.temporal_check['passed'] for e in stage.aggregation_basis)
    assert Stage.model_validate_json(stage.model_dump_json()) == stage
    data = stage.model_dump()
    data['aggregation_basis'] = data['aggregation_basis'][:1]
    with pytest.raises(ValidationError, match='connected'):
        Stage.model_validate(data)


def test_unknown_host_ip_time_and_behavior_host_do_not_merge(cfg, normalization, policy):
    for operation in (None, 'ProcessStart'):
        rows = [record(i, time=i, hostname='h', src_ip='192.0.2.1', **({'operation': operation} if operation else {})) for i in range(8)]
        _, result = stage_run(rows, cfg, normalization, policy)
        assert len(result.stages) == 8
    rows = [record(i, time=i, hostname='h', user='alice') for i in range(8)]
    _, result = stage_run(rows, cfg, normalization, policy)
    assert len(result.stages) == 8


@pytest.mark.parametrize('binding', ['request_id', 'session_id', 'auth_session_id'])
def test_strong_binding_known_and_unknown(cfg, normalization, policy, binding):
    for operation in (None, 'ProcessStart'):
        rows = [record(i, time=i, **{binding: 'bound'}, **({'operation': operation} if operation else {})) for i in range(3)]
        _, result = stage_run(rows, cfg, normalization, policy)
        assert [s.alert_count for s in result.stages] == [3]


def test_hard_conflicts_do_not_leak_through_missing_context(cfg, normalization, policy):
    rows = [record(1, operation='ProcessStart', request_id='r', session_id='a'),
            record(2, operation='ProcessStart', request_id='r'),
            record(3, operation='ProcessStart', request_id='r', session_id='b')]
    _, result = stage_run(rows, cfg, normalization, policy)
    assert sorted(s.alert_count for s in result.stages) == [1, 2]
    assert result.statistics['COMPONENT_CONFLICT_REJECT_COUNT'] == 1


def test_dynamic_time_reused_and_current_gap_does_not_train_itself(cfg, normalization, policy):
    rows = [record(i, time=t, operation='ProcessStart', request_id='r') for i, t in enumerate([0, 10, 20, 30, 60])]
    _, result = stage_run(rows, cfg, normalization, policy)
    assert sorted(s.alert_count for s in result.stages) == [1, 4]
    assert any(d['reason'] == 'dynamic_time_conflict' for d in result.diagnostics)
    wider = cfg.model_copy(update=dict(temporal=cfg.temporal.model_copy(update=dict(fallback_seconds=60))))
    rows = [record(1, request_id='r'), record(2, time=45, request_id='r')]
    assert len(stage_run(rows, cfg, normalization, policy)[1].stages) == 2
    assert len(stage_run(rows, wider, normalization, policy)[1].stages) == 1


def test_deterministic_and_no_mutation_or_next_stage(cfg, normalization, policy, monkeypatch):
    original_import = builtins.__import__
    def guarded_import(name, *args, **kwargs):
        assert not name.startswith(('app.stage_relations', 'app.stage_chains', 'app.evidence_trace', 'evaluation', 'app.api'))
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', guarded_import)
    rows = [record(i, time=i, operation='ProcessStart', request_id='r') for i in range(5)]
    run, result = stage_run(rows, cfg, normalization, policy)
    original = deepcopy([a.model_dump() for a in run.alerts])
    source_settings = {a.source_namespace: settings(a.raw_alert['source_type']) for a in run.alerts}
    for _ in range(3):
        repeated = aggregate_stages(replace(run, alerts=list(reversed(run.alerts)), entities=list(reversed(run.entities))), source_settings, cfg, policy)
        assert repeated == result
    assert original == [a.model_dump() for a in run.alerts]
    assert result.statistics['NEXT_STAGE_NOT_STARTED'] is True


def test_protected_input_sha256_and_stop_guard(tmp_path, cfg, normalization, policy):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
    from verify_stage_optimization import assert_unchanged
    protected = tmp_path / 'native.json'
    protected.write_bytes(b'{"native":"synthetic protected input"}\n')
    before = {str(protected): hashlib.sha256(protected.read_bytes()).hexdigest()}
    stage_run([record(1, operation='ProcessStart', request_id='r')], cfg, normalization, policy)
    after = {str(protected): hashlib.sha256(protected.read_bytes()).hexdigest()}
    assert_unchanged(before, after)
    with pytest.raises(ValueError, match='protected_data_changed_STOP'):
        assert_unchanged(before, {str(protected): 'tampered'})
    with pytest.raises(ValueError, match='protected_data_changed_STOP'):
        assert_unchanged(before, {})
