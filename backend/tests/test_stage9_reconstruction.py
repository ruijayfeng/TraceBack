"""⑨ consumes frozen outputs only; all additional topologies are synthetic."""
import builtins
from copy import deepcopy
import io
from pathlib import Path
import sys

import pytest

from app.stage_chains.reconstruction import (FrozenStageGraph, reconstruct_attack_chains,
    validate_reconstruction)
from test_community_builder import cfg, normalization, record
from test_stage_attack_chains import graph, mixed_rows
from test_stage_candidates import source
from test_stage_evidence import evidence_policy, verify


def legacy(rows, cfg, normalization):
    return FrozenStageGraph.from_legacy(graph(rows, cfg, normalization))


def partitions(result):
    return sorted(sorted(c.stage_ids) for c in result.chains)


def test_no_added_bridge_same_community_and_host_nearby_time(cfg, normalization):
    # Strong native arrows form two components although all stages share h.
    # Existing weak host relations are absent in this frozen synthetic graph.
    original = graph([record('a', hostname='h'), record('b', hostname='h', time=5, parent_event_id='a'),
        record('c', hostname='h', time=6), record('d', hostname='h', time=10, parent_event_id='c')], cfg, normalization)
    # A test-only sealed edge subset models an upstream graph with no B/C edge.
    from app.evidence_trace import EvidenceTraceIndex
    from app.stage_chains import StageGraphSnapshot
    kept = [r for r in original.relations.values() if r.relation_type == 'STRONG_DIRECTED']
    idx = EvidenceTraceIndex(original.source_analysis_id, list(original.trace_index._alerts.values()),
        list(original.stages.values()), list(original.trace_index._behaviors.values()), kept)
    traces = [idx.stage_trace(s) for s in idx.stage_ids] + [idx.relation_trace(r) for r in idx.relation_ids]
    frozen = FrozenStageGraph.from_legacy(StageGraphSnapshot(list(original.stages.values()), kept, traces, idx))
    before = deepcopy(frozen.signature())
    result = reconstruct_attack_chains(frozen)
    assert sorted(len(c.stage_ids) for c in result.chains) == [2, 2]
    assert len({s.community_id for s in frozen.stages.values()}) == 1
    assert frozen.signature() == before
    assert sorted(r for c in result.chains for r in c.relation_ids) == sorted(frozen.relations)


def test_undirected_never_oriented_by_time(cfg, normalization):
    original = source([record(1, session_id='s'), record(2, time=300, session_id='s')], cfg, normalization)
    from app.stage_evidence import load_evidence_config
    evidence = verify(original, cfg, load_evidence_config(Path(__file__).resolve().parents[2]/'configs/stage-evidence-v1.yaml'))
    frozen = FrozenStageGraph.from_stage8(original.stages.stages, evidence, original.alerts)
    before = deepcopy(evidence)
    chain, = reconstruct_attack_chains(frozen).chains
    relation, = frozen.relations.values()
    assert relation.relation_type == 'UNDIRECTED_EDGE'
    assert relation.from_stage_id is relation.to_stage_id is None
    assert chain.entry_stage_ids == chain.exit_stage_ids == []
    assert evidence == before


def test_single_stage_and_empty_graph(cfg, normalization):
    frozen = legacy([record('a')], cfg, normalization)
    chain, = reconstruct_attack_chains(frozen).chains
    assert chain.single_stage and chain.stage_ids == sorted(frozen.stages) and chain.relation_ids == []
    assert chain.entry_stage_ids == chain.exit_stage_ids == chain.stage_ids
    empty = dict(contract_version='stage-evidence-v2', decisions=[], claims=[], context_postings=[],
        trace=dict(raw_pointers=[], validations=[], observations=[]))
    assert reconstruct_attack_chains(FrozenStageGraph.from_stage8([], empty, [])).chains == []


def test_mixed_three_original_relation_types_and_evidence_immutable(cfg, normalization):
    frozen = legacy(mixed_rows(), cfg, normalization)
    before = deepcopy(frozen.signature())
    result = reconstruct_attack_chains(frozen)
    chain, = result.chains
    assert {r.relation_type for r in frozen.relations.values()} == {'STRONG_DIRECTED', 'STRONG_UNDIRECTED', 'WEAK_DIRECTED'}
    assert chain.relation_ids == sorted(frozen.relations)
    assert frozen.signature() == before
    assert result.guard['RELATION_IDS_UNCHANGED'] and result.guard['STAGE_RELATION_GRAPH_IMMUTABLE']
    assert result.guard['STAGE_RELATION_DIGEST_BEFORE'] == result.guard['STAGE_RELATION_DIGEST_AFTER']
    assert validate_reconstruction(result, frozen)['DANGLING_REFERENCE_COUNT'] == 0


def test_disconnected_two_and_three_nodes_not_merged(cfg, normalization):
    frozen = legacy([record('a'), record('b', time=1, parent_event_id='a'),
        record('c', time=2, parent_event_id='b'), record('d', time=3),
        record('e', time=4, parent_event_id='d')], cfg, normalization)
    result = reconstruct_attack_chains(frozen)
    assert sorted(len(c.stage_ids) for c in result.chains) == [2, 3]


@pytest.mark.parametrize('change', ['add', 'remove', 'id', 'type', 'direction', 'confidence', 'evidence', 'stage'])
def test_explicit_guard_rejects_every_mutation(cfg, normalization, change):
    frozen = legacy(mixed_rows(), cfg, normalization)
    relation = next(iter(frozen.relations.values()))
    if change == 'add':
        frozen.relations['str_' + '0'*64] = relation
    elif change == 'remove':
        frozen.relations.pop(relation.relation_id)
    elif change == 'stage':
        next(iter(frozen.stages.values())).alert_ids.clear()
    elif change == 'evidence':
        object.__setattr__(relation.primary_evidence, 'reason', 'changed nested witness')
    else:
        key, value = {'id': ('relation_id', 'str_' + '0'*64), 'type': ('relation_type', 'WEAK_DIRECTED'),
            'direction': ('from_stage_id', None), 'confidence': ('confidence', 0.123456)}[change]
        if getattr(relation, key) == value:
            value = 'STRONG_UNDIRECTED' if key == 'relation_type' else relation.stage_a_id
        object.__setattr__(relation, key, value)
    with pytest.raises(ValueError, match='graph_modified'):
        reconstruct_attack_chains(frozen)


def test_guard_detects_mutation_during_assembly(cfg, normalization, monkeypatch):
    frozen = legacy(mixed_rows(), cfg, normalization)
    import app.stage_chains.reconstruction as module
    original = module.components
    def mutate(graph):
        result = original(graph)
        next(iter(graph.relations.values())).supporting_evidence.clear()
        graph.decisions.clear()
        return result
    monkeypatch.setattr(module, 'components', mutate)
    with pytest.raises(ValueError, match='graph_modified'):
        reconstruct_attack_chains(frozen)


def test_stage8_context_and_negative_decisions_cannot_connect(cfg, normalization, evidence_policy):
    upstream = source([record(i, time=i, session_id='shared') for i in range(3)], cfg, normalization)
    evidence = verify(upstream, cfg, evidence_policy)
    assert evidence.context_postings and all(d.relation_type == 'NO_RELATION' for d in evidence.decisions)
    before = deepcopy(evidence)
    frozen = FrozenStageGraph.from_stage8(upstream.stages.stages, evidence, upstream.alerts)
    result = reconstruct_attack_chains(frozen)
    assert len(result.chains) == 3 and all(c.single_stage for c in result.chains)
    assert all(not c.relation_ids for c in result.chains) and evidence == before
    assert validate_reconstruction(result, frozen)['EVIDENCE_TRACE_PRESERVED']


@pytest.mark.parametrize('target', ['claim', 'observation', 'pointer', 'negative_decision', 'context'])
def test_official_trace_and_negative_decisions_are_guarded(cfg, normalization, evidence_policy, target):
    upstream = source([record(i, time=i, session_id='shared') for i in range(3)], cfg, normalization)
    evidence = verify(upstream, cfg, evidence_policy)
    frozen = FrozenStageGraph.from_stage8(upstream.stages.stages, evidence, upstream.alerts)
    if target == 'claim': evidence.claims[0].observation_ids.clear()
    elif target == 'observation': evidence.trace.observations[0].raw_pointer_ids.clear()
    elif target == 'pointer': object.__setattr__(evidence.trace.raw_pointers[0].raw_pointer, 'pointer', '/missing')
    elif target == 'negative_decision': evidence.decisions.pop()
    else: evidence.context_postings[0].stage_ids.clear()
    with pytest.raises(ValueError, match='graph_modified'):
        reconstruct_attack_chains(frozen)


@pytest.mark.parametrize('target', ['raw', 'alert', 'claim', 'observation', 'pointer', 'validation'])
def test_missing_existing_evidence_fails_closed(cfg, normalization, evidence_policy, target):
    upstream = source([record(1, session_id='s'), record(2, time=300, session_id='s')], cfg, normalization)
    evidence = deepcopy(verify(upstream, cfg, evidence_policy).model_dump(mode='json'))
    alerts = [a.model_dump(mode='json') for a in upstream.alerts]
    if target == 'raw': alerts[0]['raw_alert'] = None
    elif target == 'alert': alerts.pop()
    elif target == 'claim': evidence['claims'].clear()
    elif target == 'observation': evidence['trace']['observations'].clear()
    elif target == 'pointer': evidence['trace']['raw_pointers'].pop()
    else: evidence['trace']['validations'].clear()
    with pytest.raises(ValueError, match='evidence|reference|pointer'):
        FrozenStageGraph.from_stage8(upstream.stages.stages, evidence, alerts)


def test_no_io_or_upstream_algorithm_calls(cfg, normalization, evidence_policy, monkeypatch):
    upstream = source([record(1, session_id='s'), record(2, time=300, session_id='s')], cfg, normalization)
    evidence = verify(upstream, cfg, evidence_policy)
    frozen = FrozenStageGraph.from_stage8(upstream.stages.stages, evidence, upstream.alerts)
    forbidden = ('app.adapters.', 'app.entities.extraction', 'app.entities.front_data', 'app.community.builder',
        'app.stages.aggregation', 'app.stages.behavior', 'app.stage_candidates.', 'app.stage_evidence.',
        'app.stage_relations.', 'app.services.', 'app.api.', 'app.ai.', 'evaluation.')
    def profile(frame, event, arg):
        if event == 'call':
            assert not frame.f_globals.get('__name__', '').startswith(forbidden)
    def no_io(*args, **kwargs):
        raise AssertionError('stage9_has_no_io')
    monkeypatch.setattr(builtins, 'open', no_io)
    monkeypatch.setattr(io, 'open', no_io)
    old = sys.getprofile()
    sys.setprofile(profile)
    try:
        validate_reconstruction(reconstruct_attack_chains(frozen), frozen)
    finally:
        sys.setprofile(old)


def test_branch_and_cycle_preserved(cfg, normalization):
    branch = legacy([record('a'), record('b', time=5, parent_event_id='a'),
        record('c', time=10, parent_event_id='a')], cfg, normalization)
    chain, = reconstruct_attack_chains(branch).chains
    assert len(chain.entry_stage_ids) == 1 and len(chain.exit_stage_ids) == 2
    cycle = legacy([record('a', parent_event_id='c'), record('b', time=5, parent_event_id='a'),
        record('c', time=10, parent_event_id='b')], cfg, normalization)
    chain, = reconstruct_attack_chains(cycle).chains
    assert chain.has_directed_cycle and not chain.entry_stage_ids and not chain.exit_stage_ids
    assert len(chain.relation_ids) == 3


def test_result_tamper_is_rejected(cfg, normalization):
    frozen = legacy(mixed_rows(), cfg, normalization)
    result = reconstruct_attack_chains(frozen)
    result.chains.clear()
    with pytest.raises(ValueError, match='membership_or_metadata'):
        validate_reconstruction(result, frozen)


def test_input_order_does_not_change_membership_identity_or_time(cfg, normalization):
    frozen = legacy(mixed_rows(), cfg, normalization)
    first = reconstruct_attack_chains(frozen)
    frozen.stages = dict(reversed(list(frozen.stages.items())))
    frozen.relations = dict(reversed(list(frozen.relations.items())))
    assert reconstruct_attack_chains(frozen) == first
    chain, = first.chains
    assert chain.start_time == min(s.start_time for s in frozen.stages.values())
    assert chain.end_time == max(s.end_time for s in frozen.stages.values())
