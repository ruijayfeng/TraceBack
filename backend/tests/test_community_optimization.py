"""Synthetic admission/merge controls; real experiment input is never edited."""
import builtins
from dataclasses import replace

import pytest
from pydantic import ValidationError

from app.community.config import TemporalPolicy, CommonEntityPolicy
from app.community.evidence import Binding, evidence_tier
from app.community.index import CommunityIndex
from app.community.temporal import TemporalHistory
from test_community_builder import cfg, normalization, record, run, sizes
from test_entity_binding_index import profiles


@pytest.mark.parametrize('binding', [dict(request_id='r'), dict(session_id='s'), dict(task_id='t'),
    dict(src_ip='192.0.2.1', dst_ip='192.0.2.2', src_port=1234, dst_port=443, protocol='tcp')])
def test_tier_a_keeps_binding_identity(binding, cfg, normalization):
    r = run([record(1, **binding), record(2, time=10, **binding)], cfg, normalization)
    assert sizes(r) == [2]
    assert r.result.statistics['STRONG_RELATION_COUNT'] == 1
    assert all(evidence_tier(e.identity_kind) == 'A' for c in r.result.incident_candidates for e in c.matching_evidence)


@pytest.mark.parametrize('fields', [dict(hostname='h'), dict(user='u'), dict(process_guid='guid'),
    dict(src_ip='192.0.2.1'), dict(dst_ip='192.0.2.1'), dict(dst_port=443), dict(protocol='tcp')])
def test_single_factor_never_admits(fields, cfg, normalization):
    assert sizes(run([record(1, **fields), record(2, time=1, **fields)], cfg, normalization)) == [1, 1]


@pytest.mark.parametrize('fields', [dict(hostname='h', process_guid='guid'), dict(hostname='h', user='u'),
    dict(process_guid='guid', behavior='execute'), dict(hostname='h', user='u', behavior_label='execute')])
def test_context_combinations_require_time(fields, cfg, normalization):
    good = run([record(1, **fields), record(2, time=5, **fields)], cfg, normalization)
    assert sizes(good) == [2] and good.result.statistics['CONTEXT_RELATION_COUNT'] == 1
    bad = run([record(1, **fields), record(2, time=100, **fields)], cfg, normalization)
    assert sizes(bad) == [1, 1]
    assert bad.result.statistics['rejection_counts']['DYNAMIC_TIME_INCOMPATIBLE'] > 0


def test_ip_behavior_time_requires_an_independent_host_context(cfg, normalization):
    a = record(1, hostname='h', src_ip='192.0.2.1', behavior='probe')
    good = run([a, dict(a, event_id='2', timestamp=record(2, time=5)['timestamp'])], cfg, normalization)
    assert sizes(good) == [2] and good.result.statistics['WEAK_RELATION_COUNT'] == 1
    assert sizes(run([a, record(2, time=100, src_ip='192.0.2.1', behavior='probe')], cfg, normalization)) == [1, 1]
    assert sizes(run([a, record(2, time=5, src_ip='192.0.2.1', behavior='unrelated')], cfg, normalization)) == [1, 1]


@pytest.mark.parametrize('fields', [dict(hostname='shared', behavior='scan'),
                                    dict(src_ip='192.0.2.1', behavior='scan'),
                                    dict(user='admin', behavior='scan')])
def test_high_degree_context_does_not_join_scenarios(fields, cfg, normalization):
    rows = [record(i, time=i, session_id='s' + str(i // 2), **fields) for i in range(12)]
    r = run(rows, cfg, normalization)
    assert sizes(r) == [2] * 6
    assert r.result.statistics['HIGH_DEGREE_ENTITY_HIT_COUNT'] == 12
    # Remove sessions as well: frequency suppression must work independently
    # of distinct-binding conflict detection.
    rows = [{k: v for k, v in row.items() if k != 'session_id'} for row in rows]
    r = run(rows, cfg, normalization)
    assert sizes(r) == [1] * 12
    assert any(k.startswith('HIGH_DEGREE_') for k in r.result.statistics['rejection_counts'])


def test_high_degree_host_account_needs_extra_context(cfg, normalization):
    rows = [record(i, time=i, hostname='gateway', user='admin') for i in range(12)]
    assert sizes(run(rows, cfg, normalization)) == [1] * 12
    rows = [dict(row, process_guid='process' + str(i // 2)) for i, row in enumerate(rows)]
    assert sizes(run(rows, cfg, normalization)) == [2] * 6


@pytest.mark.parametrize('fields', [dict(src_ip='192.0.2.1', hostname='h', behavior='scan'),
                                    dict(hostname='h', user='u'), dict(hostname='h', process_guid='guid')])
def test_nonbinding_admission_cannot_merge_regions(fields, cfg, normalization):
    rows = [record(1, time=0, request_id='a', **fields), record(2, time=1, request_id='a', **fields),
            record(3, time=2, request_id='b', **fields), record(4, time=3, request_id='b', **fields),
            record(5, time=4, **fields)]
    r = run(rows, cfg, normalization)
    assert sizes(r) == [2, 3]
    assert r.result.statistics['BRIDGE_SUPPRESSION_COUNT'] > 0
    assert r.result.statistics['merge_operations'] == 0


def test_strong_bridge_can_merge_with_public_entities(cfg, normalization):
    rows = [record(1, request_id='a'), record(2, time=1, request_id='a'),
            record(3, time=2, task_id='b'), record(4, time=3, task_id='b'),
            record(5, time=4, request_id='a', task_id='b')]
    r = run(rows, cfg, normalization)
    assert sizes(r) == [5] and r.result.statistics['merge_operations'] == 1


def test_dynamic_threshold_is_learned_from_prior_cadence(cfg, normalization):
    policy = TemporalPolicy(min_seconds=5, fallback_seconds=30, max_seconds=100, min_intervals=3)
    fast = TemporalHistory([0, 10, 20, 30])
    slow = TemporalHistory([0, 20, 40, 60])
    assert fast.snapshot(policy)['dynamic_threshold_seconds'] == 10
    assert slow.snapshot(policy)['dynamic_threshold_seconds'] == 20
    assert not fast.compatible(15, policy) and slow.compatible(15, policy)
    assert TemporalHistory([0]).snapshot(policy)['fallback_used']
    assert TemporalHistory([0, 0, 0, 0]).snapshot(policy)['dynamic_threshold_seconds'] == 5
    assert TemporalHistory([0, 10000, 20000, 30000]).snapshot(policy)['dynamic_threshold_seconds'] == 100
    # An outlier must not train its own acceptance, even within the recall cap.
    rows = [record(i, time=t, hostname='h', user='u') for i, t in enumerate([0, 10, 20, 30, 45])]
    r = run(rows, cfg, normalization)
    assert sizes(r) == [1, 4]
    assert r.result.statistics['rejection_counts']['DYNAMIC_TIME_INCOMPATIBLE'] > 0


def test_adaptive_index_recall_is_not_limited_by_old_fixed_tier_window(cfg, normalization):
    rows = [record(i, time=t, hostname='h', behavior='probe') for i, t in enumerate([0, 25, 50, 75, 110])]
    r = run(rows, cfg, normalization)
    ps = profiles(r, cfg)
    index = CommunityIndex(cfg)
    index.add(ps[-2])
    assert any(row[2].kind == 'host' for row in index.query(ps[-1]))


def test_diagnostics_cover_every_community_and_resolvable_evidence(cfg, normalization):
    r = run([record(1, hostname='h', user='u'), record(2, time=5, hostname='h', user='u'), record(3)], cfg, normalization)
    summaries = [d for d in r.result.diagnostics if d['decision'] == 'COMMUNITY_SUMMARY']
    assert len(summaries) == 2
    assert {d['community_id'] for d in summaries} == {c.community_id for c in r.result.incident_candidates}
    for d in summaries:
        assert all(k in d for k in ('members', 'association_evidence_summary', 'strong_binding_count',
            'context_relation_count', 'weak_relation_count', 'time_range', 'bridge_suppression_count',
            'rejected_weak_links', 'high_degree_entity_hits', 'temporal'))
    alerts = {a.alert_id: a for a in r.alerts}
    for c in r.result.incident_candidates:
        for e in c.matching_evidence:
            assert all(p.resolve(alerts) is not None for p in e.supporting_evidence)


def test_missing_fields_sources_typed_keys_and_no_later_stage_imports(cfg, normalization, monkeypatch):
    original = builtins.__import__
    def guarded(name, *args, **kwargs):
        assert not name.startswith(('app.stages', 'app.stage_relations', 'app.stage_chains', 'app.chains',
                                    'app.api', 'evaluation', 'app.correlation.scoring'))
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', guarded)
    r = run([record(1), record(2, 'waf'), record(3, hostname='10.0.0.1'), record(4, user='10.0.0.1')], cfg, normalization)
    assert sizes(r) == [1] * 4
    ps = profiles(r, cfg)
    a = Binding(5, 'core_host', 'identical', ('/event_id',), projection='entity')
    b = replace(a, kind='core_account')
    ps[0].bindings = [a]; ps[1].bindings = [b]
    index = CommunityIndex(cfg); index.add(ps[0])
    assert index.query(ps[1]) == []


@pytest.mark.parametrize('fields', [dict(min_seconds=31, fallback_seconds=30), dict(max_seconds=10), dict(min_intervals=1)])
def test_temporal_config_rejects_invalid_bounds(fields):
    with pytest.raises(ValidationError):
        TemporalPolicy(**fields)


def test_common_config_rejects_invalid_bounds():
    with pytest.raises(ValidationError):
        CommonEntityPolicy(min_count=1)
