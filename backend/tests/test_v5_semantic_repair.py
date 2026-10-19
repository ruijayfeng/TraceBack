"""Prospective synthetic semantic and graph witnesses, without dataset answers."""
from copy import deepcopy
from pathlib import Path
import pytest
from app.config import read_yaml, load_config
from app.correlation.semantic_repair.models import Policy, PairResult, CorrelationEdge
from app.correlation.semantic_repair.formula import aggregate, chain_admission
from app.correlation.semantic_repair.evidence import direction, hierarchy
from app.correlation.semantic_repair.graph import reconstruct
from app.correlation.scoring import CorrelationScorer
from app.utils.stable_id import id_for, content_digest
from test_correlation_score import inputs, alert, parent_child
from test_v5_separation_direction import base, flow_pair

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def policy():
    return Policy.model_validate(read_yaml(ROOT/'configs/algorithm-v5-semantic-repair.yaml')).model_dump(by_alias=True)


def tier(level=2, role=True):
    return dict(level=level, progression_proven=level == 3, contradiction=False,
                observed_behavior_transition=level >= 2, verified_role_bridge=role,
                context=dict(kind='ACCOUNT', specificity=.9),
                behavior_evidence=[dict(compatibility=.8)] if level >= 2 else [])


@pytest.mark.parametrize('design', ['A', 'B', 'C'])
def test_compatible_behavior_shared_account_is_not_unconditional_unlock(policy, design):
    b = base({'entity.ACCOUNT': .8})
    r = aggregate(b, b['group_support'], tier(role=False), policy, design)
    assert r['final_score'] == .45
    assert r['upgraded_group_support'] == b['group_support']


def test_three_fixed_ceiling_designs_and_dependency_max(policy):
    b = base({'entity.ACCOUNT': .8})
    assert aggregate(b, b['group_support'], tier(), policy, 'A')['final_score'] == .45
    assert aggregate(b, b['group_support'], tier(), policy, 'B')['final_score'] == .50
    assert aggregate(b, b['group_support'], tier(3), policy, 'A')['final_score'] == .8
    assert aggregate(b, b['group_support'], tier(3), policy, 'C')['final_score'] == .45
    assert set(aggregate(b, b['group_support'], tier(3), policy, 'A')['upgraded_group_support']) == {'entity.ACCOUNT'}


@pytest.mark.parametrize('level', [0, 1, 2])
def test_only_bound_transition_can_fully_remove_ceiling(policy, level):
    b = base({'entity.ACCOUNT': .8})
    assert aggregate(b, b['group_support'], tier(level), policy, 'A')['ceiling'] == .45


def test_missing_binding_not_contradiction_or_direction(policy):
    idx, settings = inputs([alert('neutral-a', host='unit', account='user', category='web_attack'),
                            alert('neutral-b', 1, host='unit', account='user', category='process_execution')])
    a, b = idx.alerts.values(); cfg = load_config(ROOT/'configs/algorithm-v0.yaml')
    d = direction(a, b, idx, settings, policy['observation_policy'])
    t = hierarchy(a, b, idx, policy['observation_policy'], d, cfg.algorithm.entity)
    assert t['level'] == 2 and not t['progression_proven']
    assert not t['verified_role_bridge'] and t['binding_state'] == 'UNOBSERVABLE'
    assert not t['contradiction'] and d['status'] == 'AMBIGUOUS_DIRECTION'


def test_unknown_without_typed_observation_does_not_imply_behavior(policy):
    idx, settings = inputs([alert('unknown-a', host='h'), alert('unknown-b', 1, host='h')])
    a, b = idx.alerts.values(); cfg = load_config(ROOT/'configs/algorithm-v0.yaml')
    d = direction(a, b, idx, settings, policy['observation_policy'])
    t = hierarchy(a, b, idx, policy['observation_policy'], d, cfg.algorithm.entity)
    assert t['level'] == 0 and not t['behavior_evidence']


def pivot_pair(mismatch=False):
    from app.adapters.wazuh import WazuhAdapter
    from app.adapters.base import AdapterSettings
    cfg = load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml', deployment_override=ROOT/'configs/sources.yaml')
    s = AdapterSettings('unit', 'wazuh_json_v1', 'unit-test', semantic_profile='wazuh_local_v1',
                        network_namespace='unit-net', asset_namespace='unit-assets', account_realm='unit-realm')
    adapter = WazuhAdapter(cfg, s)
    def raw(name, ip, stamp, data, groups):
        return dict(timestamp=stamp, id=name, agent=dict(id=name, name=name, ip=ip),
                    rule=dict(id='unit', description='synthetic observation', groups=groups, level=8), data=data)
    a = adapter.convert(raw('source', '192.0.2.10', '2022-01-01T00:00:00Z',
        dict(audit=dict(auid='actor', operation='read', file='/unit/resource', type='SYSCALL', exe='/bin/cat'), target_user='user'), ['audit']))
    b = adapter.convert(raw('target', '192.0.2.20', '2022-01-01T00:00:03Z',
        dict(dstuser='user', srcip='192.0.2.99' if mismatch else '192.0.2.10', status='success'), ['authentication']))
    idx, settings = inputs([a, b], {'unit': s})
    return idx, settings, cfg, idx.alerts[a.alert_id], idx.alerts[b.alert_id]


def test_account_role_plus_compatible_behavior_with_host_mismatch_stays_unbound(policy):
    idx, settings, cfg, a, b = pivot_pair(mismatch=True)
    d = direction(a, b, idx, settings, policy['observation_policy'])
    t = hierarchy(a, b, idx, policy['observation_policy'], d, cfg.algorithm.entity)
    assert t['level'] == 2 and t['verified_role_bridge'] and not t['binding_evidence']
    assert not d['contradiction'] and not t['progression_proven']
    baseline = base({'entity.ACCOUNT': .8})
    r = aggregate(baseline, baseline['group_support'], t, policy, 'A')
    assert r['final_score'] == .45
    assert not chain_admission(.9, d, t, baseline['gate'], policy, 'D')['accepted']


def make_edge(policy, score=.569, mismatch=False):
    idx, settings, cfg, a, b = pivot_pair(mismatch)
    d = direction(a, b, idx, settings, policy['observation_policy'])
    t = hierarchy(a, b, idx, policy['observation_policy'], d, cfg.algorithm.entity)
    baseline = base({'asset': score}, weak=False)
    variants = {design: aggregate(baseline, baseline['group_support'], t, policy, design) for design in policy['designs']}
    pair = PairResult.model_validate(dict(support_pair=[a.alert_id, b.alert_id], support_key=sorted(idx.alerts),
        valid=True, old_score=score, baseline=baseline, groups=baseline['group_support'], hierarchy=t,
        direction=d, variants=variants, policy_hash=content_digest(policy)))
    data = dict(source_alert_id=min(idx.alerts), target_alert_id=max(idx.alerts), score=variants['A']['final_score'],
                design='A', score_breakdown=variants['A'], support=pair)
    data['edge_id'] = id_for('CorrelationEdge', data)
    return idx, settings, cfg, CorrelationEdge.model_validate(data)


def test_verified_direction_independent_of_correlation_and_hybrid_graph(policy):
    idx, settings, cfg, edge = make_edge(policy)
    scorer = CorrelationScorer(idx, cfg, settings)
    a = reconstruct(idx, [edge], scorer, policy, 'A')
    d = reconstruct(idx, [edge], scorer, policy, 'D')
    assert not a[2] and len(d[2]) == 1
    assert len(d[0]) == 1 and d[2][0]['correlation_confidence'] == .569
    assert d[2][0]['direction_confidence'] == .9
    assert set(d[2][0]['alert_ids']) == set(idx.alerts)
    assert d == reconstruct(idx, list(reversed([edge])), scorer, policy, 'D')
    assert CorrelationEdge.model_validate_json(edge.model_dump_json()) == edge


@pytest.mark.parametrize('variant', ['A', 'B', 'C', 'D'])
def test_strong_correlation_ambiguous_direction_never_creates_chain(policy, variant):
    idx, settings, cfg, edge = make_edge(policy, .8, mismatch=True)
    assert not reconstruct(idx, [edge], CorrelationScorer(idx, cfg, settings), policy, variant)[2]


def test_component_guard_not_waived_by_bound_progression(policy):
    idx, settings, cfg, edge = make_edge(policy)
    scorer = CorrelationScorer(idx, cfg, settings)
    scorer.algorithm.clustering.max_incident_span_seconds = 1
    result = reconstruct(idx, [edge], scorer, policy, 'D')
    assert not result[2] and len(result[0]) == 2
    assert any('max_incident_span_seconds' in r.get('rejection_codes', []) for r in result[3])


def test_real_parent_child_instances_can_supply_bound_proof(policy):
    cfg = load_config(ROOT/'configs/algorithm-v0.yaml'); idx, settings = inputs(parent_child())
    a, b = sorted(idx.alerts.values(), key=lambda x: x.timestamp)
    scorer = CorrelationScorer(idx, cfg, settings); relations, _ = scorer.verify_relations(a, b)
    d = direction(a, b, idx, settings, policy['observation_policy'], relations=[r.json_data() for r in relations])
    t = hierarchy(a, b, idx, policy['observation_policy'], d, cfg.algorithm.entity)
    assert d['source_alert_id'] == a.alert_id and t['level'] == 3


@pytest.mark.parametrize('score,accepted', [(.549999999, False), (.55, True), (.569, True), (.70, True)])
def test_independent_policy_fixed_points(policy, score, accepted):
    _, _, _, e = make_edge(policy)
    d = e.support.direction.model_dump(mode='json')
    assert chain_admission(score, d, e.support.hierarchy, e.support.baseline['gate'], policy, 'D')['accepted'] == accepted


def test_unsupported_schema_and_score_tampering_rejected(policy):
    _, _, _, edge = make_edge(policy)
    data = edge.model_dump(mode='json'); data['score'] = .99
    with pytest.raises(ValueError): CorrelationEdge.model_validate(data)
    data = edge.model_dump(mode='json'); data['support']['hierarchy']['level'] = 2
    with pytest.raises(ValueError): CorrelationEdge.model_validate(data)


@pytest.mark.parametrize('change', [{'extra': True}, {'weak_ceiling': .50},
    {'partial_ceiling': float('nan')}, {'diagnostic_operating_points': [.65]}, {'designs': ['A']}])
def test_config_strict_validation(policy, change):
    with pytest.raises(ValueError): Policy.model_validate({**policy, **change})


def test_three_bound_operations_create_real_two_edge_path_and_reject_cycle(policy):
    from app.adapters.wazuh import WazuhAdapter
    from app.adapters.base import AdapterSettings
    from evaluation.framework.threshold_calibration.metrics import longest_path
    cfg = load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml', deployment_override=ROOT/'configs/sources.yaml')
    setting = AdapterSettings('unit', 'wazuh_json_v1', 'unit', semantic_profile='wazuh_local_v1',
                              network_namespace='unit-net', asset_namespace='unit-assets', account_realm='unit-realm')
    adapter = WazuhAdapter(cfg, setting)
    aa = [adapter.convert(dict(timestamp='2022-01-01T00:00:00Z', id='cycle-'+str(i),
        agent=dict(id=str(i), name='unit-host-'+str(i), ip='192.0.2.'+str(i+1)),
        rule=dict(id='unit', description='synthetic operation', groups=['authentication'], level=8),
        data=dict(dstuser='unit-user', target_user='unit-user', status='success',
                  srcip='192.0.2.'+str((i+2)%3+1)))) for i in range(3)]
    idx, settings = inputs(aa, {'unit': setting}); edges = []
    for left, right in [(0, 1), (1, 2), (2, 0)]:
        a, b = idx.alerts[aa[left].alert_id], idx.alerts[aa[right].alert_id]
        d = direction(a, b, idx, settings, policy['observation_policy'])
        t = hierarchy(a, b, idx, policy['observation_policy'], d, cfg.algorithm.entity)
        assert d['source_alert_id'] == a.alert_id and t['level'] == 3
        baseline = base({'asset': .8}, weak=False)
        variants = {design: aggregate(baseline, baseline['group_support'], t, policy, design) for design in policy['designs']}
        pair = PairResult.model_validate(dict(support_pair=[a.alert_id, b.alert_id], support_key=sorted([a.alert_id, b.alert_id]),
            valid=True, old_score=.8, baseline=baseline, groups=baseline['group_support'], hierarchy=t,
            direction=d, variants=variants, policy_hash=content_digest(policy)))
        data = dict(source_alert_id=min(pair.support_key), target_alert_id=max(pair.support_key),
                    score=.8, design='A', score_breakdown=variants['A'], support=pair)
        data['edge_id'] = id_for('CorrelationEdge', data); edges.append(CorrelationEdge.model_validate(data))
    scorer = CorrelationScorer(idx, cfg, settings)
    result = reconstruct(idx, edges, scorer, policy, 'D')
    assert len(result[2]) == 2
    assert longest_path([(e['source_node_id'], e['target_node_id']) for e in result[2]]) == 2
    assert sum(r.get('rejection_code') == 'cycle' for r in result[3]) == 1
    assert result == reconstruct(idx, list(reversed(edges)), scorer, policy, 'D')
