from evaluation.framework.preformula_baseline.boundary import development_config, development_cptc, verify_historical_inventory, verify_current
"""Synthetic hand-checkable evaluation fixtures; no real truth in production."""
import json
from fractions import Fraction
from pathlib import Path

import pytest

from evaluation.framework.v4_semisynthetic_baseline.blind import replay_guard, namespace
from evaluation.framework.v4_semisynthetic_baseline.common import (
    ROOT, MAPPING, THRESHOLD, VERSION, frozen_config, inventory, verify_inventory)
from evaluation.framework.v4_semisynthetic_baseline.metrics import (
    chain_metrics, distribution, pair_key, ranking, recall, separation, stable_match,
    population, correct_correlation_witness, directed_chain_hit)
from evaluation.framework.v4_semisynthetic_baseline.artifacts import require_sealed


def test_gt_and_dataset_writes_blocked_during_blind_then_evaluation_allowed(tmp_path):
    dataset = tmp_path / 'dataset'
    dataset.mkdir()
    alert, gt = dataset / 'input.jsonl', dataset / 'ground_truth.json'
    alert.write_text('{}')
    gt.write_text('{"synthetic":true}')
    before = inventory(dataset)
    output = tmp_path / 'output'
    output.mkdir()
    with replay_guard(alert, output) as (events, reads):
        assert alert.read_text() == '{}'
        for path in (gt, dataset / 'provenance.json'):
            with pytest.raises(PermissionError):
                path.read_text()
        with pytest.raises(PermissionError):
            alert.write_text('mutated')
        (output / 'prediction.json').write_text('{}')
        assert (output / 'prediction.json').read_text() == '{}'
    assert json.loads(gt.read_text())['synthetic']
    assert len(events) == 3
    assert verify_inventory(dataset, before)['status'] == 'PASS'


def test_inventory_detects_added_modified_and_deleted_files(tmp_path):
    (tmp_path / 'a').write_text('a')
    (tmp_path / 'b').write_text('b')
    before = inventory(tmp_path)
    (tmp_path / 'a').write_text('changed')
    (tmp_path / 'b').unlink()
    (tmp_path / 'c').write_text('added')
    assert set(verify_inventory(tmp_path, before)['differences']) == {'a', 'b', 'c'}


def test_candidate_recall_fixed_six_and_unique_edges():
    assert recall(['GT_E1', 'GT_E1', 'GT_E2'])['value'] == 2 / 6
    with pytest.raises(ValueError):
        recall([], total=5)
    with pytest.raises(ValueError):
        recall(list('1234567'))


def test_rank_missing_ties_stable_id_percentile_and_top_k():
    scored = {('a', 'b'): .9, ('c', 'd'): .9, ('e', 'f'): .2}
    r = ranking(scored, {'GT_E1': [('c', 'd')], 'GT_E2': [('missing', 'pair')]})
    assert r['edges']['GT_E1']['rank'] == 2
    assert r['edges']['GT_E1']['rank_min'] == 1
    assert r['edges']['GT_E1']['rank_max'] == 2
    assert r['edges']['GT_E1']['percentile'] == pytest.approx(100 * 2 / 3)
    assert r['MRR'] == .25
    assert r['top_k']['10']['edge_recall'] == .5
    assert r == ranking(dict(reversed(list(scored.items()))), {'GT_E1': [('c', 'd')], 'GT_E2': [('missing', 'pair')]})


def test_score_distribution_and_separation():
    d = distribution([0, 1, 2, 3])
    assert d['P25'] == .75 and d['median'] == 1.5 and d['P75'] == 2.25
    assert distribution([])['mean'] is None
    assert separation([.5], [.1, .5, .9])['pairwise_order_probability'] == .5


def test_exact_maximum_weight_match_and_lexical_tie_break():
    legal = {('a', '1'): Fraction(3, 4), ('a', '2'): Fraction(1, 2),
             ('b', '1'): Fraction(2, 3)}
    assert stable_match(legal) == [('a', '2'), ('b', '1')]
    ties = {(p, g): Fraction(1) for p in 'ab' for g in '12'}
    assert stable_match(ties) == [('a', '1'), ('b', '2')]
    assert stable_match({}) == []


def test_chain_direction_disconnected_path_and_isolates():
    result = chain_metrics(set('1234567'), [('1', '2'), ('2', '3'), ('5', '6')])
    assert result['longest_path_edges'] == 2
    assert result['connected_components'] == 4
    with pytest.raises(ValueError):
        chain_metrics(set('12'), [('1', '2'), ('2', '1')])
    assert pair_key('b', 'a') == ('a', 'b')


def test_native_shape_dispatch_never_uses_ids_or_labels():
    assert namespace({'event_type': 'alert'}) == 'suricata'
    assert namespace({'agent': {}, 'rule': {'groups': ['authentication_success']}}) == 'wazuh.authentication'
    assert namespace({'agent': {}, 'rule': {'groups': ['audit']}}) == 'wazuh.host'


def test_frozen_config_threshold_and_hashes_unchanged():
    before = inventory(ROOT, production=True)
    # Restore the historical snapshot as metadata; do not execute current code as v4.
    from app.services.storage import restore_config
    receipt = json.loads((ROOT/'outputs/correlation_v4_small/FREEZE_MANIFEST.json').read_text(encoding='utf8'))
    config = restore_config(receipt['algorithm_snapshot'])
    assert verify_historical_inventory(receipt['implementation'])['status'] == 'PASS'
    from app.correlation.edges import correlation_version
    assert correlation_version(config) == VERSION
    assert config.mapping_digest == MAPPING
    assert config.config_hash == '4b3f963cb482126aca41614242bb1e188ab7ddb21463a4996ea56b42379a1d73'
    assert config.algorithm.score.correlation_threshold == THRESHOLD == .65
    assert receipt['CORRELATION_V4_FROZEN']
    assert verify_inventory(ROOT, before, production=True)['status'] == 'PASS'


def test_evaluation_requires_completed_blind_artifacts_before_truth(tmp_path):
    with pytest.raises(FileNotFoundError):
        require_sealed(tmp_path)
    manifest = {'status': 'running', 'is_complete': False, 'ground_truth_loaded': False,
                'threshold': .65, 'algorithm_version': VERSION, 'files': {}}
    path = tmp_path / 'blind_run_manifest.json'
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        require_sealed(tmp_path)
    manifest.update(status='completed', is_complete=True, ground_truth_loaded=True)
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        require_sealed(tmp_path)


def test_hard_negative_gt_and_unlabeled_background_are_not_confused():
    positive, negative = {('a', 'b')}, {('a', 'h')}
    assert population(('a', 'b'), positive, negative, {'h'}, {'x', 'y'}) == 'gt_positive'
    assert population(('a', 'h'), positive, negative, {'h'}, {'x', 'y'}) == 'explicit_hard_negative'
    assert population(('h', 'x'), positive, negative, {'h'}, {'x', 'y'}) == 'hard_negative_touching_unknown'
    assert population(('x', 'y'), positive, negative, {'h'}, {'x', 'y'}) == 'background_unknown'
    with pytest.raises(ValueError):
        population(('a', 'b'), positive, positive, {'h'}, set())


def test_actual_support_pair_required_for_admission_and_directed_chain():
    e = {'support_pair': {'alert_id_src': 'a', 'alert_id_dst': 'b'}}
    assert correct_correlation_witness(e, {('a', 'b')})
    assert not correct_correlation_witness(e, {('a', 'c')})
    nodes = {'src': {'alert_ids': ['a']}, 'dst': {'alert_ids': ['b']}}
    chain = {'source_node_id': 'src', 'target_node_id': 'dst', 'alert_ids': ['a', 'b']}
    assert directed_chain_hit(chain, nodes, {'a'}, {'b'}, {('a', 'b')})
    assert not directed_chain_hit(chain, nodes, {'b'}, {'a'}, {('a', 'b')})


def test_truth_loader_checks_seal_before_first_gt_read(monkeypatch):
    from evaluation.framework.v4_semisynthetic_baseline import truth
    reads = []
    def unsealed():
        raise ValueError('not_sealed')
    monkeypatch.setattr(truth, 'require_sealed', unsealed)
    monkeypatch.setattr(truth, 'read', lambda p: reads.append(p))
    with pytest.raises(ValueError, match='not_sealed'):
        truth.load({})
    assert not reads


def test_source_raw_projection_gap_distinct_from_unobservability():
    from evaluation.framework.v4_semisynthetic_baseline.diagnosis import observation
    row = dict(alert_id='synthetic', source_namespace='wazuh.host', raw_alert={'data': {'audit': {'auid': 'u'}}},
               category='unknown', rule_id='1', signature='vendor', host=None, process=None)
    result = observation(row)
    assert result['fields']['account']['status'] == 'RAW_ONLY_UNMAPPED'
    assert result['fields']['session']['status'] == 'UNOBSERVABLE_IN_THIS_ALERT'
    assert result['category_status'] == 'VENDOR_SEMANTICS_UNMAPPED'


def test_raw_gt_equality_does_not_promote_collector_metadata_to_entity():
    from evaluation.framework.v4_semisynthetic_baseline.diagnosis import equality_projection
    a = {'dst_ip': '192.0.2.1', 'field_provenance': {'dst_ip': {'raw_pointer': '/dest_ip'}}}
    b = {'sensor': 'synthetic-host', 'field_provenance': {'sensor': {'raw_pointer': '/agent/name'}}}
    edge = {'equality_witnesses': [{'from_field': 'dest_ip', 'to_field': 'agent.ip'},
                                  {'from_field': 'dest_ip', 'to_field': 'agent.name'}]}
    result = equality_projection(edge, a, b)
    assert result[0]['source']['canonical_entity_fields'] == ['dst_ip']
    assert result[0]['target']['status'] == 'RAW_ONLY_UNMAPPED'
    assert result[1]['target']['status'] == 'RETAINED_AS_NON_ENTITY_METADATA'
    assert not result[1]['target']['canonical_entity_fields']


def test_posthoc_evaluation_cannot_import_or_call_production_replay():
    import ast
    base = ROOT / 'evaluation/framework/v4_semisynthetic_baseline'
    for name in ('evaluate.py', 'truth.py', 'metrics.py', 'diagnosis.py', 'report.py'):
        tree = ast.parse((base / name).read_text(encoding='utf8'))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or '').startswith('app.')
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {'run_correlation', 'run_reconstruction', 'generate_candidates', 'CorrelationScorer'}
