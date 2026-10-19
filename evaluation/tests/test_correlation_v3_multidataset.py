"""Task C exact populations, frozen calls, truth isolation and honest blockers."""

from copy import deepcopy
import gzip
import json
from pathlib import Path
import shutil

import pytest
import yaml

from app.correlation.edges import run_correlation
from app.correlation.index import AlertIndex
from app.dedup import deduplicate
from app.entities.extraction import extract_entities
from app.models import CanonicalAlert
from evaluation.framework.correlation_v3_multidataset.common import (
    bucket, capture_integrity, discover, distribution, freeze_recipe, present, read_json, truth_tripwire, write)
from evaluation.framework.correlation_v3_multidataset.diagnosis import (
    diagnose_scene, ingress_observation_coverage, offline_windows, reproduce_observation_pointer_gap)
from evaluation.framework.correlation_v3_multidataset.observer import FrozenBudgetBlocked, Observer
from evaluation.framework.correlation_v3_multidataset.pipeline import index_storage_lower_bound, run_scene, scan_scene
from evaluation.framework.correlation_v3_multidataset.report import apply_execution_progress, funnel, generate_report, summary_row
from test_aminer_adapter import aminer_record
from test_wazuh_adapter import synthetic_record


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def task_c_root(tmp_path):
    (tmp_path/'configs').mkdir()
    for name in ('algorithm-v3.yaml', 'sources.yaml'):
        shutil.copyfile(ROOT/'configs'/name, tmp_path/'configs'/name)
    shutil.copytree(ROOT/'configs/mappings', tmp_path/'configs/mappings')
    manifest = {'dataset_id': 'ait_ads', 'name': 'synthetic Task C integration', 'dataset_version': 1,
        'default_scene': 'one', 'source_profiles': {
            'aminer': {'format_profile': 'ait_ads_v1_aminer_json', 'generator': 'AMiner', 'generator_version': 'unknown', 'epoch_unit': 'seconds', 'timezone': 'UTC'},
            'wazuh': {'format_profile': 'wazuh_json_v1', 'generator': 'Wazuh', 'generator_version': 'unknown', 'epoch_unit': None, 'timezone': 'UTC'}},
        'scenes': {}, 'evaluation': {'official_labels': {'path': 'one/evaluation/labels.csv'}}}
    for scene in ('one', 'two'):
        directory = tmp_path/'data/ait_ads'/scene/'raw'
        directory.mkdir(parents=True)
        manifest['scenes'][scene] = {'enabled': True, 'namespace': 'synthetic.'+scene,
            'network_namespace': 'synthetic.'+scene+'.network',
            'raw': {'aminer': scene+'/raw/aminer.json', 'wazuh': scene+'/raw/wazuh.json'}}
        raws = [synthetic_record(id='task-c-'+str(i), timestamp=f'2022-01-21T00:00:{i:02d}Z',
            data={'host': 'synthetic-host', 'user': 'synthetic-user'}, rule={'id': str(100+i), 'level': 12, 'description': 'synthetic-'+str(i)})
            for i in range(3)]
        (directory/'wazuh.json').write_text('\n'.join(json.dumps(r) for r in raws+[raws[0]])+'\n', encoding='utf-8')
        (directory/'aminer.json').write_text(json.dumps(aminer_record())+'\n', encoding='utf-8')
    (tmp_path/'data/ait_ads/dataset.yaml').write_text(yaml.safe_dump(manifest), encoding='utf-8')
    return tmp_path


@pytest.mark.parametrize('value,expected', [(0, '[0.00,0.10)'), (.5, '[0.50,0.60)'),
    (.6, '[0.60,0.65)'), (.65, '[0.65,0.70)'), (.7, '[0.70,0.80)'), (1, '[0.90,1.00]')])
def test_distribution_boundaries_are_unrounded(value, expected):
    assert bucket(value) == expected


def test_empty_distribution_is_null_and_linear_quantiles():
    empty = distribution([])
    assert empty['max'] is None and empty['mean'] is None and empty['status'] == 'not_applicable'
    row = distribution([0, 1])
    assert row['P25'] == .25 and row['P75'] == .75


def test_every_scene_uses_identical_effective_config_and_separate_namespaces(task_c_root):
    datasets, config, sources, recipe = freeze_recipe(task_c_root)
    assert len(sources) == 4
    assert config.algorithm.normalization.source_timezones == {k: 'UTC' for k in sources}
    assert set(datasets['one'].sources).isdisjoint(datasets['two'].sources)
    assert recipe['threshold'] == .65


def test_runtime_tripwire_during_production_only(tmp_path):
    path = tmp_path/'labels.csv'
    path.write_text('synthetic truth', encoding='utf-8')
    with truth_tripwire(tmp_path):
        with pytest.raises(RuntimeError, match='production_ground_truth_access_blocked'):
            path.read_text(encoding='utf-8')
    assert path.read_text(encoding='utf-8') == 'synthetic truth'


def test_full_isolated_pipeline_observer_does_not_change_formal_output(task_c_root):
    datasets, config, settings, recipe = freeze_recipe(task_c_root)
    dest = task_c_root/'outputs/correlation_v3_multidataset/one'
    ingress = scan_scene(task_c_root, datasets['one'], config, dest)
    assert ingress['raw_alert_count'] == 5 and ingress['canonical_alert_count'] == 4
    assert ingress['duplicate_import_count'] == 1 and ingress['rejected_count'] == 0
    result = run_scene(task_c_root, 'one', dest)
    assert result['status'] == 'completed', result.get('traceback')
    assert result['config_hash'] == recipe['config_hash']
    assert result['ground_truth_used'] is False
    with gzip.open(dest/'canonical_ingress.jsonl.gz', 'rt', encoding='utf-8') as handle:
        alerts = sorted((CanonicalAlert.model_validate_json(line) for line in handle), key=lambda a: a.alert_id)
    groups = deduplicate(alerts, config, settings).groups
    extracted = extract_entities(alerts, settings)
    plain = run_correlation(extracted.alerts, groups, extracted.entities, config, settings)
    with gzip.open(dest/'correlation_edges.jsonl.gz', 'rt', encoding='utf-8') as handle:
        observed = [json.loads(line) for line in handle]
    assert observed == [e.model_dump(mode='json') for e in plain.edges]
    assert result['scores']['all_scored_candidates']['count'] == len(plain.candidates.pairs)
    assert sum(result['scores']['all_scored_candidates']['buckets'].values()) == len(plain.candidates.pairs)
    assert result['evidence']['edge_count'] == len(plain.edges)
    assert result['evidence']['candidate_continuity_observations']['account_continuity']['count'] > 0
    assert result['evidence']['candidate_continuity_observations']['session_continuity']['count'] == 0
    assert result['counts']['scored_candidate_count'] == result['counts']['candidate_pair_count']
    assert all(a.source_namespace in datasets['one'].sources for a in extracted.alerts)
    near, admitted, missed = diagnose_scene(dest, result, {'records': [], 'limitations': []}, config)
    for case in near['top_rejected'] + admitted['cases']:
        assert not case['pointer_errors']
        assert abs(case['individual_score_contribution']['recomputed_raw_total'] -
                   next(p['member']['raw_total'] for p in result['samples']['top_rejected'] + result['samples']['top_admitted']
                        if p['decision']['support_key'] == case['support_key'])) < .00001
    assert admitted['offline_window_review']['pairwise_precision'] is None
    # Report rendering includes every required output and honestly keeps the
    # second, unexecuted scenario blocked. This GT is synthetic evaluation-only.
    label_path = task_c_root/'data/ait_ads/one/evaluation/labels.csv'
    label_path.parent.mkdir()
    label_path.write_text('scenario,attack,start,end\none,synthetic,1642723200,1642723203\n', encoding='utf-8')
    (task_c_root/'AGENTS.md').write_text('synthetic test root', encoding='utf-8')
    report_dir = dest.parent
    write(report_dir/'recipe.json', recipe)
    write(report_dir/'protected_before.json', capture_integrity(task_c_root))
    write(report_dir/'dataset_inventory.json', discover(task_c_root, datasets))
    assert generate_report(task_c_root, report_dir) == 'C_EVALUATION_BLOCKED'
    comparison = read_json(report_dir/'cross_dataset_comparison.json')
    assert comparison['completed_dataset_count'] == 1 and comparison['blocked_dataset_count'] == 1
    assert (report_dir/'MULTIDATASET_EVALUATION_REPORT.md').is_file()
    assert read_json(report_dir/'integrity.json')['passed']
    temporal = read_json(report_dir/'labels_window_coverage.json')['one']
    assert temporal['canonical_alert_count'] == ingress['canonical_alert_count']
    assert temporal['alert_or_pair_quality_evaluation_coverage'] == 0
    assert temporal['temporally_overlapping_alert_count'] + temporal['outside_window_unlabelled_alert_count'] == ingress['canonical_alert_count']


def test_resource_truncation_never_becomes_complete_population(task_c_root):
    from types import SimpleNamespace
    datasets, config, settings, recipe = freeze_recipe(task_c_root)
    directory = task_c_root/'observe'
    directory.mkdir()
    with (directory/'diag.jsonl').open('w', encoding='utf-8') as handle:
        observer = Observer(directory, handle, config)
        fake = SimpleNamespace(pairs=[1], candidate_truncated=True, admitted_count=2,
            resource_truncated_count=1, policy_pruned_count=0, candidate_admission_stats={}, potential_pair_stats={})
        with pytest.raises(FrozenBudgetBlocked, match='resource_truncation'):
            observer.prepare_candidates(None, fake)
        assert observer.candidate_summary['admitted_candidate_count'] == 2
        observer.close()
        observer.finish_observation()


def test_unknown_algorithm_counts_not_zero_and_funnel_units(tmp_path):
    result = {'dataset': 'synthetic', 'status': 'blocked', 'counts': {'representative_count': 10}, 'blocked_reason': 'resource'}
    row = summary_row(result, {'raw_alert_count': 12, 'canonical_alert_count': 11})
    assert row['correlation_edge_count'] is None and row['max_score'] is None and row['cross_source_edges'] is None
    stages = funnel(row, result)['stages']
    assert stages[-1]['conversion_rate'] is None
    (tmp_path/'worker.log').write_text('\n'.join(json.dumps(r) for r in (
        {'dataset': 'synthetic', 'stage': 'candidates', 'count': 20},
        {'dataset': 'synthetic', 'stage': 'scoring', 'verified_candidates': 10, 'accepted_edges': 2})), encoding='utf-8')
    receipt = summary_row(apply_execution_progress(result, tmp_path), {'raw_alert_count': 12, 'canonical_alert_count': 11})
    assert receipt['candidate_pair_count'] == 20 and receipt['candidate_per_representative'] == 2
    assert receipt['blocked_stage'] == 'scoring'
    assert receipt['scored_candidate_count'] is None and receipt['correlation_edge_count'] is None


def test_index_allocation_proof_matches_actual_existing_postings(task_c_root):
    import struct
    import sys
    from app.adapters import WazuhAdapter
    datasets, config, settings, recipe = freeze_recipe(task_c_root)
    adapter = WazuhAdapter(config, datasets['one'].sources['synthetic.one.wazuh'][1])
    alerts = [adapter.convert(synthetic_record(id='allocation-'+str(i),
        timestamp=f'2022-01-21T00:00:{i:02d}Z', data={'host': 'synthetic-host', 'user': 'synthetic-'+str(i)})) for i in range(20)]
    extracted = extract_entities(alerts, settings)
    bound = index_storage_lower_bound(extracted.alerts, [])
    index = AlertIndex(extracted.alerts, [], extracted.entities)
    postings = [p for grouped in (index.time, *index.by_source.values(), *index.by_sensor.values(), *index.by_entity.values())
                for p in grouped.values()]
    actual = sum(sys.getsizeof(bit)+struct.calcsize('P') for p in postings for bit in p.bits if bit.bit_length() > 9)
    assert bound['bytes'] == actual


def test_window_boundary_is_unlabelled_not_false_positive():
    alerts = {'a': {'timestamp': '2022-01-01T00:00:00.000000Z'},
              'b': {'timestamp': '2022-01-01T00:00:01.000000Z'}}
    gt = {'records': [{'scene_id': 'synthetic', 'attack_label': 'synthetic',
        'start_time': '2022-01-01T00:00:00.000000Z', 'end_time': '2022-01-01T00:00:01.000000Z'}], 'limitations': []}
    edges = [{'edge_id': 'synthetic-edge', 'support_pair': {'alert_id_src': 'a', 'alert_id_dst': 'b'}}]
    result, windows = offline_windows(gt, 'synthetic', alerts, {'a': 'a', 'b': 'b'}, edges)
    assert windows['a'] == {0} and 'b' not in windows
    assert result['potential_false_correlations'][0]['classification'] == 'WINDOW_BOUNDARY_REVIEW'
    assert result['pairwise_precision'] is None and result['alert_or_pair_quality_evaluation_coverage'] == 0


def test_production_incomplete_record_is_a_blocker_not_an_empty_graph(task_c_root, monkeypatch):
    from app.correlation.edges import correlation_version, resource_incomplete
    from app.utils.stable_id import id_for
    from evaluation.framework.correlation_v3_multidataset import pipeline
    datasets, config, settings, recipe = freeze_recipe(task_c_root)
    directory = task_c_root/'outputs/correlation_v3_multidataset/one'
    scan_scene(task_c_root, datasets['one'], config, directory)
    def exhausted(alerts, groups, entities, effective_config, source_settings, **kwargs):
        import time
        index = AlertIndex(alerts, groups, entities)
        analysis_id = id_for('AnalysisRecord', {'input_alert_ids': list(index.alerts),
            'config_hash': recipe['config_hash'], 'algorithm_version': correlation_version(effective_config),
            'schema_version': '1.0'})
        return resource_incomplete(index, effective_config, recipe['config_snapshot'],
                                   recipe['config_hash'], analysis_id, time.perf_counter())
    monkeypatch.setattr(pipeline, 'run_correlation', exhausted)
    result = run_scene(task_c_root, 'one', directory)
    assert result['status'] == 'blocked'
    assert result['blocked_reason'] == 'correlation_resource_exhausted'
    assert result['production_record']['is_complete'] is False
    assert result['counts'].get('correlation_edge_count') is None
    assert not (directory/'correlation_edges.jsonl.gz').exists()


def test_wrapped_suricata_pointer_gap_is_observed_not_repaired(task_c_root):
    from app.adapters import WazuhAdapter
    datasets, config, settings, recipe = freeze_recipe(task_c_root)
    adapter = WazuhAdapter(config, datasets['one'].sources['synthetic.one.wazuh'][1])
    raw = synthetic_record(id='synthetic-wrapped-flow',
        rule={'id': '86601', 'level': 10, 'description': 'synthetic flow', 'groups': ['suricata']},
        data={'event_type': 'alert', 'alert': {'signature': 'synthetic flow'}, 'flow_id': 123,
              'proto': 'TCP', 'timestamp': '2022-01-21T00:00:00Z',
              'src_ip': '192.0.2.1', 'dest_ip': '198.51.100.1', 'src_port': 50000, 'dest_port': 443})
    a = adapter.convert(raw)
    assert a.source_type.value == 'suricata'
    directory = task_c_root/'observation-probe'
    directory.mkdir()
    with gzip.open(directory/'canonical_ingress.jsonl.gz', 'wt', encoding='utf-8') as h:
        h.write(a.canonical_json()+'\n')
    coverage = ingress_observation_coverage(directory, config)
    assert coverage['raw_embedded_flow_presence_rate'] == 1
    assert coverage['complete_tuple_pointer_miss_count'] == 1
    result = reproduce_observation_pointer_gap(coverage['samples'][0], config, settings, recipe['config_hash'])
    assert result['confirmed_envelope_pointer_mismatch']
    assert result['observed_event_fingerprint'] is None and result['observed_protocol'] is None
    # A native root-shaped control reads through the same unmodified config.
    native = deepcopy(raw)
    native['flow_id'], native['proto'] = raw['data']['flow_id'], raw['data']['proto']
    control = dict(coverage['samples'][0], canonical_alert=adapter.convert(native).model_dump(mode='json'))
    assert not reproduce_observation_pointer_gap(control, config, settings, recipe['config_hash'])['confirmed_envelope_pointer_mismatch']
    assert config.config_hash == recipe['algorithm_config_hash']
    # A report must distinguish stored flow presence from frozen visibility,
    # and keep the implementation finding even with scoring still blocked.
    with (task_c_root/'data/ait_ads/one/raw/wazuh.json').open('a', encoding='utf-8') as h:
        h.write(json.dumps(raw)+'\n')
    report_dir = task_c_root/'outputs/correlation_v3_multidataset'
    scan_scene(task_c_root, datasets['one'], config, report_dir/'one')
    (task_c_root/'AGENTS.md').write_text('synthetic fixture', encoding='utf-8')
    write(report_dir/'recipe.json', recipe)
    write(report_dir/'dataset_inventory.json', discover(task_c_root, datasets))
    write(report_dir/'protected_before.json', capture_integrity(task_c_root))
    assert generate_report(task_c_root, report_dir) == 'C_V3_IMPLEMENTATION_DEFECT_FOUND'
    field = read_json(report_dir/'field_coverage.json')['one']
    assert field['field_presence_count']['flow_id'] == 1 and field['frozen_flow_pointer_presence_count'] == 0
    defects = read_json(report_dir/'failure_modes.json')['algorithm_defect_candidates']
    assert defects[0]['code'] == 'SOURCE_ENVELOPE_POINTER_MISMATCH'
