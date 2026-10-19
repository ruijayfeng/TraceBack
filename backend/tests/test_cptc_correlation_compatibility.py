from evaluation.framework.preformula_baseline.boundary import development_config, development_cptc, verify_historical_inventory, verify_current
"""Step 3A diagnostic contracts, synthetic boundary fixtures; no CPTC labels."""
import json
from pathlib import Path
import sys

import pytest
from app.adapters.base import AdapterSettings
from app.config import load_config
from app.correlation.candidates import generate_candidates
from app.correlation.edges import run_correlation
from app.correlation.scoring import CorrelationScorer
from app.services.capacity import bounded_execution
from app.utils.stable_id import id_for, raw_fingerprint
from test_correlation_score import alert, inputs

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts'))
from cptc_2018_step3a import Observer, bucket, quantiles, recipe, verify_originals, build_report, load_frozen_config


def pair(partitions=('synthetic.t1', 'synthetic.t2'), flow_ids=(101, 102)):
    result = []
    for i, ns in enumerate(partitions):
        a = alert(str(i), i, namespace=ns, source_type='suricata', sensor='0',
                  src_ip='192.0.2.1', dst_ip='192.0.2.2', src_port=1234, dst_port=80,
                  rule_id='same', signature='same', category='web_attack')
        data = a.model_dump()
        data['raw_alert'].update(flow_id=flow_ids[i], proto='TCP')
        data['raw_fingerprint'] = raw_fingerprint(data['raw_alert'])
        data['alert_id'] = id_for('CanonicalAlert', data)
        result.append(type(a).model_validate(data))
    return result


def settings(alerts):
    return {a.source_namespace: AdapterSettings(a.source_namespace, 'synthetic', 'Suricata',
                                                network_namespace='synthetic-network') for a in alerts}


def test_frozen_recipe_sources_only_and_immutable():
    cfg, manifest, _ = development_config()
    before = cfg.snapshot
    r = recipe(cfg, settings(pair()))
    assert r['runtime_config_snapshot']['algorithm'] == before
    assert r['frozen_base_config_hash'] == cfg.config_hash
    assert r['mapping_digest'] == cfg.mapping_digest
    assert r['correlation_threshold'] == .65 and r['cluster_threshold'] == .7
    assert cfg.snapshot == before
    assert cfg.mapping_digest == manifest['mapping_digest']
    assert cfg.snapshot == manifest['algorithm_snapshot']


def test_cross_partition_ip_eligible_and_partition_has_no_score_bonus():
    cfg = development_config()[0]
    scores = []
    # Rename arbitrary partition IDs, keeping same/different-source topology.
    for namespaces in (('synthetic.t1', 'synthetic.t2'), ('synthetic.x', 'synthetic.y')):
        aa = pair(namespaces)
        index, ss = inputs(aa, settings(aa))
        scorer = CorrelationScorer(index, cfg, ss)
        candidates = generate_candidates(index, cfg, scorer)
        assert len(candidates.pairs) == 1
        assert 'IP' in candidates.pairs[0].channels
        score = scorer.score_pair(*sorted(index.alerts))
        assert not score.diagnostics['conflicts']['hard']
        scores.append((score.score, score.values, score.diagnostics['evidence_v2']['family_strengths']))
    assert scores[0] == scores[1]


def test_flow_id_and_protocol_read_from_suricata_raw():
    cfg = development_config()[0]
    aa = pair()
    index, ss = inputs(aa, settings(aa))
    scorer = CorrelationScorer(index, cfg, ss)
    for a in aa:
        identity = scorer.duplicate.observation.identities[a.alert_id]
        assert identity.event_fingerprint and identity.protocol == 'TCP'
        assert '/flow_id' in identity.event_pointers
    changed = pair(flow_ids=(901, 902))
    index2, ss2 = inputs(changed, settings(changed))
    other = CorrelationScorer(index2, cfg, ss2)
    assert {i.event_fingerprint for i in other.duplicate.observation.identities.values()} != {
        i.event_fingerprint for i in scorer.duplicate.observation.identities.values()}


def test_observer_real_admission_traceability_determinism_and_bounded_equivalence(tmp_path):
    cfg = development_config()[0]
    aa = pair()
    index, ss = inputs(aa, settings(aa))
    receipts = []
    for n, reverse in enumerate((False, True)):
        out = tmp_path/str(n)
        out.mkdir()
        obs = Observer(out)
        result = run_correlation(list(reversed(list(index.alerts.values()))) if reverse else list(index.alerts.values()),
                                 [], list(index.entities.values()), cfg, ss, diagnostic_sink=obs)
        top = obs.finish(result, cfg, ss)
        assert obs.count == result.record.metrics.candidate_pair_count == 1
        assert top[0]['evidence_pointers_valid']
        assert top[0]['production_decision']['decision'] == 'reject'
        assert not result.edges  # Plain shared IP / detection metadata cannot pass primary gate.
        stats = json.loads((out/'candidate_stats.json').read_text())
        assert stats['candidate_bearing_alerts'] == 2
        assert json.loads((out/'candidate_partition_matrix.json').read_text())['cross_partition'] == 1
        receipts.append(json.loads((out/'deterministic_statistics.json').read_text()))
    assert receipts[0] == receipts[1]
    with bounded_execution(tmp_path/'spill'):
        obs = Observer(tmp_path/'0')
        result = run_correlation(list(index.alerts.values()), [], list(index.entities.values()), cfg, ss, diagnostic_sink=obs)
        assert obs.digest.hexdigest() == receipts[0]['candidate_and_score_digest']


def test_bins_unrounded_and_missing_samples_are_not_fabricated(tmp_path):
    assert bucket(.6499999999) == '[0.60,0.65)'
    assert bucket(.65) == '[0.65,0.70)'
    assert quantiles([0, 1], {'p50': .5}) == {'p50': .5}
    cfg = development_config()[0]
    aa = pair()
    index, ss = inputs(aa, settings(aa))
    obs = Observer(tmp_path)
    result = run_correlation(list(index.alerts.values()), [], list(index.entities.values()), cfg, ss, diagnostic_sink=obs)
    obs.finish(result, cfg, ss)
    missing = json.loads((tmp_path/'missing_aware_samples.json').read_text(encoding='utf8'))
    assert missing['single_sided_ip']['status'] == 'NOT_OBSERVED_IN_SCORED_CANDIDATES'
    assert 'entity.DOMAIN' in missing['no_domain']['score_breakdown']['evidence_v2']['not_applicable_evidence']


def test_truth_guard_rejects_ground_truth_file_open(tmp_path):
    from demo_support import truth_guard, DemoError
    path = tmp_path/'labels.csv'
    path.write_text('synthetic')
    with truth_guard(tmp_path), pytest.raises(DemoError):
        path.read_text()


def test_missing_network_and_domain_are_unavailable_not_negative_evidence():
    cfg = development_config()[0]
    aa = [alert('a', source_type='suricata', src_ip='192.0.2.1', dst_ip='192.0.2.2', src_port=1000, dst_port=80),
          alert('b', 1, source_type='suricata', src_ip='192.0.2.1')]
    idx, ss = inputs(aa, settings(aa))
    score = CorrelationScorer(idx, cfg, ss).score_pair(*sorted(idx.alerts))
    ev = score.diagnostics['evidence_v2']
    assert 'topology.network_continuity' in ev['unavailable_evidence']
    assert 'entity.DOMAIN' in ev['not_applicable_evidence']
    assert score.values['conflict'] == 0
    assert 'entity.IP' in ev['matched_evidence']


def test_flow_changes_observation_duplicate_evidence_without_direct_bonus():
    cfg = development_config()[0]
    observed = []
    for flow_ids in ((101, 101), (101, 102)):
        aa = []
        for original in pair(flow_ids=flow_ids):
            data = original.model_dump()
            data['raw_alert']['tx_id'] = 0
            data['raw_fingerprint'] = raw_fingerprint(data['raw_alert'])
            data['alert_id'] = id_for('CanonicalAlert', data)
            aa.append(type(original).model_validate(data))
        idx, ss = inputs(aa, settings(aa))
        scorer = CorrelationScorer(idx, cfg, ss)
        observed.append(scorer.score_pair(*sorted(idx.alerts)))
    assert observed[0].diagnostics['duplicate_features']['observation_identity']['equivalent']
    assert not observed[1].diagnostics['duplicate_features']['observation_identity']['equivalent']
    assert observed[0].values['duplicate'] > observed[1].values['duplicate']
    assert observed[0].diagnostics['evidence_v2']['duplicate_observation_risk']


def test_report_keeps_resource_failure_unavailable_and_not_ready(tmp_path):
    (tmp_path/'result.json').write_text(json.dumps(dict(status='CPTC_STEP3A_EXECUTION_BLOCKED',
        full_scan_status='FULL_SCAN_NOT_COMPLETED', loaded_alerts=100, step_3b_ready=False)), encoding='utf8')
    result = build_report(tmp_path)
    report = (tmp_path/'CPTC_CORRELATION_COMPATIBILITY_REPORT.md').read_text(encoding='utf8')
    assert not result['step_3b_ready']
    assert 'FULL_SCAN_NOT_COMPLETED' in report and 'STEP_3B_READY = NO' in report
    assert 'Admitted unique CandidatePair: None' in report
    assert '0 highest-scoring candidates' in report
    candidate = json.loads((tmp_path/'candidate_stats.json').read_text(encoding='utf8'))
    assert candidate['candidate_pairs_total'] is None
    assert candidate['status'] == 'UNAVAILABLE_FULL_SCAN_NOT_COMPLETED'


def test_report_preserves_actual_representatives_after_production_resource_return(tmp_path):
    for name, value in {
        'result.json': dict(status='CPTC_CORRELATION_COMPATIBILITY_DEFECT', error='empty_observer', loaded_alerts=331554),
        'performance.json': dict(production_timings={'resource_error': 'correlation_resource_exhausted'}),
        'dedupe_stats.json': dict(representatives=318569),
        'resource_checkpoint.json': dict(stage='production_candidate_generation', resource_abort=True),
    }.items():
        (tmp_path/name).write_text(json.dumps(value), encoding='utf8')
    result = build_report(tmp_path)
    assert result['status'] == 'CPTC_STEP3A_EXECUTION_BLOCKED'
    assert result['diagnostic_followup_error'] == 'empty_observer'
    assert json.loads((tmp_path/'candidate_stats.json').read_text(encoding='utf8'))['total_representatives'] == 318569
