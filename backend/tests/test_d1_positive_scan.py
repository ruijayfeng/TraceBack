from evaluation.framework.preformula_baseline.boundary import development_config, development_cptc, verify_historical_inventory, verify_current
"""D.1 diagnostic safety checks; synthetic records are not real feasibility evidence."""
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('d1_scan',ROOT/'scripts/d1_positive_scan.py')
d1=importlib.util.module_from_spec(spec)
spec.loader.exec_module(d1)


def test_frozen_config_identity_and_thresholds():
    saved = d1.read_json(d1.OUT/'freeze_before.json')
    assert saved['frozen'] == d1.EXPECTED
    assert d1.read_json(d1.OUT/'scan_summary.json')['frozen'] == d1.EXPECTED
    assert verify_historical_inventory(saved['protected_files'])['status'] == 'PASS'


def test_continuous_deterministic_half_open_interval_keeps_duplicates():
    w={'start_time':'2022-02-03T20:15:00.000000Z','end_time':'2022-02-03T20:45:00.000000Z'}
    stamps=['20:14:59.999999','20:15:00','20:22:00','20:22:00','20:44:59.999999','20:45:00']
    values=[datetime.fromisoformat('2022-02-03T'+t+'+00:00') for t in stamps]
    one=[v for v in values if d1.in_window(v,w)]
    assert one==values[1:5]
    assert one==[v for v in values if d1.in_window(v,w)]


def test_inventory_nomination_reproducible_and_multiscale():
    inventory=d1.read_json(ROOT/'outputs/final_demo/time_index.json')
    a=d1.nominate(inventory)
    b=d1.nominate(dict(reversed(list(inventory.items()))))
    assert a==b
    assert len(a)==85
    assert {w['duration_seconds'] for w in a}=={900,1800,3600,7200,14400}
    assert len({(w['scenario'],w['start_time'],w['end_time']) for w in a})==len(a)
    assert all(d1.epoch(w['end_time'])-d1.epoch(w['start_time'])==w['duration_seconds'] for w in a)


def test_truth_tripwire_blocks_path_and_builtin_reads(tmp_path):
    path=tmp_path/'evaluation'/'labels.csv'
    path.parent.mkdir()
    path.write_text('synthetic',encoding='utf8')
    with d1.no_truth_reads():
        with pytest.raises(PermissionError,match='ground_truth'):
            path.read_text(encoding='utf8')
        with pytest.raises(PermissionError,match='ground_truth'):
            open(path,encoding='utf8')


def test_score_distribution_counts_unrounded_values_and_empty_population():
    values=[.6499999,.65,.6699999,.67,.68,.69,.6999999,.7,.75]
    result=d1.quantiles(values)
    assert result['cutoffs']=={'0.65':8,'0.67':6,'0.68':5,'0.69':4,'0.7':2,'0.75':1}
    assert d1.quantiles([])['max_score'] is None


def test_real_replay_deterministic_formal_threshold_and_frozen_clustering():
    path=ROOT/'outputs/d1_positive_scan/scan_summary.json'
    if not path.exists():
        pytest.skip('run actual D.1 first; no synthetic feasibility substitution')
    summary=d1.read_json(path)
    assert summary['known_replay']['deterministic']
    assert summary['known_replay']['observed_formal_max']==pytest.approx(.6587452232136708)
    assert summary['checks']['formal_threshold']
    assert summary['checks']['grounding_all_complete']
    assert summary['checks']['admitted_fully_scored']
    for w in summary['windows']:
        if w['status']!='COMPLETE':
            continue
        for edge in w['formal_edges']:
            assert edge['score']>=.65
        for guard in w['clustering_diagnostics']:
            if guard['rule_id']=='clustering.edge_threshold':
                assert guard['score']<.70 and guard['decision']=='reject'
        assert w['cluster_eligible_edge_count']==w['formal_edge_cutoffs']['0.7']


def test_top_pair_evidence_bound_to_real_raw_alert():
    path=ROOT/'outputs/d1_positive_scan/top_pairs.json'
    if not path.exists():
        pytest.skip('run actual D.1 first')
    from app.models.base import resolve_pointer
    from app.utils.stable_id import raw_fingerprint
    payload=d1.read_json(path)
    for w in payload['windows']:
        for pair in w['pairs']:
            assert pair['evidence_traceable']
            for aid,item in pair['raw_alerts'].items():
                assert raw_fingerprint(item['raw_alert'])==item['raw_fingerprint']
            for ref in pair['resolved_evidence_refs']:
                assert ref['alert_id'] in {pair['alert_a_id'],pair['alert_b_id']}
                assert resolve_pointer(pair['raw_alerts'][ref['alert_id']]['raw_alert'],ref['pointer'])==ref['resolved_value']


def test_before_after_production_source_and_config_hashes():
    path=ROOT/'outputs/d1_positive_scan/freeze_after.json'
    if not path.exists():
        pytest.skip('run actual D.1 first')
    after=d1.read_json(path)
    assert after['before_equals_after'] and after['frozen']==d1.EXPECTED
    assert not after['protected_file_changes']
    assert after['original_sources_unchanged'] and not after['labels_read']
