"""Read-only integration checks over the completed calibration artifacts."""
import json
from pathlib import Path
import pytest
from evaluation.framework.scoring_calibration import OUT
from evaluation.framework.scoring_calibration.snapshot import read
from evaluation.framework.scoring_calibration.evaluate import verify_seal


@pytest.fixture(scope='module')
def summary():
    if not (OUT / 'evaluation_summary.json').is_file():
        pytest.skip('Run the declared finite calibration replay first')
    return read(OUT / 'evaluation_summary.json')


def test_prediction_seal_and_all_files_remain_intact(summary):
    assert verify_seal()['ground_truth_loaded'] is False


def test_complete_member_cartesian_and_baseline_recomputation(summary):
    receipt = read(OUT / 'predictions/receipt.json')
    original = read(OUT / 'baseline/seal.json')['baseline_counts']
    assert receipt['members'] == original['scored_member_pairs']
    assert receipt['candidates'] == original['candidate_count']
    assert receipt['baseline_admitted'] == original['admitted_count']
    assert receipt['max_frozen_recompute_error'] == 0
    assert receipt['score_digest'] == original['score_digest']
    assert receipt['candidate_digest'] == original['candidate_digest']
    assert not receipt['truth_read'] and len(receipt['reads']) == 4


def test_complete_witnesses_and_unscored_are_explicit(summary):
    actual = read(OUT / 'complete_witness_decomposition.json')
    gt = [r for r in actual if not r['scenario_id']]
    hn = [r for r in actual if r['scenario_id']]
    assert len(gt) == summary['gt_candidates']
    assert len(hn) == summary['hn_known']
    assert sum(r['features'] is not None for r in hn) == summary['hn_candidate_count']
    for row in actual:
        if row['candidate']:
            assert row['features']['feature_contributions']
            assert row['member_predictions']['support_pair'] == row['features']['support_pair']
        else:
            assert row['baseline_score'] is None and row['no_score_reason']


def test_all_sweep_rows_preserve_denominators_and_source_partition(summary):
    rows = read(OUT / 'threshold_search.json')['rows']
    assert {r['threshold'] for r in rows} == {round(.4+i*.01, 10) for i in range(46)}
    for row in rows:
        assert row['total_admitted'] == row['cross_source_admitted']+row['same_source_admitted']
        assert row['background_background_admitted'] <= row['total_admitted']
        assert 0 <= row['gt_admitted'] <= summary['gt_candidates']
        assert 0 <= row['hn_admitted'] <= summary['hn_known']


def test_family_holdout_covers_every_label_family(summary):
    folds = read(OUT / 'group_calibration.json')['folds']
    assert sum(r['gt_count'] for r in folds) == summary['gt_candidates']
    assert sum(r['hn_count'] for r in folds) == summary['hn_known']
    assert all(r['gt_count'] == 0 or r['hn_count'] == 0 for r in folds)


def test_background_review_has_required_strata_without_new_labels(summary):
    review = read(OUT / 'background_semantic_review.json')
    assert {k: sum(v.values()) for k, v in review['counts'].items()} == dict(high=100, near=100, random=100)
    assert all(r['not_ground_truth'] and r['provisional'] for r in review['rows'])
    assert review['unique_pairs'] == 300


def test_no_scenario_identity_in_numeric_model_and_no_production_import(summary):
    root = Path(__file__).resolve().parents[2]
    model = (root / 'evaluation/framework/scoring_calibration/model.py').read_text(encoding='utf8')
    assert all(token not in model for token in ('GT-E01', 'HN07', 'HN08', 'HN10', 'HN13', 'event_id', 'fixture_identifier'))
    assert all('scoring_calibration' not in p.read_text(encoding='utf8') for p in (root / 'backend/app').rglob('*.py'))
