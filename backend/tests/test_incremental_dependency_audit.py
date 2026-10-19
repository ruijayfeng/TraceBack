"""Freeze-preserving Task B blockers; these are not incremental acceptance tests."""

import importlib.util
from pathlib import Path

import pytest

from app.config import load_config

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('incremental_dependency_audit', ROOT/'scripts/audit_incremental_dependencies.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


@pytest.fixture(scope='module')
def result():
    return audit.synthetic_audit(load_config(ROOT/'configs/algorithm-v3.yaml'))


def test_unrelated_delta_preserves_canonical_identity_and_dedupe(result):
    p = result['population_dependency']
    assert p['canonical_history_unchanged'] and p['representative_ids_preserved']
    assert p['dedupe_group_counts'] == [0,0]
    assert p['delta_candidate_count'] == p['delta_shared_entity_count'] == 0


def test_unrelated_delta_changes_formal_score_and_historical_membership(result):
    p = result['population_dependency']
    assert p['correlation_threshold'] == .65 and p['clustering_threshold'] == .70
    assert all(p['primary_gate_passed'])
    assert p['base_unrounded_score'] < .70 <= p['combined_unrounded_score']
    assert len(p['base_historical_memberships']) == 2
    assert len(p['combined_historical_memberships']) == 1
    assert p['append_only_preserve_history_equivalence'] == 'FAIL'


def test_unrelated_delta_changes_all_common_singleton_triage_payloads(result):
    p = result['triage_dependency']
    assert p['common_unrelated_singletons'] == p['changed_incident_payloads'] == 998
    assert p['base'] != p['combined']


def test_unrelated_delta_changes_historical_hot_admission(result):
    p = result['hot_dependency']
    assert p['base']['df'] == p['combined']['df'] == 100
    assert p['base']['hot'] and not p['combined']['hot']
    assert p['delta_candidate_count'] == 0
    assert p['historical_candidates_added'] > 0
