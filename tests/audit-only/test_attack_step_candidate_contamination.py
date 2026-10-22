"""Methodological acceptance checks for the additive, frozen-input audit."""
import ast
from collections import Counter
import copy
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('candidate_contamination_audit',
    ROOT / 'scripts/audit_attack_step_candidate_contamination.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


@pytest.fixture(scope='module')
def audit():
    return M.Audit(ROOT)


@pytest.fixture(scope='module')
def rows(audit):
    return audit.rows()


def test_sha_mismatch_blocks_before_any_population_read(monkeypatch, tmp_path):
    monkeypatch.setattr(M, 'sha', lambda path: '0' * 64)
    with pytest.raises(ValueError, match='BLOCKED: prototype output SHA mismatch'):
        M.Audit(tmp_path)


def test_frozen_population_all_reviewed(audit, rows):
    assert len(audit.ledger) == 129
    assert len({r['candidate_id'] for r in rows}) == 28
    assert Counter(r['gt_classification'] for r in rows) == dict(EXACT_GT_STEP=2, PURE_GT_SUBSET=6, CROSS_GT_MIXED=20)
    required = {'candidate_id', 'prototype_status', 'member_stage_ids', 'member_chain_ids', 'gt_stage_ids',
        'gt_classification', 'candidate_generation_sources', 'source_relation_ids', 'relation_types', 'shared_host',
        'shared_account', 'shared_process', 'process_lineage', 'shared_flow', 'shared_connection',
        'shared_network_session', 'shared_auth_session', 'shared_request', 'shared_object', 'temporal_features',
        'semantic_labels', 'evidence_levels', 'direct_binding_evidence', 'relation_evidence', 'context_evidence',
        'semantic_evidence', 'candidate_entry_reason', 'candidate_retention_reason', 'same_step_support',
        'cross_step_relation_support', 'ambiguous_support', 'first_candidate_admission_rule', 'code_location',
        'contamination_root_cause', 'audit_conclusion', 'FIRST_ADMISSION_EVIDENCE', 'RETENTION_EVIDENCE',
        'MISSING_REJECTION_GUARD'}
    assert all(required <= r.keys() for r in rows)


def test_first_insertion_is_not_sorted_reason_set(audit):
    with_relation = [x for x in audit.candidates if len(x['member_stage_ids']) == 2 and x['source_relation_ids']]
    assert len(with_relation) == 12
    for x in with_relation:
        paths = audit.origins[x['candidate_id']]
        assert paths[0]['rule'] == 'EXHAUSTIVE_PAIR_REVIEW'
        assert any(p['rule'] in {'EXISTING_DIRECTED_EDGE', 'EXISTING_UNDIRECTED_EDGE'} for p in paths[1:])
    multi = [x for x in audit.candidates if len(x['member_stage_ids']) > 2]
    assert len(multi) == 6
    assert all(audit.origins[x['candidate_id']][0]['rule'].endswith('_BUCKET') for x in multi)


def test_static_origin_reconstruction_covers_all129_exactly(audit):
    assert len(audit.origins) == 129
    for ledger in audit.ledger:
        assert {p['rule'] for p in audit.origins[ledger['candidate_id']]} == set(ledger['candidate_generation_reason'])


def test_every_positive_occurrence_has_one_semantic_class(audit):
    assert len(audit.semantic_occurrences) == sum(len(x['positive_evidence']) for x in audit.candidates) == 14355
    assert len({r['occurrence_id'] for r in audit.semantic_occurrences}) == 14355
    assert all(r['classification'] in M.CATEGORIES and r['classification_uses_gt'] is False for r in audit.semantic_occurrences)
    for x in audit.candidates:
        reviewed = audit.occurrence_by_candidate[x['candidate_id']]
        assert [r['evidence_ref'] for r in reviewed] == x['positive_evidence']


def test_trace_validity_does_not_become_independent_membership(audit):
    trace = [r for r in audit.semantic_occurrences if r['evidence_ref']['kind'] in {'raw_pointer', 'observation', 'validation'}]
    assert trace and all(r['independent_membership_proof'] is False for r in trace)
    assert any(r['classification'] == 'AMBIGUOUS' and len(r['parent_semantic_categories']) > 1 for r in trace)
    assert any(r['classification'] == 'SHARED_CONTEXT_ONLY' and r['evidence_ref']['kind'] == 'validation' for r in trace)


def test_native_semantics_do_not_read_gt(audit):
    class GTForbidden(dict):
        def __getitem__(self, key):
            raise AssertionError('GT read during native semantics')
        def get(self, *args):
            raise AssertionError('GT read during native semantics')
    before = audit.truth
    audit.truth = GTForbidden()
    try:
        rebuilt = {x['candidate_id']: audit.native_features(x) for x in audit.candidates}
        assert rebuilt == audit.native
        assert len(audit.audit_relations_native()) == 12
        occurrences = audit.classify_all_positive_evidence()
        assert occurrences == audit.semantic_occurrences
    finally:
        audit.truth = before


def test_relation_audit_keeps_ancestry_ambiguous_including_positive(audit):
    assert Counter(r['classification'] for r in audit.relation_semantics) == {
        'CROSS_STEP_PROGRESSION': 3, 'ASSOCIATION_ONLY': 3, 'UNDETERMINED': 5, 'SAME_STEP_COMPATIBLE': 1}
    assert all(r['existing_stage8_relation_error_implied'] is False for r in audit.relation_semantics)
    assert any(r['primary_evidence_type'] == 'PARENT_CHILD_PROCESS' and
               audit.truth[r['candidate_id']]['classification'] == 'EXACT_GT_STEP' and
               r['classification'] == 'UNDETERMINED' for r in audit.relation_semantics)


def test_session_exposure_is_not_session_causality(audit, rows):
    risk = {r['family']: r for r in audit.risk_analysis(rows)}
    assert risk['shared_session']['cross_gt_exposure_count'] == 10
    assert risk['shared_session']['direct_context_predicate_count'] == 0
    assert risk['shared_session']['sole_qualifying_binding_family_count'] == 0
    assert risk['same_host']['cross_gt_exposure_count'] == 12
    assert risk['same_account']['cross_gt_exposure_count'] == 5
    assert risk['same_flow']['cross_gt_exposure_count'] == 6
    assert risk['same_flow']['qualifying_binding_witness_count'] == 5
    assert risk['process_lineage']['qualifying_binding_witness_count'] == 8
    assert risk['process_lineage']['sole_qualifying_binding_family_count'] == 4


def test_composite_request_clue_is_not_closed_activity_boundary(audit, rows):
    clue = [r for r in rows if r['native_semantics']['plausible_membership_evidence']]
    assert len(clue) == 1
    r = clue[0]
    assert len(r['same_step_support']) > 0
    assert r['native_semantics']['reliable_membership_evidence'] is False
    contexts = r['native_semantics']['request_boundary_observations']
    assert any(c['all_selected_alerts_covered'] and c['role_link'] and c['outside_stage_ids'] for c in contexts)
    assert not r['native_semantics']['relation_only_retention']


def test_group_expansion_cannot_inherit_one_pair_membership(rows):
    expansions = [r for r in rows if len(r['member_stage_ids']) > 2]
    assert len(expansions) == 6
    assert all(r['gt_classification'] == 'CROSS_GT_MIXED' for r in expansions)
    assert all(not r['same_step_support'] for r in expansions)
    assert any(r['native_semantics']['members_without_any_accepted_relation'] for r in expansions
               if r['native_semantics']['accepted_relation_qualifies_finite_description'])


def test_pure_subsets_do_not_become_semantic_successes(audit, rows):
    subsets = audit.pure_subsets(rows)['rows']
    assert len(subsets) == 6
    assert all(r['classification'] == 'GENERIC_SHARED_CONTEXT' and
               r['secondary_classification'] == 'ENUMERATION_ARTIFACT' and
               not r['true_semantic_capability_established'] for r in subsets)


def test_sources_overlap_but_first_source_partitions(audit):
    enum = audit.enumeration()
    assert enum['PAIR_ENUMERATION_PROPOSALS'] == enum['TOTAL_STAGE_PAIRS'] == 105
    assert enum['CONTEXT_BUCKET_PROPOSALS'] == 12
    assert enum['RELATION_DERIVED_PROPOSALS'] == 29
    assert enum['ACCEPTED_RELATION_DERIVED_PROPOSALS'] == 12
    assert enum['MULTI_STAGE_EXPANSION_PROPOSALS'] == 9
    assert sum(enum['first_source_proposal_counts'].values()) == 129
    assert sum(s['FIRST_SOURCE_CANDIDATES']['CANDIDATE_COUNT'] for s in enum['sources'].values()) == 28
    assert sum(s['CANDIDATE_COUNT'] for s in enum['sources'].values()) > 28


@pytest.mark.parametrize('name,expected', [
    ('remove_relation_only', (1, 0, 15)), ('remove_lineage_only', (1, 0, 4)),
    ('remove_same_session_only', (0, 0, 0)), ('remove_same_flow_only', (0, 6, 5)),
    ('remove_host_account_only', (0, 0, 0)), ('require_membership_evidence', (1, 6, 20)),
    ('require_same_chain', (0, 6, 6)), ('require_observable_step_boundary', (2, 6, 20)),
])
def test_counterfactual_is_explicit_set_sensitivity(audit, rows, name, expected):
    scenario = next(r for r in audit.counterfactuals(rows)['scenarios'] if r['name'] == name)
    assert tuple(scenario['removed_counts'][t] for t in M.TRUTH) == expected
    assert set(scenario['removed_candidate_ids']).isdisjoint(scenario['kept_candidate_ids'])
    assert len(scenario['removed_candidate_ids']) + len(scenario['kept_candidate_ids']) == 28
    assert scenario['recommended_as_production_filter'] is False


def test_counterfactual_selection_independent_of_gt_labels(audit, rows):
    swapped = copy.deepcopy(rows)
    for i, r in enumerate(swapped):
        r['gt_classification'] = M.TRUTH[(i + 1) % 3]
        r['gt_stage_ids'] = ['OFFLINE_LABEL_REPLACED']
    original = audit.counterfactuals(rows)['scenarios']
    changed = audit.counterfactuals(swapped)['scenarios']
    assert [(r['name'], r['removed_candidate_ids']) for r in original] == [(r['name'], r['removed_candidate_ids']) for r in changed]


def test_one_primary_root_per_cross_gt_candidate(rows):
    mixed = [r for r in rows if r['gt_classification'] == 'CROSS_GT_MIXED']
    assert Counter(r['PRIMARY_ROOT_CAUSE'] for r in mixed) == {M.ROOTS['A']: 10, M.ROOTS['D']: 4, M.ROOTS['H']: 6}
    assert all(r['PRIMARY_ROOT_CAUSE'] not in r['SECONDARY_ROOT_CAUSES'] for r in mixed)


def test_no_prototype_or_production_imports_or_execution():
    tree = ast.parse((ROOT / 'scripts/audit_attack_step_candidate_contamination.py').read_text(encoding='utf-8'))
    imports = [n.module or '' for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    imports += [x.name for n in ast.walk(tree) if isinstance(n, ast.Import) for x in n.names]
    assert all(not n.startswith(('app', 'backend', 'evaluation', 'subprocess')) for n in imports)
    assert not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in {'exec', 'eval', '__import__'} for n in ast.walk(tree))


def test_existing_protected_files_unchanged():
    before = M.read(ROOT / M.DEFAULT_OUTPUT / 'protected_before.json')
    assert len(before) == 1413
    assert all(Path(p).is_file() and M.sha(p) == expected for p, expected in before.items())


def test_matrix_preserves_frozen_confirmation_and_v2_abstention():
    matrix = M.relation_matrix()
    assert len(matrix['rows']) == 9
    assert all(r['sufficient_alone_to_confirm'] is False for r in matrix['rows'])
    assert M.design_constraints()['PROTOTYPE_V2_JUSTIFIED'] is False
    assert M.design_constraints()['NEXT_ACTION'] == 'DEFINE_OBSERVABLE_STEP_BOUNDARY'


def test_empty_root_and_escaped_raw_pointer():
    value = {'a/b': {'~x': [1, 2]}}
    assert M.pointer(value, '') is value
    assert M.pointer(value, '/a~1b/~0x/1') == 2
