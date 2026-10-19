from evaluation.framework.preformula_baseline.boundary import development_config, development_cptc, verify_historical_inventory, verify_current
"""Offline adjudication contracts; synthetic examples are only unit fixtures."""
from collections import Counter, defaultdict
from copy import deepcopy
import inspect
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import v5_evidence_adjudication as m
import v5_evidence_adjudication_evidence as e


def read(name):
    return json.loads((m.OUT / name).read_text(encoding='utf8'))


@pytest.fixture(scope='module')
def cards():
    return [json.loads(line) for line in (m.OUT/'pair_adjudication.jsonl').open(encoding='utf8')]


@pytest.fixture(scope='module')
def entries():
    return list(m.cached())


def test_exact_original_targets_and_complete_review(cards):
    prior = m.targets()
    original = {r['candidate_id']: r for r in prior}
    assert len(cards) == len(original) == 94
    assert {c['pair_id'] for c in cards} == set(original)
    admitted = {c['pair_id'] for c in cards if c['algorithm']['admitted']}
    assert len(admitted) == 26
    assert admitted == {r['candidate_id'] for r in prior if r['prototypes']['b']['admitted']}
    for c in cards:
        assert c['adjudication']['label'] in e.LABELS
        assert c['adjudication']['review_status'] == 'COMPLETED_AGENT_EVIDENCE_ADJUDICATION'
        assert c['adjudication']['score_used_for_label'] is False
        assert not c['adjudication']['independent_human_review']
        assert c['algorithm']['prototypes'] == original[c['pair_id']]['prototypes']
        assert [c[s]['alert_id'] for s in ('alert_a', 'alert_b')] == original[c['pair_id']]['pair']


def test_labels_are_content_bound_and_do_not_consume_scores(cards):
    decisions = {r['pair_id']: r for r in read('semantic_decisions.json')['decisions']}
    source = inspect.getsource(e.semantic_label)
    assert 'scorer' not in source and "['algorithm']" not in source
    assert "['score']" not in source and "['admitted']" not in source
    for c in cards:
        blind = {k: deepcopy(c[k]) for k in ('pair_id','dataset','alert_a','alert_b')}
        expected = e.semantic_label(blind, decisions[c['pair_id']])
        changed_score = deepcopy(c)
        changed_score['algorithm'].update(score=0, admitted=not c['algorithm']['admitted'])
        assert e.semantic_label({k: changed_score[k] for k in blind}, decisions[c['pair_id']]) == expected
        with pytest.raises(ValueError, match='blind_evidence_only'):
            e.semantic_label(dict(blind, algorithm={'score': 1}), decisions[c['pair_id']])
        blind['alert_a']['raw_alert']['diagnostic_test_mutation'] = True
        with pytest.raises(ValueError, match='not_bound_to_raw'):
            e.semantic_label(blind, decisions[c['pair_id']])


def test_unresolved_excluded_not_negative(cards):
    admitted = [c for c in cards if c['algorithm']['admitted']]
    result = e.precision_evidence(admitted)
    assert result['unresolved'] == 25 and result['negative_count'] == 0
    assert result['adjudicable'] == 1
    assert result['strict_numerator'] == 0 and result['broad_numerator'] == 1
    unresolved = [c for c in cards if c['adjudication']['label'] == 'UNRESOLVED']
    result = e.precision_evidence(unresolved)
    assert result['adjudicable'] == result['negative_count'] == 0
    assert result['strict'] is None and result['broad'] is None
    assert result['metric_status'] == 'not_applicable'


@pytest.mark.parametrize('left,right,lc,rc,expected', [
    (None,None,'UNKNOWN','UNKNOWN','UNKNOWN'),
    (None,None,'OBSERVED','OBSERVED','UNKNOWN'),
    (None,None,'CAPABILITY_ABSENT','OBSERVED','CAPABILITY_ABSENT'),
    ('same','same','OBSERVED','OBSERVED','OBSERVABLE_MATCH'),
    ('one','two','OBSERVED','OBSERVED','OBSERVABLE_NONMATCH'),
    (0,1,'OBSERVED','OBSERVED','OBSERVABLE_NONMATCH'),
])
def test_capability_absent_is_not_observable_zero(left,right,lc,rc,expected):
    assert e.capability_comparison(left,right,lc,rc) == expected


def test_real_coverage_and_all_sample_raw_pointers(entries):
    counts = defaultdict(Counter)
    totals = Counter()
    by_id = {}
    for dataset, a, locator in entries:
        raw = a.raw_alert
        profile = (raw.get('AnalysisComponent',{}).get('AnalysisComponentType') or
                   raw.get('decoder',{}).get('name') or raw.get('event_type') or 'unknown')
        key = (dataset,a.source_namespace,a.source_type.value,profile)
        totals[key] += 1
        counts[key].update(e.observations(a).keys())
        by_id[a.alert_id] = (a,locator)
    rows = read('source_capability_attestation.json')['rows']
    assert len(rows) == len(totals)*24
    assert set(r['family'] for r in rows) == set(e.FAMILIES)
    assert sum(totals.values()) == 25320
    for row in rows:
        key = (row['dataset'],row['source'],row['source_type'],row['detector_profile'])
        assert row['total'] == totals[key]
        assert row['observed'] == counts[key][row['family']]
        assert row['coverage'] == row['observed']/row['total']
        if row['status'] == 'ATTESTED':
            assert row['observed'] == row['total'] and row['evidence']
        if row['observed'] == 0:
            assert row['status'] == 'UNAVAILABLE'
            assert row['capability_state'] == 'UNKNOWN' and not row['source_cannot_provide']
        for sample in row['evidence']:
            a,locator = by_id[sample['alert_id']]
            assert sample['raw_fingerprint'] == a.raw_fingerprint == locator['raw_fingerprint']
            assert sample['locator'] == locator
            raw_evidence = sample['raw_evidence']
            assert e.pointer(a.raw_alert, raw_evidence['pointer']) == raw_evidence['value']
            assert sample['interpreted_value'] == e.observations(a)[row['family']]['value']
            canonical = sample['canonical_evidence']
            if canonical['field'] in type(a).model_fields:
                assert a.model_dump(mode='json')[canonical['field']] == canonical['value']
            if 'additional_raw_evidence' in sample:
                extra = sample['additional_raw_evidence']
                assert e.pointer(a.raw_alert,extra['pointer']) == extra['value']


def test_source_can_expose_values_missing_from_canonical(entries):
    raw_only = Counter()
    for dataset,a,_ in entries:
        for family,fact in e.observations(a).items():
            if family in ('SESSION','ACCOUNT') and fact['canonical_value'] is None:
                assert e.payload_json(a.raw_alert)
                raw_only[family] += 1
    assert raw_only['SESSION'] > 0 and raw_only['ACCOUNT'] > 0
    missing = read('missing_evidence_reclassification.json')
    assert missing['states']['CAPABILITY_ABSENT'] == 0
    assert sum(missing['states'].values()) == missing['total_previous_missing_dimensions']
    assert missing['states']['OBSERVABLE_MATCH'] > 0


def synthetic_progression():
    return dict(alerts=['synthetic-a','synthetic-b','synthetic-c'],edges=[
        {'from':a,'to':b,'semantic_label':'CONFIRMED_RELATED','direction_grounded':True}
        for a,b in [('synthetic-a','synthetic-b'),('synthetic-b','synthetic-c')]])


def test_progression_requires_two_adjacent_grounded_edges():
    assert e.validate_progression(synthetic_progression())
    short = synthetic_progression();short['alerts'].pop();short['edges'].pop()
    with pytest.raises(ValueError,match='three_distinct_alerts'):
        e.validate_progression(short)
    disconnected = synthetic_progression();disconnected['edges'][1].update({'from':'synthetic-c','to':'synthetic-d'})
    with pytest.raises(ValueError,match='disconnected'):
        e.validate_progression(disconnected)
    repeated = synthetic_progression();repeated['alerts'][2] = repeated['alerts'][0]
    with pytest.raises(ValueError,match='three_distinct_alerts'):
        e.validate_progression(repeated)
    for mutation in ({'semantic_label':'PLAUSIBLE_RELATED'},{'direction_grounded':False}):
        ungrounded = synthetic_progression();ungrounded['edges'][0].update(mutation)
        with pytest.raises(ValueError,match='semantic_and_order'):
            e.validate_progression(ungrounded)


@pytest.mark.parametrize('change,expected', [
    ({'RAW_VISIBLE':False},'SOURCE_OBSERVABILITY'),
    ({'CANONICAL_VISIBLE':False},'CANONICALIZATION'),
    ({'CANDIDATE_NOMINATED':False},'CANDIDATE_NOMINATION'),
    ({'SCORED':False},'SCORING'),
    ({'gate_passed':False},'EVIDENCE_GATE'),
    ({'ADMITTED':False},'THRESHOLD'),
    ({},'NONE'),
])
def test_failure_stage(change,expected):
    edge = dict(RAW_VISIBLE=True,CANONICAL_VISIBLE=True,CANDIDATE_NOMINATED=True,
        SCORED=True,ADMITTED=True,gate_passed=True)
    edge.update(change)
    assert e.failure_stage(edge) == expected


def test_unverified_scanning_hypotheses_never_become_verified_progressions():
    verified = read('verified_progressions.json')
    assert verified['count'] == len(verified['progressions']) == 0
    hypotheses = read('progression_hypotheses.json')
    assert 0 < len(hypotheses) <= 8
    for package in hypotheses:
        assert e.validate_progression(package)
        assert package['verified_progression'] is False and package['level'] is None
        assert package['rejection_reason']
        assert len(package['evidence']['raw_alert_evidence']) == len(package['alerts'])
        raw_by_id={a['alert_id']:a['raw_alert'] for a in package['evidence']['raw_alert_evidence']}
        for edge in package['edges']:
            assert edge['failure_stage'] == e.failure_stage(edge)
            assert edge['gate_passed'] == (not [r for r in edge['prototypes']['b']['admission_reasons']
                if r!='below_reference_threshold'])
            from app.models import EvidencePointer
            for ref in edge['support']['raw_pointers']:
                bound=EvidencePointer.model_validate(ref)
                assert bound.alert_id in edge['support']['alert_ids']
                assert e.pointer(raw_by_id[bound.alert_id],bound.pointer) is not None
            if edge['counterfactual_score_if_not_nominated']:
                assert not edge['SCORED'] and not edge['ADMITTED']
    manifest = read('progression_search_manifest.json')
    assert manifest['brute_force_triplets'] is False
    assert manifest['production_domain_writes'] == 0
    assert manifest['verified_progression_reachability']['denominator'] == 0


def test_frozen_production_configs_prior_artifacts_and_input_identities():
    frozen = read('freeze_verification.json')
    assert frozen['status'] == 'PASS' and frozen['mismatches'] == []
    assert frozen['threshold'] == .65
    assert frozen['algorithm_version'] == 'alert-correlation-v4-role-context-candidate-v1.1'
    for folder in (m.PRIOR,m.DESIGN):
        manifest = m.d.read(folder/'manifest.json')
        for relative,expected in manifest['files'].items():
            assert m.d.file_digest(folder/relative) == expected
    assert verify_historical_inventory(read('protected_before.json'), anchor=m.OUT/'protected_before.json')['status'] == 'PASS'
    old = m.d.read(m.PRIOR/'dataset_profiles.json')['scored_slices']
    for dataset,meta in read('input_manifest.json').items():
        assert meta['selected_identity_digest'] == old[dataset]['selected_identity_digest']


def test_freeze_mismatch_blocks_before_scoring_without_touching_originals(monkeypatch,tmp_path):
    original_digest = m.d.file_digest
    protected = read('protected_before.json')
    selected = next(ROOT/p for p in protected if p.startswith('backend/app/') and p.endswith('.py'))
    monkeypatch.setattr(m, 'OUT', tmp_path)
    monkeypatch.setattr(m.d, 'file_digest', lambda path: '0'*64 if Path(path) == selected else original_digest(path))
    with pytest.raises(RuntimeError,match='BLOCKED_FREEZE_MISMATCH'):
        m.freeze()
    blocked = json.loads((tmp_path/'manifest.json').read_text(encoding='utf8'))
    assert blocked['task_result'] == 'V5_ADJUDICATION_BLOCKED_FREEZE_MISMATCH'
    assert blocked['freeze']['status'] == 'FAIL'
    assert blocked['freeze']['mismatches']


def test_bounded_progression_selection_is_score_independent_and_stable(entries):
    from v5_evidence_adjudication_progression import scan_hypotheses
    forward,stats = scan_hypotheses(entries)
    backward,reverse_stats = scan_hypotheses(list(reversed(entries)))
    identity = lambda rows: [(key,[a.alert_id for a,_,_ in chosen]) for key,chosen in rows]
    assert identity(forward) == identity(backward)
    assert stats == reverse_stats and stats['selected_flows'] <= 8
    assert not stats['brute_force_triplets']


def test_no_production_dependency_on_adjudication_labels():
    for path in (ROOT/'backend/app').rglob('*.py'):
        source = path.read_text(encoding='utf8')
        assert 'v5_evidence_adjudication' not in source
        assert 'semantic_decisions.json' not in source
    summary = read('summary.json')
    assert summary['production_v4_modified'] == summary['production_v5_implemented'] == 'NO'
    assert summary['v5_formula_freeze_gate'] == 'NEEDS_MORE_EVIDENCE'
