"""Hand-computable metrics, read isolation, and sealed integration artifacts."""
import ast
import json
import math
from pathlib import Path
import pytest
from evaluation.framework.independent_validation import ROOT, OUT, DATA
from evaluation.framework.independent_validation.evaluate import metrics, verify_predictions
from evaluation.framework.scoring_calibration.snapshot import read


def prediction(value, gate=True):
    return dict(variants=dict(frozen=dict(score=value,gate=gate)))


def test_missing_candidate_is_false_negative_not_zero_score():
    gs=[dict(support_key=['a','b']),dict(support_key=['a','c'])]
    hs=[dict(support_key=['x','y']),dict(support_key=['x','z'])]
    m=metrics(gs,hs,{('a','b'):prediction(.7),('x','y'):prediction(.8)})
    assert m['gt_candidate_recall']==.5
    assert m['gt_admission_recall']==.5
    assert m['hn_admitted']==1 and m['hn_not_nominated']==1
    assert m['hn_scored_rejected']==0
    assert m['min_gt_score']==.7 and m['max_hn_score']==.8
    assert m['worst_margin']==pytest.approx(-.1)
    assert m['pairwise_ordering_rate']==0
    assert m['pairwise_ordering_denominator']==1
    assert m['pairwise_possible_denominator']==4


def test_exact_threshold_gate_and_strict_ordering():
    g=[dict(support_key=['a','b'])];h=[dict(support_key=['c','d'])]
    m=metrics(g,h,{('a','b'):prediction(.65),('c','d'):prediction(.65,False)})
    assert m['gt_admitted']==1 and m['hn_admitted']==0
    assert m['pairwise_ordering_rate']==0 and m['worst_margin']==0


def test_empty_denominator_not_applicable():
    m=metrics([],[],{})
    for field in ('gt_candidate_recall','gt_admission_recall','hn_rejection_rate','pairwise_ordering_rate','worst_margin'):
        assert m[field] is None


def test_phase_b_has_no_scorer_import_or_call():
    path=ROOT/'evaluation/framework/independent_validation/evaluate.py'
    tree=ast.parse(path.read_text(encoding='utf8'))
    for node in ast.walk(tree):
        if isinstance(node,ast.ImportFrom):
            assert not any(v in (node.module or '') for v in ('predict','model','formula','replay'))
        if isinstance(node,ast.Call):
            name=node.func.id if isinstance(node.func,ast.Name) else node.func.attr if isinstance(node.func,ast.Attribute) else ''
            assert name not in {'score','blind','run_correlation','aggregate_semantics'}


def test_blind_guard_rejects_truth_process_and_network(tmp_path):
    from evaluation.framework.formula_design.runtime import guard
    import socket
    import subprocess
    allowed=tmp_path/'canonical.json';allowed.write_text('{}')
    truth=tmp_path/'answers.json';truth.write_text('{}')
    destination=tmp_path/'predictions';destination.mkdir()
    with guard([allowed],destination) as (events,reads):
        assert allowed.read_text()=='{}'
        with pytest.raises(PermissionError): truth.read_text()
        with pytest.raises(PermissionError): subprocess.run(['never-executed'])
        with pytest.raises(PermissionError):
            with socket.socket() as connection: connection.connect(('127.0.0.1',9))
    assert len(events)==3


def test_seals_intact_and_no_post_label_replay():
    assert verify_predictions()['labels_read'] is False
    from evaluation.framework.independent_validation.predict import require_pre_evaluation
    with pytest.raises(ValueError,match='scorer_forbidden_after_evaluation'): require_pre_evaluation()
    receipt=read(OUT/'validation_predictions/receipt.json')
    assert receipt['denied']==[] and receipt['labels_read'] is False
    assert len(receipt['reads'])==4
    assert all('answers' not in p and 'provenance' not in p for p in receipt['reads'])
    assert len(receipt['variants'])==11


def test_validation_independent_and_labels_cover_requirements():
    audit=read(OUT/'independence_audit.json');assert audit['independent']
    assert audit['shared_observation_ids']==audit['shared_native_bodies']==0
    truth=read(DATA/'evaluation/answers.json')
    assert len(truth['positives'])>=5 and len(truth['hard_negatives'])>=150
    assert len({p['family'] for p in truth['positives']})>=4
    assert {n['family'] for n in truth['hard_negatives']}=={f'HNX{i:02}' for i in range(1,7)}
    assert all(c['expected_correlation'] and not c['expected_progression'] for c in truth['repeat_controls'])


def test_all_prediction_anchor_fields_and_member_winners():
    import gzip
    expected={tuple(p) for p in read(OUT/'preprocessing/candidate_pairs.json')}
    observed=set()
    with gzip.open(OUT/'validation_predictions/candidates.jsonl.gz','rt',encoding='utf8') as f:
        for line in f:
            row=json.loads(line);observed.add(tuple(row['support_key']))
            r=row['variants']['frozen'];a=r['anchor']
            assert {'has_anchor','anchor_type','anchor_strength','anchor_reliability','anchor_scope','anchor_hot','anchor_context'}<=set(a)
            assert r['admitted']==(r['gate'] and r['score']>=.65)
            assert math.isfinite(r['score']) and 0<=r['score']<=1
            assert len(r['support_pair'])==2
    assert observed==expected


def test_generator_is_scorer_independent_and_reproducible(tmp_path):
    import importlib.util
    script=ROOT.parent/'TraceBack-Dataset/scripts/build_independent_validation_v1.py'
    tree=ast.parse(script.read_text(encoding='utf8'))
    for node in ast.walk(tree):
        if isinstance(node,ast.ImportFrom): assert not (node.module or '').startswith(('app','evaluation'))
        if isinstance(node,ast.Import): assert not any(n.name.startswith(('app','evaluation')) for n in node.names)
    spec=importlib.util.spec_from_file_location('independent_generator_test',script)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.OUT=tmp_path/'rebuild';module.build()
    for name in ('input/alerts.jsonl','evaluation/answers.json','build_manifest.json'):
        assert (module.OUT/name).read_bytes()==(DATA/name).read_bytes()


def test_report_arithmetic_and_controls_are_not_false_positives():
    result=read(OUT/'result.json');primary=read(OUT/'metrics.json')['primary']
    sources=read(OUT/'source_metrics.json')
    assert result['TOTAL_ADMITTED']==sources['same_source_admitted']+sources['cross_source_admitted']
    assert primary['hn_total']==180
    failures=read(OUT/'exact_anchor_failures.json')
    assert len(failures['failures'])==primary['hn_admitted']
    assert all(p['family']!='HNX07' for p in failures['failures'])
    assert failures['HNX07']['progression_accuracy'] is None
    assert result['V5_PRODUCTION_INTEGRATION_READY'] is False
    assert result['V5_FREEZE_READY'] is False
