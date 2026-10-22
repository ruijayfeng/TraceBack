"""Analytic counterexamples for evaluator arithmetic and population handling."""
import copy
import hashlib
import json
from pathlib import Path
import pytest

from evaluation.attack_step_independent import (Inputs,auc,candidate_truth,classify_proposal,evaluate_pairs,
    cross_gt_risks,evidence_diagnosis,hypergeom_tail,mapping_from_native,pair_metrics,pairs,ratio,recovery)

def group(key,members,status='CANDIDATE'):
    return dict(semantic_step_id=key,member_stage_ids=members,membership_status=status,evidence_level='E3',
        source_relation_ids=[],supporting_alert_ids=[],member_chain_ids=['chain'],disconnected_members=True)

def test_zero_denominator_is_not_one():
    m=pair_metrics(pairs(['a','b']),{('a','b')},set())
    assert m['PRECISION']['status']=='NOT_EVALUABLE' and m['PRECISION']['value'] is None
    assert m['RECALL']['value']==0 and m['F1']['value']==0
    assert ratio(0,0)['status']=='NOT_EVALUABLE'

def test_all_empty_metrics_not_evaluable():
    m=pair_metrics(set(),set(),set())
    assert all(m[x]['status']=='NOT_EVALUABLE' for x in ['PRECISION','RECALL','F1'])

def test_pair_union_deduplicates_without_transitive_closure():
    gt=dict(a='t1',b='t1',c='t2',d='t3')
    groups=[group('one',['a','b']),group('two',['a','c']),group('dup',['b','a']),group('larger',['a','b','c'],'UNRESOLVED')]
    m=evaluate_pairs(groups,gt)['scenarios']
    b=m['CONFIRMED_CANDIDATE']; c=m['ANY_NON_REJECTED']
    assert (b['TP'],b['FP'],b['FN'],b['TN'])==(1,1,0,4)
    assert b['PRECISION']['value']==.5 and b['F1']['value']==pytest.approx(2/3)
    assert c['FP']==2 and c['F1']['value']==.5

@pytest.mark.parametrize('members,expected',[(['a'],'SINGLE_STAGE'),(['a','b'],'EXACT_GT_STEP'),
    (['a','c'],'CROSS_GT_MIXED'),(['a','missing'],'UNMAPPABLE')])
def test_exclusive_classification(members,expected):
    gt=dict(a='t1',b='t1',c='t2'); sets=dict(t1={'a','b'},t2={'c'})
    assert classify_proposal(group('g',members),gt,sets)['classification']==expected

def test_pure_subset_and_singleton_exact_flag():
    gt=dict(a='t1',b='t1',c='t1',d='t2'); sets=dict(t1={'a','b','c'},t2={'d'})
    assert classify_proposal(group('g',['a','b']),gt,sets)['classification']=='PURE_GT_SUBSET'
    row=classify_proposal(group('single',['d']),gt,sets)
    assert row['exact_set_match'] and not row['nontrivial_exact_recovery'] and row['classification']=='SINGLE_STAGE'

def test_recovery_does_not_promote_singleton_or_cherry_pick_purity():
    sets=dict(t1={'a','b'},t2={'c'},t3={'d'})
    result=recovery([group('exact',['a','b']),group('mixed',['a','b','c']),group('single',['d'],'UNRESOLVED')],sets)
    assert result['GT_STEP_EXACT_RECOVERED_COUNT']==1
    assert result['MULTI_ACTION_GT_EXACT_RECOVERY_RATE']['value']==1
    assert result['trivial_singleton_set_coverage_count']==1
    row=next(x for x in result['stages'] if x['gt_stage_id']=='t2')
    assert row['best_proposal']['BEST_COVERAGE']==1 and row['best_proposal']['BEST_PURITY']==pytest.approx(1/3)

def test_partial_candidate_is_not_exact_true():
    gt=dict(a='t1',b='t1',c='t1',d='t2'); sets=dict(t1={'a','b','c'},t2={'d'})
    rows=[classify_proposal(g,gt,sets) for g in [group('partial',['a','b']),group('bad',['a','d']),group('true',['a','b','c'])]]
    result=candidate_truth(rows)
    assert result['CANDIDATE_GT_TRUE_COUNT']==1 and result['CANDIDATE_GT_FALSE_COUNT']==1
    assert result['PARTIAL_GT_CANDIDATE_COUNT']==1 and result['CANDIDATE_GT_TRUE_RATE']['value']==pytest.approx(1/3)

def mapping_fixture():
    alerts=[dict(alert_id='a',source_namespace='native.namespace',source_record_id='event-1',raw_alert={'x':1})]
    stages=[dict(stage_id='s',alert_ids=['a'])]
    native=[dict(event_id='event-1',source_type='sensor',event={'x':1})]
    gt=dict(stages=[dict(stage_id='t',name='step',member_alert_ids=['event-1'])],observations=[dict(alert_id='event-1',stage_id='t',source_type='sensor')])
    audit=[dict(gt_stage_id='t',algorithm_stages=[dict(stage_id='s',member_alert_ids=['a'])])]
    return alerts,stages,native,gt,audit

def test_mapping_uses_identity_source_payload_and_audit_crosscheck():
    report,*_=mapping_from_native(*mapping_fixture())
    assert report['complete'] and report['mapping_completeness']['value']==1

def test_missing_envelope_id_resolves_unique_complete_payload_only():
    args=mapping_fixture(); args[0][0]['source_record_id']=None
    report,*_=mapping_from_native(*args)
    assert report['complete'] and report['identity_resolution_counts']=={'UNIQUE_COMPLETE_NATIVE_PAYLOAD':1}

def test_ambiguous_complete_payload_is_not_guessed():
    args=mapping_fixture(); args[0][0]['source_record_id']=None
    duplicate=copy.deepcopy(args[2][0]);duplicate['event_id']='different-native-id';args[2].append(duplicate)
    report,*_=mapping_from_native(*args)
    assert not report['complete'] and report['GT_ALERT_MAPPING_DUPLICATE']==1

@pytest.mark.parametrize('damage',['missing','duplicate','payload','source_type','audit'])
def test_mapping_errors_keep_population_and_fail_quality(damage):
    args=mapping_fixture(); alerts,stages,native,gt,audit=args
    if damage=='missing':alerts[0]['source_record_id']='missing'
    if damage=='duplicate':gt['observations'].append(copy.deepcopy(gt['observations'][0]))
    if damage=='payload':native[0]['event']={'x':2}
    if damage=='source_type':gt['observations'][0]['source_type']='other'
    if damage=='audit':audit[0]['gt_stage_id']='other'
    report,*_=mapping_from_native(*args)
    assert not report['complete'] and report['population_alert_count']==1

def test_mixed_algorithm_stage_detected():
    alerts,stages,native,gt,audit=mapping_fixture()
    alerts.append(dict(alert_id='b',source_namespace='native.namespace',source_record_id='event-2',raw_alert={'x':2}))
    stages[0]['alert_ids'].append('b'); native.append(dict(event_id='event-2',source_type='sensor',event={'x':2}))
    gt['stages'].append(dict(stage_id='u',name='another',member_alert_ids=['event-2']))
    gt['observations'].append(dict(alert_id='event-2',stage_id='u',source_type='sensor'))
    report,*_=mapping_from_native(alerts,stages,native,gt,audit)
    assert not report['complete'] and report['MIXED_GT_STAGE_ALGORITHM_STAGE_COUNT']==1

def test_ranking_ties_and_one_class():
    assert auc([1,1],[1,1])['value']==.5
    assert auc([2],[1])['value']==1
    assert auc([],[1])['status']=='NOT_EVALUABLE'
    assert hypergeom_tail(4,2,2,2)==pytest.approx(1/6)

def test_gt_read_blocked_before_verification(tmp_path):
    inputs=Inputs(tmp_path)
    with pytest.raises(ValueError,match='GT_read_before'):inputs.read(tmp_path/'does_not_exist',gt=True)
    assert not inputs.events

def test_digest_mismatch_stops_before_gt(tmp_path):
    main=tmp_path/'attack_step_semantic_output.json'; main.write_text('{}',encoding='utf8')
    manifest=tmp_path/'artifact_manifest.json'; manifest.write_text('{}',encoding='utf8')
    (tmp_path/'acceptance_seal.json').write_text(json.dumps(dict(artifact_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),semantic_output_sha256='invalid')),encoding='utf8')
    inputs=Inputs(tmp_path)
    with pytest.raises(ValueError,match='SHA_mismatch'):inputs.verify()
    assert not inputs.verified and not any(r['gt'] for r in inputs.events)

def test_sole_missing_claim_diagnosis_is_not_circular():
    g=group('g',['a','b']);g.update(disconnected_members=False,source_relation_ids=['r'])
    row=classify_proposal(g,dict(a='t',b='t'),dict(t={'a','b'}))
    identity=dict(subtype='request',scope='{"kind":"request","namespace":"native","host_scope":"host"}',value='request-id')
    source=dict(alerts=[dict(alert_id='x',alert_type='request'),dict(alert_id='y',alert_type='response')],
        stages=dict(stages=[dict(stage_id='a',alert_ids=['x']),dict(stage_id='b',alert_ids=['y'])]),
        candidates=dict(features=[dict(stage_id=sid,kind='request',identity=identity,witnesses=[dict(alert_id=aid)]) for sid,aid in [('a','x'),('b','y')]]),
        evidence=dict(claims=[dict(claim_id='c',valid=True,semantic_class='DIRECTIONAL_RELATION',evidence_type='EXPLICIT_ATTESTED_RELATION')],
                      decisions=[dict(candidate_id='r',relation_claim_ids=['c'])]))
    log=dict(candidate_id='g',whole_group_check=dict(p1=dict(covered_alert_ids=[],failures=['No REQUEST_RESPONSE']),unresolved_reference_count=0),contradictions=[])
    g['contradictions']=[]
    report=evidence_diagnosis([g],[row],[log],source,dict(request_operations=['request'],response_operations=['response']))
    assert report['GT_TRUE_CANDIDATE_BLOCKED_BY_P1_COUNT']==1
    source['alerts'][1]['alert_type']='exec'
    report=evidence_diagnosis([g],[row],[log],source,dict(request_operations=['request'],response_operations=['response']))
    assert report['GT_TRUE_CANDIDATE_BLOCKED_BY_P1_COUNT']==0

def test_cross_gt_temporal_gap_ignores_within_gt_overlap():
    g=group('g',['a','b','c']);gt=dict(a='one',b='one',c='two')
    classified=classify_proposal(g,gt,dict(one={'a','b'},two={'c'}))
    shared=dict(session_bindings=[],flow_bindings=[],time_overlap=False,host_entities=[],account_entities=[])
    log=dict(candidate_id='g',whole_group_check=dict(shared_context=shared))
    source=dict(stages=dict(stages=[dict(stage_id=s,start_time=start,end_time=end) for s,start,end in [
        ('a','2026-01-01T00:00:00Z','2026-01-01T00:00:10Z'),
        ('b','2026-01-01T00:00:05Z','2026-01-01T00:00:10Z'),
        ('c','2026-01-01T00:00:20Z','2026-01-01T00:00:30Z')]]),evidence=dict(claims=[],decisions=[]))
    g['grouping_basis']=dict(reason_codes=['PURPOSE_NOT_PROVEN'])
    report=cross_gt_risks([classified],[g],[log],source)
    assert report['proposals'][0]['minimum_observed_stage_gap_seconds']==10
