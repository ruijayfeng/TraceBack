"""Synthetic scope/observability invariants, not development labels as assertions."""
import copy
import json
from pathlib import Path
import pytest
from evaluation.framework.sparse_semantics import model, runtime
from evaluation.framework.anchor_semantics.runtime import stress_inputs


@pytest.fixture
def policy(): return runtime.load_policy()['formula']


def case(name): return copy.deepcopy(next(r for r in stress_inputs(1)[0] if r['id']==name+':0'))


def projected(item,policy,behavior='provided'):
    return model.project(item['env'],item['bindings'],item['a'],item['b'],item['entities'],
                         item['behavior'] if behavior=='provided' else behavior,policy)


def test_unknown_has_no_multiplicative_factor(policy):
    item=case('missing_task_multiple_weak_signals');p,a=projected(item,policy,None)
    result=model.score(p,policy,.65)
    assert result['semantic_compatibility']==1
    assert 0<result['evidence_confidence']<1
    assert result['unobserved_evidence_mass']>0
    assert a['behavior_observed'] is False and a['behavior_support'] is None
    assert result['support_strength']>0 and result['score']>0


def test_observed_zero_is_not_missing_or_explicit_conflict(policy):
    item=case('missing_task_multiple_weak_signals')
    p,a=projected(item,policy,0.)
    q,b=projected(item,policy,None)
    assert a['behavior_observed'] and a['behavior_support']==0.
    assert not b['behavior_observed']
    assert model.score(p,policy,.65)['score']==model.score(q,policy,.65)['score']
    assert model.score(p,policy,.65)['evidence_completeness']>model.score(q,policy,.65)['evidence_completeness']


@pytest.mark.parametrize('scope',['TASK_CONTRADICTION','IDENTITY_CONTRADICTION','CONTEXT_CONTRADICTION','DIRECTION_CONTRADICTION','INCIDENT_CONTRADICTION'])
def test_all_required_scopes_are_configured(policy,scope):
    assert scope in {x['scope'] for x in policy['contradiction_matrix'].values()}


def test_task_contradiction_does_not_zero_incident_path(policy):
    item=case('worker_pool');p,a=projected(item,policy)
    result=model.score(p,policy,.65)
    assert a['local_contradictions'][0]['scope']=='TASK_CONTRADICTION'
    assert not a['incident_contradictions']
    assert result['support_strength']>0 and result['score']>0
    assert a['granularity']['TASK_RELATION']=='CONTRADICTED'
    assert a['granularity']['INCIDENT_CONTEXT_RELATION']=='OBSERVED_CONTEXT'


@pytest.mark.parametrize('name',['identifier_reuse','sensor_local_collision','pid_reuse','long_lived_session','persistent_connection','shared_login_context'])
def test_single_context_is_not_sufficient(policy,name):
    p,a=projected(case(name),policy)
    assert model.score(p,policy,.65)['decision']!='ADMIT'
    assert not a['incident_contradictions']


@pytest.mark.parametrize('name',['short_request_continuation','transaction_continuation','process_child_lineage','cross_source_attested','request_worker_binding'])
def test_task_and_direct_witnesses_survive(policy,name):
    p,a=projected(case(name),policy)
    assert model.score(p,policy,.65)['decision']=='ADMIT'
    assert a['anchor_category'] in {'DIRECT_RELATION_ANCHOR','TASK_SCOPED_ANCHOR'}


@pytest.mark.parametrize('field',['hard_contradiction','duplicate_observation'])
def test_original_guard_never_bypassed(policy,field):
    item=case('cross_source_attested');item['env']['gate'][field]=True
    p,_=projected(item,policy)
    assert model.score(p,policy,.65)['decision']=='REJECT'


def test_equivalence_is_proven_on_actual_scoring_input(policy):
    positive=case('sparse_content_continuation');negative=case('unobserved_distinct_tasks')
    p,_=projected(positive,policy);n,_=projected(negative,policy)
    assert p==n
    assert runtime.digest(p)==runtime.digest(n)
    assert model.score(p,policy,.65)==model.score(n,policy,.65)
    assert model.score(p,policy,.65)['decision']=='AMBIGUOUS'
    assert runtime.anonymized_witness(positive)==runtime.anonymized_witness(negative)


def test_ambiguity_never_counts_as_hn_rejection(policy):
    p,_=projected(case('unobserved_distinct_tasks'),policy);r=model.score(p,policy,.65)
    assert r['decision']=='AMBIGUOUS' and r['binary_admit']
    result=runtime.metrics([dict(positive=False,candidate=True,result=r),dict(positive=True,candidate=True,result=r)])
    assert result['hn_rejection']==result['binary_hn_rejection']==0
    assert result['admission_recall']==0 and result['binary_gt_admission_recall']==1
    assert result['ambiguous_rate']==1


def test_numeric_input_order_and_feature_duplication_are_neutral(policy):
    item=case('short_request_continuation');p,_=projected(item,policy)
    item['env']['features']=list(reversed(item['env']['features']))*3
    q,_=projected(item,policy)
    assert p==q
    p['channels']=list(reversed(p['channels']))*3
    assert model.score(p,policy,.65)==model.score(q,policy,.65)


def test_source_and_identity_names_do_not_enter_score(policy):
    item=case('short_request_continuation');p,_=projected(item,policy)
    item['a']['alert_id']='renamed-a';item['b']['alert_id']='renamed-b'
    item['source_pair']=['renamed-source','renamed-source']
    q,_=projected(item,policy)
    assert p==q


def test_bound_native_pointers_resolve(policy):
    item=case('short_request_continuation');_,a=projected(item,policy)
    alerts={r['alert_id']:r for r in [item['a'],item['b']]}
    from evaluation.framework.anchor_semantics.model import resolve
    refs=[r for x in a['evidence'] for r in x['evidence_refs']]
    assert refs
    assert all(resolve(alerts[r['alert_id']]['raw_alert'],r['pointer']) is not None for r in refs)


def test_seal_checked_before_evaluation_labels(monkeypatch):
    reads=[]
    monkeypatch.setattr(runtime,'verify_predictions',lambda:(_ for _ in ()).throw(ValueError('unsealed')))
    monkeypatch.setattr(runtime,'read',lambda x:reads.append(x))
    with pytest.raises(ValueError,match='unsealed'):runtime.evaluate()
    assert reads==[]


def test_missing_candidate_stays_in_recall_denominator():
    r=dict(positive=True,candidate=False,result=dict(score=0.,decision='REJECT',binary_admit=False))
    result=runtime.metrics([r]);assert result['candidate_recall']==0 and result['admission_recall']==0


def test_writes_are_scoped_to_evaluation():
    assert runtime.OUT.is_relative_to(runtime.ROOT/'evaluation')
    assert runtime.OUT!=runtime.PREVIOUS


def test_object_handoff_is_incident_context_without_direction(policy):
    item=case('long_lived_session')
    item['a']['host']=item['b']['host']='asset'
    item['a']['raw_alert'].update(application_id='application',response_object_id='opaque-object')
    item['b']['raw_alert'].update(application_id='application',request_object_id='opaque-object')
    p,a=projected(item,policy,None)
    assert p['discriminating_context']
    assert a['granularity']['DIRECT_RELATION']=='UNKNOWN'
    assert a['granularity']['TASK_RELATION']=='UNKNOWN'
    assert model.score(p,policy,.65)['decision']=='ADMIT'


def test_same_object_token_without_target_scope_does_not_qualify(policy):
    item=case('long_lived_session')
    item['a'].update(host='asset-a');item['b'].update(host='asset-b')
    item['a']['raw_alert'].update(application_id='app',response_object_id='object')
    item['b']['raw_alert'].update(application_id='app',request_object_id='object')
    p,_=projected(item,policy,None)
    assert not p['discriminating_context']


def test_unknown_config_key_fails_closed(tmp_path,monkeypatch):
    import yaml
    p=runtime.load_policy();p['formula']['unknown_penalty']=.7
    target=tmp_path/'bad.yaml';target.write_text(yaml.safe_dump(p),encoding='utf8')
    monkeypatch.setattr(runtime,'POLICY',target)
    with pytest.raises(ValueError,match='unknown_or_missing_formula_key'):runtime.load_policy()
