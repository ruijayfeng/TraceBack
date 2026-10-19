"""Evidence-bound semantic regressions; labels never enter the arithmetic."""
import copy
import json
from pathlib import Path
import pytest
import yaml
from evaluation.framework.anchor_semantics import model, runtime
from evaluation.framework.scoring_calibration.model import score as original_score


@pytest.fixture
def policy():
    return yaml.safe_load(runtime.POLICY.read_text(encoding='utf8'))['formula']


def case(name):
    inputs,_=runtime.stress_inputs(1)
    return next(r for r in inputs if r['id']==name+':0')


def projected(item,policy):
    return model.project(item['env'],item['bindings'],item['a'],item['b'],item['entities'],item['behavior'],policy)


@pytest.mark.parametrize('scenario',[
    'identifier_reuse','long_lived_session','persistent_connection','shared_login_context',
    'worker_pool','multi_action_process','sensor_local_collision','pid_reuse'])
def test_context_or_identity_is_not_sufficient(scenario,policy):
    env,bound=projected(case(scenario),policy)
    result=model.score(env,policy)
    assert result['score']<.65
    assert result['direct_support']==0
    assert result['gate']  # score rejection, not a missing-evidence hard gate


@pytest.mark.parametrize('scenario',[
    'short_request_continuation','transaction_continuation','legitimate_long_session',
    'legitimate_login_context','process_child_lineage','cross_source_attested',
    'request_worker_binding','missing_task_multiple_weak_signals'])
def test_legitimate_and_sparse_alternatives_remain(scenario,policy):
    env,bound=projected(case(scenario),policy)
    result=model.score(env,policy)
    assert result['score']>=.65 and result['gate']


def test_original_shortcut_is_reproduced_without_validation_inputs(policy):
    item=case('long_lived_session');env,bound=projected(item,policy)
    old_policy=yaml.safe_load((runtime.ROOT/'evaluation/configs/scoring_calibration.yaml').read_text(encoding='utf8'))
    old=original_score(item['env'],old_policy,'C')
    new=model.score(env,policy)
    assert old['anchor'] and old['score']>=.65
    assert new['score']<.65
    assert new['anchors'][0]['dimensions']['task']==model.UNKNOWN


def test_missing_does_not_become_contradiction_or_veto(policy):
    item=case('legitimate_long_session');env,_=projected(item,policy)
    assert all(model.CONTRADICTED not in a['dimensions'].values() for a in env['anchors'])
    assert any(model.UNKNOWN in a['dimensions'].values() for a in env['anchors'])
    assert model.score(env,policy)['score']>=.65
    item=case('identifier_reuse');env,_=projected(item,policy)
    assert env['anchors'][0]['dimensions']['lifecycle']==model.CONTRADICTED


def test_task_anchor_still_needs_context_and_lifecycle(policy):
    item=case('short_request_continuation');env,_=projected(item,policy)
    assert env['anchors'][0]['taxonomy']=='TASK_SCOPED_ANCHOR'
    env['features']=[f for f in env['features'] if f['name']!='entity.HOST']
    assert model.score(env,policy)['score']<.65
    item=case('short_request_continuation')
    for alert in [item['a'],item['b']]:
        for k in ['start','end','epoch']: alert['raw_alert']['session_context'].pop(k)
    env,_=projected(item,policy)
    assert env['anchors'][0]['taxonomy']=='IDENTITY_ONLY'
    assert model.score(env,policy)['task_support']==0


def test_parent_only_does_not_upgrade_to_process_anchor(policy):
    item=case('worker_pool');item['bindings'][0]['parent_only']=True
    item['env']['features'][2]['parent_only']=True
    env,_=projected(item,policy)
    assert env['anchors']==[]
    before=model.score(env,policy)
    env['features']=[f for f in env['features'] if f['name']!='entity.PROCESS']
    assert model.score(env,policy)['score']==before['score']
    env['features']=[f for f in env['features'] if f['name']!='entity.ACCOUNT']
    assert model.score(env,policy)['score']<.65


@pytest.mark.parametrize('guard',['valid','hard_contradiction','duplicate_observation'])
def test_direct_path_preserves_existing_guards(guard,policy):
    env,_=projected(case('cross_source_attested'),policy)
    if guard=='valid':env['valid']=False
    else:env['gate'][guard]=True
    assert model.score(env,policy)['score']==0


def test_direct_cross_boundary_relation_remains_alternative(policy):
    item=case('worker_pool')
    item['env']['features'].append(runtime.feature('topology.attested_relation',.95,1.,
        anchor='attested_relation',role='direct',family='relation'))
    env,_=projected(item,policy)
    result=model.score(env,policy)
    assert result['weak_support']==0 and result['direct_support']==.95 and result['score']>=.65


def test_identity_renaming_and_evidence_repackaging_do_not_raise_score(policy):
    item=case('short_request_continuation');env,_=projected(item,policy)
    expected=model.score(env,policy)
    changed=copy.deepcopy(env)
    changed['features']=list(reversed(changed['features']))*2
    changed['anchors']=list(reversed(changed['anchors']))*2
    actual=model.score(changed,policy)
    assert actual['score']==expected['score']
    assert actual['mass']==expected['mass']


def test_bound_pointers_resolve_and_prediction_precedes_labels(policy):
    item=case('short_request_continuation');env,bound=projected(item,policy)
    alerts={a['alert_id']:a for a in [item['a'],item['b']]}
    assert bound[0]['evidence_refs']
    for a in bound:
        for ref in a['evidence_refs']:
            assert model.resolve(alerts[ref['alert_id']]['raw_alert'],ref['pointer']) is not None
    assert runtime.evaluate.__code__.co_names.index('verify_predictions')<runtime.evaluate.__code__.co_names.index('read')


def test_evaluation_never_reads_answers_if_seal_invalid(monkeypatch):
    reads=[]
    monkeypatch.setattr(runtime,'verify_predictions',lambda:(_ for _ in ()).throw(ValueError('unsealed')))
    monkeypatch.setattr(runtime,'read',lambda p:reads.append(p))
    with pytest.raises(ValueError,match='unsealed'):runtime.evaluate()
    assert reads==[]


def test_observation_equivalent_pairs_expose_identifiability_limit(policy):
    # A positive and a negative with identical observables must have equal scores.
    # No source name, scenario, label or identity-specific rule may separate them.
    item=case('missing_task_multiple_weak_signals');env,_=projected(item,policy)
    same=copy.deepcopy(item);same['id']='unrelated-but-unobserved-task'
    same['a']['alert_id']='renamed-a';same['b']['alert_id']='renamed-b'
    env2,_=projected(same,policy)
    assert model.score(env,policy)==model.score(env2,policy)


def test_stratified_denominators_include_missing_candidates():
    r=dict(id='missing',positive=True,candidate=False,result={'score':0.,'gate':False})
    m=runtime.metrics([r],.65)
    assert m['candidate_recall']==m['admission_recall']==0
    assert m['hn_rejection'] is None
