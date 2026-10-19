"""Synthetic formula safety, observable semantics and blind boundary tests."""
from dataclasses import replace
from pathlib import Path
import copy
import json
import math
import pytest
import yaml

from evaluation.framework.formula_design import POLICY
from evaluation.framework.formula_design.model import Evidence, Envelope, score, project, conflict_classification, incompatible_identity_proof
from evaluation.framework.formula_design.runtime import guard


@pytest.fixture
def policy():return yaml.safe_load(POLICY.read_text(encoding='utf8'))


def sample(kind='ip'):
    values={'ip':[Evidence('entity.IP','entity','SUPPORT',.8,.15)],
        'account':[Evidence('entity.ACCOUNT','entity','SUPPORT',.8,.3)],
        'joint':[Evidence('entity.HOST','entity','SUPPORT',.8,.7,role='host'),Evidence('entity.ACCOUNT','entity','SUPPORT',.8,.75,role='account')],
        'direct':[Evidence('topology.attested_relation','relation','SUPPORT',.9,.95,role='direct')],
        'time':[]}[kind]
    return Envelope(tuple(values+[Evidence('time.distance','time','SUPPORT',1.,.1)]),(),0.,False,True,.2,.2,0.,(('entity',.3),('time',.2)))


def counterexamples(policy,model='F3'):
    a,b,c=(score(sample(x),policy,model) for x in ('ip','account','joint'))
    representation=replace(sample('joint'),conflicts=({'kind':'REPRESENTATION_DIFFERENCE','rule':'different_target_without_bridge','strength':.8,'provenance':[]},))
    proof=incompatible_identity_proof(left='asset-one',right='asset-two',role='operation_target',scope='synthetic-scope',context='same-operation',moment='same-observation',provenance=({'pointer':'/left'},{'pointer':'/right'}))
    hard=score(replace(sample('joint'),conflicts=(proof,)),policy,model)
    sparse=sample('ip');many=replace(sparse,evidence=sparse.evidence+tuple(Evidence('missing.'+str(i),'source','UNAVAILABLE',0.,.6) for i in range(20)))
    return dict(A=dict(score=a['final_score'],pass_=a['final_score']<=.45),B=dict(score=b['final_score'],pass_=b['final_score']<=.45),
        C=dict(score=c['final_score'],pass_=c['final_score']>max(a['final_score'],b['final_score'])+.2),
        D=dict(score=score(representation,policy,model)['final_score'],pass_=score(representation,policy,model)['conflict_penalty']==0.),
        E=dict(score=hard['final_score'],pass_=hard['gates']['hard'] and hard['final_score']==0.),
        F=dict(score=score(many,policy,model)['final_score'],pass_=score(many,policy,model)['final_score']==score(sparse,policy,model)['final_score'] and score(many,policy,model)['final_score']<=.45))


@pytest.mark.parametrize('case',list('ABCDEF'))
@pytest.mark.parametrize('model',['F1','F2','F3'])
def test_counterexamples(policy,case,model):assert counterexamples(policy,model)[case]['pass_']


@pytest.mark.parametrize('model',['F0','F1','F2','F3'])
def test_score_finite_range_and_reconstruction(policy,model):
    for kind in ('ip','account','joint','direct','time'):
        r=score(sample(kind),policy,model)
        assert math.isfinite(r['final_score']) and 0<=r['final_score']<=1
        if model=='F0':assert r['final_score']==sample(kind).v4_score
        else:
            raw=max(0,min(1,r['positive_support']-r['conflict_penalty']-r['duplicate_penalty']))
            expected=min(raw,policy['weak_ceiling']) if r['gates']['weak_only'] else raw
            if not r['gates']['non_temporal_semantics']:expected=0.
            assert r['final_score']==pytest.approx(expected)


def test_time_only_never_admitted_and_weak_normalization_cannot_inflate(policy):
    for m in ('F1','F2','F3'):
        for g in ('hard','soft','hybrid'):
            r=score(sample('time'),policy,m,gate_mode=g)
            assert r['final_score']==0 and not r['reference_admitted']
        assert score(sample('ip'),policy,m)['final_score']<=.45


def test_missing_zero_contradiction_distinct(policy):
    e=sample('joint')
    missing=replace(e,evidence=e.evidence+(Evidence('source','source','UNAVAILABLE',0,.6),))
    zero=replace(e,evidence=e.evidence+(Evidence('source','source','OBSERVED_ZERO',0,.6),))
    assert score(missing,policy)['support_score']==score(e,policy)['support_score']
    assert score(zero,policy)['support_score']<score(e,policy)['support_score']
    assert not score(missing,policy)['contradictions']


def test_provenance_identity_and_marker_text_never_score_features(policy):
    e=sample('joint')
    poisoned=replace(e,evidence=tuple(replace(x,provenance=({'alert_id':'GT-E03','scenario_id':'attack','pointer':'/synthetic','fixed_account':'admin'},)) for x in e.evidence))
    a,b=score(e,policy),score(poisoned,policy)
    for key in ('final_score','support_score','coverage_confidence','positive_support','gates'):assert a[key]==b[key]


def test_project_ignores_raw_labels_detector_text_and_dataset_ids(policy):
    a=dict(alert_id='a',entity_occurrences=[],field_provenance={},raw_alert={})
    b={**a,'alert_id':'b'}
    audit=dict(dimensions=[dict(dimension='time.distance',family='time',state='AVAILABLE_MATCH',strength=.9,weight=1.,entity_ids=[])],
               family_weights={'time':.2},quality_factor=.65,mass_factor=.35,normalized_quality=.9,evidence_mass=.18,
               duplicate_observation_risk=False,evidence_gate_passed=False,entity_reliability=[])
    row=dict(support_pair=['a','b'],score=.2,values={'duplicate':0.,'conflict':0.},evidence={'evidence_v2':audit,'conflicts':{},'relations':[]})
    e=project(row,{'a':a,'b':b},policy)
    altered=copy.deepcopy({'a':a,'b':b})
    for x in altered.values():
        x.update(scenario_id='GT-E05',source_record_id='synthetic',signature='attack',host='dataset-host')
        x['raw_alert']={'GT label':True,'scenario_id':'attack','synthetic marker':'yes','dataset-specific IP':'192.0.2.1'}
    assert score(e,policy)['final_score']==score(project(row,altered,policy),policy)['final_score']


def test_entity_projection_preserves_original_and_corrects_only_compatible_roles(policy):
    alerts={k:dict(alert_id=k,entity_occurrences=[dict(entity_id='e',role=r,raw_pointer='/subject')],field_provenance={}) for k,r in [('a','authenticated_account'),('b','audit_account')]}
    audit=dict(dimensions=[dict(dimension='entity.ACCOUNT',family='entity',state='AVAILABLE_MATCH',strength=.35,weight=.7,entity_ids=['e'])],
        family_weights={'entity':.3},quality_factor=.65,mass_factor=.35,normalized_quality=.35,evidence_mass=.105,
        duplicate_observation_risk=False,evidence_gate_passed=False,entity_reliability=[dict(entity_id='e',role_factor=.5)])
    row=dict(support_pair=['a','b'],score=.2,values={'duplicate':0.,'conflict':0.},evidence=dict(evidence_v2=audit,conflicts={},relations=[]))
    e=project(row,alerts,policy).evidence[0]
    assert e.strength==.7 and e.original_strength==.35 and e.reliability==.75 and e.role=='account'


@pytest.mark.parametrize('kind',['UNAVAILABLE','NOT_APPLICABLE','OBSERVED_ZERO','AMBIGUOUS','CONTRADICTORY'])
def test_non_support_has_no_strength(kind):
    with pytest.raises(ValueError):Evidence('x','entity',kind,.1,.2)


@pytest.mark.parametrize('strength',[float('nan'),float('inf'),-.1,1.1])
def test_invalid_numeric_evidence_fails(strength):
    with pytest.raises(ValueError):Evidence('x','entity','SUPPORT',strength,.5)


def test_representation_and_unknown_equivalence_are_not_proved_hard():
    for l,r,expected in [('HOST','ENDPOINT','REPRESENTATION_DIFFERENCE'),('HOST','HOST','UNKNOWN_EQUIVALENCE')]:
        conflicts=dict(soft=[('different_target_without_bridge',.8)],left_targets=[{'key':[l],'raw_pointers':[]}],right_targets=[{'key':[r],'raw_pointers':[]}])
        assert conflict_classification(conflicts)[0]['kind']==expected
    with pytest.raises(ValueError):incompatible_identity_proof(left='one',right='two',role='',scope='',context='',moment='',provenance=[])


def test_duplicate_cannot_manufacture_new_evidence(policy):
    e=sample('joint');r=score(replace(e,duplicate_risk=True),policy)
    assert not r['reference_admitted'] and r['final_score']==0.
    assert score(replace(e,duplicate=.9),policy)['final_score']<score(e,policy)['final_score']


def test_blind_allowlist_blocks_truth_other_outputs_and_mutations(tmp_path):
    input_=tmp_path/'canonical.json';input_.write_text('{}');truth=tmp_path/'ground_truth.json';truth.write_text('{}')
    out=tmp_path/'out';out.mkdir()
    with guard([input_],out) as (events,reads):
        assert input_.read_text()=='{}'
        for path in (truth,tmp_path/'other.json'):
            with pytest.raises(PermissionError):path.read_text()
        with pytest.raises(PermissionError):input_.write_text('changed')
        (out/'prediction.json').write_text('{}')
    assert len(events)==3 and input_.read_text()=='{}'


def test_runtime_has_no_truth_reader_or_production_dispatch_imports():
    import ast
    from evaluation.framework.formula_design import ROOT
    for name in ('model.py','runtime.py'):
        tree=ast.parse((ROOT/'evaluation/framework/formula_design'/name).read_text(encoding='utf8'))
        for n in ast.walk(tree):
            if isinstance(n,ast.ImportFrom):assert not any(x in (n.module or '') for x in ('truth','evaluate','scoring','candidates','chains'))


def test_gate_ablation_changes_admission_without_claiming_score_improvement(policy):
    e=replace(sample('joint'),evidence=tuple(x for x in sample('joint').evidence if x.role!='account'))
    hard,soft,hybrid=(score(e,policy,gate_mode=g) for g in ('hard','soft','hybrid'))
    assert not hard['gates']['passed'] and hybrid['gates']['passed']
    assert soft['final_score']<hybrid['final_score']


def test_strict_ordering_does_not_silently_credit_ties_or_missing_negatives():
    from evaluation.framework.formula_design.evaluate import ordering,dist
    r=ordering({'one':.5,'two':.9},[.1,.5,.9])
    assert r['strict_rate']==.5
    assert r['tie_half_rate']==pytest.approx(2/3)
    assert r['per_gt']['one']==dict(score=.5,above=1,below=1,tied=1,negative_count=3)
    assert ordering({'one':.5},[])['strict_rate'] is None
    assert dist([])['p99'] is None and dist([0,1])['p95']==.95


def test_independent_f2_arithmetic_and_tamper_detection_basis(policy):
    from evaluation.framework.formula_design.audits import recompute_f2
    row=dict(evidence=dict(supporting_evidence=[dict(name='entity.HOST',family='entity',weight=1.,reliability=.7,strength=.8,state='SUPPORT')],
        weak_evidence=[],observed_zero_evidence=[],unavailable_evidence=[]),
        results={'F2':dict(temporal_compatibility=.5,conflict_penalty=.08,duplicate_penalty=.04,
            gates=dict(weak_only=False,non_temporal_semantics=True,hard=False,duplicate_risk=False))})
    r=recompute_f2(row,policy)
    assert r['support_score']==pytest.approx(.8)
    assert r['positive_support']==pytest.approx(.72)
    assert r['final_score']==pytest.approx(.6)
    row['results']['F2']['gates']['hard']=True
    assert recompute_f2(row,policy)['final_score']==0.


def test_prediction_seal_is_required_before_formula_truth_read(monkeypatch):
    from evaluation.framework.formula_design import evaluate
    reads=[]
    monkeypatch.setattr(evaluate,'require_sealed',lambda:(_ for _ in ()).throw(ValueError('not_sealed')))
    monkeypatch.setattr(evaluate,'read',lambda p:reads.append(p))
    with pytest.raises(ValueError,match='not_sealed'):evaluate.evaluate()
    assert not reads
