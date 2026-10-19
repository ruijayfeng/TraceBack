"""Synthetic checks for post-seal evaluation boundaries and denominators."""
import pytest
from evaluation.framework.source_bound_final import evaluate


def test_unsealed_evaluation_denied_before_any_truth_read(monkeypatch):
    reads=[]
    monkeypatch.setattr(evaluate,'verify_seal',lambda:(_ for _ in ()).throw(ValueError('not_sealed')))
    monkeypatch.setattr(evaluate,'read',lambda p:reads.append(p))
    with pytest.raises(ValueError,match='not_sealed'): evaluate.main()
    assert reads==[]


def test_binding_denominator_counts_typed_pairs_not_component_rows():
    component=dict(binding_type='flow',source_alert_id='a',target_alert_id='b',source_field='event.flow_id',target_field='event.flow_id',value=1)
    port={**component,'source_field':'event.src_port','target_field':'event.src_port','value':2}
    truth=dict(observation_bindings=[component,port],edges=[dict(binding_evidence=[component])])
    groups=evaluate.binding_groups(truth)
    assert len(groups)==1 and len(next(iter(groups.values())))==2
    truth['observation_bindings'].append({**component,'binding_type':'request'})
    assert len(evaluate.binding_groups(truth))==2


def test_progression_length_requires_consecutive_admitted_links():
    edges=[dict(source_stage='a',target_stage='b',admitted=True),dict(source_stage='b',target_stage='c',admitted=False),
           dict(source_stage='c',target_stage='d',admitted=True),dict(source_stage='d',target_stage='e',admitted=True)]
    assert evaluate.longest_path(edges,'admitted')==2


def test_key_normalizes_pair_orientation_without_identity_inference():
    assert evaluate.key('a','b')==evaluate.key('b','a')
    assert evaluate.key('a','b')!=evaluate.key('a','c')


def test_missing_scored_member_is_not_zero_or_admitted(monkeypatch):
    rep=object.__new__(evaluate.FrozenReplay)
    rep.trace={'x':'a','y':'b'};rep.owner={'a':'a','b':'b'}
    rep.candidates=set();rep.scores={};rep.admitted={};rep.nominations={};rep.decisions={}
    row=rep.pair('x','y')
    assert not row['candidate'] and row['score'] is None and not row['admitted']
