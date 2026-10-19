"""Synthetic safety witnesses for experimental calibration, without release labels."""
from copy import deepcopy
import ast
from pathlib import Path
import pytest
import yaml
from evaluation.framework.scoring_calibration import POLICY
from evaluation.framework.scoring_calibration.model import score, project, admits
from evaluation.framework.scoring_calibration.statistics import distribution, ThresholdCounts, choose


@pytest.fixture
def config():
    return yaml.safe_load(POLICY.read_text(encoding='utf8'))


def feature(kind='SESSION', state='OBSERVED_SUPPORT', **updates):
    return dict(name='entity.'+kind, family='entity', state=state, strength=.8,
                reliability=.8, hot=False, role='generic', parent_only=False,
                anchor_kind='session' if kind == 'SESSION' else None, **updates)


def environment(features):
    return dict(features=features, gate=dict(passed=True), valid=True, duplicate=0.,
                conflict_penalty=0., duplicate_penalty=0.)


@pytest.mark.parametrize('model', ['A', 'B', 'C'])
def test_missing_and_unobservable_never_dilute_or_create_support(config, model):
    env = environment([feature()])
    value = score(env, config, model)['score']
    env['features'] += [feature('HOST', state='MISSING'), feature('ACCOUNT', state='UNOBSERVABLE')]
    assert score(env, config, model)['score'] == value
    assert score(environment(env['features'][1:]), config, model)['score'] == 0


@pytest.mark.parametrize('model', ['A', 'B', 'C'])
def test_duplicate_packaging_does_not_increase_score(config, model):
    env = environment([feature()])
    old = score(env, config, model)['score']
    env['features'] += [deepcopy(env['features'][0])]*7
    assert score(env, config, model)['score'] == old


@pytest.mark.parametrize('model', ['A', 'B', 'C'])
def test_time_source_capability_and_detector_cannot_nominate(config, model):
    fs = [dict(feature(), family=f, name=f, strength=1) for f in ('time', 'source', 'behavior')]
    assert score(environment(fs), config, model)['score'] == 0


@pytest.mark.parametrize('model', ['A', 'B', 'C'])
def test_hard_guard_always_beats_high_score(config, model):
    env = environment([feature()]); env['gate']['passed'] = False
    assert score(env, config, model)['score'] == 0
    assert not admits(score(env, config, model), .4, 'global', config)


def test_shared_parent_is_not_child_identity_or_anchor(config):
    f = feature('PROCESS'); f.update(parent_only=True, anchor_kind=None, strength=.95)
    result = score(environment([f, feature('HOST')]), config, 'C')
    assert not result['anchor'] and result['score'] <= .45
    assert not admits(result, .4, 'strong_anchor', config)


def test_observed_zero_affects_confidence_but_missing_does_not(config):
    before = score(environment([feature()]), config, 'A')['score']
    after = score(environment([feature(), feature('HOST', state='OBSERVED_NEUTRAL')]), config, 'A')['score']
    assert after < before


def test_explicit_penalties_never_reward(config):
    env = environment([feature()])
    before = score(env, config, 'C')['score']
    env['conflict_penalty'] = .2
    env['duplicate_penalty'] = .1
    assert score(env, config, 'C')['score'] == pytest.approx(before-.3)


def test_hot_identifier_not_a_strong_anchor(config):
    f = feature(); f['hot'] = True
    assert not score(environment([f]), config, 'C')['anchor']


def test_exact_threshold_is_unrounded_and_no_epsilon(config):
    r = dict(gate=True, score=.648292, anchor=True, mass=.9, contradiction=False)
    assert not admits(r, .65, 'global', config)
    r['score'] = .65
    assert admits(r, .65, 'global', config)


def test_policy_uses_observable_class_only(config):
    r = dict(gate=True, score=.7, anchor=False, mass=.3, contradiction=True)
    assert admits(r, .65, 'global', config)
    assert not admits(r, .65, 'evidence_class', config)
    assert not admits(r, .65, 'strong_anchor', config)
    assert not admits(r, .65, 'contradiction_gate', config)
    assert not admits(r, .65, 'mass_floor', config)


def test_distribution_keeps_unscored_out_of_quantiles():
    result = distribution([None, .6, .8], 1, total=3)
    assert result['count'] == 3 and result['unscored_count'] == 1
    assert result['min'] == .6 and result['median'] == pytest.approx(.7)
    assert result['admission_rate'] == pytest.approx(1/3)
    assert distribution([], 0)['median'] is None


def test_threshold_counts_exact_boundary_and_partition():
    c = ThresholdCounts([.4, .65, .85], ['all', 'cross', 'same'])
    c.add(.65, ['all', 'cross']); c.add(.39, ['all', 'same']); c.add(None, ['all'])
    result = c.rows()
    assert [r['all'] for r in result] == [1, 1, 0]
    assert all(r['all'] == r['same']+r['cross'] for r in result)


def test_projection_discards_ids_pointers_and_source_names_before_arithmetic():
    f = feature('PROCESS'); f.update(entity_ids=['p'], provenance=[{'pointer': '/parent_pid'}])
    v5 = dict(features=[f], gate=dict(passed=True), duplicate=0., conflict_penalty=0., duplicate_penalty=0.)
    row = dict(support_pair=['a', 'b'], evidence=dict(evidence_v5=v5), valid=True)
    alerts = {i: dict(entity_ids=['p'], entity_occurrences=[dict(entity_id='p', role='parent_process')]) for i in ('a', 'b')}
    env, bindings = project(row, alerts, dict(p=dict(value='{}', scope='{}')))
    assert env['features'][0]['parent_only'] and env['features'][0]['anchor_kind'] is None
    assert all(k not in env['features'][0] for k in ('entity_ids', 'provenance', 'source_type', 'event_id'))
    # Shared ancestors are retained as context features, not typed instance bindings.
    assert bindings == []


def test_evaluation_checks_seal_before_labels(monkeypatch):
    from evaluation.framework.scoring_calibration import evaluate
    seen = []
    monkeypatch.setattr(evaluate, 'verify_seal', lambda: (_ for _ in ()).throw(ValueError('unsealed')))
    monkeypatch.setattr(evaluate, 'read', lambda p: seen.append(p))
    with pytest.raises(ValueError, match='unsealed'):
        evaluate.run()
    assert seen == []


def test_experimental_arithmetic_has_no_file_access_or_label_branches():
    from evaluation.framework.scoring_calibration import model
    tree = ast.parse(__import__('inspect').getsource(model.score))
    assert not any(isinstance(n, ast.Name) and n.id in {'open', 'read', 'source_type', 'scenario_id'} for n in ast.walk(tree))


def test_selection_respects_exposure_and_volume_limits(config):
    rows = [dict(model='C', policy='global', gt_admitted=7, hn_admitted=0, threshold=.65,
                 total_admitted=50000),
            dict(model='B', policy='global', gt_admitted=5, hn_admitted=0, threshold=.65,
                 total_admitted=100)]
    assert choose(rows, gt_total=7, hn_total=180, baseline_total=1000,
                  config=config['selection'])['model'] == 'B'
