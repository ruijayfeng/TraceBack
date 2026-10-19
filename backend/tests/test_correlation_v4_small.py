"""Synthetic safety boundaries for the small-slice v4 experiment."""
from copy import deepcopy
from pathlib import Path
import sys
import pytest
from app.config import load_config
from app.models import ScoreBreakdown
from app.correlation.edges import run_correlation
from app.services.storage import restore_config
from test_correlation_score import alert, inputs, parent_child
from test_correlation_v3 import score, flow

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def cfg():
    return load_config(ROOT/'configs/algorithm-v4.yaml')


def test_missing_fields_excluded_but_observed_mismatch_counts(cfg):
    aa = [alert('a', host='h', rule_id='a'), alert('b', 1, host='h', rule_id='b')]
    missing, _ = score(aa, cfg)
    observed, _ = score([alert('a', host='h', rule_id='a', account='alice'),
                        alert('b', 1, host='h', rule_id='b', account='bob')], cfg)
    ev = missing.diagnostics['evidence_v2']
    assert 'entity.ACCOUNT' in ev['not_applicable_evidence']
    assert 'entity.ACCOUNT' in observed.diagnostics['evidence_v2']['mismatched_evidence']
    assert missing.score > observed.score
    # Adding unilateral optional evidence leaves score identical.
    unilateral, _ = score([alert('a', host='h', rule_id='a', account='alice'), aa[1]], cfg)
    assert unilateral.score == missing.score


def test_single_weak_fact_cannot_be_amplified(cfg):
    pair, _ = score([alert('a', src_ip='192.0.2.1'), alert('b', 1, src_ip='192.0.2.1')], cfg)
    assert not pair.valid and not pair.diagnostics['evidence_v2']['evidence_gate_passed']


def test_independent_host_resource_and_time_can_accept(cfg):
    aa = [alert('a', host='rare', file='/tmp/specific-artifact', rule_id='a'),
          alert('b', 1, host='rare', file='/tmp/specific-artifact', rule_id='b')]
    pair, scorer = score(aa, cfg)
    assert pair.valid and pair.score >= .65
    assert {'HOST_CONTEXT','RESOURCE_CONTEXT','TEMPORAL'} <= set(pair.diagnostics['evidence_v2']['evidence_families'])
    scorer.breakdown(pair)


def test_metadata_only_cannot_publish(cfg):
    aa = [alert('a', rule_id='same', signature='same'), alert('b', 1, rule_id='same', signature='same')]
    idx, settings = inputs(aa)
    result = run_correlation(idx.alerts.values(), (), idx.entities.values(), cfg, settings)
    assert result.candidates.pairs and not result.edges and result.record.is_complete


def test_hot_only_rejected_and_hot_plus_rare_evidence_eligible(cfg):
    aa = [alert('a', host='public', file='/tmp/specific-artifact', rule_id='a'),
          alert('b', 1, host='public', file='/tmp/specific-artifact', rule_id='b')]
    aa += [alert(str(i), i+10, host='public') for i in range(105)]
    supported, _ = score(aa, cfg)
    hot_only, _ = score([alert('a', host='public', rule_id='a'), alert('b', 1, host='public', rule_id='b')]+aa[2:], cfg)
    # Eligibility is separate from the formal score threshold. Hot context
    # stays supporting evidence, and cannot force a marginal pair over .65.
    assert not hot_only.valid and supported.valid and supported.score > hot_only.score
    assert any(r['hot'] for r in supported.diagnostics['evidence_v2']['entity_reliability'])
    assert any(f['family']=='RESOURCE_CONTEXT' and f['role']=='primary' for f in supported.diagnostics['evidence_v2']['evidence'])


def test_entity_consumed_by_flow_never_double_counted(cfg):
    pair, scorer = score(flow(), cfg)
    data = scorer.breakdown(pair).model_dump()
    ev = data['evidence_v2']
    assert 'entity.IP' in ev['suppressed_dimensions']
    assert 'entity.IP' not in ev['matched_evidence']
    ev['evidence'].append(deepcopy(ev['evidence'][0]))
    with pytest.raises(ValueError):
        ScoreBreakdown.model_validate(data)


def test_legal_lineage_candidate_retained(cfg):
    aa = parent_child()
    idx, settings = inputs(aa)
    result = run_correlation(idx.alerts.values(), (), idx.entities.values(), cfg, settings)
    assert len(result.candidates.pairs)==1 and len(result.edges)==1
    assert result.edges[0].score_breakdown.evidence_v2.relation_support == ['parent_child_process']


def test_score_order_and_restored_snapshot_deterministic(cfg):
    aa = parent_child()
    one, scorer = score(aa, cfg)
    two, other = score(list(reversed(aa)), restore_config(cfg.snapshot))
    assert one.score == two.score
    assert scorer.breakdown(one).canonical_json() == other.breakdown(two).canonical_json()


def test_zero_edges_keep_grounded_singletons(cfg):
    from app.chains.assembly import run_reconstruction
    aa = [alert('a'), alert('b', 86400)]
    idx, settings = inputs(aa)
    c = run_correlation(idx.alerts.values(), (), idx.entities.values(), cfg, settings)
    r = run_reconstruction(idx.alerts.values(), (), idx.entities.values(), c.edges, cfg, settings, upstream_record=c.record)
    assert not c.edges and len(r.incidents)==2 and r.grounding.valid


def test_slice_runner_refuses_validation_retry(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT/'scripts'))
    import correlation_v4_small as runner
    monkeypatch.setattr(runner, 'OUTPUT', tmp_path)
    with pytest.raises(ValueError, match='validation_requires_frozen_v4'):
        runner.run('validation', 'v3', 'validation')
    assert not (tmp_path/'validation').exists()


def test_started_validation_is_consumed_even_without_result(tmp_path, monkeypatch):
    import json
    sys.path.insert(0, str(ROOT/'scripts'))
    import correlation_v4_small as runner
    monkeypatch.setattr(runner, 'OUTPUT', tmp_path)
    monkeypatch.setattr(runner, 'implementation', lambda: {'synthetic': 'hash'})
    (tmp_path/'FREEZE_MANIFEST.json').write_text(json.dumps({
        'CORRELATION_V4_FROZEN':True, 'implementation':{'synthetic':'hash'}}))
    (tmp_path/'validation').mkdir()
    (tmp_path/'validation/STARTED.json').write_text('consumed')
    with pytest.raises(FileExistsError):
        runner.run('validation', 'v4', 'validation')
    assert (tmp_path/'validation/STARTED.json').read_text() == 'consumed'


def test_small_observer_exports_internal_tuple_diagnostics(cfg, tmp_path, monkeypatch):
    import json
    from app.services import bounded_diagnostics
    sys.path.insert(0, str(ROOT/'scripts'))
    import correlation_v4_small as runner
    monkeypatch.setattr(bounded_diagnostics, 'BoundedDiagnostics', runner.SmallObserver)
    aa = parent_child()+[alert('weak-a', 1, src_ip='192.0.2.1'), alert('weak-b', 2, src_ip='192.0.2.1')]
    idx, settings = inputs(aa)
    result = run_correlation(idx.alerts.values(), (), idx.entities.values(), cfg, settings, output_root=tmp_path)
    from app.services.storage import SnapshotStore
    store = SnapshotStore(tmp_path, result.record.analysis_id)
    store.read_metadata()
    audit = json.loads((store.details/'small_audit.json').read_text(encoding='utf8'))
    assert audit['score_distribution']['count'] == len(result.candidates.pairs)
    assert json.loads((store.details/'top_accepted_pairs.json').read_text(encoding='utf8'))
    assert json.loads((store.details/'top_rejected_pairs.json').read_text(encoding='utf8'))


def test_frozen_snapshot_replay_checks_candidates_and_evidence(cfg, tmp_path, monkeypatch):
    import json
    from app.services import bounded_diagnostics
    from app.services.storage import SnapshotStore, atomic_json
    from app.chains.assembly import run_reconstruction
    sys.path.insert(0, str(ROOT/'scripts'))
    import correlation_v4_small as runner
    monkeypatch.setattr(runner, 'OUTPUT', tmp_path)
    monkeypatch.setattr(bounded_diagnostics, 'BoundedDiagnostics', runner.SmallObserver)
    dest = tmp_path/'synthetic_dev'
    aa = parent_child()+[alert('weak-a', 1, src_ip='192.0.2.1'), alert('weak-b', 2, src_ip='192.0.2.1')]
    idx, settings = inputs(aa)
    c = run_correlation(idx.alerts.values(), (), idx.entities.values(), cfg, settings, output_root=dest)
    r = run_reconstruction(idx.alerts.values(), (), idx.entities.values(), c.edges, cfg, settings, upstream_record=c.record, output_root=dest)
    store = SnapshotStore(dest, c.record.analysis_id)
    observed = json.loads((store.details/'small_audit.json').read_text(encoding='utf8'))
    atomic_json(dest/'RESULT.json', {'role':'dev', 'correlation_analysis_id':c.record.analysis_id,
        'reconstruction_analysis_id':r.record.analysis_id, 'candidate_pair_count':len(c.candidates.pairs),
        'evidence_audit':observed['evidence_audit']})
    for name in ('accepted','rejected'):
        atomic_json(dest/f'top_{name}_pairs.json', json.loads((store.details/f'top_{name}_pairs.json').read_text(encoding='utf8')))
    runner.verify_dev_replay('synthetic_dev')
    assert json.loads((dest/'REPRODUCIBILITY.json').read_text(encoding='utf8'))['reverse_input_all_candidates_equal']
    import audit_correlation_v4_small as coverage
    monkeypatch.setattr(coverage, 'OUTPUT', tmp_path)
    audit = coverage.audit('synthetic_dev')
    assert audit['attested_relation_count'] > 0
    assert audit['omitted_audit_exhaustive_for_primary_superset']
    assert not audit['apparent_missed_formal_pairs']
