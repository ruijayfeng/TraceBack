"""Integration boundary, unchanged scoring, immutable artifact and evidence tests."""
import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from evaluation.framework.preformula_baseline import ROOT, OUT, VERSION, IDENTITY
from evaluation.framework.preformula_baseline import boundary
from evaluation.framework.preformula_baseline.boundary import development_config, verify_current
from evaluation.framework.preformula_baseline.snapshot import card, evidence_state
from evaluation.framework.v4_semisynthetic_baseline.common import read, save, sha


def test_explicit_identity_changes_run_version_and_hash_but_preserves_v4_snapshot():
    from app.correlation.edges import correlation_version
    from app.services.storage import restore_config
    historical = read(ROOT/'outputs/v5_preformula_candidate_recovery/preparation.json')['algorithm']
    old = restore_config(historical)
    new, receipt, _ = development_config()
    assert old.algorithm.version == new.algorithm.version == 'v4'
    assert correlation_version(new) == VERSION != correlation_version(old)
    assert new.config_hash != old.config_hash
    assert new.mapping_digest == old.mapping_digest
    snapshot = new.snapshot
    assert snapshot.pop('implementation_version') == IDENTITY
    assert snapshot == historical
    assert new.algorithm.score.correlation_threshold == .65
    assert restore_config(new.snapshot).config_hash == new.config_hash
    assert receipt['baseline_name'] == 'V5_PRE_FORMULA_BASELINE'


def test_old_snapshot_hash_and_serialization_are_unchanged():
    from app.services.storage import restore_config
    frozen = read(ROOT/'outputs/correlation_v4_small/FREEZE_MANIFEST.json')
    config = restore_config(frozen['algorithm_snapshot'])
    assert config.config_hash == '4b3f963cb482126aca41614242bb1e188ab7ddb21463a4996ea56b42379a1d73'
    assert config.snapshot == frozen['algorithm_snapshot']
    assert 'implementation_version' not in config.snapshot


@pytest.mark.parametrize('changes', [{'version':'v0'}, {'implementation_version':'v5'},
    {'score_threshold': .64}])
def test_invalid_version_and_threshold_do_not_enter_preformula(changes):
    from app.services.storage import restore_config
    changes = dict(changes)
    snapshot = development_config()[0].snapshot
    threshold = changes.pop('score_threshold', None)
    snapshot.update(changes)
    if threshold is not None: snapshot['score']['correlation_threshold'] = threshold
    with pytest.raises(ValidationError): restore_config(snapshot)


def test_strict_historical_executor_still_rejects_current_implementation():
    import sys
    sys.path.insert(0,str(ROOT/'scripts'))
    from cptc_2018_step3a import load_frozen_config
    with pytest.raises(ValueError, match='frozen_correlation_implementation_changed'):
        load_frozen_config()


def test_identical_scoring_and_decisions_across_identity_boundary():
    from app.correlation.scoring import CorrelationScorer
    from app.services.storage import restore_config
    from test_correlation_score import parent_child, inputs
    index, settings = inputs(parent_child())
    new = development_config()[0]
    snap = new.snapshot
    snap.pop('implementation_version')
    old = restore_config(snap)
    pair = sorted(index.alerts)
    a = CorrelationScorer(index, old, settings).score_pair(*pair)
    b = CorrelationScorer(index, new, settings).score_pair(*pair)
    assert (a.score,a.raw_total,a.valid,a.values,a.contributions,a.rejection_codes) == (
        b.score,b.raw_total,b.valid,b.values,b.contributions,b.rejection_codes)
    assert a.diagnostics == b.diagnostics
    assert [r.model_dump() for r in a.reasons] == [r.model_dump() for r in b.reasons]


def test_active_receipt_rejects_mutated_source_without_rewriting_hash(tmp_path,monkeypatch):
    monkeypatch.setattr(boundary,'ROOT',tmp_path)
    monkeypatch.setattr(boundary,'OUT',tmp_path)
    source = tmp_path/'backend/app/current.py'
    source.parent.mkdir(parents=True)
    source.write_text('original',encoding='utf8')
    save(tmp_path/'freeze_receipt.json', {'baseline_name':'V5_PRE_FORMULA_BASELINE',
        'implementation_file_hashes':{'backend/app/current.py':sha(source)},
        'configuration_file_hashes':{},'mapping_hashes':{}})
    receipt_before = sha(tmp_path/'freeze_receipt.json')
    verify_current()
    source.write_text('mutated',encoding='utf8')
    with pytest.raises(ValueError,match='current_preformula_baseline_changed'): verify_current()
    assert sha(tmp_path/'freeze_receipt.json') == receipt_before
    source.write_text('original',encoding='utf8')
    (source.parent/'unrecorded.py').write_text('extra',encoding='utf8')
    with pytest.raises(ValueError,match='file_set_changed'): verify_current()


def test_historical_attestation_is_distinct_from_current_bytes_and_detects_tampering(tmp_path,monkeypatch):
    monkeypatch.setattr(boundary,'ROOT',tmp_path)
    monkeypatch.setattr(boundary,'OUT',tmp_path)
    expected = {'backend/old.py':'a'*64}
    save(tmp_path/'old_inventory.json',expected)
    save(tmp_path/'integration_before.json', {'historical_files':{'old_inventory.json':sha(tmp_path/'old_inventory.json')},
        'historical_identities':{'backend/old.py':['a'*64]}})
    result = boundary.verify_historical_inventory(expected,anchor=tmp_path/'old_inventory.json')
    assert result['status'] == 'PASS' and result['historical_source_identity_attestations'] == 1
    assert result['historical_source_reexecution_verified'] is False
    with pytest.raises(ValueError,match='unattested_historical_identity'):
        boundary.verify_historical_inventory({'backend/old.py':'b'*64})
    save(tmp_path/'old_inventory.json',{'backend/old.py':'b'*64})
    with pytest.raises(ValueError,match='historical_inventory_changed'):
        boundary.verify_historical_inventory(expected,anchor=tmp_path/'old_inventory.json')


@pytest.mark.parametrize('state,strength,expected',[
    ('UNAVAILABLE',0,'UNAVAILABLE'),('NOT_APPLICABLE',0,'NOT_APPLICABLE'),
    ('AVAILABLE_MISMATCH',0,'OBSERVED_ZERO'),('AVAILABLE_MATCH',0,'OBSERVED_ZERO'),
    ('AVAILABLE_MATCH',.5,'OBSERVED_POSITIVE')])
def test_zero_and_missing_do_not_become_contradictions(state,strength,expected):
    assert evidence_state({'state':state,'strength':strength}) == expected


def test_saved_score_decomposition_recomputes_and_rejects_tampered_total():
    from app.correlation.scoring import CorrelationScorer
    from test_correlation_score import parent_child, inputs
    idx,settings = inputs(parent_child())
    cfg = development_config()[0]
    scorer = CorrelationScorer(idx,cfg,settings)
    ids = sorted(idx.alerts)
    pair = scorer.score_pair(*ids)
    row = {'support_pair':ids,'values':pair.values,'contributions':pair.contributions,'evidence':pair.diagnostics,
        'raw_total':pair.raw_total,'score':pair.score,'source_independence':pair.source_independence,
        'valid':pair.valid,'rejection_codes':pair.rejection_codes}
    alerts = {a:idx.alerts[a].model_dump(mode='json') for a in ids}
    entities = {e:v.model_dump(mode='json') for e,v in idx.entities.items()}
    c = card(row,{},alerts,entities,cfg.snapshot,1,'synthetic')
    assert c['formula_recomputed_raw_total'] == pytest.approx(pair.raw_total,abs=1e-12)
    assert c['final_score'] == pair.score
    row['raw_total'] += .1
    with pytest.raises(ValueError,match='does_not_recompute'):
        card(row,{},alerts,entities,cfg.snapshot,1,'synthetic')


def test_evaluation_fails_seal_before_any_truth_adapter_read(monkeypatch):
    from evaluation.framework.preformula_baseline import snapshot
    def fail(): raise ValueError('synthetic_seal_failure')
    monkeypatch.setattr(snapshot,'seal',fail)
    with pytest.raises(ValueError,match='synthetic_seal_failure'): snapshot.evaluate()


def test_guard_audit_keeps_cache_attempts_and_blocks_unknown_reads(tmp_path):
    import sys
    from evaluation.framework.preformula_baseline.guard_audit import audit_guard
    source = tmp_path/'alerts.jsonl'
    cache = Path(sys.base_prefix)/'Lib/sqlite3/__pycache__/__init__.cpython-311.pyc.12345'
    event = {'event':'open','path':str(cache),'rejected':True}
    guard = {'ground_truth_loaded':False,'non_code_reads':[str(source)],'rejected_events':[event]}
    result = audit_guard(guard,source)
    assert result['status'] == 'PASS'
    assert result['blocked_bytecode_cache_attempts'] == [event]
    assert result['receipt_records_open_flags'] is False
    guard['rejected_events'].append({'event':'open','path':str(tmp_path/'ground_truth.json'),'rejected':True})
    assert audit_guard(guard,source)['status'] == 'FAIL'
    guard['rejected_events'] = [event]
    guard['non_code_reads'].append(str(tmp_path/'ground_truth.json'))
    assert audit_guard(guard,source)['status'] == 'FAIL'
    guard['non_code_reads'] = [str(source)]
    guard['ground_truth_loaded'] = True
    assert audit_guard(guard,source)['status'] == 'FAIL'
