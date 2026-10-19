"""Score-seal ordering and exact full-dataset calibration invariants."""
import json
from pathlib import Path
import pytest
from evaluation.framework.semantics_final import OUT
from evaluation.framework.semantics_final import evaluate

def test_truth_blocked_before_seal(monkeypatch):
    from evaluation.framework.formula_repair import evaluate as old
    reads=[]
    monkeypatch.setattr(evaluate,'verify_seal',lambda:(_ for _ in ()).throw(ValueError('not_sealed')))
    monkeypatch.setattr(old,'save',lambda *a:reads.append(a))
    with pytest.raises(ValueError,match='not_sealed'):evaluate.labels({})
    assert not reads

def test_delivered_distribution_and_sweep_are_complete():
    if not (OUT/'calibration.json').exists():pytest.skip('post-seal artifact not yet produced')
    c=json.loads((OUT/'calibration.json').read_text(encoding='utf8'))
    rows=c['threshold_sweep']
    assert [r['threshold'] for r in rows]==sorted(set(r['threshold'] for r in rows))
    for field in ('GT_TP','Hard_Negative_FP','total_admitted_edges','background_admitted_edges'):
        values=[r[field] for r in rows];assert values==sorted(values,reverse=True)
    assert all(r['Hard_Negative_FP']+r['Hard_Negative_TN']==30 for r in rows)
    assert all(r['GT_TP']+r['GT_FN']==6 for r in rows)
    negatives=json.loads((OUT/'hard_negative_scores.json').read_text(encoding='utf8'))
    assert len(negatives['alerts'])==30 and negatives['explicit_negative_total']==630
    d=json.loads((OUT/'blind_score_distribution.json').read_text(encoding='utf8'))
    assert sum(r['count'] for r in d['histogram'])==d['scored_count']

def test_historical_seals_still_match_and_new_source_is_frozen():
    from evaluation.framework.semantics_final.runtime import verify_freeze
    frozen=verify_freeze()
    assert frozen['formula_revision_count']==1 and frozen['weights_changed'] is False
    # No old seal is claimed to authorize changed source; its bytes remain frozen.
    from evaluation.framework.formula_design.runtime import read,sha
    for p,h in read(OUT/'historical_before.json')['protected_files'].items():
        if p.endswith(('score_seal.json','blind_run_manifest.json','scored_seal.json')):
            assert sha(Path(p))==h


def test_actual_downstream_has_grounded_storage_and_no_post_truth_rescoring():
    path=OUT/'chain_validation.json'
    if not path.exists():pytest.skip('actual downstream replay not yet produced')
    chain=json.loads(path.read_text(encoding='utf8'))
    guard=json.loads((OUT/'downstream/guard_receipt.json').read_text(encoding='utf8'))
    assert chain['actual_reconstruction_executed']
    assert chain['all_tables_roundtrip'] and chain['grounding_valid']
    assert chain['production_formula_rescoring_calls']==guard['production_formula_rescoring_calls']==0
    assert guard['ground_truth_loaded'] is False and guard['t2_read'] is False
    assert guard['rejected_events']==[]
    assert chain['Longest_GT_path_recovered']<=chain['ChainEdges_recovered']<=chain['CorrelationEdges_recovered']<=6
    assert len(chain['failures'])==6
    assert chain['GT_NODES_RECOVERED'] is None  # no frozen stage/category matching contract
    c=json.loads((OUT/'calibration.json').read_text(encoding='utf8'))
    for row in c['threshold_sweep']:
        assert all(isinstance(row[k],int) and row[k]>=0 for k in
                   ('multi_alert_incidents','chain_edges','longest_chain','GT_chain_edges','GT_longest_path'))
        assert row['GT_longest_path']<=row['GT_chain_edges']<=row['GT_TP']
