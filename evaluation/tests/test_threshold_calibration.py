import math
import pytest

from evaluation.framework.threshold_calibration.metrics import (
    ranking_metrics, classification, distribution, longest_path, choose, pareto)


def test_ranking_perfect_reversed_and_tied_blocks():
    perfect=ranking_metrics([.8,.9],[.1,.2])
    assert perfect['ROC_AUC']==perfect['PR_AUC']==perfect['Average_Precision']==1
    assert ranking_metrics([.1],[.9])['ROC_AUC']==0
    tied=ranking_metrics([.5],[.5])
    assert tied['ROC_AUC']==.5
    assert tied['Average_Precision']==.5
    assert tied['PR_AUC']==.75


def test_empty_denominators_and_missing_scores_are_not_zero_imputed():
    assert ranking_metrics([.5],[])['ROC_AUC'] is None
    assert classification(0,0)['precision'] is None
    assert classification(0,0)['recall']==0
    assert distribution([])['mean'] is None
    assert distribution([0,1])['std']==.5


def test_GT_path_is_contiguous_and_directed():
    assert longest_path([('a','b'),('c','d')])==1
    assert longest_path([('a','b'),('b','c'),('c','d')])==3
    with pytest.raises(ValueError,match='cyclic'):
        longest_path([('a','b'),('b','a')])


def test_exact_boundary_does_not_round_away_an_admission():
    score=.3074976783886427
    assert score>=score
    assert not score>=math.nextafter(score,math.inf)
    assert score<round(score,6)


def test_selection_respects_recovery_then_negative_control_then_conservatism():
    def r(t,tp,fp,unlabelled):
        return dict(threshold=t,GT_TP=tp,FP=fp,unlabeled_admitted=unlabelled,
                    total_admitted_edges=tp+fp+unlabelled,correlation_GT_longest_path_proxy=tp)
    assert choose([r(.3,5,5,10),r(.4,5,4,10),r(.41,5,4,10),r(.8,1,0,0)])['threshold']==.41


def test_undefined_precision_does_not_dominate_positive_recovery():
    a=dict(threshold=.8,precision=None,recall=0,chain_completeness=0,FP=0)
    b=dict(threshold=.4,precision=.5,recall=.5,chain_completeness=0,FP=1)
    assert pareto([a,b])==[a,b]


def test_truth_loader_cannot_run_before_score_seal(monkeypatch):
    from evaluation.framework.threshold_calibration import runner
    reads=[]
    monkeypatch.setattr(runner,'verify_score_seal',lambda:(_ for _ in ()).throw(ValueError('unsealed')))
    monkeypatch.setattr(runner,'save',lambda *args:reads.append(args))
    with pytest.raises(ValueError,match='unsealed'):
        runner.load_labels({})
    assert reads==[]


def test_frozen_sweep_monotonicity_gate_ceiling_and_real_downstream_result():
    """Integration on delivered predictions; no scorer or GT reader invoked."""
    import csv
    import json
    from evaluation.framework.threshold_calibration import OUT
    metrics=list(csv.DictReader((OUT/'threshold_metrics.csv').open(encoding='utf8',newline='')))
    thresholds=[float(r['threshold']) for r in metrics]
    volumes=[int(r['total_admitted_edges']) for r in metrics]
    recovered=[int(r['GT_TP']) for r in metrics]
    assert thresholds==sorted(set(thresholds))
    assert volumes==sorted(volumes,reverse=True)
    assert recovered==sorted(recovered,reverse=True)
    assert max(recovered)==5
    historical=next(r for r in metrics if float(r['threshold'])==.65)
    assert int(historical['total_admitted_edges'])==0
    assert historical['precision']==''  # Empty denominator is null, never 0/1.
    actual=json.loads((OUT/'downstream_final/summary.json').read_text(encoding='utf8'))
    assert actual['production_scorer_calls']==0 and actual['grounding']['valid']
    assert actual['chain_edge_count']==0 and actual['max_incident_representatives']==1
    assert actual['F2_max_score']<.70

