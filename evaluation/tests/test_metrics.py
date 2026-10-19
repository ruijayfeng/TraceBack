import pytest

from evaluation.metrics.classification import binary_metrics, candidate_metrics, evaluate_pairs, ranking_curves


@pytest.mark.parametrize("counts,expected", [((2,0,3,0),(1,1,1)), ((0,0,3,2),(None,0,0)),
    ((2,3,0,0),(.4,1,4/7)), ((0,0,3,0),(None,None,None)), ((0,2,0,0),(0,None,0))])
def test_binary_metric_extremes(counts, expected):
    m = binary_metrics(*counts)
    assert (m["precision"], m["recall"], m["f1"]) == expected
    for k in ("precision", "recall", "f1"):
        assert m["metric_status"][k] == ("not_applicable" if m[k] is None else "available")


def test_missing_candidate_positive_counts_fn_and_unlabelled_excluded():
    m = evaluate_pairs([("a","b"), ("u","v")], [("a","b",True),("a","c",True),("b","c",False)])
    assert (m["tp"],m["fp"],m["tn"],m["fn"]) == (1,0,1,1)
    assert m["unlabelled_predictions_excluded"] == 1
    with pytest.raises(ValueError, match="ambiguous"):
        evaluate_pairs([], [("a","b",True),("b","a",False)])


def test_candidate_policy_resource_and_unknown_are_distinct():
    pairs = [("a","b"),("a","c"),("a","d")]
    m = candidate_metrics(pairs, dict(zip(pairs, ["admitted","policy_pruned","resource_truncated"])))
    assert m["candidate_recall"] == 2/3 and m["candidate_miss_count"] == 1
    assert m["resource_truncated"] == m["policy_pruned"] == 1
    missing = candidate_metrics(pairs, {})
    assert missing["candidate_recall"] is None and missing["unknown"] == 3


def test_curves_perfect_ties_and_missing_classes():
    assert ranking_curves([1,.9,.2,.1],[True,True,False,False])["roc_auc"] == 1
    tied = ranking_curves([.5,.5],[True,False])
    assert tied["roc_auc"] == tied["average_precision"] == .5
    assert ranking_curves([.1],[False])["status"] == "not_applicable"
    with pytest.raises(ValueError):
        binary_metrics(-1,0,0,0)
