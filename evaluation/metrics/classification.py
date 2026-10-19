"""Frozen count/denominator policy. Unlabelled pairs are excluded."""


def binary_metrics(tp, fp, tn, fn):
    values = (tp, fp, tn, fn)
    if any(type(v) is not int or v < 0 for v in values):
        raise ValueError("counts_must_be_nonnegative_integers")
    denominators = {"precision": tp + fp, "recall": tp + fn, "f1": 2 * tp + fp + fn}
    numerators = {"precision": tp, "recall": tp, "f1": 2 * tp}
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            **{k: numerators[k] / d if d else None for k, d in denominators.items()},
            "metric_status": {k: "available" if d else "not_applicable" for k, d in denominators.items()},
            "denominators": denominators, "zero_division_policy": "null+not_applicable"}


def unavailable_quality(reason="alert_pair_ground_truth_unavailable"):
    return {"tp": None, "fp": None, "tn": None, "fn": None, "precision": None, "recall": None, "f1": None,
            "metric_status": {k: "unavailable" for k in ("tp", "fp", "tn", "fn", "precision", "recall", "f1")},
            "evaluation_coverage": 0.0, "reason": reason, "zero_division_policy": "null+not_applicable"}


def evaluate_pairs(predicted, labelled):
    """Generic explicit pair-label contract, not inferred from attack windows."""
    predictions = {tuple(sorted(p)) for p in predicted}
    labels = {}
    for left, right, positive in labelled:
        if left == right or type(positive) is not bool:
            raise ValueError("invalid_pair_label")
        key = tuple(sorted((left, right)))
        if key in labels and labels[key] != positive:
            raise ValueError("ambiguous_pair_label")
        labels[key] = positive
    tp = sum(y and p in predictions for p, y in labels.items())
    fp = sum(not y and p in predictions for p, y in labels.items())
    tn = sum(not y and p not in predictions for p, y in labels.items())
    fn = sum(y and p not in predictions for p, y in labels.items())
    return {**binary_metrics(tp, fp, tn, fn), "labelled_pair_count": len(labels),
            "unlabelled_predictions_excluded": len(predictions - labels.keys())}


def candidate_metrics(positive_pairs, dispositions):
    """Dispositions must come from audited admission; absence is not pruning."""
    positives = {tuple(sorted(p)) for p in positive_pairs}
    allowed = {"admitted", "policy_pruned", "resource_truncated", "not_potential", "unknown"}
    counts = dict.fromkeys(sorted(allowed), 0)
    for p in positives:
        state = dispositions.get(p, "unknown")
        if state not in allowed:
            raise ValueError("invalid_candidate_disposition")
        counts[state] += 1
    # resource-truncated is admitted to policy, but did not reach scoring.
    recall = (counts["admitted"] + counts["resource_truncated"]) / len(positives) if positives and not counts["unknown"] else None
    return {"gt_positive_pairs": len(positives), **counts, "candidate_recall": recall,
            "candidate_miss_count": len(positives) - counts["admitted"] - counts["resource_truncated"] if not counts["unknown"] else None,
            "status": "unavailable" if counts["unknown"] else "available" if positives else "not_applicable"}


def ranking_curves(scores, labels):
    """Tie-aware exact PR/AP and ROC/AUC for explicitly labelled scored pairs."""
    import math
    if len(scores) != len(labels) or any(type(v) is not bool for v in labels) or any(not math.isfinite(s) for s in scores):
        raise ValueError("invalid_ranking_input")
    positive, negative = sum(labels), len(labels) - sum(labels)
    if not positive or not negative:
        return {"status": "not_applicable", "reason": "both_label_classes_required", "average_precision": None, "roc_auc": None,
                "pr_curve": [], "roc_curve": []}
    ordered = sorted(zip(scores, labels), reverse=True)
    tp = fp = 0
    ap = auc = previous_recall = previous_tpr = previous_fpr = 0.0
    pr, roc = [], [{"threshold": None, "tpr": 0.0, "fpr": 0.0}]
    i = 0
    while i < len(ordered):
        threshold = ordered[i][0]
        while i < len(ordered) and ordered[i][0] == threshold:
            tp += ordered[i][1]
            fp += not ordered[i][1]
            i += 1
        recall, precision, fpr = tp / positive, tp / (tp + fp), fp / negative
        ap += (recall - previous_recall) * precision
        auc += (fpr - previous_fpr) * (recall + previous_tpr) / 2
        previous_recall = previous_tpr = recall
        previous_fpr = fpr
        pr.append({"threshold": threshold, "precision": precision, "recall": recall})
        roc.append({"threshold": threshold, "tpr": recall, "fpr": fpr})
    return {"status": "available", "average_precision": ap, "roc_auc": auc, "pr_curve": pr, "roc_curve": roc,
            "scope": "explicitly_labelled_scored_pairs_only; candidate omissions must separately count as FN"}
