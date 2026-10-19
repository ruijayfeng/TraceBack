"""Tie-aware ranking and threshold metrics, with explicit missing denominators."""
from bisect import bisect_left, bisect_right
from collections import defaultdict
import math


def ratio(n, d):
    return n / d if d else None


def distribution(values):
    v = sorted(values)
    def q(p):
        if not v:
            return None
        x = (len(v) - 1) * p
        a, b = math.floor(x), math.ceil(x)
        return v[a] + (v[b] - v[a]) * (x - a)
    mean = ratio(math.fsum(v), len(v))
    return dict(count=len(v), min=q(0), p05=q(.05), p25=q(.25), median=q(.5),
                p75=q(.75), p95=q(.95), max=q(1), mean=mean,
                std=math.sqrt(math.fsum((x-mean)**2 for x in v)/len(v)) if v else None,
                std_definition='population', status='available' if v else 'not_applicable')


def ranking_metrics(positive, negative):
    """AUC groups ties; AP uses the precision after the complete tied block."""
    p, n = len(positive), len(negative)
    if not p or not n:
        return dict(ROC_AUC=None, PR_AUC=None, Average_Precision=None,
                    status='not_applicable', positive_count=p, negative_count=n)
    neg = sorted(negative)
    auc = math.fsum(bisect_left(neg, s) + .5*(bisect_right(neg, s)-bisect_left(neg, s))
                    for s in positive)/(p*n)
    blocks = defaultdict(lambda: [0, 0])
    for s in positive:
        blocks[s][0] += 1
    for s in negative:
        blocks[s][1] += 1
    tp = fp = 0
    last_r, last_p, area, ap = 0., 1., 0., 0.
    for s in sorted(blocks, reverse=True):
        a, b = blocks[s]
        tp += a
        fp += b
        recall, precision = tp/p, tp/(tp+fp)
        area += (recall-last_r)*(precision+last_p)/2
        ap += (recall-last_r)*precision
        last_r, last_p = recall, precision
    return dict(ROC_AUC=auc, PR_AUC=area, Average_Precision=ap, status='available',
                positive_count=p, negative_count=n, PR_AUC_definition='trapezoidal grouped PR curve',
                AP_definition='noninterpolated grouped recall increments times precision')


def longest_path(edges):
    children = defaultdict(set)
    nodes = set()
    for a, b in edges:
        children[a].add(b)
        nodes.update((a, b))
    visiting, cache = set(), {}
    def length(a):
        if a in visiting:
            raise ValueError('cyclic_GT')
        if a not in cache:
            visiting.add(a)
            cache[a] = max((1 + length(b) for b in children[a]), default=0)
            visiting.remove(a)
        return cache[a]
    return max((length(a) for a in nodes), default=0)


def classification(tp, fp, total=6):
    return dict(GT_TP=tp, GT_FN=total-tp, FP=fp, precision=ratio(tp, tp+fp),
                recall=ratio(tp, total), F1=ratio(2*tp, total+tp+fp))


def pareto(rows):
    def dominates(a, b):
        # An undefined precision from zero admissions confers no advantage.
        x = (a['precision'] or 0, a['recall'], a['chain_completeness'], -a['FP'])
        y = (b['precision'] or 0, b['recall'], b['chain_completeness'], -b['FP'])
        return all(i >= j for i, j in zip(x, y)) and any(i > j for i, j in zip(x, y))
    return [r for r in rows if not any(dominates(a, r) for a in rows)]


def choose(rows):
    """Declared hierarchy; this nominates a diagnostic point, never production."""
    return max(rows, key=lambda r: (r['GT_TP'], r['correlation_GT_longest_path_proxy'],
                -r['FP'], -r['unlabeled_admitted'], -r['total_admitted_edges'], r['threshold']))

