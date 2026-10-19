"""Auditable finite-grid metrics; missing scores are never filled with zero."""
import bisect
import math


def quantile(values, p):
    if not values:
        return None
    position = (len(values)-1)*p
    lo = int(position)
    hi = min(lo+1, len(values)-1)
    return values[lo]*(hi-position) + values[hi]*(position-lo) if hi != lo else values[lo]


def distribution(values, admitted, *, total=None):
    values = sorted(v for v in values if v is not None)
    total = len(values) if total is None else total
    bins = [0]*10
    for value in values:
        bins[min(9, int(value*10))] += 1
    result = dict(count=total, scored_count=len(values), unscored_count=total-len(values),
                  admitted_count=admitted, admission_rate=admitted/total if total else None,
                  min=values[0] if values else None, max=values[-1] if values else None,
                  buckets={f'{i/10:.2f}-{(i+1)/10:.2f}': n for i, n in enumerate(bins)})
    for label, p in [('p05', .05), ('p25', .25), ('median', .5), ('p75', .75),
                     ('p90', .9), ('p95', .95), ('p99', .99)]:
        result[label] = quantile(values, p)
    return result


class ThresholdCounts:
    def __init__(self, thresholds, metrics):
        self.thresholds = thresholds
        self.differences = {m: [0]*(len(thresholds)+1) for m in metrics}

    def add(self, score, metrics):
        if score is None:
            return
        k = bisect.bisect_right(self.thresholds, score)
        if k:
            for metric in metrics:
                a = self.differences[metric]
                a[0] += 1
                a[k] -= 1

    def rows(self):
        running = dict.fromkeys(self.differences, 0)
        result = []
        for i, t in enumerate(self.thresholds):
            for name in running:
                running[name] += self.differences[name][i]
            result.append(dict(threshold=t, **running))
        return result


def choose(rows, *, gt_total, hn_total, baseline_total, config):
    eligible = [r for r in rows if r['gt_admitted'] >= min(gt_total, config['minimum_gt_admitted'])
                and r['hn_admitted'] <= min(hn_total, config['maximum_hn_admitted'])
                and r['total_admitted'] <= baseline_total*config['maximum_total_admitted_ratio']]
    if not eligible:
        return None
    complexity = {'global': 0, 'contradiction_gate': 1, 'mass_floor': 2,
                  'strong_anchor': 3, 'evidence_class': 4}
    return min(eligible, key=lambda r: (r['hn_admitted'], gt_total-r['gt_admitted'],
               complexity[r['policy']], abs(r['threshold']-.65), r['total_admitted'], r['model']))


def frontier(rows):
    # GT/HN exposure and edge-volume tradeoff, not unlabelled precision.
    distinct = {}
    for r in rows:
        key = (r['gt_admitted'], r['hn_admitted'], r['total_admitted'])
        distinct.setdefault(key, r)
    values = list(distinct.values())
    return [r for r in values if not any(
        x['gt_admitted'] >= r['gt_admitted'] and x['hn_admitted'] <= r['hn_admitted']
        and x['total_admitted'] <= r['total_admitted'] and
        (x['gt_admitted'], x['hn_admitted'], x['total_admitted']) !=
        (r['gt_admitted'], r['hn_admitted'], r['total_admitted']) for x in values)]
