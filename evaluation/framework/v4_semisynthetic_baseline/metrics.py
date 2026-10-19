"""Pure post-hoc metrics; no production scoring or candidate calls."""
from bisect import bisect_left, bisect_right
from collections import defaultdict
from fractions import Fraction
import math


def pair_key(a, b):
    if a == b:
        raise ValueError('self_pair')
    return tuple(sorted((a, b)))


def recall(ids, total=6):
    if total != 6:
        raise ValueError('this controlled baseline requires exactly six GT edges')
    ids = sorted(set(ids))
    if len(ids) > total:
        raise ValueError('recall_numerator_exceeds_denominator')
    return {'numerator': len(ids), 'denominator': total, 'value': len(ids) / total,
            'gt_edge_ids': ids, 'status': 'available'}


def distribution(values):
    v = sorted(values)
    def q(p):
        if not v:
            return None
        x = (len(v) - 1) * p
        lo, hi = math.floor(x), math.ceil(x)
        return v[lo] + (v[hi] - v[lo]) * (x - lo)
    return {'count': len(v), 'min': v[0] if v else None, 'P25': q(.25),
            'median': q(.5), 'P75': q(.75), 'max': v[-1] if v else None,
            'mean': math.fsum(v) / len(v) if v else None,
            'status': 'available' if v else 'not_applicable'}


def ranking(scored, witnesses):
    """Score descending, full alert-ID tuple ascending; gate failures remain ranked.

    Missing candidates have no rank and zero reciprocal-rank/Top-K credit.
    Midrank CDF percentile is higher-is-better; tie bounds are disclosed.
    """
    ordered = sorted(scored, key=lambda p: (-scored[p], p))
    ranks = {p: i + 1 for i, p in enumerate(ordered)}
    values = sorted(scored.values())
    n = len(values)
    edges, pairs = {}, {}
    for edge, ws in sorted(witnesses.items()):
        present = [p for p in sorted(set(ws)) if p in ranks]
        for p in present:
            s = scored[p]
            lo, hi = bisect_left(values, s), bisect_right(values, s)
            pairs['|'.join(p)] = {'pair': list(p), 'score': s, 'rank': ranks[p],
                'rank_min': n - hi + 1, 'rank_max': n - lo,
                'percentile': 100 * (lo + .5 * (hi - lo)) / n}
        best = min(present, key=lambda p: ranks[p]) if present else None
        edges[edge] = {'best_pair': list(best) if best else None,
            **(pairs['|'.join(best)] if best else {'score': None, 'rank': None, 'percentile': None}),
            'reciprocal_rank': 1 / ranks[best] if best else 0.,
            'scored_witness_count': len(present)}
    all_pairs = set().union(*(set(v) for v in witnesses.values()))
    return {'population': n, 'rank_scope': 'all computed original-member pair scores, including evidence gate/hard-guard rejects',
        'order': 'unrounded score DESC, sorted full alert ID pair ASC',
        'percentile_definition': '100*(count(lower)+0.5*count(equal))/N; higher is better',
        'mrr_definition': 'mean reciprocal global rank of first correct witness per GT edge; missing=0',
        'MRR': math.fsum(e['reciprocal_rank'] for e in edges.values()) / len(edges) if edges else None,
        'edges': edges, 'pairs': list(pairs.values()), 'top_k': {
            str(k): {'edge_hits': sum(e['rank'] is not None and e['rank'] <= k for e in edges.values()),
                     'edge_denominator': len(edges),
                     'edge_recall': sum(e['rank'] is not None and e['rank'] <= k for e in edges.values()) / len(edges) if edges else None,
                     'pair_hits': sum(p in ranks and ranks[p] <= k for p in all_pairs),
                     'pair_denominator': len(all_pairs),
                     'pair_recall': sum(p in ranks and ranks[p] <= k for p in all_pairs) / len(all_pairs) if all_pairs else None}
            for k in (10, 50, 100, 500, 1000)}}


def separation(positive, negative):
    """Empirical probability positive > negative, ties half; no unlabeled FPR."""
    negatives = sorted(negative)
    if not positive or not negatives:
        return {'status': 'not_applicable', 'pairwise_order_probability': None}
    mass = math.fsum(bisect_left(negatives, s) + .5 *
        (bisect_right(negatives, s) - bisect_left(negatives, s)) for s in positive)
    return {'status': 'available', 'pairwise_order_probability': mass / (len(positive) * len(negative)),
            'strict_nonoverlap': min(positive) > max(negatives),
            'positive_count': len(positive), 'negative_count': len(negative)}


def population(pair, positives, negatives, hard_alerts, background_alerts):
    if pair in positives and pair in negatives:
        raise ValueError('positive_negative_label_conflict')
    if pair in positives:
        return 'gt_positive'
    if pair in negatives:
        return 'explicit_hard_negative'
    if set(pair) & hard_alerts:
        return 'hard_negative_touching_unknown'
    if set(pair) <= background_alerts:
        return 'background_unknown'
    return 'other_unknown'


def correct_correlation_witness(edge, witnesses):
    support = edge['support_pair']
    return pair_key(support['alert_id_src'], support['alert_id_dst']) in witnesses


def directed_chain_hit(edge, nodes, source_alerts, target_alerts, witness_pairs):
    """Direction and actual support must both match; time order cannot substitute."""
    left, right = nodes[edge['source_node_id']], nodes[edge['target_node_id']]
    if not set(left['alert_ids']) & source_alerts or not set(right['alert_ids']) & target_alerts:
        return False
    support_ids = set(edge['alert_ids'])
    return any(set(p) <= support_ids and (p[0] in source_alerts and p[1] in target_alerts
        or p[1] in source_alerts and p[0] in target_alerts) for p in witness_pairs)


def stable_match(legal):
    """Maximum exact rational weight, then lexicographically smallest pair list.

    Seven GT nodes permit exact mask DP without numeric epsilon tie breaking.
    Nonempty weights must be positive. Pairs absent from legal are never matched.
    """
    targets = {g: i for i, g in enumerate(sorted({g for _, g in legal}))}
    by_pred = defaultdict(list)
    for (p, g), w in legal.items():
        if w <= 0:
            raise ValueError('matching_requires_positive_weights')
        by_pred[p].append((g, Fraction(w)))
    states = {0: (Fraction(0), ())}
    for p in sorted(by_pred):
        next_states = dict(states)
        for mask, (total, pairs) in states.items():
            for g, weight in sorted(by_pred[p]):
                bit = 1 << targets[g]
                if mask & bit:
                    continue
                proposal = (total + weight, pairs + ((p, g),))
                prior = next_states.get(mask | bit)
                if prior is None or proposal[0] > prior[0] or proposal[0] == prior[0] and proposal[1] < prior[1]:
                    next_states[mask | bit] = proposal
        states = next_states
    best = min(states.values(), key=lambda x: (-x[0], x[1]))
    return list(best[1])


def chain_metrics(nodes, recovered_edges):
    """Strict, directed GT subgraph. Isolated GT nodes remain components."""
    ids = sorted(nodes)
    children, undirected = defaultdict(set), defaultdict(set)
    for a, b in set(recovered_edges):
        if a not in nodes or b not in nodes:
            raise ValueError('chain_endpoint_not_gt_node')
        children[a].add(b)
        undirected[a].add(b)
        undirected[b].add(a)
    memo, visiting = {}, set()
    def longest(n):
        if n in visiting:
            raise ValueError('GT_subgraph_must_be_DAG')
        if n not in memo:
            visiting.add(n)
            memo[n] = max((1 + longest(c) for c in children[n]), default=0)
            visiting.remove(n)
        return memo[n]
    path = max((longest(n) for n in ids), default=0)
    seen, components = set(), []
    for n in ids:
        if n in seen:
            continue
        queue, component = [n], set()
        while queue:
            item = queue.pop()
            if item in component:
                continue
            component.add(item)
            queue.extend(undirected[item] - component)
        seen.update(component)
        components.append(sorted(component))
    return {'longest_path_edges': path, 'connected_components': len(components), 'components': components}
