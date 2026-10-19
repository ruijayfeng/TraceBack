"""Labels are joined only after verifying all numeric research predictions."""
import collections
import csv
import gzip
import hashlib
import heapq
import itertools
import json
import re
from . import ROOT, BASE, OUT
from .snapshot import read, save, sha
from .replay import rows
from .statistics import distribution, ThresholdCounts, choose, frontier


def pairkey(a, b):
    return tuple(sorted((a, b)))


def verify_seal():
    seal = read(OUT / 'prediction_seal.json')
    if seal['status'] != 'SEALED' or seal['ground_truth_loaded']:
        raise ValueError('unsealed_predictions')
    for name, expected in seal['files'].items():
        if sha(OUT / name) != expected:
            raise ValueError('prediction_modified:' + name)
    for name, expected in seal['implementation'].items():
        if sha(ROOT / name) != expected:
            raise ValueError('scoring_implementation_modified:' + name)
    if sha(OUT / 'experiment_specification.json') != seal['specification_sha256']:
        raise ValueError('specification_modified')
    return seal


def threshold_grid(policy):
    v = policy['thresholds']
    return [round(v['start']+i*v['step'], 10) for i in range(round((v['stop']-v['start'])/v['step'])+1)]


def sample_push(heap, rank, item, n=100):
    value = (rank, tuple(item['support_pair']), item)
    if len(heap) < n:
        heapq.heappush(heap, value)
    elif value[:2] > heap[0][:2]:
        heapq.heapreplace(heap, value)


def run():
    verify_seal()
    save(OUT / 'evaluation_started.json', dict(prediction_seal_sha256=sha(OUT / 'prediction_seal.json'),
         split='Final Dataset development/calibration only', independent_test=False))
    policy = read(OUT / 'experiment_specification.json')['policy']
    gt = read(BASE / 'gt_edge_evaluation.json')
    hn = read(BASE / 'hard_negative_evaluation.json')
    # Membership sidecars are used exclusively in this post-seal evaluation process.
    data = __import__('pathlib').Path(read(BASE / 'preparation.json')['input']).parents[1]
    truth = read(data / 'ground_truth/ground_truth.json')
    trace = {r['event_id']: r['alert_id'] for r in read(BASE / 'trace_map.json')}
    owner = read(BASE / 'blind_A/owner.json')
    attack_ids = {trace[o['alert_id']] for o in truth['observations']}
    hn_ids = {a for r in hn['pairs'] for a in r['canonical_alert_ids'] if a}
    allids = set(trace.values())
    background = allids - attack_ids - hn_ids
    assert len(attack_ids) == 125 and len(hn_ids) == 360 and len(background) == 9500
    alerts = {r['alert_id']: r for r in rows(BASE / 'blind_A/canonical.jsonl.gz')}
    sources = {i: a['raw_alert'].get('source_type', a['source_type']) for i, a in alerts.items()}
    gt_groups = {tuple(r['support_key']): r for r in gt['edges']}
    hn_groups = {tuple(r['support_key']): r for r in hn['pairs'] if r['support_key']}
    gt_wanted = {pairkey(*r['canonical_alert_ids']): r for r in gt['edges']}
    hn_wanted = {pairkey(*r['canonical_alert_ids']): r for r in hn['pairs']}
    group_name = {tuple(r['support_key']): 'binding:' + '+'.join(sorted({c['binding_type'] for c in r['raw_evidence']}))
                  for r in gt['edges']}
    group_name.update({tuple(r['support_key']): r['scenario_id'] for r in hn['pairs'] if r['support_key']})
    thresholds = threshold_grid(policy)
    names = ['baseline'] + [m + ':' + p for m in policy['models'] for p in policy['policies']]
    families = sorted(set(group_name.values()))
    metrics = ['total_admitted', 'same_source_admitted', 'cross_source_admitted', 'background_background_admitted',
               'gt_admitted', 'hn_admitted'] + families
    counters = {name: ThresholdCounts(thresholds, metrics) for name in names}
    dist_values = collections.defaultdict(list)
    dist_admitted = collections.Counter()
    dist_total = collections.Counter()
    samples = {k: [] for k in ('high', 'near', 'random_pool', 'near_rejected_attack', 'rejected_background')}
    pair_results = {}
    candidate_count = 0
    source_pairs = {name: collections.Counter() for name in names}
    for row in rows(OUT / 'predictions/candidates.jsonl.gz'):
        candidate_count += 1
        key = tuple(row['support_key'])
        base = row['results'].get('baseline', row['observed_baseline'])
        a, b = base['support_pair']
        if key in gt_groups or key in hn_groups:
            pair_results[key] = row
        base_bg = a in background and b in background
        base_accept = 'baseline' in row['results'] and base['score'] >= .65
        if base_bg and base_accept:
            sample_push(samples['high'], base['score'], base)
            sample_push(samples['near'], -abs(base['score']-.65), base)
            rank = int(hashlib.sha256((str(policy['sample_seed'])+'|'.join(key)).encode()).hexdigest(), 16)
            sample_push(samples['random_pool'], rank, base, n=400)
        if base_bg and not base_accept:
            sample_push(samples['rejected_background'], base['score'], base, n=25)
        if a in attack_ids and b in attack_ids and not base_accept:
            sample_push(samples['near_rejected_attack'], -abs(base['score']-.65), base, n=25)
        for name in names:
            result = row['results'].get(name)
            result_for_dist = result or base if name == 'baseline' else result
            support = result['support_pair'] if result else [a, b]
            x, y = support
            same = sources[x] == sources[y]
            bg = x in background and y in background
            category = ['same_source_candidates' if same else 'cross_source_candidates']
            if bg:
                category.append('background_background_candidates')
            if x in attack_ids and y in attack_ids:
                category.append('attack_support_observation_pairs')
            if key in gt_groups:
                category.append('gt_witness')
            if key in hn_groups:
                category.append('known_hard_negative')
            score_value = result_for_dist['score'] if result_for_dist else None
            # For global variants, no eligible member means every fully scored
            # member failed the preserved hard gate. model.score returns exactly
            # zero there; this is a computed rejection, not an unscored pair.
            if result is None and name in {'A:global', 'B:global', 'C:global'}:
                score_value = 0.
            admitted = result is not None and result['effective_score'] >= .65
            if name in {'baseline', 'A:global', 'B:global', 'C:global'}:
                for c in category:
                    dist_total[name, c] += 1
                    if score_value is not None:
                        dist_values[name, c].append(score_value)
                    dist_admitted[name, c] += admitted
            if admitted:
                source_pairs[name]['|'.join(sorted((sources[x], sources[y])))] += 1
            if result:
                active = ['total_admitted', 'same_source_admitted' if same else 'cross_source_admitted']
                if bg:
                    active.append('background_background_admitted')
                if key in gt_groups:
                    active += ['gt_admitted', group_name[key]]
                if key in hn_groups:
                    active += ['hn_admitted', group_name[key]]
                counters[name].add(result['effective_score'], active)
        if candidate_count % 60000 == 0:
            print('EVALUATED_CANDIDATES', candidate_count, flush=True)
    if candidate_count != 240621:
        raise ValueError('candidate_denominator_changed')
    sweep = []
    for name, counter in counters.items():
        for row in counter.rows():
            model, admission = name.split(':') if ':' in name else ('baseline', 'global')
            row.update(model=model, policy=admission, variant=name,
                       gt_recall=row['gt_admitted']/7, hn_rejection_rate=1-row['hn_admitted']/180)
            sweep.append(row)
    base = next(r for r in sweep if r['variant'] == 'baseline' and r['threshold'] == .65)
    if (base['gt_admitted'], base['hn_admitted'], base['total_admitted'], base['background_background_admitted']) != (4, 48, 14788, 13221):
        raise ValueError('baseline_evaluation_mismatch')
    selected = choose([r for r in sweep if r['variant'] != 'baseline'], gt_total=7, hn_total=180,
                      baseline_total=14788, config=policy['selection'])
    save(OUT / 'threshold_search.json', dict(rows=sweep, pareto_frontier=frontier(sweep), selected=selected,
         objective=policy['selection'], count=len(sweep), candidate_count=240621,
         note='Counts are unique representative pairs, using complete eligible member max for each admission policy. No background FP assumption.'))
    with (OUT / 'threshold_search.csv').open('w', newline='', encoding='utf8') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(sweep[0])); writer.writeheader(); writer.writerows(sweep)
    distributions = {}
    for (name, category), count in dist_total.items():
        if category == 'known_hard_negative':
            count = 180
        distributions.setdefault(name, {})[category] = distribution(
            dist_values[name, category], dist_admitted[name, category], total=count)
    save(OUT / 'score_distributions.json', distributions)
    save(OUT / 'source_pair_counts_at_0_65.json', source_pairs)
    # LOFO: hold out entire authored binding families or entire HN scenarios.
    folds = []
    for family in families:
        held = [r for r in gt['edges'] if group_name[tuple(r['support_key'])] == family]
        held_hn = [r for r in hn['pairs'] if r['scenario_id'] == family]
        train = []
        for row in sweep:
            if row['variant'] == 'baseline':
                continue
            adjusted = dict(row)
            metric = 'gt_admitted' if family.startswith('binding:') else 'hn_admitted'
            adjusted[metric] -= row[family]
            train.append(adjusted)
        choice = choose(train, gt_total=7-len(held), hn_total=180-len(held_hn),
                        baseline_total=14788, config=policy['selection'])
        original = next((r for r in sweep if choice and r['variant'] == choice['variant'] and
                         r['threshold'] == choice['threshold']), None)
        folds.append(dict(held_out=family, gt_count=len(held), hn_count=len(held_hn),
            chosen_variant=choice['variant'] if choice else None, threshold=choice['threshold'] if choice else None,
            held_admitted=original[family] if original else None,
            train_gt_recall=choice['gt_admitted']/(7-len(held)) if choice and len(held) < 7 else None,
            train_hn_rejection=1-choice['hn_admitted']/(180-len(held_hn)) if choice else None))
    save(OUT / 'group_calibration.json', dict(protocol='Leave one entire binding/HN family out of selection; no formula refit',
        folds=folds, note='Developer has seen this development dataset; LOFO cannot establish independent generalization. Unscored HN11 remains in denominator.',
        stable_selected_variant=all(f['chosen_variant'] == selected['variant'] for f in folds) if selected else False))
    # Save all witness members, including the 12 HN with no candidate, explicitly.
    wanted = set(gt_wanted) | set(hn_wanted)
    witness_members = {}
    for row in rows(OUT / 'predictions/members.jsonl.gz'):
        key = pairkey(*row['support_pair'])
        if key in wanted:
            witness_members[key] = row
    high = [v[2] for v in sorted(samples['high'], reverse=True)]
    near = [v[2] for v in sorted(samples['near'], reverse=True)]
    occupied = {pairkey(*v['support_pair']) for v in high+near}
    random_sample = [v[2] for v in sorted(samples['random_pool'], reverse=True)
                     if pairkey(*v[2]['support_pair']) not in occupied][:100]
    if min(len(high), len(near), len(random_sample)) < 100:
        raise ValueError('insufficient_background_sample')
    sample_lists = dict(high=high, near=near, random=random_sample,
                        near_rejected_attack=[v[2] for v in sorted(samples['near_rejected_attack'], reverse=True)],
                        rejected_background=[v[2] for v in sorted(samples['rejected_background'], reverse=True)])
    for values in sample_lists.values():
        wanted.update(pairkey(*v['support_pair']) for v in values)
    decompositions = {}
    # Skip parsing unrelated feature rows using their already sealed member ID prefix.
    patterns = set(i for pair in wanted for i in pair)
    with gzip.open(OUT / 'predictions/member_features.jsonl.gz', 'rt', encoding='utf8') as stream:
        for line in stream:
            ids = re.findall(r'alt_[a-f0-9]{64}', line[:380])[-2:]
            if len(ids) == 2 and pairkey(*ids) in wanted:
                row = json.loads(line)
                decompositions[pairkey(*row['support_pair'])] = row
    witness_rows = []
    for key, original in itertools.chain(gt_wanted.items(), hn_wanted.items()):
        member = witness_members.get(key)
        d = decompositions.get(key)
        if original['candidate'] and (member is None or d is None):
            raise ValueError('missing_witness_decomposition')
        witness_rows.append(dict(pair_id=original.get('edge_id', original.get('scenario_id')),
            scenario_id=original.get('scenario_id'), original_pair=original['canonical_alert_ids'],
            candidate=original['candidate'], baseline_score=original['score'],
            baseline_admitted=original['admitted'], candidate_prediction=pair_results.get(tuple(original['support_key'])),
            features=d, member_predictions=member,
            no_score_reason=None if member else 'not_nominated_by_frozen_candidate_policy; no manufactured score'))
    save(OUT / 'witness_decomposition.json', witness_rows)
    save(OUT / 'sample_decomposition.json', {kind: [dict(selection=v, features=decompositions.get(pairkey(*v['support_pair'])))
         for v in values] for kind, values in sample_lists.items()})
    # Margins use exact scored witnesses, not means or a substituted stage member.
    margins = {}
    for model in ['baseline'] + policy['models']:
        def value(row):
            if not row['member_predictions']:
                return None
            return (row['member_predictions']['baseline']['score'] if model == 'baseline'
                    else row['member_predictions']['experiments'][model]['score'])
        pos = [value(r) for r in witness_rows if not r['scenario_id']]
        neg = [value(r) for r in witness_rows if r['scenario_id'] and value(r) is not None]
        margins[model] = dict(gt_min=min(pos), gt_max=max(pos), hn_max=max(neg),
            worst_case_margin=min(pos)-max(neg),
            positive_negative_order_rate=sum(p > n for p in pos for n in neg)/(len(pos)*len(neg)),
            hn_unscored=180-len(neg), gt_scores=pos)
    save(OUT / 'separation_margins.json', margins)
    save(OUT / 'evaluation_summary.json', dict(baseline=base, selected=selected, source_counts=source_pairs,
        gt_candidates=7, hn_known=180, hn_candidate_count=hn['candidate'], margins=margins,
        background_sample_counts={k: len(v) for k, v in sample_lists.items()},
        no_production_deployment=True, independent_test_available=False))
    print('EVALUATION_COMPLETE', json.dumps(selected, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    run()
