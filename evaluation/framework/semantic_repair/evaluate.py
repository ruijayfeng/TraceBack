"""Post-seal development metrics. Labels never enter scoring or graph workers."""
from collections import Counter
from itertools import product
from statistics import median
from . import OUT, OLD, ROOT
from .runtime import verify_seal
from evaluation.framework.formula_design.runtime import read, save, rows, sha
from evaluation.framework.threshold_calibration.metrics import distribution, longest_path


def run(stage):
    frozen, seal = verify_seal(stage)  # Every prediction kind is verified before any GT read.
    folder = OUT/stage
    if (folder/'evaluation_started.json').exists(): raise ValueError('single_use_evaluation')
    save(folder/'evaluation_started.json', dict(score_seal_sha256=sha(folder/'score_seal.json'),
        score_sealed_first=True, direction_sealed_first=True, graph_sealed_first=True,
        development_previously_saw_labels=True, independent_test_validation=False))
    baseline = ROOT/'outputs/v5_evidence_semantics_final'
    labels = read(baseline/'evaluation/label_projection.json')
    oldgt = read(baseline/'ground_truth_edge_scores.json')['edges']
    attack, hard, background = (set(labels[k]) for k in ('attack_ids', 'hard_ids', 'background_ids'))
    negative = {tuple(sorted(p)) for p in product(attack, hard)}
    gt_pairs = {tuple(sorted((g['source_alert_id'], g['target_alert_id']))): key for key, g in oldgt.items()}
    designs = frozen['policy']['designs'] if stage == 'development' else [frozen['selection']['design']]
    selected = {d: list(rows(folder/'blind'/d/'selected_scores.jsonl.gz')) for d in designs}
    stats = {d: dict(gt={}, negatives={}, touching={}, background=[], direction_count=0,
                    tier_counts=Counter(), binding_negative_pairs=[]) for d in designs}
    old_negative = read(OLD/'hard_negative_results.json')
    old_worst = max((r for r in old_negative['pairs'] if r['score'] is not None), key=lambda r: r['score'])
    worst_pair = tuple(sorted(old_worst['support_pair'])); worst = None
    total = 0
    for row in rows(folder/'blind/pair_scores.jsonl.gz'):
        total += 1; pair = tuple(sorted(row['support_pair']))
        if pair == worst_pair: worst = row
        for design in designs:
            state = stats[design]; score = row['variants'][design]['final_score']
            state['tier_counts'][row['hierarchy']['name']] += 1
            if row['direction']['status'] == 'DERIVED_VERIFIED_DIRECTION': state['direction_count'] += 1
            if pair in gt_pairs: state['gt'][gt_pairs[pair]] = row
            if pair in negative:
                state['negatives'][pair] = row
                if row['hierarchy']['level'] == 3: state['binding_negative_pairs'].append(pair)
            for h in set(pair)&hard:
                prior = state['touching'].get(h)
                if prior is None or score > prior['score']: state['touching'][h] = dict(score=score, pair=pair)
    if total != seal['member_count']: raise ValueError('evaluation_member_coverage')
    all_results = {}
    node_labels = {}
    for key, g in oldgt.items():
        node_labels[g['source_alert_id']] = g['from_node']; node_labels[g['target_alert_id']] = g['to_node']
    # The archived projection explicitly describes all members of each GT node.
    # Their use is post-hoc matching only, never graph construction.
    for name, node in labels['nodes'].items():
        members = node.get('alert_ids', []) if isinstance(node, dict) else node if isinstance(node, list) else []
        for aid in members: node_labels[labels['ids'].get(aid, aid)] = name
    gt_node_relations = {(g['from_node'], g['to_node']) for g in oldgt.values()}
    for design in designs:
        state = stats[design]
        gs = {key: row['variants'][design]['final_score'] for key, row in state['gt'].items()}
        negatives = [r['variants'][design]['final_score'] for r in state['negatives'].values()]
        bg = [r['score'] for r in selected[design] if set(r['support_pair']) <= background]
        points = []
        for point in frozen['policy']['diagnostic_operating_points']:
            path = folder/'blind'/design/('correlation_'+str(point).replace('.', '_')+'.jsonl.gz')
            actual = list(rows(path)); pairs = {tuple(sorted(e['support']['support_pair'])) for e in actual}
            gt_ids = [key for pair, key in gt_pairs.items() if pair in pairs]
            points.append(dict(threshold=point, file=str(path.relative_to(OUT)), total_edges=len(actual),
                               GT_CORRELATION_EDGES=len(gt_ids), GT_edges=gt_ids,
                               correlation_recall=len(gt_ids)/len(oldgt),
                               explicit_negative_admission=len(pairs&negative),
                               unlabeled_background_admission=sum(set(p) <= background for p in pairs)))
        graph_results = {}
        variants = frozen['policy']['chain_policies'] if stage == 'development' else [frozen['selection']['chain_policy']]
        for variant in variants:
            graph = folder/'blind'/design/('policy_'+variant)
            nodes = list(rows(graph/'nodes.jsonl.gz')); chains = list(rows(graph/'chain_edges.jsonl.gz'))
            support = list(rows(graph/'correlation_edges.jsonl.gz')); diags = list(rows(graph/'diagnostics.jsonl.gz'))
            byalert = {aid: n for n in nodes for aid in n['alert_ids']}; byid = {n['node_id']: n for n in nodes}
            directed = {(e['source_node_id'], e['target_node_id']) for e in chains}
            peredge = {}
            recovered = []
            for key, g in oldgt.items():
                row = state['gt'].get(key); a, b = g['source_alert_id'], g['target_alert_id']
                proof = bool(row and row['direction']['source_alert_id'] == a and row['direction']['target_alert_id'] == b)
                created = (byalert[a]['node_id'], byalert[b]['node_id']) in directed
                if created: recovered.append((g['from_node'], g['to_node']))
                why = None if created else 'source_observability_missing_binding' if not proof else 'chain_or_component_guard'
                peredge[key] = dict(score=gs.get(key), candidate=row is not None,
                    gate_pass=bool(row and row['valid'] and row['baseline']['gate']['passed']),
                    direction_verified=proof, transition_level=row['hierarchy']['level'] if row else None,
                    chain_edge_created=created, same_incident=byalert[a]['incident_id'] == byalert[b]['incident_id'],
                    failure=why, actual_source_node_id=byalert[a]['node_id'], actual_target_node_id=byalert[b]['node_id'])
            explicit = background_chains = hard_touching_chains = matched_stage_chains = 0
            for e in chains:
                ids = set(e['alert_ids']); pair = tuple(sorted(ids))
                explicit += pair in negative
                background_chains += ids <= background
                hard_touching_chains += bool(ids&hard)
                a, b = byid[e['source_node_id']], byid[e['target_node_id']]
                matched_stage_chains += any((node_labels.get(x), node_labels.get(y)) in gt_node_relations
                                            for x in a['alert_ids'] for y in b['alert_ids'])
            summary = read(graph/'summary.json')
            graph_results[variant] = dict(chain_policy=variant, GT=peredge,
                GT_CHAIN_EDGES=sum(x['chain_edge_created'] for x in peredge.values()),
                GT_DIRECTION_PROOFS=sum(x['direction_verified'] for x in peredge.values()),
                longest_GT_directed_path=longest_path(recovered),
                full_reconstructed_progression_length=longest_path(directed), path_unit='edges',
                background_chain_edges=background_chains, explicit_negative_chain_edges=explicit,
                all_hard_touching_chain_edges=hard_touching_chains, actual_chain_edges=len(chains),
                stage_matched_actual_chain_edges=matched_stage_chains,
                component_sizes=summary['component_sizes'], original_alerts_retained=summary['original_alerts_retained'],
                cycle_rejection=sum(r.get('rejection_code') == 'cycle' for r in diags),
                conflict_rejection=sum('component_hard_conflict' in r.get('rejection_codes', []) for r in diags),
                component_guard_rejections=sum(r.get('stage') == 'clustering' and r['decision'] == 'reject' for r in diags),
                correlation_support_edge_count=len(support), graph_file=str((graph/'chain_edges.jsonl.gz').relative_to(OUT)))
        meaningful = [gs[key] for key, r in state['gt'].items() if r['hierarchy']['level'] == 3]
        result = dict(design=design, GT_min=min(gs.values()), GT_median=median(gs.values()), GT_max=max(gs.values()),
            explicit_negative_max=max(negatives, default=None), positive_negative_margin=min(gs.values())-max(negatives),
            positive_negative_overlap=min(gs.values()) <= max(negatives), meaningful_bound_GT_min=min(meaningful, default=None),
            meaningful_bound_GT_negative_margin=min(meaningful)-max(negatives) if meaningful else None,
            all_hard_touching_max=max(r['score'] for r in state['touching'].values()),
            candidate_recall=len(state['gt'])/len(oldgt),
            gate_recall=sum(r['valid'] and r['baseline']['gate']['passed'] for r in state['gt'].values())/len(oldgt),
            direction_proof_recall=next(iter(graph_results.values()))['GT_DIRECTION_PROOFS']/len(oldgt),
            GT_scores=gs, operating_points=points, chain_policies=graph_results,
            hard_alert_count=len(hard), explicit_labeled_negative_pairs=len(negative),
            scored_labeled_negative_pairs=len(negatives), absent_negative_policy='not predicted; no invented score',
            binding_negative_pairs=state['binding_negative_pairs'], background_distribution=distribution(bg),
            background_pair_count=len(bg), total_selected_pairs=len(selected[design]), tier_counts=dict(state['tier_counts']),
            total_direction_proofs=state['direction_count'], all_hard_alert_maxima=state['touching'],
            evaluation_coverage=(len(state['gt'])+len(negatives))/total, unlabeled_excluded_from_precision=True)
        all_results[design] = result
        save(folder/('metrics_'+design+'.json'), result)
        save(folder/('GT_evidence_'+design+'.json'), state['gt'])
        save(folder/('negative_pairs_'+design+'.json'), dict(pairs=[dict(support_pair=list(pair),
            candidate=pair in state['negatives'], score=state['negatives'][pair]['variants'][design]['final_score'] if pair in state['negatives'] else None,
            hierarchy=state['negatives'][pair]['hierarchy'] if pair in state['negatives'] else None) for pair in sorted(negative)]))
    if worst:
        save(folder/'worst_negative_before_after.json', dict(support_pair=worst_pair,
             before=next(r for r in old_negative['top20_decomposition'] if tuple(sorted(r['support_pair'])) == worst_pair),
             after=worst, identity_evidence=worst['hierarchy']['identity_evidence'],
             role_evidence=worst['hierarchy']['role_evidence'], behavior_evidence=worst['hierarchy']['behavior_evidence'],
             binding_evidence=worst['hierarchy']['binding_evidence'],
             ceiling_decisions={d: worst['variants'][d] for d in designs}))
    save(folder/'comparison.json', all_results)
    if stage == 'development':
        # Predeclared safety/separation ordering, never a GT-recovery objective.
        # Prefer the fewest contextual promotion assumptions on equal outcomes.
        eligible = [d for d in designs if not all_results[d]['binding_negative_pairs'] and
                    all_results[d]['chain_policies']['D']['explicit_negative_chain_edges'] == 0]
        chosen = min(eligible, key=lambda d: (all_results[d]['explicit_negative_max'],
                     -all_results[d]['meaningful_bound_GT_negative_margin'] if all_results[d]['meaningful_bound_GT_negative_margin'] is not None else 1.,
                     next(p['unlabeled_background_admission'] for p in all_results[d]['operating_points'] if p['threshold'] == .65), d)) if eligible else None
        save(folder/'selection.json', dict(design=chosen, chain_policy='D', parameter_changes=0,
             source='predeclared safety/separation/background ordering; A wins ties; D conservative hybrid',
             comparison_sha256=sha(folder/'comparison.json'), independent_validation=False))
        if not chosen: raise ValueError('V5_DESIGN_STILL_DEFECTIVE')
    print('POST_SEAL_EVALUATION_COMPLETE', stage, flush=True)
    return all_results


if __name__ == '__main__':
    import sys
    run(sys.argv[1])
