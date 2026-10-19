"""Post-hoc evaluation of sealed outputs. Never imports a production runner."""
from collections import Counter, defaultdict
from fractions import Fraction
import heapq
import json

from .artifacts import rows, require_sealed
from .common import OUT, ROOT, THRESHOLD, read, save, sha, integrity
from .diagnosis import candidate_absence, decomposition, capability, equality_projection
from .metrics import (pair_key, recall, distribution, ranking, separation, stable_match,
                      chain_metrics, population, correct_correlation_witness, directed_chain_hit)
from .truth import load


def run():
    require_sealed()
    blind = OUT / 'blind'
    alerts = {r['alert_id']: r for r in rows(blind / 'canonical.jsonl.gz')}
    entities = {r['entity_id']: r for r in rows(blind / 'entities.jsonl.gz')}
    owners = read(blind / 'owner.json')
    prepared = read(OUT / 'preparation.json')
    algorithm = prepared['algorithm']
    truth = load(alerts)
    gt, witnesses, members = truth['gt'], truth['witnesses'], truth['members']
    positives = set().union(*witnesses.values())
    endpoint_pairs = {e['edge_id']: {pair_key(a, b) for a in members[e['from']] for b in members[e['to']]}
                      for e in gt['edges']}
    all_endpoint_pairs = set().union(*endpoint_pairs.values())
    targeted_reps = {pair_key(owners[a], owners[b]) for a, b in all_endpoint_pairs if owners[a] != owners[b]}
    scores, details, candidates, representative_scores = {}, {}, {}, {}
    distributions, population_counts, negative_tops = defaultdict(list), Counter(), []
    candidate_keys, decision_counts, scored_representative_keys = set(), Counter(), set()
    hard_candidates, hard_members, hard_admitted, hard_alert_counts = set(), 0, set(), Counter()
    negative_candidates = set()
    negative_representatives = set()
    for p in truth['negative_pairs']:
        if owners[p[0]] != owners[p[1]]:
            negative_representatives.add(pair_key(owners[p[0]], owners[p[1]]))
    member_count = 0
    print(json.dumps({'stage': 'truth_validated', 'positive_pairs': len(positives),
                      'negative_pairs': len(truth['negative_pairs'])}), flush=True)
    for row in rows(blind / 'diagnostics.jsonl.gz'):
        stage = row['stage']
        if stage == 'candidate':
            k = tuple(row['support_key'])
            candidate_keys.add(k)
            if k in targeted_reps:
                candidates[k] = row
        elif stage == 'member_score':
            p, k = pair_key(*row['support_pair']), tuple(row['support_key'])
            if p in scores:
                raise ValueError('original_member_pair_scored_more_than_once_in_correlation')
            scores[p] = row['score']
            representative_scores[k] = max(representative_scores.get(k, -1.), row['score'])
            scored_representative_keys.add(k)
            label = population(p, positives, truth['negative_pairs'], truth['hard_ids'], truth['background_ids'])
            distributions[label].append(row['score'])
            population_counts[label] += 1
            if p in all_endpoint_pairs or p in truth['negative_pairs']:
                details[p] = row
            if set(p) & truth['hard_ids']:
                hard_members += 1
                hard_candidates.add(k)
                for aid in set(p) & truth['hard_ids']:
                    hard_alert_counts[aid] += 1
                distributions['all_hard_negative_touching'].append(row['score'])
                item = (row['score'], p, row)
                if len(negative_tops) < 20:
                    heapq.heappush(negative_tops, item)
                elif item[:2] > negative_tops[0][:2]:
                    heapq.heapreplace(negative_tops, item)
            if p in truth['negative_pairs']:
                negative_candidates.add(p)
            member_count += 1
            if member_count % 50000 == 0:
                print(json.dumps({'stage': 'diagnostic_read', 'member_scores': member_count}), flush=True)
        elif stage == 'correlation_decision':
            decision_counts[row['rule_id']] += 1
    summary = read(blind / 'correlation_summary.json')
    if len(candidate_keys) != summary['scored_candidate_count'] or candidate_keys != scored_representative_keys:
        raise ValueError('candidate_vs_scored_diagnostics_mismatch')
    if summary['resource_truncated_count'] or summary['admitted_candidate_count'] != summary['scored_candidate_count']:
        raise ValueError('baseline_has_resource_or_scoring_omissions')
    formal = list(rows(blind / 'correlation_edges.jsonl.gz'))
    chains = list(rows(blind / 'chains.jsonl.gz'))
    chain_nodes = {n['node_id']: n for ch in chains for n in ch['nodes']}
    chain_edges = [e for ch in chains for e in ch['edges']]
    admitted_primary, recovered_primary = {}, {}
    for edge in gt['edges']:
        e = edge['edge_id']
        admitted_primary[e] = [r['edge_id'] for r in formal if correct_correlation_witness(r, witnesses[e])]
        recovered_primary[e] = [r['edge_id'] for r in chain_edges if directed_chain_hit(
            r, chain_nodes, members[edge['from']], members[edge['to']], witnesses[e])]
    for r in formal:
        p = pair_key(r['support_pair']['alert_id_src'], r['support_pair']['alert_id_dst'])
        if set(p) & truth['hard_ids']:
            hard_admitted.add(r['edge_id'])
    edge_audit, evidence, source_capabilities, coverage = [], {}, {}, []
    for edge in gt['edges']:
        e = edge['edge_id']
        supported = sorted(witnesses[e])
        scored = [details[p] for p in supported if p in details]
        best = min(scored, key=lambda r: (-r['score'], tuple(sorted(r['support_pair'])))) if scored else None
        candidate = any(owners[a] != owners[b] and pair_key(owners[a], owners[b]) in candidate_keys for a, b in supported)
        valid = any(r['valid'] for r in scored)
        admitted, chain = bool(admitted_primary[e]), bool(recovered_primary[e])
        failure = 'BROKEN_AT_CANDIDATE' if not candidate else 'BROKEN_AT_SCORING' if not scored or not valid else \
                  'BROKEN_AT_ADMISSION' if not admitted else 'BROKEN_AT_CHAIN' if not chain else 'FULLY_RECOVERED'
        a, b = next(iter(witnesses[e]))
        audit = best['evidence']['evidence_v2'] if best else None
        absence = candidate_absence(alerts[a], alerts[b], entities, owners, algorithm) if not candidate else None
        member_rows = []
        for p in sorted(endpoint_pairs[e]):
            k = pair_key(owners[p[0]], owners[p[1]]) if owners[p[0]] != owners[p[1]] else None
            member_rows.append({'pair': list(p), 'explicit_positive': p in witnesses[e],
                'candidate': k in candidate_keys, 'scored': p in scores, 'score': scores.get(p)})
        coverage.append({'gt_edge_id': e, 'explicit_positive_pairs': len(supported),
            'explicit_positive_candidates': int(candidate), 'explicit_positive_scored': len(scored),
            'node_endpoint_pair_count': len(member_rows), 'node_endpoint_candidates': sum(r['candidate'] for r in member_rows),
            'node_endpoint_scored': sum(r['scored'] for r in member_rows), 'node_endpoint_pairs': member_rows})
        evidence[e] = decomposition(best, algorithm)
        directed_source = alerts[truth['ids'][edge['witness_alert_ids']['from']]]
        directed_target = alerts[truth['ids'][edge['witness_alert_ids']['to']]]
        projection = equality_projection(edge, directed_source, directed_target)
        source_capabilities[e] = {'gt_declared_observable_evidence': edge['observable_evidence'],
            'gt_declared_unobservable_evidence': edge['unobservable_evidence'],
            'declared_raw_join_projection': projection,
            'saved_input_observations': capability(best, [alerts[a], alerts[b]]),
            'all_node_alert_observations': capability(None, [alerts[x] for x in sorted(members[edge['from']] | members[edge['to']])])}
        edge_audit.append({'gt_edge_id': e, 'display_id': 'GT_E' + str(len(edge_audit) + 1),
            'src_gt_node': edge['from'], 'dst_gt_node': edge['to'],
            'src_stage': truth['nodes'][edge['from']]['stage'], 'dst_stage': truth['nodes'][edge['to']]['stage'],
            'supporting_alerts': {'explicit_witness_external': edge['witness_alert_ids'],
                'canonical_pairs': [list(p) for p in supported],
                'src_node_canonical_alerts': sorted(members[edge['from']]), 'dst_node_canonical_alerts': sorted(members[edge['to']])},
            'candidate_generated': candidate, 'candidate_failure_reason': absence,
            'raw_join_projection': projection,
            'canonical_categories': {'source': directed_source['category'], 'target': directed_target['category']},
            'candidate_provenance': candidates.get(pair_key(owners[a], owners[b])) if owners[a] != owners[b] else None,
            'score_computed': bool(scored), 'score': best['score'] if best else None,
            'scoring_valid': valid, 'scoring_rejection_codes': best['rejection_codes'] if best else [],
            'evidence_gate_passed': audit['evidence_gate_passed'] if audit else None,
            'evidence_gate_reason': audit['gate_reason'] if audit else None,
            'threshold': THRESHOLD, 'admitted': admitted, 'correlation_edge_ids': admitted_primary[e],
            'score_gap': best['score'] - THRESHOLD if best else None,
            'strongest_evidence': sorted(audit['evidence'], key=lambda f: (-f['strength'], f['fact_key'])) if audit else [],
            'missing_evidence': {'gt_unobservable': edge['unobservable_evidence'],
                'v4_unavailable': audit['unavailable_evidence'] if audit else None,
                'v4_not_applicable': audit['not_applicable_evidence'] if audit else None},
            'negative_evidence': {'mismatches': audit['mismatched_evidence'] if audit else None,
                'conflicts': best['evidence']['conflicts'] if best else None,
                'duplicate_penalty': best['values']['duplicate'] if best else None},
            'chain_edge_created': chain, 'chain_edge_ids': recovered_primary[e],
            'final_failure_stage': failure,
            'stage_definition': 'BROKEN_AT_SCORING includes a computed score that fails the v4 evidence/hard guard; numeric threshold is audited independently.',
            'downstream_observation': 'No correct admitted support; chain stage not reached' if not admitted else
                'Correct correlation support exists; inspect reconstruction diagnostics' if not chain else 'Directed support recovered'})
    candidate_recall = recall([e['gt_edge_id'] for e in edge_audit if e['candidate_generated']])
    candidate_recall.update({'edge_level_candidate_recall': candidate_recall['value'],
        'alert_pair_candidate_coverage': {'numerator': sum(c['explicit_positive_candidates'] for c in coverage),
            'denominator': 6, 'value': sum(c['explicit_positive_candidates'] for c in coverage) / 6},
        'policy': gt['evaluation_policy']['positive_alert_pairs'], 'per_edge': coverage,
        'node_endpoint_coverage_supplement': {'candidate_pairs': sum(c['node_endpoint_candidates'] for c in coverage),
            'denominator': 54, 'value': sum(c['node_endpoint_candidates'] for c in coverage) / 54,
            'note': '54 source-node x target-node combinations are a membership diagnostic, not 54 explicitly labeled positive pairs.'}})
    admission_recall = recall([e['gt_edge_id'] for e in edge_audit if e['admitted']])
    admission_recall.update(FULL_GT_EDGES=admission_recall['gt_edge_ids'],
        MISSED_GT_EDGES=[{'gt_edge_id': e['gt_edge_id'], 'reason': e['final_failure_stage'],
                         'candidate_reason': e['candidate_failure_reason'], 'gate_reason': e['evidence_gate_reason'],
                         'score_gap': e['score_gap']} for e in edge_audit if not e['admitted']])
    rank = ranking(scores, witnesses)
    rep_witnesses = {e: {pair_key(owners[a], owners[b]) for a, b in ws if owners[a] != owners[b]}
                     for e, ws in witnesses.items()}
    rank['representative_candidates'] = ranking(representative_scores, rep_witnesses)
    rank['representative_candidates']['rank_scope'] = 'one maximum observed member score per scheduled representative candidate, including evidence/guard rejects; diagnostic ranking, not a substitute selected support'
    positive_dist = distribution(distributions['gt_positive'])
    negative_dist = distribution(distributions['explicit_hard_negative'])
    separation_result = separation(distributions['gt_positive'], distributions['explicit_hard_negative'])
    hard_dist = distribution(distributions['all_hard_negative_touching'])
    score_dist = {'positive': positive_dist, 'hard_negative': negative_dist,
        'hard_negative_touching_all_candidates': hard_dist,
        'background_negative_requested': {**distribution(distributions['background_unknown']),
            'label_status': 'UNLABELED_UNKNOWN_NOT_PROVEN_NEGATIVE',
            'excluded_from_supervised_confusion_counts': True},
        'other_unknown': distribution(distributions['other_unknown']),
        'separation': separation_result, 'population_counts': dict(population_counts),
        'scope': 'computed original member scores only; unscored positive pairs are null, never imputed zero',
        'all_six_positive_pair_scores': [{'gt_edge_id': e['gt_edge_id'], 'score': e['score'], 'scored': e['score_computed']} for e in edge_audit]}
    hard_audit = {'hard_negative_alert_count': 30,
        'hard_negative_candidate_count': len(hard_candidates), 'hard_negative_member_score_count': hard_members,
        'hard_negative_admitted_count': len(hard_admitted), 'hard_negative_max_score': hard_dist['max'],
        'hard_negative_mean_score': hard_dist['mean'], 'explicit_negative_pair_denominator': 630,
        'explicit_negative_candidate_count': len(negative_candidates),
        'explicit_negative_candidate_coverage': len(negative_candidates) / 630,
        'explicit_negative_distribution': negative_dist,
        'explicit_negative_admitted_count': sum(correct_correlation_witness(r, truth['negative_pairs']) for r in formal),
        'all_touching_definition': 'representative candidates with at least one scored member belonging to one of the 30 hard-negative alerts; background/hard-hard pair labels remain unknown',
        'explicit_definition': 'only declared 30 x 21 hard-negative/attack pairs count as known negatives',
        'per_hard_negative_alert': [{'external_id': r['alert_id'], 'alert_id': truth['ids'][r['alert_id']],
            'family': r['negative_family'], 'scored_member_pair_count': hard_alert_counts[truth['ids'][r['alert_id']]]}
            for r in gt['hard_negatives']],
        'top_touching_pairs': [{'pair': list(p), 'score': s,
            'label': population(p, positives, truth['negative_pairs'], truth['hard_ids'], truth['background_ids']),
            'valid': row['valid'], 'rejections': row['rejection_codes'],
            'gate_reason': row['evidence']['evidence_v2']['gate_reason']} for s, p, row in sorted(negative_tops, reverse=True)]}
    # Exact rational one-to-one support matching and an independent semantic view.
    support_legal, strict_legal = {}, {}
    for pred, n in chain_nodes.items():
        for g, ids in members.items():
            overlap = len(set(n['alert_ids']) & ids)
            if overlap:
                w = Fraction(overlap, len(set(n['alert_ids']) | ids))
                support_legal[pred, g] = w
                if n['category'] == truth['nodes'][g]['stage']:
                    strict_legal[pred, g] = w
    node_matches, semantic_matches = stable_match(support_legal), stable_match(strict_legal)
    recovered_gt = [(e['src_gt_node'], e['dst_gt_node']) for e in edge_audit if e['chain_edge_created']]
    subgraph = chain_metrics(set(members), recovered_gt)
    chain_count = len(recovered_gt)
    chain_result = {'GT_NODE_COUNT': 7, 'GT_EDGE_COUNT': 6, 'LONGEST_GT_PATH_EDGES': 6,
        'recovered_gt_nodes_by_alert_support': len(node_matches), 'support_node_matches': node_matches,
        'GT_NODE_EVIDENCE_COVERAGE': len(node_matches) / 7,
        'CHAIN_NODE_RECALL': len(semantic_matches) / 7, 'semantic_node_matches': semantic_matches,
        'node_recall_definition': 'exact category=GT stage plus alert overlap, maximum-weight one-to-one; no invented stage/category translation',
        'formal_RQ3_metrics': {'status': 'unavailable', 'reason': 'GT provides progression stages rather than a frozen Category mapping, and no gold Incident matching contract; support coverage and exact-stage diagnostics are reported separately'},
        'recovered_gt_edges': chain_count, 'CHAIN_EDGE_RECALL': chain_count / 6,
        'LONGEST_RECOVERED_PATH_EDGES': subgraph['longest_path_edges'], **subgraph,
        'exact_progression_recovered': chain_count == 6 and subgraph['longest_path_edges'] == 6,
        'status': 'FULL_CHAIN' if chain_count == 6 else 'NO_CHAIN' if chain_count == 0 else
                  'PARTIAL_CHAIN' if subgraph['connected_components'] == 1 else 'FRAGMENTED_CHAIN',
        'correlation_correct_but_chain_failed': [e['gt_edge_id'] for e in edge_audit if e['admitted'] and not e['chain_edge_created']],
        'actual_chain_node_count': len(chain_nodes), 'actual_chain_edge_count': len(chain_edges),
        'category_coverage_for_GT_nodes': {g: sorted({alerts[a]['category'] for a in ids}) for g, ids in members.items()}}
    failure_counts = Counter(e['final_failure_stage'] for e in edge_audit)
    separation_failure = (separation_result['pairwise_order_probability'] is not None and
                          separation_result['pairwise_order_probability'] <= .5)
    modes = int(candidate_recall['numerator'] < 6) + int(any(e['score_computed'] and not e['admitted'] for e in edge_audit)) + int(separation_failure)
    task_result = 'V4_BASELINE_FULL_CHAIN_RECOVERED' if chain_count == 6 else 'V4_BASELINE_MULTIPLE_FAILURE_MODES' if modes > 1 else \
        'V4_BASELINE_CANDIDATE_RECALL_INSUFFICIENT' if candidate_recall['numerator'] < 6 else \
        'V4_BASELINE_HARD_NEGATIVE_SEPARATION_FAILURE' if separation_failure else \
        'V4_BASELINE_GT_FOUND_BUT_BELOW_THRESHOLD' if admission_recall['numerator'] == 0 else 'V4_BASELINE_PARTIAL_CHAIN_RECOVERED'
    # A measured baseline can inform design, but formula-only attribution requires
    # enough correctly extracted/candidate-covered true transitions. Do not
    # mistake an interface/observability gap for proof of a formula defect.
    ready = candidate_recall['numerator'] == 6 and all(e['score_computed'] for e in edge_audit)
    result = {'TASK_RESULT': task_result, 'DATASET_INTEGRITY': 'PASS', 'GROUND_TRUTH_LEAKAGE': False,
        'GT_EDGES': 6, 'CANDIDATE_GT_EDGES': candidate_recall['numerator'],
        'SCORED_GT_EDGES': sum(e['score_computed'] for e in edge_audit),
        'ADMITTED_GT_EDGES': admission_recall['numerator'], 'CHAIN_GT_EDGES': chain_count,
        'CANDIDATE_RECALL': candidate_recall['value'], 'ADMISSION_RECALL': admission_recall['value'],
        'LONGEST_GT_PATH_EDGES': 6, 'LONGEST_RECOVERED_PATH_EDGES': subgraph['longest_path_edges'],
        'GT_MAX_SCORE': positive_dist['max'], 'GT_MEDIAN_SCORE': positive_dist['median'],
        'GT_SCORED_PAIR_COUNT': positive_dist['count'], 'GT_UNSCORED_PAIR_COUNT': 6 - positive_dist['count'],
        'HARD_NEGATIVE_MAX_SCORE': hard_dist['max'],
        'EXPLICIT_HARD_NEGATIVE_MAX_SCORE': negative_dist['max'],
        'V4_MODIFIED': 'NO', 'THRESHOLD': THRESHOLD,
        'V5_FORMULA_DESIGN_GATE': 'READY' if ready else 'NOT_READY',
        'V5_FORMULA_DESIGN_ANSWER': 'YES' if ready else 'NO',
        'gate_basis': 'Conservative assessment for this experiment, not a new frozen acceptance rule: five of six transitions lack scores, preventing progression-wide formula attribution. The baseline remains useful evidence for ingestion/candidate/observability gaps; no production rerun after labels.',
        'failure_stage_counts': dict(failure_counts), 'primary_cause': 'G. Multiple causes' if modes > 1 else 'A. Candidate generation failure',
        'score_separation': separation_result, 'candidate_count': len(candidate_keys),
        'original_member_score_count': member_count, 'formal_correlation_edge_count': len(formal)}
    findings = {'implemented': False, 'findings': [
        {'id': 'F1', 'finding': 'Frozen native field projection and category coverage must be resolved independently of GT before claiming all six edges test a formula.',
         'evidence': 'source_capability.json; gt_edge_audit.json; no new host/asset/realm assertions were made'},
        {'id': 'F2', 'finding': 'Source namespaces alone do not declare shared network/asset/account scopes; a legitimate cross-source deployment contract is needed.',
         'evidence': 'freeze_verification.json scope_policy; actual CanonicalAlerts'},
        {'id': 'F3', 'finding': 'Known scenario causality is not the explicit request/process/session lineage required for formal ChainEdge.',
         'evidence': 'GT explicitly notes absent HTTP/SSH cross-sensor sessions; frozen chain guards remain active'},
        {'id': 'F4', 'finding': 'Unavailable evidence is excluded from quality but not the configured mass denominator; gate and temporal decay must be audited separately.',
         'evidence': 'evidence_decomposition.json, exact saved v4 dimensions and equation'},
        {'id': 'F5', 'finding': 'Compare score ranks only on explicitly labeled pairs; one measured positive cannot establish progression-wide separation.',
         'evidence': 'ranking_metrics.json and score_distribution.json'}]}
    for name, value in [('gt_edge_audit', edge_audit), ('candidate_recall', candidate_recall),
        ('admission_recall', admission_recall), ('score_distribution', score_dist), ('ranking_metrics', rank),
        ('hard_negative_audit', hard_audit), ('chain_reconstruction', chain_result),
        ('evidence_decomposition', evidence), ('source_capability', source_capabilities),
        ('V5_DESIGN_FINDINGS', findings), ('summary', result)]:
        save(OUT / (name + '.json'), value)
    integrity()
    from .report import write_report
    write_report()
    print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    run()
