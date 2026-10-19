"""Post-seal evaluation only: decompose saved scores without calling a scorer."""
from collections import Counter, defaultdict
import hashlib
import json
import math

from . import ROOT, OUT, PREVIOUS
from .replay import seal
from .boundary import verify_current
from evaluation.framework.v4_semisynthetic_baseline.common import DATASET, read, save, sha, verify_inventory
from evaluation.framework.v4_semisynthetic_baseline.artifacts import rows
from evaluation.framework.v4_semisynthetic_baseline.metrics import pair_key, distribution, ranking, separation
from evaluation.framework.v4_semisynthetic_baseline.diagnosis import decomposition


def evidence_state(dimension):
    state = dimension['state']
    if state in {'UNAVAILABLE', 'NOT_APPLICABLE'}: return state
    # Inequality is observable zero support, not proof of unrelated incidents.
    if state == 'AVAILABLE_MISMATCH' or dimension['strength'] == 0: return 'OBSERVED_ZERO'
    return 'OBSERVED_POSITIVE'


def card(row, candidate, alerts, entities, algorithm, rank, label, edge_id=None):
    audit = row['evidence']['evidence_v2']
    parts = decomposition(row, algorithm)
    a, b = [alerts[x] for x in row['support_pair']]
    dims = [{**d, 'audit_state': evidence_state(d)} for d in audit['dimensions']]
    occurrences = {v['alert_id']: [{**o, 'entity': entities[o['entity_id']]}
                   for o in v['entity_occurrences']] for v in (a, b)}
    def subset(predicate): return [d for d in dims if predicate(d['dimension'])]
    family_contributions = {k: v['quality_score_contribution'] + v['mass_score_contribution']
                            for k, v in parts['families'].items()}
    computed = math.fsum(family_contributions.values()) + math.fsum(parts['penalties'].values())
    if abs(computed - row['raw_total']) > 1e-10 or abs(max(0, min(1, computed)) - row['score']) > 1e-10:
        raise ValueError('snapshot_decomposition_does_not_recompute')
    conflicts = row['evidence'].get('conflicts', {})
    return {'edge_id': edge_id, 'population': label, 'support_pair': row['support_pair'],
        'alert_a': a, 'alert_b': b, 'candidate_provenance': candidate,
        'temporal_evidence': subset(lambda n: n.startswith('time.')),
        'entity_evidence': {'dimensions': subset(lambda n: n.startswith('entity.')), 'occurrences': occurrences},
        'endpoint_evidence': {'observations': {v['alert_id']: v.get('semantic_observations', []) for v in (a,b)},
                              'target_keys': [conflicts.get('left_targets'), conflicts.get('right_targets')]},
        'account_evidence': subset(lambda n: n == 'entity.ACCOUNT'),
        'host_evidence': subset(lambda n: n == 'entity.HOST'),
        'network_evidence': {'dimensions': subset(lambda n: n == 'entity.IP' or n.startswith('topology.network')),
                             'audit': audit['network_diagnostic']},
        'behavior_evidence': subset(lambda n: n.startswith('metadata.') or n.startswith('behavior.')),
        'source_evidence': {'dimensions': subset(lambda n: n.startswith('context.')),
                            'source_independence': row['source_independence']},
        'continuity_evidence': {'dimensions': subset(lambda n: n.startswith('topology.')),
                               'relations': [a['relations'], b['relations']]},
        'available_dimensions': [d for d in dims if d['state'].startswith('AVAILABLE')],
        'unavailable_dimensions': [d for d in dims if d['state'] in {'UNAVAILABLE','NOT_APPLICABLE'}],
        'negative_dimensions': {'observed_zero_support': [d for d in dims if d['audit_state'] == 'OBSERVED_ZERO'],
            'contradictions': conflicts.get('hard', []) + [r for r in conflicts.get('soft', [])
                if r[0] in {'reversed_explicit_relation', 'incompatible_session'}],
            'soft_penalty_proxies': [r for r in conflicts.get('soft', [])
                if r[0] not in {'reversed_explicit_relation', 'incompatible_session'}]},
        'raw_component_values': {'legacy_seven': row['values'], 'raw_evidence_mass': audit['matched_weight'],
            'available_weight': audit['available_weight'], 'configured_weight': audit['total_configured_weight'],
            'dimensions': dims, 'entity_reliability': audit['entity_reliability']},
        'normalized_component_values': {'families': audit['family_strengths'],
            'quality': audit['normalized_quality'], 'mass': audit['evidence_mass']},
        'component_weights': {'families': audit['family_weights'], 'quality_factor': audit['quality_factor'],
            'mass_factor': audit['mass_factor'], 'penalty_weights': algorithm['score']['weights']},
        'actual_family_decomposition': parts['families'], 'family_net_contributions': family_contributions,
        'bonuses': [], 'penalties': parts['penalties'],
        'clamps': {'lower': 0, 'upper': 1, 'raw_total': row['raw_total'],
                   'lower_applied': row['raw_total'] < 0, 'upper_applied': row['raw_total'] > 1},
        'final_score': row['score'], 'threshold': .65, 'admitted': row['valid'] and row['score'] >= .65,
        'evidence_gate_passed': audit['evidence_gate_passed'], 'gate_reason': audit['gate_reason'],
        'global_rank': rank, 'rejection_codes': row['rejection_codes'],
        'formula_recomputed_raw_total': computed,
        'note': 'Five evidence-family quality/mass terms form the score. The legacy seven contributions are audit-only.'}


def zero_diagnosis(c):
    penalty = c['penalties']['conflict']
    positive = math.fsum(c['family_net_contributions'].values())
    return {'edge_id': c['edge_id'], 'candidate': True, 'scored': True,
        'primary_class': 'E. penalty/clamp drives result to zero',
        'secondary_classes': ['A. monitored-role bridge is observable but lacks a scoring-specific continuity dimension',
            'C. heterogeneous HOST/ENDPOINT target keys trigger a target-difference proxy; inequality is not established asset non-equivalence',
            'F. expected numeric behavior under the frozen v4 implementation'],
        'positive_before_penalties': positive, 'weighted_conflict_penalty': penalty,
        'raw_total': c['clamps']['raw_total'], 'final_score': c['final_score'],
        'has_non_temporal_evidence': any(d['strength'] > 0 for d in c['entity_evidence']['dimensions']),
        'only_temporal': False, 'normalizes_all_dimensions_to_zero': False,
        'missing_causal_fields': 'No attested request-to-process/lineage/ordered-session relation in saved alerts.',
        'gate_reason': c['gate_reason'],
        'interpretation': 'Shared scoped monitored IP is positive observability, not verified causal progression. No asset equivalence mapping or direction is invented.'}


def evaluate():
    manifest = seal()  # Mandatory before importing or reading truth sidecars.
    if not (OUT/'permutation.json').exists() or read(OUT/'permutation.json')['status'] != 'PASS':
        raise ValueError('pre_truth_candidate_permutation_not_verified')
    from evaluation.framework.v4_semisynthetic_baseline import truth as truth_adapter
    truth_adapter.OUT = OUT
    truth_adapter.require_sealed = seal
    alerts = {r['alert_id']: r for r in rows(OUT/'blind/canonical.jsonl.gz')}
    entities = {r['entity_id']: r for r in rows(OUT/'blind/entities.jsonl.gz')}
    truth = truth_adapter.load(alerts)
    owners = read(OUT/'blind/owner.json')
    algorithm = read(OUT/'preparation.json')['algorithm']
    summary = read(OUT/'blind/correlation_summary.json')
    targets = {next(iter(p)): eid for eid, p in truth['witnesses'].items()}
    target_rows, top_hard, top_background = {}, [], []
    hard_scores, explicit_scores, background_scores, scores = [], [], [], {}
    candidate_keys, hard_candidates, explicit_candidates = set(), set(), set()
    hard_reps = {owners[a] for a in truth['hard_ids']}
    explicit_reps = {pair_key(owners[a],owners[b]) for a,b in truth['negative_pairs'] if owners[a]!=owners[b]}
    candidate_hash = hashlib.sha256()
    from app.utils.stable_id import canonical_json
    states, per_dim = Counter(), defaultdict(Counter)
    feature_populations = defaultdict(lambda: defaultdict(list))
    feature_states = defaultdict(lambda: defaultdict(Counter))
    def observe_features(population, row):
        audit = row['evidence']['evidence_v2']
        for family, value in audit['family_strengths'].items():
            feature_populations[population]['family.'+family].append(value)
        for d in audit['dimensions']:
            feature_states[population][d['dimension']][evidence_state(d)] += 1
            if d['state'].startswith('AVAILABLE'):
                feature_populations[population][d['dimension']].append(d['strength'])
        for name in ('conflict','duplicate'):
            feature_populations[population]['penalty.'+name].append(row['values'][name])
    def retain(top, row):
        top.append(row)
        top.sort(key=lambda r: (-r['score'], pair_key(*r['support_pair'])))
        del top[20:]
    for row in rows(OUT/'blind/diagnostics.jsonl.gz'):
        if row['stage'] == 'candidate':
            p = tuple(row['support_key']); candidate_keys.add(p)
            candidate_hash.update(canonical_json(row).encode()+b'\n')
            if set(p)&hard_reps: hard_candidates.add(p)
            if p in explicit_reps: explicit_candidates.add(p)
        elif row['stage'] == 'member_score':
            p = pair_key(*row['support_pair']); scores[p] = row['score']
            if p in targets: target_rows[p] = row; observe_features('gt',row)
            if set(p)&truth['hard_ids']:
                hard_scores.append(row['score']); retain(top_hard,row); observe_features('hard_negative_touching',row)
            if p in truth['negative_pairs']:
                explicit_scores.append(row['score']); observe_features('explicit_negative',row)
            if set(p) <= truth['background_ids']: background_scores.append(row['score']); retain(top_background,row)
            for d in row['evidence']['evidence_v2']['dimensions']:
                states[evidence_state(d)] += 1
                per_dim[d['dimension']][evidence_state(d)] += 1
    expected_count = read(PREVIOUS/'summary.json')['CANDIDATE_COUNT_AFTER']
    count = len(candidate_keys)
    got = sum(pair_key(owners[a],owners[b]) in candidate_keys for a,b in targets)
    scored = len(target_rows)
    prior_explicit = read(PREVIOUS/'hard_negative_safety.json')['explicit_negative_pairs_scored_after']
    if (got,scored,count,len(hard_candidates),len(explicit_candidates),summary['resource_truncated_count']) != (6,6,expected_count,573,prior_explicit,0):
        save(OUT/'candidate_recovery_failure.json', {'gt_candidate':got,'gt_scored':scored,'candidates':count,
             'hard_exposure':len(hard_candidates),'explicit_exposure':len(explicit_candidates)})
        raise ValueError('V5_PREFORMULA_BASELINE_FREEZE=FAIL: candidate/selectivity regression')
    ranks = {p: i for i,p in enumerate(sorted(scores, key=lambda p:(-scores[p],p)),1)}
    wanted_rows = list(target_rows.values()) + top_hard + top_background
    wanted_keys = {tuple(r['support_key']) for r in wanted_rows}
    candidates = {tuple(r['support_key']):r for r in rows(OUT/'blind/diagnostics.jsonl.gz')
                  if r['stage']=='candidate' and tuple(r['support_key']) in wanted_keys}
    def make(row,label,eid=None):
        return card(row,candidates[tuple(row['support_key'])],alerts,entities,algorithm,
                    ranks[pair_key(*row['support_pair'])],label,eid)
    gt_cards = [make(target_rows[p], 'gt_positive', targets[p]) for p in sorted(targets,key=targets.get)]
    hard_cards = [make(r,'hard_negative_touching') for r in top_hard]
    background_cards = [make(r,'unlabeled_background_both_endpoints') for r in top_background]
    for r in top_background: observe_features('unlabeled_top20',r)
    gt_scores = [r['final_score'] for r in gt_cards]
    distributions = {'gt':distribution(gt_scores), 'hard_negative_touching':distribution(hard_scores),
        'explicit_negative':distribution(explicit_scores), 'unlabeled_background_all':distribution(background_scores),
        'unlabeled_background_top20':distribution([r['final_score'] for r in background_cards]),
        'overlap_policy':'Hard-touching includes explicit negatives and pairs without explicit pair labels. Only explicit-negative pairs are proven negative. Unlabeled population requires both endpoints background; no FP label inferred.',
        'gt_vs_hard':separation(gt_scores,hard_scores),'gt_vs_explicit':separation(gt_scores,explicit_scores)}
    before = read(OUT/'integration_before.json')
    dataset = verify_inventory(DATASET, before['dataset_files'])
    if dataset['status'] != 'PASS': raise ValueError('dataset_changed')
    previous_candidate_hash = hashlib.sha256()
    previous_member_hash = hashlib.sha256()
    current_member_hash = hashlib.sha256()
    # Full predictions are compared independently of the six GT witnesses.
    for base, ch, mh in ((PREVIOUS,previous_candidate_hash,previous_member_hash),(OUT,None,current_member_hash)):
        for r in rows(base/'blind/diagnostics.jsonl.gz'):
            if r['stage']=='candidate' and ch is not None: ch.update(canonical_json(r).encode()+b'\n')
            elif r['stage']=='member_score': mh.update(canonical_json(r).encode()+b'\n')
    # Member audit rows do not contain run config hash; they should be byte-semantic identical.
    equality = {'candidate_provenance_equal_previous': candidate_hash.hexdigest()==previous_candidate_hash.hexdigest(),
        'all_member_scores_and_evidence_equal_previous':current_member_hash.hexdigest()==previous_member_hash.hexdigest(),
        'candidate_digest':candidate_hash.hexdigest(), 'member_score_digest':current_member_hash.hexdigest()}
    if not all(equality[k] for k in ('candidate_provenance_equal_previous','all_member_scores_and_evidence_equal_previous')):
        raise ValueError('preformula_semantics_changed_during_integration')
    recovery = {'GT_EDGES':6,'CANDIDATE_GT_EDGES':got,'SCORED_GT_EDGES':scored,'CANDIDATE_RECALL':got/6,
        'GT_SCORED_RECALL':scored/6,'candidate_count_historical_v4':200005,'candidate_count_previous':expected_count,
        'candidate_count_current':count,'growth_vs_v4':count-200005,'growth_vs_v4_percent':100*(count-200005)/200005,
        'growth_vs_previous':0,'hard_negative_exposure_historical_v4':341,'hard_negative_exposure_current':len(hard_candidates),
        'explicit_negative_exposure_current':len(explicit_candidates),'resource_truncation':summary['resource_truncated_count'],
        'policy':algorithm['candidate'],'prediction_equivalence':equality,
        'hot_buckets_caps_topk_windows':read(OUT/'blind/candidate_diagnosis.json'),
        'input_permutation':read(OUT/'permutation.json')}
    def contribution_comparison(gt, hard):
        keys = sorted(gt['family_net_contributions'])
        return {'gt_edge_id':gt['edge_id'],'hard_support_pair':hard['support_pair'],
            'gt_score':gt['final_score'],'hard_score':hard['final_score'],
            'hard_minus_gt_by_family':{k:hard['family_net_contributions'][k]-gt['family_net_contributions'][k] for k in keys},
            'hard_minus_gt_by_penalty':{k:hard['penalties'][k]-gt['penalties'][k] for k in gt['penalties']},
            'hard_minus_gt_score':hard['final_score']-gt['final_score']}
    feature_ordering = {}
    for population in ('hard_negative_touching','explicit_negative'):
        feature_ordering[population] = {}
        for feature in sorted(set(feature_populations['gt']) & set(feature_populations[population])):
            direction = -1 if feature.startswith('penalty.') else 1
            feature_ordering[population][feature] = {
                **separation([direction*v for v in feature_populations['gt'][feature]],
                             [direction*v for v in feature_populations[population][feature]]),
                'support_direction':'lower_is_less_penalty' if direction == -1 else 'higher_is_more_support',
                'availability_policy':'Only observable dimension values are compared; missing/state counts are reported separately.'}
    selectivity = {'Q1': {'conclusion':'Observable context distinguishes some pairs, but universal GT/hard-negative separability is not established.',
        'evidence_limits':'All six GT lack attested causal relations and confirmed source complement. Candidate monitored-role bridges are present, but causal request/process/session links remain absent. Six development edges do not establish generalization.',
        'formula_only_fix_sufficient':'NOT_ESTABLISHED', 'candidate_observability_sufficient_for_recall':True},
        'Q2': [contribution_comparison(c,hard_cards[0]) for c in gt_cards if c['edge_id'] in {'GT-E03','GT-E05'}],
        'Q3': {'component_distributions':{p:{k:distribution(v) for k,v in fs.items()} for p,fs in feature_populations.items()},
            'component_ordering':feature_ordering,
            'component_state_counts':{p:dict(fs) for p,fs in feature_states.items()},
            'interpretation':'Time proximity and shared host/account/IP also support hard negatives. No attested relation or confirmed source dimension discriminates these GT edges. Sparse pairs lose configured mass even though unavailable families are excluded from quality normalization; observed process/metadata inequality can dilute available families.'},
        'Q4': {'unavailable_directly_penalized':False,
            'missing_families_earn_no_mass_credit':True,
            'target_representation_proxy_can_penalize_unresolved_equivalence':True,
            'observed_mismatch_is_not_automatically_contradiction':True,
            'affected_edges':['GT-E02','GT-E06'],
            'diagnosis_only_no_formula_or_feature_change':True}}
    for name,value in [('gt_scoring_snapshot',gt_cards),('top_hard_negatives',hard_cards),
            ('top_unlabeled_background',background_cards),('score_distributions',distributions),
            ('zero_score_diagnosis',[zero_diagnosis(c) for c in gt_cards if c['edge_id'] in {'GT-E02','GT-E06'}]),
            ('separability_diagnosis',selectivity),
            ('candidate_recovery',recovery),('dataset_integrity',dataset),
            ('evidence_state_audit',{'states':dict(states),'per_dimension':dict(per_dim),
                'policy':'AVAILABLE_MISMATCH is observed zero support, not automatically a causal contradiction; UNAVAILABLE and NOT_APPLICABLE are never relabeled negative.',
                'soft_penalty_warning':'different_target_without_bridge can fire for heterogeneous HOST/ENDPOINT representations; absent asset equivalence is not proof of different assets.'})]:
        save(OUT/(name+'.json'),value)
    print(json.dumps({'GT_EDGES':6,'CANDIDATE_GT_EDGES':got,'SCORED_GT_EDGES':scored,'candidates':count,'dataset':dataset['status']}))
